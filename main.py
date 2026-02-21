import flask
import os
import re
import json
import requests
from flask import Flask, request, jsonify, redirect, render_template_string
from google.cloud import firestore
from chump import Application
from typing import List, Dict, Any
from datetime import datetime, timezone
from urllib.parse import urlencode, urlparse

from authlib.jose import JsonWebKey
from atproto import Client, IdResolver, client_utils

from oauth_identity import (
    is_valid_did,
    is_valid_handle,
    resolve_identity,
    pds_endpoint,
)
from oauth_client import (
    refresh_token_request,
    revoke_token_request,
    pds_authed_req,
    resolve_pds_authserver,
    initial_token_request,
    send_par_auth_request,
    fetch_authserver_meta,
    pds_dpop_jwt,
    is_use_dpop_nonce_error_response
)
from oauth_security import is_safe_url, hardened_http
from bsky_util import extract_facets

app = Flask(__name__)

registrations_open = True
bluesky_api_username = os.environ.get("BLUESKY_USERNAME", "assf.art")
bluesky_api_password = os.environ.get("BLUESKY_APP_PASSWORD", "")
global approved_senders

OAUTH_SCOPE = "atproto repo:app.bsky.feed.post?action=create"

def get_db():
    return firestore.Client(project=os.environ.get("PROJECT_ID"), database="bluesky-registrations")

def get_or_create_client_jwk():
    db = get_db()
    doc_ref = db.collection("config").document("oauth")
    doc = doc_ref.get()
    if doc.exists and "client_secret_jwk" in doc.to_dict():
        return JsonWebKey.import_key(json.loads(doc.to_dict()["client_secret_jwk"]))
    else:
        jwk = JsonWebKey.generate_key("EC", "P-256", is_private=True)
        doc_ref.set({"client_secret_jwk": jwk.as_json(is_private=True)}, merge=True)
        return jwk

try:
    CLIENT_SECRET_JWK = get_or_create_client_jwk()
    CLIENT_PUB_JWK = json.loads(CLIENT_SECRET_JWK.as_json(is_private=False))
except Exception as e:
    print(f"Failed to load/create client JWK: {e}")
    CLIENT_SECRET_JWK = JsonWebKey.generate_key("EC", "P-256", is_private=True)
    CLIENT_PUB_JWK = json.loads(CLIENT_SECRET_JWK.as_json(is_private=False))

def compute_client_id(url_root):
    parsed_url = urlparse(url_root)
    if parsed_url.hostname in ["localhost", "127.0.0.1"]:
        redirect_uri = f"http://127.0.0.1:{parsed_url.port}/oauth/callback"
        client_id = "http://localhost?" + urlencode({
            "redirect_uri": redirect_uri,
            "scope": OAUTH_SCOPE,
        })
    else:
        app_url = url_root.replace("http://", "https://")
        redirect_uri = f"{app_url}oauth/callback"
        client_id = f"{app_url}oauth-client-metadata.json"
    return client_id, redirect_uri

def send_pushover_message(message: str) -> None:
    print(f"Sending Pushover: {message}")
    token = os.environ.get("PUSHOVER_API_TOKEN")
    user_key = os.environ.get("PUSHOVER_USER_KEY")
    if token and user_key:
        app_pushover = Application(token)
        user = app_pushover.get_user(user_key)
        msg = user.create_message(message, title="Bluesky SMS Service", html=False)
        msg.send()

def load_approved_senders() -> list[str]:
    global approved_senders
    db = get_db()
    docs = db.collection("bluesky-registrations").stream()
    approved_senders = [doc.id for doc in docs if doc.to_dict().get("access_token")]
    print("Approved senders loaded: " + str(approved_senders))
    return approved_senders

def retrieve_user_info(sender) -> dict:
    db = get_db()
    doc = db.collection("bluesky-registrations").document(sender).get()
    if doc.exists:
        data = doc.to_dict()
        data["sender"] = sender
        return data
    return None

def save_oauth_auth_request(state, data):
    db = get_db()
    db.collection("oauth-requests").document(state).set(data)

def get_and_delete_oauth_auth_request(state):
    db = get_db()
    doc_ref = db.collection("oauth-requests").document(state)
    doc = doc_ref.get()
    if doc.exists:
        data = doc.to_dict()
        doc_ref.delete()
        return data
    return None

def save_oauth_session(sender, data):
    db = get_db()
    db.collection("bluesky-registrations").document(sender).set(data, merge=True)

def delete_oauth_session(sender):
    db = get_db()
    db.collection("bluesky-registrations").document(sender).delete()

def send_dm(to_did: str, text: str):
    if not bluesky_api_password:
        print("No BLUESKY_APP_PASSWORD set, cannot send DM.")
        return False
    client = Client()
    client.login(bluesky_api_username, bluesky_api_password)
    chat_client = client.with_bsky_chat_proxy()
    try:
        convo = chat_client.chat.bsky.convo.get_convo_for_members({'members': [to_did]})
        convo_id = convo.convo.id
    except Exception as e:
        print(f"Could not get convo: {e}")
        return False
    try:
        chat_client.chat.bsky.convo.send_message({'convo_id': convo_id, 'message': {'text': text}})
        return True
    except Exception as e:
        print(f"Could not send message: {e}")
        return False

def pds_upload_blob(url: str, user: dict, file_bytes: bytes, content_type: str) -> Any:
    db = get_db()
    dpop_private_jwk = JsonWebKey.import_key(json.loads(user["dpop_private_jwk"]))
    dpop_pds_nonce = user.get("dpop_pds_nonce", "")
    access_token = user["access_token"]
    for i in range(2):
        dpop_jwt = pds_dpop_jwt("POST", url, access_token, dpop_pds_nonce, dpop_private_jwk)
        with hardened_http.get_session() as sess:
            resp = sess.post(
                url,
                headers={
                    "Authorization": f"DPoP {access_token}",
                    "DPoP": dpop_jwt,
                    "Content-Type": content_type
                },
                data=file_bytes,
            )
        if is_use_dpop_nonce_error_response(resp):
            dpop_pds_nonce = resp.headers.get("DPoP-Nonce")
            user["dpop_pds_nonce"] = dpop_pds_nonce
            save_oauth_session(user["sender"], {"dpop_pds_nonce": dpop_pds_nonce})
            continue
        break
    return resp

def pds_authed_req_with_db(method: str, url: str, user: dict, body=None) -> Any:
    db = get_db()
    dpop_private_jwk = JsonWebKey.import_key(json.loads(user["dpop_private_jwk"]))
    dpop_pds_nonce = user.get("dpop_pds_nonce", "")
    access_token = user["access_token"]
    for i in range(2):
        dpop_jwt = pds_dpop_jwt(method, url, access_token, dpop_pds_nonce, dpop_private_jwk)
        with hardened_http.get_session() as sess:
            resp = sess.request(
                method,
                url,
                headers={
                    "Authorization": f"DPoP {access_token}",
                    "DPoP": dpop_jwt,
                },
                json=body,
            )
        if is_use_dpop_nonce_error_response(resp):
            dpop_pds_nonce = resp.headers.get("DPoP-Nonce")
            user["dpop_pds_nonce"] = dpop_pds_nonce
            save_oauth_session(user["sender"], {"dpop_pds_nonce": dpop_pds_nonce})
            continue
        break
    return resp

def parse_facets_to_dict(text: str) -> list:
    resolver = IdResolver()
    facets = []
    mention_regex = r'@([a-zA-Z0-9]+\.[a-zA-Z0-9]{2,})'
    for match in re.finditer(mention_regex, text):
        username = match.group(1)
        did = resolver.handle.resolve(username)
        if did:
            facets.append({
                "index": {"byteStart": len(text[:match.start()].encode('utf-8')), "byteEnd": len(text[:match.end()].encode('utf-8'))},
                "features": [{"$type": "app.bsky.richtext.facet#mention", "did": did}]
            })
    url_regex = r"(https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*[-a-zA-Z0-9@%_\+~#//=])?)"
    for match in re.finditer(url_regex, text):
        url = match.group(1)
        facets.append({
            "index": {"byteStart": len(text[:match.start()].encode('utf-8')), "byteEnd": len(text[:match.end()].encode('utf-8'))},
            "features": [{"$type": "app.bsky.richtext.facet#link", "uri": url}]
        })
    facets.sort(key=lambda x: x["index"]["byteStart"])
    return facets

def send_post_oauth(user: dict, body: str, attachment_path=None):
    pds_url = user["pds_url"]
    
    blob_ref = None
    if attachment_path:
        upload_url = f"{pds_url}/xrpc/com.atproto.repo.uploadBlob"
        content_type = "image/jpeg"
        if attachment_path.lower().endswith(".png"): content_type = "image/png"
        with open(attachment_path, "rb") as f:
            img_bytes = f.read()
        resp = pds_upload_blob(upload_url, user, img_bytes, content_type)
        resp.raise_for_status()
        blob_ref = resp.json()["blob"]

    req_url = f"{pds_url}/xrpc/com.atproto.repo.createRecord"
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    
    record = {
        "$type": "app.bsky.feed.post",
        "text": body,
        "facets": parse_facets_to_dict(body),
        "createdAt": now,
    }
    if blob_ref:
        record["embed"] = {
            "$type": "app.bsky.embed.images",
            "images": [{"alt": "Uploaded image", "image": blob_ref}]
        }

    post_body = {
        "repo": user["did"],
        "collection": "app.bsky.feed.post",
        "record": record,
    }
    resp = pds_authed_req_with_db("POST", req_url, user, body=post_body)
    resp.raise_for_status()
    print("Post sent successfully!")
    return resp.json()


@app.route("/oauth-client-metadata.json")
def oauth_client_metadata():
    app_url = request.url_root.replace("http://", "https://")
    client_id = f"{app_url}oauth-client-metadata.json"
    return jsonify({
        "client_id": client_id,
        "dpop_bound_access_tokens": True,
        "application_type": "web",
        "redirect_uris": [f"{app_url}oauth/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": OAUTH_SCOPE,
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "jwks_uri": f"{app_url}oauth/jwks.json",
        "client_name": "Bluesky SMS Service",
        "client_uri": app_url,
    })

@app.route("/oauth/jwks.json")
def oauth_jwks():
    return jsonify({"keys": [CLIENT_PUB_JWK]})

@app.route("/oauth/login")
def oauth_login():
    sender = request.args.get("sender")
    username = request.args.get("username")
    if not sender or not username:
        return "Missing sender or username", 400

    try:
        did, handle, did_doc = resolve_identity(username)
    except Exception as e:
        return f"Failed to resolve identity: {e}", 400

    pds_url = pds_endpoint(did_doc)
    authserver_url = resolve_pds_authserver(pds_url)
    authserver_meta = fetch_authserver_meta(authserver_url)

    dpop_private_jwk = JsonWebKey.generate_key("EC", "P-256", is_private=True)
    client_id, redirect_uri = compute_client_id(request.url_root)

    pkce_verifier, state, dpop_authserver_nonce, resp = send_par_auth_request(
        authserver_url, authserver_meta, did, client_id, redirect_uri, OAUTH_SCOPE, CLIENT_SECRET_JWK, dpop_private_jwk
    )
    if resp.status_code >= 400:
        print(f"PAR HTTP {resp.status_code}: {resp.text}")
    resp.raise_for_status()
    par_request_uri = resp.json()["request_uri"]

    save_oauth_auth_request(state, {
        "state": state,
        "authserver_iss": authserver_meta["issuer"],
        "did": did,
        "handle": handle,
        "pds_url": pds_url,
        "pkce_verifier": pkce_verifier,
        "scope": OAUTH_SCOPE,
        "dpop_authserver_nonce": dpop_authserver_nonce,
        "dpop_private_jwk": dpop_private_jwk.as_json(is_private=True),
        "sender": sender
    })

    auth_url = authserver_meta["authorization_endpoint"]
    qparam = urlencode({"client_id": client_id, "request_uri": par_request_uri})
    return redirect(f"{auth_url}?{qparam}")

@app.route("/oauth/callback")
def oauth_callback():
    error = request.args.get("error")
    if error:
        return f"Authorization failed: {error} - {request.args.get('error_description')}", 400

    state = request.args.get("state")
    authserver_iss = request.args.get("iss")
    authorization_code = request.args.get("code")

    row = get_and_delete_oauth_auth_request(state)
    if not row:
        return "OAuth request not found", 400
    if row["authserver_iss"] != authserver_iss:
        return "Issuer mismatch", 400

    client_id, redirect_uri = compute_client_id(request.url_root)
    tokens, dpop_authserver_nonce = initial_token_request(
        row, authorization_code, client_id, redirect_uri, CLIENT_SECRET_JWK
    )
    
    if row["did"] and tokens["sub"] != row["did"]:
        return "DID mismatch", 400

    save_oauth_session(row["sender"], {
        "did": row["did"],
        "username": row["handle"],
        "pds_url": row["pds_url"],
        "authserver_iss": authserver_iss,
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "dpop_authserver_nonce": dpop_authserver_nonce,
        "dpop_private_jwk": row["dpop_private_jwk"],
        "dpop_pds_nonce": "",
        "timestamp": firestore.SERVER_TIMESTAMP
    })

    return render_template_string("<h1>Success!</h1><p>You can now close this window and send SMS to post.</p>")

@app.route("/sms", methods=["POST"])
def webhook_handler() -> flask.Response:
    flask_response = flask.Response("OK")
    sms_body = request.form["Body"].strip()
    sender = request.form["From"]
    media_included = request.form.get("NumMedia", "0") != "0"

    user_info = retrieve_user_info(sender)
    
    if sms_body.lower().startswith("register") or sms_body.lower().startswith("!register"):
        if not registrations_open: return flask_response
        parts = sms_body.split(" ")
        if len(parts) < 2: return flask_response
        username = parts[1].strip().lower()
        if username.startswith("<"): username = username.replace("<","").replace(">","")
        try:
            did, handle, _ = resolve_identity(username)
        except Exception as e:
            print(f"Failed to resolve identity: {e}")
            return flask_response

        # Generate login link
        app_url = request.url_root.replace("http://", "https://")
        login_link = f"{app_url}oauth/login?sender={urlencode({'s':sender})[2:]}&username={urlencode({'u':username})[2:]}"
        
        # DM user
        send_dm(did, f"Click here to authorize your account for SMS posting: {login_link}")
        return flask_response

    if sms_body.lower().startswith("!unregister"):
        delete_oauth_session(sender)
        return flask_response

    if not user_info or "access_token" not in user_info:
        print(f"Sender {sender} not registered or not authorized.")
        return flask_response

    # Refresh token logic before posting
    try:
        client_id, _ = compute_client_id(request.url_root)
        tokens, dpop_authserver_nonce = refresh_token_request(user_info, client_id, CLIENT_SECRET_JWK)
        user_info["access_token"] = tokens["access_token"]
        user_info["refresh_token"] = tokens["refresh_token"]
        user_info["dpop_authserver_nonce"] = dpop_authserver_nonce
        save_oauth_session(sender, {
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "dpop_authserver_nonce": dpop_authserver_nonce
        })
    except Exception as e:
        print(f"Failed to refresh token: {e}")
        return flask_response

    try:
        if not media_included:
            send_post_oauth(user_info, sms_body)
        else:
            filename = ""
            for i in range(int(request.form.get("NumMedia", 0))):
                if request.form.get(f"MediaContentType{i}", None) in ["image/jpeg", "image/png"]:
                    response = requests.get(request.form.get(f"MediaUrl{i}", None))
                    filename = request.form.get(f"MediaUrl{i}", None).split('/')[-1]
                    with open(filename, 'wb') as f: f.write(response.content)
                elif request.form.get(f"MediaContentType{i}", None) == "text/plain":
                    sms_body = str(sms_body) + requests.get(request.form.get(f"MediaUrl{i}", None)).text

            attachment_path = os.path.abspath(filename) if filename else None
            send_post_oauth(user_info, sms_body, attachment_path=attachment_path)
    except Exception as e:
        send_pushover_message(f"Error posting: {e}")
        print(e)

    return flask_response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
