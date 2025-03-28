import flask
from atproto import Client, models, client_utils
import requests, os, ast, re, time, sys
from flask import Flask, request
from google.cloud import secretmanager
from google.cloud import firestore
from chump import Application
from typing import List, Dict

app = Flask(__name__)

registrations_open = True
bluesky_api_username = 'assf.art'
global approved_senders  # cloud run's docs says it's chill: https://cloud.google.com/run/docs/tips/general#use_global_variables


def send_pushover_message(message: str) -> None:
    """
    Send a message to Pushover.

    Args:
        message (str): The message to send.
    """
    print(f"Sending the following message to Pushover: {message}")
    app = Application(os.environ.get("PUSHOVER_API_TOKEN"))
    user = app.get_user(os.environ.get("PUSHOVER_USER_KEY"))
    message = user.create_message(message, title="Bluesky SMS Service", html=False)
    message.send()
    return


def load_approved_senders() -> list[str]:
    """
    Load the list of approved senders (phone numbers) from the Firestore database.

    Returns:
        list[str]: A list of approved sender phone numbers.
    """
    global approved_senders
    db = firestore.Client(project=os.environ.get("PROJECT_ID"), database="bluesky-registrations")
    # Get all documents from the bluesky-registrations collection
    docs = db.collection("bluesky-registrations").stream()
    # Extract the document IDs (phone numbers)
    approved_senders = [doc.id for doc in docs]
    print("Approved senders loaded: " + str(approved_senders))
    return approved_senders

def add_sender(sender, username) -> bool:
    """
    Add a new sender to the Firestore database.

    Args:
        sender (str): The phone number of the sender.
        username (str): The Bluesky username of the sender.

    Returns:
        bool: True if the sender was successfully added, False otherwise.
    """
    global approved_senders
    db = firestore.Client(project=os.environ.get("PROJECT_ID"), database="bluesky-registrations")
    # Create a new document with sender (phone) as the document ID
    doc_ref = db.collection("bluesky-registrations").document(sender)
    doc_ref.set({
        "username": username,
        "timestamp": firestore.SERVER_TIMESTAMP  # Use server timestamp for consistency
    })
    if sender not in approved_senders:
        approved_senders.append(sender)
    print(f"Added sender {sender} with username {username}")
    return True

def delete_sender(sender, username=None) -> bool:
    """
    Delete a sender from the Firestore database.

    Args:
        sender (str): The phone number of the sender.
        username (str): The Bluesky username of the sender. If it is not specified, uses the first username associated with the sender's phone

    Returns:
        bool: True if the sender was successfully deleted, False otherwise.
    """
    global approved_senders
    db = firestore.Client(project=os.environ.get("PROJECT_ID"), database="bluesky-registrations")
    # Delete the document with sender (phone) as the document ID
    db.collection("bluesky-registrations").document(sender).delete()
    if sender in approved_senders:
        approved_senders.remove(sender)
    return True

def add_secret(username, app_password) -> bool:
    """
    Add a new secret (app password) to the Google Cloud Secret Manager.
    The secret is titled as the user's Bluesky handle (with '.' replaced with '_')

    Args:
        username (str): The Bluesky username.
        app_password (str): The app password for the Bluesky account.

    Returns:
        bool: True if the secret was successfully added, False otherwise.
    """
    secret_manager = secretmanager.SecretManagerServiceClient()
    secret_id = username.lower().replace(".","_")
    secret_settings = {'replication': {'automatic': {}}}
    parent = "projects/" + os.environ.get("PROJECT_ID")
    payload = app_password.encode("UTF-8")
    try:
        response = secret_manager.create_secret(secret_id=secret_id, parent=parent, secret=secret_settings)
    except:
        print("Failed to create secret for user: " + username)
        send_pushover_message("Failed to create secret for user: " + username)
        return False
    parent = parent + "/secrets/" + secret_id
    try:
        response = secret_manager.add_secret_version(parent=parent, payload={"data": payload})
    except:
        print("Failed to add secret version for user: " + username)
        send_pushover_message("Failed to add secret version for user: " + username)
        return False
    return True

def delete_secret(username) -> bool:
    """
    Delete a secret (app password) from the Google Cloud Secret Manager.

    Args:
        username (str): The Bluesky username.

    Returns:
        bool: True if the secret was successfully deleted, False otherwise.
    """
    secret_manager = secretmanager.SecretManagerServiceClient
    secret_id = "projects/" + os.environ.get("PROJECT_ID") + "/secrets/" + username
    try:
        response = secret_manager.delete_secret(name=secret_id)
    except:
        print("Failed to delete secret for user: " + username)
        send_pushover_message("Failed to delete secret for user: " + username)
        return False
    return True



def retrieve_secret(username) -> dict:
    """
    Retrieve the secret (app password) for a given username from the Google Cloud Secret Manager.

    Args:
        username (str): The Bluesky username.

    Returns:
        dict: The app password for the given username.
    """
    username = username.lower().replace(".","_") # Secret names don't allow periods, bsky usernames don't allow underscores
    secret_manager = secretmanager.SecretManagerServiceClient()
    secret_id = "projects/" + os.environ.get("PROJECT_ID") + "/secrets/" + username + "/versions/latest"
    try:
        response = secret_manager.access_secret_version(name=secret_id)
    except Exception as e:
        print(e)
        print("Failed to retrieve secret for user: " + username)
        send_pushover_message("Failed to retrieve secret for user: " + username)
        exit(1)
    secret_value = response.payload.data.decode("UTF-8")
    return secret_value


def retrieve_username(sender) -> str:
    """
    Retrieve the Bluesky username for a given sender from the Firestore database.

    Args:
        sender (str): The phone number of the sender.

    Returns:
        str: The Bluesky username of the sender, or None if not found.
    """
    db = firestore.Client(project=os.environ.get("PROJECT_ID"), database="bluesky-registrations")
    # Get the document with sender (phone) as the document ID
    doc = db.collection("bluesky-registrations").document(sender).get()
    if doc.exists:
        return doc.get("username")
    return None


def matches_app_password_format(app_password) -> bool:
    """
    Check if the given app password matches the required format.

    Args:
        app_password (str): The app password to check.

    Returns:
        bool: True if the app password matches the required format, False otherwise.
    """
    # app_password_format = re.compile(r'[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}')
    # if app_password_format.match(app_password) is None:
    #     print("App password is not in the correct format")
    #     print("Login passwords are NOT supported")
    #     return False
    
    # app passwords can be customized now! Just allow whatever
    return True


def username_exists(username: str) -> bool:
    """
    Check if a username exists on Bluesky.

    Args:
        username (str): The username to check.

    Returns:
        bool: True if the username exists, False otherwise.
    """
    try:
        client = Client()
        response = client.com.atproto.identity.resolve_handle({'handle': username})
        return bool(response.did)
    except Exception as e:
        print(f"Error checking username existence: {e}")
        return False


def valid_app_password(username: str, app_password: str) -> bool:
    """
    Validate an app password for a given username.

    Args:
        username (str): The username to validate.
        app_password (str): The app password to validate.

    Returns:
        bool: True if the app password is valid, False otherwise.
    """
    try:
        client = Client()
        client.login(username, app_password)
        return True
    except Exception as e:
        print(f"Error validating app password: {e}")
        return False


def register_sender(sender, username, app_password) -> bool:
    """
    Register a new sender with their Bluesky username and app password.

    Args:
        sender (str): The phone number of the sender.
        username (str): The Bluesky username of the sender.
        app_password (str): The app password for the Bluesky account.
    Returns:
        bool: True if the sender was successfully registered, False otherwise.
    """
    global approved_senders

    if not matches_app_password_format(app_password):
        if app_password.startswith("<"):
            app_password = app_password.replace("<","").replace(">","")
        else:
            print("App password is not in the correct regex format")
            return False

    #https://atproto.com/specs/handle#:~:text=Handles%20are%20not%20case%2Dsensitive%2C%20and%20should%20be%20normalized%20to%20lowercase%20(that%20is%2C%20normalize%20ASCII%20A%2DZ%20to%20a%2Dz)
    username = username.lower()
    if not username_exists(username):
        if username.startswith("<"):
            username = username.replace("<","").replace(">","")
        else:
            print("Username does not exist")
            return False

    print("Username validated")

    if not valid_app_password(username, app_password):
        print("App password is not valid, could not log in as " + username)
        return False

    if add_sender(sender, username):
        print("Successfully added sender to database")
    else:
        print("Failed to add sender to database")
        approved_senders = load_approved_senders()
        if sender not in approved_senders:
            return False
        else:
            print("Sender got added even though add_sender returned false")
            send_pushover_message("Sender " + sender + " got added even though add_sender returned false")
            pass

    if add_secret(username, app_password):
        print("Successfully added secret")
    else:
        print("Failed to add secret")
        approved_senders = load_approved_senders()
        if sender not in approved_senders:
            return False
        else:
            print("Sender got added even though add_secret returned false. Attempting to delete sender")
            send_pushover_message("Sender " + sender + " got added even though add_secret returned false. Attempting to delete sender")
            if delete_sender(sender, username):
                print("Successfully deleted sender")
            else:
                print("Failed to delete sender")
                return False
    return True


def cleanup_jpgs() -> None:
    """
    Remove all .jpg files from the current directory.
    """
    for filename in os.listdir():
        if filename.endswith(".jpg"):
            os.remove(filename)


def parse_mentions(text: str) -> List[Dict]:
    spans = []
    # regex based on: https://atproto.com/specs/handle#handle-identifier-syntax
    mention_regex = rb"[$|\W](@([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    text_bytes = text.encode("UTF-8")
    for m in re.finditer(mention_regex, text_bytes):
        spans.append({
            "start": m.start(1),
            "end": m.end(1),
            "handle": m.group(1)[1:].decode("UTF-8")
        })
    return spans

def parse_urls(text: str) -> List[Dict]:
    spans = []
    # partial/naive URL regex based on: https://stackoverflow.com/a/3809435
    # tweaked to disallow some training punctuation
    url_regex = rb"[$|\W](https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*[-a-zA-Z0-9@%_\+~#//=])?)"
    text_bytes = text.encode("UTF-8")
    for m in re.finditer(url_regex, text_bytes):
        spans.append({
            "start": m.start(1),
            "end": m.end(1),
            "url": m.group(1).decode("UTF-8"),
        })
    return spans
    
# Parse facets from text and resolve the handles to DIDs
def parse_facets(text: str) -> List[Dict]:
    facets = []
    for m in parse_mentions(text):
        try:
            resp = requests.get(
                "https://bsky.social/xrpc/com.atproto.identity.resolveHandle",
                params={"handle": m["handle"]},
            )
            # If the handle can't be resolved, just skip it!
            # It will be rendered as text in the post instead of a link
            if resp.status_code == 400:
                continue
            did = resp.json()["did"]
            facets.append({
                "index": {
                    "byteStart": m["start"],
                    "byteEnd": m["end"],
                },
                "features": [{"$type": "app.bsky.richtext.facet#mention", "did": did}],
            })
        except Exception as e:
            print(f"Error resolving handle {m['handle']}: {e}")
            # Skip this mention if there's an error
            continue
            
    for u in parse_urls(text):
        facets.append({
            "index": {
                "byteStart": u["start"],
                "byteEnd": u["end"],
            },
            "features": [
                {
                    "$type": "app.bsky.richtext.facet#link",
                    # NOTE: URI ("I") not URL ("L")
                    "uri": u["url"],
                }
            ],
        })
    return facets

def send_post(username: str, app_password: str, body: str, reply_ref=None, attachment_path=None) -> dict:
    """
    Send a post to Bluesky.

    Args:
        username (str): The Bluesky username.
        app_password (str): The app password for the Bluesky account.
        body (str): The content of the post.
        reply_ref (dict, optional): The reference to the post being replied to. Defaults to None.
        attachment_path (str, optional): The path to the attachment file. Defaults to None.

    Returns:
        dict: The response from the Bluesky API.
    """
    try:
        client = Client()
        client.login(username, app_password)

        # Use TextBuilder to properly handle URLs and mentions
        text_builder = client_utils.TextBuilder()
        text_builder.text(body)

        # If there's an attachment
        if attachment_path:
            with open(attachment_path, 'rb') as f:
                # Pass the TextBuilder and attachment directly to the send_post method
                response = client.send_post(
                    text=text_builder,
                    image=f,
                    image_alt="Uploaded image"
                )
        else:
            # Without attachment, just pass the TextBuilder
            if reply_ref:
                response = client.send_post(
                    text=text_builder,
                    reply_to=reply_ref
                )
            else:
                response = client.send_post(text=text_builder)

        # Extract URI and CID from the response
        return {'uri': response.uri, 'cid': response.cid}

    except Exception as e:
        send_pushover_message(f"Error sending post: {e}")
        raise


def unregister_sender(sender: str, username: str = None) -> bool:
    """
    Unregister a sender from the Firestore database and delete their secret from the Google Cloud Secret Manager.

    Args:
        sender (str): The phone number of the sender.   
        username (str): The Bluesky username of the sender. If it is not specified, uses the first username associated with the sender's phone

    Returns:
        bool: True if the sender was successfully unregistered, False otherwise.
    """
    global approved_senders
    if username is None:
        username = retrieve_username(sender)
    if delete_sender(sender, username):
        print("Successfully deleted sender from database")
    else:
        print("Failed to delete sender from database")
        return False
    if delete_secret(username):
        print("Successfully deleted secret")
    else:
        print("Failed to delete secret")
        return False
    return True


@app.route("/sms", methods=["POST"])
def webhook_handler() -> flask.Response:
    """
    Handle incoming SMS messages and process them accordingly.

    Returns:
        flask.Response: The response to be sent back to the sender.
    """
    flask_response = flask.Response("OK")
    global approved_senders
    approved_senders = load_approved_senders()
    sms_body = request.form["Body"]
    sender = request.form["From"]
    media_included = request.form.get("NumMedia", "0") != "0"  # True if media is included, else false
    if sender not in approved_senders:  # Sender not in approved senders
        if registrations_open:
            if sms_body.lower().startswith("register") or sms_body.lower().startswith("!register"):
                username = sms_body.split(" ")[1].strip()
                app_password = sms_body.split(" ")[2].strip().lower()
                resp = register_sender(sender, username, app_password)
                print(sender + ": " + sms_body)
                print(resp)
                return flask_response
            else:
                print("Sender: " + sender + " not registered, and SMS did not start with the word 'register'")
                print(sms_body)
                sys.exit(1)
        else:
            print("A registration request was sent while registrations are closed. From: " + sender + ": " + sms_body)
            sys.exit(1)
    else:  # Sender is in approved senders
        username = retrieve_username(sender)
        app_password = retrieve_secret(username)
        if sms_body.lower().startswith("!unregister"):
            try:
                unregister_username = sms_body.split(" ")[1]
            except:
                unregister_username = username
            if unregister_username == username:
                resp = unregister_sender(sender, unregister_username)
                print(sender + ": " + sms_body)
                print(resp)
                return flask_response
            else:
                print("Unregister username does not match registered username")
                sys.exit(1)
        elif sms_body.startswith("!register") or sms_body.startswith("register"):
            try:
                potential_app_password = sms_body.split(" ")[2]
            except:
                potential_app_password = None
            print("Exiting so we don't accidentially leak somebody's password! Multiple accounts not supported right now, but this is planned")
            sys.exit(1)
            # if matches_app_password_format(potential_app_password):
            #     print("Registration request sent by registered sender")
            #     if registrations_open:
            #         print("Registering new account for known sender")
            #         username = sms_body.split(" ")[1]
            #         app_password = sms_body.split(" ")[2]
            #         developer_app_password = retrieve_secret(bluesky_api_username)
            #         developer_username = bluesky_api_username
            #         resp = register_sender(sender, username, app_password, developer_username, developer_app_password)
            #         return flask_response
        if not media_included:
            send_post(username, app_password, sms_body)
            return flask_response
        elif media_included:
            jpg_included = False
            filename = ""
            sms_body = request.form["Body"]
            for i in range(int(request.form.get("NumMedia", 0))):
                if request.form.get(f"MediaContentType{i}", None) == "image/jpeg":
                    jpg_included = True
                    response = requests.get(request.form.get(f"MediaUrl{i}", None))
                    filename = request.form.get(f"MediaUrl{i}", None).split('/')[-1]
                    open(filename, 'wb').write(response.content)
                elif request.form.get(f"MediaContentType{i}", None) == "text/plain":
                    sms_body = str(sms_body) + requests.get(request.form.get(f"MediaUrl{i}", None)).text
                else:
                    print("Unsupported media type: " + request.form.get(f"MediaContentType{i}", None))
            attachment_path = os.path.abspath(filename)
            send_post(username, app_password, sms_body, attachment_path=attachment_path)
            if not jpg_included:  # TODO: add support for other image formats
                print("Not a jpg")
                return flask_response
            return flask_response

    return flask_response


if __name__ == "__main__":
    # Google Cloud Run expects the app to listen on 8080
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
