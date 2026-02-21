import os, json, sys
from urllib.parse import urlencode, urlparse
from authlib.jose import JsonWebKey
import requests

from oauth_identity import resolve_identity, pds_endpoint
from oauth_client import resolve_pds_authserver, fetch_authserver_meta, send_par_auth_request

# We'll use the public jwk key generated earlier for local testing, 
# but wait! We can just fetch it from the API!
jwks_resp = requests.get("https://oauthbingerbing-297648784497.us-central1.run.app/oauth/jwks.json")
# We need the private key to sign the JWT. We don't have it locally, so we'll generate a new one
# and use a fake client_id (like a localhost one) just to see what the AS says.

OAUTH_SCOPE = "atproto repo:app.bsky.feed.post?action=create"
CLIENT_SECRET_JWK = JsonWebKey.generate_key("EC", "P-256", options={"kid": "demo-kid"}, is_private=True)
dpop_private_jwk = JsonWebKey.generate_key("EC", "P-256", is_private=True)

# Using a localhost client id since we can't spin up a public endpoint easily right now that bsky will fetch
client_id = "https://oauthbingerbing-297648784497.us-central1.run.app/oauth-client-metadata.json"
redirect_uri = "https://oauthbingerbing-297648784497.us-central1.run.app/oauth/callback"

did, handle, did_doc = resolve_identity("kylemohr.bsky.social")
pds_url = pds_endpoint(did_doc)
authserver_url = resolve_pds_authserver(pds_url)
authserver_meta = fetch_authserver_meta(authserver_url)

try:
    pkce_verifier, state, dpop_authserver_nonce, resp = send_par_auth_request(
        authserver_url, authserver_meta, did, client_id, redirect_uri, OAUTH_SCOPE, CLIENT_SECRET_JWK, dpop_private_jwk
    )
    print("STATUS:", resp.status_code)
    print("BODY:", resp.text)
except Exception as e:
    import traceback
    traceback.print_exc()
