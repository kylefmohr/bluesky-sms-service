import flask
from atprototools import Session
import requests, os, ast, re, time
from flask import Flask, request
from google.cloud import secretmanager
from atprotocol.bsky import BskyAgent as Client
from google.cloud import bigquery

agent = Client()
app = Flask(__name__)

registrations_open = True
bluesky_api_username = 'assf.art'

def load_approved_senders() -> list[str]:
    global approved_senders
    client = bigquery.Client()
    query = 'SELECT * FROM `' + os.environ.get("PROJECT_ID") + '.bluesky_registrations.bluesky_registrations`'
    results = client.query(query)
    approved_senders = []
    for row in results:
        approved_senders.append(row['sender'])
    print("Approved senders loaded: " + str(approved_senders))
    return approved_senders


def add_sender(sender, username) -> bool:
    global approved_senders
    client = bigquery.Client()
    payload = {"sender": sender, "username": username, "timestamp": time.time()}
    table_path = os.environ.get("PROJECT_ID") + ".bluesky_registrations.bluesky_registrations"
    insert_job = client.insert_rows_json(table_path, [payload])
    print("Add sender results: " + str(insert_job))
    return True


global approved_senders  # cloud run's docs says it's chill: https://cloud.google.com/run/docs/tips/general#use_global_variables


def add_secret(username, app_password) -> bool:
    secret_manager = secretmanager.SecretManagerServiceClient()
    secret_id = username
    secret_settings = {'replication': {'automatic': {}}}
    parent = "projects/" + os.environ.get("PROJECT_ID")
    payload = app_password.encode("UTF-8")
    try:
        response = secret_manager.create_secret(secret_id=secret_id, parent=parent, secret=secret_settings)
    except:
        return False
    parent = parent + "/secrets/" + username
    try:
        response = secret_manager.add_secret_version(parent=parent, payload={"data": payload})
    except:
        return False
    return True



def retrieve_secret(username) -> dict:
    username = username.lower().replace(".","_") # Secret names don't allow periods, bsky usernames don't allow underscores
    secret_manager = secretmanager.SecretManagerServiceClient()
    secret_id = "projects/" + os.environ.get("PROJECT_ID") + "/secrets/" + username + "/versions/latest"
    try:
        response = secret_manager.access_secret_version(name=secret_id)
    except Exception as e:
        print(e)
        print("Failed to retrieve secret even though sender is registered")
        exit(1)
    secret_value = response.payload.data.decode("UTF-8")
    return secret_value


def retrieve_username(sender) -> str:
    client = bigquery.Client()
    query = f"SELECT username FROM `{os.environ.get('PROJECT_ID')}.bluesky_registrations.bluesky_registrations` WHERE sender = '{sender}'"
    query_job = client.query(query)
    results = query_job.result()
    for row in results:
        return row['username']
    return None


def matches_app_password_format(app_password) -> bool:
    app_password_format = re.compile(r'[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}')
    if app_password_format.match(app_password) is None:
        print("App password is not in the correct format")
        print("Login passwords are NOT supported")
        return False
    return True



def register_sender(sender, username, app_password, developer_username=None, developer_app_password=None) -> bool:
    global approved_senders

    if sender in approved_senders:
        print("Sender already registered")
        return False

    if not matches_app_password_format(app_password):
        print("App password is not in the correct format")
        return False
    

    client = Client()
    client.login(developer_username, developer_app_password)

    try:
        client.get_profile(username)
    except Exception as e:
        print(e)
        print("Username does not exist")
        return False

    try:
        new_client = Client()
        new_client.login(username, app_password)
        print("Successfully logged in")
    except Exception as e:
        print(e)
        print("Incorrect password")
        return False

    if add_sender(sender, username):
        print("Successfully added sender to database")
    else:
        print("Failed to add sender to database")
        return False

    if add_secret(username, app_password):
        print("Successfully added secret")
    else:
        print("Failed to add secret")
        return False
    return True


def cleanup_jpgs() -> None:
    for filename in os.listdir():
        if filename.endswith(".jpg"):
            os.remove(filename)


def send_post(username, app_password, body, reply_ref=None, attachment_path=None) -> dict:
    if len(body) > 300:  # maximum post length, otherwise we'll thread it
        last_page = False
        full_reply_ref = None
        while not last_page:
            if reply_ref is None:
                parent_response = send_post(username, app_password, body[:300], attachment_path=attachment_path)  # only post attachment on the first post of a thread
                full_reply_ref = {"root": parent_response, "parent": parent_response}
            else:
                response = send_post(username, app_password, body[:300], reply_ref=reply_ref)
                full_reply_ref = {"root": reply_ref["root"], "parent": response}
            body = body[300:]
            if len(body) <= 300:
                last_page = True
        response = send_post(username, app_password, body, reply_ref=full_reply_ref)
        return response

    session = Session(username, app_password)
    if reply_ref is None:
        if attachment_path is None:
            response = session.postBloot(body)
            print(username + ": " + body)
            print(response)
            print(response.json())
        else:  # handle attachment
            response = session.postBloot(body, attachment_path)
            print(username + ": " + body + " with attachment: " + attachment_path)
            print(response)
            print(response.json())
            cleanup_jpgs()

    else:
        full_reply_ref = reply_ref
        response = session.postBloot(body, reply_to=full_reply_ref)

    return response.json()


def unregister_sender(sender, username) -> bool:
    global approved_senders
    client = bigquery.Client()
    query = f"DELETE FROM `{os.environ.get('PROJECT_ID')}.bluesky_registrations.bluesky_registrations` WHERE sender = '{sender}' AND username = '{username}'"
    query_job = client.query(query)
    query_job.result()
    if sender in approved_senders:
        approved_senders.remove(sender)
    secret_manager = secretmanager.SecretManagerServiceClient()
    secret_id = f"projects/{os.environ.get('PROJECT_ID')}/secrets/{username}"
    try:
        secret_manager.delete_secret(name=secret_id)
    except Exception as e:
        print(e)
        print("Failed to delete secret")
        return False
    return True


@app.route("/sms", methods=["POST"])
def webhook_handler() -> flask.Response:
    flask_response = flask.Response("OK")
    global approved_senders
    approved_senders = load_approved_senders()
    sms_body = request.form["Body"]
    sender = request.form["From"]
    media_included = request.form["NumMedia"] != "0"  # True if media is included, else false
    if sender not in approved_senders:  # Sender not in approved senders
        if registrations_open:
            if sms_body.startswith("register"):
                username = sms_body.split(" ")[1]
                app_password = sms_body.split(" ")[2]
                developer_app_password = retrieve_secret(bluesky_api_username)
                developer_username = bluesky_api_username
                resp = register_sender(sender, username, app_password, developer_username, developer_app_password)
                print(sender + ": " + sms_body)
                print(resp)
                return flask_response
            else:
                print("Sender: " + sender + " not registered, and SMS did not start with the word 'register'")
                exit(1)
        else:
            print("A registration request was sent while registrations are closed. From: " + sender + ": " + sms_body)
            exit(1)
    else:  # Sender is in approved senders
        username = retrieve_username(sender)
        app_password = retrieve_secret(username)
        if sms_body.startswith("!unregister"):
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
                exit(1)
        elif sms_body.startswith("!register") or sms_body.startswith("register"):
            try:
                potential_app_password = sms_body.split(" ")[2]
            except:
                potential_app_password = None
            if matches_app_password_format(potential_app_password):
                print("Registration request sent by registered sender")
                if registrations_open:
                    print("Registering new account for known sender")
                    username = sms_body.split(" ")[1]
                    app_password = sms_body.split(" ")[2]
                    developer_app_password = retrieve_secret(bluesky_api_username)
                    developer_username = bluesky_api_username
                    resp = register_sender(sender, username, app_password, developer_username, developer_app_password)
                    return flask_response
        if not media_included:
            send_post(username, app_password, sms_body)
            return flask_response
        elif media_included:
            jpg_included = False
            filename = ""
            sms_body = request.form["Body"]
            for i in range(int(request.form["NumMedia"])):
                if request.form[f"MediaContentType{i}"] == "image/jpeg":
                    jpg_included = True
                    response = requests.get(request.form[f"MediaUrl{i}"])
                    filename = request.form[f"MediaUrl{i}"].split('/')[-1]
                    open(filename, 'wb').write(response.content)
                elif request.form[f"MediaContentType{i}"] == "text/plain":
                    sms_body = str(sms_body) + requests.get(request.form[f"MediaUrl{i}"]).text
                else:
                    print("Unsupported media type: " + request.form[f"MediaContentType{i}"])
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
