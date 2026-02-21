import pytest
from unittest.mock import MagicMock, patch
import os
import json

# Set environment before importing main
os.environ['PROJECT_ID'] = 'test-project'
os.environ['PUSHOVER_API_TOKEN'] = 'test'
os.environ['PUSHOVER_USER_KEY'] = 'test'
os.environ['BLUESKY_USERNAME'] = 'bot.bsky.social'
os.environ['BLUESKY_APP_PASSWORD'] = 'bot-password'

from main import app, retrieve_user_info, save_oauth_session, send_post_oauth

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def mock_firestore():
    with patch('main.firestore.Client') as mock:
        mock_collection = MagicMock()
        mock_doc = MagicMock()
        mock_collection.document.return_value = mock_doc
        mock.return_value.collection.return_value = mock_collection
        yield mock

def test_retrieve_user_info(mock_firestore):
    mock_doc = mock_firestore.return_value.collection.return_value.document.return_value.get.return_value
    mock_doc.exists = True
    mock_doc.to_dict.return_value = {"username": "test.bsky.social"}
    
    result = retrieve_user_info("+1234567890")
    assert result["username"] == "test.bsky.social"
    assert result["sender"] == "+1234567890"

def test_save_oauth_session(mock_firestore):
    save_oauth_session("+1234567890", {"access_token": "token"})
    mock_firestore.return_value.collection.return_value.document.assert_called_with("+1234567890")
    mock_firestore.return_value.collection.return_value.document.return_value.set.assert_called_with({"access_token": "token"}, merge=True)

@patch('main.pds_authed_req_with_db')
def test_send_post_oauth(mock_pds_authed_req_with_db):
    user = {
        "did": "did:plc:123", 
        "pds_url": "https://pds.example.com", 
        "dpop_private_jwk": '{"kty":"EC"}', 
        "access_token": "token", 
        "sender": "+1"
    }
    
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"uri": "test_uri", "cid": "test_cid"}
    mock_pds_authed_req_with_db.return_value = mock_resp
    
    with patch('main.JsonWebKey.import_key'):
        with patch('main.datetime') as mock_datetime:
            mock_datetime.now.return_value.isoformat.return_value = "2023-01-01T00:00:00Z"
            # mock parse_facets_to_dict as well to avoid complicated matching
            with patch('main.parse_facets_to_dict', return_value=[]):
                result = send_post_oauth(user, "Hello!")
                assert result == {"uri": "test_uri", "cid": "test_cid"}
