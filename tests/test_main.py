import pytest
from unittest.mock import MagicMock, patch
import os
import json
from main import app, username_exists, valid_app_password, send_post, add_sender, retrieve_secret
from dotenv import load_dotenv
from chump import Application

# Initialize variables
PROJECT_ID = None
PUSHOVER_API_TOKEN = None
PUSHOVER_USER_KEY = None

load_dotenv(override=True)
# Load environment variables
try:
    PROJECT_ID = os.environ['PROJECT_ID']
    PUSHOVER_API_TOKEN = os.environ['PUSHOVER_API_TOKEN']
    PUSHOVER_USER_KEY = os.environ['PUSHOVER_USER_KEY']
except:
    print("One or more environment variables are missing")

# Keep trying to load from .env until we have all variables
while not all([PROJECT_ID, PUSHOVER_API_TOKEN, PUSHOVER_USER_KEY]):
    load_dotenv(override=True)
    PROJECT_ID = os.environ.get('PROJECT_ID')
    PUSHOVER_API_TOKEN = os.environ.get('PUSHOVER_API_TOKEN')
    PUSHOVER_USER_KEY = os.environ.get('PUSHOVER_USER_KEY')
    if not PROJECT_ID:
        print("PROJECT_ID is missing")
    if not PUSHOVER_API_TOKEN:
        print("PUSHOVER_API_TOKEN is missing")
    if not PUSHOVER_USER_KEY:
        print("PUSHOVER_USER_KEY is missing")

# Initialize global variables
import main
main.approved_senders = []

@pytest.fixture
def client():
    """Create a test client for our Flask app"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def mock_firestore():
    """Mock Firestore client"""
    with patch('google.cloud.firestore.Client') as mock:
        mock_collection = MagicMock()
        mock_doc = MagicMock()
        mock_collection.document.return_value = mock_doc
        mock.return_value.collection.return_value = mock_collection
        yield mock

@pytest.fixture
def mock_secret_manager():
    """Mock Secret Manager client"""
    with patch('google.cloud.secretmanager.SecretManagerServiceClient') as mock:
        mock_response = MagicMock()
        mock_response.payload.data.decode.return_value = "test-secret"
        mock.return_value.access_secret_version.return_value = mock_response
        yield mock

@pytest.fixture
def mock_atproto_client():
    """Mock atproto Client"""
    with patch('main.Client') as mock:
        # Create a mock client instance with all required attributes
        mock_client = MagicMock()
        
        # Set up mock structure
        mock_client.com = MagicMock()
        mock_client.com.atproto = MagicMock()
        mock_client.com.atproto.identity = MagicMock()
        mock_client.com.atproto.repo = MagicMock()
        
        # Set up successful response for resolve_handle
        mock_resolve_response = MagicMock()
        mock_resolve_response.did = "test_did"
        mock_client.com.atproto.identity.resolve_handle.return_value = mock_resolve_response
        
        # Set up successful response for login
        mock_client.login = MagicMock(return_value=mock_client)
        
        # Set up successful response for create_record
        mock_record_response = MagicMock()
        mock_record_response.uri = "test_uri"
        mock_record_response.cid = "test_cid"
        mock_client.com.atproto.repo.create_record = MagicMock(return_value=mock_record_response)
        mock_client.me = MagicMock(did="test_did")
        
        # Make the mock return our configured client
        mock.return_value = mock_client
        
        yield mock

def test_username_exists_valid(mock_atproto_client):
    """Test username_exists with a valid username"""
    result = username_exists("valid.user")
    assert result is True
    mock_atproto_client.return_value.com.atproto.identity.resolve_handle.assert_called_once_with(
        {'handle': 'valid.user'}
    )

def test_username_exists_invalid(mock_atproto_client):
    """Test username_exists with an invalid username"""
    mock_atproto_client.return_value.com.atproto.identity.resolve_handle.side_effect = Exception("User not found")
    result = username_exists("invalid.user")
    assert result is False

def test_valid_app_password_success(mock_atproto_client):
    """Test valid_app_password with valid credentials"""
    result = valid_app_password("valid.user", "valid-password")
    assert result is True
    mock_atproto_client.return_value.login.assert_called_once_with("valid.user", "valid-password")

def test_valid_app_password_failure(mock_atproto_client):
    """Test valid_app_password with invalid credentials"""
    mock_atproto_client.return_value.login.side_effect = Exception("Invalid credentials")
    result = valid_app_password("invalid.user", "invalid-password")
    assert result is False

@patch('main.time')
def test_send_post_success(mock_time, mock_atproto_client):
    """Test send_post with successful post"""
    mock_time.time.return_value = 1234567890
    
    result = send_post("test.user", "test-password", "Hello, world!")
    
    assert result == {"uri": "test_uri", "cid": "test_cid"}
    mock_atproto_client.return_value.login.assert_called_once_with("test.user", "test-password")
    mock_atproto_client.return_value.com.atproto.repo.create_record.assert_called_once_with({
        'repo': 'test_did',
        'collection': 'app.bsky.feed.post',
        'record': {
            'text': 'Hello, world!',
            'createdAt': mock_time.time.return_value
        }
    })

@patch('main.load_approved_senders')
@patch('main.sys.exit')
def test_webhook_handler_unauthorized(mock_exit, mock_load_approved_senders, client):
    """Test webhook handler with unauthorized sender"""
    mock_load_approved_senders.return_value = []
    response = client.post('/sms', data={
        'From': '+1234567890',
        'Body': 'Test message'
    })
    assert response.status_code == 200
    mock_exit.assert_called_once_with(1)

def test_add_sender_success(mock_firestore):
    """Test adding a new sender successfully"""
    result = add_sender("+1234567890", "test.user")
    
    assert result is True
    mock_firestore.return_value.collection.assert_called_once_with("bluesky-registrations")
    mock_firestore.return_value.collection.return_value.document.assert_called_once_with("+1234567890")
    mock_firestore.return_value.collection.return_value.document.return_value.set.assert_called_once()

def test_retrieve_secret_success(mock_secret_manager):
    """Test retrieving a secret successfully"""
    result = retrieve_secret("test.user")
    
    assert result == "test-secret"
    expected_secret_path = f"projects/{PROJECT_ID}/secrets/test_user/versions/latest"
    mock_secret_manager.return_value.access_secret_version.assert_called_once_with(
        name=expected_secret_path
    )

def test_pushover_notification_success():
    """Test sending a notification to Pushover"""
    app = Application(PUSHOVER_API_TOKEN)
    user = app.get_user(PUSHOVER_USER_KEY)
    message = user.create_message("Test message", title="Test title")
    result = message.send()
    assert result is True
