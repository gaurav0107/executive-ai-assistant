import logging
import json
import base64
import os
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List
from urllib.parse import parse_qs

from pydantic import BaseModel, EmailStr, HttpUrl
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow, Flow
from googleapiclient.discovery import build
from email.mime.text import MIMEText

from eaia.repository.store_init import user_token_store

# Configure logging
logger = logging.getLogger(__name__)

# Constants
_SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar",
]

# Path configurations
_ROOT = Path(__file__).parent.absolute()
_SECRETS_DIR = _ROOT / ".secrets"
_SECRETS_PATH = str(_SECRETS_DIR / "secrets.json")
_CLIENT_SECRETS_PATH = str(_SECRETS_DIR / "client_secrets.json")
_TOKEN_PATH = str(_SECRETS_DIR / "token.json")
_PORT = 54191
_REDIRECT_URI = 'http://127.0.0.1:2024/setup/oauth2callback'

class UserCredentials(BaseModel):
    """Model for storing user OAuth credentials."""
    token: str
    expiry: datetime
    _scopes: List[str]
    _default_scopes: Optional[List[str]] = None
    _refresh_token: str
    _granted_scopes: List[str]
    _token_uri: HttpUrl
    _client_id: str

class OAuthState(BaseModel):
    """Model for OAuth state data."""
    email: EmailStr

class AuthService:
    """Service class for handling Gmail authentication."""
    
    @staticmethod
    def _encode_state(email: EmailStr) -> str:
        """Encode state data for OAuth flow."""
        state_obj = OAuthState(email=email)
        return base64.urlsafe_b64encode(state_obj.json().encode()).decode()

    @staticmethod
    def _decode_state(state: str) -> OAuthState:
        """Decode state data from OAuth flow."""
        try:
            decoded = base64.urlsafe_b64decode(state.encode()).decode()
            return OAuthState.parse_raw(decoded)
        except Exception as e:
            logger.error(f"Error decoding state: {e}")
            raise ValueError("Invalid state parameter")

    @classmethod
    def get_auth_url(cls, email: EmailStr) -> str:
        """Generate OAuth2 authorization URL."""
        try:
            state_str = cls._encode_state(email)
            logger.info(f"Generating auth URL for {email}")
            
            flow = Flow.from_client_secrets_file(
                _CLIENT_SECRETS_PATH,
                scopes=_SCOPES,
                redirect_uri=_REDIRECT_URI
            )
            
            auth_url, _ = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                state=state_str
            )
            return auth_url
            
        except Exception as e:
            logger.error(f"Error generating auth URL: {e}")
            traceback.print_exc()
            raise

    @classmethod
    def send_auth_email(cls, email: EmailStr) -> str:
        """Send authentication email to user with auth URL."""
        try:
            auth_url = cls.get_auth_url(email)
            
            message = {
                'to': email,
                'subject': 'Authorize Your Email Account',
                'body': f"""
                    Please click the link below to authorize access to your email account:
                    
                    {auth_url}
                    
                    If you did not request this, please ignore this email.
                    """
            }
            
            service = build('gmail', 'v1', credentials=cls._get_admin_credentials())
            
            msg = MIMEText(message['body'])
            msg['to'] = message['to']
            msg['subject'] = message['subject']
            
            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode('utf-8')
            service.users().messages().send(userId='me', body={'raw': raw}).execute()
            
            return "Authentication email sent successfully"
            
        except Exception as e:
            logger.error(f"Error sending auth email: {e}")
            traceback.print_exc()
            raise Exception(f"Failed to send authentication email: {str(e)}")

    @staticmethod
    def _get_admin_credentials() -> Credentials:
        """Get admin credentials for sending auth emails."""
        creds = None
        if os.path.exists(_TOKEN_PATH):
            creds = Credentials.from_authorized_user_file(_TOKEN_PATH)

        if not creds or not creds.valid or not creds.has_scopes(_SCOPES):
            if (creds and creds.expired and creds.refresh_token and 
                creds.has_scopes(_SCOPES)):
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(_SECRETS_PATH, _SCOPES)
                creds = flow.run_local_server(port=_PORT)
            with open(_TOKEN_PATH, "w") as token:
                token.write(creds.to_json())

        return creds

    @classmethod
    def handle_oauth2callback(cls, state: str, code: str, url: str) -> Dict:
        """Handle OAuth2 callback and store credentials."""
        try:
            if not state:
                raise ValueError("No state parameter provided")
            if not code:
                raise ValueError("No authorization code provided")

            # Decode state and get email
            state_data = cls._decode_state(state)
            email = state_data.email

            # Create flow and exchange code for credentials
            flow = Flow.from_client_secrets_file(
                _CLIENT_SECRETS_PATH,
                scopes=_SCOPES,
                redirect_uri=_REDIRECT_URI
            )

            flow.fetch_token(
                authorization_response=str(url),
                code=code
            )

            credentials = flow.credentials

            # Prepare token data
            token_data = {
                'token': credentials.token,
                'refresh_token': credentials.refresh_token,
                'token_uri': credentials.token_uri,
                'client_id': credentials.client_id,
                'client_secret': credentials.client_secret,
                'scopes': credentials.scopes,
                'expiry': credentials.expiry.isoformat() if credentials.expiry else None
            }

            # Store credentials
            user_token_store.put(email, json.dumps(token_data))

            return {
                "status": "success",
                "message": f"Gmail connected successfully for {email}!"
            }

        except Exception as e:
            logger.error(f"Error in OAuth callback: {e}")
            traceback.print_exc()
            raise

    @classmethod
    def check_auth_status(cls, email: EmailStr) -> str:
        """Check the authentication status of a user."""
        user_token = user_token_store.get(email)
        if not user_token:
            return "FAILED"
        return "SUCCESSFUL"

# Export the service class
auth_service = AuthService()