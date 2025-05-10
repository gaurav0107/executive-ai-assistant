import logging
from datetime import datetime, timedelta, time
from pathlib import Path
from typing import Iterable
import pytz
import os
from pydantic import BaseModel, EmailStr
from dateutil import parser
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow, Flow
from googleapiclient.discovery import build
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import email.utils
import json

from langchain_core.tools import tool
from langchain_core.pydantic_v1 import BaseModel, Field
from eaia.main.config import get_config
import traceback
from eaia.schemas import EmailData
# from fastapi import url_for
logger = logging.getLogger(__name__)
_SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar",
]

import sys
from pathlib import Path

from pydantic import BaseModel, HttpUrl
from typing import List, Optional
from datetime import datetime

from eaia.repository.store_init import user_token_store
from urllib.parse import parse_qs

# Add the project root to Python path
project_root = str(Path(__file__).parent.parent.parent)
if project_root not in sys.path:
    sys.path.append(project_root)

_ROOT = Path(__file__).parent.absolute()
_PORT = 54191
_SECRETS_DIR = _ROOT / ".secrets"
_SECRETS_PATH = str(_SECRETS_DIR / "secrets.json")
_CLIENT_SECRETS_PATH = str(_SECRETS_DIR / "client_secrets.json")
_TOKEN_PATH = str(_SECRETS_DIR / "token.json")
# _EA_SECRETS_PATH = str(_SECRETS_DIR / "ea_secrets.json")
# _EA_TOKEN_PATH = str(_SECRETS_DIR / "ea_token.json")


class UserCredentials(BaseModel):
    token: str
    expiry: datetime
    _scopes: List[str]
    _default_scopes: Optional[List[str]] = None
    _refresh_token: str
    _granted_scopes: List[str]
    _token_uri: HttpUrl
    _client_id: str



def _get_auth_url(email: EmailStr) -> str:
    """Generate OAuth2 authorization URL."""
    try:
        state_obj = {"email": email}
        state_str = base64.urlsafe_b64encode(json.dumps(state_obj).encode()).decode()
        print(f"Generating auth URL for {email}")
        flow = Flow.from_client_secrets_file(
            _CLIENT_SECRETS_PATH,
            scopes=_SCOPES,
            redirect_uri='http://127.0.0.1:2024/setup/oauth2callback'
        )
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            state=state_str
        )
        return auth_url
    except Exception as e:
        traceback.print_exc()
        logger.error(f"Error generating auth URL: {e}")
        raise


def send_auth_email(email: EmailStr) -> str:
    """
    Send authentication email to user with auth URL.
    
    Args:
        email: Email address to send auth link to
        
    Returns:
        str: Status message indicating email was sent
    """
    try:
        # Get the authorization URL
        auth_url = _get_auth_url(email)
        
        print(auth_url)
        # Compose email message
        message = {
            'to': email,
            'subject': 'Authorize Your Email Account',
            'body': f"""
                Please click the link below to authorize access to your email account:
                
                {auth_url}
                
                If you did not request this, please ignore this email.
                """
        }
        
        # Send email using Gmail API
        service = build('gmail', 'v1', credentials=_get_admin_credentials())
        
        msg = MIMEText(message['body'])
        msg['to'] = message['to']
        msg['subject'] = message['subject']
        
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode('utf-8')
        service.users().messages().send(userId='me', body={'raw': raw}).execute()
        
        return "Authentication email sent successfully"
        
    except Exception as e:
        traceback.print_exc()
        logger.error(f"Error sending auth email: {e}")
        raise Exception(f"Failed to send authentication email: {str(e)}")


def _get_admin_credentials() -> Credentials:
    creds = None
    #  _SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    if os.path.exists(_TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(_TOKEN_PATH)

    if not creds or not creds.valid or not creds.has_scopes(_SCOPES):
        if (
            creds
            and creds.expired
            and creds.refresh_token
            and creds.has_scopes(_SCOPES)
        ):
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(_SECRETS_PATH, _SCOPES)
            creds = flow.run_local_server(port=_PORT)
        with open(_TOKEN_PATH, "w") as token:
            token.write(creds.to_json())

    return creds


def handle_oauth2callback(state: str, code: str, url: str):
    try:
        if state:

            decoded_state = base64.urlsafe_b64decode(state.encode()).decode()
            state_data = json.loads(decoded_state)
            email = state_data.get("email")

            print(decoded_state)


            # email = decoded_state.get('email', [None])[0]
            
        else:
            raise HTTPException(status_code=400, detail="No state parameter provided")

        # Get the authorization code from the request
        if not code:
            raise HTTPException(status_code=400, detail="No authorization code provided")

        # Create flow instance
        flow = Flow.from_client_secrets_file(
            _CLIENT_SECRETS_PATH,
            scopes=_SCOPES,
            redirect_uri='http://127.0.0.1:2024/setup/oauth2callback'
        )

        # Exchange code for credentials
        flow.fetch_token(
            authorization_response=str(url),
            code=code
        )

        credentials = flow.credentials

        # Store credentials
        token_data = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes,
            'expiry': credentials.expiry.isoformat() if credentials.expiry else None
        }

        # Store credentials with the correct email
        user_token_store.put(email, json.dumps(token_data))

        return {"status": "success", "message": f"Gmail connected successfully for {email}!"}

    except Exception as e:
        traceback.print_exc()
        logger.error(f"Error in OAuth callback: {e}")
        raise e