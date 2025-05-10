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
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import email.utils

from langchain_core.tools import tool
from langchain_core.pydantic_v1 import BaseModel, Field
from eaia.main.config import get_config

from eaia.schemas import EmailData

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

# Add the project root to Python path
project_root = str(Path(__file__).parent.parent.parent)
if project_root not in sys.path:
    sys.path.append(project_root)

_ROOT = Path(__file__).parent.absolute()
_PORT = 54191
_SECRETS_DIR = _ROOT / ".secrets"
_SECRETS_PATH = str(_SECRETS_DIR / "secrets.json")
# _TOKEN_PATH = str(_SECRETS_DIR / "token.json")
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

def get_user_credentials(email: EmailStr) -> UserCredentials:

    if user_token_store.get(email):
        return UserCredentials.model_validate_json(user_token_store.get(email))

    flow = InstalledAppFlow.from_client_secrets_file(_SECRETS_PATH, _SCOPES)
    creds = flow.run_local_server(port=_PORT)
    user_creds = UserCredentials(
        email=email,
        token=creds.token,
        secret=creds.client_secret,
        expiry=creds.expiry,
        refresh_token=creds.refresh_token
    )
    user_token_store.put(email, user_creds.json())
    return user_creds


def get_credentials(
    gmail_token: str | None = None, gmail_secret: str | None = None
) -> Credentials:
    creds = None
    _SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    gmail_token = gmail_token or os.getenv("GMAIL_TOKEN")
    if gmail_token:
        with open(_TOKEN_PATH, "w") as token:
            token.write(gmail_token)
    gmail_secret = gmail_secret or os.getenv("GMAIL_SECRET")
    if gmail_secret:
        with open(_SECRETS_PATH, "w") as secret:
            secret.write(gmail_secret)
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
