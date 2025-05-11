"""Gmail service module for handling email operations."""
import logging
from datetime import datetime, timedelta, time
from pathlib import Path
from typing import Iterable, List, Optional, Dict, Any
import pytz
import os
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import email.utils

from dateutil import parser
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from langchain_core.tools import tool
from langchain_core.pydantic_v1 import BaseModel, Field

from eaia.schemas import EmailData
from eaia.agent.config.config import get_config
from eaia.gmail_manager.auth import auth_service

# Configure logging
logger = logging.getLogger(__name__)

class GmailService:
    """Service class for Gmail operations."""
    
    def __init__(self, email: str):
        """Initialize Gmail service with credentials."""
        self.creds = self._get_credentials()
        self.service = build("gmail", "v1", credentials=self.creds)
        # self.calendar_service = build("calendar", "v3", credentials=self.creds)

    @staticmethod
    def _get_credentials() -> Credentials:
        """Get Gmail credentials."""
        creds = auth_service.get_gmail_user_creds(email)
        print(creds)

        return creds

    @staticmethod
    def _extract_message_part(msg: Dict[str, Any]) -> str:
        """Extract message body from email parts."""
        if msg["mimeType"] in ["text/plain", "text/html"]:
            body_data = msg.get("body", {}).get("data")
            if body_data:
                return base64.urlsafe_b64decode(body_data).decode("utf-8")
        if "parts" in msg:
            for part in msg["parts"]:
                body = GmailService._extract_message_part(part)
                if body:
                    return body
        return "No message body available."

    @staticmethod
    def _parse_time(send_time: str) -> datetime:
        """Parse email send time."""
        try:
            return parser.parse(send_time)
        except (ValueError, TypeError) as e:
            raise ValueError(f"Error parsing time: {send_time} - {e}")

    def _create_message(
        self,
        sender: str,
        to: List[str],
        subject: str,
        message_text: str,
        thread_id: str,
        original_message_id: str
    ) -> Dict[str, str]:
        """Create a Gmail message."""
        message = MIMEMultipart()
        message["to"] = ", ".join(to)
        message["from"] = sender
        message["subject"] = subject
        message["In-Reply-To"] = original_message_id
        message["References"] = original_message_id
        message["Message-ID"] = email.utils.make_msgid()
        
        msg = MIMEText(message_text)
        message.attach(msg)
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
        
        return {"raw": raw, "threadId": thread_id}

    def _get_recipients(
        self,
        headers: List[Dict[str, str]],
        email_address: str,
        additional_recipients: Optional[List[str]] = None
    ) -> List[str]:
        """Get all recipients for an email."""
        recipients = set(additional_recipients or [])
        sender = None
        
        for header in headers:
            if header["name"].lower() in ["to", "cc"]:
                recipients.update(header["value"].replace(" ", "").split(","))
            if header["name"].lower() == "from":
                sender = header["value"]
                
        if sender:
            recipients.add(sender)
            
        return [r for r in recipients if email_address not in r]

    def send_message(self, user_id: str, message: Dict[str, str]) -> Dict[str, Any]:
        """Send a Gmail message."""
        return self.service.users().messages().send(userId=user_id, body=message).execute()

    def send_email(
        self,
        email_id: str,
        response_text: str,
        email_address: str,
        additional_recipients: Optional[List[str]] = None
    ) -> None:
        """Send an email response."""
        message = self.service.users().messages().get(userId="me", id=email_id).execute()
        headers = message["payload"]["headers"]
        
        message_id = next(
            header["value"] for header in headers if header["name"].lower() == "message-id"
        )
        thread_id = message["threadId"]
        
        recipients = self._get_recipients(headers, email_address, additional_recipients)
        subject = next(
            header["value"] for header in headers if header["name"].lower() == "subject"
        )
        
        response_message = self._create_message(
            "me", recipients, subject, response_text, thread_id, message_id
        )
        self.send_message("me", response_message)

    def fetch_group_emails(
        self,
        email: str,
        ea_email: str,
        minutes_since: int = 30
    ) -> Iterable[EmailData]:
        """Fetch emails from delegated account."""
        after = int((datetime.now() - timedelta(minutes=minutes_since)).timestamp())
        query = f"(to:{email} OR from:{email}) after:{after}"
        
        messages = []
        next_page_token = None
        
        while True:
            try:
                results = self.service.users().messages().list(
                    userId="me",
                    q=query,
                    pageToken=next_page_token
                ).execute()
                
                if "messages" in results:
                    messages.extend(results["messages"])
                next_page_token = results.get("nextPageToken")
                if not next_page_token:
                    break
            except Exception as e:
                logger.error(f"Error fetching messages: {e}")
                break

        for message in messages:
            try:
                msg = self.service.users().messages().get(userId="me", id=message["id"]).execute()
                thread_id = msg["threadId"]
                payload = msg["payload"]
                headers = payload.get("headers", [])
                
                thread = self.service.users().threads().get(userId="me", id=thread_id).execute()
                messages_in_thread = thread["messages"]
                last_message = messages_in_thread[-1]
                last_headers = last_message["payload"]["headers"]
                
                from_header = next(
                    header["value"] for header in last_headers if header["name"] == "From"
                )
                
                if to_email in from_header:
                    yield {
                        "id": message["id"],
                        "thread_id": message["threadId"],
                        "user_respond": True,
                    }
                    continue
                
                if to_email not in from_header and message["id"] == last_message["id"]:
                    subject = next(
                        header["value"] for header in headers if header["name"] == "Subject"
                    )
                    from_email = next(
                        (header["value"] for header in headers if header["name"] == "From"),
                        "",
                    ).strip()
                    
                    reply_to = next(
                        (header["value"] for header in headers if header["name"] == "Reply-To"),
                        "",
                    ).strip()
                    
                    if reply_to:
                        from_email = reply_to
                        
                    send_time = next(
                        header["value"] for header in headers if header["name"] == "Date"
                    )
                    parsed_time = self._parse_time(send_time)
                    body = self._extract_message_part(payload)
                    
                    yield {
                        "from_email": from_email,
                        "to_email": next(
                            (header["value"] for header in headers if header["name"] == "To"),
                            "",
                        ).strip(),
                        "subject": subject,
                        "page_content": body,
                        "id": message["id"],
                        "thread_id": message["threadId"],
                        "send_time": parsed_time.isoformat(),
                    }
            except Exception as e:
                logger.error(f"Failed to process message {message['id']}: {e}")

    def mark_as_read(self, message_id: str) -> None:
        """Mark an email as read."""
        self.service.users().messages().modify(
            userId="me",
            id=message_id,
            body={"removeLabelIds": ["UNREAD"]}
        ).execute()

    def create_label(self, label_name: str) -> str:
        """Create a new Gmail label."""
        try:
            results = self.service.users().labels().list(userId='me').execute()
            labels = results.get('labels', [])
            
            for label in labels:
                if label['name'].lower() == label_name.lower():
                    return label['id']
            
            label_object = {
                'name': label_name,
                'messageListVisibility': 'show',
                'labelListVisibility': 'labelShow'
            }
            created_label = self.service.users().labels().create(
                userId='me',
                body=label_object
            ).execute()
            return created_label['id']
        
        except Exception as e:
            logger.error(f"Error creating label {label_name}: {e}")
            raise

    def add_labels_to_email(self, message_id: str, label_names: List[str]) -> None:
        """Add labels to an email."""
        label_ids = []
        for label_name in label_names:
            try:
                label_id = self.create_label(label_name)
                label_ids.append(label_id)
            except Exception as e:
                logger.error(f"Failed to create/get label {label_name}: {e}")
                continue
        
        if label_ids:
            self.service.users().messages().modify(
                userId="me",
                id=message_id,
                body={"addLabelIds": label_ids}
            ).execute()
        else:
            logger.warning("No valid labels to add")

    def create_draft_email(
        self,
        email_id: str,
        draft_text: str,
        email_address: str,
        additional_recipients: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Create a draft email reply."""
        message = self.service.users().messages().get(userId="me", id=email_id).execute()
        headers = message["payload"]["headers"]
        
        message_id = next(
            header["value"] for header in headers if header["name"].lower() == "message-id"
        )
        thread_id = message["threadId"]
        
        recipients = self._get_recipients(headers, email_address, additional_recipients)
        subject = next(
            header["value"] for header in headers if header["name"].lower() == "subject"
        )
        
        draft_message = self._create_message(
            "me", recipients, subject, draft_text, thread_id, message_id
        )
        
        return self.service.users().drafts().create(
            userId="me",
            body={"message": draft_message}
        ).execute()

    def add_ea_to_thread(
        self,
        self_email: str,
        thread_id: str,
        new_recipient: str,
        message_text: str
    ) -> Dict[str, Any]:
        """Add EA to an email thread."""
        thread = self.service.users().threads().get(userId="me", id=thread_id).execute()
        latest_message = thread["messages"][-1]
        headers = latest_message["payload"]["headers"]
        
        def get_header(name: str) -> str:
            return next((h["value"] for h in headers if h["name"].lower() == name.lower()), "")
        
        subject = get_header("Subject")
        to = get_header("To")
        cc = get_header("Cc")
        from_email = get_header("From")
        message_id = get_header("Message-ID")
        
        to_list = [email.strip() for email in to.split(",") if email.strip()] if to else []
        cc_list = [email.strip() for email in cc.split(",") if email.strip()] if cc else []
        
        if from_email and from_email not in to_list and from_email not in cc_list:
            to_list.append(from_email)
        
        if new_recipient not in cc_list and new_recipient not in to_list:
            cc_list.append(new_recipient)
        
        to_list = [e for e in to_list if self_email not in e]
        cc_list = [e for e in cc_list if self_email not in e]
        
        conversation_history = []
        for msg in reversed(thread["messages"]):
            msg_headers = msg["payload"]["headers"]
            msg_from = next((h["value"] for h in msg_headers if h["name"].lower() == "from"), "")
            msg_date = next((h["value"] for h in msg_headers if h["name"].lower() == "date"), "")
            msg_body = self._extract_message_part(msg["payload"])
            
            conversation_history.append(
                f"On {msg_date}, {msg_from} wrote:\n{msg_body}\n"
            )
        
        quoted_body = (
            f"Adding: {new_recipient}\n\n"
            f"{message_text}\n\n"
            f"{'='*50}\n"
            f"{''.join(conversation_history)}"
        )
        
        message = MIMEMultipart()
        message["to"] = ", ".join(to_list)
        if cc_list:
            message["cc"] = ", ".join(cc_list)
        message["from"] = "me"
        message["subject"] = subject
        message["In-Reply-To"] = message_id
        message["References"] = message_id
        message["Message-ID"] = email.utils.make_msgid()
        
        message.attach(MIMEText(quoted_body, "plain"))
        
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
        message_object = {
            "raw": raw,
            "threadId": thread_id
        }
        
        try:
            return self.service.users().messages().send(
                userId="me",
                body=message_object
            ).execute()
        except Exception as e:
            logger.error(f"Error adding recipient to thread: {e}")
            raise