import logging
from datetime import datetime, timedelta, time
from pathlib import Path
from typing import Iterable
import pytz
import os

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
from eaia.agent.config.config import get_config

from eaia.schemas import EmailData
from eaia.gmail_manager.auth import auth_service
import logging
logger = logging.getLogger(__name__)

def get_credentials(email: str):
    return auth_service.get_credentials(email)

def extract_message_part(msg):
    """Recursively walk through the email parts to find message body."""
    if msg["mimeType"] == "text/plain":
        body_data = msg.get("body", {}).get("data")
        if body_data:
            return base64.urlsafe_b64decode(body_data).decode("utf-8")
    elif msg["mimeType"] == "text/html":
        body_data = msg.get("body", {}).get("data")
        if body_data:
            return base64.urlsafe_b64decode(body_data).decode("utf-8")
    if "parts" in msg:
        for part in msg["parts"]:
            body = extract_message_part(part)
            if body:
                return body
    return "No message body available."


def parse_time(send_time: str):
    try:
        parsed_time = parser.parse(send_time)
        return parsed_time
    except (ValueError, TypeError) as e:
        raise ValueError(f"Error parsing time: {send_time} - {e}")


def create_message(sender, to, subject, message_text, thread_id, original_message_id):
    message = MIMEMultipart()
    message["to"] = ", ".join(to)
    message["from"] = sender
    message["subject"] = subject
    message["In-Reply-To"] = original_message_id
    message["References"] = original_message_id
    message["Message-ID"] = email.utils.make_msgid()
    msg = MIMEText(message_text)
    message.attach(msg)
    raw = base64.urlsafe_b64encode(message.as_bytes())
    raw = raw.decode()
    return {"raw": raw, "threadId": thread_id}


def get_recipients(
    headers,
    email_address,
    addn_receipients=None,
):
    recipients = set(addn_receipients or [])
    sender = None
    for header in headers:
        if header["name"].lower() in ["to", "cc"]:
            recipients.update(header["value"].replace(" ", "").split(","))
        if header["name"].lower() == "from":
            sender = header["value"]
    if sender:
        recipients.add(sender)  # Ensure the original sender is included in the response
    for r in list(recipients):
        if email_address in r:
            recipients.remove(r)
    return list(recipients)


def send_message(service, user_id, message):
    message = service.users().messages().send(userId=user_id, body=message).execute()
    return message


def send_email(
    email_address,
    email_id,
    response_text,
    addn_receipients=None,
):
    creds = get_credentials(email_address)

    service = build("gmail", "v1", credentials=creds)
    message = service.users().messages().get(userId="me", id=email_id).execute()

    headers = message["payload"]["headers"]
    message_id = next(
        header["value"] for header in headers if header["name"].lower() == "message-id"
    )
    thread_id = message["threadId"]

    # Get recipients and sender
    recipients = get_recipients(headers, email_address, addn_receipients)

    # Create the response
    subject = next(
        header["value"] for header in headers if header["name"].lower() == "subject"
    )
    response_subject = subject
    response_message = create_message(
        "me", recipients, response_subject, response_text, thread_id, message_id
    )
    # Send the response
    send_message(service, "me", response_message)


def fetch_group_emails(
    user_email_id: str,
    minutes_since: int = 30,
) -> Iterable[EmailData]:
    """
    Fetch emails from a delegated an account.
    
    Args:
        to_email: Email address to filter by
        minutes_since: Only fetch emails from the last X minutes
        gmail_token: Optional Gmail token
        gmail_secret: Optional Gmail secret
    """
    creds = get_credentials(user_email_id)
    print("creds", creds)

    service = build("gmail", "v1", credentials=creds)
    after = int((datetime.now() - timedelta(minutes=minutes_since)).timestamp())

    query = f"(to:{user_email_id} OR from:{user_email_id}) after:{after}"
    messages = []
    nextPageToken = None
    user_id = "me"

    # Fetch messages matching the query
    while True:
        try:
            results = (
                service.users()
                .messages()
                .list(userId=user_id, q=query, pageToken=nextPageToken)
                .execute()
            )
            if "messages" in results:
                messages.extend(results["messages"])
            nextPageToken = results.get("nextPageToken")
            if not nextPageToken:
                break
        except Exception as e:
            logger.error(f"Error fetching messages: {e}")
            break

    count = 0
    print(len(messages))
    for message in messages:
        try:
            msg = (
                service.users()
                .messages()
                .get(userId=user_id, id=message["id"])
                .execute()
            )
            thread_id = msg["threadId"]
            payload = msg["payload"]
            headers = payload.get("headers")
            
            # Get the thread details
            thread = (
                service.users()
                .threads()
                .get(userId=user_id, id=thread_id)
                .execute()
            )
            messages_in_thread = thread["messages"]
            # Check the last message in the thread
            last_message = messages_in_thread[-1]
            last_headers = last_message["payload"]["headers"]
            from_header = next(
                header["value"] for header in last_headers if header["name"] == "From"
            )
            last_from_header = next(
                header["value"]
                for header in last_message["payload"].get("headers")
                if header["name"] == "From"
            )
            print("last_from_header", last_from_header)
            if user_email_id in last_from_header:
                yield {
                    "id": message["id"],
                    "thread_id": message["threadId"],
                    "user_respond": True,
                }
            # Check if the last message was from you and if the current message is the last in the thread
            if user_email_id not in from_header and message["id"] == last_message["id"]:
                subject = next(
                    header["value"] for header in headers if header["name"] == "Subject"
                )
                from_email = next(
                    (header["value"] for header in headers if header["name"] == "From"),
                    "",
                ).strip()
                _to_email = next(
                    (header["value"] for header in headers if header["name"] == "To"),
                    "",
                ).strip()
                if reply_to := next(
                    (
                        header["value"]
                        for header in headers
                        if header["name"] == "Reply-To"
                    ),
                    "",
                ).strip():
                    from_email = reply_to
                send_time = next(
                    header["value"] for header in headers if header["name"] == "Date"
                )
                # Only process emails that are less than an hour old
                parsed_time = parse_time(send_time)
                body = extract_message_part(payload)
                yield {
                    "from_email": from_email,
                    "to_email": _to_email,
                    "subject": subject,
                    "page_content": body,
                    "id": message["id"],
                    "thread_id": message["threadId"],
                    "send_time": parsed_time.isoformat(),
                }
                count += 1
        except Exception:
            logger.info(f"Failed on {message}")

    logger.info(f"Found {count} emails.")


def mark_as_read(
    email_address,
    message_id,
):
    creds = get_credentials(email_address)

    service = build("gmail", "v1", credentials=creds)
    service.users().messages().modify(
        userId="me", id=message_id, body={"removeLabelIds": ["UNREAD"]}
    ).execute()


def create_label(
    label_name: str,
    service,
) -> str:
    """
    Creates a new Gmail label if it doesn't exist.

    Args:
        label_name: Name of the label to create.
        service: Gmail API service instance.

    Returns:
        str: ID of the created or existing label.
    """
    try:
        # First check if label already exists
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        
        # Check if label exists
        for label in labels:
            if label['name'].lower() == label_name.lower():
                return label['id']
        
        # If not found, create new label
        label_object = {
            'name': label_name,
            'messageListVisibility': 'show',
            'labelListVisibility': 'labelShow'
        }
        created_label = service.users().labels().create(
            userId='me',
            body=label_object
        ).execute()
        return created_label['id']
    
    except Exception as e:
        logger.error(f"Error creating label {label_name}: {e}")
        raise


def add_labels_to_email(
    email_address: str,
    message_id: str,
    label_names: list[str]
):
    """
    Adds one or more labels to a Gmail message, creating labels if they don't exist.

    Args:
        message_id: The ID of the Gmail message.
        label_names: A list of label names to add to the message.
        gmail_token: Optional Gmail token.
        gmail_secret: Optional Gmail secret.
    """
    creds = get_credentials(email_address)
    service = build("gmail", "v1", credentials=creds)
    
    # Convert label names to IDs, creating labels if needed
    label_ids = []
    for label_name in label_names:
        try:
            label_id = create_label(label_name, service)
            label_ids.append(label_id)
        except Exception as e:
            logger.error(f"Failed to create/get label {label_name}: {e}")
            continue
    
    if label_ids:
        service.users().messages().modify(
            userId="me",
            id=message_id,
            body={"addLabelIds": label_ids}
        ).execute()
    else:
        logger.warning("No valid labels to add")


class CalInput(BaseModel):
    date_strs: list[str] = Field(
        description="The days for which to retrieve events. Each day should be represented by dd-mm-yyyy string."
    )


@tool(args_schema=CalInput)
def get_events_for_days(date_strs: list[str], email_address: str):
    """
    Retrieves events for a list of days. If you want to check for multiple days, call this with multiple inputs.

    Input in the format of ['dd-mm-yyyy', 'dd-mm-yyyy']

    Args:
    date_strs: The days for which to retrieve events (dd-mm-yyyy string).

    Returns: availability for those days.
    """

    creds = get_credentials(email_address)
    service = build("calendar", "v3", credentials=creds)
    results = ""
    for date_str in date_strs:
        # Convert the date string to a datetime.date object
        day = datetime.strptime(date_str, "%d-%m-%Y").date()

        start_of_day = datetime.combine(day, time.min).isoformat() + "Z"
        end_of_day = datetime.combine(day, time.max).isoformat() + "Z"

        events_result = (
            service.events()
            .list(
                calendarId="primary",
                timeMin=start_of_day,
                timeMax=end_of_day,
                singleEvents=True,
                orderBy="startTime",
            )
            .execute()
        )
        events = events_result.get("items", [])

        results += f"***FOR DAY {date_str}***\n\n" + print_events(events)
    return results


def format_datetime_with_timezone(dt_str, timezone="US/Pacific"):
    """
    Formats a datetime string with the specified timezone.

    Args:
    dt_str: The datetime string to format.
    timezone: The timezone to use for formatting.

    Returns:
    A formatted datetime string with the timezone abbreviation.
    """
    dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    tz = pytz.timezone(timezone)
    dt = dt.astimezone(tz)
    return dt.strftime("%Y-%m-%d %I:%M %p %Z")


def print_events(events):
    """
    Prints the events in a human-readable format.

    Args:
    events: List of events to print.
    """
    if not events:
        return "No events found for this day."

    result = ""

    for event in events:
        start = event["start"].get("dateTime", event["start"].get("date"))
        end = event["end"].get("dateTime", event["end"].get("date"))
        summary = event.get("summary", "No Title")

        if "T" in start:  # Only format if it's a datetime
            start = format_datetime_with_timezone(start)
            end = format_datetime_with_timezone(end)

        result += f"Event: {summary}\n"
        result += f"Starts: {start}\n"
        result += f"Ends: {end}\n"
        result += "-" * 40 + "\n"
    return result


def send_calendar_invite(
    email_address: str,
    emails, title, start_time, end_time, timezone="PST"
):
    creds = get_credentials(email_address)
    service = build("calendar", "v3", credentials=creds)

    # Parse the start and end times
    start_datetime = datetime.fromisoformat(start_time)
    end_datetime = datetime.fromisoformat(end_time)
    emails = list(set(emails + [email_address]))
    event = {
        "summary": title,
        "start": {
            "dateTime": start_datetime.isoformat(),
            "timeZone": timezone,
        },
        "end": {
            "dateTime": end_datetime.isoformat(),
            "timeZone": timezone,
        },
        "attendees": [{"email": email} for email in emails],
        "reminders": {
            "useDefault": False,
            "overrides": [
                {"method": "email", "minutes": 24 * 60},
                {"method": "popup", "minutes": 10},
            ],
        },
        "conferenceData": {
            "createRequest": {
                "requestId": f"{title}-{start_datetime.isoformat()}",
                "conferenceSolutionKey": {"type": "hangoutsMeet"},
            }
        },
    }

    try:
        service.events().insert(
            calendarId="primary",
            body=event,
            sendNotifications=True,
            conferenceDataVersion=1,
        ).execute()
        return True
    except Exception as e:
        logger.info(f"An error occurred while sending the calendar invite: {e}")
        return False


def create_draft_email(
    user_email_id: str,
    email_id: str,
    draft_text: str,
    email_address: str,
    gmail_token: str | None = None,
    gmail_secret: str | None = None,
    addn_receipients=None,
):
    """
    Creates a draft email reply to an existing email thread.

    Args:
        email_id: The ID of the original email to reply to.
        draft_text: The text content of the draft reply.
        email_address: The email address of the sender.
        gmail_token: Optional Gmail token.
        gmail_secret: Optional Gmail secret.
        addn_receipients: Optional list of additional recipients.

    Returns:
        The draft message object containing the draft ID and other metadata.
    """
    creds = get_credentials(user_email_id)
    service = build("gmail", "v1", credentials=creds)
    
    # Get the original message to extract headers
    message = service.users().messages().get(userId="me", id=email_id).execute()
    headers = message["payload"]["headers"]
    
    # Get message ID and thread ID
    message_id = next(
        header["value"] for header in headers if header["name"].lower() == "message-id"
    )
    thread_id = message["threadId"]

    # Get recipients
    recipients = get_recipients(headers, email_address, addn_receipients)

    # Get subject
    subject = next(
        header["value"] for header in headers if header["name"].lower() == "subject"
    )

    # Create the draft message
    draft_message = create_message(
        "me", recipients, subject, draft_text, thread_id, message_id
    )

    # Create the draft
    draft = service.users().drafts().create(
        userId="me",
        body={"message": draft_message}
    ).execute()

    return draft


def add_ea_to_thread(
    user_email_id: str,
    thread_id: str,
    new_recipient: str,
    message_text: str,
):
    """
    Adds a new recipient to an existing email thread by replying to all and including them.
    Properly handles reply-all functionality including the original sender and all CC recipients.

    Args:
        user_email_id: The email address of the sender (EA).
        thread_id: The ID of the email thread to add the recipient to.
        new_recipient: Email address of the person to add to the thread.
        message_text: Text content of the message to send.

    Returns:
        The sent message object containing the message ID and other metadata.
    """
    creds = get_credentials(user_email_id)
    service = build("gmail", "v1", credentials=creds)

    # Get the full thread
    thread = service.users().threads().get(userId="me", id=thread_id).execute()
    latest_message = thread["messages"][-1]  # Use the latest message
    headers = latest_message["payload"]["headers"]

    def get_header(name):
        return next((h["value"] for h in headers if h["name"].lower() == name.lower()), "")

    # Get all relevant headers
    subject = get_header("Subject")
    to = get_header("To")
    cc = get_header("Cc")
    from_email = get_header("From")
    message_id = get_header("Message-ID")

    # Prepare recipient lists
    to_list = [email.strip() for email in to.split(",") if email.strip()] if to else []
    cc_list = [email.strip() for email in cc.split(",") if email.strip()] if cc else []
    
    # Add the original sender to recipients if not already present
    if from_email and from_email not in to_list and from_email not in cc_list:
        to_list.append(from_email)
    
    # Add new recipient if not already in the thread
    if new_recipient not in cc_list and new_recipient not in to_list:
        cc_list.append(new_recipient)

    # Remove self from recipient lists
    to_list = [e for e in to_list if user_email_id not in e]
    cc_list = [e for e in cc_list if user_email_id not in e]

    # Build conversation history
    conversation_history = []
    for msg in reversed(thread["messages"]):  # Process messages in chronological order
        msg_headers = msg["payload"]["headers"]
        msg_from = next((h["value"] for h in msg_headers if h["name"].lower() == "from"), "")
        msg_date = next((h["value"] for h in msg_headers if h["name"].lower() == "date"), "")
        msg_body = extract_message_part(msg["payload"])
        
        conversation_history.append(
            f"On {msg_date}, {msg_from} wrote:\n{msg_body}\n"
        )

    # Combine conversation history with new message
    quoted_body = (
        f"Adding: {new_recipient}\n\n"
        f"{message_text}\n\n"
        f"{'='*50}\n"
        f"{''.join(conversation_history)}"
    )

    # Construct the reply message
    message = MIMEMultipart()
    message["to"] = ", ".join(to_list)
    if cc_list:  # Only add CC header if there are CC recipients
        message["cc"] = ", ".join(cc_list)
    message["from"] = "me"
    message["subject"] = subject
    message["In-Reply-To"] = message_id
    message["References"] = message_id
    message["Message-ID"] = email.utils.make_msgid()

    message.attach(MIMEText(quoted_body, "plain"))

    # Encode and send
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    message_object = {
        "raw": raw,
        "threadId": thread_id
    }

    try:
        sent_message = service.users().messages().send(
            userId="me",
            body=message_object
        ).execute()
        return sent_message
    except Exception as e:
        logger.error(f"Error adding recipient to thread: {e}")
        raise