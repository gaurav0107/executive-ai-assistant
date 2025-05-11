import argparse
import asyncio
from typing import Optional
from eaia.gmail import fetch_group_emails
from eaia.agent.config.config import get_config
from langgraph_sdk import get_client
import httpx
import uuid
import hashlib


async def main():
    config = get_config({"configurable": {}})
    
    email_address = config["email"]
    ea_email = config["ea_email"]
    client = get_client(url="http://127.0.0.1:2024")
    minutes_since = 60

    for email in fetch_group_emails(
        email_address,
        ea_email=ea_email,
        minutes_since=minutes_since,
    ):
        thread_id = str(
            uuid.UUID(hex=hashlib.md5(email["thread_id"].encode("UTF-8")).hexdigest())
        )
        try:
            thread_info = await client.threads.get(thread_id)
        except httpx.HTTPStatusError as e:
            if "user_respond" in email:
                continue
            if e.response.status_code == 404:
                thread_info = await client.threads.create(thread_id=thread_id)
            else:
                raise e
        if "user_respond" in email:
            await client.threads.update_state(thread_id, None, as_node="__end__")
            continue
        recent_email = thread_info["metadata"].get("email_id")
        if recent_email == email["id"]:
            if early:
                break
            else:
                if rerun:
                    pass
                else:
                    continue
        await client.threads.update(thread_id, metadata={"email_id": email["id"]})

        await client.runs.create(
            thread_id,
            "main",
            input={"email": email},
            multitask_strategy="rollback",
        )


if __name__ == "__main__":
    asyncio.run(main())
