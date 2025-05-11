import argparse
import asyncio
from typing import Optional
from eaia.gmail_manager.gmail import fetch_group_emails


from eaia.agent.config.config import get_config
from langgraph_sdk import get_client
import httpx
import uuid
import hashlib


email_id = "gd@minimuse.co.in"
url = "http://127.0.0.1:2024"
minutes_since = 90
client = get_client(url=url)
early = False #whether to break when encountering seen emails
rerun = True #whether to rerun all emails

async def main():
    count = 0
    for email in fetch_group_emails(
        user_email_id=email_id,
        minutes_since=minutes_since,
    ):
        print(count)
        count += 1
        if count > 10:
            break
        thread_id = str(
            uuid.UUID(hex=hashlib.md5(email["thread_id"].encode("UTF-8")).hexdigest())
        )
        print(thread_id)
        try:
            thread_info = await client.threads.get(thread_id)
            print("thread_info", thread_info)
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
        print("recent_email", recent_email)
        if recent_email == email["id"]:
            if early:
                break
            else:
                if rerun:
                    pass
                else:
                    continue
        await client.threads.update(thread_id, metadata={"email_id": email["id"]})
        print("started run")
        await client.runs.create(
            thread_id,
            "main",
            input={"email": email, "config": {"user_email_id": email_id, "user_name": "gd", "assistant_name": "lisa", "assistant_email": "lisa@minimuse.co.in"}},
            multitask_strategy="rollback",
        )


if __name__ == "__main__":
    asyncio.run(main())
