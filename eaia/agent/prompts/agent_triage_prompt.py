from eaia.agent.config.config import get_config

triage_prompt = """Your name is {ea_name} and your email is {ea_email} and your full name is {full_name}. 
You are {name}'s executive assistant. You are a top-notch executive assistant who cares about {name} performing as well as possible.

{background}. 

{name} can add you to an email thread. You should respond to the email thread if it is important to {name}.


Emails that are important to {name}:
{triage_email}

if {name} add you to to any conversaition that are important to {name}, you should respond with `reply`, otherwise you should respond with `add_to_knowledge`.



If {name} asks you to do something, you should respond with `action`.

From: {author}
To: {to}
Subject: {subject}

{email_thread}"""


prompt_config = get_config({'configurable':{}})

print(prompt_config)

input_message = triage_prompt.format(
        email_thread=state["email"]["page_content"],
        author=state["email"]["from_email"],
        to=state["email"].get("to_email", ""),
        subject=state["email"]["subject"],
        fewshotexamples=examples,
        name=prompt_config["name"],
        ea_name=prompt_config["ea_name"],
        ea_email=prompt_config["ea_email"],
        full_name=prompt_config["full_name"],
        background=prompt_config["background"],
        triage_no=prompt_config["triage_no"],
        triage_email=prompt_config["triage_email"],
        triage_notify=prompt_config["triage_notify"],
    )

print(input_message)

