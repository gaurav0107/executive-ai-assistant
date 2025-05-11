"""Overall agent."""
import json
from typing import TypedDict, Literal
from langgraph.graph import END, StateGraph
from langchain_core.messages import HumanMessage
from eaia.agent.triage import (
    triage_input,
)
from eaia.agent.draft_response import draft_response
from eaia.agent.find_meeting_time import find_meeting_time
from eaia.agent.rewrite import rewrite
from eaia.agent.config.config import get_config
from langchain_core.messages import ToolMessage
# from eaia.agent.human_inbox import (
#     send_message,
#     send_email_draft,
#     notify,
#     send_cal_invite,
# )
from eaia.gmail_manager.gmail import (
    send_email,
    create_draft_email,
    mark_as_read,
    add_labels_to_email,
    add_ea_to_thread,
    send_calendar_invite,
)

from eaia.schemas import (
    State,
)


def route_after_triage(
    state: State,
) -> Literal["draft_response", "skip", "notify", "unsure"]:
    if state["triage"].response == "email":
        return "draft_response"
    elif state["triage"].response == "no":
        return "skip"
    elif state["triage"].response == "notify":
        return "notify"
    elif state["triage"].response == "unsure":
        return "unsure"   
    else:
        raise ValueError



def create_email_draft(state, config):
    tool_call = state["messages"][-1].tool_calls[0]
    _args = tool_call["args"]
    email = get_config(config)["email"]
    new_receipients = _args["new_recipients"]
    if isinstance(new_receipients, str):
        new_receipients = json.loads(new_receipients)
    create_draft_email(
        state["config"]["user_email_id"],
        state["email"]["id"],                                    
        _args["content"],
        email,
        addn_receipients=new_receipients,
    )


def skip_node(state):
    add_labels_to_email(state["config"]["user_email_id"], state["email"]["id"], ["EA-SKIP"])
    mark_as_read(state["config"]["user_email_id"], state["email"]["id"])
    pass

def notify_node(state):
    add_labels_to_email(state["config"]["user_email_id"], state["email"]["id"], ["EA-NOTIFY"])
    mark_as_read(state["config"]["user_email_id"], state["email"]["id"])
    pass

def unsure_node(state):
    add_labels_to_email(state["config"]["user_email_id"], state["email"]["id"], ["EA-UNSURE"])
    mark_as_read(state["config"]["user_email_id"], state["email"]["id"])
    pass


def mark_as_read_node(state):
    print("state", state)
    mark_as_read(state["config"]["user_email_id"], state["email"]["id"])


def add_ea_to_thread_node(state):
    ea_name = state["config"]["assistant_name"]
    add_ea_to_thread(
        state["config"]["user_email_id"],
        state["email"]["thread_id"], 
        state["config"]["assistant_email"], 
        f"Hi {ea_name}, Adding you to this conversation")

def label_unsure(state):
    add_labels_to_email(state["config"]["user_email_id"], state["email"]["id"], ["EA-UNSURE"])
    pass

def label_notify(state):
    print("state", state)
    add_labels_to_email(state["config"]["user_email_id"], state["email"]["id"], ["EA-NOTIFY"])
    pass


def label_skip(state):
    add_labels_to_email(state["config"]["user_email_id"], state["email"]["id"], ["EA-SKIP"])
    pass


def human_node(state: State):
    pass


class ConfigSchema(TypedDict):
    db_id: int
    model: str



graph_builder = StateGraph(State, config_schema=ConfigSchema)
graph_builder.add_node(triage_input)
graph_builder.add_node("notify", notify_node)
graph_builder.add_node("skip", skip_node)
graph_builder.add_node("unsure", unsure_node)
graph_builder.add_node("draft_response", create_email_draft)
graph_builder.set_entry_point("triage_input")
graph_builder.add_conditional_edges("triage_input", route_after_triage)
graph_builder.add_edge("draft_response", END)
graph_builder.add_edge("notify", END)
graph_builder.add_edge("skip", END)
graph_builder.add_edge("unsure", END)
graph = graph_builder.compile()
