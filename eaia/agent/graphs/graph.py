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
from eaia.agent.human_inbox import (
    send_message,
    send_email_draft,
    notify,
    send_cal_invite,
)
from eaia.gmail import (
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
) -> Literal["draft_response", "label_skip", "label_notify", "label_unsure"]:
    if state["triage"].response == "email":
        return "draft_response"
    elif state["triage"].response == "no":
        return "label_skip"
    elif state["triage"].response == "notify":
        return "label_notify"
    elif state["triage"].response == "unsure":
        return "label_unsure"   
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
        state["email"]["id"],
        _args["content"],
        email,
        addn_receipients=new_receipients,
    )



def mark_as_read_node(state):
    mark_as_read(state["email"]["id"])


def add_ea_to_thread_node(state):
    self_email = get_config({"configurable": {}})["email"]
    ea_email = get_config({"configurable": {}})["ea_email"]
    ea_name = get_config({"configurable": {}})["ea_name"]
    add_ea_to_thread(
        self_email,
        state["email"]["thread_id"], 
        ea_email, 
        f"Hi {ea_name}, Adding you to this conversation")

def label_unsure(state):
    add_labels_to_email(state["email"]["id"], ["EA-UNSURE"])
    pass

def label_notify(state):
    add_labels_to_email(state["email"]["id"], ["EA-NOTIFY"])
    pass


def label_skip(state):
    add_labels_to_email(state["email"]["id"], ["EA-SKIP"])
    pass


def human_node(state: State):
    pass


class ConfigSchema(TypedDict):
    db_id: int
    model: str



graph_builder = StateGraph(State, config_schema=ConfigSchema)
graph_builder.add_node(triage_input)
graph_builder.add_node(label_notify)
graph_builder.add_node(label_unsure)
graph_builder.add_node(label_skip)
graph_builder.add_node(add_ea_to_thread_node)
graph_builder.add_node(mark_as_read_node)
graph_builder.add_node(draft_response)
graph_builder.add_node(create_email_draft)
graph_builder.set_entry_point("triage_input")
graph_builder.add_conditional_edges("triage_input", route_after_triage)
graph_builder.add_edge("draft_response", "create_email_draft")
graph_builder.add_edge("create_email_draft", END)
graph_builder.add_edge("label_notify", "add_ea_to_thread_node")
graph_builder.add_edge("label_skip", "mark_as_read_node")
graph_builder.add_edge("add_ea_to_thread_node", "mark_as_read_node")
graph_builder.add_edge("label_unsure", "add_ea_to_thread_node")
graph_builder.add_edge("add_ea_to_thread_node", "mark_as_read_node")
graph_builder.add_edge("mark_as_read_node", END)
graph = graph_builder.compile()
