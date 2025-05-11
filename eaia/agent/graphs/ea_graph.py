"""Overall agent."""
from typing import TypedDict, Literal
from langgraph.graph import END, StateGraph
from eaia.agent.draft_response import draft_response
from eaia.agent.find_meeting_time import find_meeting_time
from eaia.agent.rewrite import rewrite
from eaia.agent.config.config import get_config
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
from eaia.schemas import State

def route_after_triage(
    state: State,
) -> Literal["reply_to_email_node", "mark_as_read_node"]:
    if state["triage"].response == "email":
        return "reply_to_email_node"
    else:
        return "mark_as_read_node"

def triage_input_node(state):
    pass

def mark_as_read_node(state):
    mark_as_read(state["email"]["id"])

def reply_to_email_node(state):
    pass

class ConfigSchema(TypedDict):
    db_id: int
    model: str

graph_builder = StateGraph(State, config_schema=ConfigSchema)
graph_builder.add_node(triage_input_node)
graph_builder.add_node(mark_as_read_node)
graph_builder.add_node(reply_to_email_node)

graph_builder.set_entry_point("triage_input_node")
graph_builder.add_conditional_edges("triage_input_node", route_after_triage)
graph_builder.add_edge("reply_to_email_node", END)
graph_builder.add_edge("mark_as_read_node", END)

graph = graph_builder.compile()