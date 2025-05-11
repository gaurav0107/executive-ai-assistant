"""Agent responsible for triaging the email, can either ignore it, try to respond, or notify user."""

from langchain_core.runnables import RunnableConfig
from langchain_openai import ChatOpenAI
from langchain_core.messages import RemoveMessage
from langgraph.store.base import BaseStore

from eaia.schemas import (
    State,
    RespondTo,
)
from eaia.agent.fewshot import get_few_shot_examples
from eaia.agent.config.config import get_config
from eaia.agent.prompts.agent_triage_prompt import triage_prompt

async def triage_input(state: State, config: RunnableConfig, store: BaseStore):
    model = config["configurable"].get("model", "gpt-4o-mini")
    llm = ChatOpenAI(model=model, temperature=0)
    # examples = await get_few_shot_examples(state["email"], store, config)
    prompt_config = get_config(config)
    input_message = triage_prompt.format(
        email_thread=state["email"]["page_content"],
        author=state["email"]["from_email"],
        to=state["email"].get("to_email", ""),
        subject=state["email"]["subject"],
        # fewshotexamples=examples,
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


    # model = llm.with_structured_output(RespondTo).bind(
    #     tool_choice={"type": "function", "function": {"name": "RespondTo"}}
    # )
    # response = await model.ainvoke(input_message)
    # if len(state["messages"]) > 0:
    #     delete_messages = [RemoveMessage(id=m.id) for m in state["messages"]]
    #     print({"triage": response, "messages": delete_messages})
    #     return {"triage": response, "messages": delete_messages}
    # else:
    #     print({"triage": response})
    #     return {"triage": response}
