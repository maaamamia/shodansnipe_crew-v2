# Skill — Building an Agent

An **agent** is a specialist in the crew: it owns a job, a set of tools, and the tasks that
produce its output. Every agent is one file in `agents/` exporting two builders:

- `build_<name>_agent(llm, extra_tools=None)` → a CrewAI `Agent`
- `build_<name>_tasks(agent, target_org, scope_query, ...)` → a list of `Task`

Keeping these as plain functions (not a class) is what makes each agent **individually
runnable and testable**, and lets `launchers/poc_crew.py` assemble them in any order.

## Template

```python
# agents/example_agent.py
from __future__ import annotations
import os, sys
from crewai import Agent, Task

def _tools():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
    from my_tool import MyTool          # see BUILDING_TOOLS.md
    return [MyTool()]


def build_example_agent(llm, extra_tools=None):
    tools = _tools() + (extra_tools or [])
    return Agent(
        role="Example Specialist",
        goal="Find X within the authorized scope and hand a clean, prioritised result to the next agent.",
        backstory=(
            "You are precise and scope-disciplined. You never touch anything outside the "
            "active scope. You report findings as structured text the next agent can parse."
        ),
        tools=tools,
        llm=llm,
        verbose=True,
        allow_delegation=False,
    )


def build_example_tasks(agent, target_org, scope_query, prior_output: str = ""):
    return [
        Task(
            description=(
                f"Target org: {target_org}\n"
                f"Active scope: {scope_query}\n"
                f"{('Prior findings:\\n' + prior_output) if prior_output else ''}\n\n"
                "Do your job for IN-SCOPE assets only. Use your tools. "
                "Return a concise, structured summary (markdown) the next agent can consume."
            ),
            expected_output="A structured markdown summary of in-scope findings.",
            agent=agent,
        ),
    ]
```

## Conventions that matter

- **Scope in every task prompt** — restate the scope and say "in-scope only." The hard
  enforcement is in the tools (see BUILDING_TOOLS); the prompt is the second layer.
- **`allow_delegation=False`** unless the agent is a Manager that coordinates others.
- **Output is the handoff** — return structured markdown. The next agent's task takes it as
  `prior_output`. Don't truncate; the report stage controls length via `REPORT_SECTION_CHARS`.
- **`extra_tools`** lets the orchestrator inject optional tools (e.g. Nmap tools into Recon)
  without changing the agent file.

## Run it in isolation

```python
from agents.example_agent import build_example_agent, build_example_tasks
from crewai import Crew, Process, LLM
llm = LLM(model="gpt-4o-mini")
agent = build_example_agent(llm)
tasks = build_example_tasks(agent, "Acme Corp", 'org:"Acme Corp"')
Crew(agents=[agent], tasks=tasks, process=Process.sequential, verbose=True).kickoff()
```

## Wire it into the pipeline

In `launchers/poc_crew.py`, import the builders and insert at the right position:

```python
from example_agent import build_example_agent, build_example_tasks
example_agent = build_example_agent(llm)
example_tasks = build_example_tasks(example_agent, target_org, scope_query, recon_output)
# add example_agent to the phase's agents list and example_tasks to its tasks list
```

If the agent should be **toggleable** from the Control Center (skippable like OSINT/Auth),
add a `CREW_MODULES` check so it's gated — see `ADDING_A_CAPABILITY_MODULE.md`.

## Checklist

- [ ] One file in `agents/`, exports `build_<name>_agent` + `build_<name>_tasks`
- [ ] `allow_delegation=False` (unless a Manager)
- [ ] Scope restated in the task prompt; tools enforce it in code
- [ ] Returns structured markdown for the next agent
- [ ] Runs standalone with the isolation snippet
- [ ] Wired into `poc_crew.py` at the right pipeline position
