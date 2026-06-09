# Skill — Building a Tool

A **tool** is one capability an agent can call: a Shodan query, an API lookup, a parser. In
ShodanSnipe every tool is a CrewAI `BaseTool` living in `tools/`.

## The contract

1. Subclass `crewai.tools.BaseTool`.
2. Declare `name`, `description`, and an `args_schema` (a pydantic `BaseModel`).
3. Implement `_run(self, ...) -> str` — **it must return a string** (JSON is ideal).
4. **Never raise** — catch everything and return a short error string.
5. **Enforce scope** if the tool touches a target.

## Template

```python
# tools/my_tool.py
from __future__ import annotations
import json
import requests
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

_TIMEOUT = 12


class MyToolInput(BaseModel):
    target: str = Field(description="What to look up, e.g. 'acme.com'")
    limit: int = Field(25, description="Max items to return")


class MyTool(BaseTool):
    name: str = "my_capability"          # the name the LLM/agent sees — keep it verb-like
    description: str = (
        "One or two sentences the agent reads to decide WHEN to use this. Say what it returns "
        "and any safety note (read-only? scope-gated?). Be concrete."
    )
    args_schema: type = MyToolInput

    def _run(self, target: str, limit: int = 25) -> str:
        out = {"target": target, "items": []}
        if not target:
            return json.dumps(out)
        try:
            r = requests.get("https://api.example.com/lookup",
                             params={"q": target, "n": limit}, timeout=_TIMEOUT)
            if not r.ok:
                out["note"] = f"HTTP {r.status_code}"
                return json.dumps(out, indent=2)
            out["items"] = r.json().get("results", [])[:limit]
        except requests.RequestException as e:
            out["note"] = f"lookup failed: {e}"     # fail soft — return, don't raise
        except ValueError as e:
            out["note"] = f"could not parse response: {e}"
        return json.dumps(out, indent=2)
```

## Scope enforcement

If your tool sends traffic to a target (active scan, host fetch), gate it. The simplest pattern
is to ask the server for the active scope and bail on a miss:

```python
import os, requests
SERVER = os.environ.get("SHODANSNIPE_URL", "http://127.0.0.1:8000")

def _in_scope(ip_or_host: str) -> bool:
    try:
        scope = requests.get(f"{SERVER}/api/scope", timeout=5).json()
        return scope and _matches(ip_or_host, scope)   # implement _matches for your scope shape
    except requests.RequestException:
        return False        # fail closed — if you can't confirm scope, don't touch the target
```

Discovery/OSINT tools that only read public data (Shodan, Wayback, RDAP) don't send traffic to
the target and don't need this — but they should still only *report* in-scope results.

## Wire it into an agent

Tools are passed to the agent that uses them. Agents add `tools/` to `sys.path` and import:

```python
# inside agents/<your>_agent.py  (build_<name>_tools)
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from my_tool import MyTool
tools = [MyTool(), ...]
```

## Test it in isolation

```python
from tools.my_tool import MyTool
print(MyTool()._run("acme.com", limit=5))   # should print JSON, never throw
```

## Checklist

- [ ] Lives in `tools/`, subclasses `BaseTool`
- [ ] `args_schema` describes every argument
- [ ] `_run` returns a string and never raises
- [ ] Scope-gated if it touches a target; fails closed
- [ ] Added to the relevant agent's tool list
- [ ] (Optional) exposed as a Control Center toggle → see `ADDING_A_CAPABILITY_MODULE.md`
