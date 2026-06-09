# DEPENDENCIES — How the modules connect

This documents how every file imports every other file, and lists the local
`core/` modules you must have for the server to run. Read this if an import
fails.

---

## Module interaction map

```
                        ┌─────────────────────────────┐
                        │     Browser (static/)       │
                        │       index.html            │
                        └──────────────┬──────────────┘
                                       │ REST + MCP (HTTP)
                                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                          core/server.py                            │
│  imports:  db  scope  diff_store  query_advisor                    │
│            shodansnipe_core  llm  threat_feeds                     │
└───────┬────────────┬───────────┬───────────┬──────────────────────┘
        │            │           │           │
        ▼            ▼           ▼           ▼
   shodansnipe_   llm.py    threat_     (db, scope,
   core.py        →db       feeds.py    diff_store,
   →shodan,                 →db         query_advisor)
    aiohttp                              ← YOUR LOCAL FILES
                                            (see below)

┌──────────────────────────────────────────────────────────────────┐
│                    launchers/poc_crew.py                           │
│  imports via _bootstrap.py:                                        │
│     tools/shodansnipe_tools.py   (Shodan, scope, results, history) │
│     agents/nmap_recon_agent.py   (NMAP recon stage)                │
│       └── tools/nmap_tool.py     (NmapDiscoveryTool, NmapTriage)   │
│  talks to core/server.py over HTTP (REST API), not by import       │
└──────────────────────────────────────────────────────────────────┘
```

**Key point:** the crew (launchers/agents/tools) does NOT import the server
code. It talks to the running server over HTTP. That's why you start the
server first, then run the crew — they're separate processes that communicate
via the REST API and the `/mcp` endpoint.

---

## How imports resolve (_bootstrap.py)

Every entry point imports `_bootstrap` first. It adds `core/`, `tools/`,
`agents/` to `sys.path`, so flat imports like `import shodansnipe_tools` or
`import db` work no matter which folder you launch from.

```python
import _bootstrap   # must be the first local import
from shodansnipe_tools import ShodanSearchTool   # now resolves
```

`core/server.py` doesn't need the bootstrap — Python automatically puts a
script's own directory on the path, so its siblings (`db`, `llm`, etc.) resolve
when you run `python core/server.py`.

---

## Required local `core/` modules

These four modules are imported by `core/server.py` and `core/llm.py` /
`core/threat_feeds.py`. They hold your database and scope logic. If they are
not present in `core/`, the server will not start.

| Module | What server.py uses from it |
|--------|----------------------------|
| `db.py` | `init`, `get_config`, `set_config`, `delete_config`, `search_record`, `search_history`, `search_load`, `search_delete`, `saved_add`, `saved_list`, `saved_delete`, `audit_tail`, `ai_message_add`, `ai_session_history`, `ai_all_sessions`, `ai_latest_session`, `workspace_save`, `workspace_list`, `workspace_load`, `workspace_delete` |
| `scope.py` | `Scope` (dataclass), `apply_scope`, `audit` |
| `diff_store.py` | `save_snapshot`, `diff` |
| `query_advisor.py` | `FILTER_REFERENCE`, `TEMPLATES`, `render_template`, `suggest_followups` |

**Action:** copy your existing `db.py`, `scope.py`, `diff_store.py`, and
`query_advisor.py` into `core/` alongside `server.py`. They were part of your
original project; they just need to live in `core/` now.

---

## pip dependencies

See `requirements.txt`. Summary:

| Used by | Packages |
|---------|----------|
| Server | fastapi, uvicorn, shodan, aiohttp, pydantic, requests |
| Crew | crewai (>=0.86, Python 3.12) |
| NMAP stage | the `nmap` binary (not pip — install via OS package manager) |

---

## Verifying everything connects

From the project root:

```bash
# 1. Server side — should start without ImportError
cd core && python server.py        # Ctrl-C after it binds the port

# 2. Crew side — should print the agent list without ImportError
cd launchers && python poc_crew.py  # will prompt for scope or read from server
```

If the crew prints `[NMAP] Active recon stage ENABLED`, the NMAP agent wired in
correctly. If you see `disabled (passive Shodan only)`, either `ENABLE_NMAP=0`
or the nmap tooling failed to import.
