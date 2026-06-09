# ShodanSnipe AI — Project Structure

This is the organised layout. Each folder has one job. To add capabilities,
follow the skill docs in `skills/`.

```
shodansnipe/
│
├── _bootstrap.py      Import-path setup. Every launcher imports this first.
├── requirements.txt   pip dependencies
├── STRUCTURE.md       This file
├── DEPENDENCIES.md    Module interaction map + required local core modules
│
├── core/              The engine. Rarely changes.
│   ├── server.py            FastAPI server: REST API + MCP server + DB
│   ├── shodansnipe_core.py  Shodan query execution, rate limiting, risk scoring
│   ├── llm.py               LLM client: goal→query, CVE intel, summarise
│   └── threat_feeds.py      C2 tracker / STIX-TAXII feed crawler
│
├── agents/            One file per crew agent — the official team roster.
│   ├── recon_agent.py        Attack Surface Reconnaissance Specialist
│   ├── nmap_recon_agent.py   Stealthy Network Reconnaissance Specialist
│   ├── vuln_agent.py         Vulnerability Intelligence Analyst
│   ├── report_agent.py       Security Report Writer
│   ├── example_crew.py       Assembles the team into a simple sequential crew
│   └── example_crew_mcp.py   Same, but via the MCP adapter (auto tool discovery)
│
├── tools/             CrewAI tool wrappers. ADD NEW TOOLS HERE.
│   ├── shodansnipe_tools.py NMAP search, results, scope, CVE, history
│   └── nmap_tool.py         NmapDiscoveryTool, NmapTriageTool
│
├── skills/            How to extend the system. READ THESE FIRST.
│   ├── BUILDING_AGENTS.md   The repeatable pattern for adding an agent
│   └── BUILDING_TOOLS.md    The repeatable pattern for adding a tool
│
├── launchers/         Entry points you actually run.
│   ├── poc_crew.py          The orchestrator — wires all agents into a pipeline
│   ├── run_server.bat       Start the FastAPI server (run this first)
│   ├── crewai.bat           Run the crew (reads scope + mode from server)
│   └── setup_crewai.bat     One-time Python 3.12 venv + deps + nmap check
│
├── static/
│   └── index.html           The web console (served by core/server.py)
│
└── docs/
    ├── README.md            Full feature documentation
    ├── CREWAI_SETUP.md      Step-by-step crew setup + env vars
    └── sec598_submission.md SEC598 coin submission writeup
```

---

## The crew pipeline

```
MANAGER ──────────────── validates scope, enforces order, writes final report
   │
   ├─ RECON SPECIALIST ──── passive recon: maps the attack surface (Shodan)
   │
   ├─ NMAP RECON ────────── active recon: confirm live + triage
   │                        hands off a prioritised list to →
   │                        ┌─────────────────────────────────────┐
   │                        │  SENIOR NETWORK OPERATOR (human)     │
   │                        │  does intensive testing on HIGH hosts│
   │                        └─────────────────────────────────────┘
   │
   ├─ VULN ANALYST ──────── CVE cross-reference, detection queries, severity
   │
   └─ REPORT WRITER ─────── synthesises everything into the executive report

Every agent is a standalone module in agents/ — reusable, individually
testable, and individually visualisable. They are the official team roster.
```

The NMAP recon agent sits between passive Shodan recon and human specialist
testing. It confirms what's *actually* live (Shodan data can be stale), then
produces a ranked HIGH/MEDIUM/LOW hand-off so the specialist spends their
intensive-testing time where it matters most.

---

## Running it

### First time
```bat
cd launchers
setup_crewai.bat            REM one-time venv
```

### Every run
```bat
REM 1. Start the server (separate terminal)
cd core
python server.py

REM 2. Run the crew
cd launchers
crewai.bat anthropic        REM reads scope + autonomy mode from the UI
```

The web console is at http://127.0.0.1:8000

### Toggling the NMAP stage
```bat
set ENABLE_NMAP=1     REM active scanning ON  (default if nmap installed)
set ENABLE_NMAP=0     REM passive Shodan only (no active scanning)
```

NMAP must be installed for the active stage:
- Windows: `choco install nmap`
- Linux: `sudo apt install nmap`
- Mac: `brew install nmap`

---

## Adding a new agent (the short version)

1. Write the tool in `tools/your_tool.py` (see `skills/BUILDING_TOOLS.md`)
2. Write the agent in `agents/your_agent.py` (see `skills/BUILDING_AGENTS.md`)
3. Import and insert it in `launchers/poc_crew.py` at the right pipeline position
4. Test in isolation, then run the full crew

The NMAP agent is your worked example — copy its shape.

---

## Safety model

- **Scope enforcement is in code, not just prompts.** The NMAP tool refuses to
  scan any IP outside the active scope, regardless of what the LLM asks.
- **The NMAP agent does discovery only.** No exploits, no brute force, no
  intrusive scripts. It enumerates and prioritises; the human specialist decides
  what intensive testing to perform.
- **HITL preserved.** In `hitl` autonomy mode, every scan action requires
  approval. The intensive-testing decision always stays with the human operator.
