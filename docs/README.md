# ShodanSnipe AI

**Agentic attack surface management console powered by CrewAI, FastAPI, and Shodan.**

ShodanSnipe turns Shodan into a systematic, AI-augmented recon workflow. A three-agent CrewAI crew automatically plans searches based on your scope, deduplicates findings across all queries, maps results to MITRE ATT&CK techniques, and produces an executive threat report — with Human-in-the-Loop controls at every step.

---

## What It Does

```
You define a scope  →  Crew plans 14+ searches  →  Results deduplicated  →  MITRE-mapped intel report
org:"Acme Corp"         Remote access, web,             Same IP across          T1133, T1190,
hostname:acme.com       databases, TLS, admin           queries = 1 finding     risk verdict,
net:203.0.113.0/24      panels, cloud APIs…             with merged CVEs        remediation actions
```

The web console runs locally in your browser. The CrewAI crew runs from the command line. Both talk to the same FastAPI server, which also exposes a full MCP server so any MCP-compatible AI host can use ShodanSnipe as a toolset.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│               Browser — ShodanSnipe Console             │
│                    http://localhost:8000                 │
│                                                         │
│  ┌──────────┐ ┌───────────┐ ┌─────────┐ ┌───────────┐  │
│  │ AI       │ │ Query     │ │ Results │ │ History   │  │
│  │ Analyst  │ │ Builder   │ │ +Filter │ │ by Search │  │
│  │          │ │ +Library  │ │         │ │ by Scope  │  │
│  └──────────┘ └───────────┘ └─────────┘ └───────────┘  │
│  ┌──────────┐ ┌───────────┐ ┌─────────────────────────┐ │
│  │ MCP      │ │ CVE Intel │ │ Findings (cross-search  │ │
│  │ Config   │ │           │ │ dedup view)             │ │
│  └──────────┘ └───────────┘ └─────────────────────────┘ │
└─────────────────────────┬───────────────────────────────┘
                          │  REST API + MCP endpoint
                          ▼
┌─────────────────────────────────────────────────────────┐
│               FastAPI Server  (server.py)               │
│                                                         │
│  Shodan search  │  LLM endpoints  │  Session history    │
│  Scope storage  │  CVE intel      │  Audit log          │
│  Saved queries  │  Workspaces     │  Threat feeds       │
│                                                         │
│  /mcp  ←  JSON-RPC 2.0 MCP server (6 tools)            │
│                                                         │
│  Encrypted SQLite  (passphrase-protected at startup)    │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│          CrewAI Threat-Hunting Crew  (poc_crew.py)      │
│                   run via  crewai.bat                   │
│                                                         │
│  MANAGER    validates scope · enforces dedup · report   │
│  RESEARCHER 14+ dynamic searches · pivot from findings  │
│  ANALYST    MITRE TTPs · threat actor patterns · prose  │
│                                                         │
│  Autonomy:  HITL  │  Scoped  │  Full Auto              │
│  Limits:    credit-aware (200 / 100 / 50 / 25)         │
└─────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.12 | Required for CrewAI; earlier versions have wheel issues |
| Shodan API key | Any | Free key works; paid unlocks `vuln:`, higher limits |
| LLM API key | Any | Anthropic, OpenAI, or local Ollama |

Install server dependencies:

```bash
pip install fastapi uvicorn shodan requests pydantic
```

### 2. Start the Server

```bash
python server.py
```

You will be prompted for a **passphrase** on first run — this encrypts the local database. Use the same passphrase every time. There is no recovery if lost.

Open **http://localhost:8000** in your browser.

### 3. Configure

Click **⚙ Config** in the top-right corner:

- **◈ Scope** — add your target as org name, CIDR, domain, ASN, or free-form Shodan syntax
- **⬡ API Key** — enter your Shodan API key
- **✦ AI Model** — choose Anthropic / OpenAI / Ollama and enter the model name and key

### 4. Run a Search

Type a Shodan query in the Query Builder panel and press **RUN**, or describe your goal in the AI Analyst panel and let it build a query queue for you.

### 5. Run the CrewAI Crew (optional)

```bat
# One-time setup
setup_crewai.bat

# Run the crew (reads scope and autonomy mode from the running server)
crewai.bat anthropic          # Claude, mode from UI
crewai.bat openai             # OpenAI, mode from UI
crewai.bat anthropic scoped   # Override to scoped autonomous
crewai.bat anthropic full     # Override to full autonomous
```

> **Note:** Do not include a leading dash — use `crewai.bat anthropic` not `crewai.bat -anthropic`

---

## File Reference

| File | Purpose |
|------|---------|
| `server.py` | FastAPI backend — all API endpoints, MCP server, DB management |
| `index.html` | Single-file web console — drop into `static/` folder |
| `shodansnipe_core.py` | Shodan query engine — rate limiting, result serialisation, risk scoring |
| `llm.py` | LLM abstraction — goal-to-query, CVE intel, summarise, rank, explain |
| `threat_feeds.py` | C2 tracker and STIX/TAXII feed crawler |
| `poc_crew.py` | Three-agent CrewAI crew with dynamic search plan |
| `shodansnipe_tools.py` | CrewAI `BaseTool` wrappers for the REST API |
| `example_crew.py` | Simple example crew using tool wrappers |
| `example_crew_mcp.py` | Example crew using the MCP adapter (auto-discovers tools) |
| `crewai.bat` | Windows launcher — reads scope + mode from server, runs crew |
| `setup_crewai.bat` | One-time Python 3.12 venv setup for CrewAI |

---

## Web Console Panels

### AI Analyst
Type your goal in plain English. The AI builds a queue of validated Shodan queries — you approve before anything runs (or set autonomous mode to skip approval). Includes a persistent **Guidance** field where you can store context that applies to all sessions ("We use AWS and Azure, prioritise RDP exposure, our ASN is AS64512").

### Query Builder
Direct Shodan query input with:
- Filter library (30+ categorised filters, tier-aware)
- Template library with parameterised templates
- Live syntax validator that catches OR/AND/NOT, wildcards, and paid-filter violations before you run
- Diff mode — compare against a previous snapshot to see what changed

### Results
- **SOURCE selector**: Current Search / All History / By Scope — load any historical results into the table without re-running searches
- **Filter bar**: Risk · Scope · Port · Org · Country · Product · CVE · ASN — all populate dynamically from the loaded results
- **Text search**: searches across IP, org, CVE, hostname, banner, SSL subject, tags
- Sortable columns, column picker, CSV/JSON export

### History
Four tabs: By Search (with live filter) · By Scope (grouped by active scope at run time) · Saved · Audit Log

### Findings
Cross-search deduplication view. Click **Load All** to pull every historical search, merge by IP address (same IP across 10 searches = 1 entry with combined CVEs and ports), and display grouped by Risk / Search / Org / Port. Includes a Search filter chip and CSV export.

### MCP Config
Three tabs:
- **Settings**: MCP Autonomy Mode (HITL / Scoped / Full Auto), scope enforcement, Shodan Snipe autonomy flag, crew agent role reference, usage & limits (Shodan credits + session token cost with per-model pricing)
- **MCP**: External MCP server configuration — push results, queries, and audit logs to other MCP endpoints

### CVE Intel
Paste any CVE advisory, NVD entry, vendor bulletin, or threat intel article. The AI extracts CVE IDs, severity, affected products, and generates scoped Shodan detection queries. Queries can be auto-queued for approval or saved.

---

## Scope Configuration

The **◈ Scope** tab in the ⚙ Config dropdown is a multi-tag builder:

**Structured tags** — type any value and press Enter or comma to add it as a typed tag:

| Input | Auto-detected type | Shodan query |
|-------|-------------------|--------------|
| `Acme Corp` | org | `org:"Acme Corp"` |
| `acme.com` | hostname | `hostname:acme.com` |
| `203.0.113.0/24` | CIDR | `net:203.0.113.0/24` |
| `AS64512` | ASN | `AS64512` |
| `ssl.cert.subject.cn:acme.com` | ssl | appended verbatim |

Tags show as coloured pills with a × to remove. Use the **Quick Add** buttons (+ org, + net, + hostname, + ASN, + SSL cert) to be prompted for each type.

**Free-form query** — a second textarea below the tags for raw Shodan syntax that cannot be expressed as a typed tag:

```
http.title:"Login" country:US -org:"Cloudflare" port:8443
```

This is appended verbatim to the structured tags. Supports all Shodan filter fields.

The **Shodan Query Preview** shows the combined query live as you type. Scope is stored server-side so `crewai.bat`, the crew, and the UI all share the same target without manual configuration.

---

## CrewAI Crew

### Three Agents

**MANAGER** — validates scope before any search runs; if scope is undefined, the crew stops and asks. Enforces deduplication in the final report (same IP across multiple searches = one finding with merged ports and CVEs). Produces the executive report.

**RESEARCHER** — runs a dynamic search plan built from the scope at runtime (not static templates). Pivots based on actual findings:
- Found an Apache version → checks that version against known CVEs
- Found an SSL cert subject → searches `hostname:<cert-cn>`
- Found an unexpected ASN → searches `asn:AS<number>`
- Found open management ports → investigates what services are running

**ANALYST** — reads the deduplicated results and writes 3-4 paragraphs of threat intelligence prose. Maps to specific MITRE ATT&CK technique IDs (T1133, T1190 etc) based on what was actually found. Attributes threat actor patterns where evidence supports it. Never uses bullet-list templates.

### Dynamic Search Plan

The Researcher runs 14-16 searches per session, generated from the scope:

| Category | What it checks |
|----------|---------------|
| Full scope surface | All scope terms combined — baseline exposure |
| Scope atoms | Each org/CIDR/ASN/hostname searched separately |
| Remote access | SSH (22), RDP (3389), VNC (5900), Telnet (23), FTP (21) |
| Web services | Ports 80, 443, 8080, 8443, 8000, 8888 |
| Databases | MySQL, Postgres, MSSQL, MongoDB, Redis, Elasticsearch |
| TLS | Expired SSL certificates |
| HTTP titles | Login pages, admin interfaces, dashboards |
| Products | Apache, Nginx, OpenSSH |
| Cloud/DevOps | Docker API (2375), Kubernetes API (6443) |
| Network devices | SNMP (161/162), Telnet |

### Credit-Aware Limits

The crew checks available Shodan query credits before starting and sets the result limit per search accordingly:

| Credits remaining | Result limit |
|-------------------|-------------|
| > 80% | 200 |
| 50 – 80% | 100 |
| 20 – 50% | 50 |
| < 20% | 25 |
| Unknown / free tier | 100 |

### Autonomy Modes

Set in the web UI under **MCP Config → Settings** or via `crewai.bat` argument:

| Mode | Behaviour |
|------|-----------|
| **HITL** (default) | Every action prints a confirmation prompt — `y` to approve, `n` to skip |
| **Scoped** | Auto-approves all actions; scope was validated at startup |
| **Full Auto** | No confirmation; bat asks for written "yes" before starting; audit log always on |

The selected mode is stored server-side and read by `crewai.bat` at startup — no need to pass an argument unless overriding.

---

## MCP Server

ShodanSnipe exposes a JSON-RPC 2.0 MCP endpoint at `http://localhost:8000/mcp`.

### Available Tools

| Tool | Description |
|------|-------------|
| `shodan_search` | Run a Shodan query — returns hosts with ports, CVEs, org, risk score |
| `get_results` | Return current in-memory results from the last search |
| `get_scope` | Return the active scope definition (orgs, CIDRs, ASNs, domains) |
| `set_scope` | Set scope from plain text — server parses automatically |
| `get_history` | Return recent search history with result counts |
| `cve_intel` | Analyse a CVE advisory → scoped Shodan detection queries |

### Using with Claude Desktop / Cursor / Windsurf

Add to your MCP host config:

```json
{
  "mcpServers": {
    "shodansnipe": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

### Using with CrewAI (MCP Adapter)

```python
from crewai import Agent, Crew, Task
from crewai.mcp import MCPServerAdapter

with MCPServerAdapter({"url": "http://localhost:8000/mcp"}) as tools:
    print(f"Discovered {len(tools)} tools: {[t.name for t in tools]}")

    analyst = Agent(
        role="Threat Analyst",
        goal="Map the attack surface of Acme Corp",
        backstory="Senior red team operator.",
        tools=tools,
    )

    task = Task(
        description='Set scope to "Acme Corp", run surface scan, report findings.',
        expected_output="Prioritised list of exposed hosts with risk levels.",
        agent=analyst,
    )

    Crew(agents=[analyst], tasks=[task]).kickoff()
```

### Using with CrewAI (Tool Wrappers — no MCP required)

```python
from shodansnipe_tools import (
    ShodanSearchTool, GetResultsTool, SetScopeTool,
    GetScopeTool, CVEIntelTool, GetHistoryTool,
)

tools = [
    ShodanSearchTool(),
    GetResultsTool(),
    SetScopeTool(),
    GetScopeTool(),
    CVEIntelTool(),
    GetHistoryTool(),
]

agent = Agent(role="...", goal="...", backstory="...", tools=tools)
```

---

## Shodan Tier Reference

| Feature | Free | Member ($49) | Corporate |
|---------|------|-------------|-----------|
| Basic filters (`org:`, `port:`, `hostname:`) | ✓ | ✓ | ✓ |
| `vuln:CVE-XXXX` matching | ✗ | ✓ | ✓ |
| `has_vuln:true` | ✗ | ✓ | ✓ |
| `has_screenshot:true` | ✗ | ✓ | ✓ |
| `tag:` filter | ✗ | ✗ | ✓ |
| Results per search | 100 | 1,000 | 10,000+ |

The console shows your plan tier in the topbar and dims paid filters you cannot use.

---

## AI Configuration

Supported providers (set under **⚙ Config → ✦ AI Model**):

| Provider | Models | Notes |
|----------|--------|-------|
| **Anthropic** | `claude-sonnet-4-6`, `claude-haiku-4-5`, `claude-opus-4-6` | Recommended — best query generation quality |
| **OpenAI** | `gpt-4o`, `gpt-4o-mini` | Good alternative |
| **Ollama** | `llama3.2`, any local model | Free; quality varies; set endpoint URL |

Estimated token cost per session is shown in the MCP Config settings tile and in the topbar token counter.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SHODANSNIPE_URL` | `http://127.0.0.1:8000` | Server URL for CrewAI tools |
| `SHODANSNIPE_PASSPHRASE` | *(prompt)* | DB encryption passphrase (skip interactive prompt) |
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `OLLAMA_URL` | `http://localhost:11434/v1` | Ollama endpoint |
| `LLM_PROVIDER` | `openai` | Default LLM for the crew (`anthropic` / `openai` / `ollama`) |
| `MCP_AUTONOMY_MODE` | `hitl` | Crew autonomy mode (`hitl` / `scoped` / `full`) |
| `TARGET_ORG` | *(prompt)* | Target org — set by `crewai.bat` from server scope |
| `TARGET_SCOPE` | *(prompt)* | Full scope query — set by `crewai.bat` from server scope |
| `CVE_ADVISORY` | — | Optional CVE text to include in analyst task |

---

## Troubleshooting

**Page loads but filters/templates are empty**  
The Query Builder's library falls back to built-in filters if the server returns nothing. Open the Query panel — filters appear in the FILTERS tab. If they are still blank, check that `server.py` is running and `/api/filters` returns JSON.

**`crewai.bat anthropic` shows `LLM: -anthropic`**  
Do not include a leading dash. Use `crewai.bat anthropic` not `crewai.bat -anthropic`.

**Autonomy mode always shows HITL despite UI setting**  
The server needs the new `/api/config/autonomy` endpoint — use the updated `server.py` from this release. The UI POSTs the mode to the server when you click a radio button.

**Scope shows empty in crew even though it is set in UI**  
The `crewai.bat` PowerShell scope-fetch writes to a temp file and reads back `SCOPE_NAME` and `SCOPE_QUERY` — check that PowerShell execution is not blocked. Run `crewai.bat` from a terminal where PowerShell is available.

**`await is only valid in async functions` on page load**  
This error means a stale `index.html` is being served. Replace `static/index.html` with the latest version and hard-refresh the browser (Ctrl+Shift+R).

**DB passphrase prompt hangs when running as a service**  
Set `SHODANSNIPE_PASSPHRASE` as an environment variable to skip the interactive prompt.

---

## Licence

MIT — see `LICENSE` for details.

---

*Built for SEC598 · SANS Institute · Attack Surface Management + Agentic AI*
