# SEC598 Challenge Coin Submission
## ShodanSnipe AI — Agentic Attack Surface Management Console

**Submitter:** Miguel  
**Course:** SEC598 — AI Red Teaming & Security Automation  
**Submission Type:** Automation + Documentation

---

## PART 1 — Security & Business Requirements

### The Problem

Security teams running external attack surface management (ASM) today face three compounding problems:

**1. Query fatigue and blind spots.**  
Analysts know Shodan is valuable but manually crafting effective queries is slow, inconsistent, and highly dependent on individual expertise. A junior analyst running `org:"Acme Corp"` misses dozens of exposure vectors that an experienced operator would catch — expired certificates, exposed management APIs, database ports, cloud-native service endpoints, product-specific version fingerprinting. The result is a systematically incomplete picture of the attack surface.

**2. No adversarial reasoning.**  
Traditional ASM tools report what exists. They do not reason about what a threat actor would do *next*. Finding an exposed Apache 2.4.49 server requires a human to then ask: "Is that the Log4Shell-era version? What other services run alongside it? Does the SSL cert subject reveal related infrastructure?" This pivot reasoning takes time and expertise that most teams do not have at scale.

**3. Results without context.**  
Raw Shodan results are lists of IPs. They do not automatically map to MITRE ATT&CK techniques, attribute to threat actor clusters, or produce prioritised remediation guidance. An analyst still has to synthesise this manually — often under time pressure and after a long recon session.

### Security Requirements

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| SR-01 | System must accept multi-format scope (org name, CIDR, ASN, hostname, free-form Shodan syntax) and validate it before any automated action executes | Critical |
| SR-02 | All autonomous actions must respect a human-in-the-loop (HITL) control: each action requires explicit approval, scoped approval (within scope only), or full autonomous with audit log | Critical |
| SR-03 | System must deduplicate findings across all searches — the same IP counted once with merged CVEs and ports, not inflated by multiple queries | High |
| SR-04 | Search limits must be credit-aware: reduce result caps automatically when Shodan query credits fall below thresholds (80% → 200, 50% → 100, 20% → 50, <20% → 25) | High |
| SR-05 | Pivot queries must be generated from ACTUAL live results — not static templates. Version strings, cert subjects, ASNs observed in results must drive next queries | High |
| SR-06 | Final intelligence output must map to specific MITRE ATT&CK technique IDs (T-numbers) based on what was found, not generic lists | Medium |
| SR-07 | All scope settings, autonomy mode, and audit events must persist server-side so the CLI crew and the web UI remain in sync | Medium |
| SR-08 | The system must expose its tools via Model Context Protocol (MCP) so any MCP-compatible AI host (Claude Desktop, Cursor, etc.) can invoke ShodanSnipe capabilities | Medium |

### Business Requirements

| Req ID | Requirement |
|--------|-------------|
| BR-01 | A security analyst with no Shodan expertise must be able to run a comprehensive recon session by specifying only an org name or domain |
| BR-02 | The system must produce an executive-ready report in under 10 minutes for a typical target with <500 exposed hosts |
| BR-03 | Results must be filterable and viewable by scope, by search, across all historical sessions — not just the current run |
| BR-04 | The system must run locally on Windows without cloud dependencies for sensitive targets |

---

## PART 2 — The Automation (Code)

*(Code files attached separately — see file list below)*

### Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│              ShodanSnipe Web Console                │
│         (index.html — single-file SPA)              │
│                                                     │
│  Nav: AI Analyst │ Query Builder │ Results │ History │
│       MCP Config │ CVE Intel     │ Findings          │
│                                                     │
│  Results Panel:                                     │
│  ┌─ SOURCE ─────────────────────────────────────┐  │
│  │ [Current Search] [All History] [By Scope]    │  │
│  └──────────────────────────────────────────────┘  │
│  ┌─ FILTERS ────────────────────────────────────┐  │
│  │ Risk │ Scope │ Port │ Org │ Country │ CVE │ ASN│  │
│  └──────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
              │ REST API + MCP endpoint
              ▼
┌─────────────────────────────────────────────────────┐
│              FastAPI Server (server.py)             │
│                                                     │
│  /api/search      /api/scope      /api/health       │
│  /api/llm/*       /api/history    /api/config/*     │
│  /mcp  ← JSON-RPC 2.0 MCP server                   │
│                                                     │
│  Encrypted SQLite DB (passphrase-protected)         │
└─────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────┐
│           CrewAI Threat-Hunting Crew                │
│                  (poc_crew.py)                      │
│                                                     │
│  MANAGER Agent                                      │
│  ├─ Validates scope before any search               │
│  ├─ Enforces deduplication in final report          │
│  └─ Produces executive report                       │
│                                                     │
│  RESEARCHER Agent                                   │
│  ├─ Runs 14-16 dynamic searches (credit-aware limit)│
│  ├─ Deduplicates by IP across all searches          │
│  └─ Generates data-driven pivot queries             │
│                                                     │
│  ANALYST Agent                                      │
│  ├─ Maps findings to MITRE ATT&CK T-IDs             │
│  ├─ Attributes threat actor patterns                │
│  └─ Produces prose intelligence assessment          │
│                                                     │
│  ┌─ AUTONOMY MODES ──────────────────────────────┐  │
│  │ HITL     → every action requires approval     │  │
│  │ Scoped   → auto-approve within scope          │  │
│  │ Full Auto → no confirmation, audit always on  │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

### Files Submitted

| File | Purpose |
|------|---------|
| `server.py` | FastAPI backend — Shodan API, LLM endpoints, MCP server, encrypted DB |
| `index.html` | Single-file web console — query builder, results with multi-filter, AI analyst, history |
| `poc_crew.py` | CrewAI three-agent crew — dynamic search plan, dedup, MITRE mapping |
| `shodansnipe_tools.py` | CrewAI BaseTool wrappers for all six ShodanSnipe API endpoints |
| `shodansnipe_core.py` | Shodan query execution, result serialisation, risk scoring |
| `crewai.bat` | Windows launcher — reads scope + autonomy mode from running server |
| `llm.py` | LLM abstraction — goal-to-query, ask, summarise, CVE intel, cluster analysis |
| `threat_feeds.py` | C2 tracker / STIX/TAXII feed integration |
| `example_crew.py` | Simple crew example using BaseTool wrappers |
| `example_crew_mcp.py` | MCP adapter crew — auto-discovers tools from /mcp endpoint |

### Key SEC598 Concepts Used

| Concept from Class | Implementation |
|-------------------|----------------|
| **Agentic AI workflows** | Three-agent CrewAI crew with Manager, Researcher, Analyst roles and sequential task execution |
| **MCP (Model Context Protocol)** | Full MCP server at `/mcp` exposing 6 tools; also MCP client integration via `example_crew_mcp.py` |
| **Human-in-the-Loop (HITL)** | Three autonomy modes (HITL / Scoped / Full Auto) persisted server-side and enforced in bat launcher |
| **LLM-powered security tools** | Goal-to-query translation, CVE advisory parsing, threat intel prose generation, MITRE TTP mapping |
| **Attack Surface Management** | Scope-aware Shodan searches, deduplication, risk scoring, pivot query generation |
| **Prompt engineering** | Dynamic search plan prompts, analyst backstory tuning, structured output schemas |
| **Tool use / function calling** | BaseTool wrappers with Pydantic input schemas validated before every Shodan call |

---

## PART 3 — How the Automation Meets the Requirements

### SR-01: Multi-format scope input ✓
The ⚙ Config dropdown includes a multi-tag scope builder that accepts:
- Org names → `org:"SANS Institute"`  
- CIDRs → `net:203.0.113.0/24`  
- Domains/hostnames → `hostname:sans.org`  
- ASNs → `AS14618`  
- Free-form Shodan syntax → `http.title:"Login" country:US`

All are combined into a single scope query string, stored server-side (`/api/scope`), and read by the CrewAI bat before the crew starts. If scope is undefined, the Manager agent stops and prompts before any search runs.

### SR-02: HITL autonomy control ✓
Three modes implemented end-to-end:
- **HITL**: `confirm_action()` in `poc_crew.py` prints each proposed action and waits for `y/n` input
- **Scoped**: auto-approves all actions; scope was validated at startup
- **Full Auto**: auto-approves + prints `[AUTO]` prefix; bat prompts for written confirmation before starting

Mode is stored in the encrypted DB via `/api/config/autonomy`, read by `crewai.bat` via PowerShell at startup, and synced to the UI on page load. Selecting a radio button in the MCP Config panel immediately POSTs to the server — bat and UI always agree.

### SR-03: Deduplication ✓
The Researcher agent's task description includes an explicit **Deduplication Rule**: if the same IP appears in multiple searches, it is counted once with merged ports and CVEs. The Manager's backstory enforces this in the final report. The report structure uses "## Unique Hosts Found" not raw result counts. The Findings panel in the web UI (`loadAllFindings()`) performs client-side dedup across all history searches with the same merging logic.

### SR-04: Credit-aware limits ✓
`_get_search_limit()` calls `/api/health` before the crew starts, reads `query_credits_remaining` and `query_credits_limit`, and returns 200/100/50/25 based on the percentage remaining. The limit is printed at startup and passed into all 14-16 search tasks. On free-tier or unknown plans it defaults to 100.

### SR-05: Data-driven pivot queries ✓
`build_search_plan()` generates a dynamic search catalogue from the actual scope components (not static templates). The Researcher task description includes:
- **Pivot Rule**: instructions for what to do when specific findings appear (unexpected ASN → `asn:` search, version string → CVE check, SSL CN → `hostname:` search)
- **Dynamic Pivot Queries**: explicit instruction to generate 3-5 new queries referencing specific data from results (exact version strings, cert subjects, etc.)
- The static 3-search plan (`Search 1/2/3`) is replaced with 14-16 searches across remote access, web, databases, TLS, HTTP titles, products, cloud/DevOps, and network devices

### SR-06: MITRE ATT&CK mapping ✓
The Analyst agent's backstory cites specific technique references ("If you see RDP exposed on port 3389, you reference TA0001 and specific sub-techniques"). The task description requires technique IDs (T1133, T1190 etc) mapped to specific findings, not generic lists. The agent is instructed to write prose not bullet lists, preventing template-filling behaviour.

### SR-07: Server-side persistence ✓
`/api/config/autonomy` (GET/POST) stores the MCP autonomy mode in the encrypted SQLite DB. `/api/scope` stores the full scope object including `extra_query`. `crewai.bat` reads both via PowerShell at startup using a temp-file approach to avoid Windows `for /f` empty-line issues. The UI syncs on load via `loadMcpMode()` → `G('/api/config/autonomy')`.

### SR-08: MCP server ✓
`server.py` exposes a full JSON-RPC 2.0 MCP endpoint at `/mcp` with 6 tools:
- `shodan_search`, `get_results`, `get_scope`, `set_scope`, `get_history`, `cve_intel`

`example_crew_mcp.py` uses `crewai.mcp.MCPServerAdapter` to auto-discover and use these tools. Any MCP-compatible host (Claude Desktop, Cursor, Windsurf) can connect to `http://127.0.0.1:8000/mcp` and immediately use ShodanSnipe as a toolset.

### Business Requirements

**BR-01** — A user specifies `SANS, sans.org` in the scope box. The system auto-parses to `org:"SANS" hostname:sans.org`, builds 14+ searches across all attack surface categories, runs them, deduplicates, and produces a report. Zero Shodan expertise required.

**BR-02** — Typical runtime for a 100-500 host target is 3-8 minutes depending on LLM speed. The crew produces an executive report with 7 structured sections under 800 words.

**BR-03** — The Results panel SOURCE selector shows Current Search / All History / By Scope with 8 live filter chips (Risk, Port, Org, Country, Product, CVE, ASN, Scope). The Findings panel provides full cross-search dedup with CSV export.

**BR-04** — Runs entirely locally on Windows. All dependencies are pip-installable. No cloud account required beyond the LLM API key and Shodan API key.

---

## Summary

ShodanSnipe AI demonstrates the practical application of the SEC598 curriculum to a real security problem — external attack surface management — that most organisations either outsource expensively or do inconsistently. The automation addresses the gap between "we have Shodan access" and "we have a systematic, repeatable, AI-augmented process for understanding our exposure."

The three-agent CrewAI architecture with HITL controls, MCP integration, and dynamic prompt engineering directly applies the agentic security automation concepts from the course. The Human-in-the-Loop design reflects the course's emphasis on the "dangerous gap between automation and autonomy" — the system is capable of full autonomous operation but defaults to human confirmation, with explicit acknowledgment required to escalate.

