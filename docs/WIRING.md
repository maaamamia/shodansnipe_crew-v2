# Wiring pick-your-crew + settings into the two files I don't have

Everything else is done and verified (`settings.py`, `cli.py`, `server.py`
endpoints, the UI panel). These two files weren't in the upload — here are the
exact drop-ins. Both are small.

---

## 1. `launchers/poc_crew.py` — build only the selected stages

The server/CLI set `CREW_STAGES` (e.g. `recon,vuln,report`). Read it and assemble
only those agents. Replace the fixed "build all four" block with this shape:

```python
import os, settings   # settings.py is importable via _bootstrap / sys.path

STAGES      = set(settings.selected_stage_keys()
                  if not os.environ.get("CREW_STAGES")
                  else os.environ["CREW_STAGES"].split(","))
MAX_RESULTS = int(os.environ.get("SHODAN_MAX_RESULTS", str(settings.max_results())))

agents, tasks = [], []

# recon is always present (it produces the data the others consume)
recon = build_recon_agent(llm); agents.append(recon)
recon_tasks = build_recon_tasks(recon, TARGET_ORG, TARGET_SCOPE)
tasks += recon_tasks
last = recon_tasks[-1]

if "nmap" in STAGES:
    nm = build_nmap_agent(llm); agents.append(nm)
    nm_tasks = build_nmap_tasks(nm, prior_task=last)
    tasks += nm_tasks; last = nm_tasks[-1]

if "vuln" in STAGES:
    v = build_vuln_agent(llm); agents.append(v)
    # match YOUR build_vuln_tasks signature (it varies between versions):
    v_tasks = build_vuln_tasks(v, recon_output=str(last.output or ""), auth_output="")
    tasks += v_tasks; last = v_tasks[-1]

if "report" in STAGES:
    rp = build_report_agent(llm); agents.append(rp)
    tasks += build_report_tasks(rp, prior_tasks=[t for t in tasks if t])

crew = Crew(agents=agents, tasks=tasks, process=Process.sequential, verbose=True)
print(f"[crew] stages: {' -> '.join(k for k in ['recon','nmap','vuln','report'] if k in STAGES)}")
```

That's the whole feature on the orchestrator side: `if "<stage>" in STAGES`.

---

## 2. `tools/shodansnipe_tools.py` — limit from settings (clamp, don't reject)

This is the file that threw `limit must be <= 100`. Two changes: drop the `le=`
bound so Pydantic stops rejecting, and clamp in `_run` using `settings`.

```python
import settings   # central limits

class ShodanSearchInput(BaseModel):
    query:  str  = Field(..., description="One Shodan query; no OR/AND/NOT. Quote comma values: org:\"Company, Inc\"")
    limit:  int  = Field(default_factory=settings.max_results, ge=1,
                         description="Max results; clamped to the configured hard cap")
    enrich: bool = Field(False, description="Add InternetDB CVE/hostname data (slower)")

class ShodanSearchTool(BaseTool):
    name: str = "shodan_search"
    args_schema: type = ShodanSearchInput
    def _run(self, query: str, limit: int | None = None, enrich: bool = False) -> str:
        limit = settings.clamp_results(limit if limit is not None else settings.max_results())
        # …unchanged: POST to /api/search with the clamped limit…
```

Apply the same `cve_intel` path fix you already have in `mcp_tools.py`
(`/api/llm/cve-intel`, not `explain-cve`) and route `get_results` through
`/api/history` — `shodansnipe_tools.py` has the same two stale paths.

---

Send me `poc_crew.py` and `shodansnipe_tools.py` and I'll apply these directly and
re-verify, the same way I did `server.py`.
