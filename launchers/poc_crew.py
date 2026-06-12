"""
poc_crew.py — ShodanSnipe Parallel Crew Orchestrator v2

Architecture — the MANAGER (ASM) is the spine; it plans, owns scope, loops, and correlates:

  PHASE 0 — MANAGER (ASM): scope expansion + HUNT PLAN
            creative pivots, hypotheses, top blind-spots → directives to every agent
                              │
  ┌───────────────────────────────────────────────────────────────┐
  │            PHASE 1 (PARALLEL) — SEED, then EXPAND              │
  │                                                               │
  │   OSINT AGENT  (the SEED — a starting point, NEVER the limit) │
  │     cert transparency · ASN validation · cloud assets         │
  │     historical DNS · reverse WHOIS · scope_advisor            │
  │     → PROPOSES validated scope + a BROAD seed query package    │
  │                            ║                                  │
  │   RECON AGENT  (EXPANDS far beyond the seed)                  │
  │     ASN→Shodan · DNS posture · big→targeted funnel            │
  │     dynamic/combinatorial queries · FULL host inventory       │
  │     Nmap (live port confirmation, skill)                      │
  └───────────────────────────────────────────────────────────────┘
                              │
  PHASE 1.6 — MANAGER (ASM): scope RECONCILIATION  (FINAL authority)
              locks scope from observed metadata; routes the gaps
                              │
  PHASE 1.7 — REFINE LOOP  ↺  (bounded by REFINE_MAX_LOOPS; repeats until covered)
              gaps → OSINT re-verify + RECON re-sweep → re-reconcile →
              loops back into Phase 1 until NO new in-scope surface appears
                              │
  ┌───────────────────────────────────────────────────────────────┐
  │                    PHASE 2 (SEQUENTIAL)                       │
  │   AUTH AGENT     →    VULN AGENT                              │
  │   auth type / exposed paths     CVE → evidence-gated severity │
  └───────────────────────────────────────────────────────────────┘
                              │
  PHASE 2.5 — MANAGER (ASM): cross-agent CORRELATION
  PHASE 2.6 — THREAT INTEL: TTPs · attack chains · IOCs
                              │
  PHASE 3 — REPORT: full inventory · evidence-gated severities · no truncation

  Flow: OSINT SEEDS → RECON/others EXPAND → MANAGER RECONCILES → LOOP until the
  surface is fully covered. OSINT never caps scope; it kicks it off. The manager
  holds final authority and keeps the loop running until coverage is confident.

Usage:
    crewai.bat anthropic
    crewai.bat anthropic scoped
    crewai.bat anthropic full
    python poc_crew.py --provider anthropic --report brief
    python poc_crew.py --provider anthropic --no-auth
    python poc_crew.py --provider openai --model gpt-4o
    python poc_crew.py --provider ollama --model llama3.2
"""
from __future__ import annotations
import os, sys, json, argparse, re, datetime
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Bootstrap ─────────────────────────────────────────────────────────────────
# poc_crew.py lives in launchers/
# agents/ and tools/ are siblings of launchers/ (one level up)
LAUNCHERS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT  = os.path.dirname(LAUNCHERS_DIR)   # shodansnipe/
ROOT = LAUNCHERS_DIR  # keep ROOT for report saving

for p in [
    PROJECT_ROOT,
    os.path.join(PROJECT_ROOT, "agents"),
    os.path.join(PROJECT_ROOT, "tools"),
    LAUNCHERS_DIR,
]:
    if p not in sys.path:
        sys.path.insert(0, p)

SHODANSNIPE_URL = os.environ.get("SHODANSNIPE_URL", "http://127.0.0.1:8000")
AUTONOMY_MODE   = os.environ.get("MCP_AUTONOMY_MODE", "").lower()

ARCH_BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║  ShodanSnipe — ASM Crew Pipeline                              ║
║  the MANAGER (ASM) orchestrates every phase ↓                 ║
╟──────────────────────────────────────────────────────────────╢
║   0    PLAN ........ scope expansion + hunt plan              ║
║   1  ┌ OSINT ....... SEED: certs · ASN · cloud · DNS · WHOIS  ║
║      └ RECON ....... EXPAND: Shodan funnel · full inventory   ║
║   1.5  NMAP ........ live port confirmation (optional)        ║
║   1.6  RECONCILE ... MANAGER locks scope (final authority)    ║
║   1.7  LOOP  ↺ ..... refine until coverage is confident       ║
║   2    AUTH → VULN . exposure + evidence-gated severity       ║
║   2.5  CORRELATE ... MANAGER cross-agent patterns             ║
║   2.6  THREAT ...... TTPs · attack chains · IOCs              ║
║   3    REPORT ...... full inventory · no truncation           ║
╟──────────────────────────────────────────────────────────────╢
║  OSINT seeds → others EXPAND → MANAGER reconciles → LOOP      ║
╚══════════════════════════════════════════════════════════════╝"""


def print_arch_banner() -> None:
    """Print the pipeline at a glance. Suppress with CREW_NO_BANNER=1."""
    if os.environ.get("CREW_NO_BANNER", "").lower() not in ("1", "true", "yes", "on"):
        print(ARCH_BANNER)


def _load_autonomy_mode() -> str:
    """Read autonomy mode from server (UI setting), fall back to env var."""
    global AUTONOMY_MODE
    if AUTONOMY_MODE:  # env var override takes priority
        return AUTONOMY_MODE
    try:
        r = requests.get(f"{SHODANSNIPE_URL}/api/config/autonomy", timeout=5)
        if r.ok:
            return r.json().get("mode", "hitl")
    except Exception:
        pass
    return "hitl"  # safe default


def _confirm(msg: str) -> bool:
    if AUTONOMY_MODE == "full":
        print(f"[AUTO] {msg}")
        return True
    ans = input(f"\n{msg} (yes/no): ").strip().lower()
    return ans in ("yes", "y")


def check_server() -> dict:
    try:
        r = requests.get(f"{SHODANSNIPE_URL}/api/health", timeout=10)
        return r.json()
    except Exception as e:
        print(f"\n[ERROR] Cannot reach server at {SHODANSNIPE_URL}")
        print(f"        Start it first: uvicorn server:app --port 8000")
        print(f"        Error: {e}")
        sys.exit(1)


def get_scope() -> str:
    try:
        r = requests.get(f"{SHODANSNIPE_URL}/api/scope", timeout=10)
        d = r.json()
        if d.get("is_empty"):          # honor the server's explicit empty flag
            return ""
        # If the server ever supplies an explicit Shodan query, trust it.
        if d.get("query"):
            return d["query"]
        # Otherwise BUILD a real scope seed from the structured fields. NEVER fall back to
        # 'summary' — that is a human count string ("test: 1 domain(s), 1 org(s)") and using
        # it as the scope query corrupts target_org and every OSINT lookup downstream.
        orgs    = d.get("orgs") or []
        domains = d.get("domains") or []
        cidrs   = d.get("cidrs") or []
        asns    = d.get("asns") or []
        parts = []
        if orgs:
            parts.append(f'org:"{orgs[0]}"')      # primary org → also feeds target_org
        if domains:
            parts.append(f'hostname:{domains[0]}')  # primary domain
        if not parts:                              # no org/domain → anchor on net/asn
            if cidrs:
                parts.append(f'net:{cidrs[0]}')
            elif asns:
                a = str(asns[0])
                parts.append(f'asn:{a if a.upper().startswith("AS") else "AS"+a}')
        return " ".join(parts)                     # e.g. org:"test" hostname:test.com
    except Exception:
        return ""


def get_credits() -> tuple[int, int]:
    try:
        r = requests.get(f"{SHODANSNIPE_URL}/api/health", timeout=10)
        d = r.json()
        u = d.get("usage", {})
        return u.get("query_credits_remaining", 0), u.get("query_credits_limit", 100)
    except Exception:
        return 0, 0


def print_run_history(n: int = 6) -> None:
    """Show the last few captured runs at startup so terminal runs have visible history too."""
    try:
        r = requests.get(f"{SHODANSNIPE_URL}/api/runs", params={"limit": n}, timeout=10)
        runs = (r.json() or {}).get("runs", [])
    except Exception:
        return
    if not runs:
        print("[History] no prior runs recorded yet — this will be the first.")
        return
    print(f"[History] last {min(n, len(runs))} run(s):")
    for run in runs[:n]:
        when  = str(run.get("started_at", ""))[:19].replace("T", " ")
        scope = (run.get("scope") or run.get("target") or "(none)")
        if len(scope) > 38:
            scope = scope[:35] + "..."
        status = run.get("status", "")
        src    = run.get("source", "")
        tail   = f" · {status}" if status else ""
        tail  += f" · {src}" if src else ""
        print(f"          {when}  {scope}{tail}")


def record_run(record: dict) -> str | None:
    """Capture THIS run into the server's persisted history (best-effort, never fatal).
    Returns the run id if recorded. Works whether the crew was started from the CLI or the UI."""
    try:
        r = requests.post(f"{SHODANSNIPE_URL}/api/runs", json=record, timeout=10)
        return (r.json() or {}).get("recorded", {}).get("id")
    except Exception:
        return None


def extract_findings(report_md: str) -> list[dict]:
    """Parse the report's '### [N]. Title' finding blocks into structured records so they can be
    stored, shown on the GUI, and exported with enriched columns. Best-effort — unknown fields
    just pass through as extra columns."""
    findings: list[dict] = []
    # split into blocks that start at a numbered '### ' finding header
    blocks = re.split(r"\n(?=#{2,3}\s*\[?\d+[\.\)])", report_md or "")
    key_map = {
        "risk": "severity", "cvss": "cvss", "confidence": "confidence",
        "affected": "asset", "evidence": "evidence", "cves": "cve", "cve": "cve",
        "mitre": "mitre", "impact": "impact", "fix": "fix", "timeline": "timeline",
        "control surface": "control_surface", "scope": "scope",
    }
    for blk in blocks:
        m = re.match(r"#{2,3}\s*\[?\d+[\.\)]\]?\s*(.+)", blk.strip())
        if not m:
            continue
        title = re.split(r"\s+[—-]\s+", m.group(1).strip())[0].strip()[:200]
        rec: dict = {"title": title, "source": "report"}
        # pull every **Key:** value pair in the block
        for k, v in re.findall(r"\*\*\s*([^*:]+?)\s*:\*\*\s*([^*\n]*?)(?=\s*\*\*|\n|$)", blk):
            key = key_map.get(k.strip().lower())
            val = v.strip().rstrip("|").strip()
            if key and val:
                rec.setdefault(key, val)
        if len(rec) > 2:  # title + source + at least one real field
            findings.append(rec)
    return findings


def record_findings(findings: list[dict], run_id: str | None) -> int:
    """POST extracted findings to the server store (best-effort). Returns count recorded."""
    if not findings:
        return 0
    for f in findings:
        if run_id:
            f["run_id"] = run_id
    try:
        r = requests.post(f"{SHODANSNIPE_URL}/api/findings",
                          json={"findings": findings}, timeout=15)
        return (r.json() or {}).get("added", 0)
    except Exception:
        return 0


def build_llm(provider: str, model: str | None = None):
    from crewai import LLM
    try:
        from tools.cached_llm import make_llm as _make_llm, cache_status as _cache_status
    except ImportError:
        try:
            from cached_llm import make_llm as _make_llm, cache_status as _cache_status
        except ImportError:
            _make_llm = _cache_status = None

    # max_tokens MUST be explicit. Without it the provider default caps the completion and
    # silently truncates long analysis JSON / multi-section reports mid-stream — the root of
    # "the report is only 5 findings long". The server bridges the UI's "Report max tokens"
    # slider as REPORT_MAX_TOKENS; crewai.bat / CLI can also set LLM_MAX_TOKENS. Prefer the
    # canonical REPORT_MAX_TOKENS so the Control Center slider actually controls the cap.
    max_tokens = int(os.environ.get("REPORT_MAX_TOKENS")
                     or os.environ.get("LLM_MAX_TOKENS")
                     or "20000")

    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            print("\n[ERROR] ANTHROPIC_API_KEY not set.")
            print("        PowerShell: $env:ANTHROPIC_API_KEY = 'sk-ant-...'")
            sys.exit(1)
        m = model or "claude-sonnet-4-6"
        mt = max(max_tokens, 16000)            # Sonnet/Opus support large outputs
        print(f"[LLM] Anthropic — {m} (max_tokens={mt})")
        if _make_llm:
            llm = _make_llm(model=m, api_key=key, provider="anthropic",
                            max_tokens=mt, temperature=0.2)
            if _cache_status:
                st = _cache_status()
                if not st["prompt_cache_enabled"]:
                    mode = "off (PROMPT_CACHE=0)"
                elif st["automatic"]:
                    mode = "AUTO (crewai marks breakpoints, native provider stamps cache_control)"
                elif st["crewai_auto_breakpoints"] and not st["native_anthropic_provider"]:
                    mode = "INACTIVE — run: pip install \"crewai[anthropic]\" (native provider missing)"
                else:
                    mode = "litellm-inject (older crewai)"
                print(f"[LLM] prompt caching: {mode}")
            return llm
        return LLM(model=m, api_key=key, provider="anthropic",
                   max_tokens=mt, temperature=0.2)

    elif provider == "openai":
        key = os.environ.get("OPENAI_API_KEY", "")
        if not key:
            print("\n[ERROR] OPENAI_API_KEY not set.")
            sys.exit(1)
        m = model or "gpt-4o-mini"
        mt = min(max(max_tokens, 12000), 16000)  # gpt-4o-mini output ceiling ~16k
        print(f"[LLM] OpenAI — {m} (max_tokens={mt})")
        return LLM(model=m, api_key=key, max_tokens=mt, temperature=0.2)

    elif provider == "ollama":
        url = os.environ.get("OLLAMA_URL", "http://localhost:11434")
        m = model or "llama3.2"
        print(f"[LLM] Ollama — {m} at {url} (max_tokens={max_tokens})")
        return LLM(model=f"ollama/{m}", base_url=url, max_tokens=max_tokens, temperature=0.2)

    else:
        print(f"[ERROR] Unknown provider: {provider}. Use: anthropic, openai, ollama")
        sys.exit(1)


def run_crew_phase(agents, tasks, verbose=True) -> str:
    """Run a crew and return string output.
    
    Notes:
    - max_rpm limits LLM calls per minute to avoid Anthropic rate limits
    - Claude doesn't support assistant prefill (the "force_final_answer" 
      mechanism in older CrewAI versions). If you hit that error, upgrade:
      pip install "crewai>=0.80.0"
    """
    from crewai import Crew, Process
    crew = Crew(
        agents=agents,
        tasks=tasks,
        process=Process.sequential,
        verbose=verbose,
        max_rpm=10,          # max LLM calls/min — prevents Anthropic 429s
    )
    try:
        result = crew.kickoff()
        return str(result)
    except Exception as e:
        err = str(e)
        if "assistant message prefill" in err.lower():
            print(
                "\n[ERROR] CrewAI 'assistant prefill' error with Claude.\n"
                "Fix: upgrade CrewAI: pip install 'crewai>=0.80.0'\n"
                "Or switch provider: crewai.bat openai\n"
            )
        elif "maximum iterations" in err.lower():
            print(
                "\n[WARN] Agent hit max iterations. Partial results may be available.\n"
                "Consider: increase max_iter in agent config or simplify the task.\n"
            )
        raise


def main():
    # Version check — Claude requires CrewAI >= 0.80.0 to avoid assistant prefill errors
    try:
        import crewai
        version = tuple(int(x) for x in crewai.__version__.split(".")[:2])
        if version < (0, 80):
            print(f"[WARN] CrewAI {crewai.__version__} detected. Claude may hit 'assistant prefill' errors.")
            print("       Upgrade: pip install 'crewai>=0.80.0'")
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="ShodanSnipe Crew v2")
    parser.add_argument("provider", nargs="?", default="anthropic",
                        choices=["anthropic", "openai", "ollama"])
    parser.add_argument("mode", nargs="?", default=None,
                        choices=["hitl", "scoped", "full"])
    parser.add_argument("--model",   default=None, help="Override LLM model")
    parser.add_argument("--scope",   default=None, help="Override scope query")
    parser.add_argument("--report",  default="comprehensive",
                        choices=["comprehensive", "brief"],
                        help="Report style: comprehensive (default) or brief")
    parser.add_argument("--no-auth", action="store_true", help="Skip auth agent")
    parser.add_argument("--no-nmap", action="store_true", help="Disable nmap")
    parser.add_argument("--no-osint",   action="store_true", help="Skip OSINT agent")
    parser.add_argument("--no-threat",  action="store_true", help="Skip threat-intel agent")
    parser.add_argument("--refine", action="store_true",
                        help="After scope reconciliation, run ONE bounded extra recon pass on "
                             "the gaps it found (off by default — enable once the server keeps up).")
    parser.add_argument("--no-archive", action="store_true", help="Skip Wayback/ShodanURI enrichment")
    args = parser.parse_args()

    # ── Control Center integration ────────────────────────────────────────────
    # Honor the user's SAVED settings. When the server's Run button launches the crew it
    # passes CREW_STAGES/CREW_MODULES as env (explicit override). When you run crewai.bat
    # yourself, no env is set — so we ASK THE SERVER for the saved selection here. Either way
    # the crew obeys what you chose in the Control Center instead of a hardcoded default.
    if os.environ.get("CREW_STAGES") is None or os.environ.get("CREW_MODULES") is None:
        try:
            if os.environ.get("CREW_STAGES") is None:
                s = requests.get(f"{SHODANSNIPE_URL}/api/crew/stages", timeout=8).json()
                os.environ["CREW_STAGES"] = ",".join(s.get("selected", []))
            if os.environ.get("CREW_MODULES") is None:
                m = requests.get(f"{SHODANSNIPE_URL}/api/crew/modules", timeout=8).json()
                os.environ["CREW_MODULES"] = ",".join(m.get("selected", []))
            print("[Settings] Loaded saved crew selection from the server.")
        except Exception as e:
            print(f"[Settings] Could not load saved settings ({e}); using built-in defaults.")

    # Translate the (saved or explicitly-passed) selection onto the existing flags so a toggle
    # in the GUI actually changes the crew. Empty string = nothing selected = treated as default.
    _stages = os.environ.get("CREW_STAGES")
    if _stages:
        st = {s.strip() for s in _stages.split(",") if s.strip()}
        if "nmap" not in st:
            args.no_nmap = True
        if "threat" not in st:
            args.no_threat = True
    _modules = os.environ.get("CREW_MODULES")
    if _modules:
        mods = {m.strip() for m in _modules.split(",") if m.strip()}
        OSINT_M   = {"cert_transparency", "validate_ownership", "historical_dns",
                     "reverse_whois", "cloud_asset_discovery"}
        AUTH_M    = {"analyze_auth", "classify_posture", "json_keyword_scan",
                     "probe_sensitive_paths"}
        ARCHIVE_M = {"wayback", "shodan_host_uri"}
        if not (mods & OSINT_M):
            args.no_osint = True
        if not (mods & AUTH_M):
            args.no_auth = True
        if not (mods & ARCHIVE_M):
            args.no_archive = True

    global AUTONOMY_MODE
    if args.mode:
        AUTONOMY_MODE = args.mode
    else:
        AUTONOMY_MODE = _load_autonomy_mode()
    print(f"[Mode] {AUTONOMY_MODE.upper()} (from {'CLI override' if args.mode else 'server/env'})")
    if args.no_nmap:
        os.environ["ENABLE_NMAP"] = "0"
    if getattr(args, 'no_archive', False):
        os.environ["ENABLE_ARCHIVE"] = "0"

    print("=" * 62)
    print("  ShodanSnipe + CrewAI — Parallel Attack Surface Crew v2")
    print(f"  Provider : {args.provider}")
    print(f"  Mode     : {AUTONOMY_MODE.upper()}")
    print(f"  Report   : {args.report.upper()}")
    print(f"  OSINT    : {'OFF' if args.no_osint else 'ON (parallel with Recon)'}")
    print(f"  Nmap     : {'OFF' if args.no_nmap else 'ON (skill in Recon)'}")
    print("=" * 62)

    if AUTONOMY_MODE == "full":
        print("\n  [WARNING] FULL AUTONOMOUS — no confirmations.")
        if not _confirm("  Proceed?"):
            sys.exit(0)

    # ── Server ────────────────────────────────────────────────────────────────
    health = check_server()
    tier = health.get("tier_label", "unknown")
    cr, ct = get_credits()
    print(f"\n[OK] Server alive — tier: {tier}")
    if ct:
        print(f"[Credits] {cr}/{ct} ({int(100*cr/ct) if ct else 0}%)")
    print_arch_banner()
    print_run_history()

    # ── Scope ─────────────────────────────────────────────────────────────────
    scope_query = args.scope or get_scope()
    if not scope_query:
        print("\n[ERROR] No scope defined.")
        print("        Set scope in the UI: http://127.0.0.1:8000")
        print("        Or: python poc_crew.py --scope 'org:\"Acme Corp\" hostname:acme.com'")
        sys.exit(1)

    m = re.search(r'org:"([^"]+)"', scope_query)
    if m:
        target_org = m.group(1)
    else:
        # No org in the query — derive a clean name from a hostname/domain or net,
        # never a raw 40-char slice of the query string.
        hm = re.search(r'(?:hostname|ssl\.cert\.subject\.cn):([^\s"]+)', scope_query)
        if hm:
            target_org = hm.group(1).split(".")[0]      # test.com -> test
        else:
            target_org = re.split(r'[:\s]', scope_query.strip())[0][:40] or "target"
    print(f"[Scope]  {scope_query}")
    print(f"[Target] {target_org}")

    # Capture this run into the shared history (so terminal runs show up too, not just
    # Control-Center launches). Best-effort — never blocks the run.
    _run_id = record_run({
        "scope": scope_query,
        "target": target_org,
        "mode": os.environ.get("CREW_MODE", "cli"),
        "report": args.report,
        "stages": [s for s in os.environ.get("CREW_STAGES", "").split(",") if s] or None,
        "status": "running",
        "source": "cli",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })
    if _run_id:
        print(f"[Run]    recorded id={_run_id} (view all: GET {SHODANSNIPE_URL}/api/runs)")

    # ── Pre-flight: show exactly what's about to run ──────────────────────────
    _mods = [k for k in os.environ.get("CREW_MODULES", "").split(",") if k]
    print("\n" + "-" * 62)
    print("  PRE-FLIGHT — what will run (from your saved Control Center settings)")
    print("-" * 62)
    print(f"  Scope     : {scope_query}")
    print(f"  Report    : {args.report}")
    print(f"  Stages    : recon"
          f"{'' if args.no_nmap else ' + nmap'}"
          f"{' + vuln' }"
          f" + report")
    print(f"  OSINT     : {'OFF' if args.no_osint else 'ON'}")
    print(f"  Nmap      : {'OFF' if args.no_nmap else 'ON'}")
    print(f"  Auth      : {'OFF' if args.no_auth else 'ON'}")
    print(f"  Threat    : {'OFF' if args.no_threat else 'ON'}")
    print(f"  Archive   : {'OFF' if args.no_archive else 'ON'}")
    print(f"  Modules   : {len(_mods)} enabled" + (f" ({', '.join(_mods)})" if _mods else ""))
    print(f"  Autonomy  : {AUTONOMY_MODE.upper()}")
    print("-" * 62)

    if AUTONOMY_MODE == "hitl" and not _confirm(f"\nProceed with scope: {scope_query}?"):
        sys.exit(0)

    # ── Build LLM ─────────────────────────────────────────────────────────────
    llm = build_llm(args.provider, args.model)

    # ── Import agents ─────────────────────────────────────────────────────────
    # Mandatory team members — the crew cannot run without these. A clear message beats
    # a raw ModuleNotFoundError if the agents/ folder isn't on the path.
    try:
        from manager_agent    import build_manager_agent, build_manager_hunt_plan_task, build_manager_correlation_task, build_manager_scope_reconciliation_task
        from recon_agent      import build_recon_agent,   build_recon_tasks
        from vuln_agent       import build_vuln_agent,    build_vuln_tasks
        from report_agent     import build_report_agent,  build_report_tasks
    except ModuleNotFoundError as e:
        print(f"\n[ERROR] Missing a REQUIRED agent module: {e.name}")
        print( "        The launcher expects the agent files in an 'agents/' folder next to 'launchers/'.")
        print( "        Searched these paths:")
        for _p in sys.path[:6]:
            print(f"          - {_p}")
        print( "        Fix: make sure agents/manager_agent.py, recon_agent.py, vuln_agent.py and")
        print( "        report_agent.py all exist (exact names), then re-run.")
        sys.exit(1)

    # Optional team members — if a file is missing, disable that stage with a warning
    # instead of crashing the whole run (these are the same stages as the --no-* flags).
    try:
        from osint_agent      import build_osint_agent,   build_osint_tasks, build_osint_verify_task
    except ModuleNotFoundError as e:
        print(f"[WARN] osint_agent not found ({e.name}) — OSINT stage DISABLED. "
              "Restore agents/osint_agent.py to enable it.")
        args.no_osint = True
        build_osint_agent = build_osint_tasks = build_osint_verify_task = None
    try:
        from nmap_recon_agent import build_nmap_agent,    build_nmap_tasks
    except ModuleNotFoundError as e:
        print(f"[WARN] nmap_recon_agent not found ({e.name}) — NMAP stage DISABLED.")
        args.no_nmap = True
        build_nmap_agent = build_nmap_tasks = None
    try:
        from auth_agent       import build_auth_agent,    build_auth_tasks
    except ModuleNotFoundError as e:
        print(f"[WARN] auth_agent not found ({e.name}) — AUTH stage DISABLED.")
        args.no_auth = True
        build_auth_agent = build_auth_tasks = None
    try:
        from threat_intel_agent import build_threat_intel_agent, build_threat_intel_task
    except ModuleNotFoundError as e:
        print(f"[WARN] threat_intel_agent not found ({e.name}) — THREAT-INTEL stage DISABLED.")
        args.no_threat = True
        build_threat_intel_agent = build_threat_intel_task = None

    # Optional tool packs — degrade if absent.
    try:
        from nmap_tool        import get_nmap_tools
        nmap_tools = get_nmap_tools()
    except ModuleNotFoundError as e:
        print(f"[WARN] nmap_tool not found ({e.name}) — nmap tools unavailable.")
        args.no_nmap = True
        nmap_tools = []
    try:
        from archive_tool     import get_archive_tools
        archive_tools = get_archive_tools()
    except ModuleNotFoundError as e:
        print(f"[WARN] archive_tool not found ({e.name}) — Wayback/ShodanURI enrichment off.")
        archive_tools = []

    # Shodan API key for shodan_host_uri tool
    shodan_key = os.environ.get("SHODAN_API_KEY", "")
    if not shodan_key:
        try:
            import requests as _req
            r = _req.get(f"{SHODANSNIPE_URL}/api/config/api-key", timeout=5)
            if r.ok:
                shodan_key = r.json().get("key", "")
        except Exception:
            pass
    if shodan_key:
        os.environ["SHODAN_API_KEY"] = shodan_key
        print(f"[Shodan] API key loaded ({shodan_key[:8]}...)")
    else:
        print("[Shodan] WARNING: No API key found — shodan_host_uri tool will be limited")

    manager_agent = build_manager_agent(llm)
    recon_agent   = build_recon_agent(llm, extra_tools=nmap_tools)
    osint_agent   = build_osint_agent(llm) if not args.no_osint else None
    nmap_agent    = build_nmap_agent(llm)  if (nmap_tools and build_nmap_agent) else None
    auth_agent    = build_auth_agent(llm)  if not args.no_auth   else None
    vuln_agent    = build_vuln_agent(llm, extra_tools=archive_tools)
    threat_agent  = build_threat_intel_agent(llm) if not args.no_threat else None
    report_agent  = build_report_agent(llm)

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 1: RECON + OSINT in PARALLEL
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 62)
    print("  PHASE 0 — MANAGER: scope expansion + hunt plan")
    print("=" * 62)

    hunt_plan_task = build_manager_hunt_plan_task(manager_agent, target_org, scope_query)
    manager_plan_output = run_crew_phase([manager_agent], [hunt_plan_task])
    print(f"\n[MANAGER] Hunt plan complete — {len(manager_plan_output)} chars")

    print("\n" + "=" * 62)
    print("  PHASE 1 — OSINT first, then Recon uses validated intel")
    print("=" * 62)

    recon_output = ""
    osint_output = ""

    if osint_agent:
        # ── OSINT runs FIRST to validate scope and build intel package ──
        print("[P1] OSINT agent running first — validating scope and building intel package...")
        osint_tasks = build_osint_tasks(osint_agent, target_org, scope_query)
        osint_output = run_crew_phase([osint_agent], osint_tasks)
        print(f"\n[OSINT] Complete — {len(osint_output)} chars")

        # Extract the intel_package from OSINT output
        intel_package = ""
        try:
            # Try to parse as JSON first
            osint_json = json.loads(osint_output)
            intel_pkg = osint_json.get("intel_package", {})
            query_pkg = osint_json.get("shodan_query_package", [])
            intel_package = json.dumps({
                "intel_package": intel_pkg,
                "shodan_query_package": query_pkg,
            })
            q_count = len(query_pkg)
            print(f"[P1] OSINT produced {q_count} prioritised Shodan queries for Recon")
        except Exception:
            # Fall back: pass raw OSINT output as intel context
            intel_package = osint_output[:30000]
            print("[P1] OSINT output parsed as raw text (not JSON) — passing to Recon")

        # ── Merge Manager creative pivots INTO intel_package before Recon starts ──
        # Creative pivots are hypotheses, not a separate pass — Recon gets them
        # alongside OSINT intel so it can discover more freely in one pass.
        try:
            plan_json = json.loads(manager_plan_output)
            pivots = plan_json.get("hunt_plan", {}).get("creative_pivots", [])
            pivot_queries = [p for p in pivots if p.get("shodan_query")]
            blind_spots   = plan_json.get("hunt_plan", {}).get("top_5_blind_spots", [])
            hypotheses    = plan_json.get("hunt_plan", {}).get("hypotheses", [])
            if pivot_queries or blind_spots:
                # Inject manager intelligence into the OSINT intel package
                # so Recon starts with ALL available context in one shot
                try:
                    base = json.loads(intel_package) if intel_package else {}
                except Exception:
                    base = {"raw_osint": intel_package[:2000]}
                base["manager_creative_pivots"] = [
                    {"query": p["shodan_query"], "priority": "HIGH",
                     "why": p.get("why", "Manager hypothesis")}
                    for p in pivot_queries[:8]
                ]
                base["manager_blind_spots"]  = blind_spots[:5]
                base["manager_hypotheses"]   = hypotheses[:5]
                intel_package = json.dumps(base)
                print(f"[P1] Merged {len(pivot_queries)} Manager pivots + "
                      f"{len(blind_spots)} blind spots into Recon seed")
        except Exception as e:
            print(f"[WARN] Could not merge Manager pivots: {e}")

        # ── RECON: one pass, full context (OSINT + Manager + creative) ──────
        print("[P1] Recon agent running — OSINT intel + Manager pivots merged...")
        recon_tasks = build_recon_tasks(recon_agent, target_org, scope_query,
                                        osint_intel=intel_package)
        recon_output = run_crew_phase([recon_agent], recon_tasks)
        print(f"\n[RECON] Complete — {len(recon_output)} chars")

    else:
        # No OSINT — still use Manager's scope expansion
        print("[P1] OSINT disabled — using Manager scope expansion for Recon seed...")
        try:
            plan_json = json.loads(manager_plan_output)
            pivots = plan_json.get("hunt_plan", {}).get("creative_pivots", [])
            pivot_queries = [p.get("shodan_query","") for p in pivots if p.get("shodan_query")]
            intel_seed = json.dumps({
                "shodan_query_package": [
                    {"query": scope_query, "priority": "HIGH", "why": "primary scope"},
                    *[{"query": q, "priority": "HIGH", "why": "Manager pivot"}
                      for q in pivot_queries[:4]]
                ]
            })
        except Exception:
            intel_seed = ""

        recon_tasks = build_recon_tasks(recon_agent, target_org, scope_query,
                                        osint_intel=intel_seed)
        recon_output = run_crew_phase([recon_agent], recon_tasks)
        print(f"\n[RECON] Complete — {len(recon_output)} chars")

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 1.5: NMAP — live confirmation of Shodan findings
    # ══════════════════════════════════════════════════════════════════════════
    nmap_output = ""
    if nmap_agent:
        print("\n" + "=" * 62)
        print("  PHASE 1.5 — NMAP: live port confirmation + triage")
        print("=" * 62)
        # Pass the recon task as prior context so nmap agent knows which IPs to scan
        nmap_tasks = build_nmap_tasks(nmap_agent, prior_task=None)
        nmap_output = run_crew_phase([nmap_agent], nmap_tasks)
        print(f"\n[NMAP] Complete — {len(nmap_output)} chars")
    else:
        print("\n[NMAP] Skipped — nmap binary not available or ENABLE_NMAP=0")

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 1.6: SCOPE RECONCILIATION — define scope from what was actually found
    # ══════════════════════════════════════════════════════════════════════════
    def _reconcile():
        t = build_manager_scope_reconciliation_task(
            manager_agent, osint_output=osint_output,
            recon_output=recon_output, nmap_output=nmap_output)
        return run_crew_phase([manager_agent], [t])

    print("\n" + "=" * 62)
    print("  PHASE 1.6 — MANAGER: scope reconciliation (lock scope from metadata)")
    print("=" * 62)
    scope_recon_output = _reconcile()
    print(f"\n[SCOPE-RECON] Complete — {len(scope_recon_output)} chars")
    manager_plan_output += "\n\n=== SCOPE RECONCILIATION (authoritative) ===\n" + scope_recon_output

    # ── PHASE 1.7: bounded refine LOOP ────────────────────────────────────────
    # reconcile → route gaps (recon queries → recon, domain/ownership leads → osint) →
    # re-engage → RE-reconcile to confirm closure. Bounded by REFINE_MAX_LOOPS; breaks
    # early when reconciliation reports no gaps (converged).
    refine_max = max(1, int(os.environ.get("REFINE_MAX_LOOPS", "1")))
    if args.refine:
        _seen_queries = set()      # gap queries already executed — never repeat across loops
        _seen_leads   = set()      # osint leads already verified — never re-verify
        for it in range(1, refine_max + 1):
            try:
                g = json.loads(scope_recon_output)
            except Exception:
                print(f"[REFINE] Loop {it}: reconciliation JSON unparseable — stopping loop.")
                break
            gaps        = g.get("gaps", {}) or {}
            recon_qs    = [q for q in (g.get("refined_queries") or [])
                           if isinstance(q, str) and q.strip() and q.strip() not in _seen_queries][:10]
            osint_leads = [d for d in (gaps.get("alt_domains_to_verify") or [])
                           if isinstance(d, str) and d.strip() and d.strip() not in _seen_leads][:15]

            if not recon_qs and not osint_leads:
                print(f"\n[REFINE] Loop {it}: converged — no NEW gaps to chase.")
                break

            print("\n" + "=" * 62)
            print(f"  PHASE 1.7 — REFINE LOOP {it}/{refine_max}: "
                  f"{len(osint_leads)} new osint leads, {len(recon_qs)} new recon gap queries")
            print("=" * 62)

            # Re-engage OSINT first (verify domains/ownership) so recon can trust them.
            if osint_leads and osint_agent and build_osint_verify_task:
                vt = build_osint_verify_task(osint_agent, target_org, osint_leads)
                o2 = run_crew_phase([osint_agent], [vt])
                osint_output += f"\n\n=== OSINT RE-ENGAGE (loop {it}: lead verification) ===\n" + o2
                _seen_leads.update(osint_leads)
                print(f"[REFINE] osint verify done — {len(o2)} chars")

            # Re-engage RECON on the scope-gap queries.
            if recon_qs:
                seed = json.dumps({"shodan_query_package": [
                    {"query": q, "priority": "HIGH", "why": "scope-reconciliation gap"} for q in recon_qs]})
                r2 = run_crew_phase([recon_agent],
                                    build_recon_tasks(recon_agent, target_org, scope_query, osint_intel=seed))
                recon_output += f"\n\n=== RECON RE-ENGAGE (loop {it}: gap-closing) ===\n" + r2
                _seen_queries.update(recon_qs)
                print(f"[REFINE] recon re-engage done — {len(r2)} chars")

            # Re-reconcile to confirm the gaps actually closed (and seed the next loop).
            scope_recon_output = _reconcile()
            manager_plan_output += f"\n\n=== SCOPE RECONCILIATION (after loop {it}) ===\n" + scope_recon_output
            print(f"[REFINE] re-reconciled after loop {it} — {len(scope_recon_output)} chars "
                  f"({len(_seen_queries)} queries / {len(_seen_leads)} leads consumed so far)")
    else:
        print("\n[SCOPE-RECON] --refine off: gaps reported, no re-engage pass "
              "(enable with --refine; tune depth with REFINE_MAX_LOOPS).")

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 2: AUTH + VULN (sequential)
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 62)
    print("  PHASE 2 — AUTH ANALYSIS + VULN INTEL")
    print("=" * 62)

    auth_output = ""
    vuln_output = ""

    # Run AUTH as its own crew so we capture its OWN clean output. (Previously auth+vuln
    # ran as one crew and the combined result was sliced in half by character count —
    # crew.kickoff() returns only the FINAL task's output, so that split produced junk for
    # both agents and vuln never actually received the auth findings.)
    if auth_agent:
        # Pass nmap confirmed output so auth agent focuses on LIVE ports
        combined_recon = recon_output + ("\n\n=== NMAP LIVE CONFIRMATION ===\n" + nmap_output if nmap_output else "")
        auth_tasks = build_auth_tasks(auth_agent, combined_recon)
        auth_output = run_crew_phase([auth_agent], auth_tasks)
        print(f"\n[AUTH] Complete — {len(auth_output)} chars")

    # VULN runs after, and now genuinely receives the real auth_output as context.
    vuln_tasks = build_vuln_tasks(vuln_agent, recon_output, auth_output)
    vuln_output = run_crew_phase([vuln_agent], vuln_tasks)
    print(f"\n[VULN] Complete — {len(vuln_output)} chars")
    print(f"[P2] Auth: {len(auth_output)} chars | Vuln: {len(vuln_output)} chars")

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 2.5: MANAGER CORRELATION — cross-agent pattern detection
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 62)
    print("  PHASE 2.5 — MANAGER: cross-agent correlation")
    print("=" * 62)

    # Include nmap triage output in manager correlation for cross-agent hits
    combined_recon_for_corr = recon_output + ("\n" + nmap_output if nmap_output else "")
    correlation_task = build_manager_correlation_task(
        manager_agent,
        osint_output=osint_output,
        recon_output=combined_recon_for_corr,
        auth_output=auth_output,
        vuln_output=vuln_output,
    )
    manager_correlation_output = run_crew_phase([manager_agent], [correlation_task])
    print(f"\n[MANAGER-CORRELATION] Complete — {len(manager_correlation_output)} chars")

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 2.6: THREAT INTEL — TTP mapping / attack chains / IOCs
    # ══════════════════════════════════════════════════════════════════════════
    threat_output = ""
    if threat_agent:
        print("\n" + "=" * 62)
        print("  PHASE 2.6 — THREAT INTEL: TTP map + attack chains + IOCs")
        print("=" * 62)
        threat_task = build_threat_intel_task(
            threat_agent,
            vuln_output=vuln_output,
            recon_output=combined_recon_for_corr,
        )
        threat_output = run_crew_phase([threat_agent], [threat_task])
        print(f"\n[THREAT-INTEL] Complete — {len(threat_output)} chars")
    else:
        print("\n[THREAT-INTEL] Skipped (--no-threat) — report will derive TTPs itself")

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 3: REPORT — full output, no truncation
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 62)
    print(f"  PHASE 3 — {args.report.upper()} REPORT")
    print("=" * 62)

    report_tasks = build_report_tasks(
        agent            = report_agent,
        recon_output     = recon_output,              # full, no truncation
        osint_output     = osint_output,              # full
        auth_output      = auth_output,               # full
        vuln_output      = vuln_output,               # full
        manager_plan     = manager_plan_output,       # hunt plan
        manager_summary  = manager_correlation_output,# cross-agent executive summary
        threat_output    = threat_output,             # TTP map / chains / IOCs (if run)
        target_org       = target_org,
        scope_query      = scope_query,
        report_style     = args.report,
    )
    final_report = run_crew_phase([report_agent], report_tasks)

    # ── Save report ───────────────────────────────────────────────────────────
    ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_org = re.sub(r'[^\w]', '_', target_org)[:30]
    style    = "brief" if args.report == "brief" else "full"
    fname    = f"report_{safe_org}_{style}_{ts}.md"
    fpath    = os.path.join(ROOT, fname)

    with open(fpath, "w", encoding="utf-8") as f:
        f.write(f"# ShodanSnipe Assessment — {target_org}\n")
        f.write(f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Scope:** `{scope_query}`\n")
        f.write(f"**Style:** {args.report}\n")
        f.write(f"**Provider:** {args.provider}\n\n---\n\n")
        f.write(final_report)

    print("\n" + "=" * 62)
    print(f"  DONE — {args.report.upper()} REPORT SAVED")
    print(f"  File: {fpath}")
    print("=" * 62)

    # ── Store structured findings so the GUI can show enriched fields + export ──
    try:
        _findings = extract_findings(final_report)
        _n = record_findings(_findings, _run_id)
        if _n:
            print(f"  Findings: {_n} stored (view: GET {SHODANSNIPE_URL}/api/findings "
                  f"| export: {SHODANSNIPE_URL}/api/findings/export?fmt=csv)")
    except Exception as e:
        print(f"  Findings: not stored ({e}) — report file above is unaffected")

    # ── Also send it to the server so the GUI "▤ Report" panel renders it as HTML ─
    try:
        r = requests.post(f"{SHODANSNIPE_URL}/api/report/save",
                          json={"markdown": final_report, "target_org": target_org},
                          timeout=15)
        if r.ok:
            print(f"  GUI: report posted to {SHODANSNIPE_URL} — open the ▤ Report panel")
    except Exception as e:
        print(f"  GUI: could not post report ({e}) — the .md file above is still saved")
    # Print preview
    preview = final_report[:3000]
    print(preview)
    if len(final_report) > 3000:
        print(f"\n... [{len(final_report) - 3000} more chars in file]")


if __name__ == "__main__":
    main()
