"""
settings.py — Single source of truth for runtime configuration.

Replaces scattered, hard-coded knobs (the `le=100` in tools, the credit/limit
logic in poc_crew, the ENABLE_NMAP flag) with ONE place that is:

  * read/written from the UI and CLI (via server.py /api/settings + /api/crew/stages)
  * persisted across restarts (via db config when available)
  * overridable by environment variable (so crewai.bat / cli.py can pass choices)
  * safe to import with no database (falls back to in-memory — used by the CLI)

Two things it controls:
  1. LIMITS   — results-per-query, query budget, nmap host cap, report tokens …
  2. STAGES   — "pick your crew": which pipeline agents run. Granular, not all-or-nothing.

Usage:
    import settings
    s = settings.get_settings()                 # full dict (defaults+saved+env)
    settings.update_settings({"max_results_per_query": 200})
    settings.set_stages(["recon", "vuln", "report"])   # skip nmap
    keys = settings.selected_stage_keys()       # ordered, dependency-resolved
    n = settings.clamp_results(99999)           # -> hard cap
"""
from __future__ import annotations
import os, json, copy

# Persist through the app DB if present; otherwise keep it in memory (CLI use).
try:
    import db  # type: ignore
    _HAS_DB = True
except Exception:
    _HAS_DB = False

_CONFIG_KEY = "ui_settings"
# When there's no app DB (pure CLI use), persist to a local JSON file so choices
# survive between `python cli.py ...` invocations.
_FILE_STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           ".shodansnipe_settings.json")

# ─────────────────────────────────────────────────────────────────────────────
# Pipeline stages — the "pick your crew" registry. Order = execution order.
# `requires` lists stages whose DATA this stage consumes (auto-enabled if needed).
# ─────────────────────────────────────────────────────────────────────────────
STAGE_REGISTRY = [
    {"key": "recon",  "name": "Recon Specialist",
     "desc": "Passive Shodan attack-surface mapping (scope-gated).",
     "requires": [], "default": True,  "always_on": True},
    {"key": "nmap",   "name": "Nmap Recon",
     "desc": "Stealthy active confirmation + HIGH/MED/LOW triage. Discovery only.",
     "requires": ["recon"], "default": True,  "always_on": False},
    {"key": "vuln",   "name": "Vuln Analyst",
     "desc": "CVE cross-reference + scoped detection queries + severity.",
     "requires": ["recon"], "default": True,  "always_on": False},
    {"key": "threat", "name": "Threat-Intel Analyst",
     "desc": "Adversary layer on confirmed findings: MITRE ATT&CK map, actor context, "
             "attack chains, IOCs/SIEM. Consumes Vuln output — does not re-discover.",
     "requires": ["vuln"], "default": True,  "always_on": False},
    {"key": "report", "name": "Report Writer",
     "desc": "Synthesises findings into the executive threat report.",
     "requires": [], "default": True,  "always_on": False},
]
_STAGE_ORDER = [s["key"] for s in STAGE_REGISTRY]
_STAGE_BY_KEY = {s["key"]: s for s in STAGE_REGISTRY}

# ─────────────────────────────────────────────────────────────────────────────
# Optional capability MODULES — finer-grained than stages. Toggle individual
# actions/tools (JS crawl, wayback, banner pull, …) on or off from the UI.
# ─────────────────────────────────────────────────────────────────────────────
MODULE_REGISTRY = [
    # ── Manager ──────────────────────────────────────────────────────────────
    {"key": "expand_scope", "group": "Manager", "name": "Scope Expander",
     "desc": "Expand scope into related ASNs / domains / orgs.", "default": True},
    {"key": "build_hunt_plan", "group": "Manager", "name": "Hunt Planner",
     "desc": "Build the prioritised hunt plan for the run.", "default": True},
    {"key": "correlate_findings", "group": "Manager", "name": "Cross-Correlator",
     "desc": "Correlate findings across agents; dedupe.", "default": True},

    # ── Recon ────────────────────────────────────────────────────────────────
    {"key": "shodan_search", "group": "Recon", "name": "Shodan Search",
     "desc": "Passive Shodan host search (core).", "default": True, "always_on": True},
    {"key": "scope_control", "group": "Recon", "name": "Scope Get/Set",
     "desc": "Read & set the active scope (core).", "default": True, "always_on": True},
    {"key": "asn_hunt", "group": "Recon", "name": "ASN Hunt",
     "desc": "Discover org ASNs and expand to net ranges.", "default": True},
    {"key": "dns_posture", "group": "Recon", "name": "DNS Posture",
     "desc": "SPF / DMARC / CAA / DNSSEC checks.", "default": True},

    # ── OSINT ────────────────────────────────────────────────────────────────
    {"key": "cert_transparency", "group": "OSINT", "name": "Cert Transparency",
     "desc": "CT-log search for subdomains & hosts.", "default": True},
    {"key": "validate_ownership", "group": "OSINT", "name": "Ownership Validation",
     "desc": "Confirm an asset belongs to the target before in-scoping.", "default": True},
    {"key": "historical_dns", "group": "OSINT", "name": "Historical / Passive DNS",
     "desc": "Historical DNS records for the scope.", "default": True},
    {"key": "reverse_whois", "group": "OSINT", "name": "Reverse WHOIS",
     "desc": "Pivot on registrant to find related domains.", "default": False},
    {"key": "cloud_asset_discovery", "group": "OSINT", "name": "Cloud Asset Discovery",
     "desc": "Find cloud storage / tenant assets (S3, blob, …).", "default": False},

    # ── Nmap (only used when the nmap STAGE is enabled) ──────────────────────
    {"key": "nmap_discovery", "group": "Nmap", "name": "Discovery Scan",
     "desc": "Stealthy active host/port discovery.", "default": True, "stage": "nmap"},
    {"key": "nmap_triage", "group": "Nmap", "name": "Triage",
     "desc": "Rank hosts HIGH / MED / LOW for the human operator.", "default": True, "stage": "nmap"},
    {"key": "nmap_scan", "group": "Nmap", "name": "Deeper Service Scan",
     "desc": "Fuller service/version scan. Slower.", "default": False, "stage": "nmap"},

    # ── Auth ─────────────────────────────────────────────────────────────────
    {"key": "analyze_auth", "group": "Auth", "name": "Auth Analysis",
     "desc": "Identify auth mechanisms on exposed services.", "default": True},
    {"key": "classify_posture", "group": "Auth", "name": "Posture Classify",
     "desc": "Classify the auth/exposure posture of a host.", "default": True},
    {"key": "json_keyword_scan", "group": "Auth", "name": "JSON Keyword Scan",
     "desc": "Scan JSON responses for sensitive keywords.", "default": True},
    {"key": "probe_sensitive_paths", "group": "Auth", "name": "Sensitive-Path Probe",
     "desc": "Check well-known sensitive paths. Active.", "default": False},

    # ── Vuln ─────────────────────────────────────────────────────────────────
    {"key": "get_results", "group": "Vuln", "name": "Get Results",
     "desc": "Read the latest results in memory (core).", "default": True, "always_on": True},
    {"key": "cve_intel", "group": "Vuln", "name": "CVE Intel",
     "desc": "CVE / advisory analysis + Shodan detection queries.", "default": True},
    {"key": "shodan_host_uri", "group": "Vuln", "name": "Host Banner Pull",
     "desc": "Full HTTP/SSL banner & URIs on Critical/High hosts.", "default": True},
    {"key": "wayback", "group": "Vuln", "name": "Wayback History",
     "desc": "Historical URLs / sensitive paths from web archives.", "default": True},

    # ── Threat Intel (only used when the threat STAGE is enabled) ────────────
    {"key": "mitre_attack_lookup", "group": "Threat Intel", "name": "MITRE ATT&CK Map",
     "desc": "Map exposures to ATT&CK techniques for the report.", "default": True, "stage": "threat"},
    {"key": "generate_iocs", "group": "Threat Intel", "name": "IOC Generator",
     "desc": "Produce indicators of compromise from findings.", "default": True, "stage": "threat"},
    {"key": "threat_actor_attribution", "group": "Threat Intel", "name": "Threat-Actor Context",
     "desc": "Note actors historically associated with the exposures.", "default": False, "stage": "threat"},
    {"key": "red_team_attack_chains", "group": "Threat Intel", "name": "Attack-Chain Hypotheses",
     "desc": "Narrative attack-chain hypotheses for the report.", "default": False, "stage": "threat"},

    # ── Validation (cross-cutting — used by recon/vuln/auth/nmap/report) ──────
    {"key": "http_probe", "group": "Validation", "name": "Live Finding Validation",
     "desc": "Curl-style GET/HEAD confirmation that an exposure is really reachable & "
             "unauthenticated before it is called Critical/High. Scope-gated; no exploitation. "
             "Always on — agents fall back to passive evidence if a host can't be reached.",
     "default": True, "always_on": True},

    # ── Report ───────────────────────────────────────────────────────────────
    {"key": "get_history", "group": "Report", "name": "History Access",
     "desc": "Read run history for the report (core).", "default": True, "always_on": True},
]
_MODULE_ORDER = [m["key"] for m in MODULE_REGISTRY]

# ─────────────────────────────────────────────────────────────────────────────
# Defaults. Every one of these used to be a magic number somewhere in the code.
# ─────────────────────────────────────────────────────────────────────────────
DEFAULTS: dict = {
    # ── result / query limits ────────────────────────────────────────────────
    "max_results_per_query": 100,   # results a single shodan_search may request
    "hard_cap_results":      1000,  # absolute ceiling — requests are clamped here
    "max_queries_per_run":   16,    # crew query budget per run
    "credit_budget":         1000,  # Shodan credit awareness (for the planner)
    # ── nmap stage ────────────────────────────────────────────────────────────
    "nmap_max_hosts_per_call": 50,
    "nmap_intensity":          "stealth",   # stealth (-T2 SYN) | normal (-sV)
    # ── report ────────────────────────────────────────────────────────────────
    "report_max_tokens": 20000,     # report output budget. 8000 truncated multi-finding
                                    #   reports mid-section; 20k fits a full clustered report.
                                    #   (gpt-4o-mini caps ~16k; Sonnet/Opus go much higher.)
    "report_section_chars": 60000,  # chars of EACH agent's findings fed to the report's
                                    #   ANALYSIS step → how many hosts make it into the report.
                                    #   (Was 8000, which silently dropped findings; the crew now
                                    #   reads this value, so the UI slider actually controls it.)
    "report_profile":    "technical",  # technical | executive | client
    # ── result depth (global cap control — see limits.py) ───────────────────
    "result_depth_multiplier": 1.0, # scales EVERY hardcoded cap (hosts, findings, CVEs…).
                                    #   2.0 = twice as deep everywhere. Bridged as
                                    #   GLOBAL_LIMIT_MULTIPLIER so one slider drives the pipeline.
    "no_limits": False,             # True removes caps entirely (exhaustive, slower).
    # ── autonomy ────────────────────────────────────────────────────────────
    "autonomy_mode": "hitl",        # hitl | scoped | full
    "profile": "comprehensive",     # active scan profile (quick|comprehensive|all|custom)
    # ── pick-your-crew: enabled stages ──────────────────────────────────────
    "stages": {s["key"]: s["default"] for s in STAGE_REGISTRY},
    # ── enabled capability modules ──────────────────────────────────────────
    "modules": {m["key"]: m["default"] for m in MODULE_REGISTRY},
}

# Map env var -> (settings key, caster). Lets crewai.bat / cli.py override.
_ENV_OVERRIDES = {
    "SHODAN_MAX_RESULTS":   ("max_results_per_query", int),
    "CREW_MAX_QUERIES":     ("max_queries_per_run",   int),
    "CREW_CREDIT_BUDGET":   ("credit_budget",         int),
    "NMAP_MAX_HOSTS":       ("nmap_max_hosts_per_call", int),
    "REPORT_MAX_TOKENS":    ("report_max_tokens",     int),
    "REPORT_SECTION_CHARS": ("report_section_chars",  int),
    "MCP_AUTONOMY_MODE":    ("autonomy_mode",         str),
    "REPORT_PROFILE":       ("report_profile",        str),
    "GLOBAL_LIMIT_MULTIPLIER": ("result_depth_multiplier", float),
    "GLOBAL_NO_LIMITS":     ("no_limits",              lambda v: str(v).lower() in ("1", "true", "yes", "on")),
}


# ─────────────────────────────────────────────────────────────────────────────
# Persistence
# ─────────────────────────────────────────────────────────────────────────────
def _load_saved() -> dict:
    # Prefer the DB, but fall back to the local JSON file if the DB is unavailable or
    # returns nothing (e.g. a fresh/re-keyed DB). The file always reflects the last save.
    if _HAS_DB:
        try:
            raw = db.get_config(_CONFIG_KEY)
            if raw:
                return json.loads(raw)
        except Exception:
            pass
    try:
        with open(_FILE_STORE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(data: dict) -> None:
    # Always write the local JSON file so settings survive restarts no matter what the DB
    # does; ALSO write the DB when present so the running server sees it immediately.
    try:
        with open(_FILE_STORE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass
    if _HAS_DB:
        try:
            db.set_config(_CONFIG_KEY, json.dumps(data))
        except Exception:
            pass


def reset_settings() -> dict:
    """Clear all saved settings (stages, modules, limits, profile) back to defaults."""
    if _HAS_DB:
        try:
            db.delete_config(_CONFIG_KEY)
        except Exception:
            try:
                db.set_config(_CONFIG_KEY, "{}")
            except Exception:
                pass
    try:
        if os.path.exists(_FILE_STORE):
            os.remove(_FILE_STORE)
    except Exception:
        pass
    return get_settings()


def _apply_env(cfg: dict) -> dict:
    # scalar overrides
    for env, (key, cast) in _ENV_OVERRIDES.items():
        val = os.environ.get(env)
        if val not in (None, ""):
            try:
                cfg[key] = cast(val)
            except (ValueError, TypeError):
                pass
    # stage override: CREW_STAGES="recon,vuln,report"
    raw_stages = os.environ.get("CREW_STAGES")
    if raw_stages:
        wanted = {k.strip().lower() for k in raw_stages.split(",") if k.strip()}
        cfg["stages"] = {k: (k in wanted) for k in _STAGE_ORDER}
    # legacy ENABLE_NMAP=0 still respected
    if os.environ.get("ENABLE_NMAP") == "0":
        cfg.setdefault("stages", {})["nmap"] = False
    # module override: CREW_MODULES="dns_posture,wayback,js_crawl"
    raw_mods = os.environ.get("CREW_MODULES")
    if raw_mods:
        wanted = {k.strip().lower() for k in raw_mods.split(",") if k.strip()}
        cfg["modules"] = {k: (k in wanted) for k in _MODULE_ORDER}
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────
def get_settings() -> dict:
    """Defaults <- saved <- env. Always returns a complete, valid dict."""
    cfg = copy.deepcopy(DEFAULTS)
    saved = _load_saved()
    # shallow-merge top level, deep-merge the stages sub-dict
    for k, v in saved.items():
        if k == "stages" and isinstance(v, dict):
            cfg["stages"].update({sk: bool(sv) for sk, sv in v.items() if sk in _STAGE_ORDER})
        elif k == "modules" and isinstance(v, dict):
            cfg["modules"].update({mk: bool(mv) for mk, mv in v.items() if mk in _MODULE_ORDER})
        elif k in cfg:
            cfg[k] = v
    cfg = _apply_env(cfg)
    # always-on stages can't be disabled
    for s in STAGE_REGISTRY:
        if s["always_on"]:
            cfg["stages"][s["key"]] = True
    # always-on (core) modules can't be disabled either
    for m in MODULE_REGISTRY:
        if m.get("always_on"):
            cfg["modules"][m["key"]] = True
    return cfg


def update_settings(patch: dict) -> dict:
    """Validate + persist a partial update. Unknown keys ignored. Returns new state."""
    saved = _load_saved()
    for k, v in (patch or {}).items():
        if k == "stages" and isinstance(v, dict):
            cur = saved.get("stages", {})
            cur.update({sk: bool(sv) for sk, sv in v.items() if sk in _STAGE_ORDER})
            saved["stages"] = cur
        elif k == "modules" and isinstance(v, dict):
            cur = saved.get("modules", {})
            cur.update({mk: bool(mv) for mk, mv in v.items() if mk in _MODULE_ORDER})
            saved["modules"] = cur
        elif k in DEFAULTS and k not in ("stages", "modules"):
            # clamp the integer knobs to sane ranges
            if isinstance(DEFAULTS[k], int):
                try:
                    v = max(1, int(v))
                except (ValueError, TypeError):
                    continue
                if k == "max_results_per_query":
                    v = min(v, int(saved.get("hard_cap_results",
                                             DEFAULTS["hard_cap_results"])))
            saved[k] = v
    _save(saved)
    return get_settings()


def clamp_results(n) -> int:
    """Clamp any requested result count to [1, hard_cap]. Never raises."""
    try:
        n = int(n)
    except (ValueError, TypeError):
        n = DEFAULTS["max_results_per_query"]
    cap = get_settings()["hard_cap_results"]
    return max(1, min(n, cap))


def max_results() -> int:
    return get_settings()["max_results_per_query"]


# ── stages ───────────────────────────────────────────────────────────────────
def get_stages() -> list[dict]:
    """Registry + current enabled state — what the UI renders as checkboxes."""
    enabled = get_settings()["stages"]
    return [{**s, "enabled": bool(enabled.get(s["key"], s["default"]))}
            for s in STAGE_REGISTRY]


def set_stages(selection) -> dict:
    """Enable exactly the stages in `selection` (list of keys or {key:bool}).
    Auto-enables any required upstream stage, and forces always-on stages."""
    if isinstance(selection, dict):
        wanted = {k for k, v in selection.items() if v}
    else:
        wanted = set(selection or [])
    # resolve requires (transitively, the registry is shallow so one pass is enough)
    for s in STAGE_REGISTRY:
        if s["key"] in wanted:
            wanted.update(s["requires"])
    for s in STAGE_REGISTRY:
        if s["always_on"]:
            wanted.add(s["key"])
    return update_settings({"stages": {k: (k in wanted) for k in _STAGE_ORDER}})


def selected_stage_keys() -> list[str]:
    """Enabled stage keys, in execution order."""
    enabled = get_settings()["stages"]
    return [k for k in _STAGE_ORDER if enabled.get(k)]


# ── modules ──────────────────────────────────────────────────────────────────
def get_modules() -> list[dict]:
    """Module registry + current enabled state — UI capability toggles."""
    enabled = get_settings()["modules"]
    return [{**m, "enabled": bool(enabled.get(m["key"], m["default"]))}
            for m in MODULE_REGISTRY]


def set_modules(selection) -> dict:
    """Enable exactly the modules in `selection` (list of keys or {key:bool}).
    Core (always_on) modules are always kept enabled."""
    if isinstance(selection, dict):
        wanted = {k for k, v in selection.items() if v}
    else:
        wanted = set(selection or [])
    for m in MODULE_REGISTRY:
        if m.get("always_on"):
            wanted.add(m["key"])
    return update_settings({"modules": {k: (k in wanted) for k in _MODULE_ORDER}})


def selected_module_keys() -> list[str]:
    enabled = get_settings()["modules"]
    return [k for k in _MODULE_ORDER if enabled.get(k)]


# ─────────────────────────────────────────────────────────────────────────────
# Scan PROFILES — one-click presets that set stages + modules + limits together.
# "Quick" triages passively; "Comprehensive" is the recommended full run;
# "All" turns on every capability incl. the active ones (authorized targets only).
# ─────────────────────────────────────────────────────────────────────────────
PROFILES = {
    "quick": {
        "label": "Quick",
        "desc": "Passive triage — what's exposed right now. Seconds, tiny credit use.",
        "stages": ["recon", "report"],
        "modules": ["build_hunt_plan", "dns_posture"],
        "limits": {"max_results_per_query": 50, "max_queries_per_run": 6,
                   "report_max_tokens": 6000},
    },
    "comprehensive": {
        "label": "Comprehensive",
        "desc": "Recommended. Passive + light active across the full pipeline.",
        "stages": ["recon", "nmap", "vuln", "threat", "report"],
        "modules": ["expand_scope", "build_hunt_plan", "correlate_findings",
                    "asn_hunt", "dns_posture", "cert_transparency", "validate_ownership",
                    "historical_dns", "nmap_discovery", "nmap_triage", "analyze_auth",
                    "classify_posture", "json_keyword_scan", "cve_intel",
                    "shodan_host_uri", "wayback", "mitre_attack_lookup", "generate_iocs"],
        "limits": {"max_results_per_query": 100, "max_queries_per_run": 16,
                   "report_max_tokens": 8000},
    },
    "all": {
        "label": "All modules (deep)",
        "desc": "Every capability incl. active scans. Slowest, highest credit use. "
                "Authorized active targets only — keep autonomy on HITL.",
        "stages": ["recon", "nmap", "vuln", "threat", "report"],
        "modules": [m["key"] for m in MODULE_REGISTRY],
        "limits": {"max_results_per_query": 200, "max_queries_per_run": 24,
                   "report_max_tokens": 12000},
    },
}


def get_profiles() -> dict:
    """Profile summaries for the UI + the currently active profile name."""
    out = []
    for name, p in PROFILES.items():
        mods = set(p["modules"]) | {m["key"] for m in MODULE_REGISTRY if m.get("always_on")}
        out.append({"name": name, "label": p["label"], "desc": p["desc"],
                    "stages": p["stages"], "module_count": len(mods),
                    "limits": p["limits"]})
    return {"profiles": out, "active": get_settings().get("profile", "custom")}


def apply_profile(name: str) -> dict:
    """Apply a preset: set its stages, modules and limits in one shot."""
    p = PROFILES.get(name)
    if not p:
        return get_settings()
    set_stages(p["stages"])
    set_modules(p["modules"])
    patch = dict(p["limits"])
    patch["profile"] = name
    return update_settings(patch)


# ─────────────────────────────────────────────────────────────────────────────
# Cost model — single source of truth for run-cost estimates.
# Both the Control Center preview (/api/cost/estimate) and the per-run capture
# (/api/crew/run → run history) derive their numbers from estimate_run_cost(),
# so the estimate you see before a run is the same figure that gets recorded.
# ─────────────────────────────────────────────────────────────────────────────
import math as _math

# USD per 1,000,000 tokens: (input, output). Local models are free.
MODEL_PRICING = {
    "claude-opus-4-8":   (15.0, 75.0),
    "claude-opus-4-6":   (15.0, 75.0),
    "claude-opus":       (15.0, 75.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-sonnet-4":   (3.0, 15.0),
    "claude-sonnet":     (3.0, 15.0),
    "claude-haiku-4-5":  (0.8, 4.0),
    "claude-haiku":      (0.8, 4.0),
    "gpt-4o-mini":       (0.15, 0.6),
    "gpt-4o":            (5.0, 15.0),
    "gpt-4-turbo":       (10.0, 30.0),
    "llama3.2":          (0.0, 0.0),
    "llama3":            (0.0, 0.0),
    "llama":             (0.0, 0.0),
    "mistral":           (0.0, 0.0),
    "qwen":              (0.0, 0.0),
}
_DEFAULT_PRICING = (3.0, 15.0)   # fall back to Sonnet-class pricing

# Rough Shodan equivalence so credits can be shown as an approximate dollar
# figure for a unified total. Not every plan is billed per credit, so the UI
# also surfaces the raw credit counts separately.
_USD_PER_QUERY_CREDIT = 0.0020
_USD_PER_SCAN_CREDIT  = 0.0010


def model_pricing(model: str | None) -> tuple[float, float]:
    """Return (input_per_M, output_per_M) USD for the given model name."""
    m = (model or "").lower()
    for key, val in MODEL_PRICING.items():
        if key in m:
            return val
    return _DEFAULT_PRICING


def estimate_run_cost(model: str | None = None, cfg: dict | None = None) -> dict:
    """Estimate the cost of one crew run for the given (or current) settings.

    Returns a transparent breakdown:
      * query_credits / scan_credits — Shodan usage
      * llm_tokens                   — estimated LLM tokens (report + triage + modules)
      * llm_cost_usd                 — dollar cost of those tokens for `model`
      * shodan_cost_usd              — approximate dollar value of Shodan credits
      * total_usd                    — llm_cost_usd + shodan_cost_usd
    """
    s = cfg or get_settings()
    queries = int(s.get("max_queries_per_run", 0) or 0)
    rpq     = int(s.get("max_results_per_query", 0) or 0)
    stages  = s.get("stages", {}) or {}
    modules = s.get("modules", {}) or {}

    # ── Shodan query credits: 1 credit ≈ 100 results, so each query may page. ──
    pages_per_query = max(1, _math.ceil(rpq / 100)) if rpq else 1
    query_credits = queries * pages_per_query

    # ── Shodan scan credits: only when the active nmap stage is enabled. ──
    nmap_on = bool(stages.get("nmap"))
    scan_credits = int(s.get("nmap_max_hosts_per_call", 0) or 0) if nmap_on else 0

    # ── LLM tokens: report synthesis + per-query triage + per-module analysis. ──
    report_on     = bool(stages.get("report"))
    report_tokens = int(s.get("report_max_tokens", 0) or 0) if report_on else 0
    module_count  = sum(1 for v in modules.values() if v)
    triage_tokens = queries * 1200          # summarise/rank each query's results
    module_tokens = module_count * 800      # each enabled capability adds analysis
    llm_tokens    = report_tokens + triage_tokens + module_tokens

    cin, cout = model_pricing(model)
    # Assume ~35% input / ~65% output for analyst-style generation.
    llm_cost_usd = (llm_tokens * 0.35 / 1e6) * cin + (llm_tokens * 0.65 / 1e6) * cout

    shodan_cost_usd = (query_credits * _USD_PER_QUERY_CREDIT
                       + scan_credits * _USD_PER_SCAN_CREDIT)

    total_usd = llm_cost_usd + shodan_cost_usd
    return {
        "queries": queries,
        "results_per_query": rpq,
        "query_credits": query_credits,
        "scan_credits": scan_credits,
        "llm_tokens": llm_tokens,
        "model": model or "unknown",
        "model_input_per_m": cin,
        "model_output_per_m": cout,
        "llm_cost_usd": round(llm_cost_usd, 4),
        "shodan_cost_usd": round(shodan_cost_usd, 4),
        "total_usd": round(total_usd, 4),
        "breakdown": {
            "report_tokens": report_tokens,
            "triage_tokens": triage_tokens,
            "module_tokens": module_tokens,
            "modules_enabled": module_count,
            "pages_per_query": pages_per_query,
            "nmap": nmap_on,
        },
    }


if __name__ == "__main__":
    print("defaults max_results:", max_results())
    print("estimate_run_cost (sonnet):", estimate_run_cost("claude-sonnet-4-6"))
    print("clamp 99999 ->", clamp_results(99999))
    print("\nstages (default):")
    for s in get_stages():
        print(f"  [{'x' if s['enabled'] else ' '}] {s['key']:7} {s['name']}")
    print("\n-> set_stages(['report']) (report alone, recon forced on):")
    set_stages(["report"])
    print("  selected:", selected_stage_keys())
    print("\n-> set_stages(['vuln']) (vuln pulls in recon):")
    set_stages(["vuln"])
    print("  selected:", selected_stage_keys())
    print("\n-> env CREW_STAGES override:")
    os.environ["CREW_STAGES"] = "recon,report"
    print("  selected:", selected_stage_keys())
    os.environ["SHODAN_MAX_RESULTS"] = "350"
    print("  env max_results ->", max_results())
