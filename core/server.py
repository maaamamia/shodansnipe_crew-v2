"""
server.py — FastAPI server for ShodanSnipe.

Run:   uvicorn server:app --reload
Then open http://127.0.0.1:8000

Changes per NEXT_SESSION_SPEC.md:
  - execute_query() now returns (results, warning) tuple — warning propagated to UI
  - /api/llm/goal — AI agent builder: translate goal → proposed Shodan query
  - Free-tier messages surfaced in every search/bulk response
  - /api/config/api-key returns tier info + free_tier_limits flag
"""

from __future__ import annotations

import asyncio
import getpass
import json
import os
import sys
import uuid
import logging
from uuid import uuid4
from datetime import datetime, timezone
from typing import Optional, Any

from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Make this file's own directory importable no matter where it is launched from.
# Without this, `python server.py` run from another folder (or a launcher) fails to
# find db / scope / mcp_tools / etc. This is what caused the MCP module not to load.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
os.chdir(_HERE)  # so relative paths (static/, launchers/) resolve too

import db
import settings
from shodansnipe_core import ShodanQuery, serialize_result as _serialize_result_raw, DataValidator
from scope import Scope, apply_scope, audit
from diff_store import save_snapshot, diff
from query_advisor import FILTER_REFERENCE, TEMPLATES, render_template, suggest_followups
import threat_feeds

# ── Host hygiene: cap absurd port lists and flag CDN/WAF shared edges ─────────────
# Some hosts (esp. CDN/WAF front-ends like Incapsula/Cloudflare/Akamai) report hundreds
# of "open" ports that are shared infrastructure, NOT real service exposure. Left raw,
# one such host dumps >1000 lines of JSON into an agent's context and can stall it. We
# cap the port list (interesting-first), strip the bulky triple port_sources breakdown,
# flag the host, and de-inflate a purely port-based Critical on a CDN edge. Tunable via
# MAX_PORTS_PER_HOST. Every endpoint that serializes a result inherits this.
_CDN_NAMES = (
    "incapsula", "imperva", "cloudflare", "akamai", "fastly", "cloudfront",
    "sucuri", "stackpath", "edgecast", "edgio", "limelight", "front door",
    "cdn77", "keycdn", "cachefly", "bunnycdn", "g-core", "gcore", "qrator",
)
_SIGNAL_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587, 636,
    993, 995, 1433, 1521, 2375, 2376, 3306, 3389, 5432, 5601, 5900, 5985, 6379,
    6443, 8080, 8443, 9000, 9200, 9300, 10250, 11211, 27017,
]
_MAX_PORTS_PER_HOST = max(5, int(os.environ.get("MAX_PORTS_PER_HOST", "40") or "40"))

def _ports_interesting_first(ports):
    sig = [p for p in _SIGNAL_PORTS if p in ports]
    rest = sorted(p for p in ports if p not in _SIGNAL_PORTS)
    seen, out = set(), []
    for p in sig + rest:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out

def _cap_and_flag_host(s):
    ports = s.get("ports") or []
    try:
        ports = [int(p) for p in ports]
    except Exception:
        pass
    n = len(ports)
    org_blob = " ".join(str(s.get(k, "")) for k in ("org", "asn_name", "asn")).lower()
    tags = [str(t).lower() for t in (s.get("tags") or [])]
    is_cdn = ("cdn" in tags) or any(name in org_blob for name in _CDN_NAMES)

    # Always drop the bulky shodan/internetdb/enriched port triple-listing — pure context bloat.
    s.pop("port_sources", None)

    if n > _MAX_PORTS_PER_HOST:
        s["port_count"] = n
        s["ports_capped"] = True
        s["high_port_count_flag"] = True
        s["ports"] = _ports_interesting_first(ports)[:_MAX_PORTS_PER_HOST]
        if is_cdn:
            s["ports_note"] = (
                f"{n} ports reported, but this is a CDN/WAF shared edge — the port list is shared "
                f"infrastructure, NOT real service exposure. Showing top {_MAX_PORTS_PER_HOST}.")
        else:
            s["ports_note"] = (
                f"{n} ports reported (unusually high). Showing top {_MAX_PORTS_PER_HOST}; confirm "
                "real exposure with nmap before trusting this list.")

    if is_cdn:
        s["cdn_shared"] = True
        s["cdn_note"] = (
            "On a CDN/WAF (shared edge). Ports and the many hostnames here are shared across "
            "unrelated tenants — do not attribute them to one target or rate Critical off the "
            "raw port list.")
        # De-inflate a purely port-based Critical on a CDN edge (leave CVE-based risk alone).
        rl = str(s.get("risk_level") or "")
        rfull = str(s.get("risk_full") or s.get("risk_simplified") or "")
        if rl.lower() == "critical" and "port" in rfull.lower():
            s["risk_level_original"] = rl
            s["risk_level"] = "Informational"
            s["risk_full"] = "Informational (CDN/WAF shared edge — port-based risk not host-attributable)"
            s["risk_simplified"] = "Informational - CDN shared edge"
    return s

def serialize_result(r):
    """Wraps core serialize_result: caps huge port lists, strips port_sources bloat, and
    flags CDN/WAF shared edges so one front-end host can't flood or mislead an agent."""
    s = _serialize_result_raw(r)
    try:
        return _cap_and_flag_host(s)
    except Exception:
        return s   # never break serialization over a flagging bug

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")
logger = logging.getLogger(__name__)


def _get_passphrase() -> str:
    pw = os.environ.get("SHODANSNIPE_PASSPHRASE", "").strip()
    if pw:
        logger.info("Passphrase loaded from SHODANSNIPE_PASSPHRASE env var")
        return pw
    # Prompt — handle Python 3.14 Windows getpass bug gracefully
    print("\nShodanSnipe — encrypted DB passphrase required.")
    print("(Tip: set $env:SHODANSNIPE_PASSPHRASE to skip this prompt)\n")
    try:
        return getpass.getpass("Passphrase: ")
    except (KeyboardInterrupt, Exception):
        # Fallback for Python 3.14 Windows where getpass raises KeyboardInterrupt
        try:
            import msvcrt
            print("Passphrase: ", end="", flush=True)
            chars = []
            while True:
                c = msvcrt.getwch()
                if c in ("\r", "\n"):
                    print()
                    break
                elif c == "\x03":  # Ctrl+C
                    raise KeyboardInterrupt
                elif c == "\x08":  # Backspace
                    if chars:
                        chars.pop()
                else:
                    chars.append(c)
            return "".join(chars)
        except ImportError:
            # Non-Windows fallback
            return input("Passphrase (visible): ")


_passphrase = _get_passphrase()
try:
    db.init(_passphrase)
except ValueError as e:
    sys.exit(f"Database init failed: {e}")
del _passphrase

logger.info("=" * 60)
logger.info("  ShodanSnipe v1.0 — NEW server.py loaded correctly")
logger.info("  Endpoints: /api/llm/goal  /api/search  /api/bulk")
logger.info("  If you see ImportError or 404 on /api/llm/goal,")
logger.info("  you are running the OLD server.py — replace it.")
logger.info("=" * 60)

# ---------------------------------------------------------------------------
# App state
# ---------------------------------------------------------------------------
from contextlib import asynccontextmanager

# MCP is optional: if fastmcp / mcp_tools isn't available the REST UI still runs,
# we just don't expose /mcp (and we log why).
try:
    from mcp_tools import mcp_app
    _MCP_ENABLED = True
except Exception as _mcp_err:               # pragma: no cover
    mcp_app = None
    _MCP_ENABLED = False
    logger.warning("MCP endpoint disabled — could not import mcp_tools: %s", _mcp_err)


@asynccontextmanager
async def _lifespan(app):
    """Run the MCP session manager (if enabled) plus the existing startup restore."""
    if _MCP_ENABLED:
        async with mcp_app.lifespan(app):
            await _startup_restore_engine()   # late-bound; defined further down
            yield
    else:
        await _startup_restore_engine()
        yield


app = FastAPI(title="ShodanSnipe", version="1.0.0", lifespan=_lifespan)

# Mount the MCP endpoint in THIS process — one `python server.py`, no extra script.
if _MCP_ENABLED:
    app.mount("/mcp", mcp_app)
    logger.info("MCP endpoint mounted at /mcp (streamable-http)")


# ── Global exception handlers — ALWAYS return JSON, never plain text ──
from fastapi import Request
from fastapi.exceptions import RequestValidationError

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("Unhandled exception on %s: %s", request.url, exc, exc_info=True)
    return JSONResponse(status_code=500, content={"detail": str(exc)})

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": str(exc)})

_engine: ShodanQuery | None = None

# ── Scope persistence ─────────────────────────────────────────────────────────
# Scope used to live only in memory, so it reset to empty on every server restart.
# Persist it to a JSON file next to server.py and reload on startup.
_SCOPE_STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".shodansnipe_scope.json")

def _save_scope_dict(d: dict) -> None:
    try:
        with open(_SCOPE_STORE, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2)
    except Exception:
        pass

def _load_scope() -> Scope:
    try:
        with open(_SCOPE_STORE, "r", encoding="utf-8") as f:
            return Scope.from_dict(json.load(f))
    except Exception:
        return Scope(name="(none)")

_current_scope: Scope = _load_scope()

# ── Run history persistence ───────────────────────────────────────────────────
# Every crew run is captured here (timestamp, scope, mode, settings snapshot and
# its estimated cost) so the Control Center can show a run log with costs that
# survives a server restart — same pattern as the scope store above.
_RUNS_STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".shodansnipe_runs.json")
_MAX_RUNS_KEPT = 200

def _load_runs() -> list[dict]:
    try:
        with open(_RUNS_STORE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []

def _save_runs(runs: list[dict]) -> None:
    try:
        with open(_RUNS_STORE, "w", encoding="utf-8") as f:
            json.dump(runs[:_MAX_RUNS_KEPT], f, indent=2)
    except Exception:
        pass

def _record_run(record: dict) -> dict:
    """Prepend a run record (newest first) and persist it."""
    runs = _load_runs()
    runs.insert(0, record)
    _save_runs(runs)
    return record


# ── Findings persistence ──────────────────────────────────────────────────────
# Structured findings captured from crew runs so the GUI can show enriched fields, the user can
# add arbitrary columns (any key on a finding becomes a column), and export at any time. Same
# durable JSON-store pattern as runs/scope above — independent of the search-results DB.
_FINDINGS_STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".shodansnipe_findings.json")
_MAX_FINDINGS_KEPT = 5000

def _load_findings() -> list[dict]:
    try:
        with open(_FINDINGS_STORE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []

def _save_findings(items: list[dict]) -> None:
    try:
        with open(_FINDINGS_STORE, "w", encoding="utf-8") as f:
            json.dump(items[:_MAX_FINDINGS_KEPT], f, indent=2)
    except Exception:
        pass

def _finding_columns(items: list[dict]) -> list[str]:
    """Union of all keys across findings, with the common ones first — so the GUI/export show
    every column the user has added, in a stable, readable order."""
    preferred = ["id", "title", "severity", "confidence", "asset", "ip", "port", "hostname",
                 "product", "version", "cve", "evidence", "impact", "fix", "scope",
                 "control_surface", "source", "run_id", "recorded_at"]
    seen = list(preferred)
    extra: list[str] = []
    for it in items:
        for k in it.keys():
            if k not in seen and k not in extra:
                extra.append(k)
    return [c for c in preferred if any(c in it for it in items)] + extra

_last_results: list[dict] = []
_last_query: str = ""
_last_search_id: int | None = None
_current_tier: str = "free"  # updated on health check and key set


def _ensure_results() -> bool:
    """
    If _last_results is empty but we have a search_id, reload from DB.
    Returns True if results are available.
    """
    global _last_results, _last_query
    if _last_results:
        return True
    if _last_search_id is not None:
        record = db.search_load(_last_search_id)
        if record and record.get("results"):
            _last_results = record["results"]
            _last_query = record.get("query", _last_query)
            logger.info("Reloaded %d results from search_id=%s", len(_last_results), _last_search_id)
            return True
    # Last resort: load the most recent search from history
    history = db.search_history(limit=1)
    if history:
        record = db.search_load(history[0]["id"])
        if record and record.get("results"):
            _last_results = record["results"]
            _last_query = record.get("query", "")
            logger.info("Auto-restored results from last search (id=%s)", history[0]["id"])
            return True
    return False


def _get_engine() -> ShodanQuery:
    global _engine
    if _engine is None:
        key = db.get_config("shodan_api_key")
        if not key:
            raise HTTPException(503, "No Shodan API key set. POST one to /api/config/api-key.")
        _engine = ShodanQuery(key)
    return _engine


def _reset_engine() -> None:
    global _engine
    _engine = None


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class ScopeIn(BaseModel):
    name: str = "default"
    cidrs: list[str] = []
    domains: list[str] = []
    asns: list[str] = []
    orgs: list[str] = []


class SearchIn(BaseModel):
    query: str
    limit: int = Field(25, ge=1)  # upper bound clamped to settings in-handler
    enrich: bool = False
    tags: Optional[list[str]] = None
    override_scope: bool = False
    override_reason: str = ""


class BulkIn(BaseModel):
    ips: list[str]
    enrich: bool = False
    override_scope: bool = False
    override_reason: str = ""


class TemplateRenderIn(BaseModel):
    template_id: str
    params: dict[str, str] = {}


class SaveIn(BaseModel):
    label: str
    query: str
    watched: bool = False


class DiffIn(BaseModel):
    query: str
    limit: int = Field(25, ge=1)  # upper bound clamped to settings in-handler
    enrich: bool = False
    override_scope: bool = False
    override_reason: str = ""
    save_snapshot: bool = True


class SuggestIn(BaseModel):
    query: str


class ApiKeyIn(BaseModel):
    api_key: str


class GoalIn(BaseModel):
    """AI Agent Builder: translate a natural-language goal into a Shodan query."""
    goal: str
    provider: Optional[str] = None


# ---------------------------------------------------------------------------
# Static UI — search multiple locations so it works regardless of CWD
# ---------------------------------------------------------------------------
def _find_static_dir() -> str:
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"),
        os.path.join(os.getcwd(), "static"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "static"),
    ]
    for c in candidates:
        if os.path.isdir(c) and os.path.exists(os.path.join(c, "index.html")):
            return c
    # Return the __file__-relative path even if it doesn't exist yet
    return candidates[0]

STATIC_DIR = _find_static_dir()
logger.info("Static dir: %s (exists: %s)", STATIC_DIR, os.path.isdir(STATIC_DIR))
if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")



# ── STARTUP: restore engine from persisted key (called from _lifespan) ──────
async def _startup_restore_engine():
    global _engine
    try:
        key = db.get_config("shodan_api_key")
        if key:
            _engine = ShodanQuery(key)
            logger.info("Shodan engine restored from saved key on startup")
    except Exception as e:
        logger.warning("Could not restore Shodan engine on startup: %s", e)


@app.get("/")
def index() -> FileResponse:
    path = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(path):
        # Give a helpful message showing where it's looking
        raise HTTPException(404, (
            f"UI not installed. Expected: {path}\n"
            f"Fix: create a 'static' folder next to server.py and put index.html in it.\n"
            f"server.py is at: {os.path.abspath(__file__)}"
        ))
    return FileResponse(path)


def _logo_path() -> str:
    # Use STATIC_DIR (already correctly resolved) as primary source
    candidates = [
        os.path.join(STATIC_DIR, "logo.svg"),
        os.path.join(os.path.dirname(STATIC_DIR), "logo.svg"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "logo.svg"),
        os.path.join(os.getcwd(), "static", "logo.svg"),
        os.path.join(os.getcwd(), "logo.svg"),
    ]
    for p in candidates:
        if os.path.exists(p):
            logger.info("logo.svg found at: %s", p)
            return p
    logger.warning("logo.svg not found. Searched: %s", candidates)
    return ""

@app.get("/logo.svg")
def logo():
    from fastapi.responses import Response
    p = _logo_path()
    if p:
        return FileResponse(p, media_type="image/svg+xml")
    # Always serve embedded logo as fallback — never 404
    return Response(content=_LOGO_SVG, media_type="image/svg+xml")

@app.get("/favicon.ico")
def favicon() -> FileResponse:
    p = _logo_path()
    if not p:
        raise HTTPException(404)
    return FileResponse(p, media_type="image/svg+xml")


# ---------------------------------------------------------------------------
# Tier classification
# ---------------------------------------------------------------------------
def _classify_tier(info: dict) -> dict:
    plan = (info.get("plan") or "").lower()
    unlocked = bool(info.get("unlocked", False))

    if plan in {"enterprise"}:
        tier, label = "enterprise", "Enterprise"
    elif plan in {"corporate", "small-business", "asm"}:
        tier, label = "enterprise", "Corporate"
    elif plan in {"edu", "gov"}:
        tier, label = "enterprise", plan.upper()
    elif plan in {"member", "freelancer", "academic", "plus", "business", "professional", "enterprise-plus"}:
        tier, label = "member", plan.capitalize()
    elif plan in {"oss", "dev", ""}:
        tier, label = "free", "Free"
    else:
        tier, label = ("member" if unlocked else "free"), plan or "unknown"

    usage_limits = info.get("usage_limits", {}) or {}
    qc_limit = usage_limits.get("query_credits", 0)
    qc_remaining = info.get("query_credits", 0)
    qc_used = max(qc_limit - qc_remaining, 0) if qc_limit else None

    sc_limit = usage_limits.get("scan_credits", 0)
    sc_remaining = info.get("scan_credits", 0)
    sc_used = max(sc_limit - sc_remaining, 0) if sc_limit else None

    return {
        "tier": tier,
        "tier_label": label,
        "plan": plan or "unknown",
        "unlocked": unlocked,
        "can_use_paid_filters": unlocked,
        # Flag the UI to explain free-tier limitations
        "free_tier_limits": tier == "free",
        "https": bool(info.get("https", False)),
        "telnet": bool(info.get("telnet", False)),
        "usage": {
            "query_credits_used": qc_used,
            "query_credits_remaining": qc_remaining,
            "query_credits_limit": qc_limit or None,
            "scan_credits_used": sc_used,
            "scan_credits_remaining": sc_remaining,
            "scan_credits_limit": sc_limit or None,
        },
    }


# ---------------------------------------------------------------------------
# Meta / health
# ---------------------------------------------------------------------------
@app.get("/api/tier")
def get_tier() -> dict:
    """Return current Shodan plan tier for AI context injection."""
    return {"tier": _current_tier}


@app.get("/api/version")
def version() -> dict:
    """Which build is loaded + which feature routes are present. One call ends the
    'am I running the right server.py / right tree?' guessing."""
    want = ["/api/settings", "/api/settings/reset", "/api/crew/stages",
            "/api/crew/modules", "/api/crew/profiles", "/api/crew/profile",
            "/api/crew/run", "/api/mcp/tools", "/mcp"]
    have = {getattr(r, "path", "") for r in app.routes}
    routes = {p: (p in have) for p in want}
    sel = {}
    try:
        sel = {"profile": settings.get_settings().get("profile"),
               "stages": settings.selected_stage_keys(),
               "modules_on": len(settings.selected_module_keys()),
               "store": getattr(settings, "_FILE_STORE", None),
               "store_exists": os.path.exists(getattr(settings, "_FILE_STORE", "")),
               "uses_db": getattr(settings, "_HAS_DB", False)}
    except Exception as e:
        sel = {"error": str(e)}
    return {"build": "shodansnipe-controlcenter-1",
            "file": os.path.abspath(__file__),
            "cwd": os.getcwd(),
            "mcp_enabled": bool(globals().get("_MCP_ENABLED", False)),
            "routes": routes,
            "all_present": all(routes.values()),
            "total_routes": len(have),
            "saved_settings": sel}


@app.get("/api/health")
def health() -> dict:
    key = db.get_config("shodan_api_key")
    if not key:
        return {
            "status": "needs_api_key",
            "tier": "free",
            "tier_label": "no key",
            "can_use_paid_filters": False,
            "free_tier_limits": True,
            "usage": {},
        }
    try:
        info = _get_engine().api_info()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(503, f"Shodan API not reachable: {e}")
    tier_data = _classify_tier(info)
    _current_tier = tier_data.get("tier", "free")
    return {"status": "ok", **tier_data}


@app.post("/api/config/api-key")
def set_api_key(body: ApiKeyIn) -> dict:
    key = body.api_key.strip()
    if len(key) < 10:
        raise HTTPException(400, "API key looks too short to be valid")
    db.set_config("shodan_api_key", key)
    _reset_engine()
    try:
        info = _get_engine().api_info()
        tier_info = _classify_tier(info)
        _current_tier = tier_info.get("tier", "free")
        audit("api_key_set", {"plan": tier_info["plan"], "tier": tier_info["tier"]})
        return {"status": "ok", **tier_info}
    except Exception as e:
        raise HTTPException(401, f"Key saved but Shodan rejected it: {e}")


@app.delete("/api/config/api-key")
def clear_api_key() -> dict:
    db.delete_config("shodan_api_key")
    _reset_engine()
    return {"cleared": True}


# ---------------------------------------------------------------------------
# Filters + templates
# ---------------------------------------------------------------------------
@app.get("/api/filters")
def filters() -> dict:
    return {"filters": FILTER_REFERENCE}


@app.get("/api/templates")
def templates_list() -> dict:
    return {"templates": TEMPLATES}


@app.post("/api/templates/render")
def render(body: TemplateRenderIn) -> dict:
    q = render_template(body.template_id, body.params)
    if q is None:
        raise HTTPException(404, f"Unknown template: {body.template_id}")
    return {"query": q}


# ---------------------------------------------------------------------------
# Query inspection
# ---------------------------------------------------------------------------
PAID_FILTERS = {
    "vuln:": "Shodan CVE matching",
    "has_screenshot:": "screenshot data",
    "has_vuln:": "vulnerability flag",
}


@app.post("/api/inspect-query")
def inspect_query(body: dict = Body(...)) -> dict:
    q = (body.get("query") or "").lower()
    if not q:
        return {"paid_features": [], "can_run": True}
    features = [name for prefix, name in PAID_FILTERS.items() if prefix in q]
    try:
        info = _get_engine().api_info()
        unlocked = bool(info.get("unlocked", False))
    except Exception:
        unlocked = False
    return {
        "paid_features": features,
        "can_run": (not features) or unlocked,
        "unlocked": unlocked,
    }


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------
@app.post("/api/scope")
def set_scope(body: ScopeIn) -> dict:
    global _current_scope
    _current_scope = Scope.from_dict(body.dict())
    _save_scope_dict(body.dict())          # persist so it survives a server restart
    audit("scope_installed", {"scope": _current_scope.name, "summary": _current_scope.summary()})
    return {"scope": _current_scope.summary()}


@app.post("/api/scope/set")
def scope_set_alias(body: dict = Body(...)) -> dict:
    """Alias for /api/scope (POST) — some UI versions call /api/scope/set."""
    scope_body = ScopeIn(**{k: v for k, v in body.items() if k in ScopeIn.__fields__})
    return set_scope(scope_body)          # set_scope persists + returns the summary


@app.get("/api/scope")
def get_scope() -> dict:
    return {
        "name": _current_scope.name,
        "cidrs": _current_scope.cidrs,
        "domains": _current_scope.domains,
        "asns": _current_scope.asns,
        "orgs": _current_scope.orgs,
        "summary": _current_scope.summary(),
        "is_empty": _current_scope.is_empty(),
    }


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------
_ANCHOR_KEYS = (
    "hostname", "org", "net", "asn", "ip", "autonomous_system",
    "ssl.cert.subject.cn", "ssl.cert.subject.o", "ssl.cert.issuer.cn",
)

def _query_anchor_problem(query: str) -> str:
    """Return a human-readable reason if a query has no usable scope anchor — i.e. it would
    scan the whole internet (e.g. 'hostname:' with no value, 'ssl.cert.subject.cn:' empty,
    a trailing-dot hostname like 'hostname:accounts.', or only negations). Returns '' when the
    query has at least one usable positive constraint. This is what stops broad queries from
    being sent to Shodan and timing out."""
    import shlex
    q = (query or "").strip()
    if not q:
        return "empty query"
    try:
        toks = shlex.split(q)
    except ValueError:
        toks = q.split()
    positive_value = False     # any usable positive constraint (filter value or bare keyword)
    void_anchors = []
    for t in toks:
        if not t or t.startswith("-"):     # negations never anchor scope
            continue
        if ":" not in t:                   # bare keyword term — usable on its own
            positive_value = True
            continue
        key, _, val = t.partition(":")
        val = val.strip().strip('"').strip("'")
        if not val:                        # hostname: / org: / ssl.cert.subject.cn:  (empty)
            void_anchors.append(f"{key}:")
        elif val.endswith("."):            # hostname:accounts.  → empty domain
            void_anchors.append(f"{key}:{val}")
        else:
            positive_value = True          # a real, non-empty filter value
    if positive_value:
        return ""
    if void_anchors:
        return "anchor(s) have empty/malformed values: " + ", ".join(void_anchors[:4])
    return "no positive scope anchor (only negations)"


@app.post("/api/search")
async def search(body: SearchIn) -> dict:
    global _last_results, _last_query
    try:
        engine = _get_engine()
    except HTTPException as e:
        # Return JSON 503 with instructions instead of crashing the UI
        return JSONResponse(
            status_code=503,
            content={
                "error": "no_api_key",
                "detail": str(e.detail),
                "fix": (
                    "Go to ⚙ Config → API Key and enter your Shodan API key. "
                    "Or POST to /api/config/api-key with {api_key: 'your-key'}."
                ),
                "results": [],
                "total_returned": 0,
                "in_scope": 0,
                "out_of_scope": 0,
                "warning": "No Shodan API key configured.",
            }
        )

    # Control Center / settings reflect here, so the GUI *and* the MCP shodan_search
    # (which both call /api/search) obey the saved max-results preference.
    body.limit = settings.clamp_results(min(body.limit, settings.max_results()))
    audit("search_start", {"query": body.query, "limit": body.limit, "enrich": body.enrich})

    # Guard: refuse internet-wide queries (empty/malformed anchors) BEFORE hitting Shodan.
    # An empty filter like 'hostname:' or 'ssl.cert.subject.cn:' scans the whole internet and
    # times out; reject it with an actionable message so the agent re-queries with an anchor.
    anchor_problem = _query_anchor_problem(body.query)
    if anchor_problem:
        audit("search_refused_broad", {"query": body.query, "reason": anchor_problem})
        return {
            "error": "query_too_broad",
            "detail": f"Refusing internet-wide search — {anchor_problem}.",
            "results": [],
            "total_returned": 0,
            "in_scope": 0,
            "out_of_scope": 0,
            "warning": (
                f"Refused: {anchor_problem}. Anchor the query to scope "
                "(org:\"...\" / net:CIDR / asn:ASxxxx / hostname:domain). A filter with an empty "
                "value (e.g. 'hostname:') searches the whole internet and will time out."
            ),
        }

    raw_results, warning = await engine.execute_query(
        body.query, limit=body.limit, tags=body.tags, enrich=body.enrich
    )
    in_scope, out_of_scope = apply_scope(raw_results, _current_scope, override=True, query=body.query)

    visible = in_scope + out_of_scope
    _last_results = visible
    _last_query = body.query

    serialized = [serialize_result(r) for r in visible]
    in_scope_ips = {r.get("ip_str") for r in in_scope}
    for s in serialized:
        s["in_scope"] = s["ip_str"] in in_scope_ips

    search_id = db.search_record(body.query, _current_scope.name, serialized, override=False)
    _last_search_id = search_id

    audit("search_complete", {
        "query": body.query,
        "search_id": search_id,
        "total_returned": len(raw_results),
        "in_scope": len(in_scope),
        "out_of_scope": len(out_of_scope),
    })

    return {
        "query": body.query,
        "search_id": search_id,
        "total_returned": len(raw_results),
        "in_scope": len(in_scope),
        "out_of_scope": len(out_of_scope),
        "results": serialized,
        # Free-tier warning surfaced in the response so UI can display it
        "warning": warning,
    }


@app.post("/api/bulk")
async def bulk(body: BulkIn) -> dict:
    """Bulk IP lookup. Uses api.host() per IP — works on free keys."""
    global _last_results, _last_query
    engine = _get_engine()
    ips = [ip.strip() for ip in body.ips if ip.strip()]
    if not ips:
        raise HTTPException(400, "No IPs provided")

    audit("bulk_start", {"ip_count": len(ips), "enrich": body.enrich})

    raw, warning = await engine.execute_query(query="", limit=len(ips), enrich=body.enrich, ip_list=ips)
    in_scope, out_of_scope = apply_scope(raw, _current_scope, override=True, query=f"bulk({len(ips)})")
    visible = in_scope + out_of_scope
    _last_results = visible
    _last_query = f"bulk({len(ips)} IPs)"

    serialized = [serialize_result(r) for r in visible]
    in_scope_ips = {r.get("ip_str") for r in in_scope}
    for s in serialized:
        s["in_scope"] = s["ip_str"] in in_scope_ips

    bulk_search_id = db.search_record(f"bulk({len(ips)} IPs)", _current_scope.name, serialized, override=False)
    _last_search_id = bulk_search_id
    return {
        "ip_count": len(ips),
        "in_scope": len(in_scope),
        "out_of_scope": len(out_of_scope),
        "results": serialized,
        "warning": warning,
        "search_id": bulk_search_id,
    }


# ---------------------------------------------------------------------------
# Suggestions (propose-approve loop)
# ---------------------------------------------------------------------------
@app.post("/api/suggest")
def suggest(body: SuggestIn) -> dict:
    return {"suggestions": suggest_followups(body.query, _last_results)}


# ---------------------------------------------------------------------------
# Saved searches
# ---------------------------------------------------------------------------
@app.get("/api/saved")
def list_saved() -> dict:
    return {"saved": db.saved_list()}


@app.post("/api/saved")
def add_saved(body: SaveIn) -> dict:
    return db.saved_add(uuid.uuid4().hex[:12], body.label.strip(), body.query.strip(), body.watched)


@app.delete("/api/saved/{item_id}")
def del_saved(item_id: str) -> dict:
    return {"deleted": db.saved_delete(item_id)}


# ---------------------------------------------------------------------------
# Diff mode
# ---------------------------------------------------------------------------
@app.post("/api/diff")
async def run_diff(body: DiffIn) -> dict:
    global _last_results, _last_query
    engine = _get_engine()

    raw, warning = await engine.execute_query(body.query, limit=body.limit, enrich=body.enrich)
    in_scope, out_of_scope = apply_scope(raw, _current_scope, override=True, query=body.query)
    visible = in_scope + out_of_scope

    diff_report = diff(body.query, _current_scope.name, visible)

    if body.save_snapshot:
        save_snapshot(body.query, _current_scope.name, visible)
        audit("snapshot_saved", {"query": body.query, "scope": _current_scope.name, "result_count": len(visible)})

    _last_results = visible
    _last_query = body.query

    return {
        "query": body.query,
        "result_count": len(visible),
        "diff": diff_report,
        "results": [serialize_result(r) for r in visible],
        "warning": warning,
    }


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
@app.get("/api/audit")
def audit_tail_endpoint(limit: int = 50) -> dict:
    return {"events": db.audit_tail(limit)}


# ---------------------------------------------------------------------------
# Search history
# ---------------------------------------------------------------------------
@app.get("/api/history")
def history(limit: int = 50) -> dict:
    return {"history": db.search_history(limit)}


@app.get("/api/history/{search_id}")
def history_load(search_id: int) -> dict:
    global _last_results, _last_query, _last_search_id
    record = db.search_load(search_id)
    if not record:
        raise HTTPException(404, "Search not found")
    # Restore in-memory state so triage works on historical results
    _last_results = record.get("results", [])
    _last_query = record.get("query", "")
    _last_search_id = search_id
    return record


@app.delete("/api/history/{search_id}")
def history_delete(search_id: int) -> dict:
    return {"deleted": db.search_delete(search_id)}


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------
@app.post("/api/export/csv")
def export_csv() -> Response:
    import csv
    import io

    if not _last_results:
        raise HTTPException(404, "No results to export. Run a search first.")

    buf = io.StringIO()
    fields = ["IP", "Ports", "Port_Count", "Org", "ASN", "Country", "City",
              "Hostnames", "Product", "OS", "Tags", "CVEs", "CVE_Count",
              "CPEs", "Risk_Level", "Risk", "HTTP_Title", "SSL_Subject", "Enriched"]
    w = csv.DictWriter(buf, fieldnames=fields, quoting=csv.QUOTE_ALL)
    w.writeheader()
    for r in _last_results:
        s = serialize_result(r)
        w.writerow({
            "IP": s["ip_str"],
            "Ports": ", ".join(map(str, s["ports"])),
            "Port_Count": s["port_count"],
            "Org": s["org"],
            "ASN": s["asn"],
            "Country": s["country"],
            "City": s["city"],
            "Hostnames": ", ".join(s["hostnames"]),
            "Product": s["product"],
            "OS": s["os"],
            "Tags": ", ".join(s["tags"]),
            "CVEs": ", ".join(s["cves"]),
            "CVE_Count": s["cve_count"],
            "CPEs": ", ".join(s["cpes_internetdb"]),
            "Risk_Level": s["risk_level"],
            "Risk": s["risk_simplified"],
            "HTTP_Title": s["http_title"],
            "SSL_Subject": s["ssl_subject"],
            "Enriched": "Yes" if s["enriched"] else "No",
        })
    audit("export_csv", {"query": _last_query, "rows": len(_last_results)})
    csv_bytes = buf.getvalue().encode("utf-8-sig")
    return Response(
        content=csv_bytes,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="shodansnipe_{int(datetime.now().timestamp())}.csv"'},
    )


@app.post("/api/export/json")
def export_json() -> Response:
    if not _last_results:
        raise HTTPException(404, "No results to export.")
    payload = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "query": _last_query,
        "scope": _current_scope.summary(),
        "results": [serialize_result(r) for r in _last_results],
    }
    audit("export_json", {"query": _last_query, "rows": len(_last_results)})
    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="shodansnipe_{int(datetime.now().timestamp())}.json"'},
    )


# ---------------------------------------------------------------------------
# AI Triage + AI Agent Builder
# ---------------------------------------------------------------------------
import llm
# Embedded logo SVG (fallback when logo.svg file not found)
_LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128" role="img" aria-label="ShodanSnipe logo">
  <defs>
    <radialGradient id="glow" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#ffb347" stop-opacity="0.35"/>
      <stop offset="70%" stop-color="#ffb347" stop-opacity="0"/>
    </radialGradient>
    <linearGradient id="ring" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#ffd089"/>
      <stop offset="100%" stop-color="#e8861e"/>
    </linearGradient>
  </defs>

  <!-- background plate -->
  <rect x="2" y="2" width="124" height="124" rx="22" fill="#0e1116" stroke="#1f242c" stroke-width="1.5"/>

  <!-- ambient glow -->
  <circle cx="64" cy="64" r="50" fill="url(#glow)"/>

  <!-- concentric rings -->
  <circle cx="64" cy="64" r="44" fill="none" stroke="url(#ring)" stroke-width="1.5" opacity="0.55"/>
  <circle cx="64" cy="64" r="32" fill="none" stroke="url(#ring)" stroke-width="1.5" opacity="0.75"/>
  <circle cx="64" cy="64" r="20" fill="none" stroke="url(#ring)" stroke-width="1.5"/>

  <!-- aperture blades (4-way crosshair, broken) -->
  <g stroke="#ffb347" stroke-width="2" stroke-linecap="round">
    <line x1="64" y1="14" x2="64" y2="30"/>
    <line x1="64" y1="98" x2="64" y2="114"/>
    <line x1="14" y1="64" x2="30" y2="64"/>
    <line x1="98" y1="64" x2="114" y2="64"/>
  </g>

  <!-- diagonal tick marks -->
  <g stroke="#ffb347" stroke-width="1.25" opacity="0.6">
    <line x1="28" y1="28" x2="36" y2="36"/>
    <line x1="100" y1="28" x2="92" y2="36"/>
    <line x1="28" y1="100" x2="36" y2="92"/>
    <line x1="100" y1="100" x2="92" y2="92"/>
  </g>

  <!-- center dot with ring -->
  <circle cx="64" cy="64" r="6" fill="#0e1116" stroke="#ffb347" stroke-width="2"/>
  <circle cx="64" cy="64" r="2" fill="#ffb347"/>

  <!-- subtle scan line -->
  <line x1="64" y1="64" x2="104" y2="44" stroke="#ffb347" stroke-width="1" opacity="0.4" stroke-dasharray="2 3"/>
</svg>
"""


class LLMSettingsIn(BaseModel):
    provider: str
    model: str
    endpoint: Optional[str] = None
    anthropic_key: Optional[str] = None
    openai_key: Optional[str] = None


class TriageIn(BaseModel):
    provider: Optional[str] = None
    persona: Optional[str] = "asm"  # "asm" | "ti"


class ExplainHostIn(BaseModel):
    ip: str
    provider: Optional[str] = None


@app.get("/api/llm/settings")
def llm_settings_get() -> dict:
    return llm.get_settings()


@app.post("/api/llm/settings")
def llm_settings_set(body: LLMSettingsIn) -> dict:
    llm.set_settings(body.provider, body.model, body.endpoint, body.anthropic_key, body.openai_key)
    audit("llm_settings_changed", {"provider": body.provider, "model": body.model})
    return llm.get_settings()


@app.post("/api/llm/goal")
async def llm_goal(body: GoalIn) -> dict:
    """
    AI Agent Builder — propose-approve loop, step 1.
    User provides a natural-language goal; AI proposes a Shodan query + rationale.
    The human reviews and decides whether to run it. Nothing is executed here.
    """
    if not body.goal.strip():
        raise HTTPException(400, "Goal cannot be empty.")
    # Expose current tier in response for UI display

    try:
        result = await llm.goal_to_query(body.goal.strip(), body.provider, tier=_current_tier)
        audit("llm_goal", {"goal": body.goal, "provider": body.provider or "default"})
        return result
    except Exception as e:
        raise HTTPException(500, f"LLM call failed: {e}")


@app.post("/api/llm/summarize")
async def llm_summarize(body: TriageIn) -> dict:
    _ensure_results()
    if not _last_results:
        raise HTTPException(400, "No results to summarize. Run a search first (or load a previous search from History).")
    try:
        text = await llm.summarize(_last_query, [serialize_result(r) for r in _last_results], body.provider, persona=body.persona or "asm")
        audit("llm_summarize", {"query": _last_query, "provider": body.provider or "default", "results": len(_last_results)})
        return {"summary": text}
    except Exception as e:
        raise HTTPException(500, f"LLM call failed: {e}")


@app.post("/api/llm/rank")
async def llm_rank(body: TriageIn) -> dict:
    _ensure_results()
    if not _last_results:
        raise HTTPException(400, "No results to rank. Run a search first.")
    try:
        ranked = await llm.rank(_last_query, [serialize_result(r) for r in _last_results], body.provider)
        audit("llm_rank", {"query": _last_query, "provider": body.provider or "default", "results": len(_last_results)})
        return {"ranked": ranked}
    except Exception as e:
        raise HTTPException(500, f"LLM call failed: {e}")


@app.post("/api/llm/explain")
async def llm_explain(body: ExplainHostIn) -> dict:
    _ensure_results()
    host = next((r for r in _last_results if r.get("ip_str") == body.ip), None)
    if not host:
        raise HTTPException(404, f"Host {body.ip} not in current result set.")
    try:
        text = await llm.explain_host(serialize_result(host), body.provider)
        audit("llm_explain", {"ip": body.ip, "provider": body.provider or "default"})
        return {"explanation": text}
    except Exception as e:
        raise HTTPException(500, f"LLM call failed: {e}")


@app.post("/api/llm/suggest")
async def llm_suggest(body: TriageIn) -> dict:
    _ensure_results()
    if not _last_results:
        raise HTTPException(400, "No results to base suggestions on. Run a search first.")
    try:
        items = await llm.suggest_queries(_last_query, [serialize_result(r) for r in _last_results], body.provider, tier=_current_tier)
        audit("llm_suggest", {"query": _last_query, "provider": body.provider or "default", "suggestions": len(items)})
        return {"suggestions": items}
    except Exception as e:
        raise HTTPException(500, f"LLM call failed: {e}")


# ---------------------------------------------------------------------------
# AI Conversation History
# ---------------------------------------------------------------------------
class AiMessageIn(BaseModel):
    session_id: str
    role: str  # 'user' | 'assistant' | 'system'
    content: str
    search_id: Optional[int] = None


@app.post("/api/ai/message")
def ai_message_save(body: AiMessageIn) -> dict:
    """Save a single AI conversation message."""
    msg_id = db.ai_message_add(body.session_id, body.role, body.content, body.search_id)
    return {"id": msg_id}


@app.get("/api/ai/history/{session_id}")
def ai_history_get(session_id: str, limit: int = 200) -> dict:
    """Get full conversation history for a session."""
    messages = db.ai_session_history(session_id, limit=limit)
    return {"session_id": session_id, "messages": messages}


@app.get("/api/ai/sessions")
def ai_sessions() -> dict:
    """List recent AI sessions."""
    return {"sessions": db.ai_all_sessions()}


@app.get("/api/ai/latest-session")
def ai_latest_session() -> dict:
    """Return the most recent session_id for auto-resume."""
    sid = db.ai_latest_session()
    return {"session_id": sid}


@app.delete("/api/ai/session/{session_id}")
def ai_session_delete(session_id: str) -> dict:
    """Clear a session's history from the DB."""
    with db._lock:
        db._c().execute("DELETE FROM ai_messages WHERE session_id=?", (session_id,))
        db._c().commit()
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Workspace endpoints
# ---------------------------------------------------------------------------
class WorkspaceSaveIn(BaseModel):
    name: str
    description: str = ""
    query: str = ""
    session_id: str = ""
    results_snapshot: str = ""   # JSON of serialized results
    panel_layout: str = ""       # JSON of panel state
    tags: str = ""


@app.get("/api/workspaces")
def list_workspaces() -> dict:
    return {"workspaces": db.workspace_list()}


@app.post("/api/workspaces")
def save_workspace(body: WorkspaceSaveIn) -> dict:
    ws_id = db.workspace_save(
        name=body.name.strip(),
        description=body.description,
        query=body.query,
        search_id=_last_search_id,
        session_id=body.session_id,
        results_snapshot=body.results_snapshot,
        panel_layout=body.panel_layout,
        tags=body.tags,
    )
    audit("workspace_saved", {"id": ws_id, "name": body.name})
    return {"workspace_id": ws_id}


@app.get("/api/workspaces/{ws_id}")
def load_workspace(ws_id: int) -> dict:
    global _last_results, _last_query, _last_search_id
    ws = db.workspace_load(ws_id)
    if not ws:
        raise HTTPException(404, "Workspace not found")
    # Restore in-memory state if results_snapshot present
    if ws.get("results_snapshot"):
        try:
            import json as _json
            _last_results = _json.loads(ws["results_snapshot"])
            _last_query = ws.get("query", "")
            _last_search_id = ws.get("search_id")
        except Exception as e:
            logger.warning("Could not restore results from workspace: %s", e)
    audit("workspace_loaded", {"id": ws_id, "name": ws.get("name")})
    return ws


@app.delete("/api/workspaces/{ws_id}")
def delete_workspace(ws_id: int) -> dict:
    count = db.workspace_delete(ws_id)
    return {"deleted": count > 0}


@app.post("/api/clear/results")
def clear_results() -> dict:
    """Clear in-memory results (called after user confirms + optionally saves workspace)."""
    global _last_results, _last_query, _last_search_id
    _last_results = []
    _last_query = ""
    _last_search_id = None
    return {"cleared": True}



# ---------------------------------------------------------------------------
# Workspace endpoints — save/restore named result sets
# ---------------------------------------------------------------------------
WORKSPACE_SCHEMA = """
CREATE TABLE IF NOT EXISTS workspaces (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    query       TEXT NOT NULL,
    search_id   INTEGER,
    notes       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
"""

def _ensure_workspace_schema():
    with db._lock:
        db._c().executescript(WORKSPACE_SCHEMA)
        db._c().commit()


class WorkspaceSaveIn(BaseModel):
    name: str
    notes: str = ""


@app.post("/api/workspace/save")
def workspace_save(body: WorkspaceSaveIn) -> dict:
    """Save current results + query as a named workspace."""
    _ensure_workspace_schema()
    if not _last_query:
        raise HTTPException(400, "No active query to save. Run a search first.")
    sid = _last_search_id
    # If no search_id tracked, record it now
    if not sid and _last_results:
        serialized = [serialize_result(r) if not isinstance(r, dict) or 'ip_str' not in r else r
                      for r in _last_results]
        sid = db.search_record(_last_query, _current_scope.name, serialized, False)
    with db._lock:
        cur = db._c().execute(
            "INSERT INTO workspaces(name,query,search_id,notes,created_at) VALUES(?,?,?,?,?)",
            (body.name.strip(), _last_query, sid, body.notes.strip(),
             datetime.now(timezone.utc).isoformat())
        )
        db._c().commit()
        wid = cur.lastrowid
    audit("workspace_saved", {"id": wid, "name": body.name, "query": _last_query})
    return {"workspace_id": wid, "name": body.name}


@app.get("/api/workspace")
def workspace_list() -> dict:
    _ensure_workspace_schema()
    with db._lock:
        rows = db._c().execute(
            "SELECT id,name,query,search_id,notes,created_at FROM workspaces ORDER BY created_at DESC"
        ).fetchall()
    return {"workspaces": [{"id":r[0],"name":r[1],"query":r[2],"search_id":r[3],"notes":r[4],"created_at":r[5]} for r in rows]}


@app.get("/api/workspace/{wid}")
def workspace_load(wid: int) -> dict:
    """Load a workspace — restores results into memory so triage works."""
    global _last_results, _last_query, _last_search_id
    _ensure_workspace_schema()
    with db._lock:
        row = db._c().execute(
            "SELECT id,name,query,search_id,notes,created_at FROM workspaces WHERE id=?", (wid,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Workspace not found")
    ws = {"id":row[0],"name":row[1],"query":row[2],"search_id":row[3],"notes":row[4],"created_at":row[5]}
    # Restore results from search history
    if row[3]:
        record = db.search_load(row[3])
        if record:
            _last_results = record.get("results", [])
            _last_query = record.get("query", row[2])
            _last_search_id = row[3]
    return {**ws, "result_count": len(_last_results)}


@app.delete("/api/workspace/{wid}")
def workspace_delete(wid: int) -> dict:
    _ensure_workspace_schema()
    with db._lock:
        db._c().execute("DELETE FROM workspaces WHERE id=?", (wid,))
        db._c().commit()
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Threat Feed endpoints
# ---------------------------------------------------------------------------
class FeedRefreshIn(BaseModel):
    otx_api_key: Optional[str] = None


@app.post("/api/feeds/refresh")
async def feeds_refresh(body: FeedRefreshIn = FeedRefreshIn()) -> dict:
    """Crawl C2-Tracker, BushidoUK, C2Hunter, OTX, STIX/TAXII and store validated queries."""
    try:
        otx_key = body.otx_api_key or db.get_config("otx_api_key") or None
        result = await threat_feeds.refresh_feeds(otx_api_key=otx_key)
        audit("feeds_refresh", {"total": result["total"], "sources": result["sources"]})
        return result
    except Exception as e:
        raise HTTPException(500, f"Feed refresh failed: {e}")


@app.get("/api/feeds/queries")
def feeds_queries(
    category: str = "",
    source: str = "",
    search: str = "",
    limit: int = 500,
) -> dict:
    try:
        threat_feeds._ensure_feed_schema()
        queries = threat_feeds.get_feed_queries(category=category, source=source, search=search, limit=limit)
        return {"queries": queries}
    except Exception as e:
        raise HTTPException(500, f"Feed query failed: {e}")


@app.get("/api/feeds/stats")
def feeds_stats() -> dict:
    try:
        threat_feeds._ensure_feed_schema()
        return threat_feeds.get_feed_stats()
    except Exception as e:
        raise HTTPException(500, f"Feed stats failed: {e}")


@app.get("/api/feeds/categories")
def feeds_categories() -> dict:
    try:
        threat_feeds._ensure_feed_schema()
        return {"categories": threat_feeds.get_feed_categories()}
    except Exception as e:
        raise HTTPException(500, f"Feed categories failed: {e}")


@app.post("/api/feeds/mark-run/{query_id}")
def feeds_mark_run(query_id: int) -> dict:
    try:
        threat_feeds.mark_query_run(query_id)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(500, str(e))



@app.post("/api/config/otx-key")
def set_otx_key(body: dict = Body(...)) -> dict:
    key = (body.get("key") or "").strip()
    if key:
        db.set_config("otx_api_key", key)
    return {"saved": bool(key)}


@app.get("/api/config/autonomy")
def get_autonomy() -> dict:
    """Get the current MCP autonomy mode (hitl|scoped|full)."""
    mode = db.get_config("mcp_autonomy_mode") or "hitl"
    return {"mode": mode}


@app.post("/api/config/autonomy")
def set_autonomy(body: dict = Body(...)) -> dict:
    """Set the MCP autonomy mode. UI sends: hitl|scoped|full."""
    mode = (body.get("mode") or "hitl").lower().strip()
    if mode not in ("hitl", "confirm", "scoped", "full"):
        mode = "hitl"
    # Normalize confirm -> hitl
    if mode == "confirm":
        mode = "hitl"
    db.set_config("mcp_autonomy_mode", mode)
    audit("autonomy_mode_changed", {"mode": mode})
    return {"mode": mode, "saved": True}


@app.get("/api/guidance")
def get_guidance() -> dict:
    """Get the persistent analyst guidance text."""
    guidance = db.get_config("analyst_guidance") or ""
    return {"guidance": guidance}


@app.post("/api/guidance")
def save_guidance(body: dict = Body(...)) -> dict:
    """Save the persistent analyst guidance text."""
    text = (body.get("guidance") or "").strip()
    db.set_config("analyst_guidance", text)
    return {"saved": True, "guidance": text}


@app.delete("/api/guidance")
def clear_guidance() -> dict:
    """Clear the analyst guidance."""
    db.delete_config("analyst_guidance")
    return {"cleared": True}


# ---------------------------------------------------------------------------
# Cluster endpoints (AI-assisted campaign identification)
# ---------------------------------------------------------------------------
class ClusterIn(BaseModel):
    name: str
    description: str = ""
    actor: str = ""
    mitre_ttps: list[str] = []
    ioc_summary: str = ""
    query_ids: list[int] = []


@app.get("/api/feeds/clusters")
def list_clusters() -> dict:
    try:
        threat_feeds._ensure_feed_schema()
        return {"clusters": threat_feeds.get_clusters()}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/feeds/clusters")
def create_cluster(body: ClusterIn) -> dict:
    try:
        cluster_id = threat_feeds.save_cluster(
            body.name, body.description, body.actor,
            body.mitre_ttps, body.ioc_summary, body.query_ids
        )
        audit("cluster_created", {"id": cluster_id, "name": body.name})
        return {"cluster_id": cluster_id}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/api/feeds/clusters/{cluster_id}/queries")
def cluster_queries(cluster_id: int) -> dict:
    try:
        return {"queries": threat_feeds.get_cluster_queries(cluster_id)}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.delete("/api/feeds/clusters/{cluster_id}")
def delete_cluster(cluster_id: int) -> dict:
    try:
        threat_feeds.delete_cluster(cluster_id)
        return {"deleted": True}
    except Exception as e:
        raise HTTPException(500, str(e))


class AiClusterIn(BaseModel):
    query_ids: list[int]
    provider: Optional[str] = None


@app.post("/api/feeds/ai-cluster")
async def ai_cluster(body: AiClusterIn) -> dict:
    """
    AI-assisted campaign clustering.
    Given a list of feed query IDs, asks the LLM to identify clusters,
    name them, attribute actors, map MITRE TTPs, and suggest Shodan pivot queries.
    """
    try:
        threat_feeds._ensure_feed_schema()
        # Load the queries
        all_q = threat_feeds.get_feed_queries(limit=2000)
        selected = [q for q in all_q if q["id"] in set(body.query_ids)]
        if not selected:
            raise HTTPException(400, "No queries found for given IDs")

        import llm
        result = await llm.cluster_analysis(selected, body.provider)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"AI cluster analysis failed: {e}")


@app.post("/api/crew/run")
def crew_run(body: dict = Body(...)) -> dict:
    """Launch the crew as a background process from the server's own directory.

    No second terminal needed. Output streams to crew_run.log next to server.py.
    Override the launcher with the CREW_CMD env var, e.g.
        CREW_CMD="python agents/example_crew.py"
    """
    import subprocess, shlex
    scope = (body.get("scope") or "").strip()
    mode  = (body.get("mode") or "hitl").strip()

    # Resolve the launcher: explicit CREW_CMD wins; otherwise first script that exists.
    cmd_env = os.environ.get("CREW_CMD", "").strip()
    if cmd_env:
        args = shlex.split(cmd_env, posix=(os.name != "nt"))
    else:
        candidates = ["launchers/poc_crew.py", "poc_crew.py",
                      "agents/example_crew.py", "example_crew.py"]
        script = next((c for c in candidates if os.path.exists(os.path.join(_HERE, c))), None)
        if not script:
            return {"status": "error",
                    "detail": "No crew launcher found.",
                    "hint": "Set CREW_CMD, e.g. CREW_CMD=\"python agents/example_crew.py\"",
                    "looked_for": candidates}
        args = [sys.executable, script]

    log_path = os.path.join(_HERE, "crew_run.log")
    s = settings.get_settings()
    child_env = {**os.environ,
                 "SHODANSNIPE_URL": "http://127.0.0.1:8000",
                 "TARGET_SCOPE": scope, "CREW_MODE": mode,
                 # pick-your-crew + limits, so the launcher needs no code edits:
                 "CREW_STAGES": ",".join(settings.selected_stage_keys()),
                 "CREW_MODULES": ",".join(settings.selected_module_keys()),
                 "SHODAN_MAX_RESULTS": str(s["max_results_per_query"]),
                 "CREW_MAX_QUERIES": str(s["max_queries_per_run"]),
                 "CREW_CREDIT_BUDGET": str(s["credit_budget"]),
                 "NMAP_MAX_HOSTS": str(s["nmap_max_hosts_per_call"]),
                 "REPORT_MAX_TOKENS": str(s["report_max_tokens"]),
                 "REPORT_SECTION_CHARS": str(s["report_section_chars"]),
                 "GLOBAL_LIMIT_MULTIPLIER": str(s.get("result_depth_multiplier", 1.0)),
                 "GLOBAL_NO_LIMITS": "1" if s.get("no_limits") else "0",
                 "MCP_AUTONOMY_MODE": mode or s["autonomy_mode"]}
    db.set_config("crew_last_trigger", json.dumps({
        "scope": scope, "mode": mode,
        "triggered_at": datetime.now(timezone.utc).isoformat()}))
    try:
        logf = open(log_path, "ab", buffering=0)
        logf.write(f"\n=== crew run @ {datetime.now(timezone.utc).isoformat()} "
                   f"scope={scope!r} mode={mode!r} cmd={args} ===\n".encode())
        proc = subprocess.Popen(args, cwd=_HERE, env=child_env,
                                stdout=logf, stderr=subprocess.STDOUT)
    except Exception as e:
        logger.error("crew launch failed: %s", e)
        return {"status": "error", "detail": str(e),
                "hint": "Set CREW_CMD to your launcher command."}

    audit("crew_run_started", {"scope": scope, "mode": mode, "pid": proc.pid})

    # ── Capture this run (with its estimated cost) into the persisted run log. ──
    try:
        model = (llm.get_settings() or {}).get("model")
    except Exception:
        model = None
    cost = settings.estimate_run_cost(model=model, cfg=s)
    run_record = _record_run({
        "id": uuid4().hex[:12],
        "started_at": datetime.now(timezone.utc).isoformat(),
        "scope": scope or "(none)",
        "mode": mode,
        "pid": proc.pid,
        "profile": s.get("profile", "custom"),
        "stages": settings.selected_stage_keys(),
        "module_count": len(settings.selected_module_keys()),
        "cost": cost,
    })

    return {"status": "started", "pid": proc.pid, "scope": scope, "mode": mode,
            "log": log_path, "run_id": run_record["id"], "cost": cost,
            "note": f"Crew launched (pid {proc.pid}). Output → crew_run.log"}


# ── Run cost: estimate (preview) + captured run history ───────────────────────
@app.get("/api/cost/estimate")
def cost_estimate() -> dict:
    """Estimated cost of one crew run with the *current* settings + active LLM
    model. The Control Center polls this so the figure shown before a run is the
    same one captured into the run log when the crew actually launches."""
    try:
        model = (llm.get_settings() or {}).get("model")
    except Exception:
        model = None
    est = settings.estimate_run_cost(model=model)
    return {"estimate": est, "model": model or "unknown"}


@app.get("/api/runs")
def runs_list(limit: int = 50) -> dict:
    """Captured crew runs, newest first, each with its estimated cost."""
    runs = _load_runs()
    return {"runs": runs[: max(1, limit)], "total": len(runs)}


@app.post("/api/runs")
def runs_record(body: dict = Body(...)) -> dict:
    """Record a crew run launched OUTSIDE the server (e.g. the CLI launcher / crewai.bat) so
    terminal runs appear in the SAME history as Control-Center-launched ones. The launcher
    posts what it knows (scope, target, mode, stages, report path, status); the server stamps
    an id/timestamp if missing."""
    rec = dict(body or {})
    rec.setdefault("id", uuid4().hex[:12])
    rec.setdefault("started_at", datetime.now(timezone.utc).isoformat())
    rec.setdefault("source", "cli")
    audit("crew_run_recorded", {"scope": rec.get("scope"), "source": rec.get("source")})
    return {"recorded": _record_run(rec)}


@app.delete("/api/runs")
def runs_clear() -> dict:
    """Clear the captured run history."""
    _save_runs([])
    audit("runs_cleared", {})
    return {"cleared": True}


# ── Findings: store / list / export (dynamic columns) ─────────────────────────
@app.post("/api/findings")
def findings_record(body: dict = Body(...)) -> dict:
    """Record one finding (dict) or a batch ({"findings":[...]}). Any keys are accepted —
    each becomes a column. The server stamps id/recorded_at if missing."""
    incoming = body.get("findings") if isinstance(body, dict) and "findings" in body else [body]
    if not isinstance(incoming, list):
        incoming = [incoming]
    items = _load_findings()
    added = 0
    for f in incoming:
        if not isinstance(f, dict) or not f:
            continue
        rec = dict(f)
        rec.setdefault("id", uuid4().hex[:12])
        rec.setdefault("recorded_at", datetime.now(timezone.utc).isoformat())
        items.insert(0, rec)
        added += 1
    _save_findings(items)
    audit("findings_recorded", {"added": added, "run_id": (incoming[0] or {}).get("run_id") if incoming else None})
    return {"added": added, "total": len(items)}


@app.get("/api/findings")
def findings_list(limit: int = 500, run_id: str = "") -> dict:
    """Findings newest-first, plus the full column set (so the GUI can render every column,
    including ones you've added)."""
    items = _load_findings()
    if run_id:
        items = [f for f in items if f.get("run_id") == run_id]
    items = items[: max(1, limit)]
    return {"findings": items, "columns": _finding_columns(items), "total": len(items)}


@app.delete("/api/findings")
def findings_clear(run_id: str = "") -> dict:
    """Clear all findings, or only those from one run_id."""
    if run_id:
        kept = [f for f in _load_findings() if f.get("run_id") != run_id]
        _save_findings(kept)
        return {"cleared": True, "run_id": run_id, "remaining": len(kept)}
    _save_findings([])
    audit("findings_cleared", {})
    return {"cleared": True}


@app.get("/api/findings/export")
def findings_export(fmt: str = "csv", run_id: str = "") -> Response:
    """Export findings any time, as CSV (default) or JSON. Columns are dynamic — every key any
    finding has becomes a column, so user-added fields export automatically."""
    items = _load_findings()
    if run_id:
        items = [f for f in items if f.get("run_id") == run_id]
    ts = int(datetime.now().timestamp())
    if fmt.lower() == "json":
        body = json.dumps({"findings": items, "columns": _finding_columns(items)}, indent=2)
        return Response(content=body.encode("utf-8"), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="findings_{ts}.json"'})
    import csv, io
    cols = _finding_columns(items)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, quoting=csv.QUOTE_ALL, extrasaction="ignore")
    w.writeheader()
    for f in items:
        w.writerow({c: (", ".join(map(str, f[c])) if isinstance(f.get(c), list) else f.get(c, ""))
                    for c in cols})
    audit("findings_export", {"rows": len(items), "fmt": fmt})
    return Response(content=buf.getvalue().encode("utf-8-sig"), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="findings_{ts}.csv"'})


# ── Settings & "pick your crew" — read/write from the UI, no code edits ───────
@app.get("/api/settings")
def settings_get() -> dict:
    """All runtime tunables (limits, report, autonomy, enabled stages)."""
    return settings.get_settings()


@app.post("/api/settings")
def settings_set(body: dict = Body(...)) -> dict:
    """Patch any subset of settings, e.g. {"max_results_per_query": 200}."""
    updated = settings.update_settings(body or {})
    audit("settings_updated", {"keys": list((body or {}).keys())})
    return updated


@app.get("/api/crew/stages")
def crew_stages_get() -> dict:
    """The pipeline stage registry + which are currently enabled (UI checkboxes)."""
    return {"stages": settings.get_stages(),
            "selected": settings.selected_stage_keys()}


@app.post("/api/crew/stages")
def crew_stages_set(body: dict = Body(...)) -> dict:
    """Set enabled stages. Accepts {"stages": ["recon","vuln","report"]} or
    {"stages": {"nmap": false}}. Required upstream stages are auto-enabled."""
    sel = body.get("stages", body)
    settings.set_stages(sel)
    audit("crew_stages_set", {"selected": settings.selected_stage_keys()})
    return {"stages": settings.get_stages(),
            "selected": settings.selected_stage_keys()}


@app.get("/api/crew/modules")
def crew_modules_get() -> dict:
    """Capability modules (JS crawl, wayback, …) + which are enabled (UI toggles)."""
    return {"modules": settings.get_modules(),
            "selected": settings.selected_module_keys()}


@app.post("/api/crew/modules")
def crew_modules_set(body: dict = Body(...)) -> dict:
    """Set enabled modules. Accepts {"modules": ["dns_posture","wayback"]} or {key:bool}."""
    settings.set_modules(body.get("modules", body))
    audit("crew_modules_set", {"selected": settings.selected_module_keys()})
    return {"modules": settings.get_modules(),
            "selected": settings.selected_module_keys()}


@app.post("/api/settings/reset")
def settings_reset() -> dict:
    """Clear all saved settings back to defaults."""
    out = settings.reset_settings()
    audit("settings_reset", {})
    return out


# ── Reports — render, list, and serve the generated HTML report ───────────────
_REPORTS_DIR = os.path.join(_HERE, "reports")


class ReportSaveIn(BaseModel):
    markdown: str = ""
    html: str = ""
    title: str = "ShodanSnipe Threat Report"
    target_org: str = "Target"


@app.post("/api/report/save")
def report_save(body: ReportSaveIn) -> dict:
    """Render the crew's report (markdown) to HTML and save it. The report stage / crew
    posts its final output here so it shows up in the GUI Report panel."""
    os.makedirs(_REPORTS_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = os.path.join(_REPORTS_DIR, f"report-{ts}.html")
    try:
        if body.html:
            with open(path, "w", encoding="utf-8") as f:
                f.write(body.html)
        else:
            from report_render import save_html_report
            save_html_report(body.markdown or "(empty report)", path,
                             target_org=body.target_org)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    audit("report_saved", {"path": path})
    return {"status": "saved", "file": os.path.basename(path)}


@app.get("/api/reports")
def reports_list() -> dict:
    """List saved reports, newest first."""
    if not os.path.isdir(_REPORTS_DIR):
        return {"reports": []}
    files = sorted((f for f in os.listdir(_REPORTS_DIR) if f.endswith(".html")), reverse=True)
    return {"reports": files}


@app.get("/api/report/latest")
def report_latest():
    """Serve the most recent report as HTML (for the GUI Report panel iframe)."""
    if os.path.isdir(_REPORTS_DIR):
        files = sorted((f for f in os.listdir(_REPORTS_DIR) if f.endswith(".html")), reverse=True)
        if files:
            return FileResponse(os.path.join(_REPORTS_DIR, files[0]), media_type="text/html")
    return HTMLResponse(
        "<body style='font-family:monospace;background:#0a0e17;color:#7d8aa0;padding:40px'>"
        "<h3 style='color:#39d0d8'>No report yet</h3>"
        "<p>Run the crew with the Report stage enabled. The report appears here once the "
        "crew posts it to <code>/api/report/save</code>.</p></body>")


@app.get("/api/report/{name}")
def report_by_name(name: str, download: bool = False):
    """Serve a specific saved report by filename. Pass ?download=1 to force a
    file download (Content-Disposition: attachment) instead of inline display."""
    safe = os.path.basename(name)
    path = os.path.join(_REPORTS_DIR, safe)
    if safe.endswith(".html") and os.path.exists(path):
        if download:
            return FileResponse(path, media_type="text/html", filename=safe)
        return FileResponse(path, media_type="text/html")
    return JSONResponse(status_code=404, content={"error": "not found"})


def _render_report_pdf(path: str) -> tuple[bytes | None, str | None]:
    """Render a saved HTML report to PDF bytes. Tries WeasyPrint first (best CSS
    fidelity), then pdfkit/wkhtmltopdf. Returns (None, None) if neither engine is
    installed so the caller can respond with install guidance instead of a 500."""
    try:
        from weasyprint import HTML  # type: ignore
        return HTML(filename=path).write_pdf(), "weasyprint"
    except Exception as e:
        logger.info("weasyprint unavailable for PDF render: %s", e)
    try:
        import pdfkit  # type: ignore
        return pdfkit.from_file(path, False), "pdfkit"
    except Exception as e:
        logger.info("pdfkit/wkhtmltopdf unavailable for PDF render: %s", e)
    return None, None


@app.get("/api/report/{name}/pdf")
def report_pdf(name: str):
    """Render a saved report to PDF and return it as a download. Requires an
    HTML→PDF engine on the server (WeasyPrint or wkhtmltopdf+pdfkit)."""
    safe = os.path.basename(name)
    if not safe.endswith(".html"):
        return JSONResponse(status_code=400, content={"error": "not an html report"})
    path = os.path.join(_REPORTS_DIR, safe)
    if not os.path.exists(path):
        return JSONResponse(status_code=404, content={"error": "not found"})
    pdf_bytes, engine = _render_report_pdf(path)
    if pdf_bytes is None:
        return JSONResponse(status_code=501, content={
            "error": "pdf_engine_unavailable",
            "detail": "No HTML→PDF engine is installed on the server.",
            "fix": "Install one in the server's interpreter:  pip install weasyprint   "
                   "(or)  pip install pdfkit  plus the wkhtmltopdf binary. "
                   "The HTML export and the ⤢ open-in-new-tab (print → PDF) work without it.",
        })
    out_name = safe[:-5] + ".pdf"  # report-….html → report-….pdf
    audit("report_pdf", {"file": safe, "engine": engine})
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{out_name}"'})


@app.get("/api/crew/profiles")
def crew_profiles_get() -> dict:
    """Scan profiles (quick / comprehensive / all) + the active one — UI presets."""
    return settings.get_profiles()


@app.post("/api/crew/profile")
def crew_profile_apply(body: dict = Body(...)) -> dict:
    """Apply a profile by name: sets stages, modules and limits together."""
    name = (body or {}).get("name", "")
    settings.apply_profile(name)
    audit("crew_profile_applied", {"profile": name})
    return {"applied": name, "settings": settings.get_settings(),
            "stages": settings.get_stages(), "modules": settings.get_modules()}


@app.get("/api/mcp/tools")
async def mcp_tools_list() -> dict:
    """List the MCP tools so the UI can show them (no MCP handshake needed)."""
    if not _MCP_ENABLED:
        return {"enabled": False, "endpoint": None, "tools": [],
                "note": "MCP disabled — install fastmcp in the server's interpreter."}
    try:
        from mcp_tools import list_manifest
        return {"enabled": True, "endpoint": "/mcp", "transport": "streamable-http",
                "tools": await list_manifest()}
    except Exception as e:
        return {"enabled": True, "endpoint": "/mcp", "tools": [], "error": str(e)}


@app.post("/api/llm/ask")
async def llm_ask(body: dict = Body(...)) -> dict:
    """Answer a direct analyst question using the configured LLM."""
    question = (body.get("question") or "").strip()
    query    = (body.get("query") or "").strip()
    guidance = (body.get("analyst_guidance") or "").strip()
    if not question:
        return {"answer": "No question provided."}
    settings = llm.get_settings()
    provider = settings.get("provider", "ollama")
    prompt = question
    if query:
        prompt += f"\n\nActive Shodan query: {query}"
    if guidance:
        prompt += f"\n\nAnalyst guidance: {guidance}"
    try:
        # Use summarize with a short prompt as a general-purpose ask
        result = await llm.summarize(prompt, [], provider, persona="asm")
        answer = result.get("summary", str(result)) if isinstance(result, dict) else str(result)
        return {"answer": answer}
    except Exception as e:
        logger.error("llm/ask error: %s", e)
        return {"answer": f"AI error: {e}"}


@app.post("/api/llm/cve-intel")
async def llm_cve_intel(body: dict = Body(...)) -> dict:
    """Extract CVEs from advisory text and generate scoped Shodan detection queries."""
    import re as _re
    text       = (body.get("text") or body.get("advisory") or "").strip()
    scope_data = body.get("scope") or {}
    scope_q    = scope_data.get("query", "") if isinstance(scope_data, dict) else ""
    if not text:
        return {"cve_ids": [], "queries": [], "error": "No text provided"}

    # 1) Extract CVE IDs FIRST — pure regex on the INPUT, no LLM involved. This must always
    #    succeed even if the AI step later fails, so a valid ID is never silently dropped.
    #    Any 4-digit year (incl. 2026+), 4+ digit sequence, case-insensitive.
    cve_ids = sorted({m.upper() for m in _re.findall(r'CVE-\d{4}-\d{4,}', text, _re.IGNORECASE)})

    # 2) Generate detection queries via the LLM — best-effort, and isolated so a provider/key
    #    failure NEVER zeroes out the CVEs extracted above.
    settings = llm.get_settings()
    provider = settings.get("provider", "ollama")

    def _flatten_queries(result) -> list:
        """Normalize whatever the LLM layer returns into a list of query dicts.
        Handles: a bare list; {"queries": [...]} (dedicated cve_intel shape); and
        goal_to_query's {"query","rationale","alternatives"} shape — the last of which the
        old parser silently dropped (it only read "queries"), which is why diversity vanished."""
        if isinstance(result, list):
            return result
        if not isinstance(result, dict):
            return []
        if result.get("queries"):
            return result["queries"]
        out = []
        if result.get("query"):
            out.append({"query": result["query"], "rationale": result.get("rationale", "")})
        for alt in result.get("alternatives", []) or []:
            if isinstance(alt, dict) and alt.get("query"):
                out.append(alt)
            elif isinstance(alt, str) and alt.strip():
                out.append({"query": alt.strip(), "rationale": ""})
        return out

    try:
        # PREFERRED: the dedicated diverse generator (rich, multi-angle, returns {cve_ids,queries}).
        # This is the path that produced the diverse query sets; use it when llm.py still exposes it.
        if hasattr(llm, "cve_intel"):
            res = llm.cve_intel(text[:3000], scope_query=scope_q)
            if __import__("inspect").isawaitable(res):
                res = await res
            if isinstance(res, dict):
                qs = _flatten_queries(res)
                return {"cve_ids": res.get("cve_ids") or cve_ids, "queries": qs}
            return {"cve_ids": cve_ids, "queries": _flatten_queries(res)}

        # FALLBACK: drive goal_to_query with a diversity-forcing prompt, then flatten its
        # query+alternatives shape correctly (the bug was reading a non-existent "queries" key).
        cve_prompt = (
            "You are generating Shodan DETECTION queries from a vulnerability advisory. First "
            "identify the affected product(s), framework(s), version(s), default/dev port(s), and "
            "the vulnerability class. If the advisory is SPARSE (just an ID or one line), REASON "
            "from the product name and vuln class using how that product actually appears on "
            "Shodan — do NOT return nothing just because NVD hasn't ingested the CVE yet.\n\n"
            "Produce a DIVERSE set of 5-8 COMPLEMENTARY queries — each catching the exposure from a "
            "DIFFERENT angle, never repeating the same filter. Put the strongest as the primary "
            "query and the rest in 'alternatives'. Cover as many of these surfaces as apply:\n"
            "  - product:\"...\"  (and version: when known)\n"
            "  - http.component:\"...\"  (framework / CMS fingerprint)\n"
            "  - banner/header angle: http.headers:\"x-powered-by: ...\" or server:\"...\"\n"
            "  - http.title:\"...\"  (login / admin / panel titles)\n"
            "  - http.html:\"...\"  (unique body markers, JS vars, error strings)\n"
            "  - port:NNNN  (default AND common dev/container ports, e.g. 3000/8080/9000)\n"
            "  - a PLAINTEXT-over-HTTP variant (port 80) mirroring any HTTPS query\n"
            "  - http.favicon.hash / ssl.cert.subject.cn pivots where the product has a known one\n"
            "  - vuln:CVE-XXXX (paid) AND a has_vuln:true fallback for free tier\n"
            "Each query MUST be valid Shodan syntax with a concise rationale."
            f"{' Scope EVERY query to: ' + scope_q if scope_q else ''}\n\n"
            f"Advisory:\n{text[:3000]}"
        )
        result = await llm.goal_to_query(cve_prompt, provider, tier=_current_tier)
        return {"cve_ids": cve_ids, "queries": _flatten_queries(result)}
    except Exception as e:
        logger.error("llm/cve-intel query-gen error: %s", e)
        # Still return the CVE(s) we found; make clear it's the AI query step that failed,
        # not CVE parsing — and point at the likely cause (LLM provider/key not configured).
        return {
            "cve_ids": cve_ids,
            "queries": [],
            "error": (f"Extracted {len(cve_ids)} CVE(s); detection-query generation failed "
                      f"({provider} LLM): {e}. Set a working LLM provider/key in Config."),
        }


@app.post("/api/llm/selection")
async def llm_selection(body: dict = Body(...)) -> dict:
    """Generate Shodan queries from selected filters/templates and a user instruction."""
    instruction        = (body.get("instruction") or "").strip()
    selected_filters   = body.get("selected_filters") or []
    selected_templates = body.get("selected_templates") or []
    guidance           = (body.get("analyst_guidance") or "").strip()
    num_queries        = int(body.get("num_queries") or 6)
    settings = llm.get_settings()
    provider = settings.get("provider", "ollama")
    scope_q  = ""
    try:
        sc = db.get_scope()
        scope_q = (sc or {}).get("query", "")
    except Exception:
        pass
    parts = [f"Generate {num_queries} Shodan queries."]
    if instruction:   parts.append(f"Instruction: {instruction}")
    if selected_filters: parts.append(f"Filters: {', '.join(str(f) for f in selected_filters)}")
    if selected_templates: parts.append(f"Templates: {', '.join(str(t) for t in selected_templates)}")
    if guidance:      parts.append(f"Analyst guidance: {guidance}")
    if scope_q:       parts.append(f"Scope: {scope_q}")
    prompt = " ".join(parts)
    try:
        result = await llm.goal_to_query(prompt, provider, tier=_current_tier)
        queries = result if isinstance(result, list) else result.get("queries", []) if isinstance(result, dict) else []
        return {"queries": queries, "rationale": "Generated from selection"}
    except Exception as e:
        logger.error("llm/selection error: %s", e)
        return {"queries": [], "error": str(e)}

# ---------------------------------------------------------------------------
# Entry point — kept at the END so every @app route above is registered before
# uvicorn starts (this block previously sat mid-file, stranding the routes below
# it whenever the server was started with `python server.py`).
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)