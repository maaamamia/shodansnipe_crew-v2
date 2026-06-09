"""
mcp_tools.py — MCP endpoint mounted INSIDE server.py (one process, no extra script).

This restores the /mcp endpoint that the UI rewrite dropped. It is a *module*
imported by server.py — you still run only `python server.py`. There is no
separate mcp_server.py process.

The six tools proxy the same /api/* routes the REST server already exposes, so
scope enforcement, the audit DB, and false-positive filtering all stay in
server.py. The MCP layer adds no capability — it re-exposes the existing tools.

server.py wiring (three small edits, shown in the comment block below).
"""
from __future__ import annotations
import os, json
import requests
from fastmcp import FastMCP

# Self-target: the same process's REST port (server.py runs on 8000).
REST = os.environ.get("SHODANSNIPE_SELF_URL", "http://127.0.0.1:8000").rstrip("/")

mcp = FastMCP("ShodanSnipe")


def _post(path: str, payload: dict, timeout: int = 60) -> str:
    try:
        r = requests.post(f"{REST}{path}", json=payload, timeout=timeout)
        try:
            return json.dumps(r.json(), indent=2)
        except ValueError:
            return f"{path} -> HTTP {r.status_code}: {r.text[:500]}"
    except Exception as e:
        return f"Error calling {path}: {e}"


def _get(path: str, timeout: int = 30) -> str:
    try:
        r = requests.get(f"{REST}{path}", timeout=timeout)
        try:
            return json.dumps(r.json(), indent=2)
        except ValueError:
            return f"{path} -> HTTP {r.status_code}: {r.text[:500]}"
    except Exception as e:
        return f"Error calling {path}: {e}"


@mcp.tool
def shodan_search(query: str, limit: int = 25, enrich: bool = False) -> str:
    """Run a Shodan search through ShodanSnipe (scope enforced server-side).
    ONE logical query per call — no OR/AND/NOT. Quote comma/space values:
    org:"Company, Inc". Returns IP, ports, product, version, org, CVEs, risk, in_scope.
    Any limit is accepted and clamped to 500 — it never errors on a large value."""
    return _post("/api/search",
                 {"query": query, "limit": max(1, min(int(limit), 500)), "enrich": bool(enrich)})


@mcp.tool
def get_results() -> str:
    """Return results from the most recent Shodan search (loaded via history,
    since there is no standalone /api/results route)."""
    hist = _get("/api/history?limit=1")
    try:
        rows = json.loads(hist).get("history", [])
        if not rows:
            return json.dumps({"results": [], "note": "no searches recorded yet"})
        sid = rows[0].get("id")
        return _get(f"/api/history/{sid}")
    except Exception as e:
        return f"Error reading latest results: {e}"


@mcp.tool
def get_scope() -> str:
    """Return the active scope: name, cidrs, domains, asns, orgs."""
    return _get("/api/scope")


@mcp.tool
def set_scope(name: str = "default",
              cidrs: list[str] | None = None,
              domains: list[str] | None = None,
              asns: list[str] | None = None,
              orgs: list[str] | None = None) -> str:
    """Set the active scope BEFORE searching so results are gated to it.
    e.g. cidrs=["203.0.113.0/24"], asns=["AS64500"], orgs=["Company, Inc"]."""
    return _post("/api/scope", {
        "name": name,
        "cidrs":   cidrs   or [],
        "domains": domains or [],
        "asns":    asns    or [],
        "orgs":    orgs    or [],
    })


@mcp.tool
def get_history(limit: int = 50) -> str:
    """Return recent Shodan search history with queries and result counts."""
    return _get(f"/api/history?limit={int(limit)}")


@mcp.tool
def cve_intel(text: str) -> str:
    """Analyze a CVE ID or advisory text: severity, affected products, detection
    Shodan queries, remediation. Proxies /api/llm/cve-intel."""
    return _post("/api/llm/cve-intel", {"text": text}, timeout=45)


# The streamable-HTTP ASGI app. server.py mounts this at /mcp and shares its lifespan.
mcp_app = mcp.http_app(path="/")


async def list_manifest() -> list[dict]:
    """Tool name + description + params, for the UI's MCP viewer (no MCP handshake)."""
    out = []
    for t in await mcp.list_tools():
        schema = (getattr(t, "parameters", None) or getattr(t, "inputSchema", None)
                  or getattr(t, "input_schema", None) or {})
        props = schema.get("properties", {}) if isinstance(schema, dict) else {}
        required = set(schema.get("required", []) if isinstance(schema, dict) else [])
        params = []
        for k, v in props.items():
            v = v if isinstance(v, dict) else {}
            params.append({"name": k, "type": v.get("type", "string"),
                           "required": k in required,
                           "description": (v.get("description", "") or "").strip()})
        out.append({"name": t.name,
                    "description": (getattr(t, "description", "") or "").strip(),
                    "params": params})
    return out


# ─────────────────────────────────────────────────────────────────────────────
# server.py — apply these THREE edits (you run only `python server.py`):
#
# (1) Near the top, after the other imports, add:
#
#         from contextlib import asynccontextmanager
#         from mcp_tools import mcp_app
#
#         @asynccontextmanager
#         async def _lifespan(app):
#             async with mcp_app.lifespan(app):     # start the MCP session manager
#                 await _startup_restore_engine()   # keep the existing startup behaviour
#                 yield
#
#     (_startup_restore_engine is defined lower in the file; late binding makes
#      this reference resolve fine at startup time.)
#
# (2) Change the app creation line (currently line ~94):
#
#         app = FastAPI(title="ShodanSnipe", version="1.0.0")
#     to:
#         app = FastAPI(title="ShodanSnipe", version="1.0.0", lifespan=_lifespan)
#
# (3) Remove the decorator on the existing startup hook (currently line ~244) so
#     it doesn't conflict with the lifespan — keep the function, drop the line:
#
#         @app.on_event("startup")     # <-- delete this one line only
#         async def _startup_restore_engine():
#             ...
#
#     and, once after the routes are defined (anywhere near the bottom is fine), add:
#
#         app.mount("/mcp", mcp_app)
#
# Then: `python server.py` serves REST on :8000 AND MCP on :8000/mcp.
# Point the crew at  http://127.0.0.1:8000/mcp  (transport "streamable-http").
# Delete mcp_server.py — it's no longer needed.
# ─────────────────────────────────────────────────────────────────────────────
