"""
mcp_server.py — Standalone MCP front-end for ShodanSnipe.

Why this exists
---------------
Your crew got `POST /mcp -> 404` because server.py (FastAPI) never mounted an
MCP endpoint — it only serves /api/*. This process adds the missing /mcp.

Why STANDALONE (not mounted into server.py)
--------------------------------------------
Mounting a streamable-http MCP app into an existing FastAPI app silently breaks
unless the parent app also runs the MCP session-manager lifespan — Starlette does
not execute a sub-app's lifespan on mount, so the session manager never starts and
every request raises "Task group is not initialized." Your `app` is built with no
lifespan, so an in-place mount would turn the 404 into a 500. A separate process
runs its own lifespan correctly and needs ZERO changes to server.py.

Each tool is a THIN PROXY to the existing /api/* routes, so all scope enforcement,
the audit DB, and false-positive filtering stay in server.py. The MCP layer adds
no new capability — it just re-exposes the same tools over MCP.

Run (three windows / processes)
-------------------------------
    pip install fastmcp requests
    python server.py            # window 1 — ShodanSnipe REST  @ 127.0.0.1:8000
    python mcp_server.py        # window 2 — MCP (this file)    @ 127.0.0.1:8001/mcp
    python example_crew_mcp.py  # window 3 — the crew

Point the crew at:  http://127.0.0.1:8001/mcp   transport="streamable-http"

Env overrides: SHODANSNIPE_URL (REST target), MCP_HOST, MCP_PORT.
"""
from __future__ import annotations
import os, json
import requests
from fastmcp import FastMCP

REST     = os.environ.get("SHODANSNIPE_URL", "http://127.0.0.1:8000").rstrip("/")
MCP_HOST = os.environ.get("MCP_HOST", "127.0.0.1")
MCP_PORT = int(os.environ.get("MCP_PORT", "8001"))

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
    """Run a Shodan search through ShodanSnipe (scope is enforced server-side).
    ONE logical query per call — there is no OR/AND/NOT keyword; run alternatives
    as separate calls. Quote multi-word or comma values: org:"Company, Inc".
    Returns IP, ports, product, version, org, CVEs, risk, and the in_scope verdict."""
    return _post("/api/search",
                 {"query": query, "limit": max(1, min(int(limit), 500)), "enrich": bool(enrich)})


@mcp.tool
def get_results() -> str:
    """Return the current in-memory results from the most recent Shodan search."""
    return _get("/api/results")


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
    Provide any of: cidrs (e.g. ["203.0.113.0/24"]), domains, asns (["AS64500"]),
    orgs (["Company, Inc"])."""
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
    """Analyze a CVE ID or advisory text and return severity, affected products,
    Shodan detection queries, and remediation notes. Proxies /api/llm/explain-cve;
    if that route is absent on your build the tool reports the HTTP status so you
    can fall back to the recon/vuln agents' own NVD lookup."""
    return _post("/api/llm/explain-cve", {"text": text}, timeout=45)


if __name__ == "__main__":
    print(f"ShodanSnipe MCP  ->  proxying REST {REST}")
    print(f"                 ->  serving http://{MCP_HOST}:{MCP_PORT}/mcp  (transport: streamable-http)")
    # transport="http" is FastMCP 3's streamable-HTTP; default path is /mcp.
    mcp.run(transport="http", host=MCP_HOST, port=MCP_PORT)
