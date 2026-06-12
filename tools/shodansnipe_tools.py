"""
shodansnipe_tools.py — CrewAI BaseTool wrappers for ShodanSnipe REST API.

Drop-in tools for any CrewAI crew. Each tool wraps one or more ShodanSnipe
endpoints and returns structured text the LLM can reason about.

Set SHODANSNIPE_URL env var if not running on localhost:8000.
"""

import json
import os
from typing import Optional, Type

import requests
from pydantic import BaseModel, Field

try:
    from crewai.tools import BaseTool
except ImportError:
    try:
        from crewai_tools import BaseTool
    except ImportError:
        raise ImportError(
            "crewai not installed. Run: pip install crewai\n"
            "Or for older versions: pip install crewai-tools"
        )

# ---------------------------------------------------------------------------
# Client config
# ---------------------------------------------------------------------------
SHODANSNIPE_URL = os.getenv("SHODANSNIPE_URL", "http://127.0.0.1:8000").rstrip("/")
_TIMEOUT_SEARCH = 180   # searches take time
_TIMEOUT_FAST   = 30    # scope / history / etc.


def _check_server() -> bool:
    """Return True if ShodanSnipe is reachable."""
    try:
        r = requests.get(f"{SHODANSNIPE_URL}/api/health", timeout=5)
        return r.ok
    except Exception:
        return False


def _post(path: str, body: dict, timeout: int = _TIMEOUT_SEARCH) -> dict:
    try:
        r = requests.post(f"{SHODANSNIPE_URL}{path}", json=body, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except requests.ConnectionError:
        raise RuntimeError(
            f"Cannot reach ShodanSnipe at {SHODANSNIPE_URL}.\n"
            "Start the server:  python server.py\n"
            "Or set env var:    SHODANSNIPE_URL=http://host:port"
        )
    except requests.HTTPError as e:
        detail = ""
        try:
            detail = e.response.json().get("detail", "")
        except Exception:
            detail = e.response.text[:200]
        raise RuntimeError(f"ShodanSnipe API {e.response.status_code}: {detail}")


def _get(path: str, params: dict | None = None, timeout: int = _TIMEOUT_FAST) -> dict:
    try:
        r = requests.get(f"{SHODANSNIPE_URL}{path}", params=params, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except requests.ConnectionError:
        raise RuntimeError(f"Cannot reach ShodanSnipe at {SHODANSNIPE_URL}.")
    except requests.HTTPError as e:
        raise RuntimeError(f"ShodanSnipe API {e.response.status_code}: {e.response.text[:200]}")


def _mcp_call(tool_name: str, arguments: dict) -> str:
    """Call a tool via the MCP endpoint, return text result."""
    r = requests.post(
        f"{SHODANSNIPE_URL}/mcp",
        json={
            "jsonrpc": "2.0", "id": 99,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        },
        timeout=_TIMEOUT_SEARCH,
    )
    data = r.json()
    if "error" in data:
        raise RuntimeError(f"MCP error: {data['error']['message']}")
    content = data.get("result", {}).get("content", [])
    return content[0].get("text", "") if content else ""


def _fmt(results: list[dict], limit: int = 30) -> str:
    """Format result list as readable text for the LLM."""
    if not results:
        return "No results."
    lines = [f"Found {len(results)} host(s):"]
    for r in results[:limit]:
        ip       = r.get("ip_str", "?")
        org      = r.get("org", "unknown")
        ports    = ",".join(str(p) for p in (r.get("ports") or [])[:8])
        cves     = r.get("cves") or []
        risk     = r.get("risk_score", 0)
        product  = r.get("product", "")
        hostnames= (r.get("hostnames") or [])[:2]
        line = f"  {ip:16s}  org={org}  ports={ports or '?'}  risk={risk}"
        if product:   line += f"  product={product}"
        if cves:      line += f"  CVEs={','.join(cves[:4])}"
        if hostnames: line += f"  hostname={hostnames[0]}"
        lines.append(line)
    if len(results) > limit:
        lines.append(f"  ... and {len(results)-limit} more hosts")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool 1 — Shodan Search
# ---------------------------------------------------------------------------
class ShodanSearchInput(BaseModel):
    query:  str  = Field(description=(
        "Shodan query string. Valid syntax only:\n"
        "  Fields:    org:, port:, product:, http.title:, ssl.cert.subject.cn:,\n"
        "             hostname:, net:, asn:, country:, http.html:, http.favicon.hash:\n"
        "  Exclusion: -org:, -isp:, -country:, -port:  (NOT -asn: — unsupported)\n"
        "  NO OR/AND/NOT operators. Comma separates ports only: port:22,80,443\n"
        "  Quotes:    org:\"Acme Corp\"  product:\"Apache httpd\""
    ))
    limit:  int  = Field(default=25, ge=1, le=100, description="Max results (1-100)")
    enrich: bool = Field(default=False, description="Add InternetDB CVE/hostname data (slower)")


class ShodanSearchTool(BaseTool):
    name: str = "shodan_search"
    description: str = (
        "Run a Shodan query and return matching internet-exposed hosts. "
        "Returns IP, organisation, open ports, product fingerprints, CVEs, and risk score. "
        "IMPORTANT — Shodan syntax rules:\n"
        "• Space = AND. No OR, AND, NOT operators.\n"
        "• Exclusion: -country:CN  -org:\"Akamai\"  -isp:\"Cloudflare\"\n"
        "• Do NOT use -asn: (unsupported). Use -org: or -isp: instead.\n"
        "• Comma only works in port: filter: port:22,80,443\n"
        "• Quotes for multi-word values: org:\"Acme Corp\""
    )
    args_schema: Type[BaseModel] = ShodanSearchInput

    def _run(self, query: str, limit: int = 25, enrich: bool = False) -> str:
        try:
            d = _post("/api/search", {"query": query, "limit": limit, "enrich": enrich})
            results  = d.get("results", [])
            warning  = d.get("warning") or ""
            total    = d.get("total_returned", len(results))
            in_scope = d.get("in_scope", total)
            out = _fmt(results)
            summary = (
                f"\nSearch: {query!r}\n"
                f"Total returned: {total}  |  In-scope: {in_scope}  |  Limit: {limit}"
            )
            if warning:
                summary += f"\n⚠ {warning}"
            return out + summary
        except Exception as e:
            return f"shodan_search error: {e}"


# ---------------------------------------------------------------------------
# Tool 2 — Get Current Results
# ---------------------------------------------------------------------------
class GetResultsInput(BaseModel):
    limit: int = Field(default=50, ge=1, le=200)


class GetResultsTool(BaseTool):
    name: str = "get_current_results"
    description: str = (
        "Return the results already loaded in ShodanSnipe from the most recent search. "
        "Faster than re-running a search. Use this to analyse what has already been found."
    )
    args_schema: Type[BaseModel] = GetResultsInput

    def _run(self, limit: int = 50) -> str:
        try:
            raw = _mcp_call("get_results", {"limit": limit})
            parsed = json.loads(raw)
            results = parsed.get("results", [])
            total   = parsed.get("total", 0)
            returned= parsed.get("returned", len(results))
            out = _fmt(results, limit=limit)
            return f"Console results ({returned} of {total} total):\n{out}"
        except Exception as e:
            return f"get_current_results error: {e}"


# ---------------------------------------------------------------------------
# Tool 3 — Set Scope
# ---------------------------------------------------------------------------
class SetScopeInput(BaseModel):
    scope_text: str = Field(description=(
        "Target scope in plain text. Any combination of:\n"
        "  • Org name:  Acme Corp\n"
        "  • CIDR:      203.0.113.0/24\n"
        "  • ASN:       AS64512\n"
        "  • Domain:    acme.example\n"
        "Example: 'test, test.com, AS111'"
    ))


class SetScopeTool(BaseTool):
    name: str = "set_scope"
    description: str = (
        "Set the active scope — the organisation, CIDRs, ASNs, and domains "
        "that define the target environment. All subsequent Shodan searches "
        "are filtered to this scope. Accepts plain text; parsing is automatic."
    )
    args_schema: Type[BaseModel] = SetScopeInput

    def _run(self, scope_text: str) -> str:
        try:
            raw = _mcp_call("set_scope", {"text": scope_text})
            parsed = json.loads(raw)
            return f"Scope set: {parsed.get('scope', scope_text)}"
        except Exception as e:
            return f"set_scope error: {e}"


# ---------------------------------------------------------------------------
# Tool 4 — Get Scope
# ---------------------------------------------------------------------------
class GetScopeInput(BaseModel):
    pass


class GetScopeTool(BaseTool):
    name: str = "get_scope"
    description: str = (
        "Return the currently active scope definition. "
        "Shows org names, CIDRs, ASNs, and domains in target."
    )
    args_schema: Type[BaseModel] = GetScopeInput

    def _run(self, **kwargs) -> str:
        try:
            d = _get("/api/scope")
            if d.get("is_empty"):
                return "No scope set — searches are not restricted to any organisation."
            parts = []
            if d.get("name"):    parts.append(f"Name: {d['name']}")
            if d.get("orgs"):    parts.append(f"Orgs: {', '.join(d['orgs'])}")
            if d.get("cidrs"):   parts.append(f"CIDRs: {', '.join(d['cidrs'])}")
            if d.get("asns"):    parts.append(f"ASNs: {', '.join(d['asns'])}")
            if d.get("domains"): parts.append(f"Domains: {', '.join(d['domains'])}")
            return "Active scope — " + " | ".join(parts)
        except Exception as e:
            return f"get_scope error: {e}"


# ---------------------------------------------------------------------------
# Tool 5 — CVE Intel
# ---------------------------------------------------------------------------
class CVEIntelInput(BaseModel):
    advisory: str = Field(description=(
        "CVE advisory, NVD page text, vendor bulletin, or threat intel article. "
        "The tool extracts CVE IDs, affected products, severity, and generates "
        "Shodan queries to detect vulnerable hosts in the target environment."
    ))
    scope_queries: bool = Field(
        default=True,
        description="Scope detection queries to the active org/CIDRs (recommended)."
    )


class CVEIntelTool(BaseTool):
    name: str = "cve_intel"
    description: str = (
        "Analyse a CVE advisory or threat intel text. "
        "Returns: CVE IDs, severity (CVSS), affected products, executive summary, "
        "and ready-to-run Shodan detection queries. "
        "Use this when you have a CVE advisory and want to find exposed hosts."
    )
    args_schema: Type[BaseModel] = CVEIntelInput

    def _run(self, advisory: str, scope_queries: bool = True) -> str:
        try:
            d = _post("/api/llm/cve-intel", {
                "advisory": advisory,
                "scope_queries": scope_queries,
                "tier": "member",
            }, timeout=120)
            cves     = d.get("cve_ids") or []
            severity = d.get("severity", "Unknown")
            products = d.get("affected_products") or []
            summary  = d.get("summary", "")
            queries  = d.get("queries") or []
            tier_note= d.get("tier_note", "")

            lines = [
                "─── CVE INTEL RESULT ───",
                f"CVE(s):   {', '.join(cves) or 'not extracted'}",
                f"Severity: {severity}",
                f"Affected: {', '.join(products[:5]) or 'unknown'}",
                f"Summary:  {summary}",
                "",
                f"Detection queries ({sum(1 for q in queries if not q.get('query_invalid'))}):",  # noqa
            ]
            for q in queries:
                if q.get("query_invalid"):
                    continue
                lines.append(f"  [{q.get('detection_type','?'):18s}] {q['query']}")
                if q.get("rationale"):
                    lines.append(f"    → {q['rationale'][:120]}")
            if tier_note:
                lines.append(f"\n⚠ {tier_note}")
            return "\n".join(lines)
        except Exception as e:
            return f"cve_intel error: {e}"


# ---------------------------------------------------------------------------
# Tool 6 — Search History
# ---------------------------------------------------------------------------
class GetHistoryInput(BaseModel):
    limit: int = Field(default=10, ge=1, le=50)


class GetHistoryTool(BaseTool):
    name: str = "get_search_history"
    description: str = (
        "Return recent Shodan searches run in the console — queries, timestamps, result counts. "
        "Use this to understand what has already been investigated."
    )
    args_schema: Type[BaseModel] = GetHistoryInput

    def _run(self, limit: int = 10) -> str:
        try:
            d = _get("/api/history", params={"limit": limit})
            history = d.get("history", [])
            if not history:
                return "No search history."
            lines = [f"Recent searches ({len(history)}):"]
            for h in history:
                ts    = str(h.get("run_at", ""))[:16]
                query = h.get("query", "?")
                count = h.get("result_count", 0)
                scope = h.get("scope_name", "")
                line  = f"  [{ts}] {query}  →  {count} results"
                if scope and scope != "(none)":
                    line += f"  (scope: {scope})"
                lines.append(line)
            return "\n".join(lines)
        except Exception as e:
            return f"get_search_history error: {e}"


# ---------------------------------------------------------------------------
# Convenience bundle
# ---------------------------------------------------------------------------
def get_all_tools() -> list:
    return [
        ShodanSearchTool(),
        GetResultsTool(),
        SetScopeTool(),
        GetScopeTool(),
        CVEIntelTool(),
        GetHistoryTool(),
    ]
