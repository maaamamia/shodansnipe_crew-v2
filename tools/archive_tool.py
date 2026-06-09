"""
archive_tool.py — historical + host-detail enrichment for the Vuln agent.

Provides the two tools vuln_agent.py expects:
  * WaybackTool        — historical snapshots & sensitive paths from web.archive.org (keyless)
  * ShodanHostURITool  — per-IP host detail via Shodan InternetDB (keyless) with optional
                         full-banner upgrade when a Shodan key is present.

Both are discovery/enrichment only and fail soft: network errors, rate limits, or
"no data" return a clean empty result instead of raising (so a CloudFront edge IP with
no Shodan record just reports "no data", it does not error the run).
"""
from __future__ import annotations
import os, json, re
import requests
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

_UA = {"User-Agent": "ShodanSnipe-ASM/1.0 (+authorized assessment)"}
_TIMEOUT = 12

# Paths worth surfacing if they ever appeared in the archive.
_SENSITIVE = re.compile(
    r"(/\.env|/\.git|/\.svn|/\.aws|/backup|/dump|/\.sql|/config\.|/wp-config|"
    r"/admin|/phpinfo|/server-status|/actuator|/api/|/swagger|/\.well-known|"
    r"/credentials|/secret|/id_rsa|/\.htpasswd|/debug)", re.IGNORECASE)


# ─────────────────────────────────────────────────────────────────────────────
# WaybackTool
# ─────────────────────────────────────────────────────────────────────────────
class WaybackInput(BaseModel):
    target: str = Field(description="Domain or host to look up, e.g. 'acme.com' or 'app.acme.com'")
    limit: int = Field(50, description="Max snapshots to return")


class WaybackTool(BaseTool):
    name: str = "wayback_history"
    description: str = (
        "Query the Wayback Machine (web.archive.org) for historical snapshots of a host or "
        "domain. Flags archived paths that are sensitive (/.env, /.git, /admin, /actuator, "
        "swagger, backups). Read-only OSINT against public archives; no live requests to the "
        "target. Use on Critical/High hosts to find historically exposed endpoints."
    )
    args_schema: type = WaybackInput

    def _run(self, target: str, limit: int = 50) -> str:
        target = (target or "").strip().rstrip("/")
        target = re.sub(r"^https?://", "", target)
        out = {"target": target, "total_snapshots": 0, "sensitive": [], "sample": []}
        if not target:
            return json.dumps(out)
        try:
            url = ("http://web.archive.org/cdx/search/cdx"
                   f"?url={target}/*&output=json&collapse=urlkey"
                   f"&fl=original,timestamp,statuscode,mimetype&limit={max(1, min(limit, 500))}")
            r = requests.get(url, headers=_UA, timeout=_TIMEOUT)
            if not r.ok:
                out["note"] = f"archive returned HTTP {r.status_code}"
                return json.dumps(out, indent=2)
            rows = r.json()
            if rows and rows[0] and rows[0][0] == "original":
                rows = rows[1:]            # drop header row
            out["total_snapshots"] = len(rows)
            for row in rows:
                original = row[0] if len(row) > 0 else ""
                ts = row[1] if len(row) > 1 else ""
                status = row[2] if len(row) > 2 else ""
                snap = {"url": original, "timestamp": ts, "status": status,
                        "snapshot_url": f"https://web.archive.org/web/{ts}/{original}"}
                if _SENSITIVE.search(original):
                    out["sensitive"].append(snap)
                elif len(out["sample"]) < 15:
                    out["sample"].append(snap)
        except requests.RequestException as e:
            out["note"] = f"archive lookup failed: {e}"
        except (ValueError, IndexError) as e:
            out["note"] = f"could not parse archive response: {e}"
        return json.dumps(out, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# ShodanHostURITool
# ─────────────────────────────────────────────────────────────────────────────
class ShodanHostURIInput(BaseModel):
    ip: str = Field(description="IP address to pull host detail for, e.g. '203.0.113.10'")


class ShodanHostURITool(BaseTool):
    name: str = "shodan_host_detail"
    description: str = (
        "Per-IP host detail: open ports, detected products (CPEs), hostnames, tags and known "
        "CVEs. Uses Shodan InternetDB (free, no credits). If SHODAN_API_KEY is set it upgrades "
        "to the full host banner. Returns 'no data' cleanly for IPs Shodan has not scanned "
        "(common for CloudFront/CDN edge IPs) instead of erroring."
    )
    args_schema: type = ShodanHostURIInput

    def _run(self, ip: str) -> str:
        ip = (ip or "").strip()
        out = {"ip": ip, "source": "internetdb", "ports": [], "cpes": [],
               "hostnames": [], "tags": [], "vulns": []}
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            out["note"] = "not an IPv4 address"
            return json.dumps(out)

        # Optional full-banner upgrade when a key is available.
        key = os.environ.get("SHODAN_API_KEY")
        if key:
            try:
                r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={key}",
                                 headers=_UA, timeout=_TIMEOUT)
                if r.ok:
                    d = r.json()
                    return json.dumps({
                        "ip": ip, "source": "shodan",
                        "ports": d.get("ports", []),
                        "hostnames": d.get("hostnames", []),
                        "tags": d.get("tags", []),
                        "vulns": list(d.get("vulns", []) or []),
                        "org": d.get("org"), "os": d.get("os"),
                        "cpes": sorted({c for s in d.get("data", []) for c in s.get("cpe", [])}),
                        "services": [{"port": s.get("port"),
                                      "product": s.get("product"),
                                      "version": s.get("version")}
                                     for s in d.get("data", [])][:25],
                    }, indent=2)
                # 404 = Shodan has no record for this IP → fall through to InternetDB
            except requests.RequestException:
                pass  # fall back to InternetDB

        # Keyless InternetDB.
        try:
            r = requests.get(f"https://internetdb.shodan.io/{ip}", headers=_UA, timeout=_TIMEOUT)
            if r.status_code == 404:
                out["note"] = "no data (Shodan has not scanned this IP)"
                return json.dumps(out, indent=2)
            if not r.ok:
                out["note"] = f"internetdb HTTP {r.status_code}"
                return json.dumps(out, indent=2)
            d = r.json()
            out.update({"ports": d.get("ports", []), "cpes": d.get("cpes", []),
                        "hostnames": d.get("hostnames", []), "tags": d.get("tags", []),
                        "vulns": d.get("vulns", [])})
        except requests.RequestException as e:
            out["note"] = f"internetdb lookup failed: {e}"
        except ValueError as e:
            out["note"] = f"could not parse internetdb response: {e}"
        return json.dumps(out, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Factory — what poc_crew.py / agents import: get_archive_tools()
# Mirrors get_nmap_tools(): returns the tool instances, honors ENABLE_ARCHIVE=0.
# ─────────────────────────────────────────────────────────────────────────────
def get_archive_tools():
    """Return the archive/host-detail tools. Set ENABLE_ARCHIVE=0 to disable (returns [])."""
    if os.environ.get("ENABLE_ARCHIVE", "1") == "0":
        return []
    return [WaybackTool(), ShodanHostURITool()]
