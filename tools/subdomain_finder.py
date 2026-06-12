"""
subdomain_finder.py — passive subdomain discovery (authorized recon).

Aggregates subdomains for a domain from several PASSIVE sources (no brute force, no auth),
de-duplicates, optionally resolves to IPs, and returns a clean list. Each source is best-effort
and isolated — if one is blocked by an egress allowlist or rate-limited, the others still return.

Sources: crt.sh (certificate transparency), HackerTarget hostsearch, RapidDNS, AlienVault OTX,
ThreatMiner. All free, all passive.

Exposes a single minimal-schema CrewAI tool (one field: `domain`) so it adds almost nothing to
an agent's tool-schema compile budget. Toggle off with SUBDOMAIN_TOOL=0.
"""
from __future__ import annotations

import json
import os
import re
import socket

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

try:
    from crewai.tools import BaseTool
    from pydantic import BaseModel, Field
except Exception:  # pragma: no cover
    BaseTool = object  # type: ignore
    class BaseModel:  # type: ignore
        pass
    def Field(*a, **k):  # type: ignore
        return None

_HEADERS = {"User-Agent": "Mozilla/5.0 (ShodanSnipe passive recon)"}
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-_.]*[a-z0-9])?$", re.I)


def _clean(host: str, domain: str) -> str | None:
    h = (host or "").strip().lower().lstrip("*.").rstrip(".")
    if not h or " " in h:
        return None
    if not (h == domain or h.endswith("." + domain)):
        return None
    if not _HOST_RE.match(h):
        return None
    return h


# ── individual passive sources (each returns a set of hostnames, never raises) ──
def _src_crtsh(domain: str, timeout: int) -> set[str]:
    out: set[str] = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                         headers=_HEADERS, timeout=timeout)
        for row in r.json():
            for name in str(row.get("name_value", "")).splitlines():
                c = _clean(name, domain)
                if c:
                    out.add(c)
    except Exception:
        pass
    return out


def _src_hackertarget(domain: str, timeout: int) -> set[str]:
    out: set[str] = set()
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                         headers=_HEADERS, timeout=timeout)
        if r.status_code == 200 and "API count exceeded" not in r.text:
            for line in r.text.splitlines():
                c = _clean(line.split(",")[0], domain)
                if c:
                    out.add(c)
    except Exception:
        pass
    return out


def _src_rapiddns(domain: str, timeout: int) -> set[str]:
    out: set[str] = set()
    try:
        r = requests.get(f"https://rapiddns.io/subdomain/{domain}?full=1",
                         headers=_HEADERS, timeout=timeout)
        for m in re.findall(r"<td>([a-z0-9_.\-]+\." + re.escape(domain) + r")</td>", r.text, re.I):
            c = _clean(m, domain)
            if c:
                out.add(c)
    except Exception:
        pass
    return out


def _src_otx(domain: str, timeout: int) -> set[str]:
    out: set[str] = set()
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            headers=_HEADERS, timeout=timeout)
        for rec in (r.json() or {}).get("passive_dns", []):
            c = _clean(rec.get("hostname", ""), domain)
            if c:
                out.add(c)
    except Exception:
        pass
    return out


def _src_threatminer(domain: str, timeout: int) -> set[str]:
    out: set[str] = set()
    try:
        r = requests.get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5",
                         headers=_HEADERS, timeout=timeout)
        for name in (r.json() or {}).get("results", []):
            c = _clean(name, domain)
            if c:
                out.add(c)
    except Exception:
        pass
    return out


_SOURCES = {
    "crt.sh": _src_crtsh,
    "hackertarget": _src_hackertarget,
    "rapiddns": _src_rapiddns,
    "otx": _src_otx,
    "threatminer": _src_threatminer,
}


def find_subdomains(domain: str, resolve: bool = True, timeout: int = 20,
                    max_resolve: int = 200) -> dict:
    """Discover subdomains for `domain` from all passive sources.

    Returns {"domain", "count", "sources_ok", "sources_failed", "subdomains":[{host,ip?,sources[]}]}.
    """
    domain = (domain or "").strip().lower().lstrip("*.").rstrip(".")
    if not domain or "." not in domain or requests is None:
        return {"domain": domain, "count": 0, "subdomains": [],
                "error": "invalid domain or requests unavailable"}

    found: dict[str, set[str]] = {}     # host -> set(sources)
    ok, failed = [], []
    for name, fn in _SOURCES.items():
        hosts = fn(domain, timeout)
        if hosts:
            ok.append(name)
            for h in hosts:
                found.setdefault(h, set()).add(name)
        else:
            failed.append(name)

    hosts_sorted = sorted(found)
    resolved: dict[str, str] = {}
    if resolve:
        for h in hosts_sorted[:max_resolve]:
            try:
                resolved[h] = socket.gethostbyname(h)
            except Exception:
                pass

    subs = [{"host": h,
             "ip": resolved.get(h),
             "sources": sorted(found[h])} for h in hosts_sorted]
    return {
        "domain": domain,
        "count": len(subs),
        "sources_ok": ok,
        "sources_failed": failed,
        "resolved": len(resolved),
        "subdomains": subs,
        "note": ("Passive sources only — no brute force. Some sources may be blocked by an "
                 "egress allowlist; results reflect what was reachable."),
    }


# ── CrewAI tool (single minimal field) ───────────────────────────────────────
class SubdomainInput(BaseModel):
    domain: str = Field(description="Apex domain to enumerate, e.g. example.com (no scheme, no path)")


class SubdomainFinderTool(BaseTool):
    name: str = "find_subdomains"
    description: str = (
        "Passively enumerate subdomains for an apex domain via certificate transparency and "
        "public passive-DNS sources (crt.sh, HackerTarget, RapidDNS, AlienVault OTX, "
        "ThreatMiner). De-duplicates across sources and resolves to IPs where possible. No brute "
        "force, no auth. Use it to widen the in-scope surface beyond what's already known."
    )
    args_schema: type = SubdomainInput

    def _run(self, domain: str) -> str:
        return json.dumps(find_subdomains(domain), indent=2)


def get_subdomain_tools() -> list:
    """Subdomain finder tool, for build_*_agent tool lists. SUBDOMAIN_TOOL=0 disables it."""
    if os.environ.get("SUBDOMAIN_TOOL", "1").strip().lower() in ("0", "false", "no", "off"):
        return []
    try:
        return [SubdomainFinderTool()]
    except Exception:
        return []


if __name__ == "__main__":  # quick manual test: python subdomain_finder.py example.com
    import sys
    print(json.dumps(find_subdomains(sys.argv[1] if len(sys.argv) > 1 else "example.com",
                                     resolve=False), indent=2))
