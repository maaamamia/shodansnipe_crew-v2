"""
agents/recon_agent.py — Attack Surface Recon Specialist (Shodan power-user build)

Parallel recon pipeline:
  1. ASN discovery (BGPView, RIPE, ARIN)  -> ASN-LINKED bucket (kept SEPARATE)
  2. Shodan search within the app-selected scope
  3. IP -> hostname enrichment
  4. DNS posture (SPF, DMARC, CAA, DNSSEC)

This agent is treated as the most important in the workflow. It is written as a
senior OSINT/Shodan operator: precise, low-false-positive queries, every result
enriched with context, every finding tagged with a confidence level, and a hard
wall between the PRIMARY (app-selected) scope and ASN-EXPANDED discoveries.

Hands off HIGH/MEDIUM findings only. Skips LOW-value hosts automatically.
"""
from __future__ import annotations
import os, json, socket
from typing import Any
from crewai import Agent, Task
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import requests

SHODANSNIPE_URL = os.environ.get("SHODANSNIPE_URL", "http://127.0.0.1:8000")

import time as _time
# Shodan-via-server requests can be slow on broad or enriched queries. Give them room,
# and on timeout retry LIGHTER (smaller limit, no enrich) rather than repeating the heavy
# call — that's what actually clears "read timed out". Both are env-tunable.
_HTTP_TIMEOUT = int(os.environ.get("SHODAN_HTTP_TIMEOUT", "120"))
_HTTP_RETRIES = int(os.environ.get("SHODAN_HTTP_RETRIES", "2"))

# Shared assessment doctrine (discover-don't-assume, modern-infra focus, impact-driven scoring).
try:
    from tools.doctrine import ASSESSMENT_DOCTRINE as _DOCTRINE
except ImportError:
    try:
        from doctrine import ASSESSMENT_DOCTRINE as _DOCTRINE
    except ImportError:
        _DOCTRINE = ""

# Global overridable caps — see limits.py. GLOBAL_NO_LIMITS=1 / GLOBAL_LIMIT_MULTIPLIER / LIMIT_<KEY>.
try:
    from tools.limits import cap as _cap
except ImportError:
    try:
        from limits import cap as _cap
    except ImportError:
        def _cap(key, default):
            if (os.environ.get("GLOBAL_NO_LIMITS", "").lower() in ("1", "true", "yes", "on")):
                return 1_000_000
            v = os.environ.get("LIMIT_" + key.upper())
            if v:
                try: return max(1, int(v))
                except ValueError: pass
            try: m = float(os.environ.get("GLOBAL_LIMIT_MULTIPLIER", "1") or "1")
            except ValueError: m = 1.0
            return max(1, int(round(default * m)))


def _search_with_retry(query: str, limit: int, enrich: bool) -> dict:
    """POST /api/search with a generous timeout; on timeout/conn-error retry with a
    halved limit and enrich off (the two things that make a query slow). Returns parsed
    JSON; raises the last timeout if every attempt fails."""
    last = None
    cur_limit, cur_enrich = limit, enrich
    for attempt in range(_HTTP_RETRIES + 1):
        try:
            r = requests.post(f"{SHODANSNIPE_URL}/api/search",
                              json={"query": query, "limit": cur_limit, "enrich": cur_enrich},
                              timeout=_HTTP_TIMEOUT)
            return r.json()
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            last = e
            cur_limit = max(10, cur_limit // 2)
            cur_enrich = False
            if attempt < _HTTP_RETRIES:
                _time.sleep(1.5 * (attempt + 1))
    raise last

# ── LOW-VALUE FILTER ──────────────────────────────────────────────────────────
INTERESTING_PORTS = {
    # web / remote access
    21,22,23,25,80,443,445,3389,5900,5901,5985,5986,
    # mail / directory / mgmt
    110,143,389,465,587,636,993,995,161,
    # databases
    1433,1521,1522,3306,5432,5984,6379,7474,7687,9042,9200,9300,11211,27017,
    # app servers + message queues  (WebLogic, JBoss, MQ family, Kafka, MQTT)
    1414,1883,4222,4848,5672,6443,7001,7002,8080,8161,8443,8888,9043,9092,
    9990,15672,50000,61616,
    # devops / orchestration
    2375,2376,2379,8200,8500,9000,10250,10255,
    # industrial / legacy
    102,502,20000,47808,
}

def _is_low_value(host: dict) -> bool:
    """Return True if this host has nothing worth an analyst's time."""
    cves  = host.get("cves") or []
    risk  = host.get("risk_level") or "Low"
    prod  = (host.get("product") or "").strip()
    ports = set(host.get("ports") or [])
    tags  = host.get("tags") or []
    if cves:                                    return False
    if risk in ("Critical", "High", "Medium"): return False
    if prod and prod not in ("", "N/A"):        return False
    if ports & INTERESTING_PORTS:              return False
    if any(t in tags for t in ("honeypot","malware","scanner")): return True
    return len(ports) == 0

# Ports whose mere presence is high-signal. Keep these at the FRONT of any truncated
# port list so a dangerous service is never lost to the [:20] slice.
_HIGH_SIGNAL_PORTS = {
    23, 2375, 2376, 6443, 10250, 10255, 2379, 3389, 5900, 5901, 6379, 27017,
    9200, 9300, 5984, 11211, 1433, 3306, 5432, 1521, 1522, 7001, 7002, 8161,
    61616, 1414, 9092, 1883, 445, 389, 161, 8500, 8200, 9000, 502, 102, 47808,
}

_RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

def _sort_ports(ports) -> list:
    """High-signal ports first, then ascending — so truncation drops boring ports, not RDP."""
    return sorted(list(ports or []),
                  key=lambda p: (0 if p in _HIGH_SIGNAL_PORTS else 1, p))

def _risk_key(host: dict) -> int:
    return _RISK_ORDER.get(host.get("risk_level"), 4)

# ── TOOLS ─────────────────────────────────────────────────────────────────────

class ShodanSearchInput(BaseModel):
    query: str = Field(description=(
        "ONE Shodan query. Filters are space-separated and combine as AND "
        "(e.g. `org:\"Acme Corp\" port:443`). "
        "Valid filters: port:, product:, version:, org:, hostname:, net:, asn:, ip:, "
        "country:, ssl:, ssl.cert.subject.cn:, ssl.cert.subject.o:, ssl.cert.expired:, "
        "http.title:, http.html:, http.server:, http.component:, http.favicon.hash:, tag:. "
        "Negation with a leading minus is SUPPORTED and encouraged to cut noise: "
        "`-org:\"Akamai Technologies\"`, `-port:80`, `-tag:cdn`. "
        "NOT supported: the keywords OR / AND / NOT, and `*` wildcards inside a value "
        "(hostname: is already a suffix/substring match, so `hostname:acme.com` is correct, "
        "`hostname:*.acme.com` is invalid). "
        "Comma lists are allowed only inside one filter: `port:22,80,443`. "
        "Quote multi-word values: `product:\"Apache httpd\"`, `org:\"NTT DATA\"`. "
        "ALWAYS quote an org with a comma or legal suffix — `org:\"Company, Inc\"`, "
        "NOT `org:Company, Inc` (unquoted, Shodan reads the comma as a separator and the "
        "bare `Inc` as a second token, dragging in unrelated orgs). Even quoted, `org:` is "
        "a substring match server-side, so confirm scope with net:/asn:/cert anchors."
    ))
    limit: int = Field(25, ge=1, description="Max results; values over 500 are clamped")
    enrich: bool = Field(False, description="Add InternetDB CVE/hostname data (slower)")

class ShodanSearchTool(BaseTool):
    name: str = "shodan_search"
    description: str = (
        "Search Shodan. Returns IP, ports, product, org, CVEs, risk, tags. "
        "One logical query per call — there is no OR keyword, so run alternatives "
        "as separate calls. Use -filter: negation to strip CDN/aggregator noise. "
        "limit up to 500."
    )
    args_schema: type = ShodanSearchInput

    def _run(self, query: str, limit: int = 25, enrich: bool = False) -> str:
        limit = min(max(limit, 1), 500)
        try:
            d = _search_with_retry(query, limit, enrich)
            results = d.get("results", [])
            filtered = [h for h in results if not _is_low_value(h)]
            honeypots = [h.get("ip_str") for h in results
                         if "honeypot" in (h.get("tags") or [])]
            return json.dumps({
                "query": query,
                "total_returned": d.get("total_returned", 0),
                "in_scope_flag_count": sum(1 for h in results if h.get("in_scope")),
                "high_value_hosts": len(filtered),
                "low_value_skipped": len(results) - len(filtered),
                "honeypot_ips_seen": honeypots,   # decoys — DO NOT count as exposures
                "warning": d.get("warning", ""),
                "hosts": [{
                    "ip":         h.get("ip_str"),
                    "in_scope":   h.get("in_scope"),     # server's scope verdict
                    "risk":       h.get("risk_level"),
                    "ports":      _sort_ports(h.get("ports"))[:_cap("recon_ports", 20)],
                    "product":    h.get("product"),
                    "version":    h.get("version"),
                    "http_server":h.get("http_server") or (h.get("http") or {}).get("server"),
                    "http_proto": h.get("http_proto") or h.get("http_protocol"),
                    "transport":  h.get("transport"),
                    "org":        h.get("org"),
                    "asn":        h.get("asn"),
                    "country":    h.get("country"),
                    "hostnames":  h.get("hostnames", [])[:5],
                    "cves":       h.get("cves", [])[:_cap("recon_cves", 10)],
                    "http_title": h.get("http_title"),
                    "ssl_subject":h.get("ssl_subject"),
                    "tags":       h.get("tags", []),
                } for h in sorted(filtered, key=_risk_key)[:_cap("recon_hosts", 50)]]
            }, indent=2)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            return ("Error: Shodan search timed out after retries. The query is likely too "
                    "broad or the server is busy. Tighten it with net:/asn:/port: anchors, "
                    "lower the limit, or set enrich=false, then try again.")
        except Exception as e:
            return f"Error: {e}"


class GetScopeInput(BaseModel):
    pass

class GetScopeTool(BaseTool):
    name: str = "get_scope"
    description: str = (
        "Get the ACTIVE, app-selected scope (orgs, CIDRs, hostnames, ASNs). "
        "This is the authoritative primary scope — the only assets that count as in-scope."
    )
    args_schema: type = GetScopeInput

    def _run(self) -> str:
        try:
            r = requests.get(f"{SHODANSNIPE_URL}/api/scope", timeout=10)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"


class SetScopeInput(BaseModel):
    description: str = Field(description="Plain-text scope e.g. 'Acme Corp, acme.com, 203.0.113.0/24'")

class SetScopeTool(BaseTool):
    name: str = "set_scope"
    description: str = "Set the active scope from plain text. Only use if no scope is set."
    args_schema: type = SetScopeInput

    def _run(self, description: str) -> str:
        try:
            r = requests.post(f"{SHODANSNIPE_URL}/api/scope/set",
                              json={"description": description}, timeout=10)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"


class ASNHuntInput(BaseModel):
    target: str = Field(description="Org name, domain, or ASN e.g. 'Acme Corp' or 'AS15169' or 'acme.com'")

class ASNHuntTool(BaseTool):
    name: str = "asn_hunt"
    description: str = (
        "Discover ASNs and IP prefixes for a target org via BGPView, RIPE, ARIN. "
        "Returns ASN numbers, org names, IPv4 prefixes, and ready-to-run net:/asn: queries. "
        "OUTPUT IS EXPANDED RECON, NOT PRIMARY SCOPE — label everything it surfaces as "
        "'ASN-Linked (Expanded Recon)' and keep it out of in-scope counts."
    )
    args_schema: type = ASNHuntInput

    def _run(self, target: str) -> str:
        try:
            base = "https://api.bgpview.io"
            out = {"target": target, "asns": [], "ipv4_prefixes": [],
                   "shodan_queries": [], "net_queries": [],
                   "label": "ASN-Linked (Expanded Recon) — verify ownership before trusting"}

            r = requests.get(f"{base}/search", params={"query_term": target}, timeout=12)
            if r.ok:
                asns = r.json().get("data", {}).get("asns", [])
                out["asns"] = [
                    {"asn": f"AS{a['asn']}", "name": a.get("name",""),
                     "country": a.get("country_code","")}
                    for a in asns[:10]
                ]
                out["shodan_queries"] = [f"asn:AS{a['asn']}" for a in asns[:5]]
                # Get prefixes for first 3 ASNs
                for a in asns[:3]:
                    pr = requests.get(f"{base}/asn/{a['asn']}/prefixes", timeout=10)
                    if pr.ok:
                        v4 = [p["prefix"] for p in
                              pr.json().get("data", {}).get("ipv4_prefixes", [])[:5]]
                        out["ipv4_prefixes"].extend(v4)
                        out["net_queries"].extend([f"net:{p}" for p in v4])

            return json.dumps(out, indent=2)
        except Exception as e:
            return f"ASN hunt error: {e}"


class DNSPostureInput(BaseModel):
    hostname: str = Field(description="Hostname or domain to check")

class DNSPostureTool(BaseTool):
    name: str = "dns_posture"
    description: str = (
        "Check DNS posture: SPF, DMARC, CAA, DNSSEC, CNAME chain, A/AAAA, MX, NS. "
        "Flags spoofable domains, missing CAA, weak SPF, no DNSSEC."
    )
    args_schema: type = DNSPostureInput

    def _run(self, hostname: str) -> str:
        hostname = hostname.strip().lower().lstrip("https://").lstrip("http://").split("/")[0]
        out = {
            "hostname":    hostname,
            "dns_a":       [],
            "dns_mx":      [],
            "dns_findings": [],
            "dns_has_spf":    False,
            "dns_has_dmarc":  False,
            "dns_has_caa":    False,
            "dns_has_dnssec": False,
        }

        # ── A record (do NOT return early on failure — still check TXT/MX) ──
        try:
            out["dns_a"] = [socket.gethostbyname(hostname)]
        except Exception:
            out["dns_a_error"] = "Could not resolve A record"

        # ── Try dnspython first, fall back to socket/http DNS ──────────────
        try:
            import dns.resolver as res
            resolver = res.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 6.0

            def q(name, rtype):
                try:
                    return [r.to_text() for r in resolver.resolve(
                        name, rtype, raise_on_no_answer=False)]
                except Exception:
                    return []

            txt    = q(hostname, "TXT")
            dmarc  = q(f"_dmarc.{hostname}", "TXT")
            caa    = q(hostname, "CAA")
            dnskey = q(hostname, "DNSKEY")
            mx     = q(hostname, "MX")

        except ImportError:
            # dnspython not installed — use requests to hit a public DNS-over-HTTPS API
            out["dns_method"] = "doh_fallback"
            try:
                import urllib.request
                def doh(name, rtype_num):
                    url = f"https://dns.google/resolve?name={name}&type={rtype_num}"
                    with urllib.request.urlopen(url, timeout=5) as r:
                        data = json.loads(r.read())
                    return [a.get("data","") for a in data.get("Answer", [])]
                txt    = doh(hostname, 16)    # TXT
                dmarc  = doh(f"_dmarc.{hostname}", 16)
                mx     = doh(hostname, 15)    # MX
                caa    = doh(hostname, 257)   # CAA
                dnskey = doh(hostname, 48)    # DNSKEY
            except Exception as e:
                txt = dmarc = mx = caa = dnskey = []
                out["dns_doh_error"] = str(e)

        spf_rec = next((t for t in txt if "v=spf1" in t.lower()), None)
        dm_rec  = next((t for t in dmarc if "v=dmarc1" in t.lower()), None)

        out.update({
            "dns_has_spf":    bool(spf_rec),
            "dns_spf":        spf_rec,
            "dns_has_dmarc":  bool(dm_rec),
            "dns_dmarc":      dm_rec,
            "dns_has_caa":    bool(caa),
            "dns_has_dnssec": bool(dnskey),
            "dns_mx":         mx[:5],
        })

        findings = out["dns_findings"]
        if mx and not spf_rec:
            findings.append("CRITICAL: Has MX but no SPF — domain is spoofable via email")
        if mx and not dm_rec:
            findings.append("HIGH: Has MX but no DMARC — no enforcement policy")
        if dm_rec and "p=none" in dm_rec.lower():
            findings.append("HIGH: DMARC policy is p=none — monitoring only, no enforcement")
        if not caa and out["dns_a"]:
            findings.append("MEDIUM: No CAA records — any CA can issue certs for this domain")
        if not dnskey:
            findings.append("INFO: DNSSEC not enabled")
        spf_pol = next((t for t in (spf_rec or "").split()
                        if t in ("-all", "~all", "?all", "+all")), None)
        if spf_pol in ("+all", "?all"):
            findings.append(f"HIGH: SPF ends with {spf_pol} — effectively permits any sender")
        elif spf_pol == "~all":
            findings.append("MEDIUM: SPF ends with ~all (softfail) — spoofing possible")

        return json.dumps(out, indent=2)


# ── SHODAN DOCTRINE (shared text injected into agent + task) ──────────────────

_SHODAN_SYNTAX = """
━━━ SHODAN SYNTAX — GET THIS RIGHT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Filters are `filter:value`, space-separated, and combine as AND.
  GOOD:  org:"Acme Corp" port:443
  GOOD:  asn:AS12345 port:80,443,8443
  GOOD:  ssl.cert.subject.cn:acme.com -port:80
There is NO `OR`, `AND`, or `NOT` keyword in Shodan.
  ✗ org:"Acme" OR hostname:"acme.com"   → invalid, run TWO separate searches instead
There are NO `*` wildcards inside a filter value.
  hostname: is already a suffix/substring match.
  ✗ hostname:*.acme.com   → invalid
  ✓ hostname:acme.com     → matches mail.acme.com, vpn.acme.com, etc.
Negation with a leading minus IS supported — this is your main noise cutter:
  -org:"Akamai Technologies"   -org:"Cloudflare"   -port:80   -tag:cdn
Comma lists live inside ONE filter only:  port:22,80,443
Quote multi-word values:  product:"Apache httpd"   org:"NTT DATA"
Run each distinct query as its own shodan_search() call.
"""

_FALSE_POSITIVE_DOCTRINE = """
━━━ FALSE-POSITIVE DOCTRINE — APPLY TO EVERY FINDING ━━━━━━━━━━━
You flag false positives loudly and you never overstate. Tag each finding with a
confidence level: "confirmed" | "inferred" | "low".

1. SHARED / WILDCARD CERT ON A CDN IS NOT AFFILIATION.
   Shodan stores ONE banner per IP:port. A wildcard cert (e.g. *.acme.com) seen on a
   multi-tenant CDN edge (Akamai, CloudFront, Fastly, Incapsula, Fastly, Google) does
   NOT prove that some other hostname co-observed there belongs to the org. Do NOT
   write "domain X shares the cert therefore it's an affiliate/risk." Confidence: low.
   Only treat a cert as evidence of ownership when the host is an ORIGIN (org-owned ASN
   / non-CDN net) presenting that cert.

2. "NO WAF / NO CDN OBSERVED" ≠ "UNPROTECTED."
   Shodan not fingerprinting a WAF is absence of evidence, not evidence of absence.
   Write "WAF/CDN not observed (unconfirmed)" — never escalate a host to Critical solely
   because no WAF was seen.

3. SHODAN `vuln:` / VERSION-INFERRED CVEs ARE CANDIDATES, NOT CONFIRMED.
   CVE tags are largely derived from version banners. Banners lie: distro backports patch
   without bumping the version, load balancers echo a different version, banners get
   spoofed. Report these as "CVE candidate (version-inferred, unverified)" with confidence
   "inferred." Confirmation belongs to the Nmap/Vuln stage or a manual check.

4. HONEYPOTS ARE DECOYS.
   Any host with tag `honeypot` (or a high Honeyscore) is bait. List it under
   honeypots_excluded and DO NOT count it as a real exposure. Counting a honeypot is a
   false positive.

5. `org:` AND `hostname:` ARE SUBSTRING-BROAD.
   org:"sans" matches every org containing "sans". hostname:acme.com can match
   notacme.com or acme.com.evil.net. Before counting a host as primary-scope, confirm its
   hostname actually ends in an in-scope domain OR its IP sits in a confirmed in-scope
   net:/asn:. Prefer narrow anchors (confirmed CIDR/ASN + exact cert CN) over broad org:.

6. DATA FRESHNESS.
   Shodan banners can be weeks or months old. Note this. Where it matters, recommend live
   confirmation (the Nmap agent) before asserting a port is open "right now".
"""

_SCOPE_ASN_RULES = """
━━━ SCOPE & ASN RULES — A HARD WALL ━━━━━━━━━━━━━━━━━━━━━━━━━━━
- The scope selected in the application (get_scope) is the SINGLE source of truth for what
  is "in-scope". Do not redefine it, do not broaden it, do not confuse it with anything
  else.
- asn_hunt results, net:/asn: sweeps, subsidiary guesses, and CDN origins are EXPANDED
  RECON. Put them in a separate bucket labelled "ASN-Linked (Expanded Recon)".
- ASN-expanded assets NEVER inflate the primary in-scope counts. Report their counts
  separately. They are leads to hand forward to the other agents — not confirmed targets.
- Before trusting an ASN, sanity-check ownership: does the ASN's registered org actually
  match the target? Shared-hosting ASNs belong to the host, not your target.
"""

# ── AGENT + TASK BUILDERS ─────────────────────────────────────────────────────

def build_recon_agent(llm, extra_tools=None) -> Agent:
    """Create the Attack Surface Reconnaissance Specialist (Shodan power-user)."""
    tools = [
        ShodanSearchTool(), GetScopeTool(), SetScopeTool(),
        ASNHuntTool(), DNSPostureTool(),
    ]
    # Optional curl-style live confirmation (turns an "inferred" banner into "confirmed").
    try:
        from tools.http_validate_tool import HttpProbeTool
        tools.append(HttpProbeTool())
    except ImportError:
        try:
            from http_validate_tool import HttpProbeTool
            tools.append(HttpProbeTool())
        except ImportError:
            pass
    if extra_tools:
        tools.extend(extra_tools)
    return Agent(
        role="Senior OSINT & Shodan Reconnaissance Specialist",
        goal=(
            "Map the external attack surface of the target with surgical precision. "
            "Craft tight, low-false-positive Shodan queries that combine filters "
            "(org/asn/hostname/port/product/version/ssl) and use negation to strip "
            "CDN and aggregator noise. Enrich every relevant result with context — what "
            "the service is, why it belongs to the org, and what the risk is — tag each "
            "finding with a confidence level, and keep a hard wall between the "
            "app-selected primary scope and ASN-expanded discoveries."
        ),
        backstory=(
            "You are a senior OSINT/Shodan power user with 10+ years on red teams and "
            "in threat hunting. You never run raw, unfiltered Shodan dumps — every query "
            "combines filters and is built to minimise false positives. You know Shodan's "
            "real syntax cold: filters AND together by space, there is no OR keyword (so "
            "you run alternatives as separate searches), there are no `*` wildcards in "
            "filter values (hostname: is already a substring match), and `-filter:` "
            "negation is your primary tool for cutting CDN noise. "
            "You are ruthless about false positives. A wildcard cert seen on a shared CDN "
            "edge is NOT proof a co-located domain belongs to the org. 'No WAF observed' is "
            "not 'no WAF'. A version-inferred CVE is a candidate, not a confirmed finding. "
            "A honeypot is a decoy, not an exposure. You label every one of these honestly. "
            "You pivot relentlessly but cleanly: a confirmed hostname leads to a cert CN "
            "pivot, a cert leads to an org/origin pivot, an ASN leads to net: sweeps — and "
            "you keep ASN-expanded assets in their own clearly-labelled bucket so they "
            "never pollute the declared scope. "
            "Your findings feed the Auth, Vuln, and Report agents, so they are precise, "
            "evidence-backed, and confidence-tagged."
        ),
        tools=tools,
        llm=llm,
        verbose=True,
        max_iter=55,
        allow_delegation=False,
    )


def build_recon_tasks(agent, target_org: str, scope_query: str,
                     osint_intel: str = "") -> list:
    """
    Build a two-task recon pipeline:
      Task 1 — confirm the app-selected scope (authoritative)
      Task 2 — layered Shodan coverage with FP controls + ASN separation
    """
    # Build the OSINT seed block — injected into Task 2
    if osint_intel:
        seed_block = f"""
OSINT INTEL PACKAGE — use as your STARTING SEED (not your boundary):
{osint_intel}

RULE: The OSINT package tells you where to START, not where to STOP.
      Run every query in shodan_query_package[] (CRITICAL first, then HIGH, MEDIUM).
      Also run net:<cidr> for every confirmed_cidr (ASN-EXPANDED bucket).
      Also run hostname:<sub> for every high_value_subdomain (verify it ends in an
      in-scope domain before counting it as primary scope).
      Do NOT skip any confirmed asset. Skip anything listed in out_of_scope_asns.
      THEN continue to Layers B/C/D — independent discovery is REQUIRED. "Stay in scope"
      means anchor every query to the org's CIDRs / ASNs / cert CNs; it does NOT mean limit
      yourself to the assets OSINT already handed you. Your job is to find what OSINT MISSED.
"""
    else:
        seed_block = f"""
No OSINT intel yet — use the app-selected scope as seed:
  Primary query: {scope_query}
  Then run asn_hunt("{target_org}") and treat every net:/asn: it returns as the
  ASN-EXPANDED bucket (separate counts, never in-scope).
"""

    # ── Task 1: Confirm the app-selected scope ─────────────────────────────
    set_scope_task = Task(
        description=(
            f"Confirm the active engagement scope. Call get_scope FIRST — the scope "
            f"selected in the application is the authoritative primary scope; do not "
            f"redefine or broaden it.\n"
            f"If and only if get_scope returns empty, set it to: '{scope_query}'.\n"
            "Report back the org name, CIDRs, ASNs, and domains exactly as the system "
            "holds them. State clearly that ASN-discovered ranges will be tracked "
            "separately as expanded recon, not as primary scope."
        ),
        expected_output=(
            "Confirmed primary scope (org, CIDRs, ASNs, domains) exactly as set in the "
            "system, plus an explicit note that ASN-expanded assets are tracked separately."
        ),
        agent=agent,
    )

    # ── Task 2: Layered Shodan coverage ────────────────────────────────────
    recon_task = Task(
        description=f"""
Shodan reconnaissance for {target_org}.
Primary scope (authoritative): {scope_query}

{seed_block}
{_SCOPE_ASN_RULES}
{_SHODAN_SYNTAX}
{_FALSE_POSITIVE_DOCTRINE}
{_DOCTRINE}

━━━ DOCTRINE: BIG → TARGETED (funnel, and PLAN from what you see) ━━━━
Do not open with narrow port guesses. First map the surface broadly, read what is actually
there, THEN aim. Shodan has no free facet API here, so you profile by running a few broad
SCOPED queries with a high limit and tallying the distribution yourself. Every later query
should be justified by something the profile showed — you are planning from evidence, not a
checklist. Combine filters freely; a single filter is rarely the best query.

━━━ LAYER 0 — SURFACE PROFILING (run FIRST, then plan) ━━━━━━━━━━━━
Goal: understand the whole in-scope surface before drilling in.
  1. Broad scoped pull — for each confirmed net:/asn: (and the org as a fallback anchor),
     run it WIDE (limit 100) with NO port filter. Capture, across all results:
       - the set of OPEN PORTS actually present (this is your real port list — not a guess)
       - the PRODUCTS / http.component tech seen (nginx, IIS, WebLogic, Jenkins, F5…)
       - http.server banners and any X-Powered-By / framework hints
       - the CDN/WAF orgs fronting hosts vs org-owned origins
       - obvious clusters (same cert, same title, same favicon) and outliers (lone weird port)
  2. TALLY it: "N hosts, top ports = [...], dominant stack = [...], M behind Cloudflare,
     K exposed origins, unusual ports = [...]". Write this profile down — it drives the plan.
  3. DERIVE THE PLAN from the tally:
       - Standard port groups (Layer B) are the BASELINE — but ADD every non-standard port the
         profile revealed and sweep it: net:<cidr> port:<that_port>. Learn the ports; don't
         assume them.
       - For each dominant product, queue a product+version cohort query.
       - For each exposed-origin candidate, queue header + probe confirmation.
     Then execute Layers A–D against THIS plan, widening or tightening based on result counts
     (too many → add an anchor; too few → loosen one filter and re-run).

━━━ LAYER A — SEEDED QUERIES ━━━━━━━━━━━━━━━━━━━━━━━━━
Run every query from the intel package above (CRITICAL → HIGH → MEDIUM).
These are pre-validated — execute all of them. This is the START, not the end:
Layers B, C, and D below are MANDATORY independent discovery and run on EVERY engagement,
no matter how much OSINT provided. Do not stop after the seeded queries.

━━━ LAYER B — SYSTEMATIC COVERAGE (grouped, scoped searches) ━━━━━
Anchor every Layer B query to the primary scope. Use the tightest available anchor —
prefer `net:<confirmed_cidr>`, `asn:<confirmed_asn>`, or `ssl.cert.subject.cn:<domain>`
over a bare `org:` (which is substring-broad). Replace SCOPE accordingly.

  B1 — Remote access (one call):
    SCOPE port:22,23,3389,5900,5901,5985,5986,512,513,514
  B2 — File transfer & sharing (one call):
    SCOPE port:21,69,445,990,2049,873
  B3 — Mail / directory / mgmt protocols (one call):
    SCOPE port:25,110,143,389,465,587,636,993,995,161
  B4 — Databases (one call):
    SCOPE port:1433,1521,1522,3306,5432,6379,9200,27017,5984,7474,11211,9042
  B5 — App servers & message queues (one call):
    SCOPE port:7001,7002,8161,61616,5672,15672,1414,9092,1883,4848,9990,9043,8080
    (Oracle WebLogic 7001/7002 + T3, ActiveMQ 8161/61616, RabbitMQ 5672/15672,
     IBM MQ 1414, Kafka 9092, MQTT 1883 — do NOT skip these; they are high-value RCE surface.)
  B6 — Web management panels (one call):
    SCOPE port:8443,9090,9443,4443,8500,8200,2375,2376,6443,10250,2379
  B7 — TLS issues (run all):
    SCOPE ssl.cert.expired:true
    ssl.cert.subject.o:"{target_org}"
    SCOPE port:443 ssl.alpn:h2        (HTTP/2-capable endpoints)
  B8 — Origin-vs-CDN check (cuts the #1 false positive):
    When hunting org-owned origins behind a CDN, NEGATE the big CDNs, e.g.:
      ssl.cert.subject.cn:<domain> -org:"Akamai Technologies" -org:"Cloudflare" -org:"Amazon CloudFront" -org:"Fastly" -org:"Incapsula"
    A host that survives those negations and sits on an org-owned net is a real origin.

  VERSION CAPTURE (do this for every host you keep):
    Record the EXACT version, not just the product name — e.g. "OpenSSH 8.9p1",
    "WebLogic 12.2.1.3", "Apache httpd 2.4.59", "Redis 6.2.6", "nginx 1.18.0".
    Also record the HTTP protocol seen (HTTP/1.0, HTTP/1.1, or HTTP/2 via ALPN h2)
    and the TLS versions offered. Version + protocol drive the CVE matching downstream,
    so a finding without a version number is half a finding.

━━━ LAYER C — ASN-EXPANDED SWEEPS (SEPARATE BUCKET) ━━━━━━━━━━━
For each ASN/CIDR from asn_hunt that you verified belongs to the target:
  asn:AS<number>      (one call per ASN)
  net:<cidr>          (one call per CIDR)
Everything found here is "ASN-Linked (Expanded Recon)". Track its counts SEPARATELY.
It never inflates the primary in-scope numbers.

━━━ LAYER D — CREATIVE PIVOTS (be inventive — this is where coverage is won) ━━━
The systematic layers above are the floor, not the ceiling. Shodan rewards creativity — most
real exposure is found by pivoting on something you already saw, not by port lists. Run MANY
of these (each a separate call), following whatever you actually find:

  Identity / fingerprint pivots:
    ssl.cert.subject.cn:<cn>                 related hosts on the same cert subject
    ssl.cert.serial:<serial>                 every host presenting the SAME cert (origins!)
    ssl.cert.fingerprint:<sha>               exact cert reuse across IPs
    ssl.cert.issuer.cn:<issuer>              internal CA? self-signed cluster?
    ssl.jarm:<hash>                          same TLS stack fingerprint (find sibling infra)
    http.favicon.hash:<hash>                 USE WITH CARE — see favicon-fidelity rule below
    http.html_hash:<hash>                    identical page body across hosts
  Content / app pivots:
    http.title:"<title>"                     reuse of a distinctive login/portal title
    http.html:"<string>"                     copyright footer, error signature, app name, JS path
    http.component:"<tech>"                   tech-stack hunting (e.g. "Jenkins","WebLogic","GitLab")
    http.headers.server:"<banner>"           exact Server: banner reuse
  Org / infra pivots:
    org:"<variant>"                          abbreviations, legal names, subsidiaries, acquisitions
    asn:AS<n> / net:<cidr>                    sibling ranges discovered mid-run
    hostname:<value>                          related subdomains off a confirmed host
    product:"<name>" version:<v>              exact product+version cohorts
  Non-obvious:
    Unusual/ephemeral ports you SAW on one host → sweep the scope for the same port.
    A vendor name in a banner → product: that vendor's other products.
    A cloud hostname (*.amazonaws.com, *.azurewebsites.net) tied to the org → pivot on it.
Do not stop at this list. If a result hints at more, chase it. Every pivot result still has to
pass the scope test and the false-positive doctrine — creative does NOT mean sloppy.

━━━ FAVICON FIDELITY (favicon pivots are RISKY — high-fidelity only) ━━━
A favicon hash match does NOT mean same owner. Default framework/CMS favicons (Apache, IIS,
Tomcat, GitLab, Jenkins, default React/Vite, "🌐") are shared by thousands of unrelated hosts —
pivoting on them floods you with false positives. Rules:
  - Only pivot on a favicon that is DISTINCTIVE/custom to the org (a branded logo), never a
    stock/default one. If you can't tell it's custom, don't pivot on it.
  - A favicon-hash match is a CANDIDATE, not a confirmation. It enters scope ONLY when a SECOND
    independent signal agrees (cert CN on an org domain, org-owned ASN/net, or a matching
    hostname). Favicon alone is never sufficient.
  - Record favicon-derived hosts as confidence:"inferred" until corroborated.

━━━ RESPONSE-HEADER CAPTURE & ANALYSIS (do this for every web host you keep) ━━━
Passively from Shodan, capture http.server and http.component. For hosts that matter, pull live
headers with http_probe and ANALYSE them — headers are dense evidence:
  - Server / X-Powered-By / X-AspNet-Version / X-Generator → product + often a version (CVE seed).
  - Via / X-Cache / CF-RAY / X-Akamai-* / X-Served-By / Server:cloudflare → which CDN/WAF fronts it
    (feeds the WAF/Origin call). Absence of these on an org-owned IP suggests an exposed origin.
  - Missing HSTS / CSP / X-Frame-Options / X-Content-Type-Options → posture gaps (Medium, observed).
  - Set-Cookie without Secure/HttpOnly, permissive Access-Control-Allow-Origin:* → real findings.
  - WWW-Authenticate → auth scheme (Basic = cleartext creds = a finding).
Record the headers you used as evidence on the host. A version pulled from a header is as good as
a banner version for CVE matching.

━━━ WAF / CDN / ORIGIN DETERMINATION (do this — it's frequently missed) ━━━
For every in-scope web host, decide and RECORD one of:
  - Fronted by a CDN/WAF — name it (Cloudflare/Akamai/Fastly/CloudFront/Incapsula/Imperva),
    inferred from Server: header, cert issuer, ASN org, or response headers.
  - EXPOSED ORIGIN — the host survived the CDN-negation query (Layer B8) and sits on an
    org-owned net. These BYPASS the WAF and are high-value — flag each by IP.
  - Direct / no CDN observed — no CDN signature seen (state it's an observation, not proof).
Run the origin hunt explicitly: ssl.cert.subject.cn:<domain> -org:"Akamai Technologies"
-org:"Cloudflare, Inc." -org:"Amazon CloudFront" -org:"Fastly" -org:"Imperva". Anything that
returns is a candidate exposed origin — confirm it's org-owned, then record it.

━━━ SSH / REMOTE-ACCESS CAPTURE (inventory every one) ━━━
For EVERY host on 22/2222/22222/23/3389/5900/5985/5986: record the exact version
(e.g. "OpenSSH 7.4", "OpenSSH 8.9p1"). Old/EOL OpenSSH (≤7.x) maps to real CVEs — flag those
as candidates. SSH being open is not itself High, but every SSH host is INVENTORIED and handed
forward — never drop them. Non-standard SSH ports (2222, 22222) are worth an extra note.

━━━ DNS POSTURE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
For each unique in-scope domain/subdomain, run dns_posture.
Flag: missing SPF, missing DMARC, weak SPF (+all/~all), DMARC p=none, missing CAA.

━━━ NMAP ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
If nmap_scan is available, run it on hosts with ports 3389, 23, 2375, 6443, or 5900 to
confirm liveness and pull live banners. Live Nmap is how an "inferred" finding becomes
"confirmed".

━━━ ENRICHMENT & CONFIDENCE ━━━━━━━━━━━━━━━━━━━━━━━━━━
For every host you keep: say what the service is, why it plausibly belongs to the org,
the concrete evidence (banner / version / cert CN / hostname / open port), and assign
confidence: confirmed | inferred | low. Never hand forward a bare IP with no context.
Severity follows the evidence, NOT the port: an open port running a normal, current service
with no exposed sensitive function is Low/Informational — do not label it High just because
the port is "interesting". Reserve High/Critical for an observed defect (cleartext protocol,
confirmed no-auth, vulnerable version, exposed admin/data surface).
If http_probe is available and a host's risk hinges on something Shodan can't show you (is
the panel live? is it behind auth?), probe the service URL to confirm before you assign
Critical/High. A probe that returns 401/403 or refuses connection means downgrade or drop.

━━━ FULL-INVENTORY MANDATE (do not drop the clean surface) ━━━
Emit EVERY discovered in-scope host in primary_scope_findings — including the CLEAN ones with
no defect (risk:"Low"/"Informational"). The report's inventory is built from this list, so a
host you omit here vanishes from the whole assessment. Most of a real surface is unremarkable
web + SSH + mail + DNS + network services that are NOT findings — they still belong in the
inventory. In particular, do NOT filter out: SSH/remote-access hosts, mail/DNS/SNMP/BGP/NTP
and other network-service hosts, and plain web hosts behind a CDN. Risk-rank them honestly
(most will be Low), but list them all. If a cap forces truncation, prefer raising the cap
(GLOBAL_LIMIT_MULTIPLIER / LIMIT_RECON_HOSTS) over silently dropping hosts.


━━━ OUTPUT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Return JSON. Note the hard split between primary scope and ASN-expanded:
{{
  "queries_run": ["exact query 1", "exact query 2", "..."],
  "surface_profile": {{
    "total_hosts_seen": N,
    "top_ports": [443, 80, 22, "..."],
    "dominant_products": ["nginx 1.18", "Oracle WebLogic", "..."],
    "unusual_ports_found": [8531, 9092, "..."],
    "cdn_fronted_hosts": N, "exposed_origins": N,
    "plan_notes": "what the broad profile drove — which non-standard ports were swept, which "
                  "product cohorts and origin/header confirmations were queued as a result"
  }},
  "primary_scope_summary": {{
    "in_scope_hosts": N,
    "critical": N, "high": N, "medium": N,
    "remote_access_hosts": N, "exposed_databases": N,
    "expired_certs": N, "exposed_mgmt_interfaces": N
  }},
  "asn_expanded_summary": {{
    "asns_discovered": ["AS12345", "..."],
    "ownership_verified": true,
    "expanded_hosts": N,
    "note": "ASN-Linked (Expanded Recon) — NOT counted in primary scope"
  }},
  "primary_scope_findings": [
    {{
      "ip": "1.2.3.4",
      "hostname": "vpn.acme.com",
      "risk": "Critical|High|Medium|Low",
      "confidence": "confirmed|inferred|low",
      "ports": [22, 3389, 443],
      "product": "OpenSSH 7.4",
      "server_header": "nginx/1.18.0 | (from http.server or live probe)",
      "http_protocol": "HTTP/1.1 | HTTP/2 | -",
      "security_header_gaps": ["HSTS", "CSP"],
      "evidence": "banner string / cert CN / Shodan vuln tag / response headers — observed",
      "cves_candidate": ["CVE-XXXX-YYYY (version-inferred, unverified)"],
      "waf_cdn": "not observed (unconfirmed) | Akamai | Cloudflare | origin",
      "org": "...",
      "why_in_scope": "hostname ends in acme.com / IP in confirmed net 203.0.113.0/24",
      "why_notable": "Internet-facing RDP on a named VPN host — direct credential-spray target",
      "false_positive_checks": "not a honeypot; cert is on org-owned origin, not a CDN edge"
    }}
  ],
  "asn_expanded_findings": [
    {{
      "ip": "5.6.7.8", "asn": "AS12345", "risk": "High", "confidence": "inferred",
      "ports": [9200], "product": "Elasticsearch",
      "evidence": "...", "label": "ASN-Linked (Expanded Recon)",
      "why_notable": "Unauth Elastic on org-linked ASN — verify ownership and auth state"
    }}
  ],
  "honeypots_excluded": [
    {{"ip": "9.9.9.9", "reason": "tag:honeypot — decoy, excluded from counts"}}
  ],
  "dns_findings": [
    {{"domain": "acme.com", "issues": ["No DMARC", "SPF ~all — softfail only"]}}
  ],
  "false_positives_noted": [
    "shared *.acme.com cert on Akamai edge 1.2.3.4 — NOT treated as org-owned"
  ],
  "recommended_pivots": ["ssl.cert.subject.cn:acme.com -org:\\"Akamai Technologies\\"", "org:\\"Acme Holdings\\""]
}}
""",
        agent=agent,
        expected_output=(
            "JSON: queries_run[]; primary_scope_summary{}; asn_expanded_summary{}; "
            "primary_scope_findings[{ip, hostname, risk, confidence, ports, product, "
            "evidence, cves_candidate, waf_cdn, org, why_in_scope, why_notable, "
            "false_positive_checks}]; asn_expanded_findings[] (labelled, separate); "
            "honeypots_excluded[]; dns_findings[]; false_positives_noted[]; "
            "recommended_pivots[]. Primary-scope and ASN-expanded counts MUST stay separate."
        ),
        context=[set_scope_task],
    )

    return [set_scope_task, recon_task]
