"""
scope_advisor.py — evidence-first scope decisions + query expansion.

WHY THIS EXISTS
Hard-coded naming conventions (org-name permutations, subdomain prefix lists, "must contain
the org string") are great for GENERATING candidates but dangerous as INCLUSION filters: an
asset whose name doesn't fit the pattern gets silently dropped, and that is exactly how real
findings get excluded. A cloud-hosted Dell API on `Armor Defense Inc` infrastructure, a
subsidiary on an unrelated brand, an acquired company's legacy host — none of them "look like"
the org, yet all are in scope.

Two tools:

  ScopeAdvisorTool  — given a candidate + whatever evidence is known (RDAP org, cert CN,
                      hostnames, ASN/CIDR membership), returns INCLUDE / VERIFY / EXCLUDE with
                      reasons. Core rule: a name not matching a convention is NEVER, by itself,
                      grounds for exclusion. Include on any solid tie to scope; when unsure,
                      VERIFY (keep it, flag a check) rather than drop; EXCLUDE only with
                      POSITIVE contrary evidence.

  QueryExpanderTool — turns the confirmed scope + discovered data into a BROAD, diverse Shodan
                      query set (org / net / cert-serial / jarm / favicon / html_hash /
                      http.component / modern-infra), drawing on query_advisor's template
                      catalogue when available. Built to widen a thin query package, not repeat
                      the same handful of filters.
"""
from __future__ import annotations

import re
from typing import Any

try:
    from crewai.tools import BaseTool
    from pydantic import BaseModel, Field
except Exception:  # pragma: no cover - allows import in non-crewai contexts
    BaseTool = object  # type: ignore
    class BaseModel:  # type: ignore
        pass
    def Field(*a, **k):  # type: ignore
        return None


# Known CDN / cloud / security-edge orgs: RDAP showing one of these is NOT contrary evidence —
# it just means the asset is cloud-hosted. Ownership is then decided by hostname/cert ties.
_EDGE_ORGS = (
    "cloudflare", "akamai", "amazon", "aws", "amazon cloudfront", "fastly", "microsoft",
    "azure", "google", "gcp", "incapsula", "imperva", "armor defense", "fortinet", "stackpath",
    "oracle cloud", "digitalocean", "linode", "vultr", "ovh", "leaseweb", "hetzner",
)


def _norm(s: str) -> str:
    return (s or "").strip().lower()


def _csv(s) -> list[str]:
    """Split a comma/space/semicolon-separated string into a clean list. Accepts a list too,
    so the underlying advise_scope/expand_queries keep their list signatures unchanged."""
    if isinstance(s, (list, tuple)):
        return [str(x).strip() for x in s if str(x).strip()]
    return [p.strip() for p in re.split(r"[,;\s]+", str(s or "")) if p.strip()]


def _ends_in_scope_domain(host: str, scope_domains: list[str]) -> str | None:
    h = _norm(host).rstrip(".")
    for d in scope_domains:
        d = _norm(d).rstrip(".")
        if d and (h == d or h.endswith("." + d)):
            return d
    return None


def advise_scope(
    candidate: str,
    *,
    rdap_org: str = "",
    cert_cn: str = "",
    hostnames: list[str] | None = None,
    asn: str = "",
    in_confirmed_cidr: bool = False,
    in_confirmed_asn: bool = False,
    scope_domains: list[str] | None = None,
    scope_orgs: list[str] | None = None,
) -> dict:
    """Return an evidence-based scope verdict for one candidate."""
    hostnames = hostnames or []
    scope_domains = [_norm(d) for d in (scope_domains or []) if d]
    scope_orgs = [_norm(o) for o in (scope_orgs or []) if o]
    ties: list[str] = []

    # 1) Network membership — strongest tie.
    if in_confirmed_cidr:
        ties.append("IP within a confirmed in-scope CIDR")
    if in_confirmed_asn:
        ties.append("ASN is a confirmed in-scope ASN")

    # 2) Hostname / cert tie to a scope domain — survives CDN/cloud hosting.
    for h in list(hostnames) + ([candidate] if "." in candidate and not candidate[0].isdigit() else []):
        d = _ends_in_scope_domain(h, scope_domains)
        if d:
            ties.append(f"hostname {h} ends in scope domain {d}")
            break
    cd = _ends_in_scope_domain(cert_cn, scope_domains)
    if cd:
        ties.append(f"cert CN/SAN {cert_cn} ties to scope domain {cd}")

    # 3) RDAP org matches a scope org (token overlap, suffix-insensitive).
    ro = _norm(rdap_org)
    org_match = bool(ro) and any(
        o and (o in ro or ro in o or (o.split() and o.split()[0] in ro))
        for o in scope_orgs)
    if org_match:
        ties.append(f"RDAP org '{rdap_org}' matches a scope org")

    is_edge = any(e in ro for e in _EDGE_ORGS)

    # ── verdict ──────────────────────────────────────────────────────────────
    if ties:
        # Any solid tie = include. CDN/cloud RDAP org is fine when a hostname/cert tie exists.
        conf = "high" if len(ties) >= 2 or in_confirmed_cidr or in_confirmed_asn else "medium"
        note = ""
        if is_edge and not org_match:
            note = " (cloud/CDN-hosted — ownership established by hostname/cert tie, not RDAP)"
        return {"candidate": candidate, "verdict": "include", "confidence": conf,
                "reasons": ties, "note": note.strip()}

    # No ties. Is there POSITIVE contrary evidence?
    if ro and not is_edge:
        # RDAP shows a concrete, non-edge, unrelated org and nothing ties to scope.
        return {"candidate": candidate, "verdict": "exclude", "confidence": "medium",
                "reasons": [f"RDAP org '{rdap_org}' is a concrete unrelated org and no "
                            f"hostname/cert/network tie to scope was found"],
                "note": "Evidenced exclusion — NOT a name-convention guess. Re-include "
                        "immediately if a cert/DNS tie later appears."}

    # Nothing ties, nothing contradicts → VERIFY. Never drop on a name mismatch.
    return {"candidate": candidate, "verdict": "verify", "confidence": "low",
            "reasons": ["no evidence either way yet"],
            "note": "Keep and VERIFY (cert transparency / RDAP / DNS). A name that doesn't "
                    "match the org's usual convention is NOT grounds for exclusion."}


# ── Query expansion ──────────────────────────────────────────────────────────
def _load_templates() -> list[dict]:
    for path in ("query_advisor", "core.query_advisor"):
        try:
            mod = __import__(path, fromlist=["TEMPLATES"])
            return list(getattr(mod, "TEMPLATES", []) or [])
        except Exception:
            continue
    return []


# Dimensions that COMBINE with any scope anchor (org / net / asn) to form a dynamic matrix.
_PORT_GROUPS = {
    "remote-access": "port:22,2222,3389,5900,23,5985",
    "databases":     "port:3306,5432,27017,6379,9200,1433,11211,5984,9042",
    "mail":          "port:25,465,587,993,995,110,143",
    "web-alt":       "port:8080,8443,8000,8888,9443,3000,5000,7001,9090",
    "infra-net":     "port:161,179,53,123,389,636,514,1900",
    "containers":    "port:2375,2376,6443,10250,2379,10255,8001",
    "file-transfer": "port:21,69,873,2049,445,139",
    "ics-ot":        "port:502,102,20000,44818,47808,1911",
}
_COMPONENTS = ["WordPress", "Drupal", "Joomla", "Jenkins", "GitLab", "Grafana",
               "Kibana", "Apache Tomcat", "Spring", "Citrix", "Confluence"]
_MISCONFIG = [
    ('http.title:"Index of /"', "open directory listing"),
    ('http.title:"Index of /.git"', "exposed .git tree"),
    ('http.html:"ListBucketResult"', "open S3-style bucket"),
    ('ssl.cert.expired:true', "expired TLS cert"),
    ('http.title:"Dashboard [Jenkins]"', "exposed Jenkins"),
    ('http.title:"Swagger UI"', "exposed API docs"),
    ('http.title:"phpMyAdmin"', "exposed DB admin panel"),
    ('http.title:"Grafana"', "exposed Grafana"),
    ('http.html:"default password"', "default-creds hint"),
    ('http.status:401', "auth-gated surface (enumerate)"),
    ('http.status:403', "forbidden surface (probe paths)"),
    ('has_screenshot:true', "visual triage candidates"),
    ('ssl.cert.subject.cn:* -http.title:""', "TLS hosts to fingerprint"),
]


def expand_queries(org: str = "", domain: str = "", cidrs: list[str] | None = None,
                   products: list[str] | None = None, max_queries: int = 140) -> list[dict]:
    """Generate a BROAD, DYNAMIC, combinatorial Shodan query set from scope + observed data.

    DISCOVERY-FIRST with OBSERVED-PRIORITY. This is a discovery process, so the broad sweep
    (port-groups, the full component battery, misconfig/exposure signatures) ALWAYS runs against
    every scope anchor — that is how you surface the GitLab/Grafana/etc box recon has NOT seen yet.
    Recon-observed products are ADDITIVE on top: they're promoted to HIGH priority (real, current,
    version/CVE-seeded), and any static component recon already confirmed is tagged 'observed' and
    bumped — but the unobserved components stay in the sweep as 'discovery' candidates. We never
    restrict discovery to what is already known (that would only re-find the known). It also layers
    on the high-value singleton pivots (cert-CN, exposed-origin-behind-CDN) and the query_advisor
    templates; recon adds fingerprint pivots (jarm / cert-serial / favicon / html_hash) from the
    concrete seed values it observes at runtime.
    """
    cidrs = cidrs or []
    products = products or []
    out: list[dict] = []
    seen: set[str] = set()

    def add(q: str, why: str, prio: str = "MEDIUM"):
        q = (q or "").strip()
        if q and q not in seen and "{" not in q and len(out) < max_queries:
            seen.add(q)
            out.append({"query": q, "priority": prio, "why": why})

    # ── High-value singleton pivots ──────────────────────────────────────────
    if org:
        add(f'org:"{org}"', "full org footprint", "HIGH")
    if domain:
        add(f"ssl.cert.subject.cn:{domain}", "cert-CN pivot — forgotten subdomains/origins", "HIGH")
        add(f"hostname:{domain}", "hostname coverage", "HIGH")
        add(f'ssl.cert.subject.cn:{domain} -org:"Cloudflare, Inc." -org:"Akamai Technologies" '
            f'-org:"Amazon CloudFront" -org:"Fastly, Inc."',
            "exposed ORIGIN behind CDN (WAF-bypass)", "CRITICAL")

    # ── Combinatorial matrix: each ANCHOR × each DIMENSION ───────────────────
    anchors: list[tuple[str, str]] = []
    if org:
        anchors.append((f'org:"{org}"', "org"))
    for c in cidrs[:6]:
        anchors.append((f"net:{c}", f"net {c}"))
    if domain and not anchors:               # domain-only scope still gets a matrix
        anchors.append((f"ssl.cert.subject.cn:{domain}", f"cert {domain}"))

    # Observed-first PRIORITY, not a filter. Recon-observed products lead (real, current, HIGH),
    # but this is DISCOVERY: the broad component/port/misconfig sweep ALWAYS runs to surface what
    # recon has NOT seen yet. We never restrict the sweep to known products — that would only ever
    # re-find the known and never discover the GitLab/Grafana/etc box nobody has hit yet. Observed
    # products are ADDITIVE and promoted; the static battery stays for genuine discovery, and is
    # marked 'observed' for components recon already confirmed so the agent knows which are real.
    observed = [str(p).strip() for p in products if str(p).strip()]
    obs_blob = " ".join(observed).lower()

    for a_q, a_label in anchors:
        # 1) OBSERVED products FIRST — highest signal, current, actionable (recon-defined).
        for p in observed[:12]:
            add(f'{a_q} product:"{p}"', f"{a_label} × {p} (OBSERVED — version/CVE seed)", "HIGH")
        # 2) Port-groups — signature-based discovery, broadly useful regardless of target.
        for grp, pg in _PORT_GROUPS.items():
            add(f"{a_q} {pg}", f"{a_label} × {grp} ports", "MEDIUM")
        # 3) Components — FULL discovery sweep (find the unknown). Components recon already
        #    confirmed are tagged 'observed' + bumped; the rest stay as discovery candidates.
        for comp in _COMPONENTS:
            if comp.lower() in obs_blob:
                add(f'{a_q} http.component:"{comp}"', f"{a_label} × {comp} cohort [observed]", "HIGH")
            else:
                add(f'{a_q} http.component:"{comp}"', f"{a_label} × {comp} cohort [discovery]", "MEDIUM")
        # 4) Misconfig / exposure signatures — always swept (discovery).
        for mq, why in _MISCONFIG:
            add(f"{a_q} {mq}", f"{a_label} × {why}", "MEDIUM")

    # ── query_advisor template catalogue (org/domain-scoped only) ────────────
    for tpl in _load_templates():
        params = tpl.get("params", [])
        if not params:
            continue  # global template — not org-scoped, skip for a target package
        q = str(tpl.get("query", ""))
        ok, filled = True, 0
        for p in params:
            k = _norm(str(p.get("key", "")))
            if any(t in k for t in ("org", "company", "vendor")):
                val = org
            elif any(t in k for t in ("domain", "cn", "host", "cert", "site")):
                val = domain
            else:
                ok = False
                break
            if not val:
                ok = False
                break
            q = q.replace("{" + str(p.get("key")) + "}", val)
            filled += 1
        if (ok and filled and "{" not in q and ":." not in q
                and not q.rstrip().endswith(":")):
            add(q, f"template: {tpl.get('title','')}", "MEDIUM")

    return out


# ── CrewAI tool (minimal 2-field schema) ─────────────────────────────────────
# Anthropic compiles every tool's input schema into a constrained-decoding grammar and budgets
# the AGGREGATE across all of an agent's tools. To add the least possible to that budget, this
# tool exposes only TWO string fields — `action` and `params_json` — instead of a dozen typed
# fields. All real parameters travel inside the JSON string and are unpacked in _run, so the
# advise/expand logic is unchanged but the schema footprint is about as small as a tool can be.
class ScopeAdvisorInput(BaseModel):
    action: str = Field(default="advise",
                        description="'advise' = judge one asset's scope; 'expand' = build a broad query package")
    params_json: str = Field(
        default="{}",
        description=(
            'JSON object of parameters. '
            'For advise: {"candidate":"1.2.3.4","rdap_org":"","cert_cn":"","hostnames":"a.x.com,b.x.com",'
            '"scope_domains":"x.com","scope_orgs":"X","in_confirmed_cidr":false,"in_confirmed_asn":false}. '
            'For expand: {"org":"X","domain":"x.com","cidrs":"1.2.0.0/16","products":"nginx"}. '
            'List-like values may be comma-separated strings or JSON arrays.'))


class ScopeAdvisorTool(BaseTool):
    name: str = "scope_advisor"
    description: str = (
        "Scope + query advisor. Set action and pass params_json (a JSON object string).\n"
        "• action='advise' — decide if a candidate asset is in scope using EVIDENCE, not naming. "
        "Returns include / verify / exclude with reasons. Include on any solid tie (confirmed "
        "CIDR/ASN, hostname or cert tied to a scope domain, RDAP org match — cloud/CDN hosting is "
        "fine). No tie AND no contradiction → VERIFY (keep it, check it); it NEVER excludes on a "
        "name mismatch.\n"
        "• action='expand' — generate a BROAD, diverse Shodan query package (org/net/cert/jarm/"
        "favicon/html_hash/component/modern-infra + template catalogue) to widen a thin package."
    )
    args_schema: type = ScopeAdvisorInput

    def _run(self, action: str = "advise", params_json: str = "{}") -> str:
        import json
        p: dict = {}
        if isinstance(params_json, dict):
            p = params_json
        else:
            try:
                p = json.loads(params_json) if params_json else {}
            except Exception:
                p = {}
        if not isinstance(p, dict):
            p = {}
        if str(action or "advise").strip().lower().startswith("exp"):
            return json.dumps(expand_queries(
                org=p.get("org", ""), domain=p.get("domain", ""),
                cidrs=_csv(p.get("cidrs", "")), products=_csv(p.get("products", ""))), indent=2)
        return json.dumps(advise_scope(
            p.get("candidate", ""), rdap_org=p.get("rdap_org", ""), cert_cn=p.get("cert_cn", ""),
            hostnames=_csv(p.get("hostnames", "")),
            in_confirmed_cidr=bool(p.get("in_confirmed_cidr", False)),
            in_confirmed_asn=bool(p.get("in_confirmed_asn", False)),
            scope_domains=_csv(p.get("scope_domains", "")),
            scope_orgs=_csv(p.get("scope_orgs", ""))), indent=2)


def get_scope_advisor_tools() -> list:
    """Single combined advisor tool (advise + expand). Set SCOPE_ADVISOR_TOOL=0 to disable it
    entirely if an agent's aggregate tool schema ever overflows the provider's compile budget."""
    import os
    if os.environ.get("SCOPE_ADVISOR_TOOL", "1").strip().lower() in ("0", "false", "no", "off"):
        return []
    try:
        return [ScopeAdvisorTool()]
    except Exception:
        return []
