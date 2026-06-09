"""
llm.py — LLM client for ShodanSnipe.

Design principles:
  - One canonical tier enforcement block (_tier_block) — no duplication.
  - goal_to_query uses a structured reasoning chain: the AI must think through
    attack vectors, query families, and pivot points BEFORE committing to a query.
  - All prompts inject hard Shodan syntax rules — enforced again server-side by
    validate_shodan_query() before anything reaches the UI.
  - Personas (ASM / TI) carry distinct analytical lenses into every triage call.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import aiohttp
import db

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Provider config
# ---------------------------------------------------------------------------
def get_settings() -> dict[str, str]:
    return {
        "provider": db.get_config("llm_provider") or "ollama",
        "model":    db.get_config("llm_model")    or "llama3.2",
        "endpoint": db.get_config("llm_endpoint") or "http://localhost:11434",
        "has_anthropic_key": bool(db.get_config("anthropic_key")),
        "has_openai_key":    bool(db.get_config("openai_key")),
    }


def set_settings(
    provider: str,
    model: str,
    endpoint: str | None = None,
    anthropic_key: str | None = None,
    openai_key: str | None = None,
) -> None:
    db.set_config("llm_provider", provider)
    db.set_config("llm_model", model)
    if endpoint:      db.set_config("llm_endpoint",   endpoint)
    if anthropic_key: db.set_config("anthropic_key",  anthropic_key)
    if openai_key:    db.set_config("openai_key",     openai_key)


# ---------------------------------------------------------------------------
# SHODAN SYNTAX RULES — injected into every query-generating prompt.
# These are the exact constraints the Shodan API enforces at runtime.
# ---------------------------------------------------------------------------
SHODAN_SYNTAX_RULES = """
╔══════════════════════════════════════════════════════════════════╗
║            SHODAN QUERY SYNTAX — HARD CONSTRAINTS               ║
╚══════════════════════════════════════════════════════════════════╝

FORBIDDEN — these cause immediate API errors:
  ✗  OR, AND, NOT operators   e.g. "port:22 OR port:80"  → BREAKS
  ✗  Wildcards (* or ?)       e.g. "product:apache*"     → BREAKS
  ✗  Parentheses              e.g. "(port:22 OR port:80)" → BREAKS

ALLOWED syntax:
  ✓  Space = implicit AND.    port:22 org:"Acme"  →  port 22 AND org Acme
  ✓  Minus = NOT.             port:22 -country:CN →  exclude China
  ✓  Quoted strings.          org:"Acme Corp"     →  exact phrase
  ✓  Comma in port: only.     port:22,80,443      →  any of these ports
  ✓  All other filters take exactly ONE value each.

OR LOGIC WORKAROUND — when a goal needs OR (multiple products, protocols):
  Do NOT write: port:22 OR port:3389
  DO write two separate queries, one per alternative:
    alternatives[0].query = "port:22"
    alternatives[1].query = "port:3389"
  The analyst queues both and runs them separately.

VALID FILTER EXAMPLES:
  port:443                          port:22,80,443
  org:"Acme Corp"                   asn:AS15169
  product:"nginx"                   product:"Apache httpd" port:80
  http.title:"Admin Panel"          http.title:"Login"
  http.html:"phpMyAdmin"            http.favicon.hash:-1616143106
  ssl.cert.subject.cn:example.com   ssl.cert.expired:true
  ssl.cert.issuer.cn:"Let's Encrypt"
  country:US                        city:"Dallas"
  hostname:example.com              domain:example.com
  net:192.168.1.0/24                ip:1.2.3.4
  os:"Windows Server 2019"          version:"2.4.51"
  tag:iot  ← Corporate+ plan only  tag:cloud  ← Corporate+ plan only
  before:2024-01-01                 after:2023-06-01
  vuln:CVE-2021-44228               has_vuln:true
  -port:80                          -country:CN
  ssh.hassh:abc123                  http.component:"jQuery"

EXCLUSION RULES — minus (-) only works reliably on THESE filters:
  ✓  -country:CN              exclude a country
  ✓  -port:80                 exclude a port
  ✓  -org:"Akamai"            exclude an organisation
  ✓  -isp:"Cloudflare"        exclude an ISP/CDN — USE THIS to exclude CDN vendors
  ✓  -hostname:example.com    exclude a hostname pattern
  ✓  -product:"nginx"         exclude a product

  ✗  -asn:AS12345  → NOT SUPPORTED — ASN exclusion does not work in Shodan
  ✗  -net:x.x.x.x/24 → NOT SUPPORTED — CIDR exclusion does not work
  ✗  -ip:x.x.x.x   → NOT SUPPORTED — IP exclusion does not work

EXCLUDING CDN / INFRASTRUCTURE VENDORS (Akamai, Cloudflare, Fastly, etc.):
  CORRECT:  org:"Target" -isp:"Akamai Technologies"
  CORRECT:  org:"Target" -org:"Akamai"
  WRONG:    org:"Target" -asn:AS20940    ← asn exclusion NOT supported
  WRONG:    org:"Target" NOT isp:Akamai  ← NOT operator NOT supported

COMBINING FILTERS (space = AND):
  product:"nginx" country:US -port:443
  org:"Amazon" port:27017,5432,3306,6379
  http.title:"Dashboard" ssl.cert.expired:true
  hostname:example.com port:22,3389
"""


# ---------------------------------------------------------------------------
# Tier enforcement — single canonical block, no duplication
# ---------------------------------------------------------------------------
TIER_CAPABILITIES = {
    "free": {
        "label": "Free / Developer / OSS",
        "can_use_vuln": False,
        "can_use_has_vuln": False,
        "can_use_has_screenshot": False,
        "result_limit": 100,
        "allowed_filters": [
            "port:", "product:", "org:", "country:", "city:", "hostname:",
            "domain:", "net:", "http.title:", "http.html:", "http.favicon.hash:",
            "ssl.cert.subject.cn:", "ssl.cert.expired:", "ssl.cert.issuer.cn:",
            "before:", "after:", "version:", "os:", "asn:", "isp:",
        ],
        "blocked_filters": ["vuln:", "has_vuln:", "has_screenshot:", "tag:"],
        "notes": [
            "max 100 results per query",
            "vuln:, has_vuln:, has_screenshot: are BLOCKED — do not suggest them",
            "org: and asn: work but may return truncated counts",
            "SUBSTITUTE CVE queries with: product: + port: combinations",
            "SUBSTITUTE has_vuln: with: product: version: combinations for known-vulnerable versions",
        ],
    },
    "member": {
        "label": "Member / Freelancer / Small Business",
        "can_use_vuln": True,
        "can_use_has_vuln": True,
        "can_use_has_screenshot": True,
        "result_limit": 1000,
        "allowed_filters": ["ALL filters except tag:"],
        "blocked_filters": ["tag:"],
        "notes": [
            "up to 1 000 results, query credits apply",
            "vuln:CVE-XXXX-YYYY available for specific CVE matching",
            "has_vuln:true available to find any vulnerable host",
            "has_screenshot:true available",
            "tag: filter is NOT available — Corporate plan and above only",
        ],
    },
    "enterprise": {
        "label": "Corporate / Enterprise / EDU / GOV / ASM",
        "can_use_vuln": True,
        "can_use_has_vuln": True,
        "can_use_has_screenshot": True,
        "result_limit": 10000,
        "allowed_filters": ["ALL filters"],
        "blocked_filters": [],
        "notes": [
            "up to 10 000+ results",
            "all filters available including vuln:, has_vuln:, has_screenshot:",
            "historical data and scan credits available",
            "no query-credit restrictions in most plans",
        ],
    },
}


def _tier_block(tier: str) -> str:
    """Single canonical tier context block for prompt injection."""
    cap = TIER_CAPABILITIES.get(tier, TIER_CAPABILITIES["free"])
    lines = [
        f"╔══════════════════════════════════════════════════════════════════╗",
        f"║  ANALYST SHODAN PLAN: {cap['label']:<43}║",
        f"╚══════════════════════════════════════════════════════════════════╝",
        "",
    ]

    if cap["blocked_filters"]:
        lines.append("BLOCKED FILTERS — DO NOT USE IN ANY QUERY:")
        for f in cap["blocked_filters"]:
            lines.append(f"  ✗  {f}  ← will return 403 or empty results for this plan")
        lines.append("")

    lines.append("PLAN NOTES:")
    for note in cap["notes"]:
        lines.append(f"  • {note}")

    if not cap["can_use_vuln"]:
        lines += [
            "",
            "CVE MATCHING ALTERNATIVES (use these instead of vuln: / has_vuln:):",
            "  Goal: find Log4Shell exposure",
            "    BAD:   vuln:CVE-2021-44228",
            "    GOOD:  product:\"Apache Log4j\" port:8080,8443,4848",
            "  Goal: find ProxyLogon exposure",
            "    BAD:   vuln:CVE-2021-26855",
            "    GOOD:  product:\"Microsoft Exchange\" port:443,80",
            "  Goal: find any vulnerable hosts",
            "    BAD:   has_vuln:true",
            "    GOOD:  Focus on high-risk products + dangerous ports instead.",
            "           e.g. product:\"Fortinet\" port:443  or  product:\"Citrix\" port:443,8443",
        ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Master system identity — who the AI is across ALL calls
# ---------------------------------------------------------------------------
SYSTEM_IDENTITY = """You are SENTINEL, an expert Shodan intelligence analyst embedded in ShodanSnipe.

Your analytical background:
  - 10+ years of attack surface management and threat intelligence
  - Deep knowledge of Shodan's data model: what it indexes, how banner grabbing works,
    what each filter actually matches at the API level
  - Intimate familiarity with how threat actors expose infrastructure, how misconfigurations
    appear in Shodan data, and how to pivot from one indicator to related infrastructure
  - You think in layers: broad exposure → specific product risk → CVE correlation →
    misconfiguration → pivot to related infrastructure

Your operational constraints:
  - You are a DEFENDER's tool — you propose, the human approves, nothing auto-executes
  - All queries must work syntactically at the Shodan API level
  - You respect the analyst's API plan tier and never suggest filters that will 403
  - You are SPECIFIC: cite exact port numbers, product strings, CVE IDs, ASNs, cert patterns
  - You are LAYERED: every response considers what to look at NEXT, not just the immediate answer
  - You EXPLAIN your reasoning so the analyst understands what the query will surface and why"""


# ---------------------------------------------------------------------------
# Analyst personas — injected into triage calls
# ---------------------------------------------------------------------------
PERSONA_ASM = """
╔══════════════════════════════╗
║  PERSONA: ASM ASSESSOR       ║
╚══════════════════════════════╝
You are evaluating internet-exposed assets as a Senior Attack Surface Management Assessor.

Your analytical lens:
  • Exposure BREADTH — how much is visible from the internet that shouldn't be?
  • Misconfiguration PATTERNS — expired certs, default titles, open admin panels,
    debug endpoints, directory listings, version disclosure
  • Shadow IT — assets that look forgotten, unmanaged, or inconsistent with the org's posture
  • Software risk — outdated versions, EOL products, known-bad product/port combos
  • Certificate hygiene — self-signed, expired, wildcard misuse, weak issuers
  • Quick wins — findings that are easy to fix but high impact

Think like a red teamer mapping the perimeter, reporting to a CISO.
Your output should read like a professional penetration test finding report.
Be specific: name IPs, ports, products, CVEs. Prioritise by exploitability × impact."""


PERSONA_TI = """
╔══════════════════════════════╗
║  PERSONA: THREAT INTEL       ║
╚══════════════════════════════╝
You are evaluating infrastructure as a Senior Threat Intelligence Analyst.

Your analytical lens:
  • C2 INFRASTRUCTURE — Cobalt Strike, Sliver, Havoc, Mythic, Brute Ratel, Metasploit
    fingerprints: unusual port combos, known JARM hashes, default cert CNs, specific HTTP responses
  • MALWARE FAMILIES — Mirai, QakBot, TrickBot, Emotet staging infra patterns
  • ACTOR ATTRIBUTION — ASN clustering, geographic patterns, cert reuse, shared hosting
  • PIVOT INDICATORS — what shared properties (ASN, cert subject, HTTP title, favicon hash)
    link this infrastructure to other known-bad hosts?
  • MITRE ATT&CK — map observable infrastructure to specific techniques (T-numbers)
  • IOC QUALITY — distinguish high-confidence IOCs from circumstantial indicators

Think like a CTI analyst building an intelligence product.
Be specific: cite exact IPs, ports, hashes, cert values, JARM fingerprints.
Reference ATT&CK technique IDs. Flag attribution confidence levels."""


def _persona_primer(persona: str) -> str:
    return PERSONA_TI if persona == "ti" else PERSONA_ASM


# ---------------------------------------------------------------------------
# Shodan query validator — hard syntax check before anything reaches the UI
# ---------------------------------------------------------------------------
BOOLEAN_PATTERN = re.compile(r'\b(AND|OR|NOT)\b', re.IGNORECASE)
WILDCARD_PATTERN = re.compile(r'[\*\?]')
GROUP_PATTERN    = re.compile(r'[\(\)]')


def validate_shodan_query(query: str) -> tuple[bool, str]:
    """Returns (is_valid, error_message)."""
    if not query or not query.strip():
        return False, "Empty query"
    m = BOOLEAN_PATTERN.search(query)
    if m:
        op = m.group(0).upper()
        return False, (
            f"Query contains '{op}' — Shodan does not support boolean operators. "
            f"Use separate queries instead of OR, and '-filter:value' instead of NOT."
        )
    if WILDCARD_PATTERN.search(query):
        return False, "Query contains wildcards (* or ?) — Shodan does not support wildcard searches."
    stripped = re.sub(r'"[^"]*"', '', query)
    if GROUP_PATTERN.search(stripped):
        return False, "Query contains parentheses — Shodan does not support grouped expressions."
    return True, ""


def sanitize_queries(queries: list[dict]) -> list[dict]:
    out = []
    for item in queries:
        q = item.get("query", "").strip()
        valid, err = validate_shodan_query(q)
        if not valid:
            item = dict(item)
            item["query_warning"] = err
            item["query_invalid"] = True
            logger.warning("AI generated invalid Shodan query: %r — %s", q, err)
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# Result trimming for LLM context windows
# ---------------------------------------------------------------------------
def trim_result_for_llm(r: dict, banner_cap: int = 500) -> dict:
    out = {
        "ip":        r.get("ip_str"),
        "ports":     r.get("ports", [])[:30],
        "product":   r.get("product"),
        "os":        r.get("os"),
        "org":       r.get("org"),
        "asn":       r.get("asn"),
        "country":   r.get("country"),
        "city":      r.get("city"),
        "hostnames": r.get("hostnames", [])[:5],
        "tags":      r.get("tags", []),
        "cves":      r.get("cves", []),
        "risk":      r.get("risk_level"),
        "in_scope":  r.get("in_scope", True),
    }
    if "data" in r:
        out["banner_preview"] = str(r["data"])[:banner_cap]
    if r.get("http_title") and r["http_title"] != "N/A":
        out["http_title"] = str(r["http_title"])[:200]
    if r.get("ssl_subject") and r["ssl_subject"] != "N/A":
        out["ssl_subject"] = str(r["ssl_subject"])[:200]
    return out


# ---------------------------------------------------------------------------
# Provider calls
# ---------------------------------------------------------------------------
async def _call_ollama(prompt: str, model: str, endpoint: str) -> str:
    url = f"{endpoint.rstrip('/')}/api/generate"
    async with aiohttp.ClientSession() as s:
        async with s.post(
            url,
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=aiohttp.ClientTimeout(total=120),
        ) as r:
            r.raise_for_status()
            data = await r.json()
            return data.get("response", "").strip()


async def _call_anthropic(prompt: str, model: str, api_key: str) -> str:
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {
        "model": model,
        "max_tokens": 2048,
        "messages": [{"role": "user", "content": prompt}],
    }
    async with aiohttp.ClientSession() as s:
        async with s.post(
            url, headers=headers, json=body,
            timeout=aiohttp.ClientTimeout(total=120),
        ) as r:
            r.raise_for_status()
            data = await r.json()
            return data["content"][0]["text"].strip()


async def _call_openai(prompt: str, model: str, api_key: str) -> str:
    url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 2048,
    }
    async with aiohttp.ClientSession() as s:
        async with s.post(
            url, headers=headers, json=body,
            timeout=aiohttp.ClientTimeout(total=120),
        ) as r:
            r.raise_for_status()
            data = await r.json()
            return data["choices"][0]["message"]["content"].strip()


async def complete(prompt: str, provider_override: str | None = None) -> str:
    s = get_settings()
    provider = provider_override or s["provider"]
    model    = s["model"]
    if provider == "ollama":
        return await _call_ollama(prompt, model, s["endpoint"])
    if provider == "anthropic":
        key = db.get_config("anthropic_key")
        if not key:
            raise ValueError("Anthropic key not configured. Set it in AI Config.")
        return await _call_anthropic(prompt, model, key)
    if provider == "openai":
        key = db.get_config("openai_key")
        if not key:
            raise ValueError("OpenAI key not configured. Set it in AI Config.")
        return await _call_openai(prompt, model, key)
    raise ValueError(f"Unknown provider: {provider}")


def _extract_json_object(text: str) -> dict:
    text = re.sub(r"```(?:json)?", "", text).strip()
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return {}


def _extract_json_array(text: str) -> list:
    text = re.sub(r"```(?:json)?", "", text).strip()
    m = re.search(r"\[\s*\{.*?\}\s*\]", text, re.DOTALL)
    if not m:
        return []
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return []


# ---------------------------------------------------------------------------
# AI Agent Builder — goal → query queue
# ---------------------------------------------------------------------------
async def goal_to_query(
    goal: str,
    provider: str | None = None,
    tier: str = "free",
    num_queries: int = 6,
    analyst_guidance: str = "",
) -> dict:
    """
    Translate a natural-language analyst goal into Shodan queries.

    Key behaviours:
      - Respects num_queries exactly — generates that many, no fewer.
      - Uses the FULL Shodan field catalogue: filters, bare keywords, banner
        content, favicon hashes, SSL patterns, HTTP components, etc.
      - If the goal is unclear, returns needs_clarification=True with a
        specific question rather than guessing.
      - Accepts analyst_guidance (persistent preferences) injected into prompt.
      - Returns: {query, rationale, alternatives[], or_note, pivot_chain,
                  tier_note, needs_clarification?, clarification_question?}
    """
    tier_block = _tier_block(tier)
    cap = TIER_CAPABILITIES.get(tier, TIER_CAPABILITIES["free"])

    guidance_block = ""
    if analyst_guidance and analyst_guidance.strip():
        guidance_block = f"""
╔══════════════════════════════════════════════════════════════════╗
║  ANALYST GUIDANCE (stored preferences — always follow these)    ║
╚══════════════════════════════════════════════════════════════════╝
{analyst_guidance.strip()}

Apply this guidance to every query you generate. It reflects the analyst's
environment, methodology, and preferences built up over time.
"""

    prompt = f"""{SYSTEM_IDENTITY}

{tier_block}

{SHODAN_SYNTAX_RULES}

{guidance_block}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ANALYST GOAL: "{goal}"
QUERIES REQUESTED: {num_queries}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

╔══════════════════════════════════════════════════════════════════╗
║  CRITICAL: YOU MUST PRODUCE EXACTLY {num_queries} QUERIES        ║
║  The analyst explicitly asked for {num_queries}. Producing fewer  ║
║  is a failure. Generate the primary query + {num_queries-1}      ║
║  alternatives = {num_queries} total. More is fine; fewer is not.  ║
╚══════════════════════════════════════════════════════════════════╝

FULL SHODAN FIELD CATALOGUE — use ALL that are relevant, not just port/product:

NETWORK & IDENTITY:
  org:"Name"           isp:"Name"            asn:AS12345
  net:1.2.3.0/24       ip:1.2.3.4            hostname:example.com
  domain:example.com   city:"Dallas"         country:US

SERVICE & SOFTWARE:
  port:443             port:22,80,443        product:"nginx"
  version:"2.4.51"     os:"Windows Server"   server:"Apache"
  http.component:"WordPress"                 http.component:"jQuery"

HTTP CONTENT (banner-level, very powerful):
  http.title:"Admin Panel"                   http.title:"Login"
  http.html:"phpMyAdmin"                     http.html:"<title>Kibana"
  http.html:"X-Powered-By: PHP"              http.html:"wp-login"
  http.favicon.hash:-1616143106              http.favicon.hash:999357577

SSL/TLS CERTIFICATES:
  ssl.cert.subject.cn:example.com            ssl.cert.expired:true
  ssl.cert.issuer.cn:"Let's Encrypt"         ssl:"Acme Corp"
  ssl.cert.subject.cn:"*.acme.com"

BARE KEYWORD SEARCH (no filter prefix — searches ALL indexed text):
  "default password"                         "admin:admin"
  "Authorization Required" port:8080         "MongoDB" port:27017
  "VNC Desktop" port:5900                    "Elasticsearch" port:9200
  These search across ALL banner text — extremely powerful for
  finding services by response content, error messages, or page text.

PROTOCOL-SPECIFIC:
  ssh.hassh:abc123                           ftp.anonymous_login:true
  http.html:"Index of /"                     http.html:"Directory listing"

SECURITY (plan-dependent):
{"  vuln:CVE-2021-44228    has_vuln:true    has_screenshot:true" if cap["can_use_vuln"] else "  # vuln:/has_vuln:/has_screenshot: BLOCKED on this plan — use product+port+version instead"}

COMBINING (space = AND, minus = NOT):
  "Elasticsearch" port:9200 -country:US
  org:"Acme" http.title:"Admin" -port:443
  product:"Cisco" "default password" port:23,80

QUERY CREATIVITY RULES:
  1. Mix filter-based and keyword-based approaches — do both, not just one.
  2. Think about WHAT SHODAN ACTUALLY CAPTURES: HTTP banners, SSL certs,
     service responses, SSH fingerprints, FTP banners, custom headers.
  3. A service may not match product:"X" but WILL match http.html:"X".
  4. Default credentials, error messages, version strings IN banner text
     are findable with bare keyword search even when product: misses them.
  5. Favicon hashes uniquely fingerprint web apps even when titles change.
  6. Same service may run on many ports — don't assume only the default port.
  7. ISP and ASN patterns reveal cloud provider / hosting context.

WORK THROUGH THESE STEPS:

STEP 1 — AMBIGUITY CHECK
  Is the goal clear enough to generate confident queries?
  Ambiguous: "find exposed servers" — too vague, ask what kind
  Ambiguous: "check our infrastructure" — ask for org name or CIDR
  Clear: "find exposed Confluence servers in our org Acme Corp" — proceed
  
  IF UNCLEAR: return needs_clarification=true with ONE specific question.
  DO NOT guess at vague goals — ask instead.

STEP 2 — INTENT DECOMPOSITION
  a) Target: org / ASN / CIDR / product family / protocol / keyword
  b) Risk signal: open port, vulnerable version, misconfiguration, default creds, C2
  c) Urgency: CVE, TTP, compliance, shadow IT, data exposure

STEP 3 — FULL SURFACE ENUMERATION
  For the target technology, enumerate EVERY Shodan-observable angle:
  • product: strings (exact Shodan product name, may differ from common name)
  • http.title: patterns (login pages, admin panels, error pages)
  • http.html: content (page text, headers, version strings in responses)
  • http.favicon.hash: (if app has a recognisable favicon)
  • ssl.cert.subject.cn: (cert CN patterns for this service)
  • version: strings (for known-vulnerable versions)
  • Bare keywords: what text appears in the raw banner/response?
  • Port combinations: what non-standard ports does this run on?
  • http.component: (detected frameworks/libraries)

STEP 4 — GENERATE {num_queries} QUERIES
  Produce a diverse set covering different angles:
  • 1-2 broad queries (find the product family with org/net scope if possible)
  • 1-2 keyword/content queries (http.html:, bare keywords, http.title:)
  • 1-2 cert/fingerprint queries (ssl., http.favicon.hash:)
  • 1-2 version/misconfiguration queries (version:, ssl.cert.expired:, default creds)
  • 1-2 pivot/infrastructure queries (asn:, isp:, net:)
  Make every query meaningfully different — no near-duplicates.

STEP 5 — TIER CONSTRAINT CHECK
  {"BLOCKED: vuln:, has_vuln:, has_screenshot: — replace with product+port+version." if not cap["can_use_vuln"] else "All filters available."}

STEP 6 — PIVOT CHAIN
  After running these queries, what should the analyst pivot on?

Produce ONLY valid JSON, no prose, no markdown fences.

IF GOAL IS UNCLEAR (needs_clarification):
{{
  "needs_clarification": true,
  "clarification_question": "One specific question that will let me generate precise queries",
  "query": "",
  "rationale": "",
  "alternatives": [],
  "or_note": "",
  "pivot_chain": "",
  "tier_note": ""
}}

IF GOAL IS CLEAR (normal response with EXACTLY {num_queries} total queries):
{{
  "needs_clarification": false,
  "query": "best primary Shodan query — valid syntax only",
  "rationale": "3-4 sentences: what this finds, why it is highest-signal, what to look for in results",
  "alternatives": [
    {{
      "query": "query 2 — keyword/content angle",
      "why": "what different signal this surfaces vs primary"
    }},
    {{
      "query": "query 3 — cert/fingerprint angle",
      "why": "..."
    }},
    {{
      "query": "query 4 — version/misconfiguration angle",
      "why": "..."
    }},
    {{
      "query": "query 5 — pivot/infrastructure angle",
      "why": "..."
    }}
    /* continue until you have {num_queries} total (primary + alternatives) */
  ],
  "or_note": "if OR logic was needed, explain the split here",
  "pivot_chain": "2-3 sentences: recommended investigation sequence after running these queries",
  "tier_note": "{'' if cap['can_use_vuln'] else 'Plan restriction applied: replaced vuln:/has_vuln: with product+port+version alternatives.'}"
}}"""

    text = await complete(prompt, provider)
    result = _extract_json_object(text)

    if not result:
        # Raw text response — treat as a clarification question from the AI
        stripped = text.strip()
        if stripped and len(stripped) < 400 and "?" in stripped:
            return {
                "needs_clarification": True,
                "clarification_question": stripped,
                "query": "", "rationale": "", "alternatives": [],
                "or_note": "", "pivot_chain": "", "tier_note": "",
            }
        return {
            "query": "", "rationale": stripped[:500],
            "alternatives": [], "or_note": "", "pivot_chain": "", "tier_note": "",
            "needs_clarification": False,
        }

    # If the AI decided to ask for clarification, return as-is
    if result.get("needs_clarification"):
        return result

    # Hard-validate primary
    primary = result.get("query", "").strip()
    valid, err = validate_shodan_query(primary)
    if not valid:
        logger.warning("Primary query failed validation: %r — %s", primary, err)
        result["query_warning"] = err
        result["query_invalid"] = True

    # Hard-validate all alternatives
    result["alternatives"] = sanitize_queries(result.get("alternatives", []))

    return result


# ---------------------------------------------------------------------------
# ASK mode — free-form question about results, syntax, or strategy
# ---------------------------------------------------------------------------
async def ask_question(
    question: str,
    current_query: str = "",
    tier: str = "free",
    analyst_guidance: str = "",
    results_summary: str = "",
    provider: str | None = None,
) -> dict:
    """Answer a free-form analyst question. Returns {answer, suggested_queries[]}."""
    tier_block = _tier_block(tier)
    guidance_block = f"\nANALYST GUIDANCE:\n{analyst_guidance}\n" if analyst_guidance else ""

    prompt = f"""{SYSTEM_IDENTITY}

{tier_block}

{SHODAN_SYNTAX_RULES}
{guidance_block}
Current query context: {repr(current_query) if current_query else '(none)'}
Current results: {results_summary}

ANALYST QUESTION: "{question}"

Answer directly and specifically. You may:
  - Explain Shodan syntax, filters, or search strategies
  - Analyse the current query or results context
  - Suggest next investigative steps
  - Clarify how specific Shodan fields work
  - Recommend query modifications

If your answer naturally leads to 1-3 specific Shodan queries, include them in
suggested_queries. Otherwise leave it empty.

Return ONLY valid JSON:
{{
  "answer": "your answer in plain prose — be specific, cite exact filter names and examples",
  "suggested_queries": [
    {{"query": "shodan query if relevant", "rationale": "why"}}
  ]
}}"""

    text = await complete(prompt, provider)
    result = _extract_json_object(text)
    if not result:
        return {"answer": text.strip()[:1000], "suggested_queries": []}
    result["suggested_queries"] = sanitize_queries(result.get("suggested_queries", []))
    return result


# ---------------------------------------------------------------------------
# SELECTION mode — build queries from analyst-selected filters/templates
# ---------------------------------------------------------------------------
async def selection_to_queries(
    instruction: str,
    selected_filters: list[str],
    selected_templates: list[str],
    tier: str = "free",
    num_queries: int = 6,
    analyst_guidance: str = "",
    provider: str | None = None,
) -> dict:
    """Build queries constrained to the analyst's selected filters and templates."""
    tier_block = _tier_block(tier)
    guidance_block = f"\nANALYST GUIDANCE:\n{analyst_guidance}\n" if analyst_guidance else ""

    sel_block = ""
    if selected_filters:
        sel_block += f"\nSELECTED FILTERS (must use these as building blocks):\n"
        for f in selected_filters:
            sel_block += f"  {f}\n"
    if selected_templates:
        sel_block += f"\nSELECTED TEMPLATES (incorporate these patterns):\n"
        for t in selected_templates:
            sel_block += f"  {t}\n"

    prompt = f"""{SYSTEM_IDENTITY}

{tier_block}

{SHODAN_SYNTAX_RULES}
{guidance_block}
{sel_block}

ANALYST INSTRUCTION: "{instruction}"

Generate {num_queries} Shodan queries that:
  1. USE the selected filters/templates as the foundation
  2. Combine them creatively with other relevant fields
  3. Cover different angles (broad, narrow, pivot, keyword, cert-based)
  4. Follow all Shodan syntax rules

Return ONLY valid JSON:
{{
  "rationale": "2-3 sentences: how you combined the selection and what each angle targets",
  "queries": [
    {{"query": "shodan query", "why": "what angle this covers"}},
    ...
  ]
}}"""

    text = await complete(prompt, provider)
    result = _extract_json_object(text)
    if not result:
        return {"rationale": "", "queries": []}
    result["queries"] = sanitize_queries(result.get("queries", []))
    return result


# ---------------------------------------------------------------------------
# Triage: summarize
# ---------------------------------------------------------------------------
async def summarize(
    query: str,
    results: list[dict],
    provider: str | None = None,
    persona: str = "asm",
) -> str:
    trimmed = [trim_result_for_llm(r) for r in results[:50]]
    primer  = _persona_primer(persona)

    if persona == "ti":
        task = """Analyze these Shodan results through your Threat Intelligence lens.

REQUIRED SECTIONS:
1. THREAT ASSESSMENT (3-4 sentences)
   What threat actor TTPs or malware families do these results suggest?
   What is the confidence level and what evidence supports it?

2. KEY INDICATORS
   List specific IOCs, fingerprints, or patterns worth tracking:
   • IP addresses with specific unusual characteristics
   • Port combinations that fingerprint specific malware/C2 frameworks
   • Certificate patterns (CN, issuer, serial reuse)
   • HTTP response patterns (title, headers, favicon hash)
   • JARM/JA3 fingerprints if inferable from product strings

3. CAMPAIGN INFRASTRUCTURE ANALYSIS
   What infrastructure patterns are visible?
   ASN clustering? Geographic concentration? Cert reuse? Shared hosting provider?
   Do any of these match known actor infrastructure profiles?

4. MITRE ATT&CK MAPPING
   Map observable infrastructure to specific techniques:
   • C2 channels (T1071, T1090, T1572...)
   • Infra staging (T1583, T1584...)
   • Obfuscation patterns if present

5. PIVOT RECOMMENDATIONS (prioritised)
   What specific Shodan queries should the analyst run next?
   Give exact queries, not general advice.

6. INTELLIGENCE GAPS
   What is missing from this data? What additional sources would close the gap?

Cite every IP, port, CVE, product string, and cert value by exact value."""
    else:
        task = """Analyze these Shodan results as an Attack Surface Management Assessor.

REQUIRED SECTIONS:
1. EXPOSURE SUMMARY (3-4 sentences)
   What is the overall external attack surface picture?
   What is the single most alarming finding and why?
   What does this say about the organisation's security posture?

2. CRITICAL FINDINGS (top 5, ranked by risk)
   For each finding:
   • Exact host (IP or hostname)
   • What is exposed and on which port
   • Why it is critical (CVE, known exploit, compliance gap, misconfiguration)
   • Recommended immediate action

3. SYSTEMIC PATTERN FINDINGS
   Are there patterns that indicate a systemic problem?
   • Same misconfiguration across multiple hosts?
   • Expired certs? Self-signed certs at scale?
   • Consistent product versions suggesting a missed patch cycle?
   • Open admin interfaces? Debug endpoints?

4. SHADOW IT / FORGOTTEN ASSETS
   Any hosts that look unmanaged, inconsistent with org posture,
   or that don't fit the expected infrastructure profile?

5. QUICK WINS (fix within 24 hours)
   Specific, actionable items with the highest impact-to-effort ratio.

6. RISK SCORE
   Overall: Critical / High / Medium / Low
   Justify with specific data points from the results.

Cite every IP, port, product, CVE by exact value. Write for a CISO audience."""

    prompt = f"""{SYSTEM_IDENTITY}

{primer}

Query that produced these results: {query!r}
Total hosts in result set: {len(results)} (showing first {len(trimmed)} to AI)

RESULT DATA (JSON):
{json.dumps(trimmed, indent=2)}

{task}"""

    return await complete(prompt, provider)


# ---------------------------------------------------------------------------
# Triage: rank
# ---------------------------------------------------------------------------
async def rank(query: str, results: list[dict], provider: str | None = None) -> list[dict]:
    trimmed = [trim_result_for_llm(r) for r in results[:50]]
    prompt = f"""{SYSTEM_IDENTITY}

You are performing triage prioritisation for a defender.

Query: {query!r}
Hosts (JSON):
{json.dumps(trimmed, indent=2)}

Rank these hosts by defender triage priority. Consider:
  • Severity: exposed services that are directly exploitable
  • Specificity: known CVEs on the host vs generic exposure
  • Business impact: databases, admin panels, and authentication services rank higher
  • Ease of exploitation: internet-accessible, no auth visible, known weaponised CVEs
  • Unusual indicators: unexpected ports, expired certs, suspicious titles

Return ONLY a JSON array, no prose, no markdown:
[{{"ip": "1.2.3.4", "priority": 1, "reason": "specific reason citing exact ports/products/CVEs"}}, ...]
priority: 1 = highest urgency. Top 10 hosts maximum.
Reasons must be specific — cite actual values from the data, not generic descriptions."""

    text = await complete(prompt, provider)
    return _extract_json_array(text)


# ---------------------------------------------------------------------------
# Triage: explain single host
# ---------------------------------------------------------------------------
async def explain_host(host: dict, provider: str | None = None) -> str:
    trimmed = trim_result_for_llm(host)
    prompt = f"""{SYSTEM_IDENTITY}

A defender has asked for a detailed explanation of this specific host.

Host data:
{json.dumps(trimmed, indent=2)}

Provide a structured explanation covering:
1. IDENTITY — What organisation owns this? What is the likely business function of this host?
2. EXPOSURE — What exactly is exposed? Be specific about each open port and service.
3. RISK ASSESSMENT — What specifically concerns a defender?
   Cite exact CVEs, product versions, misconfigurations, or suspicious indicators.
4. EXPLOITATION CONTEXT — What attack paths are realistic from the internet?
   (Keep this at the level of "this service version has known RCE vulnerabilities" —
   do not provide exploitation steps.)
5. RECOMMENDED ACTIONS — What should the defender do about this host specifically?
6. PIVOT INDICATORS — What properties of this host (cert CN, ASN, product, port combo)
   could be used to find related infrastructure?

Be concrete and specific. Cite every port, product string, CVE, and cert value by exact value.
8-12 sentences total. Write for a security analyst, not an executive."""

    return await complete(prompt, provider)


# ---------------------------------------------------------------------------
# Triage: suggest follow-up queries
# ---------------------------------------------------------------------------
async def suggest_queries(
    query: str,
    results: list[dict],
    provider: str | None = None,
    tier: str = "free",
) -> list[dict]:
    trimmed = [trim_result_for_llm(r) for r in results[:30]]
    tier_block = _tier_block(tier)

    prompt = f"""{SYSTEM_IDENTITY}

{tier_block}

{SHODAN_SYNTAX_RULES}

The analyst just ran this Shodan query: {query!r}
Number of results: {len(results)} (showing first {len(trimmed)} to you)

RESULT DATA (JSON):
{json.dumps(trimmed, indent=2)}

Based on what you see in these results, suggest 4-6 follow-up Shodan queries.

For each suggestion, think about:
  • NARROWING — take a finding from the results and drill deeper
    e.g. if you see expired certs, query for that specific cert CN across all Shodan
  • PIVOTING — find related infrastructure by shared property
    e.g. same ASN, same SSL cert issuer, same HTTP title pattern, same favicon hash
  • ESCALATING — check a higher-severity aspect of the same target
    e.g. if you found nginx, check if there's an exposed admin panel or phpmyadmin
  • BROADENING — check adjacent attack surface
    e.g. if you found AWS hosts, also check Azure/GCP for the same org

Each query must:
  • Use only filters allowed for this plan
  • Follow Shodan syntax rules (no OR/AND/NOT/wildcards)
  • Be meaningfully different from the original query
  • Produce actionable results the analyst can act on

Return ONLY a valid JSON array, no prose, no markdown fences:
[
  {{
    "query": "exact Shodan query string",
    "rationale": "2 sentences: what this finds and why it follows from the current results"
  }}
]"""

    text = await complete(prompt, provider)
    raw = _extract_json_array(text)
    return sanitize_queries(raw)


# ---------------------------------------------------------------------------
# CVE Intel — advisory text → scoped Shodan detection queries
# ---------------------------------------------------------------------------
async def cve_intel_to_queries(
    advisory: str,
    scope: dict | None = None,
    scope_queries: bool = True,
    tier: str = "free",
    provider: str | None = None,
) -> dict:
    """
    Parse a CVE advisory / NVD entry / news article / vendor bulletin and
    generate Shodan queries that detect affected infrastructure.

    If scope is provided (org names, CIDRs, ASNs, domains), queries are
    narrowed to the analyst's environment. Returns:
      {cve_ids, severity, affected_products, summary, queries: [{query,
       rationale, cve_ids, severity, query_invalid?, query_warning?}]}
    """
    tier_block = _tier_block(tier)
    cap = TIER_CAPABILITIES.get(tier, TIER_CAPABILITIES["free"])

    # Build scope context block
    scope_block = ""
    if scope and scope_queries and not scope.get("is_empty"):
        scope_parts = []
        if scope.get("orgs"):
            scope_parts.append("Organizations: " + ", ".join(f'"{o}"' for o in scope["orgs"]))
        if scope.get("cidrs"):
            scope_parts.append("CIDRs: " + ", ".join(scope["cidrs"][:6]))
        if scope.get("domains"):
            scope_parts.append("Domains: " + ", ".join(scope["domains"][:6]))
        if scope.get("asns"):
            scope_parts.append("ASNs: " + ", ".join(scope["asns"]))

        if scope_parts:
            scope_block = f"""
╔══════════════════════════════════════════════════════════════════╗
║  TARGET SCOPE — narrow ALL queries to this environment          ║
╚══════════════════════════════════════════════════════════════════╝
{chr(10).join("  " + p for p in scope_parts)}

SCOPING RULES:
  • Every query MUST include at least one of: org:, net:, asn:, hostname:, domain:
    to restrict results to the target environment listed above.
  • For org names, use Shodan's org: filter with the exact string.
    Example: org:"Acme Corp" product:"Fortinet" port:443
  • For CIDRs, use net: filter. Example: net:203.0.113.0/24 port:8443
  • For ASNs, use asn: filter. Example: asn:AS64512 product:"Citrix"
  • For domains, use hostname: filter. Example: hostname:acme.example port:443
  • If multiple scope entries exist, generate one query per scope anchor
    (one per org name, one per ASN etc.) — they become separate alternatives.
"""
    else:
        scope_block = """
╔══════════════════════════════════════════════════════════════════╗
║  NO SCOPE SET — generate broad internet-wide detection queries  ║
╚══════════════════════════════════════════════════════════════════╝
  Queries will not be scoped to a specific organisation.
  The analyst can manually add org:, net:, or asn: filters later.
"""

    prompt = f"""{SYSTEM_IDENTITY}

{tier_block}

{SHODAN_SYNTAX_RULES}

{scope_block}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ADVISORY / INTELLIGENCE INPUT (analyse this carefully):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{advisory[:6000]}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TASK: Generate Shodan detection queries for this vulnerability.

Work through these steps:

STEP 1 — VULNERABILITY EXTRACTION
  Extract from the advisory:
  a) CVE identifier(s)
  b) CVSS severity (Critical/High/Medium/Low)
  c) Affected products and versions (exact product name strings Shodan indexes)
  d) Affected ports / protocols / services
  e) Observable Shodan-level indicators: banner strings, HTTP titles, SSL cert
     patterns, HTTP response content, version strings in banners

STEP 2 — SHODAN OBSERVABILITY ANALYSIS
  For each affected product, ask:
  • What does Shodan capture in its banner/response for this service?
  • What version strings appear in Shodan data for vulnerable versions?
  • What HTTP titles or page content identify this service?
  • What port + product combination fingerprints this service?
  • Is there a known favicon hash or HTTP header pattern?

STEP 3 — QUERY GENERATION (generate 4-8 queries)
  Build a layered set from broad → precise:

  BROAD (find the product family, scoped to org):
    product:"Affected Product" org:"Target Org"

  VERSION-SPECIFIC (find vulnerable versions if banner-visible):
    product:"Affected Product" version:"X.Y.Z" org:"Target Org"

  PORT-SPECIFIC (known service port):
    port:8443 product:"Affected Product" org:"Target Org"

  TITLE/CONTENT-BASED (HTTP title or page content):
    http.title:"Login Page Title" org:"Target Org"

  CERT-BASED (if SSL cert CN reveals product/service):
    ssl.cert.subject.cn:"service.example.com" org:"Target Org"

  VULN-DIRECT (only if vuln: filter is available for this plan):
    {"vuln:" + "CVE-ID" + " org:..." if cap["can_use_vuln"] else "# vuln: filter NOT available for this plan — use product+port approach above"}

STEP 4 — SCOPE BINDING
  Apply the scope constraints from above to EVERY query.
  If no scope is set, generate queries without scope anchors.

{"IMPORTANT: DO NOT use vuln: or has_vuln: — your plan does not support them. Use product: + port: + version: combinations instead." if not cap["can_use_vuln"] else "vuln: filter IS available for this plan — use it where it adds precision."}

Return ONLY valid JSON, no prose, no markdown fences:
{{
  "cve_ids": ["CVE-2024-XXXX"],
  "severity": "Critical|High|Medium|Low",
  "affected_products": ["exact product string 1", "exact product string 2"],
  "summary": "3-4 sentence executive summary: what is vulnerable, what the exposure risk is, what an attacker can do, and what defenders should prioritise immediately",
  "queries": [
    {{
      "query": "exact Shodan query — valid syntax, tier-appropriate, scoped if scope provided",
      "rationale": "2 sentences: what this finds specifically, why it catches this vulnerability",
      "cve_ids": ["CVE-2024-XXXX"],
      "severity": "Critical|High|Medium|Low",
      "detection_type": "broad|version-specific|port-specific|title-based|cert-based|vuln-direct"
    }}
  ],
  "tier_note": "{'' if cap['can_use_vuln'] else 'Plan restriction: vuln: filter unavailable — using product+port+version alternatives instead.'}"
}}"""

    text = await complete(prompt, provider)
    result = _extract_json_object(text)

    if not result:
        return {
            "cve_ids": [],
            "severity": "Unknown",
            "affected_products": [],
            "summary": text[:500] if text else "Could not parse AI response.",
            "queries": [],
            "tier_note": "",
        }

    # Hard-validate every generated query
    validated = []
    for q in result.get("queries", []):
        query_str = q.get("query", "").strip()
        valid, err = validate_shodan_query(query_str)
        if not valid:
            q["query_invalid"] = True
            q["query_warning"] = err
            logger.warning("CVE Intel: invalid query generated: %r — %s", query_str, err)
        validated.append(q)
    result["queries"] = validated

    return result


# ---------------------------------------------------------------------------
# Campaign clustering (AI-assisted threat feed analysis)
# ---------------------------------------------------------------------------
async def cluster_analysis(queries: list[dict], provider: str | None = None) -> dict:
    """
    Given a set of threat feed queries, identify clusters representing distinct
    campaigns, malware families, or actor infrastructure patterns.
    """
    q_list = []
    for q in queries[:100]:
        q_list.append({
            "id":       q["id"],
            "query":    q["query"],
            "label":    q["label"],
            "source":   q["source"],
            "category": q["category"],
            "actor":    q.get("actor", ""),
        })

    prompt = f"""{SYSTEM_IDENTITY}

{PERSONA_TI}

You are performing CAMPAIGN CLUSTERING on threat intelligence queries from:
C2-Tracker, BushidoUK OSINT Operators, C2Hunter, AlienVault OTX, STIX/TAXII feeds.

TASK: Group these {len(q_list)} queries into clusters representing distinct:
  • Threat campaigns (same actor, same operation)
  • Malware families (same C2 framework, same tooling)
  • Infrastructure patterns (same hosting provider, ASN, cert pattern)

For each cluster, provide:
  1. A precise cluster name (e.g. "Cobalt Strike Malleable C2 — East Asia Operations")
  2. Threat actor attribution (specific group name or "Unknown")
  3. MITRE ATT&CK techniques evidenced (T-numbers with names)
  4. The specific infrastructure pattern that ties these queries together
  5. Confidence level (High/Medium/Low) with explicit reasoning
  6. 2-3 NEW Shodan pivot queries to find MORE infrastructure in this cluster
     (MUST follow Shodan syntax — no OR/AND/NOT/wildcards)
  7. Which query IDs belong to this cluster

Input queries ({len(q_list)} total):
{json.dumps(q_list, indent=2)}

Return ONLY valid JSON:
{{
  "clusters": [
    {{
      "name": "precise cluster name",
      "actor": "threat actor name or Unknown",
      "mitre_ttps": ["T1071.001 — Application Layer Protocol: Web Protocols", "T1090 — Proxy"],
      "pattern_rationale": "specific pattern tying these together — cite exact values",
      "confidence": "High|Medium|Low",
      "confidence_reasoning": "why this confidence level — what evidence supports/undermines attribution",
      "ioc_summary": "3-4 sentence intelligence summary citing specific indicators",
      "query_ids": [1, 2, 3],
      "pivot_queries": [
        {{"query": "valid shodan query", "why": "what additional infrastructure this surfaces"}}
      ]
    }}
  ],
  "analyst_note": "Overall campaign landscape: 4-5 sentences on dominant threat actors, infrastructure patterns, and recommended immediate hunting priorities"
}}"""

    text = await complete(prompt, provider)
    result = _extract_json_object(text)
    if not result:
        return {
            "clusters": [],
            "analyst_note": text[:500],
            "error": "Could not parse AI response as JSON",
        }

    # Validate pivot queries in each cluster
    for cluster in result.get("clusters", []):
        pivots = cluster.get("pivot_queries", [])
        valid_pivots = []
        for p in pivots:
            q = p.get("query", "")
            ok, err = validate_shodan_query(q)
            if not ok:
                p["invalid"] = err
            valid_pivots.append(p)
        cluster["pivot_queries"] = valid_pivots

    return result
