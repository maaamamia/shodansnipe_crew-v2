"""
tools/shodan_query.py — Shodan query hygiene, scope matching, and protocol coverage.

Three jobs, one place:

  1. ESCAPING — build correctly-quoted Shodan queries so `org:Company, Inc`
     stops leaking out of scope. The fix is twofold:
       a) quote multi-word / punctuated values: org:"Company, Inc"
       b) post-filter results with a STRICT matcher, because Shodan's `org:`
          is a server-side token match that pulls in look-alikes
          (e.g. a bareword org name colliding with a foreign-language word or
           contraction — org:"Acme" can pull "Acme'Servizi" or "Acmena Srl"
           whose names merely start with the same letters).

  2. PROTOCOLS — PROTOCOL_QUERIES is a broad, de-duplicated detection catalog:
     SSH, FTP, SMTP, Telnet, LDAP, Oracle WebLogic + T3, the whole MQ family
     (ActiveMQ / RabbitMQ / IBM MQ / Kafka / MQTT), databases, DevOps, ICS.
     Nothing is artificially trimmed — pick the categories you want.

  3. VERSIONS — extract_versions() pulls product+version, the SSH banner version,
     the HTTP server banner, HTTP protocol (1.1 vs 2), and TLS versions out of a
     Shodan host record so they actually land in the report.

Pure-stdlib, no imports beyond re. Import the pieces you need:

    from shodan_query import quote_value, build_query, org_in_scope
    from shodan_query import PROTOCOL_QUERIES, protocol_queries_for, extract_versions
"""
from __future__ import annotations
import re

# ─────────────────────────────────────────────────────────────────────────────
# 1. ESCAPING / QUERY BUILDING
# ─────────────────────────────────────────────────────────────────────────────

# Shodan filters whose values are free text and therefore MUST be quoted when
# they contain a space, comma, or other token-splitting character.
_QUOTABLE_FILTERS = {
    "org", "product", "version", "isp", "ssl.cert.subject.o",
    "ssl.cert.subject.cn", "ssl.cert.issuer.cn", "http.title",
    "http.html", "http.server", "http.component", "hostname",
    "ssl.cert.subject.ou", "device", "os",
}


def quote_value(value: str) -> str:
    """
    Quote a single Shodan filter value so it is treated as ONE literal token.

    The bug being fixed: `org:Company, Inc` is parsed by Shodan as
    `org:Company` AND a stray bareword `Inc` (or, in a port list context, the
    comma is read as a list separator). Quoting makes the whole string literal:

        quote_value("Company, Inc")  -> '"Company, Inc"'
        quote_value("Acme")          -> 'Acme'          (no quotes needed)
        quote_value('A "B" C')       -> '"A B C"'        (inner quotes stripped)

    Shodan has no usable escape for an embedded double-quote, so we strip inner
    quotes rather than emit a query that silently truncates at the first one.
    """
    v = (value or "").strip()
    if not v:
        return '""'
    # Strip any embedded double quotes — Shodan can't escape them.
    v = v.replace('"', " ").strip()
    v = re.sub(r"\s+", " ", v)
    needs_quotes = any(c in v for c in ' ,()[]{}"\'/:&') or v != value.strip()
    return f'"{v}"' if needs_quotes else v


def build_filter(name: str, value: str, negate: bool = False) -> str:
    """Build one `filter:value` term, quoting the value when the filter needs it."""
    name = name.strip().rstrip(":")
    val = quote_value(value) if name in _QUOTABLE_FILTERS else str(value).strip()
    return f'{"-" if negate else ""}{name}:{val}'


# Aggregator / CDN / cloud orgs that share certs and IP space — never the target,
# always worth negating out of a broad search to cut false positives.
DEFAULT_CDN_EXCLUSIONS = [
    "Akamai Technologies", "Cloudflare", "Amazon CloudFront", "Fastly",
    "Incapsula", "Imperva", "Google LLC", "Microsoft Azure", "Amazon.com",
    "Amazon Technologies", "DigitalOcean", "OVH SAS", "Hetzner Online",
]


def build_query(org: str | None = None,
                ports: list[int] | None = None,
                hostname: str | None = None,
                net: str | None = None,
                asn: str | None = None,
                extra: list[str] | None = None,
                exclude_cdn: bool = True) -> str:
    """
    Assemble a single, correctly-escaped Shodan query (space = AND; no OR/AND/NOT).

        build_query(org="Company, Inc", ports=[443, 8443])
        -> 'org:"Company, Inc" port:443,8443 -org:"Akamai Technologies" ...'

    Prefer net:/asn:/cert anchors over a bare org: where you can — org: is
    substring-broad on Shodan's side and is the main false-positive source.
    """
    terms: list[str] = []
    if net:
        terms.append(build_filter("net", net))
    if asn:
        a = asn.strip().upper()
        terms.append(f"asn:{a if a.startswith('AS') else 'AS' + a}")
    if org:
        terms.append(build_filter("org", org))
    if hostname:
        # hostname: is already a suffix/substring match — never wildcard it.
        terms.append(f"hostname:{hostname.strip().lstrip('*.')}")
    if ports:
        terms.append("port:" + ",".join(str(int(p)) for p in ports))
    if extra:
        terms.extend(t for t in extra if t)
    if exclude_cdn:
        terms.extend(build_filter("org", c, negate=True) for c in DEFAULT_CDN_EXCLUSIONS)
    return " ".join(terms)


# ─────────────────────────────────────────────────────────────────────────────
# 1b. STRICT IN-SCOPE MATCHER  (the real false-positive killer)
# ─────────────────────────────────────────────────────────────────────────────

# Corporate suffixes dropped before comparison so "Acme" == "Acme Inc" == "Acme, Inc.".
_CORP_SUFFIXES = {
    "inc", "incorporated", "llc", "llp", "ltd", "limited", "corp", "corporation",
    "co", "company", "gmbh", "ag", "sa", "sas", "srl", "spa", "plc", "pty",
    "bv", "nv", "oy", "ab", "as", "kg", "kk", "pvt", "group", "holdings",
    "technologies", "technology", "systems", "solutions", "services",
}


def _normalize_org(name: str) -> list[str]:
    """
    Normalize an org string to a token list for comparison.

    Crucially, apostrophes are removed WITHOUT splitting, so a contraction like
    "Acme'Servizi" collapses to ONE token "acmeservizi" and can never leak a bare
    "acme" token that would false-match the target. Other punctuation splits to spaces.
    Corporate suffixes are dropped.
    """
    s = (name or "").lower().strip()
    s = s.replace("’", "'").replace("`", "'")
    s = s.replace("'", "")                 # join contractions: acme'x -> acmex
    s = re.sub(r"[^a-z0-9]+", " ", s)       # all other punctuation -> space
    toks = [t for t in s.split() if t and t not in _CORP_SUFFIXES]
    return toks


def org_in_scope(host_org: str, scope_orgs, strict: bool = False) -> tuple[bool, str]:
    """
    Decide whether a host's org field genuinely belongs to an in-scope org.

    Returns (in_scope, confidence) where confidence is one of:
        "exact"     — normalized token sets are identical
        "contains"  — scope tokens appear as a contiguous run in the host org
        "reject"    — no word-boundary match (kills the apostrophe / substring leak)

    strict=True accepts only "exact".

        org_in_scope("Acme Inc.",                 ["Acme"])  -> (True,  "exact")
        org_in_scope("Acme Technologies",         ["Acme"])  -> (True,  "contains")
        org_in_scope("Acme'Servizi Italiani",     ["Acme"])  -> (False, "reject")
        org_in_scope("Acmena Co",                 ["Acme"])  -> (False, "reject")
    """
    if isinstance(scope_orgs, str):
        scope_orgs = [scope_orgs]
    host_toks = _normalize_org(host_org)
    if not host_toks:
        return (False, "reject")

    best = "reject"
    for scope in scope_orgs:
        scope_toks = _normalize_org(scope)
        if not scope_toks:
            continue
        if host_toks == scope_toks:
            return (True, "exact")           # can't beat exact — return now
        # contiguous-run (word-boundary) containment
        n = len(scope_toks)
        for i in range(len(host_toks) - n + 1):
            if host_toks[i:i + n] == scope_toks:
                best = "contains"
                break
    if strict:
        return (best == "exact", best if best == "exact" else "reject")
    return (best != "reject", best)


# ─────────────────────────────────────────────────────────────────────────────
# 2. PROTOCOL DETECTION CATALOG  — broad, not trimmed
# ─────────────────────────────────────────────────────────────────────────────
# Each entry: (label, query_suffix, severity, note)
# query_suffix is everything AFTER the scope anchor; combine via protocol_queries_for().

PROTOCOL_QUERIES: dict[str, list[tuple[str, str, str, str]]] = {

    "Remote Access": [
        ("SSH",            "port:22",                 "Medium",   "capture OpenSSH/Dropbear banner version"),
        ("Telnet",         "port:23",                 "Critical", "cleartext — always critical if open"),
        ("RDP",            "port:3389",               "High",     "BlueKeep-era CVEs; capture OS banner"),
        ("VNC",            "port:5900,5901,5902",     "High",     "often unauthenticated"),
        ("WinRM",          "port:5985,5986",          "High",     "remote PowerShell"),
        ("rlogin/rsh",     "port:512,513,514",        "Critical", "legacy cleartext r-services"),
    ],

    "File Transfer / Sharing": [
        ("FTP",            "port:21",                 "High",     "capture banner; check anonymous login note"),
        ("FTPS",           "port:990",                "Medium",   "FTP over TLS"),
        ("TFTP",           "port:69",                 "High",     "no auth by design"),
        ("SMB",            "port:445",                "High",     "EternalBlue surface; never expose"),
        ("NFS",            "port:2049",               "High",     "exported shares"),
        ("rsync",          "port:873",                "Medium",   "module listing often exposed"),
    ],

    "Mail": [
        ("SMTP",           "port:25,465,587",         "Medium",   "open relay / version banner"),
        ("IMAP",           "port:143,993",            "Low",      "capture server banner"),
        ("POP3",           "port:110,995",            "Low",      "capture server banner"),
    ],

    "Directory / Auth": [
        ("LDAP",           "port:389,636",            "High",     "anonymous bind / directory dump"),
        ("Kerberos",       "port:88",                 "Medium",   "AS-REP roasting surface"),
        ("RADIUS",         "port:1812,1813",          "Medium",   "auth infrastructure exposure"),
        ("SNMP",           "port:161",                "High",     "public community strings leak inventory"),
    ],

    "Databases": [
        ("MySQL",          "port:3306",               "High",     "should never face internet"),
        ("PostgreSQL",     "port:5432",               "High",     "should never face internet"),
        ("MSSQL",          "port:1433",               "High",     "should never face internet"),
        ("Oracle DB",      "port:1521,1522",          "High",     "TNS listener; capture version"),
        ("MongoDB",        "port:27017",              "High",     "check for no-auth"),
        ("Redis",          "port:6379",               "High",     "check for no-auth"),
        ("Elasticsearch",  "port:9200,9300",          "High",     "check for no-auth"),
        ("CouchDB",        "port:5984",               "High",     "check for no-auth"),
        ("Cassandra",      "port:9042",               "Medium",   "CQL native transport"),
        ("Neo4j",          "port:7474,7687",          "Medium",   "browser / bolt"),
        ("Memcached",      "port:11211",              "High",     "amplification + data leak"),
    ],

    "App Servers & Message Queues": [
        ("Oracle WebLogic","port:7001,7002",          "Critical", "T3 protocol; many deserialization RCEs — capture version"),
        ("WebLogic T3",    'port:7001 product:"WebLogic"', "Critical", "T3 listener fingerprint"),
        ("JBoss/WildFly",  "port:8080,9990,9999",     "High",     "JMX/management console"),
        ("GlassFish",      "port:4848",               "High",     "admin console"),
        ("Tomcat",         'port:8080 http.title:"Tomcat"', "High", "manager app / version in banner"),
        ("WebSphere",      "port:9043,9060",          "High",     "admin console"),
        ("ActiveMQ",       "port:8161,61616",         "High",     "web console (8161) + OpenWire (61616)"),
        ("RabbitMQ",       "port:5672,15672",         "High",     "AMQP (5672) + mgmt UI (15672)"),
        ("IBM MQ",         "port:1414",               "High",     "MQ channel listener"),
        ("Apache Kafka",   "port:9092",               "High",     "broker; often unauthenticated"),
        ("MQTT",           "port:1883,8883",          "Medium",   "broker; check anonymous publish"),
        ("NATS",           "port:4222",               "Medium",   "message bus"),
    ],

    "DevOps / Orchestration": [
        ("Docker API",     "port:2375,2376",          "Critical", "2375 unauth = host takeover"),
        ("Kubernetes API", "port:6443,8443",          "High",     "API server"),
        ("Kubelet",        "port:10250,10255",        "High",     "10250 can exec into pods"),
        ("etcd",           "port:2379,2380",          "Critical", "K8s secret store"),
        ("Jenkins",        'port:8080 http.title:"Jenkins"', "High", "build RCE; capture version"),
        ("Grafana",        'http.title:"Grafana"',    "Medium",   "dashboard exposure"),
        ("Kibana",         'port:5601 http.title:"Kibana"', "Medium", "data exposure"),
        ("Prometheus",     'port:9090 http.title:"Prometheus"', "Medium", "metrics/target leak"),
        ("Consul",         "port:8500",               "High",     "service catalog + KV"),
        ("Vault",          "port:8200",               "High",     "secrets — verify sealed"),
        ("MinIO/S3",       "port:9000",               "High",     "object storage"),
    ],

    "Industrial / Legacy": [
        ("Modbus",         "port:502",                "Critical", "OT — should never face internet"),
        ("Siemens S7",     "port:102",                "Critical", "OT PLC"),
        ("BACnet",         "port:47808",              "High",     "building automation"),
        ("DNP3",           "port:20000",              "High",     "SCADA"),
    ],
}


def protocol_queries_for(scope: str,
                         categories: list[str] | None = None,
                         min_severity: str | None = None) -> list[dict]:
    """
    Materialize ready-to-run detection queries for a scope anchor.

    `scope` is the in-scope anchor you already trust — e.g. 'net:203.0.113.0/24'
    or 'org:"Company, Inc"' (use build_query / build_filter to make it).

        for q in protocol_queries_for('net:203.0.113.0/24',
                                      categories=["App Servers & Message Queues"]):
            run shodan_search(q["query"])

    Returns dicts: {category, label, query, severity, note}. No category is
    dropped unless you ask — "don't limit" by default.
    """
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    floor = order.get(min_severity, 99) if min_severity else 99
    cats = categories or list(PROTOCOL_QUERIES.keys())
    out: list[dict] = []
    for cat in cats:
        for label, suffix, sev, note in PROTOCOL_QUERIES.get(cat, []):
            if min_severity and order.get(sev, 99) > floor:
                continue
            out.append({
                "category": cat,
                "label": label,
                "query": f"{scope} {suffix}".strip(),
                "severity": sev,
                "note": note,
            })
    return out


# ─────────────────────────────────────────────────────────────────────────────
# 3. VERSION EXTRACTION  — pull versions + HTTP protocol out of a host record
# ─────────────────────────────────────────────────────────────────────────────

_SSH_RE   = re.compile(r"SSH-\d+\.\d+-([^\r\n]+)", re.I)
_HTTP_RE  = re.compile(r"HTTP/(\d(?:\.\d)?)", re.I)
_SERVER_RE = re.compile(r"^server:\s*(.+)$", re.I | re.M)
_VER_RE   = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[._-][0-9a-z]+)?)")


def extract_versions(host: dict) -> dict:
    """
    Pull every version signal we can from a Shodan host record so the report
    shows real version numbers, not just product names.

    Looks at: product/version fields, the raw banner ('data'), SSH banner,
    HTTP server header + HTTP protocol version (1.0/1.1/2), TLS/ALPN.

    Returns a flat dict; absent fields are simply omitted.
    """
    out: dict = {}
    prod = (host.get("product") or "").strip()
    ver = (host.get("version") or "").strip()
    if prod:
        out["product"] = prod
    if ver:
        out["version"] = ver

    banner = ""
    for k in ("data", "banner", "raw"):
        b = host.get(k)
        if isinstance(b, str) and b:
            banner = b
            break

    # SSH banner version (OpenSSH 8.9p1, Dropbear 2022.83, ...)
    m = _SSH_RE.search(banner)
    if m:
        out["ssh_version"] = m.group(1).strip()

    # HTTP server header + protocol version
    http = host.get("http") if isinstance(host.get("http"), dict) else {}
    server = (http.get("server") or "").strip()
    if not server:
        ms = _SERVER_RE.search(banner)
        if ms:
            server = ms.group(1).strip()
    if server:
        out["http_server"] = server

    mh = _HTTP_RE.search(banner) or _HTTP_RE.search(str(http.get("status_line", "")))
    if mh:
        out["http_protocol"] = f"HTTP/{mh.group(1)}"

    # HTTP/2 negotiated via TLS ALPN
    ssl = host.get("ssl") if isinstance(host.get("ssl"), dict) else {}
    alpn = ssl.get("alpn") or host.get("alpn") or []
    if isinstance(alpn, (list, tuple)) and any("h2" in str(a).lower() for a in alpn):
        out["http_protocol"] = "HTTP/2"
    elif "h2" in str(alpn).lower():
        out["http_protocol"] = "HTTP/2"

    # TLS versions offered
    versions = (ssl.get("versions") if isinstance(ssl, dict) else None) or []
    if versions:
        out["tls_versions"] = [v for v in versions if not str(v).startswith("-")]

    # Last resort: a version-looking number in the banner tail
    if "version" not in out and server:
        mv = _VER_RE.search(server)
        if mv:
            out["version"] = mv.group(1)

    return out


def version_capture_queries(scope: str) -> list[dict]:
    """
    Queries specifically aimed at surfacing version + HTTP-protocol data.
    Pair each with extract_versions() on the returned hosts.
    """
    return [
        {"query": f"{scope} port:80,443,8080,8443",
         "note": "web servers — capture http.server header + HTTP/1.1 vs HTTP/2"},
        {"query": f"{scope} port:443 ssl.alpn:h2",
         "note": "HTTP/2-capable hosts (ALPN h2 negotiated)"},
        {"query": f"{scope} has_ssl:true",
         "note": "TLS endpoints — capture offered TLS versions + cert details"},
        {"query": f"{scope} port:22",
         "note": "SSH — capture OpenSSH/Dropbear banner version"},
        {"query": f"{scope} port:1521,7001,8161,61616,1414",
         "note": "Oracle DB / WebLogic / MQ family — capture product versions"},
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("── escaping ──")
    print(" ", build_query(org="Company, Inc", ports=[443, 8443], exclude_cdn=False))
    print(" ", build_filter("org", 'Acme "EMC"'))

    print("\n── strict scope matcher (apostrophe / substring fix) ──")
    for ho in ["Acme Inc.", "Acme Technologies", "Acme'Servizi Italiani",
               "Acmena Co", "Michael Acme Foundation"]:
        print(f"  {ho:28} -> {org_in_scope(ho, ['Acme'])}")

    print("\n── protocol catalog size ──")
    qs = protocol_queries_for('net:203.0.113.0/24')
    print(f"  {len(qs)} queries across {len(PROTOCOL_QUERIES)} categories")
    print("  sample:", qs[0]["query"], "|", qs[0]["severity"])

    print("\n── version extraction ──")
    h = {"product": "OpenSSH", "data": "SSH-2.0-OpenSSH_8.9p1 Ubuntu",
         "ssl": {"alpn": ["h2", "http/1.1"], "versions": ["TLSv1.2", "TLSv1.3"]}}
    print(" ", extract_versions(h))
