"""
threat_feeds.py — Threat intelligence feed crawler + STIX/TAXII integration.

Sources:
  1. montysecurity/C2-Tracker       — Shodan queries for C2 infrastructure
  2. BushidoUK/OSINT-SearchOperators — Shodan adversary infrastructure queries
  3. martinkubecka/C2Hunter          — C2 hunting queries + config
  4. AlienVault OTX                  — Public pulses with Shodan indicators
  5. STIX/TAXII public feeds         — MITRE ATT&CK, CISA AIS, Anomali Limo

All Shodan queries are validated for syntax before storing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

import aiohttp
import db

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shodan syntax validator
# ---------------------------------------------------------------------------
_BOOL_RE  = re.compile(r'\b(OR|AND|NOT)\b', re.IGNORECASE)
_WILD_RE  = re.compile(r'[*?]')
_PAREN_RE = re.compile(r'[()]')

def _is_valid_shodan(q: str) -> tuple[bool, str]:
    q = q.strip()
    if not q or len(q) < 4:
        return False, "too short"
    if _BOOL_RE.search(q):
        return False, "boolean operator"
    if _WILD_RE.search(q):
        return False, "wildcard"
    stripped = re.sub(r'"[^"]*"', '', q)
    if _PAREN_RE.search(stripped):
        return False, "parentheses"
    if ':' not in q and '"' not in q:
        return False, "no filter (bare keyword)"
    return True, ""

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class FeedQuery:
    query:      str
    label:      str
    source:     str
    category:   str
    actor:      str = ""
    fetched_at: str = ""
    notes:      str = ""
    stix_id:    str = ""   # STIX object ID if from TAXII
    otx_pulse:  str = ""   # OTX pulse ID if from AlienVault

    def to_dict(self) -> dict:
        return asdict(self)

# ---------------------------------------------------------------------------
# Category guesser
# ---------------------------------------------------------------------------
_CAT_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r'cobalt.?strike|beacon|malleable|teamserver', re.I), "C2 — Cobalt Strike"),
    (re.compile(r'\bsliver\b|\bsilver\b', re.I),                      "C2 — Sliver"),
    (re.compile(r'metasploit|meterpreter',         re.I),             "C2 — Metasploit"),
    (re.compile(r'empire|covenant|havoc|brute.?ratel|deimos|mythic',re.I),"C2 — Other Framework"),
    (re.compile(r'mirai|botnet|qbot|trickbot|emotet|amadey',re.I),    "Botnet"),
    (re.compile(r'ransomware|lockbit|blackcat|conti|hive|revil|alphv',re.I),"Ransomware"),
    (re.compile(r'phish|credential.?harvest|evilginx|gophish',re.I),  "Phishing"),
    (re.compile(r'crypto.?min|monero|stratum|xmrig',re.I),            "Crypto Mining"),
    (re.compile(r'apt|nation.?state|lazarus|cozy.?bear|fancy.?bear|sandworm',re.I),"APT"),
    (re.compile(r'rdp|remote.?desktop',re.I),                         "Remote Access"),
    (re.compile(r'ssl|tls|cert|jarm|ja3|ja4',re.I),                   "TLS Fingerprint"),
    (re.compile(r'favicon|hash',re.I),                                 "Favicon Fingerprint"),
    (re.compile(r'scan|masscan|shodan|censys',re.I),                   "Scanning Infrastructure"),
    (re.compile(r'proxy|vpn|tor',re.I),                                "Anonymization"),
    (re.compile(r'iot|camera|router|embedded',re.I),                   "IoT / OT"),
    (re.compile(r'exploit|cve|vuln',re.I),                             "Vulnerability Exploitation"),
]

def _guess_category(text: str) -> str:
    for pattern, cat in _CAT_RULES:
        if pattern.search(text):
            return cat
    return "Threat Infrastructure"

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
TIMEOUT = aiohttp.ClientTimeout(total=25)
HEADERS = {"User-Agent": "ShodanSnipe-ThreatIntel/1.0", "Accept": "application/json,text/plain,*/*"}

async def _fetch_text(session: aiohttp.ClientSession, url: str) -> str | None:
    try:
        async with session.get(url, timeout=TIMEOUT, headers=HEADERS) as r:
            if r.status == 200:
                return await r.text()
            # 403/404 are expected (auth required, moved repo) — log at debug
            lvl = logger.debug if r.status in (403, 404) else logger.warning
            lvl("GET %s → %s", url, r.status)
            return None
    except Exception as e:
        logger.debug("fetch %s: %s", url, e)
        return None

async def _fetch_json(session: aiohttp.ClientSession, url: str,
                       headers: dict | None = None) -> dict | list | None:
    hdrs = {**HEADERS, **(headers or {}), "Accept": "application/json"}
    try:
        async with session.get(url, timeout=TIMEOUT, headers=hdrs) as r:
            if r.status == 200:
                return await r.json(content_type=None)
            lvl = logger.debug if r.status in (403, 404) else logger.warning
            lvl("GET %s → %s", url, r.status)
            return None
    except Exception as e:
        logger.debug("fetch_json %s: %s", url, e)
        return None

# ---------------------------------------------------------------------------
# Parser: C2-Tracker (tracker.py)
# Format: queries = {"Label": ["query1", "query2"], ...}  (Python dict literal)
# ---------------------------------------------------------------------------
def _parse_c2tracker(text: str) -> list[FeedQuery]:
    out = []
    seen: set[str] = set()
    current_label = ""

    label_re = re.compile(r'^\s*["\'](.+?)["\']\s*:\s*\[', re.M)
    sections = re.split(r'(?=^\s*["\'][^"\']+["\']\s*:\s*\[)', text, flags=re.M)

    for section in sections:
        lm = label_re.match(section.strip())
        if lm:
            current_label = lm.group(1).strip()

        # Match full query strings — both double-quoted and single-quoted
        for line in section.splitlines():
            line = line.strip()
            # Skip comment/import lines
            if line.startswith('#') or line.startswith('import') or line.startswith('def '):
                continue
            # Find quoted strings on this line
            for qm in re.finditer(r'"([^"]{6,120})"|\'([^\']{6,120})\'', line):
                q = (qm.group(1) or qm.group(2) or "").strip()
                if not q or q == current_label:
                    continue
                if "://" in q or "\\" in q:
                    continue
                if q.lower() in ("ssl", "http", "port", "org", "shodan", "query",
                                  "search", "censys", "api_key"):
                    continue
                # Normalise single-quoted filter values to double quotes
                q = re.sub(r"(\w[\w.]+:)'([^']+)'", r'\1"\2"', q)
                if q in seen:
                    continue
                valid, _ = _is_valid_shodan(q)
                if valid:
                    seen.add(q)
                    out.append(FeedQuery(
                        query=q,
                        label=current_label or q[:60],
                        source="C2-Tracker",
                        category=_guess_category((current_label or "") + " " + q),
                    ))
    return out


# ---------------------------------------------------------------------------
# Parser: BushidoUK ShodanAdversaryInfa.md
# Format: #### `Section Name` followed by - query lines
# ---------------------------------------------------------------------------
def _parse_bushido_md(text: str) -> list[FeedQuery]:
    out = []
    seen: set[str] = set()
    section = "Adversary Infrastructure"
    actor = ""

    for line in text.splitlines():
        line = line.strip()

        # #### `Section Name` or ## Heading
        hm = re.match(r'^#{1,4}\s+`?(.+?)`?\s*$', line)
        if hm:
            section = hm.group(1).strip()
            actor = section  # treat heading as actor/tool name
            continue

        # - query  (list item)
        lm = re.match(r'^[-*]\s+(.+)', line)
        if lm:
            raw = lm.group(1).strip()
            # Strip markdown: backticks, links
            q = re.sub(r'`([^`]+)`', r'\1', raw)
            q = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', q).strip()
            if q and q not in seen and len(q) > 5:
                valid, _ = _is_valid_shodan(q)
                if valid:
                    seen.add(q)
                    out.append(FeedQuery(
                        query=q,
                        label=section,
                        source="BushidoUK-OSINT",
                        category=_guess_category(section + " " + q),
                        actor=actor,
                    ))
            continue

        # Inline backtick queries: `product:"X"` on any line
        for cm in re.finditer(r'`([^`\n]{6,100})`', line):
            q = cm.group(1).strip()
            if q not in seen:
                valid, _ = _is_valid_shodan(q)
                if valid:
                    seen.add(q)
                    out.append(FeedQuery(
                        query=q, label=section, source="BushidoUK-OSINT",
                        category=_guess_category(section + " " + q),
                        actor=actor,
                    ))

    return out

# ---------------------------------------------------------------------------
# Parser: C2Hunter YAML
# ---------------------------------------------------------------------------
_YAML_Q_RE = re.compile(r'(?:query|search|shodan)\s*:\s*["\']?([^"\'\n#]+)["\']?', re.I)
_YAML_N_RE = re.compile(r'(?:name|label|description)\s*:\s*["\']?([^"\'\n#]+)["\']?', re.I)

def _parse_c2hunter_yaml(text: str) -> list[FeedQuery]:
    out = []
    pending = ""
    for line in text.splitlines():
        nm = _YAML_N_RE.match(line.strip())
        if nm:
            pending = nm.group(1).strip()
            continue
        qm = _YAML_Q_RE.match(line.strip())
        if qm:
            q = qm.group(1).strip().strip('"\'')
            valid, _ = _is_valid_shodan(q)
            if valid:
                out.append(FeedQuery(query=q, label=pending or q[:60], source="C2Hunter",
                                     category=_guess_category(pending+" "+q)))
                pending = ""
    return out

# ---------------------------------------------------------------------------
# AlienVault OTX — public pulses with Shodan indicators
# ---------------------------------------------------------------------------
OTX_BASE = "https://otx.alienvault.com/api/v1"
# Pulses tagged with shodan or that have shodan_query indicator type
OTX_SHODAN_PULSES = [
    f"{OTX_BASE}/pulses/subscribed?limit=50&page=1",
    f"{OTX_BASE}/pulses/search?q=shodan&limit=50",
    f"{OTX_BASE}/pulses/search?q=C2+infrastructure&limit=30",
    f"{OTX_BASE}/pulses/search?q=cobalt+strike+shodan&limit=30",
    f"{OTX_BASE}/pulses/search?q=threat+hunting+shodan&limit=20",
]

# Shodan indicator type in OTX
OTX_SHODAN_TYPES = {"shodan_query", "SHODAN_QUERY"}

async def _fetch_otx_pulses(session: aiohttp.ClientSession,
                             api_key: str | None) -> list[FeedQuery]:
    out: list[FeedQuery] = []
    hdrs = {"X-OTX-API-KEY": api_key} if api_key else {}

    # Public search endpoints (no key required for search)
    urls_to_try = [
        f"{OTX_BASE}/pulses/search?q=shodan+query&limit=50",
        f"{OTX_BASE}/pulses/search?q=cobalt+strike+C2&limit=30",
        f"{OTX_BASE}/pulses/search?q=apt+infrastructure+shodan&limit=20",
        f"{OTX_BASE}/pulses/search?q=malware+C2+detection&limit=20",
    ]
    if api_key:
        urls_to_try.insert(0, f"{OTX_BASE}/pulses/subscribed?limit=100&page=1")

    seen_queries: set[str] = set()

    for url in urls_to_try:
        data = await _fetch_json(session, url, hdrs)
        if not data:
            continue
        pulses = data.get("results", []) if isinstance(data, dict) else []
        for pulse in pulses:
            pulse_name = pulse.get("name", "")
            pulse_id   = pulse.get("id", "")
            author     = pulse.get("author_name", "")
            tags       = pulse.get("tags", [])
            indicators = pulse.get("indicators", [])
            # Extract Shodan queries from indicators
            for ind in indicators:
                if ind.get("type", "").lower() in ("shodan_query", "shodan"):
                    q = ind.get("indicator", "").strip()
                    if q and q not in seen_queries:
                        valid, _ = _is_valid_shodan(q)
                        if valid:
                            seen_queries.add(q)
                            cat = _guess_category(pulse_name + " " + " ".join(tags))
                            out.append(FeedQuery(
                                query=q,
                                label=pulse_name[:80],
                                source="AlienVault-OTX",
                                category=cat,
                                actor=author,
                                notes=f"Tags: {', '.join(tags[:5])}",
                                otx_pulse=pulse_id,
                            ))
            # Also extract from description (some pulses embed queries in text)
            desc = pulse.get("description", "")
            for m in re.finditer(r'(?:shodan|search):\s*([^\n,]{10,100})', desc, re.I):
                q = m.group(1).strip().strip('"\'')
                if q not in seen_queries:
                    valid, _ = _is_valid_shodan(q)
                    if valid:
                        seen_queries.add(q)
                        out.append(FeedQuery(
                            query=q, label=pulse_name[:80],
                            source="AlienVault-OTX",
                            category=_guess_category(pulse_name),
                            actor=author, otx_pulse=pulse_id,
                        ))
        await asyncio.sleep(0.5)  # Rate limit OTX

    return out

# ---------------------------------------------------------------------------
# Additional GitHub sources — raw Shodan query lists
# ---------------------------------------------------------------------------
EXTRA_GITHUB_SOURCES = {
    # jakejarvis/shodan-queries — large curated list of useful queries
    "ShodanQueries-jakejarvis": (
        "https://raw.githubusercontent.com/jakejarvis/awesome-shodan-queries/main/readme.md",
        "markdown-queries",
    ),
    # lothos/shodan-filters — filter reference with example queries
    "ShodanDorks": (
        "https://raw.githubusercontent.com/humblelad/Shodan-Dorks/master/README.md",
        "markdown-queries",
    ),
    # nice-ness/shodan-query-files — structured yaml query files
    "ShodanQueryFiles": (
        "https://raw.githubusercontent.com/lothos612/shodan/master/README.md",
        "markdown-queries",
    ),
}


def _parse_markdown_queries(text: str, source: str) -> list[FeedQuery]:
    """
    Extract Shodan queries from markdown files.
    Looks for lines in code blocks or after common prefixes.
    """
    out: list[FeedQuery] = []
    seen: set[str] = set()
    current_section = "General"

    lines = text.splitlines()
    in_code_block = False
    code_lang = ""

    for i, line in enumerate(lines):
        # Track sections (## headings)
        h = re.match(r'^#{1,3}\s+(.+)', line)
        if h:
            current_section = h.group(1).strip()[:60]
            continue

        # Code block fence
        if line.strip().startswith("```"):
            if in_code_block:
                in_code_block = False
            else:
                in_code_block = True
                code_lang = line.strip().lstrip("`").lower()
            continue

        # Inside a code block — treat as a query candidate
        if in_code_block and code_lang in ("", "shodan", "text", "bash"):
            q = line.strip()
            if q and len(q) > 5 and q not in seen:
                valid, _ = _is_valid_shodan(q)
                if valid:
                    seen.add(q)
                    out.append(FeedQuery(
                        query=q, label=current_section,
                        source=source, category=_guess_category(current_section + " " + q),
                    ))
            continue

        # Inline code in backticks: `product:"Apache" port:80`
        for m in re.finditer(r'`([^`]{10,120})`', line):
            q = m.group(1).strip()
            if q not in seen:
                valid, _ = _is_valid_shodan(q)
                if valid:
                    seen.add(q)
                    out.append(FeedQuery(
                        query=q, label=current_section,
                        source=source, category=_guess_category(current_section + " " + q),
                    ))

    return out


# ---------------------------------------------------------------------------
# AlienVault OTX — improved fetcher
# ---------------------------------------------------------------------------
async def _fetch_otx_pulses(session: aiohttp.ClientSession,
                             api_key: str | None) -> list[FeedQuery]:
    out: list[FeedQuery] = []
    hdrs = {}
    if api_key:
        hdrs["X-OTX-API-KEY"] = api_key

    urls_to_try: list[str] = []
    if api_key:
        # With a key: subscribed pulses + searches
        urls_to_try += [
            f"{OTX_BASE}/pulses/subscribed?limit=100&page=1",
            f"{OTX_BASE}/pulses/subscribed?limit=100&page=2",
        ]
    # Public searches — no key required
    urls_to_try += [
        f"{OTX_BASE}/pulses/search?q=shodan&limit=50&page=1",
        f"{OTX_BASE}/pulses/search?q=cobalt+strike&limit=50&page=1",
        f"{OTX_BASE}/pulses/search?q=C2+infrastructure&limit=30&page=1",
        f"{OTX_BASE}/pulses/search?q=apt+shodan&limit=30&page=1",
        f"{OTX_BASE}/pulses/search?q=malware+detection&limit=30&page=1",
    ]

    seen_queries: set[str] = set()

    for url in urls_to_try:
        try:
            data = await _fetch_json(session, url, hdrs)
        except Exception as e:
            logger.debug("OTX fetch error %s: %s", url, e)
            continue
        if not data:
            continue

        pulses = data.get("results", []) if isinstance(data, dict) else []
        for pulse in pulses:
            pulse_name = pulse.get("name", "")
            pulse_id   = pulse.get("id", "")
            author     = pulse.get("author_name", "")
            tags       = pulse.get("tags", [])
            indicators = pulse.get("indicators", [])

            # 1. Explicit Shodan query indicators
            for ind in indicators:
                itype = ind.get("type", "").lower()
                if itype in ("shodan_query", "shodan"):
                    q = ind.get("indicator", "").strip()
                    if q and q not in seen_queries:
                        valid, _ = _is_valid_shodan(q)
                        if valid:
                            seen_queries.add(q)
                            out.append(FeedQuery(
                                query=q, label=pulse_name[:80],
                                source="AlienVault-OTX",
                                category=_guess_category(pulse_name + " " + " ".join(tags)),
                                actor=author,
                                notes=f"OTX pulse: {pulse_name[:40]}",
                                otx_pulse=pulse_id,
                            ))

            # 2. Shodan queries embedded in description text
            desc = pulse.get("description", "")
            for m in re.finditer(
                r'(?:shodan[:\s]+|search[:\s]+|query[:\s]+)'
                r'["\']?([a-z][a-z0-9._\-]+(?::["\']?[^\n\'"]{3,60})?)["\']?',
                desc, re.I
            ):
                q = m.group(1).strip().strip('"\'')
                if len(q) > 8 and q not in seen_queries:
                    valid, _ = _is_valid_shodan(q)
                    if valid:
                        seen_queries.add(q)
                        out.append(FeedQuery(
                            query=q, label=pulse_name[:80],
                            source="AlienVault-OTX",
                            category=_guess_category(pulse_name + " " + " ".join(tags)),
                            actor=author, otx_pulse=pulse_id,
                        ))

            # 3. IP/domain indicators → Shodan ip:/hostname: queries (limited)
            ip_count = 0
            for ind in indicators:
                if ip_count >= 5:
                    break
                itype = ind.get("type", "").lower()
                val   = ind.get("indicator", "").strip()
                if not val:
                    continue
                if itype in ("ipv4", "ip"):
                    q = f"ip:{val}"
                elif itype in ("domain", "hostname") and "." in val:
                    q = f"hostname:{val}"
                else:
                    continue
                if q not in seen_queries:
                    seen_queries.add(q)
                    ip_count += 1
                    out.append(FeedQuery(
                        query=q, label=pulse_name[:60],
                        source="AlienVault-OTX",
                        category=_guess_category(pulse_name),
                        actor=author, otx_pulse=pulse_id,
                    ))

        await asyncio.sleep(0.3)  # light rate limit

    logger.info("OTX: %d queries extracted", len(out))
    return out


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------
def _deduplicate(queries: list[FeedQuery]) -> list[FeedQuery]:
    seen: set[str] = set()
    out: list[FeedQuery] = []
    for q in queries:
        norm = re.sub(r'\s+', ' ', q.query.strip().lower())
        if norm not in seen:
            seen.add(norm)
            out.append(q)
    return out

# ---------------------------------------------------------------------------
# DB schema
# ---------------------------------------------------------------------------
FEED_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_feed_queries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    query       TEXT NOT NULL,
    label       TEXT NOT NULL,
    source      TEXT NOT NULL,
    category    TEXT NOT NULL,
    actor       TEXT NOT NULL DEFAULT '',
    notes       TEXT NOT NULL DEFAULT '',
    fetched_at  TEXT NOT NULL,
    stix_id     TEXT NOT NULL DEFAULT '',
    otx_pulse   TEXT NOT NULL DEFAULT '',
    run_count   INTEGER NOT NULL DEFAULT 0,
    last_run    TEXT,
    cluster_id  INTEGER DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_tfq_source   ON threat_feed_queries(source);
CREATE INDEX IF NOT EXISTS idx_tfq_category ON threat_feed_queries(category);
CREATE INDEX IF NOT EXISTS idx_tfq_cluster  ON threat_feed_queries(cluster_id);

CREATE TABLE IF NOT EXISTS threat_clusters (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    actor       TEXT NOT NULL DEFAULT '',
    mitre_ttps  TEXT NOT NULL DEFAULT '',  -- JSON array
    ioc_summary TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feed_refresh_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    total       INTEGER,
    sources     TEXT,
    status      TEXT
);
"""

def _ensure_feed_schema() -> None:
    """
    Create feed tables if missing and migrate any columns added after initial creation.

    Deliberately avoids executescript() for the full schema because:
    - executescript() auto-COMMITs before running, which can break open transactions
    - If any statement fails (e.g. CREATE INDEX on a column that doesn't exist yet),
      the entire script aborts and subsequent migration ALTER TABLEs never run.

    Instead we: create tables → migrate columns → create indexes separately.
    """
    try:
        with db._lock:
            conn = db._c()

            # 1. Create base tables (no indexes yet — columns must exist first)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_feed_queries (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    query       TEXT NOT NULL,
                    label       TEXT NOT NULL,
                    source      TEXT NOT NULL,
                    category    TEXT NOT NULL,
                    actor       TEXT NOT NULL DEFAULT '',
                    notes       TEXT NOT NULL DEFAULT '',
                    fetched_at  TEXT NOT NULL,
                    stix_id     TEXT NOT NULL DEFAULT '',
                    otx_pulse   TEXT NOT NULL DEFAULT '',
                    run_count   INTEGER NOT NULL DEFAULT 0,
                    last_run    TEXT,
                    cluster_id  INTEGER DEFAULT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_clusters (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    name        TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    actor       TEXT NOT NULL DEFAULT '',
                    mitre_ttps  TEXT NOT NULL DEFAULT '',
                    ioc_summary TEXT NOT NULL DEFAULT '',
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feed_refresh_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at  TEXT NOT NULL,
                    finished_at TEXT,
                    total       INTEGER DEFAULT 0,
                    sources     TEXT DEFAULT '{}',
                    status      TEXT DEFAULT 'running'
                )
            """)
            conn.commit()

            # 2. Migrate missing columns (ALTER TABLE ADD COLUMN for columns
            #    added to the schema after the table was first created)
            migrations = [
                ("threat_feed_queries", "cluster_id",  "INTEGER DEFAULT NULL"),
                ("threat_feed_queries", "stix_id",     "TEXT NOT NULL DEFAULT ''"),
                ("threat_feed_queries", "otx_pulse",   "TEXT NOT NULL DEFAULT ''"),
                ("threat_feed_queries", "run_count",   "INTEGER NOT NULL DEFAULT 0"),
                ("threat_feed_queries", "last_run",    "TEXT"),
                ("threat_feed_queries", "actor",       "TEXT NOT NULL DEFAULT ''"),
                ("threat_feed_queries", "notes",       "TEXT NOT NULL DEFAULT ''"),
                ("threat_clusters",     "actor",       "TEXT NOT NULL DEFAULT ''"),
                ("threat_clusters",     "mitre_ttps",  "TEXT NOT NULL DEFAULT ''"),
                ("threat_clusters",     "ioc_summary", "TEXT NOT NULL DEFAULT ''"),
            ]
            existing: dict[str, set] = {}
            for tbl, col, defn in migrations:
                if tbl not in existing:
                    rows = conn.execute(f"PRAGMA table_info({tbl})").fetchall()
                    existing[tbl] = {r[1] for r in rows}
                if col not in existing[tbl]:
                    try:
                        conn.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {defn}")
                        existing[tbl].add(col)
                        logger.info("Migrated %s: added column %s", tbl, col)
                    except Exception as me:
                        logger.warning("Migration %s.%s: %s", tbl, col, me)
            conn.commit()

            # 3. Create indexes now that all columns are guaranteed to exist
            for stmt in [
                "CREATE INDEX IF NOT EXISTS idx_tfq_source   ON threat_feed_queries(source)",
                "CREATE INDEX IF NOT EXISTS idx_tfq_category ON threat_feed_queries(category)",
                "CREATE INDEX IF NOT EXISTS idx_tfq_cluster  ON threat_feed_queries(cluster_id)",
            ]:
                try:
                    conn.execute(stmt)
                except Exception as ie:
                    logger.debug("Index creation skipped: %s", ie)
            conn.commit()

    except Exception as e:
        logger.error("feed schema setup failed: %s", e)

def _store_queries(queries: list[FeedQuery]) -> int:
    now = datetime.now(timezone.utc).isoformat()
    count = 0
    with db._lock:
        conn = db._c()
        conn.execute("DELETE FROM threat_feed_queries")
        for q in queries:
            conn.execute(
                "INSERT INTO threat_feed_queries"
                "(query,label,source,category,actor,notes,fetched_at,stix_id,otx_pulse) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (q.query, q.label, q.source, q.category, q.actor,
                 q.notes, now, q.stix_id, q.otx_pulse)
            )
            count += 1
        conn.commit()
    return count

def get_feed_queries(category="", source="", search="", limit=500) -> list[dict]:
    _ensure_feed_schema()
    with db._lock:
        sql = ("SELECT id,query,label,source,category,actor,notes,"
               "fetched_at,run_count,last_run,stix_id,otx_pulse,cluster_id "
               "FROM threat_feed_queries WHERE 1=1")
        params: list[Any] = []
        if category:
            sql += " AND category=?"; params.append(category)
        if source:
            sql += " AND source=?"; params.append(source)
        if search:
            s = f"%{search}%"
            sql += " AND (query LIKE ? OR label LIKE ? OR actor LIKE ?)"; params.extend([s,s,s])
        sql += " ORDER BY category,source,id LIMIT ?"; params.append(limit)
        rows = db._c().execute(sql, params).fetchall()
    return [{"id":r[0],"query":r[1],"label":r[2],"source":r[3],"category":r[4],
             "actor":r[5],"notes":r[6],"fetched_at":r[7],"run_count":r[8],
             "last_run":r[9],"stix_id":r[10],"otx_pulse":r[11],"cluster_id":r[12]} for r in rows]

def get_feed_stats() -> dict:
    _ensure_feed_schema()
    with db._lock:
        conn = db._c()
        total  = conn.execute("SELECT COUNT(*) FROM threat_feed_queries").fetchone()[0]
        sources= conn.execute("SELECT source,COUNT(*) FROM threat_feed_queries GROUP BY source").fetchall()
        cats   = conn.execute("SELECT category,COUNT(*) FROM threat_feed_queries GROUP BY category ORDER BY COUNT(*) DESC").fetchall()
        clust  = conn.execute("SELECT COUNT(*) FROM threat_clusters").fetchone()[0]
        last   = conn.execute("SELECT finished_at,total,status FROM feed_refresh_log ORDER BY id DESC LIMIT 1").fetchone()
    return {
        "total":       total,
        "sources":     {r[0]:r[1] for r in sources},
        "categories":  {r[0]:r[1] for r in cats},
        "clusters":    clust,
        "last_refresh":{"at":last[0],"count":last[1],"status":last[2]} if last else None,
    }

def get_feed_categories() -> list[str]:
    _ensure_feed_schema()
    with db._lock:
        rows = db._c().execute("SELECT DISTINCT category FROM threat_feed_queries ORDER BY category").fetchall()
    return [r[0] for r in rows]

def mark_query_run(query_id: int) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with db._lock:
        db._c().execute("UPDATE threat_feed_queries SET run_count=run_count+1,last_run=? WHERE id=?", (now,query_id))
        db._c().commit()

# ---------------------------------------------------------------------------
# Cluster storage
# ---------------------------------------------------------------------------
def save_cluster(name: str, description: str, actor: str,
                 mitre_ttps: list[str], ioc_summary: str,
                 query_ids: list[int]) -> int:
    _ensure_feed_schema()
    now = datetime.now(timezone.utc).isoformat()
    with db._lock:
        conn = db._c()
        cur = conn.execute(
            "INSERT INTO threat_clusters(name,description,actor,mitre_ttps,ioc_summary,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (name, description, actor, json.dumps(mitre_ttps), ioc_summary, now, now)
        )
        cluster_id = cur.lastrowid
        if query_ids:
            conn.executemany(
                "UPDATE threat_feed_queries SET cluster_id=? WHERE id=?",
                [(cluster_id, qid) for qid in query_ids]
            )
        conn.commit()
    return cluster_id

def get_clusters() -> list[dict]:
    _ensure_feed_schema()
    with db._lock:
        rows = db._c().execute(
            "SELECT c.id,c.name,c.description,c.actor,c.mitre_ttps,c.ioc_summary,"
            "c.created_at,c.updated_at,"
            "(SELECT COUNT(*) FROM threat_feed_queries WHERE cluster_id=c.id) as q_count "
            "FROM threat_clusters c ORDER BY c.updated_at DESC"
        ).fetchall()
    return [{"id":r[0],"name":r[1],"description":r[2],"actor":r[3],
             "mitre_ttps":json.loads(r[4] or "[]"),"ioc_summary":r[5],
             "created_at":r[6],"updated_at":r[7],"query_count":r[8]} for r in rows]

def get_cluster_queries(cluster_id: int) -> list[dict]:
    _ensure_feed_schema()
    with db._lock:
        rows = db._c().execute(
            "SELECT id,query,label,source,category,actor FROM threat_feed_queries WHERE cluster_id=?",
            (cluster_id,)
        ).fetchall()
    return [{"id":r[0],"query":r[1],"label":r[2],"source":r[3],"category":r[4],"actor":r[5]} for r in rows]

def delete_cluster(cluster_id: int) -> None:
    with db._lock:
        db._c().execute("UPDATE threat_feed_queries SET cluster_id=NULL WHERE cluster_id=?", (cluster_id,))
        db._c().execute("DELETE FROM threat_clusters WHERE id=?", (cluster_id,))
        db._c().commit()

# ---------------------------------------------------------------------------
# Main crawler
# ---------------------------------------------------------------------------
async def refresh_feeds(otx_api_key: str | None = None) -> dict:
    _ensure_feed_schema()
    started = datetime.now(timezone.utc).isoformat()
    with db._lock:
        cur = db._c().execute("INSERT INTO feed_refresh_log(started_at,status) VALUES(?,?)", (started,"running"))
        db._c().commit()
        log_id = cur.lastrowid

    all_queries: list[FeedQuery] = []
    source_counts: dict[str, int] = {}
    errors: list[str] = []

    RAW_URLS = {
        "C2-Tracker":    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/tracker.py",
        "BushidoUK":     "https://raw.githubusercontent.com/BushidoUK/OSINT-SearchOperators/main/ShodanAdversaryInfa.md",
        # C2Hunter moved — try several known paths
        "C2Hunter-cfg1": "https://raw.githubusercontent.com/martinkubecka/C2Hunter/main/config/shodan_queries.yaml",
        "C2Hunter-cfg2": "https://raw.githubusercontent.com/martinkubecka/C2Hunter/main/data/queries.yaml",
        "C2Hunter-cfg3": "https://raw.githubusercontent.com/martinkubecka/C2Hunter/main/queries.yaml",
    }

    async with aiohttp.ClientSession() as session:
        # GitHub sources
        for key, url in RAW_URLS.items():
            logger.info("Fetching %s...", key)
            text = await _fetch_text(session, url)
            if not text:
                errors.append(f"{key}: fetch failed"); continue
            if key == "C2-Tracker":
                parsed = _parse_c2tracker(text)
            elif key == "BushidoUK":
                parsed = _parse_bushido_md(text)
            else:
                parsed = _parse_c2hunter_yaml(text)
            src = "C2Hunter" if key.startswith("C2Hunter") else key
            source_counts[src] = source_counts.get(src,0) + len(parsed)
            all_queries.extend(parsed)
            logger.info("%s: %d queries", key, len(parsed))

        # AlienVault OTX
        logger.info("Fetching AlienVault OTX...")
        try:
            otx_queries = await _fetch_otx_pulses(session, otx_api_key)
            source_counts["AlienVault-OTX"] = len(otx_queries)
            all_queries.extend(otx_queries)
            logger.info("OTX: %d queries", len(otx_queries))
        except Exception as e:
            errors.append(f"OTX: {e}")

        # Extra GitHub markdown query sources
        for src_key, (url, fmt) in EXTRA_GITHUB_SOURCES.items():
            logger.info("Fetching %s...", src_key)
            text = await _fetch_text(session, url)
            if not text:
                errors.append(f"{src_key}: fetch failed"); continue
            parsed = _parse_markdown_queries(text, src_key)
            source_counts[src_key] = len(parsed)
            all_queries.extend(parsed)
            logger.info("%s: %d queries", src_key, len(parsed))

    now_iso = datetime.now(timezone.utc).isoformat()
    for q in all_queries:
        q.fetched_at = now_iso

    before = len(all_queries)
    all_queries = _deduplicate(all_queries)
    stored = _store_queries(all_queries)

    finished = datetime.now(timezone.utc).isoformat()
    with db._lock:
        db._c().execute(
            "UPDATE feed_refresh_log SET finished_at=?,total=?,sources=?,status=? WHERE id=?",
            (finished, stored, json.dumps(source_counts), "ok" if not errors else "partial", log_id)
        )
        db._c().commit()

    return {"status":"ok" if not errors else "partial","total":stored,
            "deduplicated_from":before,"sources":source_counts,"errors":errors,"finished_at":finished}
