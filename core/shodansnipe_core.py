"""
shodansnipe_core.py — Library version of ShodanSnipe.

Engine changes per NEXT_SESSION_SPEC.md:
  - RateLimiter class with adaptive backoff + jitter
  - Free-tier fix: search_cursor() 403 → graceful fallback + clear UI message
  - Expanded fields: city, country, asn_name, http_title, status, ssl_subject, ssl_subject_full
  - Removed "vulnerable" from critical_tags
  - Expanded premium plan name list
  - Corporate plan detection via _check_corporate_plan()
"""

from __future__ import annotations

import asyncio
import aiohttp
import atexit
import json
import logging
import os
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

import shodan

logger = logging.getLogger(__name__)

INTERNETDB_CACHE_FILE = "internetdb_cache.json"

# ---------------------------------------------------------------------------
# Risk config — "vulnerable" removed from critical_tags per spec
# ---------------------------------------------------------------------------
RISK_CONFIG = {
    "critical_ports": {"ports": [23, 3389, 135, 445, 1433, 3306, 5432, 6379, 27017], "risk": "Critical"},
    "high_risk_ports": {"ports": [21, 22, 25, 53, 80, 110, 143, 993, 995, 5900, 5901], "risk": "High"},
    "medium_risk_ports": {"ports": [443, 8080, 8443, 9000, 9090], "risk": "Medium"},
    "critical_products": {"products": ["iis", "apache", "nginx", "tomcat", "exchange", "sql server"], "risk": "High"},
    "high_risk_products": {"products": ["outlook", "sharepoint", "wordpress", "joomla", "drupal"], "risk": "Medium"},
    # "vulnerable" removed — it's a Shodan tag that produces too many false-positives
    "critical_tags": {"tags": ["ics", "scada", "honeypot", "malware"], "risk": "Critical"},
    "high_risk_tags": {"tags": ["iot", "camera", "router", "voip", "database"], "risk": "High"},
    "critical_cves": {"cves": ["CVE-2017-0144", "CVE-2020-1472", "CVE-2021-44228"], "risk": "Critical"},
    "high_risk_cves": {"cves": ["CVE-2019-0708", "CVE-2020-0796", "CVE-2021-34527"], "risk": "High"},
}

# ---------------------------------------------------------------------------
# Expanded premium plan names per spec
# ---------------------------------------------------------------------------
PREMIUM_PLAN_NAMES = {
    "member", "asm", "enterprise", "corporate", "edu", "gov",
    "academic", "plus", "business", "professional", "enterprise-plus",
    "freelancer", "small-business",
}


# ---------------------------------------------------------------------------
# RateLimiter — adaptive backoff with jitter
# ---------------------------------------------------------------------------
class RateLimiter:
    """
    Token-bucket-style rate limiter with adaptive exponential backoff.
    Wraps any callable and retries on transient errors (429, connection errors).
    """

    def __init__(
        self,
        calls_per_second: float = 2.0,
        max_retries: int = 4,
        base_backoff: float = 1.0,
        max_backoff: float = 30.0,
    ):
        self.min_interval = 1.0 / calls_per_second
        self.max_retries = max_retries
        self.base_backoff = base_backoff
        self.max_backoff = max_backoff
        self._last_call = 0.0
        self._lock = threading.Lock()

    def _wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self.min_interval - (now - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()

    def call(self, fn, *args, **kwargs):
        """Call fn(*args, **kwargs) with rate limiting and retry.
        
        Rate limit handling:
        - 429 / rate limit exceeded: longer backoff (10-60s), more patient
        - 403 / access denied / upgrade: raise immediately (plan issue, not transient)  
        - Connection errors: standard exponential backoff
        """
        last_exc = None
        for attempt in range(self.max_retries + 1):
            try:
                self._wait()
                return fn(*args, **kwargs)
            except shodan.APIError as e:
                err = str(e).lower()
                # Non-retriable: auth/plan issues
                if any(x in err for x in ("403", "access denied", "upgrade", "401",
                                           "invalid api key", "no information available")):
                    raise
                # Shodan rate limit — longer backoff
                if any(x in err for x in ("429", "rate limit", "too many requests")):
                    wait = min(10.0 * (2 ** attempt), 60.0)
                    logger.warning("Shodan rate limit (attempt %d). Backing off %.0fs...",
                                   attempt + 1, wait)
                    time.sleep(wait)
                    last_exc = e
                    continue
                last_exc = e
            except Exception as e:
                last_exc = e

            if attempt < self.max_retries:
                backoff = min(self.base_backoff * (2 ** attempt), self.max_backoff)
                jitter = random.uniform(0, backoff * 0.3)
                sleep_time = backoff + jitter
                logger.warning("RateLimiter: attempt %d failed (%s), retrying in %.1fs",
                                attempt + 1, last_exc, sleep_time)
                time.sleep(sleep_time)

        raise last_exc
@dataclass
class PortInfo:
    shodan_ports: List[int]
    internetdb_ports: List[int]
    enriched_ports: List[int]

    @property
    def all_ports(self) -> List[int]:
        return sorted(set(self.shodan_ports) | set(self.internetdb_ports) | set(self.enriched_ports))

    @property
    def total_count(self) -> int:
        return len(self.all_ports)

    @property
    def ports_string(self) -> str:
        return ",".join(map(str, self.all_ports)) if self.all_ports else "N/A"


@dataclass
class CVEInfo:
    shodan_cves: List[str]
    internetdb_cves: List[str]
    enriched_cves: List[str]

    @property
    def all_cves(self) -> List[str]:
        return sorted(set(self.shodan_cves) | set(self.internetdb_cves) | set(self.enriched_cves))

    @property
    def total_count(self) -> int:
        return len(self.all_cves)


@dataclass
class HostnameInfo:
    shodan_hostnames: List[str]
    internetdb_hostnames: List[str]
    enriched_hostnames: List[str]

    @property
    def all_hostnames(self) -> List[str]:
        items = self.shodan_hostnames + self.internetdb_hostnames + self.enriched_hostnames
        return sorted({h for h in items if h and h != "N/A"})


@dataclass
class TagInfo:
    shodan_tags: List[str]
    internetdb_tags: List[str]

    @property
    def all_tags(self) -> List[str]:
        return sorted(set(self.shodan_tags) | set(self.internetdb_tags))


# ---------------------------------------------------------------------------
# DataValidator
# ---------------------------------------------------------------------------
class DataValidator:
    @staticmethod
    def validate_port(port: Any) -> Optional[int]:
        try:
            if isinstance(port, int):
                return port if 1 <= port <= 65535 else None
            if isinstance(port, str) and port.strip().isdigit():
                v = int(port.strip())
                return v if 1 <= v <= 65535 else None
            return None
        except (ValueError, TypeError):
            return None

    @staticmethod
    def clean_port_list(ports: Any) -> List[int]:
        if not ports:
            return []
        if isinstance(ports, int):
            v = DataValidator.validate_port(ports)
            return [v] if v is not None else []
        if isinstance(ports, str):
            try:
                parsed = json.loads(ports)
                ports = parsed if isinstance(parsed, list) else [p.strip() for p in ports.split(",") if p.strip()]
            except json.JSONDecodeError:
                ports = [p.strip() for p in ports.split(",") if p.strip()]
        if not isinstance(ports, (list, tuple)):
            return []
        clean: list[int] = []
        for p in ports:
            v = DataValidator.validate_port(p)
            if v is not None and v not in clean:
                clean.append(v)
        return sorted(clean)

    @staticmethod
    def clean_string_list(items: Any) -> List[str]:
        if not items:
            return []
        if isinstance(items, str):
            try:
                parsed = json.loads(items)
                items = parsed if isinstance(parsed, list) else [items.strip()]
            except json.JSONDecodeError:
                items = [items.strip()] if items.strip() else []
        if not isinstance(items, (list, tuple)):
            return []
        cleaned = [i.strip() for i in items if isinstance(i, str) and i.strip()]
        return sorted(set(cleaned))

    @staticmethod
    def sanitize_csv_field(value: str) -> str:
        if not isinstance(value, str):
            value = str(value)
        return value.replace("\n", " ").replace("\r", " ").replace('"', '""')


# ---------------------------------------------------------------------------
# InternetDB client — completely free, no API key required
# ---------------------------------------------------------------------------
class InternetDBClient:
    BASE_URL = "https://internetdb.shodan.io"

    def __init__(self):
        self.cache: Dict[str, Dict] = {}
        self._load()
        atexit.register(self._save)
        self.semaphore = asyncio.Semaphore(10)  # conservative concurrency

    def _load(self):
        try:
            if os.path.exists(INTERNETDB_CACHE_FILE):
                with open(INTERNETDB_CACHE_FILE, "r") as f:
                    self.cache = json.load(f)
        except Exception as e:
            logger.warning("InternetDB cache load failed: %s", e)
            self.cache = {}

    def _save(self):
        try:
            with open(INTERNETDB_CACHE_FILE, "w") as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.warning("InternetDB cache save failed: %s", e)

    async def query_ip_async(self, ip: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        if ip in self.cache:
            return self.cache[ip]
        async with self.semaphore:
            url = f"{self.BASE_URL}/{ip}"
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 404:
                        data = {"ports": [], "cpes": [], "vulns": [], "hostnames": [], "tags": []}
                        self.cache[ip] = data
                        return data
                    resp.raise_for_status()
                    raw = await resp.json()
                    data = {
                        "ports": DataValidator.clean_port_list(raw.get("ports", [])),
                        "cpes": DataValidator.clean_string_list(raw.get("cpes", [])),
                        "vulns": DataValidator.clean_string_list(raw.get("vulns", [])),
                        "hostnames": DataValidator.clean_string_list(raw.get("hostnames", [])),
                        "tags": DataValidator.clean_string_list(raw.get("tags", [])),
                    }
                    self.cache[ip] = data
                    return data
            except Exception as e:
                logger.error("InternetDB error for %s: %s", ip, e)
                return {"ports": [], "cpes": [], "vulns": [], "hostnames": [], "tags": []}

    async def batch_query(self, ips: List[str], session: aiohttp.ClientSession) -> Dict[str, Dict]:
        results = await asyncio.gather(*[self.query_ip_async(ip, session) for ip in ips])
        return dict(zip(ips, results))


# ---------------------------------------------------------------------------
# Risk assessment
# ---------------------------------------------------------------------------
class RiskAssessment:
    def __init__(self, risk_config: Dict = RISK_CONFIG):
        self.rc = risk_config

    def assess_risk(self, port_info: PortInfo, product: str, tag_info: TagInfo, cve_info: CVEInfo) -> Dict[str, str]:
        reasons: list[str] = []
        risk = "Low"

        crit_ports = [p for p in port_info.all_ports if p in self.rc["critical_ports"]["ports"]]
        if crit_ports:
            reasons.append(f"Critical Ports: {','.join(map(str, crit_ports))}")
            risk = "Critical"

        crit_cves = [c for c in cve_info.all_cves if c in self.rc["critical_cves"]["cves"]]
        if crit_cves:
            reasons.append(f"Critical CVEs: {','.join(crit_cves)}")
            risk = "Critical"

        tags_lower = [t.lower() for t in tag_info.all_tags]
        crit_tags = [t for t in tags_lower if t in self.rc["critical_tags"]["tags"]]
        if crit_tags:
            reasons.append(f"Critical Tags: {','.join(crit_tags)}")
            risk = "Critical"

        if risk != "Critical":
            hi_ports = [p for p in port_info.all_ports if p in self.rc["high_risk_ports"]["ports"]]
            if hi_ports:
                reasons.append(f"High-Risk Ports: {','.join(map(str, hi_ports))}")
                risk = "High"

            prod_l = (product or "").lower()
            if prod_l and prod_l != "n/a":
                if any(cp in prod_l for cp in self.rc["critical_products"]["products"]):
                    reasons.append(f"Critical Product: {product}")
                    risk = "High"
                elif any(hp in prod_l for hp in self.rc["high_risk_products"]["products"]):
                    reasons.append(f"High-Risk Product: {product}")
                    if risk not in ("High", "Critical"):
                        risk = "Medium"

            hi_tags = [t for t in tags_lower if t in self.rc["high_risk_tags"]["tags"]]
            if hi_tags:
                reasons.append(f"High-Risk Tags: {','.join(hi_tags)}")
                if risk not in ("High", "Critical"):
                    risk = "High"

            hi_cves = [c for c in cve_info.all_cves if c in self.rc["high_risk_cves"]["cves"]]
            if hi_cves:
                reasons.append(f"High-Risk CVEs: {','.join(hi_cves)}")
                if risk not in ("High", "Critical"):
                    risk = "High"

            if risk == "Low":
                med_ports = [p for p in port_info.all_ports if p in self.rc.get("medium_risk_ports", {}).get("ports", [])]
                if med_ports:
                    reasons.append(f"Medium-Risk Ports: {','.join(map(str, med_ports))}")
                    risk = "Medium"

        full = f"{risk} ({'; '.join(reasons)})" if reasons else risk
        simple = f"{risk} - {', '.join(reasons)}" if reasons else risk
        return {"level": risk, "full": full, "simplified": simple}


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------
class ShodanQuery:
    def __init__(self, api_key: str, batch_size: int = 25, max_concurrency: int = 10, thread_pool_size: int = 20):
        if not api_key or not api_key.strip():
            raise ValueError("API key required")
        self.api = shodan.Shodan(api_key.strip())
        self.results: list[dict] = []
        self.internetdb_client = InternetDBClient()
        self.risk_assessor = RiskAssessment()
        self.batch_size = batch_size
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.thread_pool = ThreadPoolExecutor(max_workers=thread_pool_size)
        self.results_lock = threading.Lock()
        self.rate_limiter = RateLimiter(calls_per_second=1.0, max_retries=3)
        self._plan_info: dict | None = None  # cached api.info() result

    def api_info(self) -> dict:
        """Call api.info(). Works on all tiers including free."""
        try:
            info = self.api.info()
            self._plan_info = info
            return info
        except Exception as e:
            logger.error("api.info() failed: %s", e)
            return {}

    def _check_corporate_plan(self) -> bool:
        """Returns True if the key has a corporate/enterprise-level plan."""
        if not self._plan_info:
            try:
                self._plan_info = self.api.info()
            except Exception:
                return False
        plan = (self._plan_info.get("plan") or "").lower()
        return any(p in plan for p in ("corporate", "enterprise", "asm", "edu", "gov"))

    def _is_paid_plan(self) -> bool:
        """Returns True for any paid plan (member+). Free = False."""
        if not self._plan_info:
            try:
                self._plan_info = self.api.info()
            except Exception:
                return False
        plan = (self._plan_info.get("plan") or "").lower()
        unlocked = bool(self._plan_info.get("unlocked", False))
        return unlocked or any(p in plan for p in PREMIUM_PLAN_NAMES)

    def _shodan_host(self, ip: str, enrich: bool) -> dict:
        """Single-IP host lookup — works on free keys."""
        try:
            return self.rate_limiter.call(self.api.host, ip, history=enrich)
        except shodan.APIError as e:
            logger.error("api.host(%s) failed: %s", ip, e)
            return {}
        except Exception as e:
            logger.error("api.host(%s) unexpected error: %s", ip, e)
            return {}

    def _collect_ips(self, query: str, limit: int, tags: Optional[List[str]]) -> tuple[list[str], str | None]:
        """
        Collect IPs from a search query.
        Returns (ip_list, warning_message_or_None).

        Free keys: search_cursor() → 403 → graceful fallback message.
        Paid keys: search_cursor() for full paging.
        """
        collected: list[str] = []
        warning: str | None = None

        # --- Try search_cursor first (paid) ---
        try:
            for result in self.rate_limiter.call(lambda: iter(self.api.search_cursor(query))):
                if len(collected) >= limit:
                    break
                if tags:
                    rtags = [t.lower() for t in result.get("tags", [])]
                    if not any(t.lower() in rtags for t in tags):
                        continue
                ip = result.get("ip_str")
                if ip and ip not in collected:
                    collected.append(ip)
            return collected, warning

        except shodan.APIError as e:
            err = str(e).lower()

            # Free key / plan limitation
            if any(x in err for x in ("403", "access denied", "upgrade your api", "requires a paid")):
                logger.warning("search_cursor() denied (free key). Attempting api.search() fallback.")
                warning = (
                    "Free Shodan API keys cannot run keyword searches. "
                    "Results limited to 100 via api.search(). "
                    "Upgrade to a Membership ($49 one-time) for full access. "
                    "Bulk IP lookup and InternetDB enrichment still work with your free key."
                )
                # Fallback: api.search() - works for some results on free plans
                try:
                    results = self.rate_limiter.call(
                        self.api.search, query, page=1, limit=min(limit, 100)
                    )
                    for match in results.get("matches", []):
                        ip = match.get("ip_str")
                        if ip and ip not in collected:
                            collected.append(ip)
                        if len(collected) >= limit:
                            break
                    return collected, warning
                except shodan.APIError as e2:
                    err2 = str(e2).lower()
                    if any(x in err2 for x in ("403", "access denied", "upgrade")):
                        # api.search also blocked on this free key
                        return [], (
                            "Your free Shodan API key cannot perform keyword searches. "
                            "Only single-IP lookup (Bulk mode) and InternetDB enrichment are available. "
                            "To run queries, upgrade to a Shodan Membership ($49 one-time) at shodan.io/store."
                        )
                    logger.error("api.search() fallback also failed: %s", e2)
                    return [], f"Search failed: {e2}"
            else:
                logger.error("Shodan search error: %s", e)
                return [], f"Shodan API error: {e}"

    def _adjusted_limit(self, requested: int, force_premium: bool = False) -> int:
        if force_premium:
            return requested
        try:
            if not self._plan_info:
                self._plan_info = self.api.info()
            credits = self._plan_info.get("query_credits", 0)
            is_paid = self._is_paid_plan()
            if is_paid:
                return requested if credits > requested else min(requested, max(credits, 100))
            return min(requested, 100)
        except Exception:
            return min(requested, 100)

    async def get_host_info(self, ip: str, enrich: bool, internetdb_data: dict | None = None) -> dict:
        loop = asyncio.get_event_loop()
        shodan_data = await loop.run_in_executor(self.thread_pool, self._shodan_host, ip, enrich)
        if not shodan_data:
            return {}

        if not internetdb_data:
            async with aiohttp.ClientSession() as session:
                internetdb_data = await self.internetdb_client.query_ip_async(ip, session)

        shodan_ports = DataValidator.clean_port_list(shodan_data.get("ports", []))
        enriched_ports: list[int] = []
        http_title = "N/A"
        http_status = "N/A"
        if enrich:
            for item in shodan_data.get("data", []):
                if "port" in item:
                    p = DataValidator.validate_port(item["port"])
                    if p and p not in enriched_ports:
                        enriched_ports.append(p)
                http_block = item.get("http") or {}
                if http_block.get("title") and http_title == "N/A":
                    http_title = http_block["title"]
                if http_block.get("status") and http_status == "N/A":
                    http_status = str(http_block["status"])
            enriched_ports.sort()

        port_info = PortInfo(shodan_ports, internetdb_data.get("ports", []), enriched_ports)

        shodan_cves = DataValidator.clean_string_list(shodan_data.get("vulns", []))
        enriched_cves: list[str] = []
        if enrich:
            for item in shodan_data.get("data", []):
                v = item.get("vulns", [])
                if isinstance(v, list):
                    enriched_cves.extend(DataValidator.clean_string_list(v))
                elif isinstance(v, dict):
                    enriched_cves.extend(DataValidator.clean_string_list(list(v.keys())))

        cve_info = CVEInfo(shodan_cves, internetdb_data.get("vulns", []), DataValidator.clean_string_list(enriched_cves))

        shodan_hostnames = DataValidator.clean_string_list(shodan_data.get("hostnames", []))
        enriched_hostnames: list[str] = []
        if enrich:
            for item in shodan_data.get("data", []):
                if "hostnames" in item:
                    enriched_hostnames.extend(DataValidator.clean_string_list(item["hostnames"]))

        hostname_info = HostnameInfo(shodan_hostnames, internetdb_data.get("hostnames", []),
                                     DataValidator.clean_string_list(enriched_hostnames))

        tag_info = TagInfo(DataValidator.clean_string_list(shodan_data.get("tags", [])),
                           internetdb_data.get("tags", []))

        products = {i.get("product") for i in shodan_data.get("data", []) if i.get("product")}
        product = ", ".join(products) if products else "N/A"

        # Location + ASN naming
        city = shodan_data.get("city", "N/A")
        country = shodan_data.get("country_name", shodan_data.get("country", "N/A"))
        asn_name = shodan_data.get("asn", "N/A")
        isp = shodan_data.get("isp")
        if isp:
            asn_name = f"{asn_name} ({isp})" if asn_name != "N/A" else isp

        # SSL cert subject parsing
        ssl_subject = "N/A"
        ssl_subject_full = "N/A"
        ssl_block = shodan_data.get("ssl") or {}
        subject = (ssl_block.get("cert") or {}).get("subject") or {}
        if subject:
            org_ = subject.get("O", "")
            cn = subject.get("CN", "")
            if org_ and cn:
                ssl_subject = f"O={org_}, CN={cn}"
            elif cn:
                ssl_subject = f"CN={cn}"
            elif org_:
                ssl_subject = f"O={org_}"
            parts = []
            for k in ("C", "CN", "L", "O", "ST", "OU"):
                if k in subject:
                    parts.append(f'{k}: "{subject[k]}"')
            if parts:
                ssl_subject_full = "{\n* " + ",\n* ".join(parts) + "\n}"

        enriched_data = {}
        if enrich:
            enriched_data = {
                "ssl_info": shodan_data.get("ssl", {}),
                "ssl_subject": ssl_subject,
                "ssl_subject_full": ssl_subject_full,
                "http_title": http_title,
                "status": http_status,
                "last_update": shodan_data.get("last_update", "N/A"),
                "domains": DataValidator.clean_string_list(shodan_data.get("domains", [])),
            }

        risk = self.risk_assessor.assess_risk(port_info, product, tag_info, cve_info)

        return {
            "ip_str": ip,
            "port_info": port_info,
            "cve_info": cve_info,
            "hostname_info": hostname_info,
            "tag_info": tag_info,
            "org": shodan_data.get("org", "N/A"),
            "product": product,
            "os": shodan_data.get("os", "N/A"),
            "asn": shodan_data.get("asn", "N/A"),
            "asn_name": asn_name,
            "city": city,
            "country": country,
            "http_title": http_title,
            "http_status": http_status,
            "ssl_subject": ssl_subject,
            "ssl_subject_full": ssl_subject_full,
            "domains": DataValidator.clean_string_list(shodan_data.get("domains", [])),
            "cpes_internetdb": internetdb_data.get("cpes", []),
            "risk_assessment": risk,
            "enriched": enrich,
            "enriched_data": enriched_data,
        }

    async def _process_one(self, ip: str, enrich: bool, internetdb_batch: dict) -> dict:
        async with self.semaphore:
            host_info = await self.get_host_info(ip, enrich, internetdb_batch.get(ip, {}))
            if host_info:
                with self.results_lock:
                    self.results.append(host_info)
            return host_info

    async def process_batch(self, ips: List[str], enrich: bool, session: aiohttp.ClientSession) -> list[dict]:
        internetdb_batch = await self.internetdb_client.batch_query(ips, session)
        results = await asyncio.gather(*[self._process_one(ip, enrich, internetdb_batch) for ip in ips])
        return [r for r in results if r]

    async def execute_query(
        self,
        query: str,
        limit: int = 100,
        tags: Optional[List[str]] = None,
        enrich: bool = False,
        ip_list: Optional[List[str]] = None,
        force_premium: bool = False,
    ) -> tuple[List[dict], str | None]:
        """
        Returns (results, warning_or_None).
        Warning is set when free-key limitations are hit.
        """
        self.results = []
        warning: str | None = None

        if ip_list:
            # Bulk mode - api.host() works on free keys
            ips = list(dict.fromkeys(ip_list))[:limit]
        else:
            adj = self._adjusted_limit(limit, force_premium=force_premium)
            ips, warning = self._collect_ips(query, adj, tags)

        if not ips:
            return [], warning

        batches = [ips[i:i + self.batch_size] for i in range(0, len(ips), self.batch_size)]
        async with aiohttp.ClientSession() as session:
            for batch in batches:
                await self.process_batch(batch, enrich, session)
        return self.results, warning


def serialize_result(r: dict) -> dict:
    """Convert a result dict (with dataclass fields) to JSON-safe form."""
    pi = r.get("port_info")
    ci = r.get("cve_info")
    hi = r.get("hostname_info")
    ti = r.get("tag_info")
    return {
        "ip_str": r.get("ip_str"),
        "ports": pi.all_ports if pi else [],
        "port_count": pi.total_count if pi else 0,
        "port_sources": {
            "shodan": pi.shodan_ports if pi else [],
            "internetdb": pi.internetdb_ports if pi else [],
            "enriched": pi.enriched_ports if pi else [],
        },
        "cves": ci.all_cves if ci else [],
        "cve_count": ci.total_count if ci else 0,
        "hostnames": hi.all_hostnames if hi else [],
        "tags": ti.all_tags if ti else [],
        "org": r.get("org", "N/A"),
        "product": r.get("product", "N/A"),
        "os": r.get("os", "N/A"),
        "asn": r.get("asn", "N/A"),
        "asn_name": r.get("asn_name", "N/A"),
        "city": r.get("city", "N/A"),
        "country": r.get("country", "N/A"),
        "http_title": r.get("http_title", "N/A"),
        "http_status": r.get("http_status", "N/A"),
        "ssl_subject": r.get("ssl_subject", "N/A"),
        "ssl_subject_full": r.get("ssl_subject_full", "N/A"),
        "domains": r.get("domains", []),
        "cpes_internetdb": r.get("cpes_internetdb", []),
        "risk_level": r.get("risk_assessment", {}).get("level", "Low"),
        "risk_full": r.get("risk_assessment", {}).get("full", ""),
        "risk_simplified": r.get("risk_assessment", {}).get("simplified", ""),
        "enriched": r.get("enriched", False),
        "enriched_data": r.get("enriched_data", {}),
        "scope_reason": r.get("_scope_reason", ""),
    }