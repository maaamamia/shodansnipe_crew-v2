"""
agents/vuln_agent.py — Vulnerability Intelligence Analyst

Cross-references discovered hosts with CVE data, generates Shodan detection
queries for specific CVEs, and produces a prioritized vulnerability list.
"""
from __future__ import annotations
import os, json

# Shared assessment doctrine (discover-don't-assume, modern-infra focus, impact-driven scoring).
try:
    from tools.doctrine import ASSESSMENT_DOCTRINE as _DOCTRINE
except ImportError:
    try:
        from doctrine import ASSESSMENT_DOCTRINE as _DOCTRINE
    except ImportError:
        _DOCTRINE = ""

from crewai import Agent, Task
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import requests

SHODANSNIPE_URL = os.environ.get("SHODANSNIPE_URL", "http://127.0.0.1:8000")

import time as _time
_HTTP_TIMEOUT = int(os.environ.get("SHODAN_HTTP_TIMEOUT", "120"))
_HTTP_RETRIES = int(os.environ.get("SHODAN_HTTP_RETRIES", "2"))

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


def _vuln_search_with_retry(query: str, limit: int) -> dict:
    """POST /api/search with generous timeout; on timeout retry with a halved limit."""
    last = None
    cur = min(limit, 500)
    for attempt in range(_HTTP_RETRIES + 1):
        try:
            r = requests.post(f"{SHODANSNIPE_URL}/api/search",
                              json={"query": query, "limit": cur}, timeout=_HTTP_TIMEOUT)
            return r.json()
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            last = e
            cur = max(10, cur // 2)
            if attempt < _HTTP_RETRIES:
                _time.sleep(1.5 * (attempt + 1))
    raise last


class CveIntelInput(BaseModel):
    text: str = Field(description="CVE ID, advisory text, or product+version to analyze")

class CveIntelTool(BaseTool):
    name: str = "cve_intel"
    description: str = (
        "Analyze a CVE ID or advisory text and return: severity, affected products, "
        "detection Shodan queries, and remediation notes. "
        "Use for each CVE found on discovered hosts."
    )
    args_schema: type = CveIntelInput

    def _run(self, text: str) -> str:
        try:
            r = requests.post(f"{SHODANSNIPE_URL}/api/llm/explain-cve",
                              json={"text": text}, timeout=30)
            if r.ok:
                return json.dumps(r.json(), indent=2)
        except Exception:
            pass
        # Fallback: NVD lookup for CVE IDs
        cves = __import__('re').findall(r'CVE-\d{4}-\d+', text, __import__('re').IGNORECASE)
        results = []
        for cve in cves[:5]:
            try:
                r2 = requests.get(
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cveId": cve.upper()}, timeout=10
                )
                if r2.ok:
                    data = r2.json()
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        v = vulns[0].get("cve", {})
                        metrics = v.get("metrics", {})
                        cvss = (
                            metrics.get("cvssMetricV31", [{}])[0]
                            .get("cvssData", {})
                            .get("baseScore", "N/A")
                            if metrics.get("cvssMetricV31") else "N/A"
                        )
                        desc = v.get("descriptions", [{}])[0].get("value", "")
                        results.append({
                            "cve": cve.upper(),
                            "cvss_score": cvss,
                            "description": desc[:300],
                            "source": "NVD",
                        })
            except Exception:
                results.append({"cve": cve.upper(), "error": "NVD lookup failed"})
        return json.dumps(results or {"text": text, "note": "No CVE IDs found"}, indent=2)


class GetResultsInput(BaseModel):
    pass

class GetResultsTool(BaseTool):
    name: str = "get_results"
    description: str = "Get the current search results in memory from the last Shodan search."
    args_schema: type = GetResultsInput

    def _run(self) -> str:
        try:
            r = requests.get(f"{SHODANSNIPE_URL}/api/results", timeout=10)
            d = r.json()
            results = d.get("results", [])
            # Summarize for LLM
            return json.dumps({
                "count": len(results),
                "hosts": [{
                    "ip": h.get("ip_str"),
                    "risk": h.get("risk_level"),
                    "cves": h.get("cves", []),
                    "product": h.get("product"),
                    "ports": h.get("ports", [])[:_cap("vuln_ports", 10)],
                } for h in results[:_cap("vuln_detect_hosts", 30)]]
            }, indent=2)
        except Exception as e:
            return f"Error: {e}"


class ShodanSearchInput(BaseModel):
    query: str = Field(description="Shodan query for CVE/vuln detection. No OR/AND/NOT.")
    limit: int = Field(25, ge=1, description="Max results; clamped to 500")

class ShodanSearchTool(BaseTool):
    name: str = "shodan_search"
    description: str = "Run a Shodan search to find hosts matching a CVE detection query."
    args_schema: type = ShodanSearchInput

    def _run(self, query: str, limit: int = 25) -> str:
        try:
            return json.dumps(_vuln_search_with_retry(query, limit), indent=2)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            return ("Error: detection query timed out after retries. Narrow it (add "
                    "net:/asn:/port: anchors) or lower the limit, then retry.")
        except Exception as e:
            return f"Error: {e}"



def _build_vuln_tools(extra_tools=None) -> list:
    tools = [CveIntelTool(), GetResultsTool(), ShodanSearchTool()]
    # Curl-style validation: confirm no-auth / reachability before assigning severity.
    try:
        from tools.http_validate_tool import HttpProbeTool
        tools.append(HttpProbeTool())
        print("[VulnAgent] http_probe validation tool loaded")
    except ImportError:
        try:
            from http_validate_tool import HttpProbeTool
            tools.append(HttpProbeTool())
            print("[VulnAgent] http_probe validation tool loaded")
        except ImportError:
            print("[VulnAgent] http_validate_tool not available — severity stays evidence-gated but unverified")
    try:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))
        from archive_tool import WaybackTool, ShodanHostURITool
        tools.extend([WaybackTool(), ShodanHostURITool()])
        print("[VulnAgent] Archive + ShodanURI tools loaded")
    except ImportError as e:
        print(f"[VulnAgent] archive_tool not available: {e}")
    if extra_tools:
        tools.extend(extra_tools)
    return tools

def build_vuln_agent(llm, extra_tools=None) -> Agent:
    """Create the Vulnerability Intelligence Analyst."""
    return Agent(
        role="Vulnerability Intelligence Analyst",
        goal=(
            "Cross-reference every discovered host with CVE data, score each "
            "vulnerability by severity and exploitability, generate scoped Shodan "
            "detection queries and run them, then deeply enrich Critical/High "
            "findings with archive history and full Shodan banner data."
        ),
        backstory=(
            "You are a vulnerability researcher who maps CVEs to real infrastructure. "
            "You look up every CVE found on discovered hosts, score them by CVSS and "
            "exploitability, and generate Shodan queries to find more affected hosts "
            "in scope. You run those queries — you do not just list them. "
            "You focus on: RCE, auth bypass, path traversal, SSRF, and exposed admin "
            "interfaces. You de-prioritize informational findings (CVSS < 4.0) and "
            "focus on what causes real damage. but do not remove any misconfigurations"
            "For Critical and High hosts you go deeper: Wayback Machine historical "
            "snapshots and full Shodan banner pulls. "
            "Your output feeds the Threat Intel agent and the Report Writer. "
            "LANE BOUNDARY — you own vulnerability IDENTIFICATION, CONFIRMATION, CVSS scoring, "
            "and per-finding REMEDIATION (the patch/disable/firewall step). You do NOT map MITRE "
            "ATT&CK TTPs, attribute threat actors, build attack chains, or generate IOC/SIEM/Sigma "
            "content — that is the Threat Intel agent's job downstream, and it consumes your "
            "confirmed findings. Produce the authoritative confirmed-findings list with severities "
            "and remediation; leave the adversary/detection layer to Threat Intel."
        ),
        tools=_build_vuln_tools(extra_tools),
        llm=llm,
        verbose=True,
        max_iter=30,
        allow_delegation=False,
    )


def build_vuln_tasks(agent, recon_output: str, auth_output: str) -> list[Task]:
    """Two-task pipeline: CVE intel → detection + enrichment."""

    # ── Task 1: CVE extraction and triage ─────────────────────────────────
    cve_intel_task = Task(
        description=f"""
Extract and triage every CVE from the recon and auth findings.
{_DOCTRINE}
RECON FINDINGS:
{recon_output[:60000]}

AUTH FINDINGS:
{auth_output[:20000]}

STEP 1 — EXTRACT: Find every CVE ID mentioned in the findings above.
  Also look for: version strings that imply known CVEs, product names
  with known vulnerability histories, Shodan vuln: flags.

STEP 2 — CVE LOOKUP: For every unique CVE found, call cve_intel("<CVE-ID>").
  Collect: CVSS score, description, affected product versions,
  whether remotely exploitable, and Shodan detection queries.

STEP 3 — PRIORITIZE into four tiers:
  CRITICAL  — CVSS >= 9.0. Run immediately.
  HIGH      — CVSS 7.0-8.9. Run after Critical.
  MEDIUM    — CVSS 4.0-6.9. Note, do not run detection queries.
  SKIP      — CVSS < 4.0 or informational only.

  IMPORTANT — these CVSS tiers set INVESTIGATION PRIORITY, not the final finding severity.
  Final severity follows CONFIRMED IMPACT and is capped by confidence:
    • A version-inferred CVE (matched from a banner/CPE, exploit NOT confirmed in this exposure)
      is MEDIUM at most, confidence:inferred — never Critical on the strength of CVSS alone.
    • A long CVE list on an old banner ("OpenSSH 7.4 — 25 CVEs", "Apache 2.4.37 — 134 CVEs") is
      NOT a Critical: cite the 1-3 genuinely exploitable in THIS exposure, score on that path,
      and label the rest "version-associated, not individually validated".
    • confidence 'inferred' caps the finding at HIGH; CRITICAL requires confidence:confirmed AND
      the exploit conditions actually met (probe-confirmed). State which when you write Critical.

STEP 4 — SERVICE EXPOSURE FLAGS (evidence-gated — an open port is NOT a finding):
  A port being open is CONTEXT, not a finding. Severity comes from an OBSERVED defect, never
  from the port number alone. Use http_probe (for services that speak HTTP) or concrete
  Shodan banner/tag evidence to CONFIRM the defect before assigning severity. If you cannot
  confirm a defect, record it as an "inferred" lead at Low/Informational — NOT Critical/High.
  No maybes in the Critical/High tiers.

  Cleartext-by-design (the exposure itself is the defect):
    - port 23 Telnet → Critical, once you confirm the port is actually serving (probe or
                       banner). Cleartext admin is a real finding on its own.

  Auth-state-dependent (you MUST confirm "no auth" — do not assume it):
    - port 2375 Docker API → Critical ONLY if http_probe('http://<ip>:2375/version') returns
                       data with no auth challenge. 401/403/refused → drop the finding.
    - port 6379 Redis · 27017 Mongo · 9200 Elastic · 5984 CouchDB · 11211 Memcached →
                       High ONLY if confirmed reachable AND unauthenticated (probe the HTTP
                       ones, e.g. 'http://<ip>:9200/'; for Redis/Memcached require a Shodan
                       no-auth banner). Auth present or unconfirmed → inferred lead, not High.
    - port 6443 K8s API · 10250 Kubelet · 2379 etcd → High ONLY if the API answers without
                       auth (probe 'https://<ip>:6443/version'). Otherwise inferred.

  Normal services that are NOT findings by themselves (notable only WITH evidence of a defect):
    - port 22 SSH → open SSH is normal. Flag ONLY with a vulnerable/old banner version tied
                    to a real CVE, or a confirmed weak config. Open ≠ High.
    - port 21 FTP → flag ONLY if anonymous login is confirmed or a vulnerable banner is seen.
    - port 25/465/587 SMTP → flag ONLY if open relay is confirmed or a vulnerable banner seen.
    - port 3389 RDP · 5900 VNC → High ONLY when internet-exposed in scope AND missing
                    auth/NLA is indicated. Otherwise a Medium lead pending confirmation.
    - port 7001/7002 WebLogic → severity comes from the EXACT version → CVE match, not the port.

  Posture issues (real, Medium — the observation itself is the evidence):
    - Expired SSL cert (observed)                    → Medium
    - Missing DMARC / missing SPF (observed in DNS)  → Medium

  HARD RULE: never output a host as Critical/High without naming the specific observed
  evidence (banner, version+CVE, probe result, Shodan no-auth tag). "Port open" is not evidence.

STEP 5 — OUTPUT as JSON:
{{
  "cve_triage": {{
    "critical": [
      {{"cve": "CVE-XXXX-YYYY", "cvss": 9.8, "product": "...",
        "affected_hosts": ["1.2.3.4"], "remotely_exploitable": true,
        "detection_query": "product:\"...\" version:...",
        "description": "one sentence"}}
    ],
    "high":   [ ...same structure... ],
    "medium": [ ...same structure... ],
    "service_flags": [
      {{"host": "1.2.3.4", "port": 23, "issue": "Telnet exposed",
        "severity": "Critical", "reason": "cleartext protocol"}}
    ]
  }},
  "unique_cves_found": N,
  "critical_count": N,
  "high_count": N
}}
""",
        expected_output=(
            "JSON cve_triage with critical[], high[], medium[], service_flags[]. "
            "Every CVE gets: cve, cvss, product, affected_hosts[], remotely_exploitable, "
            "detection_query, description."
        ),
        agent=agent,
    )

    # ── Task 2: Detection query execution + deep enrichment ───────────────
    detection_task = Task(
        description=f"""
Run detection queries for every Critical and High CVE from the triage.
Then deeply enrich Critical/High hosts.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
LAYER 1 — RUN DETECTION QUERIES:
  For every CVE marked Critical or High in the triage:
    a) Use the detection_query from the triage output.
    b) Run it via shodan_search() — a separate call per CVE.
    c) Note how many hosts in scope match.

  Also run these systematic detection queries for common high-value exposures:
  (Replace SCOPE with the active scope from get_results or prior context)

  Remote code execution services:
    SCOPE port:8080 http.title:"Jenkins"
    SCOPE port:8080 http.title:"Tomcat"
    SCOPE port:4848 http.title:"GlassFish"
    SCOPE port:7001 http.title:"WebLogic"
    SCOPE port:7001,7002 product:"WebLogic"   (T3 listener — capture exact version)
    SCOPE port:8161 http.title:"ActiveMQ"
    SCOPE port:4848  (JBoss/GlassFish admin)
    SCOPE port:9090  (various admin panels)

  Remote access & cleartext (capture banner versions):
    SCOPE port:22    (SSH — record OpenSSH/Dropbear version)
    SCOPE port:23    (Telnet — cleartext, always Critical)
    SCOPE port:3389  (RDP — capture OS banner)
    SCOPE port:5900,5901  (VNC — often no auth)
    SCOPE port:5985,5986  (WinRM)

  File transfer / sharing:
    SCOPE port:21    (FTP — capture banner, note anonymous)
    SCOPE port:445   (SMB — EternalBlue surface)
    SCOPE port:2049  (NFS exports)
    SCOPE port:873   (rsync module listing)

  Mail / directory:
    SCOPE port:25,465,587  (SMTP — open relay / version)
    SCOPE port:389,636     (LDAP — anonymous bind)
    SCOPE port:161         (SNMP — public community strings)

  Message queues (full family — do NOT limit to ActiveMQ):
    SCOPE port:61616 (ActiveMQ OpenWire)
    SCOPE port:5672,15672 (RabbitMQ AMQP + mgmt UI)
    SCOPE port:1414  (IBM MQ channel listener)
    SCOPE port:9092  (Apache Kafka broker — often unauthenticated)
    SCOPE port:1883,8883 (MQTT broker — check anonymous publish)

  Database exposure:
    SCOPE port:3306  (MySQL — should never face internet)
    SCOPE port:5432  (PostgreSQL — should never face internet)
    SCOPE port:1521,1522 (Oracle DB TNS listener — capture version)
    SCOPE port:27017 (MongoDB — check for auth)
    SCOPE port:6379  (Redis — check for auth)
    SCOPE port:9200  (Elasticsearch — check for auth)
    SCOPE port:5984  (CouchDB — check for auth)
    SCOPE port:7474  (Neo4j browser)
    SCOPE port:11211 (Memcached — amplification + leak)

  DevOps / CI-CD surface:
    SCOPE port:8080 http.title:"Grafana"
    SCOPE port:3000 http.title:"Grafana"
    SCOPE port:5601 http.title:"Kibana"
    SCOPE port:9090 http.title:"Prometheus"
    SCOPE port:8500  (Consul UI)
    SCOPE port:8200  (Vault UI)
    SCOPE port:2375  (Docker API — no TLS, always critical)
    SCOPE port:2376  (Docker API — with TLS, still verify)
    SCOPE port:6443  (Kubernetes API server)
    SCOPE port:10250 (Kubelet — can exec into pods)
    SCOPE port:10255 (Kubelet read-only — info disclosure)
    SCOPE port:2379  (etcd — K8s secrets storage)
    SCOPE port:8001  (kubectl proxy)

  Cloud / object storage:
    SCOPE port:9000  (MinIO object storage)
    SCOPE port:7946  (Docker Swarm)

  Industrial / legacy:
    SCOPE port:502   (Modbus)
    SCOPE port:102   (Siemens S7)
    SCOPE port:47808 (BACnet)

LAYER 2 — DEEP ENRICHMENT (Critical and High hosts only):
  For each host marked Critical or High:

  a) CONFIRM FIRST (true-findings gate): if http_probe is available and the service speaks
     HTTP/HTTPS, probe it before keeping the severity — e.g. http_probe('https://<ip>:<port>/').
     A 200 with a real unauthenticated surface confirms the finding; a 401/403 means auth is
     present (downgrade or drop); a connection error means it is not serving (drop). Record
     the probe verdict as the finding's evidence. Do NOT keep a Critical/High that the probe
     contradicts.

  b) shodan_host_uri("<ip>")
     Pull full banner: HTTP headers, SSL cert details, HTTP response body
     (first 1KB — scan for secret/token/api_key/password keywords),
     robots.txt disallowed paths, exposed components (Kibana, Jenkins, etc),
     missing security headers (HSTS, CSP, X-Frame-Options).

  c) wayback_lookup("<hostname or ip>", check_sensitive_paths=True)
     Check Wayback Machine CDX for historical snapshots.
     Sensitive paths to check per host:
       /.env, /config.json, /.git/config, /admin, /swagger, /api-docs,
       /actuator/env, /phpinfo.php, /.htpasswd, /wp-config.php
     Flag ANY path that returned HTTP 200 historically — even if patched now.
     These are evidence of past exposure.

SYNTAX RULES — hard blocks:
  ✗ Never use OR, AND, NOT in Shodan queries.
  ✗ Run each query as a separate shodan_search() call.
  ✗ Only enrich Critical and High hosts with shodan_host_uri / wayback_lookup.
  ✓ Quote any org/product value with a space or comma: product:"Oracle WebLogic",
    org:"Company, Inc" — NOT org:Company, Inc (the comma leaks scope).
  ✓ For every confirmed host, record the EXACT version (e.g. "WebLogic 12.2.1.3",
    "OpenSSH 8.9p1", "RabbitMQ 3.8.9") and the HTTP protocol (HTTP/1.1 vs HTTP/2) —
    version + protocol are what map a service to a specific CVE.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OUTPUT as JSON. CONFIRMED-ONLY for the action lists: `hosts_with_critical` and
`immediate_action_required` may contain ONLY findings backed by observed evidence (probe
result, no-auth banner, version+CVE match). Inferred/unconfirmed leads go in
`service_exposures` tagged "confidence": "inferred" — never in the critical/action lists.
The example values below are schema illustrations, not findings — do not copy them.
{{
  "vulnerability_summary": {{
    "critical_cves": N,
    "high_cves": N,
    "total_unique_cves": N,
    "detection_queries_run": N,
    "hosts_confirmed_vulnerable": N
  }},
  "top_vulnerabilities": [
    {{
      "cve": "CVE-XXXX-XXXX",
      "cvss": 9.8,
      "severity": "Critical",
      "affected_hosts": ["1.2.3.4"],
      "hosts_found_by_detection_query": N,
      "description": "...",
      "remotely_exploitable": true,
      "detection_query": "exact shodan query used",
      "remediation": "patch to version X / disable service / firewall port Y"
    }}
  ],
  "service_exposures": [
    {{"host": "1.2.3.4", "port": 6379, "issue": "Redis — no auth",
      "severity": "High", "detection_query": "..."}}
  ],
  "shodan_uri_findings": [
    {{"ip": "1.2.3.4", "port": 8080, "finding": "HTTP body contains api_key=",
      "severity": "Critical"}}
  ],
  "wayback_findings": [
    {{"host": "1.2.3.4", "path": "/.env", "date": "2023-04-12",
      "snapshot_url": "https://web.archive.org/...", "severity": "Critical"}}
  ],
  "hosts_with_critical": ["1.2.3.4", "5.6.7.8"],
  "immediate_action_required": [
    "1.2.3.4:6379 — Redis with no auth, CVSS 9.8, patch immediately",
    "5.6.7.8:3389 — RDP exposed, CVE-XXXX-YYYY"
  ]
}}
""",
        expected_output=(
            "JSON: vulnerability_summary{}, top_vulnerabilities[], service_exposures[], "
            "shodan_uri_findings[], wayback_findings[], "
            "hosts_with_critical[], immediate_action_required[]"
        ),
        agent=agent,
        context=[cve_intel_task],
    )

    return [cve_intel_task, detection_task]
