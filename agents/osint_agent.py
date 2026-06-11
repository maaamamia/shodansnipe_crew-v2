"""
agents/osint_agent.py — OSINT Intelligence & Scope Validation Agent

Runs IN PARALLEL with the Shodan Recon agent.

Responsibilities:
  1. Validate that ASNs and IPs collected by Recon actually belong to the target
     (prevents wasted credits and false findings on third-party infrastructure)
  2. Discover shadow/uncovered assets not visible in Shodan:
     - Certificate Transparency logs (crt.sh) — finds subdomains
     - WHOIS / RDAP — confirms org ownership of IP blocks
     - Reverse WHOIS — find other domains registered to same org
     - Google/Bing dork queries (structured, no scraping)
     - GitHub org discovery — exposed repos, leaked secrets
     - Shodan favicon hash pivoting — find related infrastructure
     - Cloud bucket enumeration patterns (S3, GCS, Azure Blob naming)
     - Historical DNS (SecurityTrails-style patterns)
  3. Pass validated scope + uncovered assets to Shodan agent and Auth agent
"""
from __future__ import annotations
import os, json, re, socket
from crewai import Agent, Task
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import requests

SHODANSNIPE_URL = os.environ.get("SHODANSNIPE_URL", "http://127.0.0.1:8000")


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 1: Certificate Transparency — crt.sh
# Finds subdomains not in Shodan, including expired/staging/internal certs
# ─────────────────────────────────────────────────────────────────────────────
class CertTransparencyInput(BaseModel):
    domain: str = Field(description="Base domain to search e.g. acme.com")
    include_expired: bool = Field(True, description="Include expired certificates")

class CertTransparencyTool(BaseTool):
    name: str = "cert_transparency"
    description: str = (
        "Query crt.sh certificate transparency logs to discover ALL subdomains "
        "for a domain — including staging, dev, internal, and wildcard certs. "
        "Finds assets that Shodan hostname search misses. Returns unique subdomains "
        "and generates ready-to-run Shodan queries."
    )
    args_schema: type = CertTransparencyInput

    def _run(self, domain: str, include_expired: bool = True) -> str:
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            r = requests.get(url, timeout=20,
                             headers={"User-Agent": "Mozilla/5.0 ShodanSnipe/1.0"})
            if not r.ok:
                return json.dumps({"error": f"crt.sh returned {r.status_code}"})

            entries = r.json()
            subdomains = set()
            wildcard_domains = set()

            for e in entries:
                name = e.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.startswith("*."):
                        wildcard_domains.add(n[2:])
                    elif domain in n and n != domain:
                        subdomains.add(n)

            # Interesting subdomains that warrant auth/probe analysis
            interesting_patterns = [
                "api", "admin", "portal", "dashboard", "login", "sso", "auth",
                "vpn", "remote", "dev", "staging", "test", "beta", "internal",
                "corp", "intranet", "manage", "mgmt", "ops", "monitor", "status",
                "cdn", "static", "assets", "mail", "smtp", "mx", "ftp", "sftp",
                "jenkins", "jira", "confluence", "gitlab", "github", "bitbucket",
                "kibana", "grafana", "prometheus", "elastic", "splunk",
                "s3", "blob", "storage", "bucket", "backup", "archive",
            ]

            flagged = [s for s in subdomains
                       if any(p in s.split(".")[0] for p in interesting_patterns)]

            # Generate Shodan queries for discovered subdomains
            shodan_queries = []
            for sub in list(subdomains)[:20]:
                shodan_queries.append(f"hostname:{sub}")
            # Also ssl.cert query for the domain
            shodan_queries.append(f'ssl.cert.subject.cn:"{domain}"')
            shodan_queries.append(f'ssl.cert.subject.cn:"*.{domain}"')

            return json.dumps({
                "domain": domain,
                "total_subdomains": len(subdomains),
                "subdomains": sorted(list(subdomains))[:100],
                "wildcard_certs": list(wildcard_domains)[:20],
                "high_interest_subdomains": flagged[:30],
                "shodan_queries": shodan_queries[:15],
                "note": f"Found {len(entries)} cert log entries",
            }, indent=2)

        except Exception as e:
            return json.dumps({"error": str(e)})


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 2: IP/ASN Ownership Validation — RDAP + WHOIS
# Confirms IP block actually belongs to the target before reporting findings
# ─────────────────────────────────────────────────────────────────────────────
class OwnershipValidateInput(BaseModel):
    ip_or_asn: str = Field(description="IP address or ASN to validate e.g. '1.2.3.4' or 'AS15169'")
    expected_org: str = Field(description="Expected org name to match against e.g. 'Acme Corp'")
    hostnames: list[str] = Field(default_factory=list,
        description="Hostnames/cert names Shodan saw for this IP (e.g. ['api.acme.com']). "
                    "Used to confirm cloud-hosted assets that RDAP can't.")
    scope_domains: list[str] = Field(default_factory=list,
        description="In-scope domains (e.g. ['acme.com']). A hostname ending in one of these "
                    "confirms ownership even on AWS/Azure/GCP.")


# Hyperscalers / CDNs: the registered IP-block owner here is the provider, NOT the asset
# owner — so RDAP/ASN can neither confirm nor deny org ownership. Never high-confidence
# "out-of-scope" just because the block is one of these.
_SHARED_INFRA = (
    "amazon", "aws", "amazon-02", "amazon-aes", "amazon technologies",
    "microsoft", "azure", "msft", "google", "google cloud", "gcp", "google-cloud",
    "cloudflare", "digitalocean", "linode", "akamai", "fastly", "ovh", "hetzner",
    "oracle cloud", "oraclecloud", "alibaba", "tencent", "vultr", "leaseweb",
    "stackpath", "incapsula", "sucuri", "cloudfront",
)


def _is_shared_infra(text: str) -> str | None:
    t = (text or "").lower()
    for p in _SHARED_INFRA:
        if p in t:
            return p
    return None


def _hostname_matches_scope(hostnames, scope_domains) -> str | None:
    for h in (hostnames or []):
        hl = str(h).lower().strip(".")
        for d in (scope_domains or []):
            dl = str(d).lower().strip(".")
            if dl and (hl == dl or hl.endswith("." + dl)):
                return f"{h} \u2192 {d}"
    return None


def _decide_verdict(actual_org, expected_lower, hostnames, scope_domains):
    """Cloud-aware ownership decision. Returns (verdict, confidence, evidence_note)."""
    combined = (actual_org or "").lower()
    words = [w for w in re.split(r'\W+', expected_lower) if len(w) > 3]
    matches = [w for w in words if w in combined]

    # 1) A hostname/cert tied to a scope domain proves ownership — even on the cloud.
    hit = _hostname_matches_scope(hostnames, scope_domains)
    if hit:
        return "confirmed", "high", f"hostname/cert ties to scope domain ({hit}) \u2014 cloud-hosted is fine"

    # 2) RDAP/ASN org actually matches the expected org.
    if len(matches) >= 2 or (len(matches) >= 1 and len(words) <= 2):
        return "confirmed", "high", None
    if matches:
        return "likely", "medium", None

    # 3) On shared cloud/CDN infra: RDAP can't decide. NEUTRAL, do NOT drop.
    prov = _is_shared_infra(combined)
    if prov:
        return ("cloud-hosted", "low",
                f"on {prov} shared infra \u2014 RDAP/ASN cannot decide ownership; "
                f"keep the host if a hostname/cert/DNS ties it to the target, do not drop "
                f"solely for being on {prov}")

    # 4) Dedicated block, no match → genuinely out of scope.
    return "out-of-scope", "high", None


class OwnershipValidateTool(BaseTool):
    name: str = "validate_ownership"
    description: str = (
        "Validate whether an IP/ASN belongs to the target. RDAP/ASN identifies the IP-BLOCK "
        "owner, which on AWS/Azure/GCP/Cloudflare is the cloud provider, NOT the asset owner. "
        "Verdicts: confirmed (in-scope), likely, cloud-hosted (shared infra \u2014 KEEP the host "
        "if any hostname/cert/DNS ties it to the target; do NOT drop just for being on the "
        "cloud), or out-of-scope (dedicated block, no match). Pass hostnames + scope_domains "
        "so cloud-hosted assets can be confirmed."
    )
    args_schema: type = OwnershipValidateInput

    def _run(self, ip_or_asn: str, expected_org: str,
             hostnames: list = None, scope_domains: list = None) -> str:
        hostnames = hostnames or []
        scope_domains = scope_domains or []
        result = {
            "target": ip_or_asn,
            "expected_org": expected_org,
            "verdict": "unknown",
            "confidence": "low",
            "actual_org": None,
            "actual_country": None,
            "rdap_source": None,
            "evidence": [],
        }
        try:
            expected_lower = expected_org.lower()

            if ip_or_asn.upper().startswith("AS"):
                # ASN lookup via BGPView
                asn_num = ip_or_asn.upper().replace("AS", "")
                r = requests.get(f"https://api.bgpview.io/asn/{asn_num}",
                                 timeout=10)
                if r.ok:
                    data = r.json().get("data", {})
                    name = data.get("name", "")
                    desc = data.get("description_short", "")
                    country = data.get("country_code", "")
                    result["actual_org"] = name
                    result["actual_country"] = country
                    result["rdap_source"] = "BGPView"

                    combined = f"{name} {desc}".lower()
                    verdict, conf, note = _decide_verdict(
                        f"{name} {desc}", expected_lower, hostnames, scope_domains)
                    result["verdict"] = verdict
                    result["confidence"] = conf
                    result["evidence"] = [f"BGPView: {name} — {desc} ({country})"]
                    if note:
                        result["evidence"].append(note)

            else:
                # IP lookup via RDAP
                # Try ARIN first, then RIPE
                rdap_url = f"https://rdap.arin.net/registry/ip/{ip_or_asn}"
                r = requests.get(rdap_url, timeout=10,
                                 headers={"Accept": "application/rdap+json"})
                if not r.ok:
                    rdap_url = f"https://rdap.db.ripe.net/ip/{ip_or_asn}"
                    r = requests.get(rdap_url, timeout=10)

                if r.ok:
                    data = r.json()
                    # Extract org name from entities
                    org_name = ""
                    country = data.get("country", "")
                    for entity in data.get("entities", []):
                        for vcard in entity.get("vcardArray", [[], []])[1]:
                            if vcard[0] == "fn":
                                org_name = vcard[3]
                                break
                        if org_name:
                            break
                    if not org_name:
                        org_name = data.get("name", "")

                    result["actual_org"] = org_name
                    result["actual_country"] = country
                    result["rdap_source"] = rdap_url.split("/")[2]

                    combined = org_name.lower()
                    verdict, conf, note = _decide_verdict(
                        org_name, expected_lower, hostnames, scope_domains)
                    result["verdict"] = verdict
                    result["confidence"] = conf
                    result["evidence"] = [f"RDAP: {org_name} ({country})"]
                    if note:
                        result["evidence"].append(note)

        except Exception as e:
            result["error"] = str(e)

        return json.dumps(result, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 3: Cloud Asset Discovery
# S3 bucket naming patterns, Azure blob, GCS — common org naming conventions
# ─────────────────────────────────────────────────────────────────────────────
class CloudAssetInput(BaseModel):
    org_name: str = Field(description="Org name to generate cloud asset patterns from e.g. 'Acme Corp'")
    domain: str = Field("", description="Primary domain e.g. 'acme.com'")

class CloudAssetTool(BaseTool):
    name: str = "cloud_asset_discovery"
    description: str = (
        "Generate and check common cloud asset patterns for an org: "
        "S3 buckets, Azure Blob containers, GCS buckets, Shodan queries. "
        "Returns naming patterns and Shodan queries to find exposed cloud infrastructure."
    )
    args_schema: type = CloudAssetInput

    def _run(self, org_name: str, domain: str = "") -> str:
        # Generate name variations
        base_names = []
        clean = re.sub(r'[^\w]', '', org_name.lower().replace(" ", ""))
        clean_dash = org_name.lower().replace(" ", "-").replace("_", "-")
        clean_dash = re.sub(r'[^\w-]', '', clean_dash)

        base_names = list({clean, clean_dash, clean[:10], clean[:6]})
        if domain:
            dom_base = domain.split(".")[0]
            base_names.append(dom_base)

        # S3 bucket patterns
        s3_patterns = []
        suffixes = ["", "-prod", "-dev", "-staging", "-backup", "-data", "-assets",
                    "-public", "-private", "-logs", "-archive", "-static", "-media",
                    "-uploads", "-files", "-content", "-cdn"]
        for base in base_names[:3]:
            for suf in suffixes[:8]:
                s3_patterns.append(f"{base}{suf}")

        # Shodan queries for cloud exposure
        shodan_queries = []
        for base in base_names[:3]:
            # S3 bucket exposure
            shodan_queries.append(f'http.title:"{base}" http.component:"Amazon S3"')
            # Azure
            shodan_queries.append(f'hostname:"{base}.blob.core.windows.net"')
            # Exposed Kubernetes
            shodan_queries.append(f'product:"Kubernetes" http.title:"{org_name}"')
            # Exposed databases with org name
            shodan_queries.append(f'product:"MongoDB" http.title:"{base}"')

        # GitHub search hints (can't automate — needs auth)
        github_hints = [
            f"https://github.com/{clean}",
            f"https://github.com/search?q={clean_dash}+password&type=code",
            f"https://github.com/search?q={clean_dash}+api_key&type=code",
            f"https://github.com/search?q={clean_dash}+secret&type=code",
        ]

        return json.dumps({
            "org_name": org_name,
            "name_variations": base_names,
            "s3_bucket_patterns": s3_patterns[:20],
            "shodan_queries": shodan_queries[:12],
            "github_search_hints": github_hints,
            "note": "Run shodan_queries in the Shodan agent. Check GitHub hints manually.",
        }, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 4: Reverse WHOIS / Org Footprint
# Find other domains/IPs registered to same org
# ─────────────────────────────────────────────────────────────────────────────
class ReverseWhoisInput(BaseModel):
    org_name: str = Field(description="Org name to find related domains/IPs for")

class ReverseWhoisTool(BaseTool):
    name: str = "reverse_whois"
    description: str = (
        "Find other domains and infrastructure registered to the same org. "
        "Uses BGPView org search and ARIN RDAP to find related netblocks. "
        "Surfaces shadow IT and subsidiaries not in the initial scope."
    )
    args_schema: type = ReverseWhoisInput

    def _run(self, org_name: str) -> str:
        result = {
            "org_name": org_name,
            "related_asns": [],
            "related_prefixes": [],
            "shodan_queries": [],
            "potential_subsidiaries": [],
        }
        try:
            # BGPView org search
            r = requests.get("https://api.bgpview.io/search",
                             params={"query_term": org_name}, timeout=12)
            if r.ok:
                data = r.json().get("data", {})
                asns = data.get("asns", [])
                prefixes = data.get("prefixes", [])

                result["related_asns"] = [
                    {"asn": f"AS{a['asn']}", "name": a.get("name", ""),
                     "country": a.get("country_code", "")}
                    for a in asns[:15]
                ]
                result["related_prefixes"] = [
                    {"prefix": p.get("prefix", ""), "name": p.get("name", "")}
                    for p in prefixes[:10]
                ]
                result["shodan_queries"] = [
                    f"asn:AS{a['asn']}" for a in asns[:5]
                ] + [
                    f"net:{p.get('prefix','')}" for p in prefixes[:3] if p.get("prefix")
                ]

                # Check for potential subsidiaries (different ASN name, same org search)
                main_words = set(re.split(r'\W+', org_name.lower()))
                for a in asns:
                    asn_name = a.get("name", "").lower()
                    asn_words = set(re.split(r'\W+', asn_name))
                    if not asn_words.intersection(main_words):
                        result["potential_subsidiaries"].append({
                            "asn": f"AS{a['asn']}",
                            "name": a.get("name", ""),
                            "note": "Different name — may be subsidiary or acquired company",
                        })

        except Exception as e:
            result["error"] = str(e)

        return json.dumps(result, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 5: Historical DNS & Infrastructure Patterns
# Finds what Shodan's current snapshot might miss
# ─────────────────────────────────────────────────────────────────────────────
class HistoricalDNSInput(BaseModel):
    domain: str = Field(description="Domain to check historical DNS for")

class HistoricalDNSTool(BaseTool):
    name: str = "historical_dns"
    description: str = (
        "Check historical DNS records and infrastructure patterns for a domain. "
        "Uses HackerTarget, ViewDNS public APIs, and passive DNS sources. "
        "Finds IPs that hosted the domain in the past (may still be in use)."
    )
    args_schema: type = HistoricalDNSInput

    def _run(self, domain: str) -> str:
        result = {
            "domain": domain,
            "historical_ips": [],
            "related_domains": [],
            "shodan_queries": [],
            "note": "",
        }
        try:
            # HackerTarget passive DNS
            r = requests.get(
                "https://api.hackertarget.com/hostsearch/",
                params={"q": domain}, timeout=10
            )
            if r.ok and "error" not in r.text.lower():
                lines = r.text.strip().splitlines()
                for line in lines[:30]:
                    parts = line.split(",")
                    if len(parts) >= 2:
                        hostname, ip = parts[0].strip(), parts[1].strip()
                        if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                            result["historical_ips"].append({"hostname": hostname, "ip": ip})
                            result["shodan_queries"].append(f"ip:{ip}")

            # DNS lookup for common subdomains (quick check)
            common = ["www", "api", "mail", "vpn", "remote", "admin", "portal",
                      "dev", "staging", "test", "app", "cdn", "static"]
            found_subs = []
            for sub in common:
                try:
                    ip = socket.gethostbyname(f"{sub}.{domain}")
                    found_subs.append({"subdomain": f"{sub}.{domain}", "ip": ip})
                    result["shodan_queries"].append(f"ip:{ip}")
                except Exception:
                    pass

            result["active_subdomains"] = found_subs
            result["unique_ips"] = list({item["ip"] for item in result["historical_ips"]})[:20]
            result["shodan_queries"] = list(set(result["shodan_queries"]))[:15]

        except Exception as e:
            result["error"] = str(e)

        return json.dumps(result, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# AGENT + TASK BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def build_osint_agent(llm) -> Agent:
    return Agent(
        role="OSINT Intelligence & Scope Validation Specialist",
        goal=(
            "Run in PARALLEL with the Shodan Recon agent. "
            "Validate that collected ASNs and IPs belong to the target org. "
            "Discover shadow assets not covered by Shodan: subdomains via certificate "
            "transparency, cloud assets, historical IPs, related org footprint. "
            "Hand validated scope + uncovered assets to the Shodan and Auth agents."
        ),
        backstory=(
            "You are an OSINT specialist who validates intelligence before analysts act on it. "
            "Your job is to make sure Shodan findings are actually in-scope (not third-party "
            "CDN, cloud provider, or acquired company infrastructure). "
            "You also find what Shodan misses: Certificate Transparency reveals hidden subdomains, "
            "RDAP reveals org-owned IP blocks, cloud naming patterns reveal exposed buckets, "
            "historical DNS reveals IPs that still host the target but aren't crawled recently. "
            "You give the Shodan agent a VALIDATED scope and ADDITIONAL queries to run. "
            "You flag anything that looks out-of-scope so it doesn't pollute the final report."
        ),
        tools=[
            CertTransparencyTool(),
            OwnershipValidateTool(),
            CloudAssetTool(),
            ReverseWhoisTool(),
            HistoricalDNSTool(),
        ],
        llm=llm,
        verbose=True,
        max_iter=25,
        allow_delegation=False,
        human_in_the_loop=False,
    )


def build_osint_tasks(agent, target_org: str, scope_query: str,
                     asns_from_recon: list | None = None) -> list:
    asn_list = json.dumps(asns_from_recon or [])
    domain_match = re.search(r'hostname[:\s]+"?([^\s"]+)"?', scope_query)
    domain = domain_match.group(1) if domain_match else ""

    # ── Task 1: Active footprinting — run tools, collect raw intel ────────
    footprint_task = Task(
        description=f"""
Build the intelligence footprint for {target_org}.

Target org : {target_org}
Scope query: {scope_query}
Domain hint: {domain or "(infer from org name)"}

STEP 1 — ORG FOOTPRINT:
  reverse_whois("{target_org}") — find all ASNs, prefixes, subsidiaries, related orgs.

STEP 2 — ASN VALIDATION:
  validate_ownership for each ASN found.
  Verdict per ASN: confirmed | likely | out_of_scope.
  OUT_OF_SCOPE ASNs must be clearly labelled — Recon skips them.

STEP 3 — CERTIFICATE TRANSPARENCY:
  cert_transparency("{domain or target_org.lower().replace(' ','') + '.com'}")
  Extract all subdomains. Mark high-value ones:
    admin.* api.* portal.* vpn.* remote.* staging.* dev.* uat.* backup.*
    git.* jenkins.* grafana.* kibana.* elastic.* jira.* confluence.* sso.*

STEP 4 — CLOUD ASSET DISCOVERY:
  cloud_asset_discovery("{target_org}", "{domain}")
  Find S3 buckets, Azure blobs, GCS buckets matching org naming patterns.

STEP 5 — HISTORICAL DNS:
  historical_dns("{domain or target_org}")
  Find: old IPs still in use, infrastructure changes, dangling CNAMEs,
  previously exposed subdomains.

Output raw collected data — do not filter yet. Include every ASN, IP,
subdomain, and cloud asset found, with its source and confidence level.
""",
        expected_output=(
            "Raw intelligence: all ASNs with ownership verdicts, all subdomains "
            "from cert transparency, all cloud asset patterns checked, historical IPs."
        ),
        agent=agent,
    )

    # ── Task 2: Intel synthesis — build the Recon query package ──────────
    intel_package_task = Task(
        description=f"""
Synthesise the raw footprint data into a structured intel package
that the Recon agent will use as its PRIMARY search seed.

SYNTHESIS STEPS:

1. SCOPE VERDICT:
   - List only confirmed/likely ASNs → confirmed_asns[]
   - List out_of_scope ASNs clearly → out_of_scope_asns[]
   - List all confirmed CIDRs → confirmed_cidrs[]
   - List all confirmed domains and subdomains → confirmed_domains[], high_value_subdomains[]

2. PRIORITISED SHODAN QUERY PACKAGE:
   For every confirmed asset, generate a specific Shodan query.
   Do NOT use OR/AND/NOT. One query per asset.
   Assign priority: CRITICAL | HIGH | MEDIUM

   Query types to generate:
   - hostname:<subdomain> for each high-value subdomain
   - ssl.cert.subject.cn:<domain> for cert pivots
   - org:"<confirmed org name>" for each confirmed org variant
   - net:<cidr> for each confirmed CIDR
   - http.title:"<product>" if product names found in certs
   - Cloud: http.title:"<org>" port:443 for cloud assets

   CRITICAL priority: vpn.*, rdweb.*, citrix.*, jenkins.*, admin.*
   HIGH priority:     api.*, portal.*, staging.*, dev.*, grafana.*, kibana.*
   MEDIUM priority:   general org/net queries, historical IPs

3. THREAT SURFACE NOTES:
   2-3 sentences on the most surprising or concerning thing found.
   E.g. "Found 3 dangling CNAMEs pointing to expired cloud resources —
   possible subdomain takeover candidates."

OUTPUT as JSON:
{{
  "intel_package": {{
    "confirmed_asns": ["AS12345"],
    "out_of_scope_asns": ["AS99999"],
    "confirmed_cidrs": ["1.2.3.0/24"],
    "confirmed_orgs": ["{target_org}", "subsidiary name"],
    "confirmed_domains": ["acme.com"],
    "high_value_subdomains": ["vpn.acme.com", "api.acme.com"],
    "cloud_assets_found": ["acme-backup.s3.amazonaws.com"],
    "historical_ips": ["1.2.3.4"],
    "dangling_cnames": ["old.acme.com -> expired-provider.com"]
  }},
  "shodan_query_package": [
    {{"query": "hostname:vpn.acme.com", "priority": "CRITICAL", "why": "VPN endpoint — likely internet-facing auth surface"}},
    {{"query": "ssl.cert.subject.cn:acme.com", "priority": "HIGH", "why": "cert pivot finds all TLS-enabled services"}},
    {{"query": "org:\"Acme Corp\" port:3389", "priority": "CRITICAL", "why": "RDP within org ASN"}},
    {{"query": "net:203.0.113.0/24", "priority": "MEDIUM", "why": "confirmed CIDR prefix"}}
  ],
  "scope_verdict": "Confirmed scope for {target_org}: <1 sentence summary>",
  "threat_surface_notes": "<2-3 sentences on most notable findings>"
}}
""",
        expected_output=(
            "JSON intel_package{confirmed_asns,out_of_scope_asns,confirmed_cidrs,"
            "high_value_subdomains,cloud_assets_found,historical_ips,dangling_cnames} "
            "AND shodan_query_package[{query,priority,why}] AND threat_surface_notes"
        ),
        agent=agent,
        context=[footprint_task],
    )

    return [footprint_task, intel_package_task]
