"""
agents/manager_agent.py — Manager Agent

The Manager runs BEFORE any search begins. It:
1. Reads the scope and thinks creatively about the attack surface
2. Expands the target beyond the literal scope — subsidiaries, acquisitions,
   cloud tenants, CDN origins, supply chain
3. Identifies blind spots the bare scope query would miss
4. Produces a hunt plan with specific hypotheses for each agent to test
5. After all agents complete, reads their outputs and writes the executive
   summary with cross-agent correlation

This is the "what are we actually hunting for and why" layer.
"""
from __future__ import annotations
import os, json, re

# Global overridable caps — see limits.py (GLOBAL_NO_LIMITS / GLOBAL_LIMIT_MULTIPLIER / LIMIT_<KEY>).
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

from crewai import Agent, Task
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import requests

# Shared assessment doctrine (discover-don't-assume, modern-infra focus, impact-driven scoring).
try:
    from tools.doctrine import ASSESSMENT_DOCTRINE as _DOCTRINE
except ImportError:
    try:
        from doctrine import ASSESSMENT_DOCTRINE as _DOCTRINE
    except ImportError:
        _DOCTRINE = ""


def _scope_advisor_tools() -> list:
    """Evidence-based scope advisor + query expander (tools/scope_advisor.py); empty if absent."""
    for path in ("tools.scope_advisor", "scope_advisor"):
        try:
            mod = __import__(path, fromlist=["get_scope_advisor_tools"])
            return mod.get_scope_advisor_tools()
        except Exception:
            continue
    return []

SHODANSNIPE_URL = os.environ.get("SHODANSNIPE_URL", "http://127.0.0.1:8000")


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 1: Scope Expander — think beyond the literal target
# ─────────────────────────────────────────────────────────────────────────────

class ScopeExpandInput(BaseModel):
    org_name: str = Field(description="The target org name from scope")
    scope_query: str = Field(description="The raw Shodan scope query")
    domain: str = Field(default="", description="Primary domain if known")

class ScopeExpanderTool(BaseTool):
    name: str = "expand_scope"
    description: str = (
        "Think creatively about what belongs to this org beyond the literal scope. "
        "Returns: likely subsidiaries, acquisitions, CDN origins, cloud tenants, "
        "M&A targets, joint ventures, and outsourced infrastructure that might "
        "still expose the org's data. Use to build the hunt plan."
    )
    args_schema: type = ScopeExpandInput

    def _run(self, org_name: str, scope_query: str, domain: str = "") -> str:
        # Pull what we know from server scope
        scope_data = {}
        try:
            r = requests.get(f"{SHODANSNIPE_URL}/api/scope", timeout=5)
            if r.ok:
                scope_data = r.json()
        except Exception:
            pass

        # Build creative expansion based on patterns
        domain_root = domain.split(".")[0] if domain else org_name.lower().replace(" ", "")
        tld = domain.split(".")[-1] if domain and "." in domain else "com"

        expansions = {
            # NAME-GUESS CANDIDATES ONLY — these are permutations, not discovered assets.
            # They must NOT enter scope. OSINT derives the real related domains from evidence
            # (cert transparency CN/SAN, reverse WHOIS, historical DNS); these are just low-
            # confidence seeds to verify (does it resolve? does it tie to the org?).
            "candidate_alt_domains_unverified": [
                f"{domain_root}.io", f"{domain_root}.net", f"{domain_root}.org",
                f"{domain_root}-dev.{tld}", f"{domain_root}-staging.{tld}",
                f"{domain_root}-uat.{tld}", f"{domain_root}corp.{tld}",
                f"{domain_root}inc.{tld}", f"my{domain_root}.{tld}",
            ],
            "alt_domain_note": (
                "UNVERIFIED name guesses. Do NOT scope or even search these blindly. OSINT must "
                "CONFIRM each (resolves in DNS + ties to the org via cert/WHOIS) before it counts."
            ),
            "cloud_tenant_patterns": [
                f"{domain_root}.sharepoint.com",
                f"{domain_root}.onmicrosoft.com",
                f"{domain_root}.awsapps.com",
                f"s3.amazonaws.com/{domain_root}*",
                f"{domain_root}*.blob.core.windows.net",
                f"{domain_root}*.azurewebsites.net",
                f"{domain_root}*.azurefd.net",
                f"{domain_root}*.cloudfront.net",
            ],
            "infra_patterns": [
                f"ssl.cert.subject.cn:{domain or domain_root}",
                f'http.title:"{org_name}"',
                f'http.html:"{org_name}"',
                f'http.server:"{domain_root}"',
                f"ssl.cert.subject.o:{org_name}",
            ],
            "subdomain_classes": [
                "vpn", "remote", "citrix", "rdweb", "owa", "mail", "webmail",
                "admin", "portal", "login", "sso", "auth", "id",
                "api", "api-v2", "gateway", "gw",
                "dev", "staging", "uat", "test", "preprod", "qa",
                "jenkins", "jira", "confluence", "gitlab", "github-enterprise",
                "grafana", "kibana", "prometheus", "splunk",
                "backup", "ftp", "sftp", "ssh", "jump", "bastion",
            ],
            "blind_spots_to_check": [
                f"Acquired companies that still expose {org_name} data",
                "CDN origin IPs that bypass WAF",
                "Development/staging environments often on separate ASNs",
                "Cloud resources in non-primary regions",
                "Third-party contractors hosting {org_name} assets",
                "Legacy infrastructure on old ASNs before recent acquisitions",
                "Email infrastructure (MX servers, mail gateways)",
                "Certificate transparency for wildcard certs — reveals all subdomains",
            ],
            "acquisition_subsidiary_patterns": [
                f"ssl.cert.subject.o:{org_name}            (same cert Org across IPs = sibling infra)",
                "Pivot on registrant WHOIS / reverse-WHOIS to find brands under the same owner",
                "Sibling/adjacent ASNs (AS numbers near a confirmed org ASN often share ownership)",
                "Legacy brand names + the parent's cert CN appearing together",
            ],
            "third_party_saas_tenants": [
                f"{domain_root}.statuspage.io", f"{domain_root}.zendesk.com",
                f"{domain_root}.atlassian.net", f"{domain_root}.service-now.com",
                f"{domain_root}.my.salesforce.com", f"{domain_root}.okta.com",
                f"{domain_root}.bamboohr.com", f"{domain_root}.workday.com",
            ],
            "naming_conventions": [
                "Env tiers: dev / qa / uat / stg / staging / preprod / prod / dr / sandbox",
                "Region/geo codes: us / eu / emea / apac / na / -east / -west / -1 / -2",
                "DC/site codes: dc1 / dc2 / site-a / colo / az1 / az2",
                "Function prefixes: int(ernal) / ext(ernal) / pub / priv / corp / lab",
            ],
            "port_hypotheses": [
                "Non-standard web: 8080 8443 8000 8888 9000 9443 4443 10443",
                "Mgmt/observability: 3000(Grafana) 5601(Kibana) 9090(Prom) 8500(Consul) 8200(Vault) 15672(RabbitMQ)",
                "Data: 9200 9300(Elastic) 27017(Mongo) 6379(Redis) 5984(Couch) 5432 1433 1521 3306",
                "Orchestration: 2375 2376(Docker) 6443 10250(K8s) 2379(etcd) 9000(Portainer)",
            ],
            "hunt_hypotheses": [
                f"H1  Remote-access gateway exposed (VPN/Citrix/RDWeb/GlobalProtect/Pulse) — "
                f"vpn.*, remote.*, gw.*, access.* on 443/4443/10443.",
                f"H2  Dev/staging/UAT/QA/preprod less hardened, often on separate ASNs/clouds — "
                f"dev.*, staging.*, uat.*, qa.*, test.*, sandbox.*.",
                f"H3  Acquired subsidiaries / legacy brands still expose {org_name} data — pivot on "
                f"shared cert Org, registrant WHOIS, sibling ASNs.",
                f"H4  Cloud storage / tenants exposed — S3/Azure Blob/GCS buckets, SharePoint / "
                f"onmicrosoft / awsapps tenants.",
                f"H5  Management interfaces on non-standard ports — Jenkins/Grafana/Kibana/Elastic/"
                f"K8s/Consul/Vault (see port_hypotheses).",
                f"H6  Exposed ORIGINS behind the CDN/WAF — same cert CN on an org-owned ASN, "
                f"bypassing Cloudflare/Akamai.",
                f"H7  API & doc surface — Swagger/OpenAPI/GraphQL/Actuator at /api,/v1,/swagger,"
                f"/graphql,/actuator.",
                f"H8  Forgotten/decommissioned hosts — historical DNS still live; dangling CNAMEs "
                f"(subdomain takeover).",
                f"H9  Mail & directory surface — MX/SMTP/IMAP, OWA/Exchange, LDAP, open relays, "
                f"SPF/DMARC gaps.",
                f"H10 CI/CD & source — GitLab/GitHub Enterprise/Jenkins/Artifactory/Nexus/SonarQube.",
                f"H11 Data stores reachable — Mongo/Elastic/Redis/Couch/Postgres/MSSQL weak/no auth.",
                f"H12 Containers/orchestration — Docker API, Kubernetes API/Kubelet, etcd.",
                f"H13 IoT/OT/edge — printers, cameras, BMS, ICS/SCADA on org nets (502/102/47808).",
                f"H14 Third-party SaaS tenants leaking branding — statuspage/zendesk/atlassian/"
                f"servicenow/salesforce communities.",
                f"H15 Regional/geo footprint — assets in non-primary countries (different ASNs, "
                f"country codes) frequently unmonitored.",
            ],
            "hypothesis_note": (
                "Every item above is a HYPOTHESIS to TEST, not a confirmed asset. Hand these to "
                "OSINT/Recon as leads; each must pass the scope + ownership test before it counts. "
                "Generate MORE org-specific hypotheses from what recon actually finds — this list "
                "is a starting kit, not a ceiling."
            ),
        }

        return json.dumps({
            "org": org_name,
            "scope_query": scope_query,
            "scope_data": scope_data,
            "expansions": expansions,
        }, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 2: Hunt Plan Builder
# ─────────────────────────────────────────────────────────────────────────────

class HuntPlanInput(BaseModel):
    org_name: str = Field(description="Target org name")
    expansion_results: str = Field(description="JSON from expand_scope tool")
    threat_context: str = Field(
        default="",
        description="Any known threat context e.g. 'ransomware group targeting this sector'"
    )

class HuntPlanTool(BaseTool):
    name: str = "build_hunt_plan"
    description: str = (
        "Build a structured hunt plan from the scope expansion results. "
        "Assigns specific hypotheses to each agent, defines success criteria, "
        "and identifies the highest-priority questions to answer. "
        "Returns a machine-readable plan that each agent can act on."
    )
    args_schema: type = HuntPlanInput

    def _run(self, org_name: str, expansion_results: str,
             threat_context: str = "") -> str:
        try:
            exp = json.loads(expansion_results)
        except Exception:
            exp = {}

        expansions = exp.get("expansions", {})

        plan = {
            "target": org_name,
            "threat_context": threat_context or "General attack surface assessment",
            "priority_questions": [
                f"Is there a VPN/remote-access gateway exposed to the internet?",
                f"Are there any unauthenticated management interfaces (Jenkins, Grafana, K8s)?",
                f"Are cloud storage buckets/blobs publicly accessible?",
                f"Are there development or staging environments weaker than prod?",
                f"Are there exposed services needing attention?",
                f"Which services have known CVEs that are unpatched?",
                f"Are there any expired or self-signed TLS certificates?",
                f"Is email infrastructure (SPF/DMARC/CAA) properly configured?",
            ],
            "osint_directives": {
                "must_check": [
                    "Validate ASN ownership via RDAP — only include confirmed assets",
                    "Run cert transparency — flag admin/api/vpn/staging subdomains immediately",
                    "DERIVE related/alternative domains from EVIDENCE — cert CN/SAN, reverse "
                    "WHOIS, historical DNS — not from name guesses. A domain enters scope only "
                    "if it RESOLVES and ties to the org.",
                    "Treat candidate_alt_domains_unverified as low-confidence seeds: confirm or "
                    "discard each; never scope an unconfirmed guess.",
                    "Historical DNS — look for recently decommissioned IPs still in use",
                ],
                "high_priority_subdomains": expansions.get("subdomain_classes", [])[:10],
                "alt_domain_candidates_unverified": expansions.get("candidate_alt_domains_unverified", [])[:6],
            },
            "recon_directives": {
                "osint_is_seed_not_boundary": True,
                "require_independent_coverage": (
                    "After running the OSINT seed, RUN the systematic Layer B port-group sweeps, "
                    "ASN/net sweeps, and pivots — anchored to scope — to find what OSINT missed. "
                    "'No generic queries' means no UNANCHORED org-only dumps; it does NOT mean "
                    "'only run the OSINT leads'. Independent discovery is required every run."
                ),
                "prioritize": ["VPN/Citrix/RDP", "CI/CD (Jenkins/GitLab)", "databases", "K8s/Docker"],
                "infra_pivot_queries": expansions.get("infra_patterns", []),
                "fingerprint_pivots": [
                    "http.favicon.hash:<hash>  — same favicon = same app/clone (find forgotten copies)",
                    "http.html_hash:<hash>     — identical page body across hosts (staging/mirrors)",
                    "ssl.cert.serial:<serial>  — reused cert = sibling/origin infra",
                    "jarm:<jarm>               — same TLS stack fingerprint (origin behind CDN)",
                ],
                "fingerprint_pivot_rule": (
                    "Derive these from hosts ALREADY confirmed in-scope, then pivot. IMPORTANT: a "
                    "pivot that returns a HUGE result set means the fingerprint is GENERIC/shared "
                    "(a common favicon, a default cert, a popular JARM) — that is a signal to "
                    "ANALYZE and cross-reference (intersect with scope anchors / cert CN / org), "
                    "NOT to exclude the pivot or drop the hosts. Tighten, don't discard. A pivot "
                    "with a small, specific result set is high-confidence sibling infrastructure."
                ),
            },
            "auth_directives": {
                "focus_on": [
                    "Any OAuth/SSO misconfiguration on login portals",
                    "JWT secrets or tokens in API responses",
                    "Admin panels without authentication",
                    "Sensitive paths on development hosts",
                ],
            },
            "vuln_directives": {
                "focus_on": [
                    "CVEs with CVSS >= 9.0 first",
                    "RCE and Auth Bypass CVEs over information disclosure",
                    "Use Wayback Machine on any host with exposed admin paths",
                    "Full Shodan banner pull on all Critical hosts",
                ],
            },
            "hypotheses": expansions.get("hunt_hypotheses", []),
            "blind_spots": expansions.get("blind_spots_to_check", []),
        }

        return json.dumps(plan, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 3: Cross-Agent Correlator (runs after all agents complete)
# ─────────────────────────────────────────────────────────────────────────────

class CorrelateInput(BaseModel):
    osint_output: str = Field(description="OSINT agent output JSON")
    recon_output: str = Field(description="Recon agent output JSON")
    auth_output: str = Field(description="Auth agent output JSON")
    vuln_output: str = Field(description="Vuln agent output JSON")

class CrossCorrelatorTool(BaseTool):
    name: str = "correlate_findings"
    description: str = (
        "Correlate findings across all four agents to identify patterns that no "
        "single agent would see alone. For example: OSINT found a subdomain, "
        "Recon found it exposed on port 8080, Auth found it has no authentication, "
        "Vuln found it runs a CVE-affected version — this is a critical chain. "
        "Use to produce the executive summary cross-correlation section."
    )
    args_schema: type = CorrelateInput

    def _run(self, osint_output: str, recon_output: str,
             auth_output: str, vuln_output: str) -> str:
        # Extract IPs mentioned across outputs
        all_text = " ".join([osint_output, recon_output, auth_output, vuln_output])
        ips = list(set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', all_text)))

        # Find IPs mentioned in multiple outputs (cross-agent hits)
        cross_hits = []
        for ip in ips:
            count = sum([
                1 if ip in osint_output else 0,
                1 if ip in recon_output else 0,
                1 if ip in auth_output else 0,
                1 if ip in vuln_output else 0,
            ])
            if count >= 2:
                cross_hits.append({"ip": ip, "seen_by_agents": count,
                                   "note": f"Flagged by {count}/4 agents — high confidence"})

        # Find CVEs mentioned
        cves = list(set(re.findall(r'CVE-\d{4}-\d+', all_text, re.I)))

        # Find critical/high risk keywords
        critical_signals = []
        patterns = [
            (r'unauthenticated|no.auth|auth.bypass', "Unauthenticated service exposure"),
            (r'\.env|config\.json|\.git', "Sensitive file exposed"),
            (r'expired.cert|self.signed', "Certificate issue"),
            (r'default.password|default.credential', "Default credentials"),
            (r'jenkins|grafana|kibana.*exposed', "Management interface exposed"),
            (r'rdp.*exposed|3389.*open', "RDP exposed to internet"),
            (r'docker.*2375|kubernetes.*6443', "Container orchestration API exposed"),
            (r'ssh|smtp|ftp|admin|oracle', "potential exposure"),

        ]
        for pattern, label in patterns:
            if re.search(pattern, all_text, re.I):
                critical_signals.append(label)

        return json.dumps({
            "cross_agent_hits": sorted(cross_hits, key=lambda x: x["seen_by_agents"], reverse=True)[:_cap("manager_cross_hits", 50)],
            "all_cves": cves[:_cap("manager_cves", 100)],
            "critical_signals": critical_signals,
            "high_confidence_ips": [h["ip"] for h in cross_hits if h["seen_by_agents"] >= 3],
            "correlation_summary": (
                f"Found {len(cross_hits)} IPs flagged by multiple agents. "
                f"{len(cves)} unique CVEs across all findings. "
                f"{len(critical_signals)} critical signal patterns detected."
            ),
        }, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Agent builders
# ─────────────────────────────────────────────────────────────────────────────

def build_manager_agent(llm) -> Agent:
    return Agent(
        role="Attack Surface Manager",
        goal=(
            "Think creatively about the target organization's full attack surface. "
            "Go beyond the literal scope query — find subsidiaries, cloud tenants, "
            "dev environments, and supply chain exposure the org doesn't know about. "
            "Build a precise hunt plan for each agent. After all agents complete, "
            "correlate their findings into a coherent risk picture."
        ),
        backstory=(
            "You are a senior attack surface manager who has led red team engagements "
            "for Fortune 500 companies. You know that the most dangerous assets are "
            "always the ones the security team forgot about: the dev server someone "
            "spun up in AWS personal account, the acquisition that never got merged "
            "into the main firewall policy, the CDN origin IP that bypasses the WAF. "
            "You think like an attacker but speak like a CISO. You never accept "
            "the literal scope at face value — you ask: what ELSE does this org own? "
            "Your hunt plans are specific, creative, and grounded in real attacker TTPs."
        ),
        tools=[
            ScopeExpanderTool(),
            HuntPlanTool(),
            CrossCorrelatorTool(),
            *_scope_advisor_tools(),
        ],
        llm=llm,
        verbose=True,
        max_iter=8,
        allow_delegation=False,
    )


def build_manager_scope_reconciliation_task(
        agent, osint_output: str = "", recon_output: str = "",
        nmap_output: str = "") -> Task:
    """
    Runs AFTER the first OSINT+Recon discovery pass. The Manager reconciles what OSINT
    PROPOSED against what Recon (and Nmap) actually CONFIRMED, locks the authoritative
    scope, and lists the gaps worth a bounded second pass. This is where scope is truly
    DEFINED — from observed metadata, not from the up-front guess.
    """
    return Task(
        description=f"""
Reconcile scope from the FIRST discovery pass. Do not run new broad searches here — judge
what was already found and decide what (if anything) deserves a second, targeted pass.

=== OSINT OUTPUT (proposed leads) ===
{osint_output[:40000] if osint_output else "(none)"}

=== RECON OUTPUT (what Shodan actually confirmed) ===
{recon_output[:60000] if recon_output else "(none)"}

=== NMAP OUTPUT (live confirmation, if any) ===
{nmap_output[:20000] if nmap_output else "(none)"}

STEPS:
1. AUTHORITATIVE SCOPE: from the data, state the confirmed in-scope set — hosts/domains/CIDRs
   that BOTH tie to the org AND were actually observed. Keep ASN-expanded assets separate.
   You are the FINAL scope authority here — OSINT only PROPOSED; you decide with the fuller
   picture (OSINT + Recon + Nmap).
2. EVIDENCE PASS — RE-RUN THE ADVISOR (MANDATORY, not optional): you MUST call scope_advisor
   (action='advise') for EVERY host in the RECON/NMAP output whose scope status is not already
   beyond doubt — do not eyeball it, and do not rely on the up-front OSINT advice (that was made
   WITHOUT this evidence). Build each advise call from the fields you can read above:
     • candidate         = the host IP or hostname
     • rdap_org          = the host's "org" / "asn_name" from Recon
     • cert_cn           = the host's "ssl_subject" / cert CN from Recon
     • hostnames         = the host's "hostnames" (comma-separated)
     • scope_domains     = the engagement domain(s); scope_orgs = the engagement org(s)
     • in_confirmed_cidr / in_confirmed_asn = true if the IP falls in a confirmed net:/asn:
   Use NMAP as live evidence: a host Nmap shows UP with open ports is confirmed live; a host
   Nmap shows DOWN (or that Recon saw but Nmap couldn't confirm) is NOT live — push it to gaps,
   don't count it as an active exposure. Take the advisor's include/verify/exclude verdict as the
   ruling. You MAY OVERRIDE an OSINT verdict when Recon/Nmap give evidence OSINT lacked (Recon
   confirmed a host OSINT marked 'verify'; an OSINT 'include' lead never resolved). Anything the
   advisor returns 'verify' that you still can't resolve goes to gaps — never silently rejected.
2. REJECT false leads: OSINT guesses (incl. candidate_alt_domains_unverified) that did NOT
   resolve or did NOT tie to the org — list them as rejected, with the reason. Reject only on
   positive contrary evidence, not on a name that "doesn't look like" the org.
3. GAPS — what the first pass missed and should be re-engaged on (be specific, query-ready):
   - osint_leads_not_searched: confirmed OSINT subdomains/CIDRs Recon never queried.
   - alt_domains_to_verify: candidate domains that DID resolve/tie to org but weren't scoped.
   - asns_not_swept: org-owned ASNs/nets with no net:/asn: sweep yet.
   - unconfirmed_high_value: high-risk hosts seen but not version/auth-confirmed.
4. REFINED QUERIES: a SHORT, tight list (max 10) of scope-anchored Shodan queries that would
   close the biggest gaps. Anchor each to net:/asn:/cert CN — no broad org-only queries.
   - First call scope_advisor (action='expand') with the CURRENT confirmed scope (org, each
     confirmed cidr, observed products) to regenerate the combinatorial candidate set against
     what you now know, and pull the highest-value gap-closers from it.
   - INCLUDE at least one creative FINGERPRINT pivot derived from a CONFIRMED in-scope host:
     http.favicon.hash:, http.html_hash:, ssl.cert.serial:, or jarm: — these find forgotten
     origins, clones, and CDN-bypassed origins that name/port queries miss.
   - HIGH-COUNT RULE: if a fingerprint pivot would return a very large set, that means the
     fingerprint is GENERIC/shared — ANALYZE it (intersect with a scope anchor / cert CN / org),
     do NOT exclude the pivot or the hosts. Tighten the query; never drop it. A small, specific
     result set is high-confidence sibling infrastructure.

OUTPUT as JSON:
{{
  "authoritative_scope": {{"primary": ["..."], "asn_expanded": ["..."]}},
  "rejected_leads": [{{"lead": "...", "reason": "did not resolve / not org-owned"}}],
  "gaps": {{
    "osint_leads_not_searched": ["..."],
    "alt_domains_to_verify": ["..."],
    "asns_not_swept": ["AS..."],
    "unconfirmed_high_value": ["1.2.3.4:3389 RDP — version unconfirmed"]
  }},
  "refined_queries": ["net:203.0.113.0/24 port:3389", "ssl.cert.subject.cn:acme.com -org:\\"Akamai Technologies\\""],
  "second_pass_recommended": true
}}
""",
        agent=agent,
        expected_output=(
            "JSON: authoritative_scope{primary,asn_expanded}, rejected_leads[], "
            "gaps{osint_leads_not_searched,alt_domains_to_verify,asns_not_swept,"
            "unconfirmed_high_value}, refined_queries[] (≤10, anchored), second_pass_recommended"
        ),
    )


def build_manager_hunt_plan_task(agent, target_org: str,
                                  scope_query: str) -> Task:
    domain_m = re.search(r'hostname[:\s]+"?([^\s"]+)"?', scope_query)
    domain = domain_m.group(1) if domain_m else ""

    return Task(
        description=f"""
Build the hunt plan for this engagement before any searches run.
{_DOCTRINE}
Target : {target_org}
Scope  : {scope_query}
Domain : {domain or "(infer from org name)"}

STEP 1 — EXPAND SCOPE:
  Call expand_scope("{target_org}", "{scope_query}", "{domain}")
  Think creatively: what else does this org own beyond the literal scope?
  Subsidiaries, acquisitions, cloud tenants, legacy infra, dev environments.

STEP 2 — BUILD HUNT PLAN:
  Call build_hunt_plan with the expansion results.
  Assign specific hypotheses to each downstream agent.
  Rank the top 100 highest-risk blind spots.

STEP 3 — OUTPUT as JSON:
{{
  "hunt_plan": {{
    "target": "{target_org}",
    "scope_verdict": "confirmed scope + what we\'re expanding into",
    "top_100_blind_spots": ["...", "...", "...", "...", "..."],
    "osint_directives": {{...}},
    "recon_directives": {{...}},
    "auth_directives": {{...}},
    "vuln_directives": {{...}},
    "creative_pivots": [
      {{"hypothesis": "...", "why": "...", "shodan_query": "..."}}
    ]
  }}
}}
""",
        agent=agent,
        expected_output=(
            "JSON hunt_plan with top_100_blind_spots, osint_directives, "
            "recon_directives, auth_directives, vuln_directives, creative_pivots[]"
        ),
    )


def build_manager_correlation_task(agent, osint_output: str,
                                    recon_output: str, auth_output: str,
                                    vuln_output: str) -> Task:
    return Task(
        description=f"""
All agents have completed. Correlate their findings.

Call correlate_findings with the outputs from all four agents.

Then write a 3-paragraph executive summary:
1. What we found (scope, scale, severity distribution)
2. The most dangerous cross-agent finding (IP seen by multiple agents, chain of issues)
3. The three things that must be fixed this week and why

OUTPUT as JSON:
{{
  "correlation": {{...from tool...}},
  "executive_summary": {{
    "paragraph_1_overview": "...",
    "paragraph_2_critical_chain": "...",
    "paragraph_3_immediate_actions": "...",
    "overall_risk_verdict": "CRITICAL|HIGH|MEDIUM|LOW",
    "risk_justification": "one sentence"
  }}
}}

OSINT output: {osint_output[:20000]}
Recon output: {recon_output[:60000]}
Auth output:  {auth_output[:15000]}
Vuln output:  {vuln_output[:40000]}
""",
        agent=agent,
        expected_output=(
            "JSON with correlation{} and executive_summary{"
            "paragraph_1_overview, paragraph_2_critical_chain, "
            "paragraph_3_immediate_actions, overall_risk_verdict}"
        ),
    )
