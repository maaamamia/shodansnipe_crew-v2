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
from crewai import Agent, Task
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import requests

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
            "alternative_domains": [
                f"{domain_root}.io", f"{domain_root}.net", f"{domain_root}.org",
                f"{domain_root}-dev.{tld}", f"{domain_root}-staging.{tld}",
                f"{domain_root}-uat.{tld}", f"{domain_root}corp.{tld}",
                f"{domain_root}inc.{tld}", f"my{domain_root}.{tld}",
            ],
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
            "hunt_hypotheses": [
                f"HYPOTHESIS 1: {org_name} has a VPN or Citrix gateway exposed — target: "
                f"vpn.{domain or domain_root+'.com'}, remote.{domain or domain_root+'.com'}",
                f"HYPOTHESIS 2: Dev/staging environments are less hardened — target: "
                f"dev.*, staging.*, uat.*, internal.*",
                f"HYPOTHESIS 3: Acquired subsidiaries have weaker security posture — "
                f"look for related SSL cert patterns and ASNs",
                f"HYPOTHESIS 4: Cloud storage exposed — check S3/Azure/GCS naming patterns",
                f"HYPOTHESIS 5: Management interfaces on non-standard ports — "
                f"Kubernetes, Jenkins, Grafana, Elasticsearch on 8080/8443/9200/3000",
            ],
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
                f"Which services have known CVEs that are unpatched?",
                f"Are there any expired or self-signed TLS certificates?",
                f"Is email infrastructure (SPF/DMARC/CAA) properly configured?",
            ],
            "osint_directives": {
                "must_check": [
                    "Validate ASN ownership via RDAP — only include confirmed assets",
                    "Run cert transparency — flag admin/api/vpn/staging subdomains immediately",
                    "Check cloud asset patterns for all org name variants",
                    "Historical DNS — look for recently decommissioned IPs still in use",
                ],
                "high_priority_subdomains": expansions.get("subdomain_classes", [])[:10],
                "alt_domains_to_check": expansions.get("alternative_domains", [])[:6],
            },
            "recon_directives": {
                "use_osint_output_as_primary_seed": True,
                "do_not_run_generic_queries": True,
                "prioritize": ["VPN/Citrix/RDP", "CI/CD (Jenkins/GitLab)", "databases", "K8s/Docker"],
                "infra_pivot_queries": expansions.get("infra_patterns", []),
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
        ]
        for pattern, label in patterns:
            if re.search(pattern, all_text, re.I):
                critical_signals.append(label)

        return json.dumps({
            "cross_agent_hits": sorted(cross_hits, key=lambda x: x["seen_by_agents"], reverse=True)[:10],
            "all_cves": cves[:20],
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
        ],
        llm=llm,
        verbose=True,
        max_iter=8,
        allow_delegation=False,
    )


def build_manager_hunt_plan_task(agent, target_org: str,
                                  scope_query: str) -> Task:
    domain_m = re.search(r'hostname[:\s]+"?([^\s"]+)"?', scope_query)
    domain = domain_m.group(1) if domain_m else ""

    return Task(
        description=f"""
Build the hunt plan for this engagement before any searches run.

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
  Rank the top 5 highest-risk blind spots.

STEP 3 — OUTPUT as JSON:
{{
  "hunt_plan": {{
    "target": "{target_org}",
    "scope_verdict": "confirmed scope + what we\'re expanding into",
    "top_5_blind_spots": ["...", "...", "...", "...", "..."],
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
            "JSON hunt_plan with top_5_blind_spots, osint_directives, "
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

OSINT output (first 2000 chars): {osint_output[:2000]}
Recon output (first 2000 chars): {recon_output[:2000]}
Auth output (first 1500 chars):  {auth_output[:1500]}
Vuln output (first 1500 chars):  {vuln_output[:1500]}
""",
        agent=agent,
        expected_output=(
            "JSON with correlation{} and executive_summary{"
            "paragraph_1_overview, paragraph_2_critical_chain, "
            "paragraph_3_immediate_actions, overall_risk_verdict}"
        ),
    )
