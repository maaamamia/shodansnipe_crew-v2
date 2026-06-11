"""
agents/threat_intel_agent.py — Threat Intelligence Agent

Runs AFTER Vuln agent. Takes Critical/High findings and enriches them with:
- MITRE ATT&CK TTP mapping from actual CVEs and exposed services
- Known threat actor attribution (who targets this tech stack)
- C2 infrastructure patterns — does anything look like known malware C2?
- IOC generation — IPs, domains, ports that should go to SIEM/EDR
- Historical context — has this IP/ASN been seen in threat reports?
- Dark web/paste exposure check via HackerTarget

Red Team recommendations section:
- What an attacker would do FIRST with these findings
- Specific attack chains (e.g. "RDP exposed → password spray → lateral movement")
- Estimated time-to-exploit for each Critical finding
- Prioritised hand-off list for pen testing
"""
from __future__ import annotations
import os, json, re

# Shared assessment doctrine (discover-don't-assume, modern-infra focus, impact-driven scoring).
try:
    from tools.doctrine import ASSESSMENT_DOCTRINE as _DOCTRINE
except ImportError:
    try:
        from doctrine import ASSESSMENT_DOCTRINE as _DOCTRINE
    except ImportError:
        _DOCTRINE = ""


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

from typing import Any, ClassVar
from crewai import Agent, Task
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import requests

SHODANSNIPE_URL = os.environ.get("SHODANSNIPE_URL", "http://127.0.0.1:8000")

# ─────────────────────────────────────────────────────────────────────────────
# TOOL 1: MITRE ATT&CK Lookup
# ─────────────────────────────────────────────────────────────────────────────

class MitreInput(BaseModel):
    service_or_cve: str = Field(
        description="Service name, CVE ID, or attack technique to map to MITRE ATT&CK. "
                    "Examples: 'RDP exposed', 'CVE-2021-44228', 'Jenkins unauthenticated', 'MongoDB open'"
    )

class MitreAttackTool(BaseTool):
    name: str = "mitre_attack_lookup"
    description: str = (
        "Map a discovered service, CVE, or exposure to MITRE ATT&CK TTPs. "
        "Returns relevant Tactic IDs (T-numbers), attack technique names, "
        "known threat actors using this technique, and detection opportunities. "
        "Use for every Critical and High finding to build the TTP map."
    )
    args_schema: type = MitreInput

    # Curated lookup table: service/CVE patterns → ATT&CK TTPs + actors
    ATTACK_MAP: ClassVar[dict] = {
        "rdp":          {"ttps": ["T1021.001","T1133"], "tactic": "Lateral Movement / Initial Access",
                         "actors": ["Lazarus Group","REvil","DarkSide","Vice Society"],
                         "technique": "Remote Desktop Protocol",
                         "detection": "Monitor for unusual RDP sessions, brute-force attempts, off-hours logins"},
        "ssh":          {"ttps": ["T1021.004","T1110"], "tactic": "Lateral Movement / Credential Access",
                         "actors": ["TeamTNT","Rocke","Kinsing"],
                         "technique": "SSH / Brute Force",
                         "detection": "Alert on failed SSH attempts, new authorized_keys, unusual src IPs"},
        "smb":          {"ttps": ["T1021.002","T1570","T1210"], "tactic": "Lateral Movement / Exploitation",
                         "actors": ["WannaCry","NotPetya","Emotet","Conti"],
                         "technique": "SMB / EternalBlue / Lateral Tool Transfer",
                         "detection": "Monitor SMB traffic for C$ admin shares, unusual file transfers"},
        "jenkins":      {"ttps": ["T1190","T1059.004"], "tactic": "Initial Access / Execution",
                         "actors": ["TeamTNT","Kinsing","cryptominers"],
                         "technique": "Exploit Public-Facing Application (CI/CD)",
                         "detection": "Alert on Jenkins script console access, new job creation by unknown users"},
        "elasticsearch":{"ttps": ["T1190","T1530"], "tactic": "Initial Access / Data from Cloud Storage",
                         "actors": ["Meow botnet","ransomware operators"],
                         "technique": "Unauthenticated Elasticsearch / Data Exfil",
                         "detection": "Monitor for bulk _search or DELETE index requests from external IPs"},
        "redis":        {"ttps": ["T1190","T1098","T1496"], "tactic": "Initial Access / Persistence / Resource Hijacking",
                         "actors": ["TeamTNT","Rocke","Kinsing"],
                         "technique": "Redis CONFIG SET to write SSH keys / cron jobs",
                         "detection": "Alert on Redis CONFIG SET commands from non-localhost"},
        "mongodb":      {"ttps": ["T1190","T1530"], "tactic": "Initial Access / Data from Cloud Storage",
                         "actors": ["Meow botnet","ransomware operators","data brokers"],
                         "technique": "Unauthenticated MongoDB / Data Exfil or Ransom",
                         "detection": "Monitor for connections from external IPs, collection enumeration"},
        "kubernetes":   {"ttps": ["T1190","T1609","T1613"], "tactic": "Initial Access / Container Escape",
                         "actors": ["TeamTNT","Hildegard"],
                         "technique": "Kubernetes API server / Container discovery / escape",
                         "detection": "Alert on kubectl exec from external IPs, new ClusterRoleBindings"},
        "docker":       {"ttps": ["T1190","T1610","T1611"], "tactic": "Initial Access / Deploy Container / Escape",
                         "actors": ["TeamTNT","Kinsing","cryptominers"],
                         "technique": "Unauthenticated Docker API / container escape",
                         "detection": "Monitor Docker API calls from external IPs, privileged container creation"},
        "log4j":        {"ttps": ["T1190","T1059.009","T1105"], "tactic": "Initial Access / Execution / Ingress Tool Transfer",
                         "actors": ["Aquatic Panda","Hafnium","APT35","LockBit"],
                         "technique": "Log4Shell (CVE-2021-44228) JNDI injection",
                         "detection": "Alert on ${jndi: patterns in HTTP headers/params, LDAP callbacks"},
        "log4shell":    {"ttps": ["T1190","T1059.009","T1105"], "tactic": "Initial Access / Execution",
                         "actors": ["Aquatic Panda","Hafnium","APT35"],
                         "technique": "Log4Shell (CVE-2021-44228)",
                         "detection": "IDS rules for ${jndi:ldap, DNS monitoring for unusual callbacks"},
        "exchange":     {"ttps": ["T1190","T1505.003","T1114.002"], "tactic": "Initial Access / Webshell / Email Collection",
                         "actors": ["Hafnium","LAPSUS$","Cl0p","BlackCat"],
                         "technique": "MS Exchange ProxyShell/ProxyLogon webshell",
                         "detection": "Alert on aspx files in Exchange directories, PowerShell from w3wp.exe"},
        "telnet":       {"ttps": ["T1021.001","T1040","T1110"], "tactic": "Lateral Movement / Credential Access",
                         "actors": ["Mirai botnet","IoT botnets"],
                         "technique": "Telnet cleartext protocol / credential sniffing",
                         "detection": "Block Telnet from internet; alert on any external Telnet connections"},
        "vnc":          {"ttps": ["T1021.005","T1133"], "tactic": "Remote Access",
                         "actors": ["ransomware operators","UNC2447"],
                         "technique": "VNC remote access / brute force",
                         "detection": "Alert on VNC auth failures, connections from TOR/VPN exit nodes"},
        "mssql":        {"ttps": ["T1190","T1505.001","T1059.002"], "tactic": "Initial Access / Stored Procedure Execution",
                         "actors": ["FIN7","Cl0p","ransomware operators"],
                         "technique": "MSSQL xp_cmdshell / SA brute force",
                         "detection": "Alert on xp_cmdshell enable, failed SA logins, MSSQL from external IPs"},
        "fortinet":     {"ttps": ["T1190","T1133","T1078"], "tactic": "Initial Access / Valid Accounts",
                         "actors": ["APT41","Volt Typhoon","ransomware operators"],
                         "technique": "Fortinet VPN exploit (CVE-2022-40684 etc)",
                         "detection": "Check Fortinet version, alert on config reads from external IPs"},
        "citrix":       {"ttps": ["T1190","T1133"], "tactic": "Initial Access / Remote Services",
                         "actors": ["Maze","REvil","UNC2447"],
                         "technique": "Citrix Gateway vulnerabilities (CitrixBleed etc)",
                         "detection": "Monitor Citrix ADC logs for unusual session token patterns"},
        "default":      {"ttps": ["T1190"], "tactic": "Initial Access",
                         "actors": ["opportunistic attackers","automated scanners"],
                         "technique": "Exploit Public-Facing Application",
                         "detection": "Monitor for exploit attempt patterns, unusual authentication"}
    }

    def _run(self, service_or_cve: str) -> str:
        query = service_or_cve.lower().strip()
        result = {
            "query": service_or_cve,
            "matched_techniques": [],
            "actors": [],
            "detection_opportunities": [],
            "cve_specific": {},
        }

        # Match against known patterns
        matched = []
        for key, data in self.ATTACK_MAP.items():
            if key == "default":
                continue
            if key in query or (len(key) > 4 and key in query.replace("-", "").replace(" ", "")):
                matched.append({
                    "service": key,
                    "ttps": data["ttps"],
                    "tactic": data["tactic"],
                    "technique": data["technique"],
                    "actors": data["actors"],
                    "detection": data["detection"],
                })

        if not matched:
            matched.append({**self.ATTACK_MAP["default"], "service": query})

        result["matched_techniques"] = matched
        result["actors"] = list(set(a for m in matched for a in m.get("actors", [])))
        result["detection_opportunities"] = [m.get("detection", "") for m in matched if m.get("detection")]

        # CVE-specific enrichment
        cve_ids = re.findall(r'CVE-\d{4}-\d+', service_or_cve, re.IGNORECASE)
        if cve_ids:
            result["cve_specific"]["cves"] = cve_ids
            result["cve_specific"]["note"] = (
                f"These CVEs directly enable {matched[0].get('tactic','Initial Access')}. "
                f"Patch immediately and check for IOCs of exploitation."
            )

        return json.dumps(result, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 2: Threat Actor Attribution
# ─────────────────────────────────────────────────────────────────────────────

class AttributionInput(BaseModel):
    industry: str = Field(description="Target industry e.g. 'finance', 'healthcare', 'government', 'tech'")
    ttps: list[str] = Field(default_factory=list, description="List of T-numbers e.g. ['T1190','T1021.001']")
    exposed_services: list[str] = Field(default_factory=list, description="List of exposed services")

class ThreatActorTool(BaseTool):
    name: str = "threat_actor_attribution"
    description: str = (
        "Given the target industry and discovered TTPs/services, identify the most likely "
        "threat actor groups that target this type of organization. "
        "Returns actor profiles, their known tooling, campaign history, and MITRE group IDs. "
        "Use to produce the threat actor targeting section of the report."
    )
    args_schema: type = AttributionInput

    ACTOR_DB: ClassVar[dict] = {
        "finance": ["FIN7 (G0046)", "Carbanak (G0008)", "Lazarus Group (G0032)", "UNC3944", "Scattered Spider"],
        "healthcare": ["Cl0p (G0147)", "RansomHouse", "ALPHV/BlackCat", "Vice Society", "Daixin Team"],
        "government": ["APT28 (G0007)", "APT29 (G0016)", "Volt Typhoon (G1017)", "Sandworm (G0034)", "Hafnium (G0125)"],
        "tech": ["Lazarus (G0032)", "APT41 (G0096)", "LAPSUS$ (G1004)", "TeamTNT (G0139)", "Scattered Spider"],
        "energy": ["Sandworm (G0034)", "Dragonfly (G0035)", "Volt Typhoon (G1017)", "HEXANE"],
        "retail": ["FIN7 (G0046)", "Magecart groups", "Scattered Spider", "REvil (G0115)"],
        "manufacturing": ["Lockbit (G0139)", "Cl0p (G0147)", "ALPHV", "Volt Typhoon (G1017)"],
        "default": ["opportunistic ransomware operators", "Shodan-based automated scanners", "cryptominers", "botnets"],
    }

    def _run(self, industry: str, ttps: list[str] = None, exposed_services: list[str] = None) -> str:
        ttps = ttps or []
        exposed_services = exposed_services or []
        ind = industry.lower().strip()

        actors = self.ACTOR_DB.get(ind, self.ACTOR_DB["default"])

        # Cross-reference services with high-profile campaigns
        campaigns = []
        svc_str = " ".join(exposed_services).lower()
        if "rdp" in svc_str or "3389" in svc_str:
            campaigns.append("RDP brute-force campaigns (seen in Conti, LockBit playbooks)")
        if "exchange" in svc_str or "443" in svc_str:
            campaigns.append("Exchange ProxyLogon/ProxyShell campaigns (Hafnium, LAPSUS$)")
        if "jenkins" in svc_str or "8080" in svc_str:
            campaigns.append("CI/CD supply chain attacks (TeamTNT, Kinsing)")
        if any(x in svc_str for x in ["elasticsearch","mongodb","redis","9200","27017","6379"]):
            campaigns.append("Database ransom/wipe campaigns (Meow botnet, opportunistic actors)")
        if "fortinet" in svc_str or "8443" in svc_str:
            campaigns.append("VPN exploitation campaigns (APT41, Volt Typhoon)")

        return json.dumps({
            "industry": industry,
            "likely_actors": actors,
            "relevant_campaigns": campaigns,
            "ttp_overlap": ttps,
            "risk_assessment": (
                f"Organizations in {industry} with these exposures are frequently targeted by "
                f"{actors[0] if actors else 'advanced threat actors'}. "
                f"The combination of exposed services creates {len(campaigns) or 'multiple'} high-risk scenarios."
            ),
        }, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 3: Red Team Attack Chain Builder
# ─────────────────────────────────────────────────────────────────────────────

class RedTeamInput(BaseModel):
    findings: str = Field(
        description="JSON string of Critical/High findings: list of {ip, port, service, cves, risk}"
    )
    scope: str = Field(default="", description="Target org name and scope")

class RedTeamChainTool(BaseTool):
    name: str = "red_team_attack_chains"
    description: str = (
        "Given Critical and High findings, build realistic attack chains showing exactly "
        "what a threat actor would do with these exposures. "
        "Returns: entry points ranked by ease-of-exploitation, step-by-step attack paths, "
        "estimated time-to-compromise for each, required attacker skill level, "
        "and a prioritised pen-test scope list. "
        "Use to generate the Red Team Recommendations section of the final report."
    )
    args_schema: type = RedTeamInput

    # Attack chain templates
    CHAINS: ClassVar[dict] = {
        "rdp": {
            "entry": "RDP (3389) exposed to internet",
            "steps": [
                "1. RECONNAISSANCE: Use Shodan/Censys to identify RDP version and OS",
                "2. PASSWORD SPRAY: Try common credentials with RDP client or Hydra",
                "3. VALID ACCOUNT: Establish RDP session with cracked credentials",
                "4. PERSISTENCE: Drop payload via mstsc copy-paste or mapped drive",
                "5. LATERAL MOVEMENT: Use RDP to pivot to internal hosts",
                "6. DOMAIN RECON: Run BloodHound / SharpHound for AD enumeration",
                "7. PRIVILEGE ESCALATION: Target Domain Admin or backup operators",
                "8. IMPACT: Deploy ransomware or exfiltrate data via cloud upload",
            ],
            "skill": "LOW — automated tooling available (Shodan + Hydra + Mimikatz)",
            "tte": "24-72 hours from discovery to domain compromise",
            "tools": ["Hydra", "CrackMapExec", "BloodHound", "Mimikatz", "Cobalt Strike"],
        },
        "jenkins": {
            "entry": "Jenkins CI/CD server exposed without authentication",
            "steps": [
                "1. DISCOVERY: Jenkins script console accessible at /script",
                "2. EXECUTION: POST to /script with Groovy reverse shell",
                "3. PERSISTENCE: Add new Jenkins admin user or backdoor pipeline",
                "4. PIVOTING: Access git credentials stored in Jenkins credentials store",
                "5. SUPPLY CHAIN: Modify build pipeline to inject malicious artifact",
                "6. IMPACT: Backdoor production software or exfil source code",
            ],
            "skill": "LOW — no authentication required; curl one-liner to RCE",
            "tte": "< 1 hour from discovery to code execution on build server",
            "tools": ["curl", "netcat", "custom Groovy script"],
        },
        "elasticsearch": {
            "entry": "Elasticsearch/Kibana exposed without authentication",
            "steps": [
                "1. DISCOVERY: GET /_cat/indices to enumerate all data",
                "2. EXFILTRATION: Scroll through all documents with /_search?scroll",
                "3. PERSISTENCE: Use Kibana Console for further access if available",
                "4. IMPACT: Download PII/credentials, potentially ransom the data",
            ],
            "skill": "TRIVIAL — one HTTP request returns all data",
            "tte": "< 15 minutes from discovery to full data exfiltration",
            "tools": ["curl", "elasticsearch-dump", "jq"],
        },
        "redis": {
            "entry": "Redis exposed without authentication",
            "steps": [
                "1. CONNECT: redis-cli -h <ip> (no password prompt)",
                "2. WRITE SSH KEY: CONFIG SET dir /root/.ssh + SET key content",
                "3. WRITE CRON: CONFIG SET dir /var/spool/cron + write crontab",
                "4. PERSISTENCE: Cron runs reverse shell every minute",
                "5. PRIVILEGE ESCALATION: Redis typically runs as root",
            ],
            "skill": "LOW — redis-cli is standard tooling; exploit is one-liner",
            "tte": "< 30 minutes from discovery to root shell",
            "tools": ["redis-cli", "standard Linux tools"],
        },
        "docker": {
            "entry": "Docker API exposed without authentication (port 2375)",
            "steps": [
                "1. ENUMERATE: GET /containers/json to list running containers",
                "2. DEPLOY: POST /containers/create with privileged container mounting host /",
                "3. ESCAPE: exec into container, chroot to /host, access host filesystem",
                "4. PERSISTENCE: Add SSH key to host, create new user, install cron",
                "5. LATERAL: Use host network access to pivot to internal services",
            ],
            "skill": "LOW — curl one-liners; Docker socket escape is well-documented",
            "tte": "< 1 hour from discovery to host root access",
            "tools": ["curl", "Docker CLI", "nsenter"],
        },
        "default": {
            "entry": "Exposed service with known vulnerabilities",
            "steps": [
                "1. RECONNAISSANCE: Banner grab and version fingerprinting",
                "2. VULNERABILITY MATCH: Cross-reference version with CVE database",
                "3. EXPLOIT: Use public PoC or Metasploit module for matched CVE",
                "4. ESTABLISH FOOTHOLD: Deploy persistent reverse shell or beacon",
                "5. LATERAL MOVEMENT: Pivot to internal network using new access",
                "6. IMPACT: Ransomware, data exfil, or persistent backdoor",
            ],
            "skill": "LOW-MEDIUM — public exploits available for most CVEs",
            "tte": "Hours to days depending on CVE complexity",
            "tools": ["Metasploit", "public PoC scripts", "Cobalt Strike / Sliver"],
        }
    }

    def _run(self, findings: str, scope: str = "") -> str:
        try:
            data = json.loads(findings) if isinstance(findings, str) else findings
        except Exception:
            data = []

        chains = []
        pentest_scope = []
        overall_risk_factors = []

        for finding in (data if isinstance(data, list) else [data])[:_cap("threat_findings", 50)]:
            ip = finding.get("ip", "unknown")
            port = str(finding.get("port", ""))
            service = finding.get("service", "").lower()
            cves = finding.get("cves", [])
            # Carry the finding's real risk. Do NOT invent "High" for findings that arrived
            # without a risk — an unscored finding is a lead, not a high-severity chain.
            risk = finding.get("risk") or finding.get("severity") or "unknown"

            # Match to chain template
            chain_key = "default"
            for key in self.CHAINS:
                if key == "default":
                    continue
                if key in service or key in port:
                    chain_key = key
                    break

            template = self.CHAINS[chain_key].copy()
            chain = {
                "target": f"{ip}:{port} ({service or chain_key})",
                "risk": risk,
                "entry_point": template["entry"],
                "attack_steps": template["steps"],
                "attacker_skill_required": template["skill"],
                "estimated_time_to_exploit": template["tte"],
                "tools_required": template["tools"],
                "cves_enabling_attack": cves[:5],
            }

            if risk == "Critical":
                overall_risk_factors.append(
                    f"CRITICAL: {ip}:{port} — {template['entry']} ({template['tte']})"
                )
                chain["priority"] = "IMMEDIATE — exploit chain exists, patch within 24h"
            elif risk == "High":
                chain["priority"] = "HIGH — address within 7 days"
            else:
                # unknown / medium / low — do not promote. Confirm exposure first.
                chain["priority"] = "REVIEW — confirm the exposure is real before prioritising"

            chains.append(chain)
            pentest_scope.append(f"{ip}:{port} — {template['entry'].split(' (')[0]}")

        return json.dumps({
            "scope": scope,
            "attack_chains": chains,
            "pentest_scope_handoff": pentest_scope,
            "overall_risk_factors": overall_risk_factors,
            "red_team_summary": (
                f"Found {len([c for c in chains if 'IMMEDIATE' in c.get('priority','')])} "
                f"immediately exploitable entry points. "
                f"A skilled attacker could achieve initial access within hours using public tooling. "
                f"Priority: remediate Critical findings before engaging a red team."
            ),
        }, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 4: IOC Generator
# ─────────────────────────────────────────────────────────────────────────────

class IOCInput(BaseModel):
    hosts: list[str] = Field(description="List of IP addresses from findings")
    hostnames: list[str] = Field(default_factory=list, description="Associated hostnames/domains")
    ports: list[int] = Field(default_factory=list, description="Exposed ports")

class IOCGeneratorTool(BaseTool):
    name: str = "generate_iocs"
    description: str = (
        "Generate Indicators of Compromise (IOCs) from the discovered hosts and findings. "
        "Returns: IP blocklist entries, hostname watchlist, port-based SIEM rules, "
        "YARA rule hints, and Sigma rule skeletons for detection engineering. "
        "Use to produce the IOC and detection engineering section of the TI report."
    )
    args_schema: type = IOCInput

    def _run(self, hosts: list[str], hostnames: list[str] = None, ports: list[int] = None) -> str:
        hostnames = hostnames or []
        ports = ports or []

        iocs = {
            "ip_watchlist": [{"ip": ip, "type": "exposed_attack_surface",
                              "source": "prior_findings",
                              "note": "watchlist candidate — confidence inherits the originating finding, not assumed high"}
                             for ip in hosts[:_cap("threat_watchlist_ips", 50)]],
            "hostname_watchlist": [{"hostname": h, "type": "exposed_service_dns"} for h in hostnames[:20]],
            "siem_rules": [],
            "firewall_blocks": [],
            "sigma_skeletons": [],
        }

        HIGH_RISK_PORTS = {3389: "RDP", 23: "Telnet", 5900: "VNC", 2375: "Docker API",
                           6443: "K8s API", 9200: "Elasticsearch", 6379: "Redis", 27017: "MongoDB"}

        for port in ports:
            if port in HIGH_RISK_PORTS:
                svc = HIGH_RISK_PORTS[port]
                iocs["siem_rules"].append({
                    "name": f"External {svc} Connection to Scope",
                    "condition": f"network.destination.port == {port} AND source.ip NOT IN internal_range",
                    "severity": "HIGH",
                    "action": "alert",
                })
                iocs["firewall_blocks"].append(f"BLOCK inbound {port}/tcp from 0.0.0.0/0 (exposed {svc})")

                sigma = {
                    "title": f"External {svc} Exposure Detected",
                    "id": f"ti-{port}-external",
                    "status": "experimental",
                    "detection": {
                        "selection": {"dst_port": port, "direction": "inbound"},
                        "filter": {"src_ip|contains": ["10.", "172.16.", "192.168."]},
                        "condition": "selection and not filter",
                    },
                    "level": "high",
                }
                iocs["sigma_skeletons"].append(sigma)

        iocs["summary"] = {
            "total_ips": len(hosts),
            "high_risk_ports": [p for p in ports if p in HIGH_RISK_PORTS],
            "recommended_action": "Add all IPs to SIEM watchlist; block internet-facing dangerous ports immediately",
        }

        return json.dumps(iocs, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Agent builder
# ─────────────────────────────────────────────────────────────────────────────

def build_threat_intel_agent(llm) -> Agent:
    return Agent(
        role="Threat Intelligence Analyst",
        goal=(
            "Map all Critical and High findings to MITRE ATT&CK TTPs, identify likely threat actors, "
            "build realistic attack chains showing exactly what an adversary would do with these exposures, "
            "generate IOCs and SIEM rules, and produce Red Team recommendations with prioritised pen-test scope."
        ),
        backstory=(
            "You are a senior threat intelligence analyst with 10+ years tracking APT groups, "
            "ransomware operators, and opportunistic threat actors. "
            "You read raw Shodan findings and immediately see them through an attacker's eyes: "
            "what would Lazarus Group do with exposed RDP? What would TeamTNT do with open Docker APIs? "
            "You produce two outputs: (1) Threat Intel Report — actor attribution, TTP mapping, IOCs; "
            "(2) Red Team Recommendations — step-by-step attack chains, time-to-exploit estimates, "
            "and a prioritised pen-test handoff list. You never produce vague recommendations — "
            "every finding gets a concrete attack path. "
            "LANE BOUNDARY — you sit DOWNSTREAM of the Vuln agent and build the adversary layer ON "
            "TOP of its confirmed findings. You do NOT re-discover vulnerabilities, re-run detection "
            "queries, re-look-up CVEs, or re-score severity — you take the Vuln agent's confirmed "
            "Critical/High list and its severities AS GIVEN. You also do NOT write patch/remediation "
            "steps (\"patch to X\", \"upgrade\", \"disable service\") — remediation is the Vuln agent's "
            "and the Report's job. Your actionable output is DEFENSIVE DETECTION (IOCs, SIEM/Sigma, "
            "watchlists) and OFFENSIVE pen-test scope — not a second remediation list. If a finding "
            "is not present in the Vuln/Recon input, you do not invent it."
        ),
        tools=[
            MitreAttackTool(),
            ThreatActorTool(),
            RedTeamChainTool(),
            IOCGeneratorTool(),
        ],
        llm=llm,
        verbose=True,
        max_iter=16,
        allow_delegation=False,
    )


def build_threat_intel_task(agent, vuln_output: str = "", recon_output: str = "") -> Task:
    return Task(
        description=f"""Produce a complete Threat Intelligence Report with Red Team Recommendations.
{_DOCTRINE}

INPUT DATA:
Vulnerability findings: {vuln_output[:40000] if vuln_output else 'pull from get_results tool'}
Recon findings: {recon_output[:60000] if recon_output else 'use all prior agent outputs'}

STEPS:
1. CONSUME THE CONFIRMED LIST: take the Vuln agent's confirmed Critical/High findings (and
   the recon findings) AS GIVEN — services, ports, CVEs, and the severities they already
   assigned. Do NOT re-score them, do NOT re-run detection, do NOT add findings that aren't
   in the input. You are mapping what was confirmed, not re-discovering it.

2. MITRE ATT&CK MAPPING: For each Critical/High finding, call mitre_attack_lookup.
   Build a complete TTP matrix: which T-numbers apply, what techniques are enabled.

3. THREAT ACTOR ATTRIBUTION: Call threat_actor_attribution with the target industry 
   (infer from org names/products if not stated) and the TTPs you mapped.
   Identify the 2-3 most likely threat actor groups.

4. ATTACK CHAINS: Call red_team_attack_chains with ALL Critical/High findings.
   Build step-by-step attack paths for the top 3 most dangerous entry points.
   Be specific: name the exact tools, commands, and timeframes.

5. IOC GENERATION: Call generate_iocs with all Critical/High host IPs, hostnames, and ports.

6. OUTPUT as JSON with two top-level keys:

{{
  "threat_intel_report": {{
    "executive_summary": "2-3 sentence risk summary for CISO",
    "mitre_attack_matrix": [
      {{"tactic": "...", "technique": "T1190", "finding": "...", "host": "..."}}
    ],
    "threat_actor_assessment": {{
      "likely_actors": [...],
      "campaign_matches": [...],
      "targeting_rationale": "..."
    }},
    "iocs": {{
      "ip_watchlist": [...],
      "siem_rules": [...],
      "sigma_skeletons": [...]
    }},
    "detection_actions": ["deploy SIEM rule for external RDP", "add 1.2.3.4 to EDR watchlist", "alert on port 2375 ingress"]
  }},
  "red_team_recommendations": {{
    "attack_chains": [
      {{
        "entry_point": "...",
        "steps": [...],
        "time_to_exploit": "...",
        "tools": [...],
        "priority": "IMMEDIATE|HIGH|MEDIUM"
      }}
    ],
    "pentest_scope_handoff": [
      "IP:PORT — test for X"
    ],
    "estimated_blast_radius": "...",
    "red_team_summary": "..."
  }}
}}
""",
        expected_output=(
            "JSON with threat_intel_report (MITRE mapping, actor attribution, IOCs, DETECTION "
            "actions — no remediation/patch list, that is the Vuln agent's) and "
            "red_team_recommendations (attack chains, pentest scope, blast radius assessment)"
        ),
        agent=agent,
    )
