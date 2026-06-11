"""
agents/report_agent.py — Security Report Writers (profile-based)

Two axes, kept separate:

  STRUCTURE — a single shared section library (_SECTION_LIBRARY). Every report type
              draws sections from the SAME definitions, so structure never drifts.

  VOICE     — a writer persona per audience (REPORT_PROFILES). Each profile picks and
              orders a subset of the shared sections and sets the tone/depth/word budget.

Built-in profiles:
  technical (default) — SOC / detection engineering / platform teams. Full depth.
  executive           — CISO / security leadership / board. Decision-focused, trimmed.
  client              — external client deliverable. Methodology + defensible confidence.

The ANALYSIS stage (Task 1) is audience-independent: dedup, scope split, Shodan/false-
positive analysis, and MITRE mapping happen once and are the single source of truth. Only
the WRITE stage (Task 2) changes per audience — so one assessment can render an executive
brief and a technical report off the same analysis without the two disagreeing on facts.

Universal rules enforced by every profile:
  * Group findings by category — never a flat Critical/High dump.
  * Treat Shodan output as a PRIORITY source; show the original queries.
  * Hard wall between PRIMARY (app-selected) scope and ASN-EXPANDED assets.
  * Technical depth (versions, banners, cert CNs, evidence), not high-level fluff.
  * Confidence (confirmed | inferred | low) on every finding.

NO output truncation — write task receives full agent outputs.
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

# Optional curl-style validation tool. If present, the writer can confirm an exposure
# is real (reachable + unauthenticated) before it is allowed to stand as Critical/High.
try:
    from tools.http_validate_tool import HttpProbeTool
    _HAS_PROBE = True
except ImportError:
    try:
        from http_validate_tool import HttpProbeTool
        _HAS_PROBE = True
    except ImportError:
        _HAS_PROBE = False


# Per-section input budget for the ANALYSIS step. The server bridges the Control Center
# "Report detail (chars / agent)" slider as REPORT_SECTION_CHARS, so this slider now actually
# controls how much of each agent's findings the analysis sees. Floor at 12000 so a low
# slider value can never starve the report back into the old "5 findings" truncation.
_SECTION_CHARS = max(int(os.environ.get("REPORT_SECTION_CHARS") or "60000"), 12000)
_PRIMARY_CHARS = max(_SECTION_CHARS, 100000)   # recon is the priority source — give it the most


class GetHistoryInput(BaseModel):
    limit: int = Field(20, description="Number of recent searches to retrieve")

class GetHistoryTool(BaseTool):
    name: str = "get_history"
    description: str = "Get recent Shodan search history with queries and result counts."
    args_schema: type = GetHistoryInput

    def _run(self, limit: int = 20) -> str:
        try:
            r = requests.get(f"{SHODANSNIPE_URL}/api/history?limit={limit}", timeout=10)
            return json.dumps(r.json(), indent=2)
        except Exception as e:
            return f"Error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Universal rule blocks (plain strings — safe to interpolate into f-string tasks)
# ─────────────────────────────────────────────────────────────────────────────

_SCOPE_ASN_RULES = """
SCOPE & ASN RULES (hard wall):
- The scope selected in the application is the SINGLE source of truth for "in-scope".
  Do not redefine or broaden it. Take it from the manager hunt plan / recon scope.
- ASN-discovered assets are "ASN-Linked (Expanded Recon)". Label them as such, count them
  SEPARATELY, and NEVER fold them into the primary in-scope totals or risk counts unless
  the user has explicitly approved promoting them.
- When a finding is ASN-expanded, say so on the finding itself.
"""

_SHODAN_PRIORITY_RULES = """
SHODAN EMPHASIS (priority source):
- The recon agent IS the Shodan engine. Treat its output as the primary external-recon
  source, not as one feed among many.
- Shodan findings get their own dedicated treatment AND show the ORIGINAL queries that
  produced them (from queries_run / get_history).
- Explicitly report query quality and false-positive reduction: which results were
  discarded as CDN cert-sharing artifacts, honeypots, version-inferred CVE candidates, or
  out-of-scope substring matches — and why.
"""

_CONFIDENCE_RULES = """
CONFIDENCE & FRESHNESS (apply throughout):
- Carry each finding's confidence (confirmed | inferred | low) from the recon/vuln data.
- Shodan banners can be stale; CVE tags are often version-inferred and unverified; a WAF
  not observed is not a WAF absent; a shared cert on a CDN edge is not affiliation.
  Reflect these honestly — do not launder an inferred finding into a stated fact.
"""

_SYNTAX_NOTE = (
    "Any Shodan queries you print (pivots, monitoring) must use valid syntax: filters "
    "combine with spaces (AND); there is no OR/AND/NOT keyword; no `*` wildcards in a "
    "value; `-filter:` negation is allowed; comma lists only inside one filter."
)

_EVIDENCE_GATE = """
EVIDENCE GATE (true findings only — no maybes):
- A finding may exist ONLY if there is concrete observed evidence behind it: a real banner,
  a captured product+version, an actually-open dangerous service, a verified CVE match, an
  exposed body/path that was seen. An IP or hostname with NO observed issue is NOT a finding.
- Severity follows the evidence, never the port number alone. An open port running a normal,
  current service with no exposed sensitive function is Informational/Low — not High.
  "Port 22 is open" / "port 443 is open" is context, not a Critical.
- Critical/High requires an observed defect: cleartext-by-design protocol (e.g. Telnet),
  CONFIRMED no-auth on a sensitive service, a vulnerable version tied to a real CVE, or a
  directly exposed admin/data surface. If the defect is only assumed, it is at most an
  "inferred" lead, kept OUT of the Critical/High counts until confirmed.
- No hypothetical attack chains. Only include a chain if every hop is backed by observed
  data. Do not write "an attacker could…" unless the precondition was actually seen.
- If a host's severity depends on something you cannot see in the data (is the panel really
  reachable? is the DB really unauthenticated?) and the http_probe tool is available, probe
  it: a 200 with a real unauthenticated surface confirms it; a 401/403 means auth is present
  (downgrade or drop); a connection error means it is not serving (drop). Do not upgrade to
  Critical/High on assumption when you could confirm.
"""

_COMPLETENESS_RULES = """
COMPLETENESS (do not silently shrink the assessment):
- Enumerate EVERY qualifying finding in the data. Emit one object per finding — if the data
  supports 40 Critical/High findings, emit 40. Do not stop at a "representative" few, do not
  summarise the list into examples, do not cap at a round number.
- The example objects in the schema below are ILLUSTRATIVE FORMAT ONLY. They show the shape
  of one entry. Never copy their literal values (IPs, CVE-XXXX, AS-numbers) into your output —
  those placeholders are not findings.
- Self-check before you finish: count the qualifying Critical+High findings present in the
  input data; your output array length MUST match that count. If it is shorter, you dropped
  findings — go back and add them.
"""


# ─────────────────────────────────────────────────────────────────────────────
# Shared section library — STRUCTURE. No company names. No literal { } braces
# except the {target_org} / {scope_query} fields, which are filled once at render.
# ─────────────────────────────────────────────────────────────────────────────

_SECTION_LIBRARY = {

    "title": (
        "# ATTACK SURFACE ASSESSMENT — {target_org}\n"
        "Scope: {scope_query}"
    ),

    "exec_summary": (
        "## EXECUTIVE SUMMARY\n"
        "**Risk: [Critical/High/Medium/Low]** — [one clause naming the single biggest driver, "
        "with PRIMARY-scope counts].\n\n"
        "**Top findings** (most urgent first, ONE line each, identical issues clustered across "
        "hosts — do NOT list the same issue per host):\n"
        "- [Issue] — [N hosts affected] — [confirmed/inferred] — [one-clause impact]\n"
        "(3–6 lines maximum.)\n\n"
        "**Most urgent action:** [one specific step — exact asset — who owns it — timeline].\n\n"
        "PRIMARY SCOPE — Hosts: N | Critical: N | High: N | Medium: N | Immediate: N\n"
        "ASN-EXPANDED (Expanded Recon, NOT in-scope) — Hosts: N | Notable: [one line]\n\n"
        "COUNT INTEGRITY: these numbers MUST equal what you actually enumerate below — Critical "
        "here = the number of Critical findings in the findings section, Hosts = the rows in the "
        "inventory. After applying the severity rubric, recount; do not carry a guess. If the "
        "rubric downgraded version-inferred items, the Critical count drops accordingly — that is "
        "correct, not a regression.\n\n"
        "Keep this a scannable half-page. Do NOT restate findings as full prose here — detail "
        "lives in the sections below."
    ),

    "validation_coverage": (
        "## TESTING & VALIDATION COVERAGE\n"
        "What was actually tested and what came back valid — the proof of work. Fill every "
        "count from the data; if a number is unknown, write 'n/a (not run)', never guess.\n\n"
        "| Stage | Count | Notes |\n"
        "|-------|-------|-------|\n"
        "| In-scope hosts discovered | N | Shodan + OSINT + recon |\n"
        "| Live-confirmed (Nmap / probe) | N | ports re-checked live this run |\n"
        "| Exposures probed (http_probe) | N | GET/HEAD validation attempts |\n"
        "| Confirmed exposed (200, no auth) | N | counted as findings below |\n"
        "| Auth-protected (401/403) → dropped | N | NOT findings — confirms auth present |\n"
        "| Unreachable / timed out → dropped | N | NOT findings — service not serving |\n"
        "| Version/CVE candidates (unverified) | N | carried as candidates, not confirmed |\n\n"
        "**Method:** [one line — e.g. http_probe GET/HEAD, scope-gated, no exploitation; Nmap "
        "T2 SYN live confirmation]. **Tested-and-clean:** [name hosts/services checked that had "
        "NO issue — auth present, patched, not exposed. 'Tested, valid, no issue' is a result "
        "worth stating, and shows coverage]. Every Critical/High below traces back to a row here.\n"
        "COUNT INTEGRITY: 'In-scope hosts discovered' MUST equal the number of rows in the "
        "Attack Surface Map inventory below — including the clean hosts. If they disagree, the "
        "inventory is dropping hosts; fix the inventory, not this number."
    ),

    "methodology_scope": (
        "## METHODOLOGY & SCOPE\n"
        "[What was assessed and how. State the in-scope targets, the data sources used "
        "(Shodan, OSINT, DNS posture, ASN/RDAP), and that all testing was passive/discovery "
        "unless otherwise noted. State plainly what is confirmed vs inferred and the "
        "coverage limits (e.g. paid Shodan filters unavailable, API timeouts, IPv6 not "
        "covered). Reiterate that ASN-expanded assets are leads, not confirmed in-scope "
        "targets.]"
    ),

    "critical_high_findings": (
        "## CRITICAL & HIGH FINDINGS\n"
        "CLUSTER identical issues: same CVE/misconfig/service across multiple hosts = ONE "
        "finding with an **Affected** list — never repeat per host. Enumerate every DISTINCT "
        "issue (no cap). KEEP EACH BLOCK TIGHT — aim for ~8 lines.\n\n"
        "SEVERITY RUBRIC — severity is CONFIRMED IMPACT, not the max CVSS of a version's CVE "
        "list. Apply this honestly (the doctrine demands it):\n"
        "  • CRITICAL — requires confidence:confirmed AND confirmed exploitability: a probe-"
        "confirmed unauthenticated sensitive surface, OR a confirmed-exposed service whose "
        "exploit conditions are actually met. A banner/CPE version alone is NEVER Critical.\n"
        "  • HIGH — confirmed exposure of a sensitive service, OR a CISA-KEV version match on a "
        "CONFIRMED-exposed host where exploitability is inferred (not yet probe-proven).\n"
        "  • MEDIUM — version-inferred CVEs (banner/CPE only, no probe confirmation), EOL "
        "software, hygiene issues. Old OpenSSH/Apache with a long CVE list but no confirmed "
        "exploit path lands HERE, not Critical.\n"
        "  • A finding's severity may NOT exceed what its **Confidence** supports: confidence "
        "'inferred' caps severity at HIGH; 'low' caps at MEDIUM. If you write Critical, the "
        "Evidence must show the confirmed exploit condition — otherwise downgrade and say why.\n"
        "  • Do NOT inflate with CVE counts. 'OpenSSH 7.4 — 25 CVEs' is noise: cite the 1–3 that "
        "are genuinely exploitable IN THIS exposure, note the rest as 'version-associated, not "
        "individually validated', and score on the real path.\n\n"
        "### [N]. [Issue name] — [primary asset + \"and N more\" if clustered]\n"
        "- **Risk:** Critical/High/Medium | **CVSS:** [score] | **Confidence:** confirmed/inferred/low\n"
        "- **Affected:** [every IP:port (+ hostname); if >10, give count + 3 representative]\n"
        "- **Evidence:** [MANDATORY — what was ACTUALLY observed: banner/version/title/cert + the "
        "probe verdict (200/401/403/timeout). State plainly what is CONFIRMED vs what is INFERRED. "
        "If exploitability is only potential, say 'potential — version-inferred, unverified' and "
        "give the basis. Never leave this blank.]\n"
        "- **CVEs:** [the 1–3 genuinely relevant/exploitable ones as `CVE-id (score) one-clause`; "
        "if a version carries more, add 'and N version-associated CVEs, not individually validated']\n"
        "- **MITRE:** [T-number(s)] | **Impact:** [ONE sentence — what an attacker does now]\n"
        "- **Fix:** [the single most important action — name the exact asset] | **Timeline:** Immediate/24h/7d\n"
        "- **Control surface:** [how this exposure or its severity can change dynamically — IAM "
        "policy, CI/CD variable, K8s RBAC/admission, security group, WAF rule, control-plane API "
        "— or 'static (verified)' if nothing governs it]\n"
        "- **Scope:** Primary | ASN-Expanded"
    ),

    "grouped_findings": (
        "## DETAILED ATTACK SURFACE FINDINGS (grouped by category)\n\n"
        "### 1. Shodan Intelligence (High Priority)\n"
        "[Dedicated, rich. The original queries that found each asset, the hits, the "
        "product/version evidence, why each belongs to the org, and the false positives "
        "discarded.]\n\n"
        "### 2. Domain & Web Exposure\n"
        "[DNS posture (SPF/DMARC/CAA/DNSSEC), web servers, TLS/cert issues, exposed "
        "admin/login UIs.]\n\n"
        "### 3. Network Services & Protocols\n"
        "[One sub-list per protocol family, each host WITH its version and HTTP protocol:\n"
        "  - Remote access: SSH (OpenSSH x.y), RDP, VNC, Telnet, WinRM\n"
        "  - File transfer: FTP, SMB, NFS, rsync\n"
        "  - Mail / directory: SMTP, IMAP/POP3, LDAP, SNMP\n"
        "  - Databases: MySQL, PostgreSQL, Oracle (1521), MSSQL, MongoDB, Redis, Elastic\n"
        "  - App servers & message queues: Oracle WebLogic (7001/T3), JBoss, Tomcat, "
        "ActiveMQ, RabbitMQ, IBM MQ, Kafka, MQTT — with exact product version.\n"
        "Do NOT collapse these into a single line — each family that appears gets its own "
        "treatment, and every host shows product + version + HTTP/1.1-vs-HTTP/2.]\n\n"
        "### 4. Cloud / SaaS Exposures\n"
        "[Object storage, cloud tenants, CI/CD, container/orchestration surfaces.]\n\n"
        "### 5. ASN-Expanded Assets (Expanded Recon — separate, NOT in primary counts)\n"
        "[Everything surfaced via ASN lookup, clearly labelled, with ownership confidence. "
        "These are leads, not confirmed in-scope targets.]"
    ),

    "shodan_analysis": (
        "## SHODAN DISCOVERIES & QUERY ANALYSIS\n\n"
        "**Surface profile (big-picture first):** [from recon's surface_profile — total hosts, "
        "top ports actually seen, dominant products/stack, unusual ports found, CDN-fronted vs "
        "exposed-origin counts. One tight paragraph: what the broad sweep revealed and how it "
        "shaped the targeted queries.]\n\n"
        "| Query | Results | In-scope hits | Notable |\n"
        "|-------|---------|---------------|---------|\n"
        "[Every Shodan query that ran — exact text — with counts and any notable hit.]\n\n"
        "**Header / tech evidence:** [notable Server / X-Powered-By / framework versions and "
        "CDN-WAF header signatures (CF-RAY, X-Akamai, Via) that drove product/version or origin "
        "calls.]\n"
        "**False positives reduced:** [CDN cert-sharing artifacts / honeypots / version-inferred "
        "CVE candidates / favicon-only matches without corroboration / out-of-scope substring "
        "matches that were discarded, and why.]\n"
        "**Coverage gaps:** [anything NOT covered — IPv6, specific protocols, paid filters.]"
    ),

    "attack_surface_map": (
        "## ATTACK SURFACE MAP — FULL INVENTORY (every discovered host)\n"
        "DISCOVERY-DRIVEN, not finding-driven. One row for EVERY host recon/vuln/nmap found — "
        "primary AND ASN-expanded — including the CLEAN ones (no issue). A host that was tested "
        "and had no problem still gets a row: Risk = Low/Info, Status = clean/tested-no-issue. "
        "If recon's surface_profile says N hosts, this table has ~N rows. Most of the surface is "
        "clean web + SSH + network services that never became findings — they MUST appear here, "
        "or the inventory is wrong. Do NOT cap or summarise it away. Order by risk (Critical→Low).\n\n"
        "| IP | Hostname | Ports | Product / Version | HTTP | CDN/WAF/Origin | Risk | Conf | Scope | Status |\n"
        "|----|----------|-------|-------------------|------|----------------|------|------|-------|--------|\n"
        "[One row per host. Product/Version = EXACT version string. HTTP = HTTP/1.1, HTTP/2, or — . "
        "CDN/WAF/Origin = 'Cloudflare'/'Akamai'/... if fronted, or 'ORIGIN (exposed)' if it "
        "survived the CDN-negation check, or 'direct' if no CDN seen. Status = confirmed / probed-200 / "
        "auth-403 / timeout / clean / inferred. EVERY host appears — plain web, SSH-only, mail, "
        "DNS, SNMP/BGP, databases, the lot. The row count here should reconcile with the "
        "'in-scope hosts discovered' number in the Validation Coverage section.]\n\n"
        "### Remote Access & SSH (every host on 22/2222/23/3389/5900/5985)\n"
        "| IP | Port | Service / Version | Auth/Notes | CVE candidates | Scope |\n"
        "|----|------|-------------------|-----------|----------------|-------|\n"
        "[List EVERY SSH/RDP/VNC/Telnet/WinRM host with its exact version (e.g. OpenSSH 7.4). "
        "Flag old/EOL versions and their CVE candidates. SSH being open is not itself High, but "
        "every SSH host must still be inventoried here — do not omit them.]\n\n"
        "### CDN / WAF / Origin posture\n"
        "[Short: how many hosts sit behind a CDN/WAF (named), how many are exposed ORIGINS that "
        "survived CDN-negation (these bypass the WAF — call them out by IP), and any host with NO "
        "CDN/WAF in front. Exposed origins are the ones that matter — name them.]"
    ),

    "threat_intel": (
        "## THREAT INTELLIGENCE\n"
        "[Prose assessment. Map the exposure profile to specific MITRE ATT&CK TTPs (use the "
        "T-numbers from the analysis / threat-intel data, do not invent codes). Attribute to "
        "known threat clusters ONLY where the pattern genuinely matches. Give an overall "
        "risk score justified by the live data. State plainly where Shodan enrichment "
        "limitations (e.g. risk score 0) reflect tooling, not host safety.]"
    ),

    "pivots": (
        "## PIVOT OPPORTUNITIES\n"
        "Numbered. Each is a ready-to-run Shodan query (valid syntax) plus one line on what "
        "it would surface and why it matters."
    ),

    "recommended_actions": (
        "## RECOMMENDED ACTIONS\n"
        "Numbered, ordered by urgency. Each: **Who** (owning team) | **Timeline** | the "
        "specific action (name the exact IP/port/cert/domain). No generic advice."
    ),

    "monitoring_queries": (
        "## MONITORING QUERIES\n"
        "Fenced code blocks, one per query, each followed by a one-line description of what "
        "it detects."
    ),

    "confidence_freshness": (
        "## CONFIDENCE & DATA FRESHNESS\n"
        "- Confirmed vs inferred breakdown (how many findings are live-verified vs "
        "Shodan-inferred).\n"
        "- Version-inferred CVE caveat; \"WAF not observed\" caveat; shared-cert-on-CDN caveat.\n"
        "- Data freshness: Shodan banner age and which findings still need live confirmation."
    ),

    "industry_comparison": (
        "## COMPARISON TO INDUSTRY (only if relevant)\n"
        "[1-2 sentences: how this exposure profile compares to typical posture for the "
        "org's sector. No named third parties.]"
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Report profiles — VOICE. Each picks/orders shared sections + sets persona + tone.
# ─────────────────────────────────────────────────────────────────────────────

REPORT_PROFILES = {

    "technical": {
        "label": "Technical Assessment",
        "audience": "SOC, detection engineering, and platform/security engineering teams",
        "word_budget": "No fixed cap. Be complete and evidence-dense — but never padded.",
        "voice": (
            "Write for engineers. Lead with evidence: versions, banners, cert CNs, exact "
            "ports, exact queries. Remediation must be reproduction-grade (config keys, "
            "exact commands or settings). Assume a technical reader; do not over-explain "
            "basics. T-numbers belong inline."
        ),
        "sections": [
            "title", "exec_summary", "validation_coverage", "critical_high_findings",
            "attack_surface_map", "shodan_analysis", "grouped_findings", "threat_intel",
            "pivots", "recommended_actions", "monitoring_queries", "confidence_freshness",
            "industry_comparison",
        ],
        "persona": {
            "role": "Technical Threat Assessment Writer",
            "goal": (
                "Produce a complete, evidence-dense technical assessment a SOC or platform "
                "team can act on directly. Group findings by category, give Shodan its own "
                "detailed section with the original queries, keep ASN-expanded assets "
                "separate from declared scope, map every Critical/High finding to a specific "
                "MITRE ATT&CK TTP, and tag confidence honestly. Specific asset, specific "
                "evidence, specific T-number, specific remediation."
            ),
            "backstory": (
                "You are a threat-assessment writer with deep red-team and threat-hunting "
                "experience. You read the raw data before drawing conclusions and you write "
                "for practitioners who will reproduce and remediate. You treat Shodan as the "
                "centre of gravity for external recon — surfacing the queries that ran, the "
                "hits they returned, and the false positives you discarded and why. You "
                "enforce a hard wall between primary scope and ASN-expanded leads. You are "
                "disciplined about confidence: a version-inferred CVE is a candidate, not a "
                "fact; 'no WAF observed' is not 'no WAF'; a wildcard cert on a shared CDN "
                "edge is not affiliation — and you say so. You never write 'the organization "
                "should consider'; you write the exact step. You deduplicate and never "
                "invent findings."
            ),
        },
    },

    "executive": {
        "label": "Executive Brief",
        "audience": "CISO, security leadership, and board",
        "word_budget": "Target ~800 words. Decision-relevant only — no evidence tables.",
        "voice": (
            "Write for leadership. Lead with business risk and the decisions to approve. "
            "Quantify urgency in time and, where possible, business impact. Keep jargon "
            "minimal — put T-numbers in parentheses, not as the spine. Be brief and clear; "
            "the reader wants the 'so what' and 'what now', not packet-level detail."
        ),
        "sections": [
            "title", "exec_summary", "validation_coverage", "critical_high_findings",
            "threat_intel", "recommended_actions", "confidence_freshness",
        ],
        "persona": {
            "role": "Executive Security Briefer",
            "goal": (
                "Turn the assessment into a crisp executive brief that lets leadership "
                "understand the business risk and approve the right actions fast. Lead with "
                "what is at stake and what to decide; keep findings tight and "
                "business-framed; preserve confidence honesty so leaders are not misled by "
                "inferred findings."
            ),
            "backstory": (
                "You brief CISOs and boards. You translate technical exposure into business "
                "risk and clear decisions, and you respect the reader's time. You never "
                "inflate: an inferred finding is presented as inferred, and ASN-expanded "
                "leads are kept out of the in-scope risk count. You name the single most "
                "urgent action and who owns it. You keep MITRE references and packet detail "
                "light — leadership needs the decision, not the disassembly."
            ),
        },
    },

    "client": {
        "label": "Client Deliverable",
        "audience": "an external client's security team receiving a paid assessment",
        "word_budget": "No fixed cap. Complete, professional, and defensible.",
        "voice": (
            "Write a deliverable suitable to hand to a paying client. Be professional and "
            "defensible: every claim is evidenced and confidence-tagged, scope and method "
            "are transparent, and remediation has clear ownership and timelines. Avoid "
            "overstatement; clearly separate confirmed findings from leads."
        ),
        "sections": [
            "title", "exec_summary", "methodology_scope", "validation_coverage",
            "critical_high_findings", "attack_surface_map", "shodan_analysis",
            "grouped_findings", "threat_intel", "pivots", "recommended_actions",
            "monitoring_queries", "confidence_freshness",
        ],
        "persona": {
            "role": "Client Deliverable Author",
            "goal": (
                "Produce a polished, defensible assessment deliverable for an external "
                "client: transparent scope and methodology, every finding evidenced and "
                "confidence-tagged, clear remediation ownership and timelines, and a strict "
                "separation between confirmed in-scope findings and ASN-expanded leads."
            ),
            "backstory": (
                "You author client-facing security deliverables. Your reports have to stand "
                "up to scrutiny, so you show your work: what was in scope, what sources were "
                "used, what is confirmed vs inferred, and where coverage was limited. You are "
                "precise and measured — no hype, no unverified CVEs stated as fact, no "
                "shared-cert-on-CDN treated as affiliation. You give the client an "
                "unambiguous, prioritized remediation path with owners and timelines."
            ),
        },
    },
}

# Legacy aliases so older callers keep working.
_PROFILE_ALIASES = {
    "comprehensive": "technical",
    "full": "technical",
    "brief": "executive",
    "exec": "executive",
}


def resolve_profile(key: str) -> dict:
    """Normalize a report-type key (incl. legacy aliases) to a profile dict."""
    k = (key or "technical").strip().lower()
    k = _PROFILE_ALIASES.get(k, k)
    return REPORT_PROFILES.get(k, REPORT_PROFILES["technical"])


def _render_template(profile: dict, target_org: str, scope_query: str) -> str:
    """Assemble a profile's report skeleton from the shared section library."""
    body = "\n\n---\n\n".join(_SECTION_LIBRARY[s] for s in profile["sections"])
    return body.format(target_org=target_org, scope_query=scope_query)


# ─────────────────────────────────────────────────────────────────────────────
# Agent + task builders
# ─────────────────────────────────────────────────────────────────────────────

def build_report_agent(llm, report_type: str = "technical") -> Agent:
    """
    Build the report writer for a given audience.
    report_type: "technical" (default) | "executive" | "client"
                 (legacy "comprehensive"/"brief" also accepted)
    """
    profile = resolve_profile(report_type)
    p = profile["persona"]
    tools = [GetHistoryTool()]
    if _HAS_PROBE:
        tools.append(HttpProbeTool())
    return Agent(
        role=p["role"],
        goal=p["goal"],
        backstory=p["backstory"],
        tools=tools,
        llm=llm,
        verbose=True,
        max_iter=30,
        allow_delegation=False,
    )


def build_report_tasks(agent, recon_output: str, osint_output: str,
                        auth_output: str, vuln_output: str,
                        target_org: str, scope_query: str = "",
                        report_style: str = "technical",
                        manager_plan: str = "",
                        manager_summary: str = "",
                        threat_output: str = "") -> list:
    """
    Two-task pipeline: shared analytical read -> audience-specific write.

    report_style : profile key — "technical" (default) | "executive" | "client".
                   Legacy "comprehensive"/"brief" still resolve.
    recon_output : the SHODAN / recon agent output — treated as the priority source.
    threat_output: optional pre-computed threat_intel_agent output. If supplied, the
                   analysis step reuses its TTP map instead of re-deriving (defaults "").

    NOTE: Task 1 is audience-independent. To render multiple audiences from one assessment,
    you can build Task 1 once and attach several Task-2 write tasks (one per profile) as its
    consumers — they will all share the same analyzed facts.
    """
    profile = resolve_profile(report_style)
    prompt = _render_template(profile, target_org, scope_query)
    label = profile["label"]

    # ── Task 1: Analytical read — SHARED, audience-independent ──────────────
    analysis_task = Task(
        description=f"""
Read ALL agent findings below. Do NOT write the report yet.
Produce only structured analytical output that the write task will use. This analysis is
audience-independent — it is the single source of truth for every report type.

{_SCOPE_ASN_RULES}
{_SHODAN_PRIORITY_RULES}
{_CONFIDENCE_RULES}
{_EVIDENCE_GATE}
{_COMPLETENESS_RULES}

=== MANAGER HUNT PLAN (scope decisions live here) ===
{manager_plan[:6000] if manager_plan else "(none)"}

=== MANAGER CORRELATION ===
{manager_summary[:6000] if manager_summary else "(none)"}

=== SHODAN / RECON FINDINGS (PRIORITY SOURCE) ===
{recon_output[:_PRIMARY_CHARS]}

=== OSINT FINDINGS ===
{osint_output[:_SECTION_CHARS]}

=== AUTH FINDINGS ===
{auth_output[:_SECTION_CHARS]}

=== VULN FINDINGS ===
{vuln_output[:_SECTION_CHARS]}

=== THREAT-INTEL FINDINGS (use if present; do not re-derive TTPs when provided) ===
{threat_output[:_SECTION_CHARS] if threat_output else "(none — derive TTPs yourself below)"}

ANALYSIS STEPS:

1. DEDUPLICATE: same IP+port+issue = one finding. Build a clean unique list.

2. SPLIT SCOPE: separate every finding into primary_scope vs asn_expanded using the manager
   plan and the recon agent's own split. ASN-expanded must NOT enter the primary counts.

3. SHODAN ANALYSIS:
   - Collect the exact queries that ran (recon queries_run + get_history if useful).
   - Assess query quality: scoped/anchored, or broad?
   - List false positives to discard and WHY: shared cert on a CDN edge (not affiliation),
     honeypots (decoys), version-inferred CVE candidates (unverified), org:/hostname:
     substring matches that aren't really in scope.

4. MITRE ATT&CK MAPPING — for each Critical and High finding:
   If threat-intel output is present, REUSE its T-numbers. Otherwise map to real T-numbers.
   Examples (do not limit to these and if you do you failed):
   - RDP on 3389 -> TA0001, T1021.001        - SSH exposed -> TA0001, T1021.004
   - SMB on 445  -> TA0008, T1021.002         - No auth Elastic -> T1190, T1530
   - Jenkins console -> T1190, T1059.004      - Docker API 2375 -> T1190, T1610
   - Redis no auth -> T1190, T1098            - Exposed .env -> T1552.001
   - Missing DMARC -> enables T1566.002       - Subdomain takeover -> T1584.001
   - Expired SSL cert -> T1600
   Use real T-numbers only. Do not invent codes.

5. THREAT ACTOR ATTRIBUTION — only where evidence genuinely matches (ensure do not force itif not you fail):
   - Docker 2375 + Redis 6379 -> TeamTNT, Kinsing   - Jenkins -> TeamTNT, supply-chain
   - RDP + old OS banner -> ransomware operators     - Elastic open -> opportunistic ransom
   - Fortinet/Citrix -> state-aligned exploitation of edge devices

6. RISK SCORE: Critical | High | Medium | Low — justify with specific PRIMARY-scope counts.

7. OUTPUT as JSON. The block below is an ILLUSTRATIVE SCHEMA — it shows the SHAPE of each
   entry, not real findings. Do NOT copy its placeholder values (1.2.3.4, 5.6.7.8, 9.9.9.9,
   CVE-XXXX-YYYY, AS12345). Emit ONE ttp_map object for EVERY Critical and High finding in
   the input — if there are 30 qualifying findings, ttp_map has 30 objects. Apply the
   EVIDENCE GATE: every object must carry real observed evidence; drop anything that is only
   a bare IP/host with no issue.
{{
  "dedup_summary": {{"original_count": N, "after_dedup": N, "merged": [["A","B — same host:port"]]}},
  "scope_split": {{"primary_scope_count": N, "asn_expanded_count": N, "asn_expanded_assets": ["5.6.7.8 (AS12345)"]}},
  "shodan_analysis": {{
    "queries_run": ["exact query 1", "exact query 2"],
    "query_quality_note": "anchored to net:/cert CN — low false-positive design",
    "false_positives_discarded": [
      "shared cert on CDN edge 1.2.3.4 — artifact, not affiliation",
      "9.9.9.9 tag:honeypot — decoy",
      "CVE-XXXX-YYYY on 1.2.3.4 — version-inferred, unverified"
    ]
  }},
  "ttp_map": [
    {{"finding": "RDP on <ip>:3389", "tactic": "TA0001 Initial Access",
      "technique": "T1021.001 Remote Desktop Protocol", "threat_actors": ["..."],
      "severity": "Critical", "confidence": "confirmed", "scope": "primary",
      "evidence": "what was ACTUALLY observed — banner/version/open dangerous port/probe result; if blank, this is not a finding"}}
  ],
  "overall_risk": "Critical",
  "risk_justification": "specific one-sentence reason (primary scope only)",
  "top_chains": ["1.2.3.4:3389 RDP + no MFA -> password spray -> domain access"]
}}
""",
        expected_output=(
            "JSON: dedup_summary{}, scope_split{}, shodan_analysis{}, ttp_map[] "
            "(confidence + scope per item), overall_risk, risk_justification, top_chains[]"
        ),
        agent=agent,
    )

    # ── Task 2: Write the report for this audience ─────────────────────────
    write_task = Task(
        description=f"""
Write the final report — profile: {label} (for {profile['audience']}).
Use the dedup, scope split, Shodan analysis, and TTP mapping from the analysis task, plus
the full agent data below.

AUDIENCE & VOICE:
{profile['voice']}
Length: {profile['word_budget']}

Write like a senior human analyst. Reference specific T-numbers, IPs, CVEs, and cert CNs.
Never write "the organization should consider" — write the exact remediation step.

Fill out exactly this section skeleton (it is shared across report types; your job is the
voice and depth for THIS audience). Replace bracketed guidance with real data; if a section
has no data, write "None identified in this assessment scope".

{prompt}

UNIVERSAL REQUIREMENTS:
- Group findings logically (by exposure type / technology / risk category) — never a long
  flat list.
- Give Shodan findings priority and SHOW THE ORIGINAL QUERIES wherever a Shodan section
  appears.
- Clearly separate PRIMARY scope from ASN-EXPANDED assets; ASN-expanded never inflates the
  in-scope counts.
- Carry confidence on every finding.
- {_SYNTAX_NOTE}

{_SCOPE_ASN_RULES}
{_SHODAN_PRIORITY_RULES}
{_CONFIDENCE_RULES}

=== MANAGER HUNT PLAN & SCOPE EXPANSION ===
{manager_plan[:8000] if manager_plan else "(no manager plan)"}

=== MANAGER CROSS-AGENT CORRELATION ===
{manager_summary[:8000] if manager_summary else "(no correlation)"}

=== SHODAN / RECON AGENT FINDINGS (PRIORITY SOURCE) ===
{recon_output}

=== OSINT AGENT FINDINGS ===
{osint_output}

=== AUTH & EXPOSURE FINDINGS ===
{auth_output}

=== VULNERABILITY FINDINGS ===
{vuln_output}

=== THREAT-INTEL FINDINGS (use its TTP map / actors if present) ===
{threat_output if threat_output else "(none)"}

RULES:
{_DOCTRINE}
- Use the analysis output for dedup, scope split, and TTP mapping. BUT it is a floor, not a
  ceiling: if the analysis enumerated fewer findings than the raw recon/vuln/auth data below
  clearly contains, RECOVER the missing ones from the raw data and write them up too. The
  report must reflect every qualifying finding in the evidence, not only the subset the
  analysis happened to list. Never drop a real finding because the analysis was short.
- {_EVIDENCE_GATE}
- {_COMPLETENESS_RULES}
- PLACEHOLDER BAN: the section skeleton above is a FORMAT GUIDE. Never emit a literal
  bracketed placeholder ([N], [Service or issue name], [IP:Port or hostname], [banner…]) or
  any example value as if it were data. Replace every bracket with real observed data, or
  omit that row entirely. Only use "None identified in this assessment scope" when a section
  genuinely has zero backing data — never as filler.
- Never truncate any section.
- VERBOSITY & SCALE: be comprehensive on DISTINCT issues, concise on each. Cluster repeated
  issues across hosts into one block (one nginx-bypass finding listing all affected hosts, not
  one per host). Say each thing ONCE — do not restate a finding across the exec summary, the
  findings list, and the detailed section. On large scopes (50+ hosts) push the Medium/Low long
  tail into the Attack Surface Map table rather than prose, and summarise the tail ("14 hosts
  expose only standard web ports — see map") instead of enumerating it in sentences. Density
  over length: every line earns its place. Comprehensive ≠ verbose.
- Never invent findings — only report what the data shows, with its evidence.
- Mark ASN-expanded assets clearly — keep them out of the primary risk count.
- If http_probe is available and a Critical/High rests on an exposure you cannot see proven
  in the data, confirm it with a probe before publishing that severity.
""",
        expected_output=(
            f"Complete {label} in markdown for {profile['audience']}: findings grouped by "
            "category, Shodan given priority with original queries shown, PRIMARY vs "
            "ASN-expanded kept separate, MITRE T-numbers and confidence per finding, and "
            "specific remediation. Voice and depth matched to the audience. No generic advice."
        ),
        agent=agent,
        context=[analysis_task],
    )

    return [analysis_task, write_task]


def build_report(llm, recon_output: str, osint_output: str, auth_output: str,
                 vuln_output: str, target_org: str, scope_query: str = "",
                 report_type: str = "technical", manager_plan: str = "",
                 manager_summary: str = "", threat_output: str = "") -> tuple:
    """
    Convenience: build the matching writer persona AND its tasks from one report_type key,
    so the audience is specified once. Returns (agent, [analysis_task, write_task]).
    """
    agent = build_report_agent(llm, report_type=report_type)
    tasks = build_report_tasks(
        agent, recon_output, osint_output, auth_output, vuln_output,
        target_org, scope_query=scope_query, report_style=report_type,
        manager_plan=manager_plan, manager_summary=manager_summary,
        threat_output=threat_output,
    )
    return agent, tasks