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
from crewai import Agent, Task
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import requests

SHODANSNIPE_URL = os.environ.get("SHODANSNIPE_URL", "http://127.0.0.1:8000")
# Configurable from the GUI/CLI: chars of each agent's findings fed into the report
# (= effectively how many hosts make it in). Higher = more hosts/detail. Default 8000.
_SEC = int(os.environ.get("REPORT_SECTION_CHARS", "8000"))


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
        "Risk: [Critical/High/Medium/Low — justified by specific PRIMARY-scope counts]\n"
        "[2-3 condensed sentences: what was found, what an attacker can do today, the "
        "single most urgent fix.]\n\n"
        "PRIMARY SCOPE — Hosts: N | Critical: N | High: N | Immediate actions: N\n"
        "ASN-EXPANDED (Expanded Recon, NOT in-scope) — Hosts: N | Notable: [one line]"
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
        "List ALL of them — do not stop at 5. One standardized block each:\n\n"
        "### [N]. [Service or issue name] — [IP:Port or hostname]\n"
        "- **Risk:** Critical/High | **CVSS:** [score if CVE] | **Confidence:** confirmed/inferred/low\n"
        "- **Asset:** [exact IP:port (+ hostname)]\n"
        "- **Exposure / Evidence:** [banner, version, title, cert CN, CVE ID — what was ACTUALLY observed]\n"
        "- **MITRE ATT&CK:** [T-number(s) from the analysis] — [technique name]\n"
        "- **Impact:** [one sentence — what an attacker does with this right now]\n"
        "- **Fix:** [specific action, not generic advice] | **Timeline:** Immediate/24h/7d\n"
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
        "### 3. Network Services\n"
        "[Remote access (SSH/RDP/VNC/Telnet), databases, file transfer, mail, mgmt ports.]\n\n"
        "### 4. Cloud / SaaS Exposures\n"
        "[Object storage, cloud tenants, CI/CD, container/orchestration surfaces.]\n\n"
        "### 5. ASN-Expanded Assets (Expanded Recon — separate, NOT in primary counts)\n"
        "[Everything surfaced via ASN lookup, clearly labelled, with ownership confidence. "
        "These are leads, not confirmed in-scope targets.]"
    ),

    "shodan_analysis": (
        "## SHODAN DISCOVERIES & QUERY ANALYSIS\n\n"
        "| Query | Results | In-scope hits | Notable |\n"
        "|-------|---------|---------------|---------|\n"
        "[Every Shodan query that ran — exact text — with counts and any notable hit.]\n\n"
        "**False positives reduced:** [CDN cert-sharing artifacts / honeypots / "
        "version-inferred CVE candidates / out-of-scope substring matches that were "
        "discarded, and why.]\n"
        "**Coverage gaps:** [anything NOT covered — IPv6, specific protocols, paid filters.]"
    ),

    "attack_surface_map": (
        "## ATTACK SURFACE MAP\n"
        "Order rows by risk (Critical to Low). Mark scope and confidence.\n\n"
        "| IP | Hostname | Ports | Product / Version | Risk | Confidence | Scope | ASN |\n"
        "|----|----------|-------|-------------------|------|-----------|-------|-----|\n"
        "[One row per discovered host — ALL hosts. Primary and ASN-expanded both appear, "
        "but the Scope column makes the distinction unambiguous.]"
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
            "title", "exec_summary", "critical_high_findings", "grouped_findings",
            "shodan_analysis", "attack_surface_map", "threat_intel", "pivots",
            "recommended_actions", "monitoring_queries", "confidence_freshness",
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
            "title", "exec_summary", "critical_high_findings", "threat_intel",
            "recommended_actions", "confidence_freshness",
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
            "title", "exec_summary", "methodology_scope", "critical_high_findings",
            "grouped_findings", "shodan_analysis", "attack_surface_map", "threat_intel",
            "pivots", "recommended_actions", "monitoring_queries", "confidence_freshness",
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
    return Agent(
        role=p["role"],
        goal=p["goal"],
        backstory=p["backstory"],
        tools=[GetHistoryTool()],
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

=== MANAGER HUNT PLAN (scope decisions live here) ===
{manager_plan[:_SEC] if manager_plan else "(none)"}

=== MANAGER CORRELATION ===
{manager_summary[:_SEC] if manager_summary else "(none)"}

=== SHODAN / RECON FINDINGS (PRIORITY SOURCE) ===
{recon_output[:_SEC]}

=== OSINT FINDINGS ===
{osint_output[:_SEC]}

=== AUTH FINDINGS ===
{auth_output[:_SEC]}

=== VULN FINDINGS ===
{vuln_output[:_SEC]}

=== THREAT-INTEL FINDINGS (use if present; do not re-derive TTPs when provided) ===
{threat_output[:_SEC] if threat_output else "(none — derive TTPs yourself below)"}

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
   Examples (do not limit to these):
   - RDP on 3389 -> TA0001, T1021.001        - SSH exposed -> TA0001, T1021.004
   - SMB on 445  -> TA0008, T1021.002         - No auth Elastic -> T1190, T1530
   - Jenkins console -> T1190, T1059.004      - Docker API 2375 -> T1190, T1610
   - Redis no auth -> T1190, T1098            - Exposed .env -> T1552.001
   - Missing DMARC -> enables T1566.002       - Subdomain takeover -> T1584.001
   - Expired SSL cert -> T1600
   Use real T-numbers only. Do not invent codes.

5. THREAT ACTOR ATTRIBUTION — only where evidence genuinely matches (do not force it):
   - Docker 2375 + Redis 6379 -> TeamTNT, Kinsing   - Jenkins -> TeamTNT, supply-chain
   - RDP + old OS banner -> ransomware operators     - Elastic open -> opportunistic ransom
   - Fortinet/Citrix -> state-aligned exploitation of edge devices

6. RISK SCORE: Critical | High | Medium | Low — justify with specific PRIMARY-scope counts.

7. OUTPUT as JSON:
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
    {{"finding": "RDP on 1.2.3.4:3389", "tactic": "TA0001 Initial Access",
      "technique": "T1021.001 Remote Desktop Protocol", "threat_actors": ["..."],
      "severity": "Critical", "confidence": "confirmed", "scope": "primary"}}
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
{manager_plan[:_SEC] if manager_plan else "(no manager plan)"}

=== MANAGER CROSS-AGENT CORRELATION ===
{manager_summary[:_SEC] if manager_summary else "(no correlation)"}

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
- Use the analysis output — do not re-derive TTPs, dedup, or the scope split.
- Never truncate any section.
- Never invent findings — only report what the data shows.
- Mark ASN-expanded assets clearly — keep them out of the primary risk count.
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