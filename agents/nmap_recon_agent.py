"""
nmap_recon_agent.py — Stealthy Nmap Reconnaissance & Triage Agent.

Pipeline role:
    MANAGER → OSINT → RECON → [NMAP RECON] → AUTH → VULN → REPORT

Takes the hosts Shodan confirmed are live and in-scope, runs stealthy
active scans to enumerate what is REALLY open right now (Shodan data
can be stale), then produces a PRIORITISED hand-off list telling the
Auth and Vuln agents — and the human specialist — which hosts to
focus on and why.

Discovery and triage ONLY. Never runs exploits, brute-force,
or intrusive checks. Those stay under human control.

Build with:  build_nmap_agent(llm)
Tasks with:  build_nmap_tasks(agent, prior_task)
"""
from crewai import Agent, Task

try:
    from tools.nmap_tool import NmapDiscoveryTool, NmapTriageTool, NmapScanTool
    from tools.shodansnipe_tools import GetResultsTool, GetScopeTool
except ImportError:
    from nmap_tool import NmapDiscoveryTool, NmapTriageTool, NmapScanTool
    from shodansnipe_tools import GetResultsTool, GetScopeTool

# Shared assessment doctrine (discover-don't-assume, modern-infra focus, impact-driven scoring).
try:
    from tools.doctrine import ASSESSMENT_DOCTRINE as _DOCTRINE
except ImportError:
    try:
        from doctrine import ASSESSMENT_DOCTRINE as _DOCTRINE
    except ImportError:
        _DOCTRINE = ""


def build_nmap_agent(llm) -> Agent:
    """Create the Stealthy Network Reconnaissance Specialist."""
    _tools = [
        NmapDiscoveryTool(),
        NmapTriageTool(),
        GetResultsTool(),
        GetScopeTool(),
    ]
    # Optional curl-style confirmation for web services found open.
    try:
        from tools.http_validate_tool import HttpProbeTool
        _tools.append(HttpProbeTool())
    except ImportError:
        try:
            from http_validate_tool import HttpProbeTool
            _tools.append(HttpProbeTool())
        except ImportError:
            pass
    return Agent(
        role="Stealthy Network Reconnaissance Specialist",
        goal=(
            "Take the in-scope hosts discovered via Shodan, run stealthy active "
            "Nmap scans to confirm what is REALLY exposed right now, and produce a "
            "prioritised hand-off telling the Auth agent, Vuln agent, and senior "
            "specialist which hosts deserve intensive attention — and exactly why."
        ),
        backstory=(
            "You are a careful reconnaissance operator. Shodan tells you what was "
            "seen at some point in the past; you verify it live with low-and-slow "
            "Nmap scans (SYN scan, T2 polite timing) so you do not trip alarms. "
            "You enumerate open ports and service versions but you NEVER exploit, "
            "brute-force, or run intrusive scripts — that authority belongs to the "
            "Auth and Vuln agents and the human specialist who come after you. "
            "Your deliverable is a clear, ranked list: which hosts are worth the "
            "specialist's deep-testing time, which services on them matter, and what "
            "they should look at first. "
            "You always stay strictly inside the defined scope. "
            "You flag every case where live Nmap is materially worse than Shodan "
            "suggested — those gaps matter most."
        ),
        tools=_tools,
        llm=llm,
        verbose=True,
        allow_delegation=False,
        max_iter=12,
    )


def build_nmap_tasks(agent: Agent, prior_task: Task | None = None) -> list[Task]:
    """
    Two-task pipeline:
      Task 1 — discovery scan: confirm live ports vs Shodan data
      Task 2 — triage: ranked hand-off for Auth/Vuln agents and human

    If prior_task is supplied (the Recon task), its output feeds context
    into Task 1 so the agent knows which IPs to scan.
    """
    ctx = [prior_task] if prior_task else []

    # ── Task 1: Live discovery scan ────────────────────────────────────────
    scan_task = Task(
        description=(
            _DOCTRINE + "\n"
            "Read the in-scope hosts confirmed by the Recon agent. "
            "Call get_current_results if you need the IP list — it returns the "
            "hosts Shodan found this session.\n\n"
            "For the most interesting hosts (highest Shodan risk first, "
            "batch of max 10 IPs per nmap_discovery_scan call), run a "
            "stealthy discovery scan to confirm which ports are actually "
            "open right now and what service versions are running.\n\n"
            "Default port list covers all high-risk services: "
            "21,22,23,25,80,443,445,1433,3306,3389,5432,5900,6379,"
            "8080,8443,9200,27017,2375,2376,6443,10250,10255,2379.\n\n"
            "Stealthy: intensity=stealth (T2 SYN). "
            "If permission error, retry with intensity=normal (-sV, no raw socket).\n\n"
            "Do NOT scan anything outside scope — get_scope confirms the boundary.\n\n"
            "After scanning, compare what Nmap finds to what Shodan reported:\n"
            "  - Ports Shodan missed but Nmap sees → flag immediately (CRITICAL delta)\n"
            "  - Services that changed (version bump or new product)\n"
            "  - Hosts Shodan said were live but are now offline\n\n"
            "Process all Critical and High hosts from recon FIRST (deep look). Then run a "
            "thin confirmation sweep over the remaining in-scope hosts too — recon's risk "
            "ranking comes from possibly-stale Shodan data, so a host it marked LOW can still "
            "have a dangerous port open right now. Do not skip a host entirely just because "
            "recon scored it LOW; at minimum confirm its ports against the default list. Only "
            "drop hosts that are confirmed offline or out of scope."
        ),
        expected_output=(
            "Per-host live scan results: confirmed open ports, service versions, "
            "and deltas vs Shodan data (ports added, ports closed, version changes)."
        ),
        agent=agent,
        context=ctx,
    )

    # ── Task 2: Triage and hand-off ────────────────────────────────────────
    triage_task = Task(
        description=(
            "Using nmap_triage_for_specialist on all scanned hosts, produce the "
            "HAND-OFF document for the Auth agent, Vuln agent, and human specialist.\n\n"
            "The hand-off MUST:\n\n"
            "  1. Rank every scanned host HIGH / MEDIUM / LOW for intensive testing.\n"
            "     HIGH   — any port in the critical list open "
            "(23/Telnet, 2375/Docker, 6443/K8s, 3389/RDP, 5900/VNC, "
            "9200/Elastic, 6379/Redis, 27017/Mongo, 1433/MSSQL, 3306/MySQL).\n"
            "     MEDIUM — SSH/FTP/SMTP/LDAP exposed or 5+ non-standard ports.\n"
            "     LOW    — only standard web ports (80/443), nothing else.\n\n"
            "  2. For each HIGH host: state exactly which services warrant "
            "deep testing and what the specialist should verify first "
            "(advisory only — you are recommending, not performing).\n\n"
            "  3. Flag every host where the live Nmap picture is materially worse "
            "than Shodan suggested — ports Shodan missed, services that changed, "
            "version numbers that imply unpatched CVEs.\n\n"
            "  4. End with a one-line summary:\n"
            "     N HIGH hosts. Test <IP:port> first — <one-sentence reason>.\n\n"
            "Remember: you prepare work for the Auth and Vuln agents and the human "
            "specialist. Be precise and actionable. Leave intensive testing "
            "decisions to them."
        ),
        expected_output=(
            "Prioritised hand-off JSON and summary: ranked host list with "
            "HIGH/MEDIUM/LOW, per-host advisory, Shodan delta notes, "
            "and one-line summary of N high-priority hosts and which to test first."
        ),
        agent=agent,
        context=[scan_task],
    )

    return [scan_task, triage_task]
