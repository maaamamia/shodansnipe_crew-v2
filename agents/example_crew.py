"""
example_crew.py — Reference crew assembled from the separated team-member agents.

This shows how the now-modular agents snap together. Each agent lives in its
own file in agents/ and is an "official team member" you can reuse, test in
isolation, or visualise individually:

    agents/recon_agent.py       — Attack Surface Reconnaissance Specialist
    agents/vuln_agent.py        — Vulnerability Intelligence Analyst
    agents/report_agent.py      — Security Report Writer
    agents/nmap_recon_agent.py  — Stealthy Network Reconnaissance Specialist

The full production pipeline is in launchers/poc_crew.py. This file is a
minimal, readable example of the same building blocks.

Usage:
    pip install crewai requests
    python core/server.py          # ShodanSnipe running at :8000
    python agents/example_crew.py
"""

import os
import sys

# Make tools/ and agents/ importable whether run from agents/ or the root.
_HERE = os.path.dirname(os.path.abspath(__file__))
for _c in (os.path.dirname(_HERE), _HERE):
    if os.path.isfile(os.path.join(_c, "_bootstrap.py")):
        sys.path.insert(0, _c)
        break
try:
    import _bootstrap  # noqa: F401
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "tools"))
    sys.path.insert(0, _HERE)

from crewai import Crew, Process, LLM

# Each team member is its own module — import the builders.
from recon_agent import build_recon_agent, build_recon_tasks
from vuln_agent import build_vuln_agent, build_vuln_tasks
from report_agent import build_report_agent, build_report_tasks

# ---------------------------------------------------------------------------
# Target — change these
# ---------------------------------------------------------------------------
TARGET_ORG   = os.getenv("TARGET_ORG", "Acme")
TARGET_SCOPE = os.getenv("TARGET_SCOPE", 'org:"Acme Corp" hostname:acme.com')
CVE_ADVISORY = os.getenv("CVE_ADVISORY", """
CVE-2024-38475 - Apache HTTP Server mod_rewrite vulnerability.
Unauthenticated remote code execution via malformed HTTP requests.
Affects Apache 2.4.0 through 2.4.59.
CVSS Score: 9.8 Critical. Patch available in 2.4.60.
""")


def build_llm() -> LLM:
    # max_tokens MUST be set explicitly. Without it the provider default caps the
    # completion, which silently truncates long analysis JSON and multi-section
    # reports mid-stream — the #1 cause of "report is only 5 findings long".
    # Mirror this in launchers/poc_crew.py (its build_llm has the same gap).
    provider = os.getenv("LLM_PROVIDER", "openai")
    max_tokens = int(os.getenv("LLM_MAX_TOKENS", "8000"))
    if provider == "anthropic":
        return LLM(model="claude-sonnet-4-6",
                   api_key=os.getenv("ANTHROPIC_API_KEY"), provider="anthropic",
                   max_tokens=max(max_tokens, 8000), temperature=0.2)
    if provider == "ollama":
        return LLM(model="openai/llama3.2",
                   base_url=os.getenv("OLLAMA_URL", "http://localhost:11434/v1"),
                   api_key="ollama", provider="litellm",
                   max_tokens=max_tokens, temperature=0.2)
    return LLM(model="gpt-4o-mini", api_key=os.getenv("OPENAI_API_KEY"),
               max_tokens=max(max_tokens, 16000), temperature=0.2)


def build_example_crew(llm) -> Crew:
    """Assemble the three core team members into a sequential crew."""
    recon  = build_recon_agent(llm)
    vuln   = build_vuln_agent(llm)
    report = build_report_agent(llm)

    recon_tasks  = build_recon_tasks(recon, TARGET_ORG, TARGET_SCOPE)
    vuln_tasks   = build_vuln_tasks(vuln, TARGET_ORG, CVE_ADVISORY,
                                    prior_task=recon_tasks[-1])
    report_tasks = build_report_tasks(report,
                                      prior_tasks=[recon_tasks[-1], vuln_tasks[-1]])

    return Crew(
        agents=[recon, vuln, report],
        tasks=[*recon_tasks, *vuln_tasks, *report_tasks],
        process=Process.sequential,
        verbose=True,
    )


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  ShodanSnipe + CrewAI - Example Threat-Hunting Crew")
    print(f"  Target: {TARGET_ORG}")
    print("  Team:   Recon -> Vuln Analyst -> Report Writer")
    print("=" * 60 + "\n")

    crew = build_example_crew(build_llm())
    result = crew.kickoff()

    print("\n" + "=" * 60)
    print("  FINAL REPORT")
    print("=" * 60)
    print(result)
