"""
example_crew_mcp.py — ShodanSnipe + CrewAI over MCP.

Fixed three bugs from the original:
  1. import was `from crewai.mcp import MCPServerAdapter`  -> doesn't exist.
     Correct module is crewai_tools.
  2. server params had no `transport` key -> adapter can't connect.
  3. URL pointed at the REST server, which had no /mcp (that's the 404).
     MCP is now mounted INSIDE server.py (see mcp_tools.py) — same :8000 port,
     one process. There is no separate mcp_server.py.

Run order:
    pip install "crewai-tools[mcp]" fastmcp requests
    python server.py            # REST + MCP @ 127.0.0.1:8000  (window 1)
    python example_crew_mcp.py  # crew                          (window 2)
"""
import os

try:
    from crewai import Agent, Crew, Process, Task
    from crewai_tools import MCPServerAdapter      # <-- crewai_tools, not crewai.mcp
    MCP_AVAILABLE = True
except ImportError as e:
    MCP_AVAILABLE = False
    _IMPORT_ERR = e


# server.py serves /mcp on its own port now (mounted via mcp_tools.py).
MCP_URL = os.getenv("SHODANSNIPE_MCP_URL", "http://127.0.0.1:8000/mcp")

SERVER_PARAMS = {
    "url": MCP_URL,
    "transport": "streamable-http",   # required; matches server.py mount (FastMCP "http")
}


def run_mcp_crew():
    if not MCP_AVAILABLE:
        print("crewai_tools MCP support not available:", _IMPORT_ERR)
        print('Install it:  pip install "crewai-tools[mcp]"')
        print("Or use example_crew.py with the custom BaseTool wrappers (REST, no MCP).")
        return

    # Context manager handles connect + teardown of the MCP session.
    with MCPServerAdapter(SERVER_PARAMS) as snipe_tools:
        print(f"Discovered {len(snipe_tools)} tools from ShodanSnipe MCP:")
        for t in snipe_tools:
            print(f"  - {t.name}")

        analyst = Agent(
            role="Threat Intelligence Analyst",
            goal="Identify exposed infrastructure and active CVE exposure for the target.",
            backstory=(
                "You are a defensive security analyst using ShodanSnipe to discover "
                "and prioritise external attack surface risks within an authorized scope."
            ),
            tools=snipe_tools,            # all tools auto-discovered from /mcp
            verbose=True,
        )

        hunt = Task(
            description=(
                "1. set_scope(name='Acme', orgs=['Acme Corp']) — set scope FIRST.\n"
                "2. shodan_search('org:\"Acme Corp\" port:443,80,8080,8443')\n"
                "3. shodan_search('org:\"Acme Corp\" ssl.cert.expired:true')\n"
                "4. cve_intel('CVE-2024-1234: RCE in FortiGate SSL-VPN, FortiOS 7.0-7.2, CVSS 9.8')\n"
                "5. Write a 3-paragraph summary of what you found, in-scope only."
            ),
            expected_output=(
                "Scope confirmation, search result summaries, CVE detection queries, "
                "and a findings summary."
            ),
            agent=analyst,
        )

        crew = Crew(agents=[analyst], tasks=[hunt],
                    process=Process.sequential, verbose=True)
        result = crew.kickoff()
        print("\nResult:\n", result)


if __name__ == "__main__":
    run_mcp_crew()
