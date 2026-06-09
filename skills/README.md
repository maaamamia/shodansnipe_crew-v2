# ShodanSnipe — Skills

Repeatable patterns for extending ShodanSnipe. Each file is self-contained: read the one
that matches what you're adding, copy the template, fill it in, wire it, test it.

| Skill | Use it when you want to… |
|-------|--------------------------|
| [BUILDING_TOOLS.md](BUILDING_TOOLS.md) | Add a new capability a tool can call (a Shodan query, an API lookup, a parser) |
| [BUILDING_AGENTS.md](BUILDING_AGENTS.md) | Add a new specialist to the crew pipeline |
| [ADDING_A_CAPABILITY_MODULE.md](ADDING_A_CAPABILITY_MODULE.md) | Expose a tool as a toggle in the Control Center |
| [ADDING_A_SCAN_PROFILE.md](ADDING_A_SCAN_PROFILE.md) | Add a one-click preset (like Quick / Comprehensive / All) |
| [ADDING_AN_MCP_TOOL.md](ADDING_AN_MCP_TOOL.md) | Expose a capability to MCP clients (Claude Desktop, Cursor, CrewAI) |

## The three rules every extension follows

1. **Enforce scope in code, not just prompts.** A tool must refuse any target outside the
   active scope, even if an agent asks it to.
2. **Tools return strings, never raise.** On error, return a short error/`"no data"` string so
   the crew keeps running. A raised exception kills the run.
3. **Keep destructive/intensive actions under human control.** Discovery and reporting are
   fine to automate; anything that actively touches a target stays behind the autonomy mode.

## The shape of the system (so you know where things go)

```
tools/      → a capability (BaseTool)            ← BUILDING_TOOLS
agents/     → a specialist that uses tools        ← BUILDING_AGENTS
core/settings.py → registries: modules, profiles  ← ADDING_A_CAPABILITY_MODULE / _A_SCAN_PROFILE
core/mcp_tools.py → the MCP surface               ← ADDING_AN_MCP_TOOL
launchers/poc_crew.py → wires agents into the run pipeline
```
