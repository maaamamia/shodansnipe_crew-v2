# Skill — Adding an MCP Tool

The MCP server (`core/mcp_tools.py`) exposes capabilities to MCP clients (Claude Desktop,
Cursor, CrewAI) over `http://127.0.0.1:8000/mcp`. It ships with six tools: `shodan_search`,
`get_results`, `get_scope`, `set_scope`, `get_history`, `cve_intel`.

**Key idea:** an MCP tool is a thin wrapper that **proxies an existing REST endpoint** on the
server. It should not re-implement logic — it calls the server, which already enforces scope,
clamps limits, and audits. That's how a Control Center preference automatically applies to MCP
calls too (both go through the same REST route).

## Add the tool

```python
# core/mcp_tools.py
@mcp.tool()
def my_capability(target: str, limit: int = 25) -> str:
    """Short description the MCP client shows the user. Say what it returns.

    Args:
        target: what to look up, e.g. 'acme.com'
        limit:  max items (the server clamps this to your settings)
    """
    return _post("/api/my-endpoint", {"target": target, "limit": int(limit)})
```

`_get(path)` and `_post(path, body)` helpers already exist in `mcp_tools.py` — use them so the
call goes through the server (and inherits scope-gating, clamping, and the audit log).

If the REST endpoint doesn't exist yet, add it to `core/server.py` first (a normal
`@app.get` / `@app.post` route), then have the MCP tool proxy it.

## Don't enforce limits in the tool

Let the **server** clamp. For example `shodan_search` passes the requested limit through and
`/api/search` clamps it to the saved `max_results_per_query`. If you clamp again in the tool you
defeat the Control Center setting.

## Verify it's exposed

```bash
# the tool list the UI viewer + clients read
curl http://127.0.0.1:8000/api/mcp/tools          # should include "my_capability"

# a browser hitting /mcp gets HTTP 406 — that means it's MOUNTED and working (not an error)
curl -i http://127.0.0.1:8000/mcp/
```

The Control Center's **MCP tools** panel reads `/api/mcp/tools`, so your new tool shows up there
with its arguments automatically.

## Checklist

- [ ] Added with `@mcp.tool()` in `core/mcp_tools.py`
- [ ] Docstring + typed args (the client surfaces these)
- [ ] Proxies a REST endpoint via `_get`/`_post` — no duplicated logic
- [ ] Does **not** re-clamp limits (server does it, so settings apply)
- [ ] Backing `/api/…` route exists in `server.py`
- [ ] Appears in `GET /api/mcp/tools` and the Control Center MCP panel
