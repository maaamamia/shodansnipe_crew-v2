# Wiring the new pieces in

Two new modules + edits to three agents. Drop the files into your tree:

    tools/shodan_query.py        # escaping + strict scope matcher + protocol/version catalog
    tools/report_render.py       # deterministic HTML report (never truncates)
    agents/recon_agent.py        # wider ports, version/HTTP capture, comma-quoting note
    agents/vuln_agent.py         # SSH/FTP/SMTP/LDAP/Oracle/MQ-family queries + version capture
    agents/report_agent.py       # protocols grouped w/ versions, HTTP column on the map

## 1. Kill the `org:"…, Inc"` scope leak (the value' bug)

The leak is server-side: Shodan's `org:` is a substring/token match, so `org:"Dell"`
returns hosts whose org is `value'bug bug`. Quoting fixes the *query*; the
strict matcher fixes the *results*. Wire it into `scope.py::apply_scope` where you
currently decide `in_scope`:

    from shodan_query import org_in_scope

    ok, confidence = org_in_scope(host.get("org",""), scope.orgs)   # confidence: exact|contains|reject
    if not ok:
        out_of_scope.append(host); continue
    host["scope_confidence"] = confidence   # carry it into the report

Build queries with the escaper instead of f-strings:

    from shodan_query import build_query
    q = build_query(org="Company, Inc", ports=[443,8443], net="203.0.113.0/24")

## 2. Protocols — "don't limit"

    from shodan_query import protocol_queries_for, version_capture_queries
    for item in protocol_queries_for('net:203.0.113.0/24'):     # 57 queries, 8 categories
        run shodan_search(item["query"])
    for item in version_capture_queries('net:203.0.113.0/24'):  # HTTP/2, TLS, SSH, versions
        run shodan_search(item["query"])

Pass `categories=[...]` to narrow, or leave it off for full coverage.

## 3. Versions + HTTP/1.1 vs HTTP/2

    from shodan_query import extract_versions
    v = extract_versions(host)   # -> product, version, ssh_version, http_server, http_protocol, tls_versions

## 4. The report that "cut off" — and prettifying it

The cut-off was the LLM write-task hitting its output token ceiling mid-document.
Two fixes:

  a) Raise the ceiling on the report writer's LLM (in your launcher / build_llm):
         LLM(model="...", max_tokens=8000)     # default is often ~1k–4k

  b) Render deterministically — Python has no token limit, so this can't truncate:
         from report_render import save_html_report
         save_html_report(report_markdown, "report.html",
                          target_org="Company, Inc",
                          scope_query='net:203.0.113.0/24 org:"Company, Inc"')

`reports/sample_report.html` is a rendered example so you can see the format.
Open it in a browser, or print → Save as PDF for a client deliverable.
