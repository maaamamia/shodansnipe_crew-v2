"""
tools/report_render.py — Deterministic HTML renderer for the assessment report.

Why this exists:
  The report that "cut off" did so because the LLM write-task hit its output
  token ceiling mid-document. This renderer is plain Python — there is NO token
  limit — so it can NEVER truncate. Feed it whatever markdown the report agent
  produced and it emits a complete, styled, print-ready HTML dossier.

Two entry points:
  build_html_report(markdown, target_org=..., scope_query=...) -> str(html)
  save_html_report(markdown, path, **meta)                     -> path

The aesthetic: a dark "threat dossier" — Newsreader display serif, IBM Plex Sans
body, JetBrains Mono for queries/banners, sharp severity accents. Everything word-
wraps (long banners, queries, cert CNs) and it prints cleanly to PDF.

Self-contained: a tiny markdown subset parser (headings, bold, inline code, fenced
code, tables, lists, hr) — no external deps.
"""
from __future__ import annotations
import re, html, datetime

SEVERITY_COLORS = {
    "critical": "var(--crit)",
    "high":     "var(--high)",
    "medium":   "var(--med)",
    "low":      "var(--low)",
}


# ─────────────────────────────────────────────────────────────────────────────
# Severity rollup — counted straight from the finding headers in the markdown
# ─────────────────────────────────────────────────────────────────────────────
def counts_from_markdown(md: str) -> dict:
    """Count Critical/High/Medium/Low from **Risk:** lines and finding headers."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for m in re.finditer(r"\*\*Risk:\*\*\s*([A-Za-z]+)", md):
        k = m.group(1).capitalize()
        if k in counts:
            counts[k] += 1
    if sum(counts.values()) == 0:  # fall back to bare keyword scan in headings
        for line in md.splitlines():
            if line.lstrip().startswith("#"):
                for k in counts:
                    if re.search(rf"\b{k}\b", line, re.I):
                        counts[k] += 1
    return counts


# ─────────────────────────────────────────────────────────────────────────────
# Minimal, safe markdown -> HTML (subset used by the report)
# ─────────────────────────────────────────────────────────────────────────────
def _inline(text: str) -> str:
    text = html.escape(text, quote=False)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", text)
    text = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)",
                  r'<a href="\2" target="_blank" rel="noopener">\1</a>', text)
    return text


def _sev_tag(word: str) -> str:
    w = word.lower()
    color = SEVERITY_COLORS.get(w)
    if not color:
        return html.escape(word)
    return f'<span class="sev sev-{w}">{html.escape(word.upper())}</span>'


def _render_table(rows: list[str]) -> str:
    cells = [[c.strip() for c in r.strip().strip("|").split("|")] for r in rows]
    if len(cells) >= 2 and all(set(c) <= set("-: ") for c in cells[1]):
        header, body = cells[0], cells[2:]
    else:
        header, body = cells[0], cells[1:]
    out = ['<div class="tablewrap"><table>']
    out.append("<thead><tr>" + "".join(f"<th>{_inline(c)}</th>" for c in header) + "</tr></thead>")
    out.append("<tbody>")
    for row in body:
        tds = []
        for c in row:
            # auto-badge severity words inside cells
            badged = re.sub(r"\b(Critical|High|Medium|Low)\b",
                            lambda m: _sev_tag(m.group(1)), _inline(c))
            tds.append(f"<td>{badged}</td>")
        out.append("<tr>" + "".join(tds) + "</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def markdown_to_html(md: str) -> str:
    lines = md.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    i, n = 0, len(lines)
    list_open = False

    def close_list():
        nonlocal list_open
        if list_open:
            out.append("</ul>")
            list_open = False

    while i < n:
        line = lines[i]

        # fenced code
        if line.strip().startswith("```"):
            close_list()
            i += 1
            buf = []
            while i < n and not lines[i].strip().startswith("```"):
                buf.append(html.escape(lines[i]))
                i += 1
            i += 1
            out.append(f'<pre class="code"><code>{chr(10).join(buf)}</code></pre>')
            continue

        # tables
        if line.strip().startswith("|") and "|" in line.strip()[1:]:
            close_list()
            tbl = []
            while i < n and lines[i].strip().startswith("|"):
                tbl.append(lines[i]); i += 1
            out.append(_render_table(tbl))
            continue

        # headings
        mh = re.match(r"^(#{1,6})\s+(.*)$", line)
        if mh:
            close_list()
            lvl = len(mh.group(1))
            txt = mh.group(2).strip()
            # badge a leading severity word in finding headers
            txt_html = re.sub(r"\b(Critical|High|Medium|Low)\b",
                              lambda m: _sev_tag(m.group(1)), _inline(txt))
            anchor = "sec-" + re.sub(r"[^a-z0-9]+", "-", txt.lower()).strip("-")[:48]
            out.append(f'<h{lvl} id="{anchor}">{txt_html}</h{lvl}>')
            i += 1
            continue

        # horizontal rule
        if re.match(r"^\s*([-*_])\1{2,}\s*$", line):
            close_list(); out.append('<hr/>'); i += 1; continue

        # list items
        ml = re.match(r"^\s*[-*+]\s+(.*)$", line)
        if ml:
            if not list_open:
                out.append("<ul>"); list_open = True
            body = re.sub(r"\b(Critical|High|Medium|Low)\b",
                          lambda m: _sev_tag(m.group(1)), _inline(ml.group(1)))
            out.append(f"<li>{body}</li>")
            i += 1
            continue

        # blank
        if not line.strip():
            close_list(); i += 1; continue

        # paragraph (gather until blank)
        close_list()
        para = [line]
        i += 1
        while i < n and lines[i].strip() and not re.match(r"^(#{1,6}\s|\s*[-*+]\s|\||```)", lines[i]):
            para.append(lines[i]); i += 1
        out.append(f"<p>{_inline(' '.join(para))}</p>")

    close_list()
    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# Full document
# ─────────────────────────────────────────────────────────────────────────────
_CSS = """
:root{
  --bg:#0e1116; --panel:#161b22; --panel2:#1b222c; --ink:#e6edf3; --muted:#8b98a5;
  --line:#283039; --accent:#4ea1ff;
  --crit:#ff4d4f; --high:#ff8c1a; --med:#f5c542; --low:#5fb878;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{
  margin:0; background:var(--bg); color:var(--ink);
  font-family:'IBM Plex Sans',system-ui,sans-serif; line-height:1.6;
  font-size:15px;
}
.wrap{max-width:980px;margin:0 auto;padding:0 28px 120px}
code,pre,.mono{font-family:'JetBrains Mono',ui-monospace,monospace}

/* masthead */
.masthead{
  border-bottom:2px solid var(--crit); padding:54px 0 26px; margin-bottom:8px;
  position:relative;
}
.masthead::before{
  content:"CLASSIFICATION // ATTACK SURFACE ASSESSMENT";
  font-family:'JetBrains Mono',monospace; font-size:11px; letter-spacing:.28em;
  color:var(--crit); display:block; margin-bottom:18px;
}
.masthead h1{
  font-family:'Newsreader',Georgia,serif; font-weight:600; font-size:42px;
  line-height:1.1; margin:0 0 10px;
}
.masthead .scope{
  font-family:'JetBrains Mono',monospace; font-size:13px; color:var(--muted);
  word-break:break-all; background:var(--panel); border:1px solid var(--line);
  border-radius:6px; padding:8px 12px; display:inline-block; margin-top:6px;
}
.meta{display:flex;gap:26px;flex-wrap:wrap;margin-top:18px;font-size:12px;color:var(--muted);
  font-family:'JetBrains Mono',monospace;letter-spacing:.04em}
.meta b{color:var(--ink);font-weight:500}

/* rollup cards */
.rollup{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:30px 0 10px}
.card{
  background:var(--panel); border:1px solid var(--line); border-top:3px solid var(--line);
  border-radius:8px; padding:16px 18px;
}
.card.crit{border-top-color:var(--crit)} .card.high{border-top-color:var(--high)}
.card.med{border-top-color:var(--med)}  .card.low{border-top-color:var(--low)}
.card .num{font-family:'Newsreader',serif;font-size:38px;line-height:1;font-weight:600}
.card.crit .num{color:var(--crit)} .card.high .num{color:var(--high)}
.card.med .num{color:var(--med)}    .card.low .num{color:var(--low)}
.card .lbl{font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.16em;
  text-transform:uppercase;color:var(--muted);margin-top:8px}

/* body content */
.content h2{
  font-family:'Newsreader',serif;font-weight:600;font-size:27px;margin:44px 0 12px;
  padding-bottom:8px;border-bottom:1px solid var(--line);
}
.content h3{font-family:'Newsreader',serif;font-weight:600;font-size:20px;margin:28px 0 8px;color:#cdd9e5}
.content h4{font-size:13px;font-family:'JetBrains Mono',monospace;letter-spacing:.08em;
  text-transform:uppercase;color:var(--muted);margin:18px 0 6px}
.content p{margin:10px 0;overflow-wrap:anywhere}
.content a{color:var(--accent)}
.content ul{margin:10px 0;padding-left:20px}
.content li{margin:5px 0;overflow-wrap:anywhere}
.content strong{color:#fff}
.content code{
  background:var(--panel2);border:1px solid var(--line);border-radius:4px;
  padding:1px 6px;font-size:.86em;color:#9fd0ff;word-break:break-all;
}
pre.code{
  background:#0a0d12;border:1px solid var(--line);border-left:3px solid var(--accent);
  border-radius:8px;padding:14px 16px;overflow-x:auto;font-size:13px;line-height:1.55;
  white-space:pre-wrap;word-break:break-word;
}
hr{border:none;border-top:1px dashed var(--line);margin:30px 0}

/* tables */
.tablewrap{overflow-x:auto;margin:14px 0;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:13.5px}
thead th{
  background:var(--panel2);text-align:left;padding:10px 12px;font-family:'JetBrains Mono',monospace;
  font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);
  border-bottom:1px solid var(--line);white-space:nowrap;
}
tbody td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top;
  overflow-wrap:anywhere;word-break:break-word;max-width:340px}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:rgba(78,161,255,.05)}

/* severity badges */
.sev{font-family:'JetBrains Mono',monospace;font-size:10.5px;font-weight:600;
  letter-spacing:.08em;padding:2px 7px;border-radius:4px;white-space:nowrap}
.sev-critical{background:rgba(255,77,79,.16);color:var(--crit);border:1px solid rgba(255,77,79,.4)}
.sev-high{background:rgba(255,140,26,.15);color:var(--high);border:1px solid rgba(255,140,26,.4)}
.sev-medium{background:rgba(245,197,66,.14);color:var(--med);border:1px solid rgba(245,197,66,.4)}
.sev-low{background:rgba(95,184,120,.14);color:var(--low);border:1px solid rgba(95,184,120,.4)}

footer{margin-top:60px;padding-top:18px;border-top:1px solid var(--line);
  font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:.04em}

@media (max-width:640px){.rollup{grid-template-columns:repeat(2,1fr)}.masthead h1{font-size:32px}}
@media print{
  body{background:#fff;color:#111}
  .card,.tablewrap,pre.code,.masthead .scope{break-inside:avoid}
  tbody tr:hover{background:none}
}
"""


def build_html_report(markdown: str, *, target_org: str = "Target",
                      scope_query: str = "", counts: dict | None = None,
                      generated: str | None = None,
                      profile: str = "Technical Assessment") -> str:
    """Render the report markdown into a complete, styled, never-truncated HTML doc."""
    counts = counts or counts_from_markdown(markdown)
    generated = generated or datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    # The masthead already shows the title + scope; drop a duplicate leading
    # "# ... " heading and an immediately-following "Scope:" line from the body.
    _lines = markdown.replace("\r\n", "\n").split("\n")
    while _lines and not _lines[0].strip():
        _lines.pop(0)
    if _lines and re.match(r"^#\s+", _lines[0]):
        _lines.pop(0)
        while _lines and not _lines[0].strip():
            _lines.pop(0)
        if _lines and re.match(r"^scope\s*:", _lines[0].strip(), re.I):
            _lines.pop(0)
    body_html = markdown_to_html("\n".join(_lines))

    rollup = "".join(
        f'<div class="card {cls}"><div class="num">{counts.get(k,0)}</div>'
        f'<div class="lbl">{k}</div></div>'
        for k, cls in (("Critical","crit"),("High","high"),("Medium","med"),("Low","low"))
    )
    scope_block = (f'<div class="scope">{html.escape(scope_query)}</div>'
                   if scope_query else "")

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Attack Surface Assessment — {html.escape(target_org)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Newsreader:opsz,wght@6..72,400;6..72,600&family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>{_CSS}</style>
</head><body><div class="wrap">
<header class="masthead">
  <h1>{html.escape(target_org)}</h1>
  {scope_block}
  <div class="meta">
    <span>PROFILE&nbsp; <b>{html.escape(profile)}</b></span>
    <span>GENERATED&nbsp; <b>{html.escape(generated)}</b></span>
    <span>FINDINGS&nbsp; <b>{sum(counts.values())}</b></span>
  </div>
</header>
<section class="rollup">{rollup}</section>
<main class="content">
{body_html}
</main>
<footer>ShodanSnipe // Attack Surface Assessment — authorized, scoped use only. Findings are confidence-tagged; verify inferred items before action.</footer>
</div></body></html>"""


def save_html_report(markdown: str, path: str, **meta) -> str:
    html_doc = build_html_report(markdown, **meta)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return path


if __name__ == "__main__":
    sample = """# ATTACK SURFACE ASSESSMENT — Example Corp
Scope: net:203.0.113.0/24

## EXECUTIVE SUMMARY
Risk: Critical — three internet-facing databases with no authentication and a
WebLogic admin console on 7001 expose immediate remote-code-execution paths.

PRIMARY SCOPE — Hosts: 14 | Critical: 3 | High: 5 | Immediate actions: 4

## CRITICAL & HIGH FINDINGS

### 1. Oracle WebLogic admin console — 203.0.113.10:7001
- **Risk:** Critical | **CVSS:** 9.8 | **Confidence:** confirmed
- **Asset:** 203.0.113.10:7001 (admin.example.com)
- **Exposure / Evidence:** WebLogic Server 12.2.1.3, T3 listener responding, HTTP/1.1
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application
- **Fix:** Restrict 7001 to management VLAN; patch to 14.1.1 | **Timeline:** Immediate

### 2. Redis — 203.0.113.22:6379
- **Risk:** High | **Confidence:** confirmed
- **Exposure / Evidence:** Redis 6.2.6, no auth, `INFO` returns

## ATTACK SURFACE MAP
| IP | Ports | Product / Version | HTTP | Risk | Scope |
|----|-------|-------------------|------|------|-------|
| 203.0.113.10 | 7001 | WebLogic 12.2.1.3 | HTTP/1.1 | Critical | Primary |
| 203.0.113.22 | 6379 | Redis 6.2.6 | — | High | Primary |
| 203.0.113.40 | 22 | OpenSSH 7.4 | — | Medium | Primary |

## MONITORING QUERIES
```
net:203.0.113.0/24 port:7001
net:203.0.113.0/24 port:6379
```
Detects WebLogic and Redis re-exposure.
"""
    out = save_html_report(sample, "/tmp/sample_report.html",
                           target_org="Example Corp", scope_query="net:203.0.113.0/24")
    print("wrote", out, "(", len(open(out).read()), "bytes )")
