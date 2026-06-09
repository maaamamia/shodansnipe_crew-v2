#!/usr/bin/env python3
r"""
cli.py — one entry point for ShodanSnipe: server, crew, and settings.

Cross-platform (no .bat needed). Pick your crew and set limits from flags —
no code edits, no UI required.

    python cli.py serve                       # start the web console + MCP (:8000)

    python cli.py crew --provider anthropic \         # run the crew …
        --stages recon,vuln,report \                  #   …only these stages
        --max-results 200 --scope 'org:"Acme Corp"'   #   …with this result cap

    python cli.py stages                      # list the pipeline stages + state
    python cli.py stages --set recon,report   # enable exactly these (deps auto-added)
    python cli.py settings                     # show all tunables
    python cli.py settings --set max_results_per_query=200 report_max_tokens=12000

The crew sub-command sets the same env vars the server passes (CREW_STAGES,
SHODAN_MAX_RESULTS, …) and launches your orchestrator, so the CLI, the UI
button, and crewai.bat all behave identically.
"""
from __future__ import annotations
import argparse, os, sys, subprocess, shutil, importlib.util

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import settings  # noqa: E402

# Packages the SERVER needs (the crew venv is separate, handled by setup_crewai.bat).
SERVER_DEPS = ["fastapi", "uvicorn[standard]", "shodan", "aiohttp",
               "pydantic", "requests", "fastmcp"]
# import-name -> pip-name, for verification
_IMPORT_TO_PIP = {"fastapi": "fastapi", "uvicorn": "uvicorn[standard]",
                  "shodan": "shodan", "aiohttp": "aiohttp", "pydantic": "pydantic",
                  "requests": "requests", "fastmcp": "fastmcp"}


def _have(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except Exception:
        return False


def _server_url() -> str:
    return os.environ.get("SHODANSNIPE_URL", "http://127.0.0.1:8000").rstrip("/")


def _find_launcher() -> list[str] | None:
    for c in ("launchers/poc_crew.py", "poc_crew.py",
              "agents/example_crew.py", "example_crew.py"):
        if os.path.exists(os.path.join(_HERE, c)):
            return [sys.executable, c]
    return None


def cmd_serve(_a):
    os.chdir(_HERE)
    subprocess.run([sys.executable, "server.py"])


def cmd_crew(a):
    if a.profile:
        settings.apply_profile(a.profile)
    if a.stages:
        settings.set_stages([s.strip() for s in a.stages.split(",") if s.strip()])
    if a.max_results:
        settings.update_settings({"max_results_per_query": a.max_results})
    if a.max_queries:
        settings.update_settings({"max_queries_per_run": a.max_queries})

    s = settings.get_settings()
    selected = settings.selected_stage_keys()
    launcher = (a.launcher.split() if a.launcher else None) or _find_launcher()
    if not launcher:
        sys.exit("No crew launcher found. Pass --launcher \"python agents/example_crew.py\".")

    env = {**os.environ,
           "LLM_PROVIDER":     a.provider,
           "SHODANSNIPE_URL":  os.environ.get("SHODANSNIPE_URL", "http://127.0.0.1:8000"),
           "CREW_MODE":        a.mode,
           "MCP_AUTONOMY_MODE": a.mode,
           "CREW_STAGES":      ",".join(selected),
           "SHODAN_MAX_RESULTS": str(s["max_results_per_query"]),
           "CREW_MAX_QUERIES":   str(s["max_queries_per_run"]),
           "CREW_CREDIT_BUDGET": str(s["credit_budget"]),
           "NMAP_MAX_HOSTS":     str(s["nmap_max_hosts_per_call"]),
           "REPORT_MAX_TOKENS":  str(s["report_max_tokens"])}
    if a.scope:
        env["TARGET_SCOPE"] = a.scope
    if "nmap" not in selected:
        env["ENABLE_NMAP"] = "0"

    print(f"Provider : {a.provider}")
    print(f"Stages   : {' -> '.join(selected)}")
    print(f"Limits   : results<= {s['max_results_per_query']}, queries<= {s['max_queries_per_run']}")
    print(f"Launcher : {' '.join(launcher)}\n")
    subprocess.run(launcher, cwd=_HERE, env=env)


def cmd_stages(a):
    if a.set is not None:
        settings.set_stages([s.strip() for s in a.set.split(",") if s.strip()])
    for st in settings.get_stages():
        box = "x" if st["enabled"] else " "
        dep = f"  (needs {', '.join(st['requires'])})" if st["requires"] else ""
        lock = "  [always on]" if st["always_on"] else ""
        print(f"  [{box}] {st['key']:7} {st['name']}{dep}{lock}")
    print("\n  run order:", " -> ".join(settings.selected_stage_keys()))


def cmd_profiles(a):
    if a.apply:
        settings.apply_profile(a.apply)
        print(f"applied profile: {a.apply}\n")
    gp = settings.get_profiles()
    for p in gp["profiles"]:
        mark = "*" if p["name"] == gp["active"] else " "
        print(f" {mark} {p['name']:14} {p['module_count']:2} modules | stages: {'+'.join(p['stages'])}")
        print(f"     {p['desc']}")
    print(f"\n active profile: {gp['active']}")


def cmd_settings(a):
    if a.set:
        patch = {}
        for kv in a.set:
            if "=" not in kv:
                sys.exit(f"Bad --set '{kv}', expected key=value")
            k, v = kv.split("=", 1)
            patch[k.strip()] = int(v) if v.strip().lstrip("-").isdigit() else v.strip()
        settings.update_settings(patch)
    cur = settings.get_settings()
    for k, v in cur.items():
        if k == "stages":
            v = ",".join(kk for kk, on in v.items() if on)
        print(f"  {k:24} = {v}")


def main():
    p = argparse.ArgumentParser(prog="cli.py", description="ShodanSnipe control CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("serve", help="start the web console + MCP server").set_defaults(fn=cmd_serve)

    c = sub.add_parser("crew", help="run the crew with chosen stages/limits")
    c.add_argument("--provider", default=os.environ.get("LLM_PROVIDER", "anthropic"),
                   choices=["anthropic", "openai", "ollama"])
    c.add_argument("--profile", choices=["quick", "comprehensive", "all"],
                   help="apply a preset (stages+modules+limits) before running")
    c.add_argument("--stages", help="comma list, e.g. recon,vuln,report (deps auto-added)")
    c.add_argument("--scope", help='override scope, e.g. \'org:"Acme Corp"\'')
    c.add_argument("--mode", default="hitl", choices=["hitl", "scoped", "full"])
    c.add_argument("--max-results", type=int, dest="max_results")
    c.add_argument("--max-queries", type=int, dest="max_queries")
    c.add_argument("--launcher", help='override launcher cmd, e.g. "python agents/example_crew.py"')
    c.set_defaults(fn=cmd_crew)

    st = sub.add_parser("stages", help="list or set enabled pipeline stages")
    st.add_argument("--set", help="comma list of stages to enable")
    st.set_defaults(fn=cmd_stages)

    se = sub.add_parser("settings", help="show or set tunables")
    se.add_argument("--set", nargs="+", metavar="key=value", help="one or more key=value")
    se.set_defaults(fn=cmd_settings)

    pr = sub.add_parser("profiles", help="list scan profiles or apply one")
    pr.add_argument("--apply", choices=["quick", "comprehensive", "all"],
                    help="apply a profile (stages+modules+limits)")
    pr.set_defaults(fn=cmd_profiles)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
