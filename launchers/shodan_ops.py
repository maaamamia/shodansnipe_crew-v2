"""
shodan_ops.py — ShodanOps: a guided, human-in-the-loop ASM console.

Unlike poc_crew.py (which runs the whole pipeline end-to-end), ShodanOps puts YOU in
the driver's seat: run one phase at a time, read the result, decide the next move,
inject your own Shodan queries, call any connected MCP tool from the prompt, and save
a sequence of steps as a reusable "flow". Every step pauses for your direction — the
human is in the loop at each step, by design.

This console drives the SAME discovery/validation agents we already built (recon, osint,
vuln, threat, report, scope reconciliation). It is for AUTHORIZED, scoped assessment only:
discovery + validation, no exploitation.

Run:
    python core/server.py            # ShodanSnipe API at :8000 (separate window)
    python launchers/shodan_ops.py   # this console

Type 'help' once inside.
"""
from __future__ import annotations

import json
import os
import sys
import shlex

# ── make agents/ + tools/ importable whether run from launchers/ or root ──────
_HERE = os.path.dirname(os.path.abspath(__file__))
for _c in (os.path.dirname(_HERE), _HERE,
           os.path.join(os.path.dirname(_HERE), "agents"),
           os.path.join(os.path.dirname(_HERE), "tools")):
    if os.path.isdir(_c) and _c not in sys.path:
        sys.path.insert(0, _c)

import requests

SHODANSNIPE_URL = os.environ.get("SHODANSNIPE_URL", "http://127.0.0.1:8000")
FLOWS_DIR = os.environ.get("SHODANOPS_FLOWS", os.path.join(_HERE, "ops_flows"))
os.makedirs(FLOWS_DIR, exist_ok=True)


def _crewai_available() -> bool:
    import importlib.util
    return importlib.util.find_spec("crewai") is not None


def _find_venv_python() -> str | None:
    """Best-effort: locate a venv interpreter near the project that HAS crewai, so we can tell
    the user the exact command to use. Checks common venv layouts on Windows + POSIX."""
    root = os.path.dirname(_HERE)
    names = (".venv", "venv", "cvenv", "env", ".env")
    subs  = (["Scripts", "python.exe"], ["bin", "python"])
    for base in (root, _HERE):
        for n in names:
            for sub in subs:
                cand = os.path.join(base, n, *sub)
                if os.path.isfile(cand):
                    return cand
    return None


def _print_crewai_help() -> None:
    print("\n  [!] crewai is NOT installed in THIS Python — agent phases (osint/recon/…) can't run.")
    print(f"      current interpreter: {sys.executable}")
    venv = _find_venv_python()
    here = os.path.relpath(__file__, os.getcwd()) if os.getcwd() in __file__ else __file__
    if venv:
        print(f"      run ShodanOps with the crew's venv instead, e.g.:")
        print(f"          \"{venv}\" \"{here}\"")
    else:
        print("      run ShodanOps with the SAME interpreter your crewai.bat uses (the venv that")
        print("      has crewai), e.g.:  <your-venv>\\Scripts\\python launchers\\shodan_ops.py")
        print("      or install it here:  pip install \"crewai[anthropic]\"")
    print("      (HTTP-only commands — scope / query / profile / mcp — still work without crewai.)\n")


BANNER = r"""
  ____  _               _              ___
 / ___|| |__   ___   __| | __ _ _ __  / _ \ _ __  ___
 \___ \| '_ \ / _ \ / _` |/ _` | '_ \| | | | '_ \/ __|
  ___) | | | | (_) | (_| | (_| | | | | |_| | |_) \__ \
 |____/|_| |_|\___/ \__,_|\__,_|_| |_|\___/| .__/|___/   guided HITL ASM console
                                           |_|
  Authorized, scoped assessment only — discovery + validation, no exploitation.
"""

HELP = """
Commands (every action pauses for your next move — you are in the loop):

  SCOPE
    scope                       show current scope
    scope set <list...>         set scope from IPs / CIDRs / ASNs / domains (space-separated)

  DISCOVER / DRIVE
    query <shodan query>        run a raw scoped Shodan query NOW, show top hits
    profile                     quick broad surface profile of the current scope
    run <phase>                 run ONE phase, show its output, then pause
                                phases: osint recon reconcile nmap auth vuln threat report
    step                        run the next phase in the default pipeline, then pause
    pipeline                    show the default phase order + where you are

  TALK (live session — you are the manager directing the crew)
    talk <message>              talk to the MANAGER (ASM); it answers from session context
    talk @<agent> <message>     talk to a specific agent (osint recon auth vuln threat manager)
    talk reset                  clear the conversation history

  MCP (use any connected MCP tool from here)
    mcp list                    list tools from a connected MCP server (SHODANSNIPE_MCP_URL)
    mcp call <tool> <json-args> call an MCP tool with JSON arguments

  FLOWS (compose & replay your own sequences)
    flow new <name>             start recording a flow
    flow add <command...>       append a command to the recording flow
    flow save                   save the recording flow to disk
    flow list                   list saved flows
    flow run <name>             replay a saved flow (still pauses between steps unless --auto)
    flow show <name>            print a saved flow

  SESSION
    state                       what we've collected so far (phase outputs + sizes)
    next                        analyst-style "what we have / what to do next"
    set <KEY>=<VALUE>           set an env override for this session
                                (e.g. GLOBAL_LIMIT_MULTIPLIER=3, REFINE_MAX_LOOPS=2, REPORT_MAX_TOKENS=24000)
    save <file>                 dump the whole session (all phase outputs) to JSON
    help                        this text
    quit / exit                 leave
"""

PIPELINE = ["osint", "recon", "reconcile", "nmap", "auth", "vuln", "threat", "report"]


class Ops:
    def __init__(self):
        self.llm = None
        self.agents = {}            # phase -> built agent (lazy)
        self.builders = {}          # imported builders
        self._builder_errors = {}   # mod -> import error
        self.outputs = {}           # phase -> last output string
        self.target_org = os.environ.get("TARGET_ORG", "")
        self.scope_query = os.environ.get("TARGET_SCOPE", "")
        self.pipe_idx = 0
        self.recording = None       # {"name":..., "steps":[...]}
        self.chat_history = []      # live "talk" turns: [(speaker, text), ...]
        self._quit = False
        self._load_builders()

    # ── lazy import of the crew builders ─────────────────────────────────────
    def _load_builders(self):
        try:
            import poc_crew  # reuse its build_llm + run_crew_phase
            self._poc = poc_crew
        except Exception as e:
            self._poc = None
            print(f"[warn] poc_crew not importable ({e}); some phases unavailable.")
        for mod, names in [
            ("recon_agent", ["build_recon_agent", "build_recon_tasks"]),
            ("osint_agent", ["build_osint_agent", "build_osint_tasks", "build_osint_verify_task"]),
            ("vuln_agent", ["build_vuln_agent", "build_vuln_tasks"]),
            ("threat_intel_agent", ["build_threat_intel_agent", "build_threat_intel_task"]),
            ("report_agent", ["build_report_agent", "build_report_tasks"]),
            ("manager_agent", ["build_manager_agent", "build_manager_scope_reconciliation_task"]),
            ("nmap_recon_agent", ["build_nmap_agent", "build_nmap_tasks"]),
            ("auth_agent", ["build_auth_agent", "build_auth_tasks"]),
        ]:
            try:
                m = __import__(mod)
                for n in names:
                    self.builders[n] = getattr(m, n, None)
            except Exception as e:
                self._builder_errors[mod] = str(e)
        # If the agent modules failed to import for the crewai reason, say so ONCE, clearly.
        if not _crewai_available():
            _print_crewai_help()
        elif self._builder_errors:
            for mod, err in self._builder_errors.items():
                print(f"[warn] {mod} unavailable: {err}")

    def _autoconfigure_llm(self) -> str:
        """Make the LLM 'just work' with NO manual env vars: pull the provider + keys from the
        same place the crew uses (the project's llm module, then the server's persisted LLM
        settings) and load them into this process. Returns the detected provider."""
        # 1) the project's llm module — same config the crew reads.
        try:
            import llm as _llmmod  # noqa
            s = {}
            try:
                s = _llmmod.get_settings() or {}
            except Exception:
                s = {}
            for envk, sk in (("ANTHROPIC_API_KEY", "anthropic_key"),
                             ("OPENAI_API_KEY", "openai_key")):
                v = s.get(sk)
                if v and not os.environ.get(envk):
                    os.environ[envk] = v
            if s.get("provider") and not os.environ.get("LLM_PROVIDER"):
                os.environ["LLM_PROVIDER"] = s["provider"]
            if s.get("model") and not os.environ.get("LLM_MODEL"):
                os.environ["LLM_MODEL"] = s["model"]
        except Exception:
            pass
        # 2) the server's persisted LLM settings (works even if llm module masks keys).
        try:
            d = requests.get(f"{SHODANSNIPE_URL}/api/llm/settings", timeout=10).json()
            for envk, sk in (("ANTHROPIC_API_KEY", "anthropic_key"),
                             ("OPENAI_API_KEY", "openai_key")):
                v = d.get(sk)
                if v and not os.environ.get(envk):
                    os.environ[envk] = v
            if d.get("provider") and not os.environ.get("LLM_PROVIDER"):
                os.environ["LLM_PROVIDER"] = d["provider"]
        except Exception:
            pass
        # 3) detect provider: explicit env wins, else whichever key is present.
        prov = os.environ.get("LLM_PROVIDER", "").strip().lower()
        if not prov:
            if os.environ.get("ANTHROPIC_API_KEY"):
                prov = "anthropic"
            elif os.environ.get("OPENAI_API_KEY"):
                prov = "openai"
            else:
                prov = "anthropic"   # sensible default for this project
        return prov

    def _get_llm(self):
        if self.llm is None:
            if not _crewai_available():
                _print_crewai_help()
                raise RuntimeError("crewai not installed in this interpreter — see the note above.")
            if not self._poc:
                raise RuntimeError("poc_crew unavailable — cannot build an LLM.")
            provider = self._autoconfigure_llm()
            need = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}.get(provider)
            # Guard BEFORE build_llm so a missing key never triggers its sys.exit (which would
            # kill the console). Raise a normal error that the REPL catches and recovers from.
            if need and not os.environ.get(need):
                raise RuntimeError(
                    f"no LLM key found for provider '{provider}'. Configure it once in the "
                    f"Control Center (LLM settings) so it's saved, or set {need} in your env. "
                    "ShodanOps auto-loads it from there next time — no per-launch setup.")
            self.llm = self._poc.build_llm(provider)
            print(f"  [llm] provider={provider} model={os.environ.get('LLM_MODEL','(default)')}")
        return self.llm

    def _run_phase_crew(self, agent, tasks):
        if self._poc and hasattr(self._poc, "run_crew_phase"):
            return self._poc.run_crew_phase([agent], tasks)
        from crewai import Crew, Process
        return str(Crew(agents=[agent], tasks=tasks, process=Process.sequential).kickoff())

    # ── HTTP helpers ─────────────────────────────────────────────────────────
    def _get(self, path):
        return requests.get(f"{SHODANSNIPE_URL}{path}", timeout=15).json()

    def _post(self, path, payload):
        return requests.post(f"{SHODANSNIPE_URL}{path}", json=payload, timeout=120).json()

    # ── commands ─────────────────────────────────────────────────────────────
    def cmd_scope(self, args):
        if args and args[0] == "set":
            entries = args[1:]
            cidrs, asns, domains = [], [], []
            import re
            for s in entries:
                s = s.strip().strip(",")
                if re.match(r"^as\d+$", s, re.I):
                    asns.append(s.upper())
                elif re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", s):
                    cidrs.append(s)
                elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s):
                    cidrs.append(s + "/32")
                elif re.match(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$", s, re.I):
                    domains.append(s.lower())
            self._post("/api/scope", {"name": "ShodanOps scope", "cidrs": cidrs,
                                      "domains": domains, "asns": asns, "orgs": []})
            print(f"  scope set: {len(cidrs)} CIDR/IP, {len(asns)} ASN, {len(domains)} domain")
        try:
            sc = self._get("/api/scope")
            print(json.dumps(sc, indent=2)[:2000])
            if not self.scope_query and sc.get("domains"):
                self.scope_query = f'hostname:{sc["domains"][0]}'
        except Exception as e:
            print(f"  [err] {e}")

    def cmd_query(self, args):
        q = " ".join(args)
        if not q:
            print("  usage: query <shodan query>")
            return
        try:
            d = self._post("/api/search", {"query": q, "limit": int(os.environ.get("OPS_QUERY_LIMIT", "25"))})
            res = d.get("results", [])
            print(f"  '{q}' → {len(res)} results")
            for r in res[:25]:
                ip = r.get("ip_str") or r.get("ip", "?")
                ports = r.get("ports") or ([r.get("port")] if r.get("port") else [])
                prod = r.get("product", "") or (r.get("http", {}) or {}).get("server", "")
                host = (r.get("hostnames") or [""])[0]
                print(f"    {ip:16} {str(ports)[:24]:24} {host[:30]:30} {prod[:30]}")
        except Exception as e:
            print(f"  [err] {e}")

    def cmd_profile(self, args):
        """Quick broad profile: run the scope wide, tally ports/products."""
        sc = {}
        try:
            sc = self._get("/api/scope")
        except Exception:
            pass
        anchors = []
        for c in sc.get("cidrs", [])[:5]:
            anchors.append(f"net:{c}")
        for a in sc.get("asns", [])[:3]:
            anchors.append(f"asn:{a}")
        if not anchors and self.scope_query:
            anchors = [self.scope_query]
        if not anchors:
            print("  no scope to profile — set scope first.")
            return
        ports, prods, hosts = {}, {}, set()
        for a in anchors:
            try:
                d = self._post("/api/search", {"query": a, "limit": 100})
                for r in d.get("results", []):
                    hosts.add(r.get("ip_str") or r.get("ip"))
                    for p in (r.get("ports") or ([r.get("port")] if r.get("port") else [])):
                        ports[p] = ports.get(p, 0) + 1
                    pr = r.get("product") or (r.get("http", {}) or {}).get("server", "")
                    if pr:
                        prods[pr] = prods.get(pr, 0) + 1
            except Exception as e:
                print(f"  [warn] {a}: {e}")
        top_ports = sorted(ports.items(), key=lambda x: -x[1])[:15]
        top_prods = sorted(prods.items(), key=lambda x: -x[1])[:12]
        print(f"  PROFILE — {len(hosts)} hosts across {len(anchors)} anchors")
        print("  top ports   :", ", ".join(f"{p}({n})" for p, n in top_ports))
        print("  top products:", ", ".join(f"{p}({n})" for p, n in top_prods))
        self.outputs["profile"] = json.dumps({"hosts": len(hosts), "top_ports": top_ports, "top_products": top_prods})

    def cmd_run(self, args):
        if not args:
            print("  usage: run <osint|recon|reconcile|nmap|auth|vuln|threat|report>")
            return
        phase = args[0].lower()
        try:
            out = self._run_named_phase(phase)
        except Exception as e:
            print(f"  [err] {phase}: {e}")
            return
        if out is not None:
            self.outputs[phase] = out
            print(f"\n  [{phase}] complete — {len(out)} chars. Preview:")
            print("  " + out[:1200].replace("\n", "\n  "))
            print("\n  → Your move. (try: next | run <phase> | query <q> | report)")

    def _run_named_phase(self, phase):
        b = self.builders
        llm = self._get_llm()
        org, sq = self.target_org, self.scope_query
        if phase == "osint" and b.get("build_osint_agent"):
            ag = b["build_osint_agent"](llm)
            return self._run_phase_crew(ag, b["build_osint_tasks"](ag, org, sq))
        if phase == "recon" and b.get("build_recon_agent"):
            ag = b["build_recon_agent"](llm)
            seed = self.outputs.get("osint", "")
            return self._run_phase_crew(ag, b["build_recon_tasks"](ag, org, sq, osint_intel=seed))
        if phase == "reconcile" and b.get("build_manager_scope_reconciliation_task"):
            ag = b["build_manager_agent"](llm)
            t = b["build_manager_scope_reconciliation_task"](
                ag, osint_output=self.outputs.get("osint", ""),
                recon_output=self.outputs.get("recon", ""),
                nmap_output=self.outputs.get("nmap", ""))
            return self._run_phase_crew(ag, [t])
        if phase == "nmap" and b.get("build_nmap_agent"):
            ag = b["build_nmap_agent"](llm)
            return self._run_phase_crew(ag, b["build_nmap_tasks"](ag))
        if phase == "auth" and b.get("build_auth_agent"):
            ag = b["build_auth_agent"](llm)
            return self._run_phase_crew(ag, b["build_auth_tasks"](ag, self.outputs.get("recon", "")))
        if phase == "vuln" and b.get("build_vuln_agent"):
            ag = b["build_vuln_agent"](llm)
            return self._run_phase_crew(ag, b["build_vuln_tasks"](
                ag, self.outputs.get("recon", ""), self.outputs.get("auth", "")))
        if phase == "threat" and b.get("build_threat_intel_agent"):
            ag = b["build_threat_intel_agent"](llm)
            return self._run_phase_crew(ag, [b["build_threat_intel_task"](
                ag, vuln_output=self.outputs.get("vuln", ""), recon_output=self.outputs.get("recon", ""))])
        if phase == "report" and b.get("build_report_agent"):
            ag = b["build_report_agent"](llm)
            tasks = b["build_report_tasks"](
                ag,
                recon_output=self.outputs.get("recon", ""),
                osint_output=self.outputs.get("osint", ""),
                auth_output=self.outputs.get("auth", ""),
                vuln_output=self.outputs.get("vuln", ""),
                threat_output=self.outputs.get("threat", ""),
                target_org=org, scope_query=sq)
            return self._run_phase_crew(ag, tasks)
        raise RuntimeError(f"phase '{phase}' unavailable (agent not loaded or unknown phase)")

    def cmd_step(self, args):
        if self.pipe_idx >= len(PIPELINE):
            print("  pipeline complete. 'report' or 'next' to wrap up.")
            return
        phase = PIPELINE[self.pipe_idx]
        self.pipe_idx += 1
        print(f"  → next pipeline phase: {phase}")
        self.cmd_run([phase])

    def cmd_pipeline(self, args):
        for i, p in enumerate(PIPELINE):
            mark = "→" if i == self.pipe_idx else ("✓" if p in self.outputs else " ")
            print(f"   {mark} {p}")

    # ── MCP ──────────────────────────────────────────────────────────────────
    def _mcp_tools(self):
        url = os.environ.get("SHODANSNIPE_MCP_URL", "http://127.0.0.1:8000/mcp")
        from crewai_tools import MCPServerAdapter
        return MCPServerAdapter({"url": url, "transport": "streamable-http"})

    def cmd_mcp(self, args):
        if not args:
            print("  usage: mcp list | mcp call <tool> <json-args>")
            return
        try:
            if args[0] == "list":
                with self._mcp_tools() as tools:
                    for t in tools:
                        print(f"   - {t.name}: {getattr(t, 'description', '')[:80]}")
            elif args[0] == "call" and len(args) >= 2:
                tool_name = args[1]
                payload = {}
                if len(args) > 2:
                    try:
                        payload = json.loads(" ".join(args[2:]))
                    except Exception:
                        print("  [err] args must be valid JSON")
                        return
                with self._mcp_tools() as tools:
                    tool = next((t for t in tools if t.name == tool_name), None)
                    if not tool:
                        print(f"  [err] tool '{tool_name}' not found. 'mcp list' to see options.")
                        return
                    print("  result:", str(tool.run(**payload))[:1500])
        except ImportError:
            print('  [err] MCP support not installed. pip install "crewai-tools[mcp]"')
        except Exception as e:
            print(f"  [err] MCP: {e}")

    # ── flows ────────────────────────────────────────────────────────────────
    def cmd_flow(self, args):
        if not args:
            print("  usage: flow new|add|save|list|run|show ...")
            return
        sub = args[0]
        if sub == "new":
            self.recording = {"name": args[1] if len(args) > 1 else "flow", "steps": []}
            print(f"  recording flow '{self.recording['name']}' — use 'flow add <command>'")
        elif sub == "add":
            if not self.recording:
                print("  no flow recording — 'flow new <name>' first.")
                return
            self.recording["steps"].append(" ".join(args[1:]))
            print(f"  added step {len(self.recording['steps'])}: {' '.join(args[1:])}")
        elif sub == "save":
            if not self.recording:
                print("  nothing to save.")
                return
            path = os.path.join(FLOWS_DIR, self.recording["name"] + ".json")
            with open(path, "w") as f:
                json.dump(self.recording, f, indent=2)
            print(f"  saved → {path} ({len(self.recording['steps'])} steps)")
            self.recording = None
        elif sub == "list":
            for fn in sorted(os.listdir(FLOWS_DIR)):
                if fn.endswith(".json"):
                    print("   -", fn[:-5])
        elif sub == "show" and len(args) > 1:
            path = os.path.join(FLOWS_DIR, args[1] + ".json")
            print(open(path).read() if os.path.isfile(path) else "  not found")
        elif sub == "run" and len(args) > 1:
            path = os.path.join(FLOWS_DIR, args[1] + ".json")
            if not os.path.isfile(path):
                print("  not found"); return
            flow = json.load(open(path))
            auto = "--auto" in args
            for stepcmd in flow.get("steps", []):
                print(f"\n  ▶ flow step: {stepcmd}")
                self.dispatch(stepcmd)
                if not auto:
                    if input("  [enter]=continue  s=skip rest > ").strip().lower() == "s":
                        break
        else:
            print("  usage: flow new|add|save|list|run|show ...")

    # ── session ──────────────────────────────────────────────────────────────
    def cmd_talk(self, args):
        """Live conversation with your crew. You are the engagement lead/manager giving
        direction; the agent answers using the current session context.
            talk <message>            → talk to the MANAGER (ASM)
            talk @recon <message>     → talk to a specific agent (osint/recon/auth/vuln/threat/manager)
            talk reset                → clear the conversation history
        """
        if not args:
            print("  usage: talk [<@agent>] <message>   (agents: manager osint recon auth vuln threat)")
            print("         talk reset   — clear the conversation")
            return
        if args[0].lower() == "reset":
            self.chat_history = []
            print("  conversation cleared.")
            return

        agent_map = {
            "manager": "build_manager_agent", "osint": "build_osint_agent",
            "recon": "build_recon_agent", "auth": "build_auth_agent",
            "vuln": "build_vuln_agent", "threat": "build_threat_intel_agent",
        }
        who = "manager"
        if args[0].startswith("@"):
            who = args[0][1:].lower()
            args = args[1:]
        message = " ".join(args).strip()
        if not message:
            print("  say something: talk <message>")
            return
        builder = agent_map.get(who)
        if not builder or not self.builders.get(builder):
            print(f"  no '{who}' agent available (need crewai + {builder}). Try: talk <message>")
            return

        try:
            llm = self._get_llm()
        except Exception as e:
            print(f"  [err] {e}")
            return

        # Build a compact session digest so the agent answers grounded in what we have.
        digest = f"Scope: {self.scope_query or '(unset)'} | Target: {self.target_org or '(unset)'}\n"
        if self.outputs:
            digest += "Collected so far:\n"
            for k, v in self.outputs.items():
                digest += f"  - {k}: {v[:600]}\n"
        else:
            digest += "No phases run yet.\n"
        convo = "".join(f"{s}: {t}\n" for s, t in self.chat_history[-8:])

        from crewai import Task
        ag = self.builders[builder](llm)
        task = Task(
            description=(
                "You are speaking LIVE with your engagement lead (the human acting as your "
                "manager) in an authorized, scoped assessment. Answer their message directly and "
                "concretely, grounded in the session context. Give your read, propose next moves, "
                "or carry out the reasoning they ask for. Be specific and brief.\n\n"
                f"=== SESSION CONTEXT ===\n{digest}\n"
                f"=== CONVERSATION SO FAR ===\n{convo or '(start of conversation)'}\n"
                f"=== LEAD'S MESSAGE ===\n{message}\n"),
            expected_output="A direct, concrete reply to the lead — analysis and/or next steps.",
            agent=ag,
        )
        print(f"\n  …{who} is thinking…")
        try:
            reply = self._run_phase_crew(ag, [task])
        except Exception as e:
            print(f"  [err] {who}: {e}")
            return
        reply = str(reply).strip()
        self.chat_history.append(("Lead", message))
        self.chat_history.append((who, reply))
        print(f"\n  [{who}]\n  " + reply[:2000].replace("\n", "\n  "))
        print("\n  → keep talking (talk <msg>), or run a phase to act on it.")

    def cmd_state(self, args):
        if not self.outputs:
            print("  nothing collected yet.")
            return
        print(f"  org='{self.target_org}'  scope='{self.scope_query}'")
        for k, v in self.outputs.items():
            print(f"   {k:10} {len(v):>8} chars")

    def cmd_next(self, args):
        """Analyst-style 'what we have / what to do next' — uses the manager if available."""
        have = {k: len(v) for k, v in self.outputs.items()}
        done = set(self.outputs)
        todo = [p for p in PIPELINE if p not in done]
        print("  WHAT WE HAVE :", ", ".join(f"{k}({v}ch)" for k, v in have.items()) or "nothing yet")
        print("  NOT YET RUN  :", ", ".join(todo) or "all phases run")
        # cheap heuristic suggestions
        sug = []
        if "recon" not in done:
            sug.append("run recon (or profile first to plan queries)")
        if "recon" in done and "reconcile" not in done:
            sug.append("run reconcile to lock scope & surface gaps")
        if "reconcile" in done and "vuln" not in done:
            sug.append("run vuln to confirm exposures")
        if "vuln" in done and "report" not in done:
            sug.append("run report")
        if sug:
            print("  SUGGEST      :", " ; ".join(sug))

    def cmd_set(self, args):
        for a in args:
            if "=" in a:
                k, v = a.split("=", 1)
                os.environ[k.strip()] = v.strip()
                print(f"  env {k.strip()}={v.strip()}")

    def cmd_save(self, args):
        path = args[0] if args else "shodanops_session.json"
        with open(path, "w") as f:
            json.dump({"org": self.target_org, "scope": self.scope_query, "outputs": self.outputs}, f, indent=2)
        print(f"  session → {path}")

    # ── dispatch ─────────────────────────────────────────────────────────────
    def dispatch(self, line):
        line = line.strip()
        if not line:
            return
        # record into a flow if we're recording AND it's not a flow meta-command
        if self.recording and not line.startswith("flow"):
            self.recording["steps"].append(line)
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]
        table = {
            "scope": self.cmd_scope, "query": self.cmd_query, "profile": self.cmd_profile,
            "run": self.cmd_run, "step": self.cmd_step, "pipeline": self.cmd_pipeline,
            "mcp": self.cmd_mcp, "flow": self.cmd_flow, "state": self.cmd_state,
            "next": self.cmd_next, "set": self.cmd_set, "save": self.cmd_save,
            "talk": self.cmd_talk, "ask": self.cmd_talk,
            "help": lambda a: print(HELP),
        }
        if cmd in ("quit", "exit"):
            self._quit = True
            return
        fn = table.get(cmd)
        if not fn:
            print(f"  unknown command '{cmd}' — type 'help'")
            return
        fn(args)

    def repl(self):
        print(BANNER)
        if not self.target_org:
            self.target_org = input("  Target org (e.g. Acme Corp): ").strip()
        if not self.scope_query:
            self.scope_query = input("  Scope query (e.g. org:\"Acme Corp\" hostname:acme.com), or blank: ").strip()
        print("  Type 'help' for commands. Every step pauses for you.\n")
        while True:
            try:
                line = input("shodan-ops> ")
            except (EOFError, KeyboardInterrupt):
                print("\n  bye."); break
            try:
                self.dispatch(line)
            except SystemExit:
                # A tool or build_llm called sys.exit — do NOT kill the console.
                print("  [err] a command tried to exit the process — staying in the console "
                      "(type 'quit' to leave).")
            except Exception as e:
                print(f"  [err] {e}")
            if getattr(self, "_quit", False):
                print("  bye."); break


if __name__ == "__main__":
    Ops().repl()
