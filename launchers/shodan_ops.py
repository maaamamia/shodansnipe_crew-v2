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
    mission <objective>         MANAGER orchestrates: plans, dispatches agents, gate-keeps
                                (mission auto|pick <objective> for full-plan / manager-picks modes)
    chat                        CONTINUOUS session: it waits for your reply after each answer
    chat @<agent>               continuous session with a specific agent
                                (inside: plain text=msg · /mission · /run <phase> · /save · /who · /exit)
    talk <message>              one-shot message to the MANAGER (ASM)
    talk @<agent> <message>     one-shot message to a specific agent (osint recon auth vuln threat manager)
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
    # which short name maps to which agent builder
    AGENT_MAP = {
        "manager": "build_manager_agent", "osint": "build_osint_agent",
        "recon": "build_recon_agent", "auth": "build_auth_agent",
        "vuln": "build_vuln_agent", "threat": "build_threat_intel_agent",
    }

    def _talk_send(self, who, message):
        """Send ONE message to <who>, grounded in session context + running history.
        Appends both turns to chat_history and returns the agent's reply text.
        Raises RuntimeError on any problem (no crewai/agent/key) so callers can recover."""
        builder = self.AGENT_MAP.get(who)
        if not builder or not self.builders.get(builder):
            raise RuntimeError(f"no '{who}' agent available (need crewai + {builder}).")
        llm = self._get_llm()   # may raise (caught by caller); never exits the console

        # Compact session digest so the agent answers grounded in what we have.
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
                "You are working LIVE with your engagement lead (the human acting as your "
                "manager) in an authorized, scoped assessment. You think on the fly and ACT on "
                "their command. If the request calls for discovery, USE YOUR TOOLS to actually "
                "run the searches / enrichment / confirmation NOW — do not merely propose a plan "
                "and hand it back. Stay anchored to scope (org:/net:/asn:/hostname:); never run "
                "an unanchored, internet-wide query. After acting, report concisely WHAT YOU DID "
                "and WHAT YOU FOUND (key hosts, ports, products, anomalies). If the lead is only "
                "asking a question, answer it directly. Be specific and brief.\n\n"
                f"=== SESSION CONTEXT ===\n{digest}\n"
                f"=== CONVERSATION SO FAR ===\n{convo or '(start of conversation)'}\n"
                f"=== LEAD'S MESSAGE ===\n{message}\n"),
            expected_output="What you did + what you found (or a direct answer), grounded in real tool results.",
            agent=ag,
        )
        print(f"\n  …{who} is thinking…")
        reply = str(self._run_phase_crew(ag, [task])).strip()
        self.chat_history.append(("Lead", message))
        self.chat_history.append((who, reply))
        return reply

    def _print_reply(self, who, reply):
        print(f"\n  [{who}]\n  " + reply.replace("\n", "\n  "))

    # ── Manager as orchestrator + gatekeeper ─────────────────────────────────────
    MISSION_AGENTS = ["osint", "recon", "nmap", "auth", "vuln", "threat"]

    def _manager_plan(self, objective):
        """MANAGER decides which specialists to engage for the mission, and in what order.
        Returns a list of {agent, focus}; [] if it can't be parsed."""
        from crewai import Task
        ag = self.builders["build_manager_agent"](self._get_llm())
        digest = f"Scope: {self.scope_query or '(unset)'} | Target: {self.target_org or '(unset)'}"
        task = Task(
            description=(
                "You are the engagement MANAGER. The lead has given you a mission. Decide which "
                "specialist agents to engage and in what order, with a one-line focus for each. "
                "Available: osint, recon, nmap, auth, vuln, threat. Engage only what the mission "
                "needs; respect dependencies (recon after osint; auth/vuln after recon).\n\n"
                f"{digest}\nMISSION: {objective}\n\n"
                'Respond ONLY with JSON: {"agents":[{"agent":"osint","focus":"..."}, ...]} — '
                "no prose, no markdown fences."),
            expected_output='JSON {"agents":[{"agent":"...","focus":"..."}]}',
            agent=ag)
        try:
            raw = str(self._run_phase_crew(ag, [task])).strip()
            raw = raw[raw.find("{"): raw.rfind("}") + 1]
            data = json.loads(raw)
            out = []
            for a in data.get("agents", []):
                name = str(a.get("agent", "")).lower()
                if name in self.MISSION_AGENTS:
                    out.append({"agent": name, "focus": str(a.get("focus", ""))})
            return out
        except Exception:
            return []

    def _manager_gatekeep(self, objective, agent, output):
        """MANAGER reviews a specialist's output against mission + scope and rules on what
        passes, what to drop, and what's missing. Returns the ruling text."""
        from crewai import Task
        ag = self.builders["build_manager_agent"](self._get_llm())
        digest = f"Scope: {self.scope_query or '(unset)'} | Target: {self.target_org or '(unset)'}"
        task = Task(
            description=(
                "You are the engagement MANAGER and the GATEKEEPER — the final authority on scope. "
                "Review the specialist output below against the mission and scope. State concisely: "
                "what is CONFIRMED in-scope and PASSES, what to DROP (out-of-scope / CDN-shared / "
                "unverified), and what is MISSING that warrants another pass. Be decisive.\n\n"
                f"{digest}\nMISSION: {objective}\nAGENT: {agent}\n\nOUTPUT:\n{str(output)[:6000]}\n"),
            expected_output="Gatekeeper ruling: passes / drop / missing.",
            agent=ag)
        try:
            return str(self._run_phase_crew(ag, [task])).strip()
        except Exception as e:
            return f"(gatekeeper unavailable: {e})"

    def cmd_mission(self, args):
        """Manager-orchestrated mission. You give the objective; the MANAGER plans which agents to
        engage, dispatches them, and gate-keeps every result. You can override at each gate.
            mission <objective>          → GATE: pause + override before each agent (default)
            mission auto <objective>     → run the manager's full plan, no pausing
            mission pick <objective>     → manager picks the subset and runs it
        """
        if not args:
            print("  usage: mission [auto|pick] <objective>")
            return
        mode = "gate"
        if args and args[0].lower() in ("auto", "pick", "gate"):
            mode = args[0].lower()
            args = args[1:]
        objective = " ".join(args).strip()
        if not objective:
            print("  give an objective: mission <what you want done>")
            return
        try:
            self._get_llm()
        except Exception as e:
            print(f"  [err] {e}")
            return
        if not self.builders.get("build_manager_agent"):
            print("  no manager agent available (need crewai + build_manager_agent).")
            return

        print(f"\n  …manager planning the mission…")
        plan = self._manager_plan(objective)
        if not plan:
            plan = [{"agent": a, "focus": ""} for a in self.MISSION_AGENTS]
            print("  (couldn't parse a plan — falling back to the full chain)")
        print(f"\n  ┌─ MISSION [{mode}]: {objective}")
        print(  "  │  manager's dispatch plan:")
        for i, step in enumerate(plan, 1):
            f = (" — " + step["focus"]) if step.get("focus") else ""
            print(f"  │   {i}. {step['agent']:<7}{f}")
        print(  "  └─ manager gate-keeps each result; you can override.\n")

        for step in plan:
            agent = step.get("agent", "").lower()
            if agent not in self.MISSION_AGENTS:
                continue
            focus = step.get("focus", "")
            if mode == "gate":
                ans = input(f"  engage {agent}? [y]es / [s]kip / [o]verride focus: ").strip().lower()
                if ans.startswith("s"):
                    print(f"    skipped {agent}.")
                    continue
                if ans.startswith("o"):
                    nf = input("    new focus: ").strip()
                    if nf:
                        focus = nf
                        self.chat_history.append(("Lead (focus)", f"[{agent}] {nf}"))
            print(f"  …{agent} engaging{(' — ' + focus) if focus else ''}…")
            try:
                out = self._run_named_phase(agent)
            except Exception as e:
                print(f"    [err] {agent}: {e}")
                continue
            if out is None:
                print(f"    {agent} produced nothing (agent not loaded?).")
                continue
            self.outputs[agent] = out
            print(f"    {agent} done ({len(out)} chars).")
            ruling = self._manager_gatekeep(objective, agent, out)
            print("    [gatekeeper] " + ruling[:700].replace("\n", "\n      "))
            if mode == "gate":
                ov = input("    accept manager's call? [y]es / [o]verride: ").strip().lower()
                if ov.startswith("o"):
                    note = input("    your ruling: ").strip()
                    if note:
                        self.chat_history.append(("Lead (override)", f"[{agent}] {note}"))
                        print("    ✎ override recorded.")

        print("\n  …manager correlating the mission…")
        combined = "\n".join(f"{k}:\n{v[:800]}" for k, v in self.outputs.items()
                             if k in self.MISSION_AGENTS)
        wrap = self._manager_gatekeep(objective, "ALL", combined or "(no agent output)")
        print("  [manager]\n  " + wrap[:1500].replace("\n", "\n  "))
        print("\n  → /save to commit this mission to the engagement + report, or keep going.")

    def _ensure_run(self):
        """Register this interactive session as an engagement run ONCE, so saved findings have
        something to attach to and it shows up in the same run history as batch runs. Returns
        the run id (or None if the server is unreachable)."""
        if getattr(self, "run_id", None):
            return self.run_id
        try:
            d = self._post("/api/runs", {
                "target": self.target_org or "",
                "scope": self.scope_query or "",
                "source": "shodan-ops-chat",
                "status": "interactive",
                "mode": "hitl",
            })
            self.run_id = (d or {}).get("recorded", {}).get("id") or (d or {}).get("id")
        except Exception:
            self.run_id = None
        return self.run_id

    def _save_engagement(self, who):
        """Commit what the chat session has discovered into the engagement: the hosts the agent
        actually searched (pulled from the server's current results — already in the main DB via
        search history) plus a session note capturing the agent's latest analysis. Everything is
        tagged with this run's id and source='chat', so the standard report / findings export
        picks it up. Returns (host_count, ok)."""
        run_id = self._ensure_run()
        findings = []
        # 1) hosts the agent searched this session (server holds them; they're already in history)
        try:
            res = self._get("/api/results")
            hosts = res.get("results", res) if isinstance(res, dict) else res
            for h in (hosts or [])[:200]:
                if not isinstance(h, dict):
                    continue
                findings.append({
                    "run_id": run_id, "source": "chat", "agent": who,
                    "asset": h.get("ip_str") or h.get("ip"),
                    "ports": h.get("ports"),
                    "product": h.get("product"),
                    "org": h.get("org"),
                    "hostnames": (h.get("hostnames") or [])[:5],
                    "risk": h.get("risk_level"),
                    "cdn_shared": h.get("cdn_shared", False),
                    "in_scope": h.get("in_scope"),
                    "scope_reason": h.get("scope_reason"),
                })
        except Exception:
            pass
        # 2) a session note: the agent's latest analysis, so the engagement keeps the reasoning
        last = next((t for s, t in reversed(self.chat_history) if s == who), "")
        if last:
            findings.append({
                "run_id": run_id, "source": "chat-note", "agent": who,
                "title": f"Analyst-directed note ({who})",
                "evidence": last[:4000],
                "scope": self.scope_query or "",
            })
        if not findings:
            return (0, False)
        try:
            self._post("/api/findings", {"findings": findings})
            return (sum(1 for f in findings if f.get("source") == "chat"), True)
        except Exception:
            return (0, False)

    def cmd_talk(self, args):
        """One-shot message to the crew (use `chat` for a continuous back-and-forth).
            talk <message>            → talk to the MANAGER (ASM)
            talk @recon <message>     → talk to a specific agent
            talk reset                → clear the conversation history
        """
        if not args:
            print("  usage: talk [<@agent>] <message>   (agents: manager osint recon auth vuln threat)")
            print("         talk reset   — clear the conversation")
            print("         tip: 'chat' opens a continuous session that waits for your replies")
            return
        if args[0].lower() == "reset":
            self.chat_history = []
            print("  conversation cleared.")
            return
        who = "manager"
        if args[0].startswith("@"):
            who = args[0][1:].lower()
            args = args[1:]
        message = " ".join(args).strip()
        if not message:
            print("  say something: talk <message>")
            return
        if who not in self.AGENT_MAP:
            print(f"  unknown agent '{who}'. agents: " + " ".join(self.AGENT_MAP))
            return
        try:
            reply = self._talk_send(who, message)
        except Exception as e:
            print(f"  [err] {e}")
            return
        self._print_reply(who, reply)
        print("\n  → keep talking (talk <msg>), 'chat' for a continuous session, "
              "or run a phase to act on it.")

    def cmd_chat(self, args):
        """Continuous, interactive NLP session with an agent. After each reply it WAITS for
        your next message — plain text is sent to the agent, only /-commands are parsed.
            chat                 → continuous session with the MANAGER
            chat @osint          → continuous session with a specific agent
        Inside chat:
            <plain text>         → message to the current agent
            @osint <text>        → send one message to another agent
            @osint               → switch the current agent
            /run <phase>         → run a phase to ACT on the discussion
            /scope  /reset  /who <agent>  /help  /exit
        """
        who = "manager"
        if args and args[0].startswith("@"):
            who = args[0][1:].lower()
        if who not in self.AGENT_MAP:
            print(f"  unknown agent '{who}'. agents: " + " ".join(self.AGENT_MAP))
            return
        # Preflight ONCE so we don't enter the loop only to fail on every line.
        builder = self.AGENT_MAP.get(who)
        if not self.builders.get(builder):
            print(f"  no '{who}' agent available (need crewai + {builder}).")
            return
        try:
            self._get_llm()
        except Exception as e:
            print(f"  [err] {e}")
            return

        print(f"\n  ┌─ chat with {who} — I'll wait for your reply after each answer.")
        print(  "  │  plain text = message   @<agent> = redirect   /run <phase> = act")
        print(  "  │  /save = commit findings to the engagement + report   /scope  /reset  /who  /exit")
        print(  "  └─ (actions run live; nothing enters the report until you /save)\n")

        while True:
            try:
                line = input(f"  {who}\u203a ").strip()    # waits here for YOUR input
            except (EOFError, KeyboardInterrupt):
                print("\n  leaving chat.")
                return
            if not line:
                continue

            # /-commands
            if line.startswith("/"):
                p = line[1:].split()
                c = p[0].lower() if p else ""
                rest = p[1:]
                if c in ("exit", "quit", "q", "leave", "bye"):
                    print("  leaving chat.")
                    return
                if c in ("help", "?"):
                    print("  plain text = message · @<agent> redirect · /mission <obj> · "
                          "/run <phase> · /save · /scope · /reset · /who <agent> · /exit")
                    continue
                if c == "mission":
                    if not rest:
                        print("  usage: /mission [auto|pick] <objective>  "
                              "(manager plans, dispatches agents, gate-keeps)")
                    else:
                        self.cmd_mission(rest)
                    continue
                if c == "save":
                    print("  …committing this session to the engagement…")
                    n, ok = self._save_engagement(who)
                    if ok:
                        print(f"  ✓ saved {n} host finding(s) + session note to engagement "
                              f"{self.run_id or '(run)'} — will appear in the standard report / "
                              "findings export.")
                    else:
                        print("  nothing to save yet (run a search/discovery in chat first), "
                              "or the server is unreachable.")
                    continue
                if c == "reset":
                    self.chat_history = []
                    print("  conversation cleared.")
                    continue
                if c == "scope":
                    self.cmd_scope([])
                    continue
                if c == "run":
                    if not rest:
                        print("  usage: /run <phase>  (osint recon reconcile nmap auth vuln threat report)")
                    else:
                        self.cmd_run(rest)
                    continue
                if c in ("who", "agent"):
                    if rest and rest[0].lstrip("@").lower() in self.AGENT_MAP:
                        who = rest[0].lstrip("@").lower()
                        print(f"  now talking to {who}.")
                    else:
                        print(f"  agents: " + " ".join(self.AGENT_MAP))
                    continue
                print(f"  unknown chat command '/{c}' — try /help")
                continue

            # @agent redirect / switch
            target, msg = who, line
            if line.startswith("@"):
                toks = line.split(None, 1)
                cand = toks[0][1:].lower()
                if cand in self.AGENT_MAP:
                    if len(toks) == 1:                 # bare "@osint" → switch default
                        who = cand
                        print(f"  now talking to {who}.")
                        continue
                    target, msg = cand, toks[1]        # "@osint <text>" → one message there
                else:
                    print(f"  unknown agent '{cand}'. agents: " + " ".join(self.AGENT_MAP))
                    continue

            try:
                reply = self._talk_send(target, msg)
            except Exception as e:
                print(f"  [err] {target}: {e}")
                continue
            self._print_reply(target, reply)
            # loop returns to the prompt and WAITS for your next message

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
            "talk": self.cmd_talk, "ask": self.cmd_talk, "chat": self.cmd_chat,
            "mission": self.cmd_mission,
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
