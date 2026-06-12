"""
tools/nmap_tool.py — Nmap as a CrewAI tool (skill, not an agent)

Used by the Recon agent to confirm hosts are live and get OS/service details.
Stealthy by default: SYN scan, T2 timing, top-100 ports.
Requires: nmap binary installed (auto-located) + admin/root privileges on Windows.
Disable: set ENABLE_NMAP=0
Override path: set NMAP_PATH=C:\\Program Files (x86)\\Nmap\\nmap.exe
"""
from __future__ import annotations
import os, json, subprocess, shutil, socket, ipaddress
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

ENABLE_NMAP = os.environ.get("ENABLE_NMAP", "1").strip() == "1"


# ── Self-locating nmap resolver ───────────────────────────────────────────────
# Don't trust a single shutil.which() at import time — on Windows the Python
# process's PATH often differs from the shell's (so `where.exe nmap` works but
# shutil.which returns None). Instead the agent locates nmap itself: an explicit
# NMAP_PATH override, then PATH, then the standard install locations, validating
# each candidate by actually running `--version`. Resolution is cached on success
# and retried lazily at call time (a PATH that wasn't ready at import still works).
_NMAP_BIN_CACHE: str | None = None


def _candidate_nmap_paths() -> list[str]:
    cands: list[str] = []
    env = os.environ.get("NMAP_PATH", "").strip().strip('"')
    if env:
        cands.append(env)
    w = shutil.which("nmap") or shutil.which("nmap.exe")
    if w:
        cands.append(w)
    # Standard Windows install locations (32-bit installer → Program Files (x86))
    cands += [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ]
    # Common POSIX locations
    cands += [
        "/usr/bin/nmap", "/usr/local/bin/nmap",
        "/opt/homebrew/bin/nmap", "/snap/bin/nmap",
    ]
    seen, out = set(), []
    for c in cands:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _validate_nmap(path: str) -> bool:
    try:
        r = subprocess.run([path, "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def _resolve_nmap() -> str | None:
    """Return a working nmap path, or None. Caches the first success; retries on miss."""
    global _NMAP_BIN_CACHE
    if _NMAP_BIN_CACHE:
        return _NMAP_BIN_CACHE
    for cand in _candidate_nmap_paths():
        # a bare absolute path that exists, or a name resolvable on PATH
        if (os.path.isfile(cand) or shutil.which(cand)) and _validate_nmap(cand):
            _NMAP_BIN_CACHE = cand
            return cand
    return None


# Resolve once at import for the startup banner; tools/_nmap_available re-resolve lazily.
_nmap_bin = _resolve_nmap()


def _nmap_available() -> bool:
    global _nmap_bin
    if not ENABLE_NMAP:
        return False
    if not _nmap_bin:
        _nmap_bin = _resolve_nmap()   # lazy retry — PATH may not have been ready at import
    if not _nmap_bin:
        return False
    return _validate_nmap(_nmap_bin)


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


class NmapScanInput(BaseModel):
    ips: list = Field(description="List of IP addresses to scan (max 10)")
    ports: str = Field("", description="Port spec e.g. '80,443,8080' or '' for top-100")
    intensity: str = Field("stealth", description="stealth (T2 SYN) or normal (T3)")

class NmapScanTool(BaseTool):
    name: str = "nmap_scan"
    description: str = (
        "Confirm hosts are live and get open ports/services via nmap. "
        "Stealthy by default (SYN scan, T2). Max 10 IPs per call. "
        "Returns live hosts with ports and service info. "
        "Requires nmap binary installed and admin/root privileges. "
        "Returns error if ENABLE_NMAP=0 or nmap not installed."
    )
    args_schema: type = NmapScanInput

    def _run(self, ips: list, ports: str = "", intensity: str = "stealth") -> str:
        if not ENABLE_NMAP:
            return json.dumps({
                "status": "disabled",
                "note": "Set ENABLE_NMAP=1 and ensure nmap is installed to use this tool.",
            })

        if not _nmap_available():
            return json.dumps({
                "status": "nmap_not_found",
                "note": (
                    "nmap binary not found. "
                    "Windows: choco install nmap OR https://nmap.org/download.html "
                    "Run as Administrator for SYN scans. "
                    "Set NMAP_PATH to the nmap.exe location to override. "
                    "Set ENABLE_NMAP=0 to disable this tool."
                ),
            })

        # Safety: cap at 10 IPs
        ips = [str(ip).strip() for ip in ips[:10] if str(ip).strip()]
        if not ips:
            return json.dumps({"error": "No IPs provided"})

        # Build nmap command
        cmd = [_nmap_bin]
        if intensity == "stealth":
            cmd += ["-sS", "-T2"]  # SYN scan, slow timing
        else:
            cmd += ["-sV", "-T3"]  # Version detection, normal timing

        if ports:
            cmd += ["-p", ports]
        else:
            cmd += ["--top-ports", "100"]

        cmd += ["-oX", "-", "--open", "--host-timeout", "60s"]
        cmd += ips

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode != 0 and result.stderr:
                # Common Windows admin issue
                if "requires elevated" in result.stderr.lower() or "operation not permitted" in result.stderr.lower():
                    return json.dumps({
                        "status": "permission_error",
                        "note": "nmap SYN scan requires Administrator/root. Run PowerShell as Administrator.",
                        "fallback": "Set intensity=normal for -sV scan (no raw sockets needed) or ENABLE_NMAP=0",
                    })
                return json.dumps({"status": "error", "stderr": result.stderr[:500]})

            # Parse XML output
            import xml.etree.ElementTree as ET
            hosts_found = []
            try:
                root = ET.fromstring(result.stdout)
                for host in root.findall("host"):
                    status = host.find("status")
                    if status is None or status.get("state") != "up":
                        continue
                    addr = host.find("address")
                    ip = addr.get("addr") if addr is not None else "unknown"
                    ports_found = []
                    for port in host.findall(".//port"):
                        state = port.find("state")
                        if state is None or state.get("state") != "open":
                            continue
                        svc = port.find("service")
                        ports_found.append({
                            "port":     int(port.get("portid", 0)),
                            "protocol": port.get("protocol", "tcp"),
                            "service":  svc.get("name", "") if svc is not None else "",
                            "product":  svc.get("product", "") if svc is not None else "",
                            "version":  svc.get("version", "") if svc is not None else "",
                        })
                    hosts_found.append({"ip": ip, "status": "up", "open_ports": ports_found})
            except ET.ParseError:
                # Fall back to raw output summary
                hosts_found = [{"raw_output": result.stdout[:1000]}]

            # Register scanned IPs in session tracker
            _SESSION_SCANNED.update(ips)
            return json.dumps({
                "status": "ok",
                "hosts_scanned": len(ips),
                "hosts_live": len(hosts_found),
                "hosts": hosts_found,
                "session_budget_used": len(_SESSION_SCANNED),
                "session_budget_remaining": max(0, _SESSION_MAX - len(_SESSION_SCANNED)),
            }, indent=2)

        except subprocess.TimeoutExpired:
            return json.dumps({"status": "timeout", "note": "nmap timed out after 120s"})
        except PermissionError:
            return json.dumps({
                "status": "permission_error",
                "note": "Run as Administrator for nmap SYN scans on Windows.",
            })
        except Exception as e:
            return json.dumps({"status": "error", "error": str(e)})



# ─────────────────────────────────────────────────────────────────────────────
# NmapDiscoveryTool — confirmation scan per host list
# ─────────────────────────────────────────────────────────────────────────────

class NmapDiscoveryInput(BaseModel):
    ips: list = Field(description="List of IP addresses to scan (max 10 per call)")
    ports: str = Field(
        "21,22,23,25,80,443,445,1433,3306,3389,5432,5900,6379,8080,8443,9200,27017,2375,6443,10250",
        description="Port spec e.g. '80,443,3389' or empty for top-100",
    )
    intensity: str = Field(
        "stealth",
        description="stealth = SYN T2 (default, low noise), normal = -sV T3 (no raw socket needed)",
    )

# Session-level scan budget — shared across all NmapDiscoveryTool calls
_SESSION_SCANNED: set[str] = set()
_SESSION_MAX     = 30   # hard cap: never scan more than 30 unique IPs per crew run

class NmapDiscoveryTool(BaseTool):
    name: str = "nmap_discovery_scan"
    description: str = (
        "Run a stealthy Nmap discovery scan to confirm which ports are ACTUALLY open "
        "right now on up to 10 hosts. Shodan data can be stale — this verifies live state. "
        "Returns per-host: open ports, service names, product versions. "
        "Compares to Shodan data so caller can note changes. "
        "SYN scan (stealth) requires Administrator/root. "
        "Use intensity=normal if running without elevated privileges."
    )
    args_schema: type = NmapDiscoveryInput

    def _run(self, ips: list, ports: str = "", intensity: str = "stealth") -> str:
        global _SESSION_SCANNED
        if not ENABLE_NMAP:
            return json.dumps({"status": "disabled",
                               "note": "Set ENABLE_NMAP=1 to enable nmap scans."})
        if not _nmap_available():
            return json.dumps({"status": "nmap_not_found",
                               "note": "Install nmap or set NMAP_PATH. Run as Administrator for SYN scans."})

        # Hard limit: cap per-call at 10, filter already-scanned IPs
        ips = [str(ip).strip() for ip in ips[:10] if str(ip).strip()]
        ips = [ip for ip in ips if ip not in _SESSION_SCANNED]
        if not ips:
            return json.dumps({"status": "skipped", "note": "All IPs already scanned this session."})

        # Hard limit: session cap — refuse if budget exhausted
        remaining = _SESSION_MAX - len(_SESSION_SCANNED)
        if remaining <= 0:
            return json.dumps({
                "status": "session_cap_reached",
                "note": f"Session scan cap of {_SESSION_MAX} IPs reached. "
                        "This is a hard safety limit. Review findings so far.",
                "scanned_this_session": len(_SESSION_SCANNED),
            })
        ips = ips[:remaining]  # never exceed session budget

        cmd = [_nmap_bin]
        if intensity == "stealth":
            cmd += ["-sS", "-T2"]
        else:
            cmd += ["-sV", "-T3"]

        default_ports = "21,22,23,25,80,443,445,1433,3306,3389,5432,5900,6379,8080,8443,9200,27017,2375,6443,10250"
        cmd += ["-p", ports or default_ports, "-oX", "-", "--open", "--host-timeout", "60s"]
        cmd += ips

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if result.returncode != 0 and result.stderr:
                if any(x in result.stderr.lower() for x in ["elevated", "permitted", "root"]):
                    return json.dumps({
                        "status": "permission_error",
                        "note": "Run as Administrator. Or use intensity=normal for -sV scan.",
                    })
                return json.dumps({"status": "error", "stderr": result.stderr[:400]})

            import xml.etree.ElementTree as ET
            hosts_found = []
            try:
                root = ET.fromstring(result.stdout)
                for host in root.findall("host"):
                    status = host.find("status")
                    if status is None or status.get("state") != "up":
                        continue
                    addr = host.find("address")
                    ip = addr.get("addr") if addr is not None else "unknown"
                    ports_found = []
                    for port in host.findall(".//port"):
                        state = port.find("state")
                        if state is None or state.get("state") != "open":
                            continue
                        svc = port.find("service")
                        ports_found.append({
                            "port":     int(port.get("portid", 0)),
                            "protocol": port.get("protocol", "tcp"),
                            "service":  svc.get("name", "") if svc is not None else "",
                            "product":  svc.get("product", "") if svc is not None else "",
                            "version":  svc.get("version", "") if svc is not None else "",
                        })
                    hosts_found.append({
                        "ip": ip, "status": "up", "open_ports": ports_found,
                        "port_count": len(ports_found),
                    })
            except ET.ParseError:
                hosts_found = [{"raw_output": result.stdout[:800]}]

            # Register scanned IPs in session tracker
            _SESSION_SCANNED.update(ips)
            return json.dumps({
                "status": "ok",
                "hosts_scanned": len(ips),
                "hosts_live": len(hosts_found),
                "hosts": hosts_found,
                "session_budget_used": len(_SESSION_SCANNED),
                "session_budget_remaining": max(0, _SESSION_MAX - len(_SESSION_SCANNED)),
            }, indent=2)

        except subprocess.TimeoutExpired:
            return json.dumps({"status": "timeout", "note": "nmap timed out after 180s"})
        except PermissionError:
            return json.dumps({"status": "permission_error",
                               "note": "Run PowerShell as Administrator for SYN scans."})
        except Exception as e:
            return json.dumps({"status": "error", "error": str(e)})


# ─────────────────────────────────────────────────────────────────────────────
# NmapTriageTool — produce a ranked hand-off list for the specialist
# ─────────────────────────────────────────────────────────────────────────────

HIGH_RISK_PORTS = {
    23: "Telnet — cleartext, trivial sniff",
    2375: "Docker API — unauthenticated container control",
    2376: "Docker API TLS — verify auth",
    6443: "Kubernetes API server",
    10250: "Kubelet API — exec into pods",
    10255: "Kubelet read-only — info disclosure",
    2379: "etcd — Kubernetes secrets store",
    3389: "RDP — remote desktop",
    5900: "VNC — remote desktop",
    5901: "VNC alt port",
    9200: "Elasticsearch — often unauthenticated",
    6379: "Redis — often unauthenticated",
    27017: "MongoDB — often unauthenticated",
    1433: "MSSQL direct exposure",
    3306: "MySQL direct exposure",
    5432: "PostgreSQL direct exposure",
    8080: "HTTP alt — admin panels, Jenkins",
    8443: "HTTPS alt — admin panels",
    9090: "Various admin panels, Prometheus",
    4848: "GlassFish admin",
    7001: "WebLogic admin",
    8161: "ActiveMQ admin",
}

MEDIUM_RISK_PORTS = {22, 21, 25, 143, 110, 161, 162, 389, 636}

class NmapTriageInput(BaseModel):
    scan_results: str = Field(
        description="JSON string from nmap_discovery_scan — list of hosts with open_ports[]"
    )
    shodan_results: str = Field(
        default="",
        description="Optional JSON of Shodan results for the same IPs — used to note discrepancies",
    )

class NmapTriageTool(BaseTool):
    name: str = "nmap_triage_for_specialist"
    description: str = (
        "Take live nmap scan results and produce a RANKED hand-off document "
        "for the senior specialist (human or Vuln agent). "
        "Ranks every host HIGH / MEDIUM / LOW for intensive testing. "
        "Explains which services on HIGH hosts warrant deep testing and why. "
        "Flags any host where live Nmap is materially worse than Shodan data. "
        "Returns structured JSON hand-off list."
    )
    args_schema: type = NmapTriageInput

    def _run(self, scan_results: str, shodan_results: str = "") -> str:
        try:
            data = json.loads(scan_results)
            hosts = data.get("hosts", []) if isinstance(data, dict) else data
        except Exception:
            return json.dumps({"error": "Could not parse scan_results JSON"})

        shodan_map = {}
        if shodan_results:
            try:
                sd = json.loads(shodan_results)
                results = sd if isinstance(sd, list) else sd.get("results", [])
                for r in results:
                    ip = r.get("ip_str", r.get("ip", ""))
                    if ip:
                        shodan_map[ip] = r.get("ports", [])
            except Exception:
                pass

        triage = []
        for host in hosts:
            ip = host.get("ip", "unknown")
            open_ports = [p["port"] for p in host.get("open_ports", [])]
            port_details = {p["port"]: p for p in host.get("open_ports", [])}

            # Score the host
            critical_ports = [p for p in open_ports if p in HIGH_RISK_PORTS]
            medium_ports   = [p for p in open_ports if p in MEDIUM_RISK_PORTS]
            web_ports      = [p for p in open_ports if p in {80,443,8080,8443,9090,4848,7001}]

            if critical_ports:
                rank = "HIGH"
            elif medium_ports or len(open_ports) >= 5 or web_ports:
                rank = "MEDIUM"
            else:
                rank = "LOW"

            # Build advisory for each critical port
            advisories = []
            for port in critical_ports:
                svc  = port_details.get(port, {})
                prod = svc.get("product", "")
                ver  = svc.get("version", "")
                note = HIGH_RISK_PORTS[port]
                advisories.append({
                    "port": port,
                    "service": svc.get("service", ""),
                    "product": f"{prod} {ver}".strip(),
                    "issue": note,
                    "recommended_check": (
                        "Verify authentication; check for default credentials; "
                        "confirm this port should be internet-facing at all."
                    ),
                })

            # Check discrepancy vs Shodan
            shodan_ports = set(shodan_map.get(ip, []))
            live_ports   = set(open_ports)
            new_vs_shodan = sorted(live_ports - shodan_ports)
            gone_vs_shodan = sorted(shodan_ports - live_ports)

            triage.append({
                "ip": ip,
                "rank": rank,
                "open_ports_count": len(open_ports),
                "open_ports": open_ports,
                "critical_ports": critical_ports,
                "advisories": advisories,
                "discrepancy": {
                    "ports_live_but_not_in_shodan": new_vs_shodan,
                    "ports_in_shodan_but_now_closed": gone_vs_shodan,
                    "note": (
                        f"{len(new_vs_shodan)} port(s) live that Shodan missed — "
                        "scan these immediately." if new_vs_shodan else "Matches Shodan data."
                    ),
                },
            })

        # Sort: HIGH first, then MEDIUM, then LOW
        rank_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        triage.sort(key=lambda x: (rank_order.get(x["rank"], 3), -x["open_ports_count"]))

        high_hosts   = [h for h in triage if h["rank"] == "HIGH"]
        medium_hosts = [h for h in triage if h["rank"] == "MEDIUM"]

        first_host = high_hosts[0]["ip"] if high_hosts else (medium_hosts[0]["ip"] if medium_hosts else "none")

        return json.dumps({
            "hand_off_list": triage,
            "summary": {
                "total_scanned": len(triage),
                "high_priority": len(high_hosts),
                "medium_priority": len(medium_hosts),
                "low_priority": len(triage) - len(high_hosts) - len(medium_hosts),
                "test_first": first_host,
                "one_liner": (
                    f"{len(high_hosts)} HIGH-priority host(s) — "
                    f"test {first_host} first: "
                    f"{', '.join(str(p) for p in high_hosts[0]['critical_ports']) if high_hosts else 'see list'}"
                ),
            },
        }, indent=2)


def get_nmap_tools() -> list:
    """
    Return nmap tools if available. Hard limits enforced in each tool.

    HARD LIMITS (cannot be overridden by the agent):
      - Max 10 IPs per tool call (enforced in tool code)
      - Max 30 IPs per full session (NmapDiscoveryTool tracks globally)
      - Port list fixed to high-risk set — no full port range scans
      - T2 timing (stealth) — agent cannot request faster
      - 60s host timeout — no unbounded scans
      - SYN scan requires Administrator / root on Windows / Linux
    """
    if not ENABLE_NMAP:
        print("[NMAP] Disabled (ENABLE_NMAP=0)")
        return []
    if not _nmap_available():
        print(
            "[NMAP] WARNING: nmap could not be located or did not respond to --version.\n"
            "\n"
            "  The agent auto-searched: NMAP_PATH, your PATH, and the standard install\n"
            "  locations (C:\\Program Files (x86)\\Nmap\\nmap.exe, C:\\Program Files\\Nmap,\n"
            "  /usr/bin, /usr/local/bin, /opt/homebrew/bin, /snap/bin).\n"
            "\n"
            "  SETUP / FIX:\n"
            "  Windows : install from https://nmap.org/download.html (tick 'Add to PATH'),\n"
            "            or point us straight at it:  set NMAP_PATH=C:\\Program Files (x86)\\Nmap\\nmap.exe\n"
            "  Linux   : sudo apt install nmap        macOS: brew install nmap\n"
            "\n"
            "  Verify with: nmap --version\n"
            "  SYN scans (-sS) require Administrator / sudo on all platforms.\n"
            "  Set ENABLE_NMAP=0 to suppress this warning.\n"
        )
        return []
    print(f"[NMAP] Active — binary: {_nmap_bin}")
    print("[NMAP] Hard limits: 10 IPs/call, 30 IPs/session, fixed port list, T2 timing")
    return [NmapScanTool(), NmapDiscoveryTool(), NmapTriageTool()]
