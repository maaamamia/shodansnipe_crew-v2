"""
diff_store.py — Snapshot save/load + diff computation.

Snapshots live in the encrypted DB (snapshots table); this module is just
the diff logic on top.
"""

from __future__ import annotations

import logging
from typing import Any

import db

logger = logging.getLogger(__name__)


def _serialize(results: list[dict]) -> list[dict]:
    """Flatten dataclass-bearing results into JSON-safe form."""
    out = []
    for r in results:
        pi = r.get("port_info")
        ci = r.get("cve_info")
        hi = r.get("hostname_info")
        ti = r.get("tag_info")
        out.append({
            "ip_str": r.get("ip_str"),
            "ports": pi.all_ports if pi else [],
            "cves": ci.all_cves if ci else [],
            "hostnames": hi.all_hostnames if hi else [],
            "tags": ti.all_tags if ti else [],
            "org": r.get("org"),
            "product": r.get("product"),
            "os": r.get("os"),
            "risk": r.get("risk_assessment", {}).get("simplified", ""),
        })
    return out


def save_snapshot(query: str, scope_name: str, results: list[dict]) -> int:
    return db.snapshot_save(query, scope_name, _serialize(results))


def diff(query: str, scope_name: str, current: list[dict]) -> dict[str, Any]:
    """Compare current results against the latest snapshot for same query+scope."""
    current_serialized = _serialize(current)
    current_by_ip = {r["ip_str"]: r for r in current_serialized}

    previous = db.snapshot_latest(query, scope_name)
    if not previous:
        return {
            "previous_timestamp": None,
            "new_hosts": list(current_by_ip.keys()),
            "removed_hosts": [],
            "changed_hosts": [],
        }

    prev_by_ip = {r["ip_str"]: r for r in previous["results"]}

    new_hosts = [ip for ip in current_by_ip if ip not in prev_by_ip]
    removed_hosts = [ip for ip in prev_by_ip if ip not in current_by_ip]

    changed = []
    for ip, cur in current_by_ip.items():
        if ip not in prev_by_ip:
            continue
        prev = prev_by_ip[ip]
        new_ports = sorted(set(cur.get("ports") or []) - set(prev.get("ports") or []))
        closed_ports = sorted(set(prev.get("ports") or []) - set(cur.get("ports") or []))
        new_cves = sorted(set(cur.get("cves") or []) - set(prev.get("cves") or []))
        if new_ports or closed_ports or new_cves:
            changed.append({
                "ip_str": ip,
                "new_ports": new_ports,
                "closed_ports": closed_ports,
                "new_cves": new_cves,
            })

    return {
        "previous_timestamp": previous.get("taken_at"),
        "new_hosts": new_hosts,
        "removed_hosts": removed_hosts,
        "changed_hosts": changed,
    }
