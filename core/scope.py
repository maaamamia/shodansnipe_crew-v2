"""
scope.py — Scope enforcement and audit logging.

Scope file format (JSON):
{
  "name": "Acme Corp External",
  "cidrs": ["203.0.113.0/24", "198.51.100.0/24"],
  "domains": ["acme.example", "acme.test"],
  "asns": ["AS64512"],
  "orgs": ["Acme Corp"]
}

Behavior: required-with-override. Every query and every result is checked.
Out-of-scope items are filtered by default; the operator can override per-run
with an explicit confirmation token, which is recorded in the audit log.
"""

from __future__ import annotations

import json
import ipaddress
import os
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import db

logger = logging.getLogger(__name__)

# Backward-compat export — older server.py versions imported this from scope.
# The real audit log lives in the encrypted DB (audit_events table).
AUDIT_LOG_FILE = "audit.log"  # not used; kept to prevent ImportError


@dataclass
class Scope:
    name: str = "default"
    cidrs: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    asns: list[str] = field(default_factory=list)
    orgs: list[str] = field(default_factory=list)

    _networks: list[ipaddress._BaseNetwork] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self._networks = []
        for cidr in self.cidrs:
            try:
                self._networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as e:
                logger.warning("Skipping invalid CIDR %s: %s", cidr, e)

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(
            name=data.get("name", os.path.basename(path)),
            cidrs=data.get("cidrs", []),
            domains=[d.lower().lstrip(".") for d in data.get("domains", [])],
            asns=[a.upper() for a in data.get("asns", [])],
            orgs=[o.lower() for o in data.get("orgs", [])],
        )

    @classmethod
    def from_dict(cls, data: dict) -> "Scope":
        return cls(
            name=data.get("name", "inline"),
            cidrs=data.get("cidrs", []),
            domains=[d.lower().lstrip(".") for d in data.get("domains", [])],
            asns=[a.upper() for a in data.get("asns", [])],
            orgs=[o.lower() for o in data.get("orgs", [])],
        )

    def is_empty(self) -> bool:
        return not (self._networks or self.domains or self.asns or self.orgs)

    def contains_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._networks)

    def contains_hostname(self, hostname: str) -> bool:
        if not hostname:
            return False
        h = hostname.lower().lstrip(".")
        return any(h == d or h.endswith("." + d) for d in self.domains)

    def contains_asn(self, asn: str) -> bool:
        if not asn:
            return False
        return asn.upper().lstrip("AS") in [a.lstrip("AS") for a in self.asns]

    def contains_org(self, org: str) -> bool:
        if not org:
            return False
        o = org.lower()
        return any(scope_org in o for scope_org in self.orgs)

    def check_result(self, result: dict) -> tuple[bool, str]:
        """Returns (in_scope, reason). If multiple criteria match, IP wins."""
        ip = result.get("ip_str", "")
        if ip and self.contains_ip(ip):
            return True, f"ip in CIDR ({ip})"

        hostnames = []
        hi = result.get("hostname_info")
        if hi and hasattr(hi, "all_hostnames"):
            hostnames = hi.all_hostnames
        for h in hostnames:
            if self.contains_hostname(h):
                return True, f"hostname match ({h})"

        org = result.get("org", "")
        if org and self.contains_org(org):
            return True, f"org match ({org})"

        return False, "no scope match"

    def summary(self) -> str:
        parts = []
        if self._networks:
            parts.append(f"{len(self._networks)} CIDR(s)")
        if self.domains:
            parts.append(f"{len(self.domains)} domain(s)")
        if self.asns:
            parts.append(f"{len(self.asns)} ASN(s)")
        if self.orgs:
            parts.append(f"{len(self.orgs)} org(s)")
        return f"{self.name}: " + ", ".join(parts) if parts else f"{self.name}: empty"


def audit(event_type: str, payload: dict[str, Any]) -> None:
    """Append a structured event to the encrypted audit table. Never raises."""
    try:
        db.audit_write(event_type, payload)
    except Exception as e:
        logger.error("audit failed: %s", e)


def apply_scope(
    results: list[dict],
    scope: Scope,
    override: bool = False,
    override_reason: str = "",
    actor: str = "local",
    query: str = "",
) -> tuple[list[dict], list[dict]]:
    """Returns (in_scope_results, out_of_scope_results).

    If override is True, both lists are returned in full and the override is
    logged. If override is False, only in_scope_results should be displayed
    by the caller, but out-of-scope items are still returned for transparency
    (e.g. "12 results hidden by scope filter").
    """
    if scope.is_empty():
        audit("scope_empty_warning", {
            "actor": actor,
            "query": query,
            "result_count": len(results),
        })
        return results, []

    in_scope, out_of_scope = [], []
    for r in results:
        ok, reason = scope.check_result(r)
        if ok:
            r["_scope_reason"] = reason
            in_scope.append(r)
        else:
            out_of_scope.append(r)

    audit("scope_filter", {
        "actor": actor,
        "query": query,
        "scope": scope.name,
        "in_scope": len(in_scope),
        "out_of_scope": len(out_of_scope),
        "override": override,
        "override_reason": override_reason if override else "",
    })

    return in_scope, out_of_scope
