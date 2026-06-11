"""
http_validate_tool.py — Curl-style finding VALIDATION tool (discovery only).

Purpose
-------
Turn "maybe" findings into true findings (or kill them) by actually fetching the
service and reading what comes back. An open port is not a finding; a 200 with an
unauthenticated admin/DB/API surface is. This tool lets the severity-deciding agents
(recon / vuln / auth / report) CONFIRM exposure before calling anything Critical.

What it does
------------
- GET or HEAD only. No other verbs.
- No request bodies, no auth headers, no payloads, no injection — it does not try to
  exploit, brute-force, or bypass anything. It fetches a URL the way a browser would.
- Reports: final URL, status, server header, page title, content-type/length,
  redirect target, TLS subject/issuer/expiry, security-header gaps, and a short body
  snippet with obvious secrets masked.
- Refuses loopback and link-local/cloud-metadata targets so the tool can't be turned
  against the host it runs on (169.254.0.0/16 incl. 169.254.169.254, 127.0.0.0/8, ::1).
  RFC1918 ranges are allowed for authorized internal engagements.

Scope discipline stays with the agent and the engagement: only probe hosts already
confirmed in-scope. This tool validates; it does not authorize.

Usage from an agent:
    http_probe(url="https://203.0.113.10:9200/")
    http_probe(url="http://203.0.113.10:2375/version", method="GET")
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
from urllib.parse import urlparse

import requests
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

# Obvious secret-ish keys to mask in any body snippet we surface.
_SECRET_RE = re.compile(
    r'(?i)(api[_-]?key|secret|token|passwd|password|access[_-]?key|'
    r'private[_-]?key|aws_secret|authorization|bearer)'
    r'["\']?\s*[:=]\s*["\']?([^\s"\',}&]{4,})'
)

_TITLE_RE = re.compile(r'(?is)<title[^>]*>(.*?)</title>')

# Security headers whose ABSENCE is worth noting (informational, not a vuln by itself).
_WATCH_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
)

_MAX_BODY_BYTES = 8192
_SNIPPET_CHARS = 600
_TIMEOUT = 8
_MAX_REDIRECTS = 3


def _mask(text: str) -> str:
    return _SECRET_RE.sub(lambda m: f"{m.group(1)}=***MASKED***", text)


def _blocked_target(host: str) -> str | None:
    """Return a reason string if the target must not be probed, else None."""
    candidates = []
    try:
        candidates.append(ipaddress.ip_address(host))
    except ValueError:
        # It's a hostname — resolve and check every A/AAAA record.
        try:
            for fam, _, _, _, sa in socket.getaddrinfo(host, None):
                try:
                    candidates.append(ipaddress.ip_address(sa[0]))
                except ValueError:
                    pass
        except Exception:
            return None  # can't resolve; let the request fail naturally
    for ip in candidates:
        if ip.is_loopback:
            return f"{ip} is loopback — refused"
        if ip.is_link_local:
            return f"{ip} is link-local / cloud-metadata range — refused"
        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return f"{ip} is a reserved/non-routable address — refused"
    return None


def _tls_info(host: str, port: int) -> dict:
    """Best-effort TLS peer-cert read (does not verify; we want to SEE the cert)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
                if not cert:
                    der = s.getpeercert(binary_form=True)
                    return {"present": bool(der), "note": "peer cert not parsed (no SNI match?)"}
                def _name(seq):
                    return ", ".join("=".join(x) for rdn in seq for x in rdn)
                return {
                    "present": True,
                    "subject": _name(cert.get("subject", [])),
                    "issuer": _name(cert.get("issuer", [])),
                    "not_after": cert.get("notAfter"),
                    "alt_names": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"][:8],
                }
    except Exception as e:
        return {"present": False, "error": str(e)[:120]}


class HttpProbeInput(BaseModel):
    url: str = Field(description=(
        "Full URL to fetch, INCLUDING scheme and (if non-standard) port — e.g. "
        "'https://203.0.113.10:8443/', 'http://203.0.113.10:2375/version'. "
        "Only probe hosts already confirmed in-scope for this engagement."
    ))
    method: str = Field("GET", description="GET or HEAD only. No other method is permitted.")


class HttpProbeTool(BaseTool):
    name: str = "http_probe"
    description: str = (
        "Validate a finding by fetching a service URL (GET or HEAD only) and reading what "
        "it returns. Use this to CONFIRM exposure before assigning Critical/High: does the "
        "admin panel / database / API actually respond, and is it unauthenticated? "
        "Returns status, server, page title, content-type, redirect, TLS cert details, "
        "missing security headers, and a short secrets-masked body snippet. "
        "A 200 with real data and no auth challenge confirms an unauthenticated exposure; "
        "a 401/403 means auth is present (downgrade or drop the finding); a connection "
        "error means the port is not actually serving (drop the finding). "
        "This is discovery/validation only — it sends no payloads, no credentials, and "
        "attempts no exploitation or bypass. Only probe confirmed in-scope hosts."
    )
    args_schema: type = HttpProbeInput

    def _run(self, url: str, method: str = "GET") -> str:
        method = (method or "GET").upper()
        if method not in ("GET", "HEAD"):
            return json.dumps({"error": f"method {method} not allowed; use GET or HEAD"})

        parsed = urlparse(url if "://" in url else f"http://{url}")
        if parsed.scheme not in ("http", "https"):
            return json.dumps({"error": f"scheme {parsed.scheme!r} not allowed; use http/https"})
        host = parsed.hostname
        if not host:
            return json.dumps({"error": "could not parse host from url"})

        blocked = _blocked_target(host)
        if blocked:
            return json.dumps({"error": f"target refused: {blocked}"})

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        out: dict = {"url": url, "method": method, "host": host, "port": port}

        try:
            session = requests.Session()
            session.max_redirects = _MAX_REDIRECTS
            resp = session.request(
                method, url, timeout=_TIMEOUT, allow_redirects=True,
                verify=False, stream=True,
                headers={"User-Agent": "ShodanSnipe-Validator/1.0 (authorized-assessment)"},
            )
            out["status"] = resp.status_code
            out["final_url"] = resp.url
            if resp.history:
                out["redirect_chain"] = [r.status_code for r in resp.history]
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            out["server"] = hdrs.get("server")
            out["content_type"] = hdrs.get("content-type")
            out["content_length"] = hdrs.get("content-length")
            if hdrs.get("www-authenticate"):
                out["auth_challenge"] = hdrs["www-authenticate"][:80]
            out["missing_security_headers"] = [h for h in _WATCH_HEADERS if h not in hdrs]

            if method == "GET":
                body = resp.raw.read(_MAX_BODY_BYTES, decode_content=True) or b""
                text = body.decode("utf-8", "replace")
                m = _TITLE_RE.search(text)
                if m:
                    out["title"] = m.group(1).strip()[:160]
                snippet = _mask(re.sub(r"\s+", " ", text)).strip()[:_SNIPPET_CHARS]
                out["body_snippet"] = snippet
            resp.close()

            # Plain-language verdict the agent can act on directly.
            if out["status"] in (401, 403):
                out["exposure_verdict"] = "AUTH PRESENT — likely NOT a finding (downgrade/drop)"
            elif 200 <= out["status"] < 300:
                out["exposure_verdict"] = (
                    "REACHABLE, no auth challenge — confirm the body shows a real "
                    "unauthenticated surface before calling it Critical/High"
                )
            elif 300 <= out["status"] < 400:
                out["exposure_verdict"] = "redirect — follow final_url to judge"
            else:
                out["exposure_verdict"] = f"HTTP {out['status']} — inconclusive"

        except requests.exceptions.SSLError as e:
            out["error"] = f"TLS error: {str(e)[:120]}"
        except requests.exceptions.ConnectionError:
            out["status"] = None
            out["exposure_verdict"] = "CONNECTION REFUSED/UNREACHABLE — port not serving, drop finding"
        except requests.exceptions.Timeout:
            out["status"] = None
            out["exposure_verdict"] = "TIMEOUT — no response, treat as unconfirmed"
        except Exception as e:
            out["error"] = str(e)[:160]

        if parsed.scheme == "https":
            out["tls"] = _tls_info(host, port)

        return json.dumps(out, indent=2)


# Silence the noisy unverified-HTTPS warning; we intentionally don't verify so we can
# read self-signed certs on target infrastructure.
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


def refused_target(host: str) -> str | None:
    """Public helper: returns a refusal reason for loopback/link-local/metadata/reserved
    targets, else None. Lets other tools reuse the same SSRF guard before fetching."""
    try:
        return _blocked_target(host)
    except Exception:
        return None
