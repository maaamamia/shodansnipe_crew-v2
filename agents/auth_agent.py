"""
agents/auth_agent.py — Authentication & Exposure Analysis Agent

For each high-value host from recon:
  - Detects auth type (OAuth, SAML, JWT, Basic, LDAP, Kerberos, MFA, SSO, none)
  - Checks for interesting JSON responses with keywords (token, secret, key, api_key...)
  - Probes common sensitive paths (swagger, .env, api-docs, graphql)
  - Checks security headers (CSP, HSTS, X-Frame-Options, etc.)
  - Posture classification (dangling DNS, origin exposed, WAF bypass)

Based on: url_auth_analyzer.py + kraken_probes.py + kraken_posture.py
Only runs on hosts that passed recon's high-value filter.
"""
from __future__ import annotations
import os, json, re, time
from typing import Any
from crewai import Agent, Task
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import requests

# Shared assessment doctrine (discover-don't-assume, modern-infra focus, impact-driven scoring).
try:
    from tools.doctrine import ASSESSMENT_DOCTRINE as _DOCTRINE
except ImportError:
    try:
        from doctrine import ASSESSMENT_DOCTRINE as _DOCTRINE
    except ImportError:
        _DOCTRINE = ""

SHODANSNIPE_URL = os.environ.get("SHODANSNIPE_URL", "http://127.0.0.1:8000")

# Reuse the validation tool's SSRF guard so auth's own fetchers can't be aimed at
# loopback / cloud-metadata. Degrades gracefully if the module isn't importable.
try:
    from tools.http_validate_tool import refused_target as _refused_target
except ImportError:
    try:
        from http_validate_tool import refused_target as _refused_target
    except ImportError:
        def _refused_target(_host):  # no-op fallback
            return None


def _guard_url(url: str):
    """Return an error dict if the URL's host must not be fetched, else None."""
    from urllib.parse import urlparse
    host = urlparse(url if "://" in url else f"http://{url}").hostname
    if not host:
        return {"error": "could not parse host from url", "url": url}
    reason = _refused_target(host)
    if reason:
        return {"error": f"target refused: {reason}", "url": url}
    return None

# ── JSON KEYWORDS OF INTEREST ─────────────────────────────────────────────────
SENSITIVE_KEYWORDS = [
    "token", "secret", "api_key", "apikey", "api-key", "password", "passwd",
    "credential", "auth", "bearer", "private_key", "access_key", "aws_key",
    "database_url", "connection_string", "encryption_key", "signing_key",
    "client_secret", "client_id", "refresh_token", "session_key",
    "webhook_secret", "stripe_key", "twilio", "sendgrid", "slack_token",
]

# ── SECURITY HEADERS TO CHECK ─────────────────────────────────────────────────
SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
    "Permissions-Policy", "X-XSS-Protection",
    "Access-Control-Allow-Origin",  # CORS - flag if *
]

# ── PROBE PATHS ───────────────────────────────────────────────────────────────
SWAGGER_PATHS = [
    "/swagger.json", "/swagger-ui.html", "/api-docs", "/api/docs",
    "/openapi.json", "/openapi.yaml", "/v1/api-docs", "/v2/api-docs",
    "/docs", "/redoc", "/graphql", "/graphiql",
]

ENV_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.dev",
    "/config.json", "/config.yaml", "/settings.json",
    "/application.properties", "/web.config",
]

SENSITIVE_PATHS = [
    "/.git/config", "/.git/HEAD", "/wp-config.php.bak",
    "/backup.sql", "/dump.sql", "/admin", "/admin/", "/administrator",
    "/api/v1/users", "/api/users", "/api/admin", "/_debug", "/debug",
    "/actuator", "/actuator/env", "/actuator/health", "/health",
    "/__debug__", "/server-status", "/.well-known/security.txt",
]

# ── TOOLS ─────────────────────────────────────────────────────────────────────

class AuthAnalyzeInput(BaseModel):
    url: str = Field(description="Full URL to analyze e.g. https://192.168.1.1:8443")
    timeout: float = Field(8.0, description="Request timeout in seconds")

class AuthAnalyzeTool(BaseTool):
    name: str = "analyze_auth"
    description: str = (
        "Detect authentication type for a URL: OAuth, SAML, JWT, Basic Auth, "
        "LDAP, Kerberos, MFA, SSO, API Key, or None. Also checks security headers "
        "and CORS policy. Use on every high-value host."
    )
    args_schema: type = AuthAnalyzeInput

    def _run(self, url: str, timeout: float = 8.0) -> str:
        blocked = _guard_url(url)
        if blocked:
            return json.dumps(blocked, indent=2)
        result = {
            "url": url,
            "auth_types": [],
            "auth_confidence": "low",
            "security_headers": {},
            "missing_headers": [],
            "cors_open": False,
            "findings": [],
            "error": None,
        }
        try:
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0"
                ),
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
            r = requests.get(url, headers=headers, timeout=timeout,
                             verify=False, allow_redirects=True)

            # ── Security headers ──────────────────────────────────────────
            resp_headers = {k.lower(): v for k, v in r.headers.items()}
            for h in SECURITY_HEADERS:
                val = resp_headers.get(h.lower())
                if val:
                    result["security_headers"][h] = val
                    if h == "Access-Control-Allow-Origin" and val.strip() == "*":
                        result["cors_open"] = True
                        result["findings"].append("HIGH: CORS is open (*) — any origin can read responses")
                else:
                    result["missing_headers"].append(h)

            if "Strict-Transport-Security" not in result["security_headers"]:
                result["findings"].append("MEDIUM: Missing HSTS header")
            if "Content-Security-Policy" not in result["security_headers"]:
                result["findings"].append("MEDIUM: Missing CSP header")

            # ── WWW-Authenticate header ───────────────────────────────────
            www_auth = resp_headers.get("www-authenticate", "")
            if www_auth:
                if "bearer" in www_auth.lower():
                    result["auth_types"].append("Bearer/JWT")
                if "basic" in www_auth.lower():
                    result["auth_types"].append("Basic Auth")
                    result["findings"].append("HIGH: Basic Auth exposed — credentials sent in plaintext")
                if "digest" in www_auth.lower():
                    result["auth_types"].append("Digest Auth")
                if "negotiate" in www_auth.lower() or "kerberos" in www_auth.lower():
                    result["auth_types"].append("Kerberos/NTLM")
                if "ntlm" in www_auth.lower():
                    result["auth_types"].append("NTLM")

            # ── Body analysis ─────────────────────────────────────────────
            body = r.text[:8000]
            body_lower = body.lower()

            # Auth protocol detection
            auth_signals = {
                "OAuth":    ["oauth", "access_token", "grant_type", "client_id"],
                "SAML":     ["saml", "samlrequest", "samlresponse", "assertion"],
                "OpenID":   ["openid", "oidc", ".well-known/openid-configuration"],
                "JWT":      ["eyj", "jwt", "json web token"],
                "LDAP":     ["ldap", "active directory", "ldaps"],
                "SSO":      ["single sign-on", "sso", "federation"],
                "MFA":      ["two-factor", "2fa", "mfa", "authenticator", "otp", "totp"],
                "ADFS":     ["adfs", "ad fs", "microsoft.com/adfs"],
                "SAML2":    ["samlv2", "saml 2.0"],
                "API Key":  ["api-key", "x-api-key", "apikey"],
            }
            for auth_name, signals in auth_signals.items():
                if any(s in body_lower for s in signals):
                    if auth_name not in result["auth_types"]:
                        result["auth_types"].append(auth_name)

            # Redirect chain auth detection
            for resp in r.history:
                loc = resp.headers.get("Location", "")
                loc_lower = loc.lower()
                if "oauth" in loc_lower:
                    if "OAuth" not in result["auth_types"]: result["auth_types"].append("OAuth")
                if "saml" in loc_lower:
                    if "SAML" not in result["auth_types"]: result["auth_types"].append("SAML")
                if "login.microsoftonline.com" in loc_lower:
                    if "Azure AD/SSO" not in result["auth_types"]: result["auth_types"].append("Azure AD/SSO")
                if "accounts.google.com" in loc_lower:
                    if "Google SSO" not in result["auth_types"]: result["auth_types"].append("Google SSO")
                if "okta.com" in loc_lower:
                    if "Okta SSO" not in result["auth_types"]: result["auth_types"].append("Okta SSO")
                if "ping" in loc_lower:
                    if "PingFederate SSO" not in result["auth_types"]: result["auth_types"].append("PingFederate SSO")

            # Confidence
            if len(result["auth_types"]) >= 2:
                result["auth_confidence"] = "high"
            elif len(result["auth_types"]) == 1:
                result["auth_confidence"] = "medium"

            if not result["auth_types"]:
                result["auth_types"] = ["Unknown/None detected"]
                result["findings"].append("INFO: No auth mechanism detected — may be unauthenticated")

            result["status_code"] = r.status_code
            result["final_url"] = r.url
            result["redirect_count"] = len(r.history)
            result["server"] = resp_headers.get("server", "")
            result["x_powered_by"] = resp_headers.get("x-powered-by", "")

        except requests.exceptions.SSLError:
            result["error"] = "SSL error — self-signed or invalid cert"
            result["findings"].append("HIGH: SSL certificate error — may be self-signed")
        except requests.exceptions.ConnectionError:
            result["error"] = "Connection refused or unreachable"
        except requests.exceptions.Timeout:
            result["error"] = f"Timeout after {timeout}s"
        except Exception as e:
            result["error"] = str(e)

        return json.dumps(result, indent=2)


class JsonKeywordScanInput(BaseModel):
    url: str = Field(description="URL to scan for sensitive JSON keywords")
    timeout: float = Field(8.0, description="Request timeout")

class JsonKeywordScanTool(BaseTool):
    name: str = "json_keyword_scan"
    description: str = (
        "Fetch a URL and scan the JSON response body for sensitive keywords: "
        "token, secret, api_key, password, credential, bearer, private_key, etc. "
        "Use on API endpoints, /health, /debug, /actuator/env."
    )
    args_schema: type = JsonKeywordScanInput

    def _run(self, url: str, timeout: float = 8.0) -> str:
        blocked = _guard_url(url)
        if blocked:
            return json.dumps(blocked, indent=2)
        result = {"url": url, "is_json": False, "found_keywords": [], "findings": [], "error": None}
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 Chrome/124.0.0.0",
                "Accept": "application/json, */*",
            }
            r = requests.get(url, headers=headers, timeout=timeout,
                             verify=False, allow_redirects=True)
            ct = r.headers.get("Content-Type", "")
            body = r.text[:20000]

            result["status_code"] = r.status_code
            result["content_type"] = ct
            result["is_json"] = "json" in ct.lower() or body.strip().startswith(("{", "["))

            if result["is_json"] or "json" in ct.lower():
                body_lower = body.lower()
                for kw in SENSITIVE_KEYWORDS:
                    if re.search(rf'["\']?{re.escape(kw)}["\']?\s*[:=]', body_lower):
                        result["found_keywords"].append(kw)

                if result["found_keywords"]:
                    result["findings"].append(
                        f"CRITICAL: JSON response contains sensitive keys: "
                        f"{', '.join(result['found_keywords'])}"
                    )
                    # Try to extract values (first 100 chars only)
                    extracts = []
                    for kw in result["found_keywords"][:5]:
                        m = re.search(
                            rf'["\']?{re.escape(kw)}["\']?\s*[:=]\s*["\']?([^"\',\n\r\]}}]{{1,80}})',
                            body, re.IGNORECASE
                        )
                        if m:
                            val = m.group(1).strip()
                            # Mask middle of value
                            masked = val[:4] + "****" + val[-4:] if len(val) > 12 else "****"
                            extracts.append(f"{kw}: {masked}")
                    if extracts:
                        result["value_previews"] = extracts

            # Check for common info disclosure
            if r.status_code == 200 and any(p in url for p in [".env", "config", "secret", "credentials"]):
                result["findings"].append("CRITICAL: Sensitive path returned 200 — likely exposed configuration")

        except Exception as e:
            result["error"] = str(e)

        return json.dumps(result, indent=2)


class ProbeSensitivePathsInput(BaseModel):
    base_url: str = Field(description="Base URL e.g. https://192.168.1.1:8080")
    probe_type: str = Field("swagger", description="Type: swagger, env, sensitive, all")
    timeout: float = Field(5.0, description="Per-request timeout")

class ProbeSensitivePathsTool(BaseTool):
    name: str = "probe_sensitive_paths"
    description: str = (
        "Probe a host for sensitive/exposed paths: swagger/api-docs, .env files, "
        "debug endpoints, admin panels, git config, actuator. "
        "probe_type: swagger, env, sensitive, or all."
    )
    args_schema: type = ProbeSensitivePathsInput

    def _run(self, base_url: str, probe_type: str = "swagger", timeout: float = 5.0) -> str:
        blocked = _guard_url(base_url)
        if blocked:
            return json.dumps(blocked, indent=2)
        base_url = base_url.rstrip("/")
        paths_to_check = []
        if probe_type in ("swagger", "all"):
            paths_to_check.extend(SWAGGER_PATHS)
        if probe_type in ("env", "all"):
            paths_to_check.extend(ENV_PATHS)
        if probe_type in ("sensitive", "all"):
            paths_to_check.extend(SENSITIVE_PATHS)

        hits = []
        headers = {"User-Agent": "Mozilla/5.0 Chrome/124.0.0.0"}
        hit_codes = {200, 201, 301, 302, 307, 401, 403}

        for path in paths_to_check[:50]:  # cap at 50
            try:
                url = f"{base_url}{path}"
                r = requests.get(url, headers=headers, timeout=timeout,
                                 verify=False, allow_redirects=False)
                ct   = r.headers.get("Content-Type", "")
                size = len(r.content)
                # Return ANY response with status code or content — don't filter
                hit = {
                    "path":         path,
                    "status":       r.status_code,
                    "content_type": ct,
                    "size":         size,
                }
                if r.status_code == 200:
                    if any(p in path for p in [".env","config","secret","credentials",".git","wp-config"]):
                        hit["severity"] = "CRITICAL"
                    elif any(p in path for p in ["swagger","api-docs","graphql","actuator","redoc"]):
                        hit["severity"] = "HIGH"
                    elif any(p in path for p in ["admin","console","dashboard","manage"]):
                        hit["severity"] = "HIGH"
                    else:
                        hit["severity"] = "MEDIUM"
                    # Include first 200 chars of response body as evidence
                    try:
                        hit["body_preview"] = r.text[:200]
                    except Exception:
                        pass
                elif r.status_code in (401, 403):
                    hit["severity"] = "INFO"   # path exists but auth-protected — still noteworthy
                elif r.status_code in (301, 302, 307, 308):
                    hit["severity"] = "INFO"
                    hit["redirect_to"] = r.headers.get("Location", "")
                else:
                    hit["severity"] = "INFO"
                hits.append(hit)
                time.sleep(0.05)
            except requests.exceptions.ConnectionError:
                hits.append({"path": path, "status": "connection_refused",
                             "severity": "INFO", "note": "host refused connection"})
            except requests.exceptions.Timeout:
                pass  # timeout = host not responding, skip silently  # gentle
            except Exception:
                continue

        result = {
            "base_url": base_url,
            "paths_checked": len(paths_to_check[:50]),
            "hits": hits,
            "critical_count": sum(1 for h in hits if h.get("severity") == "CRITICAL"),
            "high_count": sum(1 for h in hits if h.get("severity") == "HIGH"),
        }

        if result["critical_count"]:
            result["ALERT"] = (
                f"CRITICAL exposures found: "
                f"{[h['path'] for h in hits if h.get('severity')=='CRITICAL']}"
            )

        return json.dumps(result, indent=2)


class PostureClassifyInput(BaseModel):
    hostname: str = Field(description="Hostname to classify posture for")
    ip: str = Field("", description="IP address if known")
    headers_json: str = Field("{}", description="JSON string of response headers from a prior request")

class PostureClassifyTool(BaseTool):
    name: str = "classify_posture"
    description: str = (
        "Classify host posture: WAF/CDN detection, origin exposure, dangling DNS, "
        "potential subdomain takeover. Returns tags like CDN_PROTECTED, NO_WAF, "
        "ORIGIN_EXPOSED, DANGLING_DNS, POTENTIAL_TAKEOVER."
    )
    args_schema: type = PostureClassifyInput

    def _run(self, hostname: str, ip: str = "", headers_json: str = "{}") -> str:
        try:
            import sys
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
            try:
                from kraken_posture import classify_row
                row = {
                    "url": f"https://{hostname}",
                    "hostname": hostname,
                    "ip": ip,
                }
                try:
                    row["response_headers"] = json.loads(headers_json)
                except Exception:
                    pass
                tags = classify_row(row)
                return json.dumps({"hostname": hostname, "posture_tags": tags}, indent=2)
            except ImportError:
                pass

            # Fallback: basic CDN/WAF detection from headers
            tags = []
            try:
                hdrs = json.loads(headers_json)
                hdrs_lower = {k.lower(): v.lower() for k, v in hdrs.items()}
                cdn_signals = {
                    "cloudflare": "CF-Ray", "akamai": "X-Akamai-Request-ID",
                    "fastly": "X-Served-By", "cloudfront": "X-Amz-Cf-Id",
                    "imperva": "X-Iinfo", "sucuri": "x-sucuri-id",
                }
                cdn_detected = None
                for cdn, hdr in cdn_signals.items():
                    if hdr.lower() in hdrs_lower:
                        cdn_detected = cdn
                        tags.append({"id": "CDN_PROTECTED", "label": f"Behind {cdn}",
                                     "severity": "INFO", "confidence": "HIGH"})
                        break
                if not cdn_detected:
                    # "No WAF detected" is header-inference only and is NOT a finding on its
                    # own — a WAF not observed is not a WAF absent. Informational context.
                    tags.append({"id": "NO_WAF", "label": "No WAF/CDN detected (header inference, unconfirmed)",
                                 "severity": "INFO", "confidence": "LOW"})
            except Exception:
                pass

            # DNS-based takeover check
            try:
                import socket
                try:
                    socket.gethostbyname(hostname)
                    dns_resolves = True
                except socket.gaierror:
                    dns_resolves = False
                    tags.append({"id": "DANGLING_DNS", "label": "DNS does not resolve (takeover lead — verify, not confirmed)",
                                 "severity": "MEDIUM", "confidence": "MEDIUM"})

                # Check for known takeover signatures
                if dns_resolves:
                    try:
                        if _refused_target(hostname):
                            raise RuntimeError("target refused by guard")
                        r = requests.get(f"https://{hostname}", timeout=5, verify=False)
                        body = r.text.lower()
                        takeover_sigs = [
                            ("AWS S3", "nosuchbucket"),
                            ("GitHub Pages", "there isn't a github pages site here"),
                            ("Heroku", "no such app"),
                            ("Netlify", "not found - request id"),
                            ("Azure", "the specified resource does not exist"),
                        ]
                        for vendor, sig in takeover_sigs:
                            if sig in body:
                                tags.append({
                                    "id": "POTENTIAL_TAKEOVER",
                                    "label": f"Potential {vendor} subdomain takeover",
                                    "severity": "HIGH", "confidence": "MEDIUM",
                                    "evidence": sig,
                                })
                    except Exception:
                        pass
            except Exception:
                pass

            return json.dumps({"hostname": hostname, "posture_tags": tags}, indent=2)
        except Exception as e:
            return f"Error: {e}"


# ── AGENT + TASK BUILDERS ─────────────────────────────────────────────────────

def build_auth_agent(llm) -> Agent:
    return Agent(
        role="Authentication & Exposure Analyst",
        goal=(
            "For each high-value host: detect authentication type, find exposed sensitive paths, "
            "scan JSON responses for leaked secrets, check security headers, "
            "classify posture (WAF, CDN, dangling DNS, takeover candidates)."
        ),
        backstory=(
            "You are an expert at identifying authentication mechanisms and misconfigured exposures. "
            "You check every high-value host for: auth type (OAuth/SAML/JWT/Basic/none), "
            "exposed API docs, .env files, debug endpoints, and JSON responses leaking secrets. "
            "You classify WAF/CDN presence, CORS misconfig, and subdomain takeover candidates. "
            "You report only HIGH and CRITICAL findings — info-only findings go in a separate section."
        ),
        tools=[
            AuthAnalyzeTool(),
            JsonKeywordScanTool(),
            ProbeSensitivePathsTool(),
            PostureClassifyTool(),
        ],
        llm=llm,
        verbose=True,
        max_iter=25,
        allow_delegation=False,
        human_in_the_loop=False,
    )


def build_auth_tasks(agent, recon_output: str) -> list:

    # ── Task 1: Active probing — run tools per host ───────────────────────
    probe_task = Task(
        description=f"""
Probe every high-value host from recon for authentication and exposure.
Skip LOW-risk hosts with no web ports.
{_DOCTRINE}
RECON OUTPUT:
{recon_output[:60000]}

For each HIGH/CRITICAL/MEDIUM host with a web port (80, 443, 8080, 8443,
8888, 9090, 9443, 4443, 3000, 5601, 9200, 8161, 7474):

STEP 1 — AUTH DETECTION:
  analyze_auth("http://<ip>:<port>") and analyze_auth("https://<ip>:<port>")
  Record: auth_type (OAuth/SAML/JWT/Basic/None), MFA present, confidence.

STEP 2 — SENSITIVE PATH PROBING:
  probe_sensitive_paths("<ip>", port=<port>, probe_type="all")
  Flag any path returning HTTP 200/401/403:
    /.env, /config.json, /.git/config, /admin, /swagger, /api-docs,
    /actuator, /actuator/env, /actuator/health, /graphql, /graphiql,
    /.htpasswd, /phpinfo.php, /server-status, /debug, /console,
    /wp-config.php, /backup, /backup.zip, /db.sqlite3, /dump.sql

STEP 3 — JSON KEYWORD SCAN:
  For endpoints returning JSON (/health, /api, /actuator/env, /status):
  json_keyword_scan("<url>")
  Flag any response containing: token, secret, api_key, password,
  credential, bearer, aws_access, private_key, auth, passphrase.

Collect all raw results. Do not filter yet — synthesis happens in Task 2.
""",
        expected_output=(
            "Raw probe results per host: auth type, MFA, paths returning 200/401/403, "
            "JSON keyword hits. One entry per host:port combination probed."
        ),
        agent=agent,
    )

    # ── Task 2: Synthesis + posture triage ────────────────────────────────
    synthesis_task = Task(
        description=f"""
Synthesise the probe results into a structured auth and exposure report.
Run posture classification, then produce the final structured JSON.

STEP 1 — POSTURE CLASSIFICATION:
  For each unique hostname (not just IP — use hostnames from recon output):
  classify_posture("<hostname>")
  Flag: NO_WAF, CDN_PROTECTED, ORIGIN_EXPOSED, DANGLING_DNS, POTENTIAL_TAKEOVER

STEP 2 — SEVERITY TRIAGE (evidence-gated — confirmed exposure only):
  A path returning 401/403 means auth IS present: that is NOT an exposure. Record it at most
  as INFO ("path exists, protected"). Only a 200 with the sensitive content actually served
  counts as an exposure. Do not assign Critical/High to a host with no 200-backed evidence.
  Assign severity to every finding:
  CRITICAL: path returning 200 + sensitive file (/.env, /.git/config, /wp-config.php) — body confirms it
  CRITICAL: JSON keyword scan hit (token/secret/api_key actually present in a 200 response body)
  CRITICAL: No auth on admin interface — confirmed by a 200 that serves admin content (not a 401/403)
  HIGH: Swagger/GraphQL/API docs served at 200 without auth
  HIGH: Basic Auth (cleartext credentials) — observed WWW-Authenticate: Basic
  HIGH: CORS open (Access-Control-Allow-Origin: *) — observed in headers
  HIGH: POTENTIAL_TAKEOVER posture tag WITH a matched vendor signature
  MEDIUM: Missing security headers (HSTS, CSP, X-Frame-Options)
  MEDIUM: DANGLING_DNS posture tag (lead — not a confirmed takeover)
  MEDIUM: Self-signed cert on public interface
  INFO:   NO_WAF (header inference only — never a standalone finding)

STEP 3 — OUTPUT as JSON. The block below is an ILLUSTRATIVE SCHEMA showing the shape of one
entry — do NOT copy its literal values (1.2.3.4, paths) as if they were findings:
{{
  "auth_findings": [
    {{
      "ip": "1.2.3.4", "port": 8080,
      "auth_types": ["Basic"], "auth_confidence": "high",
      "mfa_present": false,
      "missing_headers": ["HSTS", "CSP"],
      "cors_open": false,
      "severity": "High",
      "findings": ["Basic auth on admin panel — credentials sent in cleartext"]
    }}
  ],
  "exposure_findings": [
    {{
      "ip": "1.2.3.4", "port": 8080,
      "path": "/.env", "status": 200, "severity": "Critical",
      "type": "sensitive_file", "evidence": "200 OK — file accessible"
    }}
  ],
  "secret_leaks": [
    {{
      "url": "http://1.2.3.4:8080/actuator/env",
      "keywords_found": ["api_key", "secret"],
      "severity": "Critical",
      "evidence": "JSON response contains api_key field with value"
    }}
  ],
  "posture_findings": [
    {{
      "hostname": "api.acme.com",
      "tags": ["NO_WAF", "ORIGIN_EXPOSED"],
      "severity": "High"
    }}
  ],
  "critical_count": N,
  "high_count": N,
  "medium_count": N
}}
""",
        expected_output=(
            "JSON: auth_findings[], exposure_findings[], secret_leaks[], "
            "posture_findings[], critical_count, high_count, medium_count"
        ),
        agent=agent,
        context=[probe_task],
    )

    return [probe_task, synthesis_task]
