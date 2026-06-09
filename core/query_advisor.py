"""
query_advisor.py — Guided query builder.

Per NEXT_SESSION_SPEC.md:
  - Complete filter list (all categories from PDF + Shodan docs)
  - Complete template list (attack surface, vulnerability, misconfig, threat hunting)
  - Propose-approve loop for AI agent builder
  - suggest_followups() returns data-driven next queries for human review
"""

from __future__ import annotations

from typing import Any
import re


# ---------------------------------------------------------------------------
# COMPLETE FILTER REFERENCE
# All filters from PDF guide + Shodan docs as clickable chips in the UI.
# tier: "free" | "paid"
# ---------------------------------------------------------------------------
FILTER_REFERENCE: list[dict[str, Any]] = [
    # --- Network & Identity ---
    {
        "category": "Network & Identity",
        "name": "org",
        "syntax": 'org:"Acme Corp"',
        "description": "Hosts belonging to a specific organization (per WHOIS/BGP).",
        "tier": "free",
    },
    {
        "category": "Network & Identity",
        "name": "asn",
        "syntax": "asn:AS15169",
        "description": "Hosts in a given autonomous system. Useful for scoping by network owner.",
        "tier": "free",
    },
    {
        "category": "Network & Identity",
        "name": "isp",
        "syntax": 'isp:"Google"',
        "description": "ISP providing connectivity (may differ from org).",
        "tier": "free",
    },
    {
        "category": "Network & Identity",
        "name": "ip",
        "syntax": "ip:1.2.3.4",
        "description": "Specific IP address lookup.",
        "tier": "free",
    },
    {
        "category": "Network & Identity",
        "name": "net",
        "syntax": "net:192.168.1.0/24",
        "description": "CIDR range. Useful for scoping to known IP blocks.",
        "tier": "free",
    },
    {
        "category": "Network & Identity",
        "name": "port",
        "syntax": "port:443",
        "description": "Hosts with the given port open. Combine with commas: port:80,443.",
        "tier": "free",
    },
    {
        "category": "Network & Identity",
        "name": "hostname",
        "syntax": "hostname:example.com",
        "description": "Hosts whose reverse DNS contains the substring.",
        "tier": "free",
    },
    {
        "category": "Network & Identity",
        "name": "domain",
        "syntax": "domain:example.com",
        "description": "Hosts with a matching domain in their hostnames.",
        "tier": "free",
    },
    # --- Geographic ---
    {
        "category": "Geographic",
        "name": "country",
        "syntax": "country:US",
        "description": "2-letter country code. Combine with other filters to scope by geography.",
        "tier": "free",
    },
    {
        "category": "Geographic",
        "name": "city",
        "syntax": 'city:"Dallas"',
        "description": "City name. Case-sensitive — use quotes for multi-word cities.",
        "tier": "free",
    },
    {
        "category": "Geographic",
        "name": "geo",
        "syntax": "geo:37.7749,-122.4194,10",
        "description": "Lat/long with radius in km. Useful for physical proximity searches.",
        "tier": "free",
    },
    {
        "category": "Geographic",
        "name": "region",
        "syntax": 'region:"California"',
        "description": "State or province name.",
        "tier": "free",
    },
    # --- Service & Software ---
    {
        "category": "Service & Software",
        "name": "product",
        "syntax": 'product:"nginx"',
        "description": "Hosts running a specific software product (banner detection).",
        "tier": "free",
    },
    {
        "category": "Service & Software",
        "name": "version",
        "syntax": 'version:"1.14.0"',
        "description": "Specific software version. Best combined with product:.",
        "tier": "free",
    },
    {
        "category": "Service & Software",
        "name": "os",
        "syntax": 'os:"Windows Server 2019"',
        "description": "Operating system detected from banners.",
        "tier": "free",
    },
    {
        "category": "Service & Software",
        "name": "server",
        "syntax": 'server:"Apache/2.4"',
        "description": "HTTP Server header value.",
        "tier": "free",
    },
    {
        "category": "Service & Software",
        "name": "http.component",
        "syntax": 'http.component:"WordPress"',
        "description": "Detected technology (jQuery, React, WordPress, etc.).",
        "tier": "free",
    },
    # --- Content & Protocol ---
    {
        "category": "Content & Protocol",
        "name": "http.title",
        "syntax": 'http.title:"Login"',
        "description": "HTTP responses whose page title matches. Good for finding admin panels.",
        "tier": "free",
    },
    {
        "category": "Content & Protocol",
        "name": "http.html",
        "syntax": 'http.html:"default password"',
        "description": "Raw HTML content match. Useful for detecting exposed config pages.",
        "tier": "free",
    },
    {
        "category": "Content & Protocol",
        "name": "http.favicon.hash",
        "syntax": "http.favicon.hash:116323821",
        "description": "Favicon hash fingerprint. Identifies specific apps by their icon.",
        "tier": "free",
    },
    {
        "category": "Content & Protocol",
        "name": "ssl",
        "syntax": 'ssl:"example.com"',
        "description": "SSL cert content match — searches all cert fields.",
        "tier": "free",
    },
    {
        "category": "Content & Protocol",
        "name": "ssl.cert.subject",
        "syntax": "ssl.cert.subject.cn:acme.example",
        "description": "TLS certs with a matching Common Name. Finds forgotten subdomains.",
        "tier": "free",
    },
    {
        "category": "Content & Protocol",
        "name": "ssl.cert.issuer",
        "syntax": 'ssl.cert.issuer.cn:"Let\'s Encrypt"',
        "description": "Certificate issuer. Useful for finding self-signed or expired certs.",
        "tier": "free",
    },
    {
        "category": "Content & Protocol",
        "name": "ssl.cert.expired",
        "syntax": "ssl.cert.expired:true",
        "description": "Filter to hosts with expired TLS certificates.",
        "tier": "free",
    },
    {
        "category": "Content & Protocol",
        "name": "ssh.hassh",
        "syntax": "ssh.hassh:b12d2871a123de1e434150bbc...",
        "description": "SSH fingerprint hash. Identifies server software/config.",
        "tier": "free",
    },
    # --- Security (paid) ---
    {
        "category": "Security",
        "name": "vuln",
        "syntax": "vuln:CVE-2021-44228",
        "description": "Hosts flagged as matching this CVE. Requires a paid Shodan plan.",
        "tier": "paid",
    },
    {
        "category": "Security",
        "name": "has_vuln",
        "syntax": "has_vuln:true",
        "description": "Any host with at least one Shodan-flagged vulnerability. Paid plan required.",
        "tier": "paid",
    },
    {
        "category": "Security",
        "name": "has_screenshot",
        "syntax": "has_screenshot:true",
        "description": "Hosts where Shodan captured a screenshot (HTTP/RDP/VNC). Paid plan required.",
        "tier": "paid",
    },
    {
        "category": "Security",
        "name": "tag",
        "syntax": "tag:database",
        "description": "Shodan-applied tags (ics, vpn, database, cloud, iot, malware). Corporate plan and above only.",
        "tier": "enterprise",
    },
    # --- Temporal ---
    {
        "category": "Temporal",
        "name": "before",
        "syntax": "before:2024-01-01",
        "description": "Hosts indexed before this date (YYYY-MM-DD).",
        "tier": "free",
    },
    {
        "category": "Temporal",
        "name": "after",
        "syntax": "after:2024-01-01",
        "description": "Hosts indexed after this date (YYYY-MM-DD).",
        "tier": "free",
    },
]


# ---------------------------------------------------------------------------
# COMPLETE TEMPLATE LIST
# Attack surface, vulnerability, misconfig, threat hunting — per PDF guide
# ---------------------------------------------------------------------------
TEMPLATES: list[dict[str, Any]] = [
    # ---- Attack Surface ----
    {
        "id": "org-footprint",
        "title": "Full Org Footprint",
        "category": "Attack Surface",
        "description": "All internet-visible assets for a given organization.",
        "query": 'org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    {
        "id": "asn-inventory",
        "title": "ASN Inventory",
        "category": "Attack Surface",
        "description": "Full visible inventory for a given ASN.",
        "query": "asn:{asn}",
        "params": [{"key": "asn", "label": "ASN", "placeholder": "AS64512"}],
        "tier": "free",
    },
    {
        "id": "cloud-aws",
        "title": "AWS Asset Discovery",
        "category": "Attack Surface",
        "description": "Assets hosted in Amazon AWS cloud (by org name).",
        "query": 'org:"Amazon" hostname:.amazonaws.com',
        "params": [],
        "tier": "free",
    },
    {
        "id": "cloud-azure",
        "title": "Azure Asset Discovery",
        "category": "Attack Surface",
        "description": "Assets hosted in Microsoft Azure cloud.",
        "query": 'org:"Microsoft Azure" hostname:.azure.com',
        "params": [],
        "tier": "free",
    },
    {
        "id": "cloud-gcp",
        "title": "GCP Asset Discovery",
        "category": "Attack Surface",
        "description": "Assets hosted in Google Cloud Platform.",
        "query": 'org:"Google" hostname:.googleapis.com',
        "params": [],
        "tier": "free",
    },
    {
        "id": "web-cms-wordpress",
        "title": "WordPress Sites",
        "category": "Attack Surface",
        "description": "Internet-exposed WordPress instances.",
        "query": 'http.component:"WordPress" org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    {
        "id": "web-cms-drupal",
        "title": "Drupal Sites",
        "category": "Attack Surface",
        "description": "Internet-exposed Drupal instances.",
        "query": 'http.component:"Drupal" org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    {
        "id": "web-cms-joomla",
        "title": "Joomla Sites",
        "category": "Attack Surface",
        "description": "Internet-exposed Joomla instances.",
        "query": 'http.component:"Joomla" org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    {
        "id": "exposed-admin-panels",
        "title": "Admin Panels by Title",
        "category": "Attack Surface",
        "description": "Web responses whose page title looks administrative.",
        "query": 'http.title:"admin" hostname:{domain}',
        "params": [{"key": "domain", "label": "Your domain", "placeholder": "example.com"}],
        "tier": "free",
    },
    {
        "id": "subdomain-discovery",
        "title": "Cert-based Subdomain Discovery",
        "category": "Attack Surface",
        "description": "Find hosts presenting a TLS cert for your domain — reveals forgotten subdomains.",
        "query": "ssl.cert.subject.cn:{domain}",
        "params": [{"key": "domain", "label": "Your domain", "placeholder": "example.com"}],
        "tier": "free",
    },
    {
        "id": "mail-servers",
        "title": "Mail Servers (Exchange / SMTP)",
        "category": "Attack Surface",
        "description": "Exposed mail infrastructure for your org.",
        "query": 'port:25,587,465,993,995 org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    {
        "id": "network-devices",
        "title": "Network Devices",
        "category": "Attack Surface",
        "description": "Cisco, Juniper, Palo Alto devices exposed to the internet.",
        "query": 'product:"Cisco" OR product:"Juniper" OR product:"Palo Alto" org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    {
        "id": "vpn-endpoints",
        "title": "VPN Endpoints",
        "category": "Attack Surface",
        "description": "Fortinet FortiGate, Cisco VPN, and Pulse Secure endpoints.",
        "query": 'product:"Fortinet" OR product:"Cisco VPN" OR http.title:"Pulse Connect" org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    # ---- Vulnerability ----
    {
        "id": "exposed-rdp",
        "title": "Exposed RDP (port 3389)",
        "category": "Vulnerability",
        "description": "Remote Desktop exposed to the internet — common ransomware entry point.",
        "query": 'port:3389 org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    {
        "id": "exposed-ssh",
        "title": "Exposed SSH (port 22)",
        "category": "Vulnerability",
        "description": "SSH exposed to the internet.",
        "query": 'port:22 org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    {
        "id": "exposed-telnet",
        "title": "Exposed Telnet (port 23)",
        "category": "Vulnerability",
        "description": "Unencrypted Telnet — should not be internet-facing.",
        "query": 'port:23 org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    {
        "id": "exposed-databases",
        "title": "Exposed Database Ports",
        "category": "Vulnerability",
        "description": "MongoDB, MySQL, Postgres, Redis, MSSQL, Elasticsearch exposed to internet.",
        "query": 'port:27017,3306,5432,6379,1433,9200 org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    {
        "id": "exposed-smb",
        "title": "Exposed SMB (port 445)",
        "category": "Vulnerability",
        "description": "SMB exposed to internet — EternalBlue / WannaCry attack surface.",
        "query": 'port:445 org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    {
        "id": "exposed-ftp",
        "title": "Exposed FTP (port 21)",
        "category": "Vulnerability",
        "description": "Unencrypted FTP exposed to the internet.",
        "query": 'port:21 org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    {
        "id": "log4shell-check",
        "title": "Log4Shell Exposure (paid)",
        "category": "Vulnerability",
        "description": "Hosts flagged for CVE-2021-44228 (Log4j). Requires paid Shodan plan.",
        "query": 'vuln:CVE-2021-44228 org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "paid",
    },
    {
        "id": "proxylogon-check",
        "title": "ProxyLogon Exchange (paid)",
        "category": "Vulnerability",
        "description": "Hosts flagged for CVE-2021-26855 (Exchange). Requires paid Shodan plan.",
        "query": 'vuln:CVE-2021-26855 org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "paid",
    },
    {
        "id": "outlook-cve-check",
        "title": "Outlook CVE (paid)",
        "category": "Vulnerability",
        "description": "Hosts flagged for CVE-2023-23397 (Outlook NTLM relay). Paid plan required.",
        "query": 'vuln:CVE-2023-23397 org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "paid",
    },
    {
        "id": "eol-software",
        "title": "End-of-Life Web Servers",
        "category": "Vulnerability",
        "description": "Old IIS or Apache versions still exposed to the internet.",
        "query": 'product:"Microsoft IIS httpd 7.5" OR product:"Apache httpd 2.2" org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    # ---- Misconfiguration ----
    {
        "id": "expired-ssl",
        "title": "Expired TLS Certificates",
        "category": "Misconfiguration",
        "description": "Hosts presenting expired SSL/TLS certificates.",
        "query": 'ssl.cert.expired:true org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    {
        "id": "self-signed-ssl",
        "title": "Self-Signed Certificates",
        "category": "Misconfiguration",
        "description": "Hosts using self-signed TLS certs — indicates missing CA-issued certs.",
        "query": "ssl.cert.issuer.cn:ssl.cert.subject.cn",
        "params": [],
        "tier": "free",
    },
    {
        "id": "default-credentials-html",
        "title": "Default Credentials in HTML",
        "category": "Misconfiguration",
        "description": "Pages mentioning default credentials in the HTML body.",
        "query": 'http.html:"default password" OR http.html:"admin/admin" org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    {
        "id": "open-directory",
        "title": "Open Directory Listings",
        "category": "Misconfiguration",
        "description": "Web servers serving open directory index pages.",
        "query": 'http.title:"Index of /" org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    {
        "id": "exposed-git",
        "title": "Exposed .git Repositories",
        "category": "Misconfiguration",
        "description": "Web servers accidentally exposing .git directories.",
        "query": 'http.title:"Index of /.git" OR http.html:"HEAD\nref: refs/" org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
    # ---- Threat Hunting ----
    {
        "id": "c2-cobalt-strike",
        "title": "Cobalt Strike C2",
        "category": "Threat Hunting",
        "description": "Known Cobalt Strike beacon indicators in HTTP responses.",
        "query": 'product:"Cobalt Strike Beacon" OR http.title:"Cobalt Strike"',
        "params": [],
        "tier": "free",
    },
    {
        "id": "c2-silver",
        "title": "Sliver / Silver C2",
        "category": "Threat Hunting",
        "description": "Known Sliver/Silver C2 framework indicators.",
        "query": 'ssl.cert.subject.cn:"multiplayer" port:443,80',
        "params": [],
        "tier": "free",
    },
    {
        "id": "c2-empire",
        "title": "Empire / Covenant C2",
        "category": "Threat Hunting",
        "description": "Empire PowerShell C2 and Covenant framework indicators.",
        "query": 'http.html:"Empire" port:443 ssl',
        "params": [],
        "tier": "free",
    },
    {
        "id": "botnet-mirai",
        "title": "Mirai Botnet Indicators",
        "category": "Threat Hunting",
        "description": "Hosts with Mirai botnet signatures in banners.",
        "query": 'http.html:"mirai" port:23,2323',
        "params": [],
        "tier": "free",
    },
    {
        "id": "crypto-mining",
        "title": "Crypto Mining Infrastructure",
        "category": "Threat Hunting",
        "description": "Stratum mining protocol endpoints and mining pool indicators.",
        "query": 'port:3333,4444,8333,9999 product:"stratum"',
        "params": [],
        "tier": "free",
    },
    {
        "id": "ransomware-portal",
        "title": "Ransomware Portals",
        "category": "Threat Hunting",
        "description": "Known ransomware payment/leak site indicators.",
        "query": 'http.title:"Your files have been encrypted" OR http.html:"bitcoin" http.html:"decrypt"',
        "params": [],
        "tier": "free",
    },
    {
        "id": "phishing-sites",
        "title": "Phishing Infrastructure",
        "category": "Threat Hunting",
        "description": "Suspicious newly-issued certs and login page clones.",
        "query": 'ssl.cert.subject.cn:"login" OR ssl.cert.subject.cn:"secure" port:443 after:{after}',
        "params": [{"key": "after", "label": "After date", "placeholder": "2024-01-01"}],
        "tier": "free",
    },
    {
        "id": "compromised-hosts",
        "title": "Compromised Host Indicators",
        "category": "Threat Hunting",
        "description": "Hosts showing known compromise indicators (banner-level, no tag: filter required).",
        "query": 'http.html:"command not found" port:80,8080 org:"{org}"',
        "params": [{"key": "org", "label": "Organization name", "placeholder": "Acme Corp"}],
        "tier": "free",
    },
]


def render_template(template_id: str, params: dict[str, str]) -> str | None:
    for tpl in TEMPLATES:
        if tpl["id"] == template_id:
            query = tpl["query"]
            for key, val in params.items():
                query = query.replace("{" + key + "}", val)
            # Strip any unfilled placeholders gracefully
            query = re.sub(r'\S*\{[^}]+\}\S*', "", query).strip()
            query = re.sub(r"\s+", " ", query)
            return query
    return None


def suggest_followups(query: str, results: list[dict]) -> list[dict[str, str]]:
    """
    Given a finished query + its result list, suggest next queries an analyst
    might want to run. These are displayed as buttons in the UI — the human
    decides whether to run any of them.
    """
    suggestions: list[dict[str, str]] = []
    if not results:
        return suggestions

    orgs: dict[str, int] = {}
    ports: dict[int, int] = {}
    cves: dict[str, int] = {}
    products: dict[str, int] = {}

    for r in results:
        org = r.get("org") or ""
        if org and org != "N/A":
            orgs[org] = orgs.get(org, 0) + 1
        pi = r.get("port_info")
        if pi:
            for p in pi.all_ports:
                ports[p] = ports.get(p, 0) + 1
        else:
            for p in r.get("ports", []):
                ports[p] = ports.get(p, 0) + 1
        ci = r.get("cve_info")
        if ci:
            for c in ci.all_cves:
                cves[c] = cves.get(c, 0) + 1
        else:
            for c in r.get("cves", []):
                cves[c] = cves.get(c, 0) + 1
        prod = r.get("product") or ""
        if prod and prod != "N/A":
            products[prod] = products.get(prod, 0) + 1

    # 1) Narrow by dominant org if not already scoped
    if "org:" not in query.lower() and orgs:
        top_org, count = max(orgs.items(), key=lambda x: x[1])
        if count >= 2:
            suggestions.append({
                "label": f"Narrow to top org ({top_org}, {count} hosts)",
                "query": f'{query} org:"{top_org}"',
                "rationale": "Filters results to the single most common organization in your current findings.",
            })

    # 2) Pivot on dangerous ports
    risky_ports = {3389: "RDP", 23: "Telnet", 445: "SMB", 6379: "Redis", 27017: "MongoDB", 5432: "Postgres"}
    for p, label in risky_ports.items():
        if ports.get(p, 0) >= 2 and f"port:{p}" not in query:
            suggestions.append({
                "label": f"Show only {label} exposures ({ports[p]} hosts)",
                "query": f"{query} port:{p}",
                "rationale": f"You have {ports[p]} hosts with port {p} ({label}) open. Drill in.",
            })
            break

    # 3) CVE-specific follow-up
    if cves:
        top_cve, count = max(cves.items(), key=lambda x: x[1])
        if count >= 2 and top_cve not in query:
            suggestions.append({
                "label": f"Pivot to {top_cve} ({count} hosts)",
                "query": f"vuln:{top_cve}",
                "rationale": "Shodan-flagged vulnerability appearing in multiple results. Paid plan required for vuln: filter.",
            })

    # 4) Expired certs if not already filtered
    if "ssl.cert.expired" not in query.lower():
        suggestions.append({
            "label": "Check for expired TLS certs in these results",
            "query": f"{query} ssl.cert.expired:true",
            "rationale": "Expired certificates are a common hygiene finding — worth filtering to see scope.",
        })

    # 5) Save-as-watched nudge
    suggestions.append({
        "label": "Save as a watched query",
        "query": query,
        "rationale": "Re-run this later and Diff Mode will highlight new hosts and changed exposures since today.",
        "action": "save_watch",
    })

    return suggestions
