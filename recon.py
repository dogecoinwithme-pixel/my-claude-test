#!/usr/bin/env python3
"""
recon.py - Plug-and-play recon for authorized bug bounty research.

Usage:
    python3 recon.py https://example.com
    python3 recon.py example.com --json report.json

ONLY run this against targets you are explicitly authorized to test
(your own systems, or assets inside an active bug bounty program's scope).
Unauthorized scanning may be illegal. You are responsible for staying in scope.

Dependencies: standard library only, plus `requests` (optional but recommended).
    pip install requests
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone

try:
    import requests  # nicer HTTP; optional
    HAVE_REQUESTS = True
except ImportError:  # fall back to urllib
    HAVE_REQUESTS = False

USER_AGENT = "recon.py/1.0 (authorized-bug-bounty-research)"
TIMEOUT = 12

# Security headers a well-configured site should set. Missing ones are notes,
# not vulnerabilities by themselves.
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS not set - connection downgrade risk",
    "content-security-policy": "CSP not set - weaker XSS mitigation",
    "x-frame-options": "X-Frame-Options not set - clickjacking risk",
    "x-content-type-options": "X-Content-Type-Options not set - MIME sniffing",
    "referrer-policy": "Referrer-Policy not set - referrer leakage",
    "permissions-policy": "Permissions-Policy not set - feature access unrestricted",
}

# Simple header/cookie fingerprints -> technology guess.
TECH_FINGERPRINTS = {
    "server": "Web server",
    "x-powered-by": "Backend framework/runtime",
    "x-aspnet-version": "ASP.NET",
    "x-generator": "CMS/generator",
    "via": "Proxy/CDN",
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront",
    "x-served-by": "Fastly/Varnish",
}

# Paths worth a quick look. Passive-ish: single GET each, no brute force.
INTERESTING_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/.git/config",
    "/.env",
    "/humans.txt",
]


def color(text: str, code: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


def banner(text: str) -> None:
    print("\n" + color(f"== {text} ==", "1;36"))


def normalize_target(raw: str) -> tuple[str, str]:
    """Return (base_url, hostname) from user input in any common form."""
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    host = parsed.hostname or ""
    base = f"{parsed.scheme}://{parsed.netloc}"
    return base, host


def http_get(url: str, method: str = "GET"):
    """Return (status, headers_dict, body_text). Never raises for HTTP errors."""
    headers = {"User-Agent": USER_AGENT}
    if HAVE_REQUESTS:
        try:
            r = requests.request(
                method, url, headers=headers, timeout=TIMEOUT,
                allow_redirects=True, verify=True,
            )
            return r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.text
        except requests.RequestException as e:
            return None, {}, str(e)
    # urllib fallback
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read(200_000).decode("utf-8", "replace")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, hdrs, body
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, ""
    except Exception as e:  # noqa: BLE001
        return None, {}, str(e)


def resolve_dns(host: str) -> dict:
    out = {"host": host, "addresses": [], "error": None}
    try:
        infos = socket.getaddrinfo(host, None)
        out["addresses"] = sorted({i[4][0] for i in infos})
    except socket.gaierror as e:
        out["error"] = str(e)
    return out


def get_tls_info(host: str, port: int = 443) -> dict:
    info = {"error": None}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                info["protocol"] = ssock.version()
                info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                info["subject"] = dict(x[0] for x in cert.get("subject", []))
                info["not_after"] = cert.get("notAfter")
                info["not_before"] = cert.get("notBefore")
                sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
                info["subject_alt_names"] = sans
    except Exception as e:  # noqa: BLE001
        info["error"] = str(e)
    return info


def crtsh_subdomains(domain: str) -> dict:
    """Passive subdomain discovery via crt.sh certificate transparency logs."""
    out = {"count": 0, "subdomains": [], "error": None}
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    status, _, body = http_get(url)
    if status != 200 or not body:
        out["error"] = f"crt.sh returned {status}"
        return out
    try:
        data = json.loads(body)
        subs = set()
        for entry in data:
            for name in str(entry.get("name_value", "")).split("\n"):
                name = name.strip().lstrip("*.").lower()
                if name.endswith(domain):
                    subs.add(name)
        out["subdomains"] = sorted(subs)
        out["count"] = len(subs)
    except json.JSONDecodeError as e:
        out["error"] = f"parse error: {e}"
    return out


def analyze_headers(headers: dict) -> dict:
    missing = []
    for h, note in SECURITY_HEADERS.items():
        if h not in headers:
            missing.append(note)
    tech = {}
    for h, label in TECH_FINGERPRINTS.items():
        if h in headers:
            tech[label] = headers[h]
    return {"missing_security_headers": missing, "technologies": tech}


def check_paths(base: str) -> list:
    findings = []
    for path in INTERESTING_PATHS:
        status, headers, body = http_get(base + path)
        if status and status < 400:
            snippet = (body or "")[:120].replace("\n", " ")
            findings.append({
                "path": path,
                "status": status,
                "content_type": headers.get("content-type", ""),
                "preview": snippet,
            })
    return findings


def run(target: str) -> dict:
    base, host = normalize_target(target)
    apex = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host

    report = {
        "target": base,
        "host": host,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }

    banner(f"Target: {base}  (host: {host})")

    banner("DNS resolution")
    report["dns"] = resolve_dns(host)
    if report["dns"]["error"]:
        print(color(f"  DNS error: {report['dns']['error']}", "31"))
    else:
        for a in report["dns"]["addresses"]:
            print(f"  {a}")

    banner("HTTP fingerprint")
    status, headers, _ = http_get(base)
    report["http_status"] = status
    print(f"  Status: {status}")
    report["header_analysis"] = analyze_headers(headers)
    if report["header_analysis"]["technologies"]:
        print(color("  Technologies:", "1"))
        for label, val in report["header_analysis"]["technologies"].items():
            print(f"    - {label}: {val}")
    if report["header_analysis"]["missing_security_headers"]:
        print(color("  Missing security headers:", "33"))
        for note in report["header_analysis"]["missing_security_headers"]:
            print(f"    - {note}")

    banner("TLS certificate")
    report["tls"] = get_tls_info(host)
    if report["tls"].get("error"):
        print(color(f"  TLS error: {report['tls']['error']}", "31"))
    else:
        print(f"  Protocol: {report['tls'].get('protocol')}")
        print(f"  Issuer:   {report['tls'].get('issuer', {}).get('organizationName', '?')}")
        print(f"  Expires:  {report['tls'].get('not_after')}")
        print(f"  SANs:     {len(report['tls'].get('subject_alt_names', []))} names")

    banner("Interesting paths (single GET each)")
    report["paths"] = check_paths(base)
    if report["paths"]:
        for f in report["paths"]:
            flag = color("!!", "31") if f["path"] in ("/.git/config", "/.env") else "  "
            print(f"  {flag} [{f['status']}] {f['path']}  ({f['content_type']})")
    else:
        print("  none reachable")

    banner("Passive subdomains (crt.sh)")
    report["subdomains"] = crtsh_subdomains(apex)
    if report["subdomains"]["error"]:
        print(color(f"  {report['subdomains']['error']}", "33"))
    else:
        print(f"  {report['subdomains']['count']} unique subdomains found")
        for s in report["subdomains"]["subdomains"][:30]:
            print(f"    - {s}")
        if report["subdomains"]["count"] > 30:
            print(f"    ... and {report['subdomains']['count'] - 30} more")

    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="Plug-and-play recon for authorized bug bounty research.")
    ap.add_argument("target", help="URL or domain, e.g. https://example.com or example.com")
    ap.add_argument("--json", metavar="FILE", help="write full report to a JSON file")
    ap.add_argument("--yes", action="store_true", help="skip the authorization prompt")
    args = ap.parse_args()

    if not args.yes:
        print(color("AUTHORIZATION CHECK", "1;33"))
        print("Only scan targets you are explicitly authorized to test (in-scope bug bounty asset or your own).")
        ans = input(f"Confirm you are authorized to scan '{args.target}'? [y/N] ").strip().lower()
        if ans not in ("y", "yes"):
            print("Aborted.")
            return 1

    report = run(args.target)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(color(f"\nFull report written to {args.json}", "32"))

    return 0


if __name__ == "__main__":
    sys.exit(main())
