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
import random
import re
import socket
import ssl
import string
import sys
import time
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
REQUEST_DELAY = 0.2  # seconds between requests - keep scans polite, avoid DoS-like behavior


class RequestBudget:
    """Caps total outbound requests for a run and paces them.

    Every active/OOB check goes through this so a single invocation can never
    turn into an unbounded flood against a target, no matter how many probes
    are enabled at once.
    """

    def __init__(self, max_requests: int = 300, delay: float = REQUEST_DELAY):
        self.max_requests = max_requests
        self.delay = delay
        self.count = 0
        self.exhausted_warned = False

    def allow(self) -> bool:
        if self.count >= self.max_requests:
            if not self.exhausted_warned:
                print(color(f"  [budget] request cap ({self.max_requests}) reached, skipping remaining checks", "33"))
                self.exhausted_warned = True
            return False
        self.count += 1
        if self.count > 1:
            time.sleep(self.delay)
        return True

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


def http_get(url: str, method: str = "GET", extra_headers: dict | None = None,
             budget: "RequestBudget | None" = None, allow_redirects: bool = True):
    """Return (status, headers_dict, body_text). Never raises for HTTP errors."""
    if budget is not None and not budget.allow():
        return None, {}, "budget exceeded"
    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    if HAVE_REQUESTS:
        try:
            r = requests.request(
                method, url, headers=headers, timeout=TIMEOUT,
                allow_redirects=allow_redirects, verify=True,
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


def crtsh_subdomains(domain: str, budget: "RequestBudget | None" = None) -> dict:
    """Passive subdomain discovery via crt.sh certificate transparency logs."""
    out = {"count": 0, "subdomains": [], "error": None}
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    status, _, body = http_get(url, budget=budget)
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


def check_paths(base: str, budget: "RequestBudget | None" = None) -> list:
    findings = []
    for path in INTERESTING_PATHS:
        status, headers, body = http_get(base + path, budget=budget)
        if status and status < 400:
            snippet = (body or "")[:120].replace("\n", " ")
            findings.append({
                "path": path,
                "status": status,
                "content_type": headers.get("content-type", ""),
                "preview": snippet,
            })
    return findings


REDIRECT_PARAMS = ["redirect", "url", "next", "dest", "destination", "continue", "return", "returnUrl", "r"]
INJECTABLE_PARAMS = ["q", "search", "query", "name", "id", "keyword", "s"]


def _rand_token(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def check_open_redirect(base: str, budget: "RequestBudget") -> list:
    """Non-destructive check: does the app 3xx-redirect to an attacker-supplied external URL?"""
    findings = []
    canary = "https://example.com/recon-open-redirect-check"
    for param in REDIRECT_PARAMS:
        url = f"{base}/?{param}={urllib.parse.quote(canary, safe='')}"
        status, headers, _ = http_get(url, budget=budget, allow_redirects=False)
        if status in (301, 302, 303, 307, 308):
            location = headers.get("location", "")
            if location.startswith(canary) or "example.com" in location:
                findings.append({"param": param, "status": status, "location": location})
    return findings


def check_cors_misconfig(base: str, budget: "RequestBudget") -> dict | None:
    """Non-destructive check: does the app reflect an arbitrary Origin with credentials allowed?"""
    probe_origin = "https://recon-cors-check.invalid"
    status, headers, _ = http_get(base, extra_headers={"Origin": probe_origin}, budget=budget)
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    if acao == probe_origin or acao == "*" and acac.lower() == "true":
        return {"reflects_origin": acao, "allow_credentials": acac, "status": status}
    return None


def check_reflected_xss(base: str, budget: "RequestBudget") -> list:
    """Non-destructive probe: sends a unique unescaped marker, flags if it reflects verbatim.

    This only detects a *candidate* reflection point for manual confirmation - it does not
    attempt to execute anything or exfiltrate data.
    """
    findings = []
    marker = f"reconXSS{_rand_token(6)}"
    payload = f"\"'><{marker}"
    for param in INJECTABLE_PARAMS:
        url = f"{base}/?{param}={urllib.parse.quote(payload)}"
        status, _, body = http_get(url, budget=budget)
        if body and payload in body:
            findings.append({"param": param, "status": status, "note": "payload reflected unescaped - verify manually"})
    return findings


def check_oob_collaborator(base: str, collaborator_domain: str, budget: "RequestBudget") -> list:
    """Injects a unique subdomain of a *researcher-owned* OOB listener into common
    SSRF-prone parameters and headers. You must run your own Interactsh/Burp
    Collaborator (or similar) instance and pass its domain via --collaborator-domain;
    this script never talks to a third-party listener it doesn't tell you about.

    After the scan, check your collaborator dashboard for any DNS/HTTP interaction
    matching the tokens printed below - that confirms blind SSRF.
    """
    injected = []
    ssrf_params = ["url", "uri", "path", "dest", "redirect", "callback", "webhook", "feed", "src", "target"]
    for param in ssrf_params:
        token = _rand_token(10)
        canary_url = f"http://{token}.{collaborator_domain}/"
        req_url = f"{base}/?{param}={urllib.parse.quote(canary_url, safe='')}"
        http_get(req_url, budget=budget)
        injected.append({"vector": f"param:{param}", "token": token, "canary": canary_url})

    header_token = _rand_token(10)
    header_canary = f"{header_token}.{collaborator_domain}"
    http_get(
        base,
        extra_headers={
            "X-Forwarded-For": header_canary,
            "X-Forwarded-Host": header_canary,
            "Referer": f"http://{header_canary}/",
        },
        budget=budget,
    )
    injected.append({"vector": "headers:X-Forwarded-For/Host,Referer", "token": header_token, "canary": header_canary})
    return injected


def get_wayback_urls(domain: str, budget: "RequestBudget", limit: int = 500) -> dict:
    """Passive historical URL discovery via the Wayback Machine CDX API."""
    out = {"count": 0, "urls": [], "error": None}
    api = (
        "http://web.archive.org/cdx/search/cdx"
        f"?url={urllib.parse.quote(domain)}/*&output=json&fl=original&collapse=urlkey&limit={limit}"
    )
    status, _, body = http_get(api, budget=budget)
    if status != 200 or not body:
        out["error"] = f"wayback returned {status}"
        return out
    try:
        rows = json.loads(body)
        urls = sorted({r[0] for r in rows[1:]} if rows else set())
        out["urls"] = urls
        out["count"] = len(urls)
    except (json.JSONDecodeError, IndexError) as e:
        out["error"] = f"parse error: {e}"
    return out


def extract_js_endpoints(base: str, homepage_body: str, budget: "RequestBudget", max_files: int = 8) -> dict:
    """Fetches same-origin JS files linked from the homepage and regexes out
    path-like string literals that look like API endpoints, for manual triage."""
    out = {"js_files": [], "endpoints": []}
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', homepage_body or "", re.I)
    endpoints = set()
    checked = 0
    for src in script_srcs:
        if checked >= max_files:
            break
        js_url = urllib.parse.urljoin(base + "/", src)
        if urllib.parse.urlparse(js_url).netloc != urllib.parse.urlparse(base).netloc:
            continue  # third-party JS (analytics/CDNs) - not our target's attack surface
        status, headers, body = http_get(js_url, budget=budget)
        checked += 1
        if status and status < 400 and body:
            out["js_files"].append(js_url)
            for m in re.findall(r'["\'](/[a-zA-Z0-9_\-/{}.]{2,80}?)["\']', body):
                if any(m.lower().endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".svg", ".css", ".woff", ".woff2")):
                    continue
                endpoints.add(m)
    out["endpoints"] = sorted(endpoints)[:200]
    return out


def run(target: str, active: bool = False, collaborator_domain: str | None = None,
        wayback: bool = False, js: bool = False, max_requests: int = 300) -> dict:
    base, host = normalize_target(target)
    apex = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
    budget = RequestBudget(max_requests=max_requests)

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
    status, headers, homepage_body = http_get(base, budget=budget)
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
    report["paths"] = check_paths(base, budget=budget)
    if report["paths"]:
        for f in report["paths"]:
            flag = color("!!", "31") if f["path"] in ("/.git/config", "/.env") else "  "
            print(f"  {flag} [{f['status']}] {f['path']}  ({f['content_type']})")
    else:
        print("  none reachable")

    banner("Passive subdomains (crt.sh)")
    report["subdomains"] = crtsh_subdomains(apex, budget=budget)
    if report["subdomains"]["error"]:
        print(color(f"  {report['subdomains']['error']}", "33"))
    else:
        print(f"  {report['subdomains']['count']} unique subdomains found")
        for s in report["subdomains"]["subdomains"][:30]:
            print(f"    - {s}")
        if report["subdomains"]["count"] > 30:
            print(f"    ... and {report['subdomains']['count'] - 30} more")

    if wayback:
        banner("Historical URLs (Wayback Machine, passive)")
        report["wayback"] = get_wayback_urls(apex, budget=budget)
        if report["wayback"]["error"]:
            print(color(f"  {report['wayback']['error']}", "33"))
        else:
            print(f"  {report['wayback']['count']} historical URLs found")
            for u in report["wayback"]["urls"][:20]:
                print(f"    - {u}")
            if report["wayback"]["count"] > 20:
                print(f"    ... and {report['wayback']['count'] - 20} more (see JSON report)")

    if js:
        banner("JS endpoint extraction")
        report["js"] = extract_js_endpoints(base, homepage_body, budget=budget)
        print(f"  {len(report['js']['js_files'])} same-origin JS files fetched")
        for e in report["js"]["endpoints"][:30]:
            print(f"    - {e}")
        if len(report["js"]["endpoints"]) > 30:
            print(f"    ... and {len(report['js']['endpoints']) - 30} more (see JSON report)")

    if active:
        banner("Active checks: open redirect (non-destructive)")
        report["open_redirect"] = check_open_redirect(base, budget)
        if report["open_redirect"]:
            for f in report["open_redirect"]:
                print(color(f"  !! param={f['param']} status={f['status']} -> {f['location']}", "31"))
        else:
            print("  none found")

        banner("Active checks: CORS misconfiguration (non-destructive)")
        report["cors"] = check_cors_misconfig(base, budget)
        if report["cors"]:
            print(color(f"  !! reflects arbitrary Origin, credentials={report['cors']['allow_credentials']}", "31"))
        else:
            print("  none found")

        banner("Active checks: reflected input (non-destructive probe)")
        report["reflected"] = check_reflected_xss(base, budget)
        if report["reflected"]:
            for f in report["reflected"]:
                print(color(f"  !! param={f['param']} - {f['note']}", "31"))
        else:
            print("  none found")

    if collaborator_domain:
        banner(f"OOB / blind SSRF probes -> {collaborator_domain}")
        print("  Injecting canary tokens into common SSRF-prone params/headers.")
        print("  Check YOUR OWN collaborator dashboard for interactions matching these tokens:")
        report["oob"] = check_oob_collaborator(base, collaborator_domain, budget)
        for i in report["oob"]:
            print(f"    - {i['vector']:45s} token={i['token']}")
    elif active:
        print(color(
            "\n  [info] Skipping OOB/blind-SSRF injection: no --collaborator-domain given.\n"
            "         Run your own Interactsh/Burp Collaborator instance and pass its\n"
            "         domain to test blind SSRF safely against infrastructure you control.",
            "36",
        ))

    report["requests_made"] = budget.count
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="Plug-and-play recon for authorized bug bounty research.")
    ap.add_argument("target", help="URL or domain, e.g. https://example.com or example.com")
    ap.add_argument("--json", metavar="FILE", help="write full report to a JSON file")
    ap.add_argument("--yes", action="store_true", help="skip the authorization prompt")
    ap.add_argument("--active", action="store_true",
                     help="enable non-destructive active checks: open redirect, CORS misconfig, reflected-input probe")
    ap.add_argument("--collaborator-domain", metavar="DOMAIN",
                     help="YOUR OWN Interactsh/Burp Collaborator domain, to test blind SSRF via OOB canaries. "
                          "Never defaults to any third-party listener.")
    ap.add_argument("--wayback", action="store_true", help="pull historical URLs from the Wayback Machine (passive)")
    ap.add_argument("--js", action="store_true", help="fetch same-origin JS and extract candidate endpoint paths")
    ap.add_argument("--all", action="store_true", help="shorthand for --active --wayback --js (still needs --collaborator-domain for OOB)")
    ap.add_argument("--max-requests", type=int, default=300, help="hard cap on outbound requests this run makes (default 300)")
    args = ap.parse_args()

    if args.all:
        args.active = True
        args.wayback = True
        args.js = True

    if not args.yes:
        print(color("AUTHORIZATION CHECK", "1;33"))
        print("Only scan targets you are explicitly authorized to test (in-scope bug bounty asset or your own).")
        print("Active checks and OOB probes send real requests to the target - make sure they're in scope.")
        ans = input(f"Confirm you are authorized to scan '{args.target}'? [y/N] ").strip().lower()
        if ans not in ("y", "yes"):
            print("Aborted.")
            return 1

    report = run(
        args.target,
        active=args.active,
        collaborator_domain=args.collaborator_domain,
        wayback=args.wayback,
        js=args.js,
        max_requests=args.max_requests,
    )

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(color(f"\nFull report written to {args.json}", "32"))

    return 0


if __name__ == "__main__":
    sys.exit(main())
