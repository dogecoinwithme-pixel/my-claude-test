#!/usr/bin/env python3
"""
recon.py - Authorized bug bounty recon + evidence-based vulnerability triage.

Usage:
    python3 recon.py https://example.com --yes
    python3 recon.py example.com --active --wayback --js --json report.json --yes
    python3 recon.py https://example.com --active \
        --cookie-a "session=aaa..." --cookie-b "session=bbb..." --json report.json --yes

ONLY run this against targets you are explicitly authorized to test
(your own systems, or assets inside an active bug bounty program's scope).
Unauthorized scanning may be illegal. You are responsible for staying in scope.

WHAT THIS TOOL IS
    Recon + evidence-based, confidence-scored vulnerability DETECTION:
    DNS, TLS, headers, cookies, sensitive-file disclosure (content-validated),
    secrets scanning, form/CSRF inventory, per-parameter reflection testing
    with baseline diffing, CORS misconfig, open redirect, blind SSRF/OOB
    (via a collaborator domain you own), SQLi/SSTI/command-injection/path-
    traversal indicators (single-shot, timing- or signature-based, not
    iterative extraction), GraphQL introspection, passive JWT structural
    inspection, and optional dual-session authenticated IDOR/BOLA candidate
    detection.

WHAT THIS TOOL IS DELIBERATELY NOT
    It does not attempt HTTP request smuggling or live OAuth-flow attacks.
    Smuggling exploits shared front-end/back-end connection reuse, so a
    "successful" test can desync and corrupt OTHER users' concurrent
    requests on the same infrastructure - damage to bystanders no target
    authorization covers. OAuth attacks require driving a real
    browser-redirect flow against the actual third-party identity provider
    (Google/Okta/etc.) using potentially real user tokens - that IdP is a
    separate, un-authorized party outside your target's scope. Both are
    excluded because the blast radius leaves the authorized target, not
    because they're hard to implement.

    It also does not turn a positive SQLi/traversal/command-injection signal
    into actual data extraction or command execution - that's a deliberate
    manual next step for the authorized tester using a dialect-aware tool
    (sqlmap, commix, etc.) under their own rate/scope control.

    Findings are candidates for manual triage, not confirmed vulnerabilities.
    Every finding carries a confidence score and evidence; treat anything
    below ~0.6 as "worth a look," not "worth reporting."

Dependencies: standard library only, plus `requests` (optional but recommended).
    pip install requests
"""

from __future__ import annotations

import argparse
import difflib
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
from html.parser import HTMLParser

try:
    import requests  # nicer HTTP; optional
    HAVE_REQUESTS = True
except ImportError:  # fall back to urllib
    HAVE_REQUESTS = False

USER_AGENT = "recon.py/2.0 (authorized-bug-bounty-research)"
TIMEOUT = 12
REQUEST_DELAY = 0.2  # seconds between requests - applies to every outbound request, no exceptions


# --------------------------------------------------------------------------
# Core plumbing: request budget, scope enforcement, structured findings
# --------------------------------------------------------------------------

class RequestBudget:
    """Caps total outbound requests for a run and paces them.

    Every single check in this file routes through .allow() before making a
    request - there is no separate "crawler" path with its own pacing, so
    rate control can't silently go inconsistent between modules.
    """

    def __init__(self, max_requests: int = 400, delay: float = REQUEST_DELAY):
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


def color(text: str, code: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


def banner(text: str) -> None:
    print("\n" + color(f"== {text} ==", "1;36"))


def finding(check: str, severity: str, confidence: float, evidence: str, note: str,
            tier: str = "CANDIDATE", **extra) -> dict:
    """Structured, evidence-based finding.

    severity: info/low/medium/high - how bad it would be if real.
    confidence: 0.0-1.0 - how sure the heuristic is.
    tier: INFO / CANDIDATE / VERIFIED - the epistemic status of the *method*,
        set explicitly per check rather than derived from confidence:
          INFO      - hardening/observational, not a vulnerability by itself
          CANDIDATE - a real signal that still needs manual confirmation
                      (this blind tool cannot prove exploitability or
                      ownership on its own for these classes)
          VERIFIED  - the check directly observed proof (evaluated
                      expression, exact metacharacter survival, matched
                      file content, expired cert, etc.) - still not the
                      same as a full PoC, but as conclusive as a blind
                      scan gets.
    """
    f = {
        "check": check, "severity": severity, "confidence": round(confidence, 2), "tier": tier,
        "evidence": evidence, "note": note,
    }
    f.update(extra)
    return f


def severity_for_confidence(confidence: float) -> str:
    if confidence >= 0.8:
        return "high"
    if confidence >= 0.5:
        return "medium"
    if confidence >= 0.25:
        return "low"
    return "info"


def print_finding(f: dict) -> None:
    sev_color = {"info": "36", "low": "33", "medium": "33;1", "high": "31;1"}.get(f["severity"], "0")
    tag = f["severity"].upper()
    tier = f.get("tier", "CANDIDATE")
    loc = f.get("url") or f.get("param") or f.get("cookie") or ""
    print(color(f"  [{tag} conf={f['confidence']} {tier}]", sev_color) + f" {f['check']} {loc} - {f['note']}")


def normalize_target(raw: str) -> tuple[str, str]:
    """Return (base_url, hostname) from user input in any common form.
    Host is lowercased so later scope comparisons aren't case-sensitive."""
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    host = (parsed.hostname or "").lower()
    base = f"{parsed.scheme}://{parsed.netloc}"
    return base, host


def same_host(url: str, host: str) -> bool:
    """Case-insensitive, port-agnostic host comparison. Using .netloc (which
    can include a port) against a bare hostname was a real bug: a redirect
    to the same host on a non-default port, e.g. https://example.com:8443/,
    would be misjudged as leaving scope. Port is intentionally ignored -
    scope is normally defined by hostname, not port."""
    return (urllib.parse.urlparse(url).hostname or "").lower() == host.lower()


def http_get(url: str, method: str = "GET", extra_headers: dict | None = None,
             budget: "RequestBudget | None" = None, allow_redirects: bool = False,
             json_body: dict | None = None):
    """Return (status, headers_dict, body_text). Never raises for HTTP errors.
    allow_redirects defaults to False - callers that need to follow redirects
    must go through fetch_in_scope() so redirects can't silently leave the
    authorized host."""
    if budget is not None and not budget.allow():
        return None, {}, ""
    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    if HAVE_REQUESTS:
        try:
            r = requests.request(
                method, url, headers=headers, timeout=TIMEOUT,
                allow_redirects=allow_redirects, verify=True,
                json=json_body if json_body is not None else None,
            )
            return r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.text
        except requests.RequestException:
            # NEVER put the exception text in the body slot: requests embeds the
            # full failed URL (including any injected marker/payload) in its
            # exception messages, which would make every marker-based check
            # ("is my token in the body?") false-positive on plain network errors.
            return None, {}, ""
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, headers=headers, method=method, data=data)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read(300_000).decode("utf-8", "replace")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, hdrs, body
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, ""
    except Exception:  # noqa: BLE001
        return None, {}, ""


def fetch_in_scope(url: str, host: str, budget: "RequestBudget", extra_headers: dict | None = None,
                    max_redirects: int = 5) -> tuple[int | None, dict, str, list]:
    """GET that follows redirects manually, refusing to leave the authorized host.

    Returns (status, headers, body, redirect_chain). redirect_chain entries are
    URLs the response tried to send us to; if the chain includes an off-host
    entry, that URL is the last one and the body/status reflect the last
    IN-SCOPE response actually fetched (the off-host hop is reported, not
    followed).
    """
    chain = []
    current = url
    for _ in range(max_redirects):
        status, headers, body = http_get(current, extra_headers=extra_headers, budget=budget, allow_redirects=False)
        if status in (301, 302, 303, 307, 308) and headers.get("location"):
            location = urllib.parse.urljoin(current, headers["location"])
            chain.append(location)
            if not same_host(location, host):
                return status, headers, body, chain  # stop - do not leave scope
            current = location
            continue
        return status, headers, body, chain
    return status, headers, body, chain


# --------------------------------------------------------------------------
# DNS / TLS
# --------------------------------------------------------------------------

def resolve_dns(host: str) -> dict:
    out = {"host": host, "addresses": [], "error": None}
    try:
        infos = socket.getaddrinfo(host, None)
        out["addresses"] = sorted({i[4][0] for i in infos})
    except socket.gaierror as e:
        out["error"] = str(e)
    return out


WEAK_TLS_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


def get_tls_info(host: str, port: int = 443) -> dict:
    """Certificate + protocol version checks. Not a full cipher-suite/config
    audit (that needs testssl.sh / sslscan / sslyze); this covers the
    high-signal basics: expiry, weak protocol negotiated, obvious self-signed."""
    info = {"error": None, "findings": []}
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

                if info["protocol"] in WEAK_TLS_PROTOCOLS:
                    info["findings"].append(finding(
                        "tls-weak-protocol", "medium", 0.9, info["protocol"],
                        f"negotiated {info['protocol']} - deprecated protocol, should be disabled server-side",
                        tier="VERIFIED",
                    ))
                if info["issuer"] == info["subject"]:
                    info["findings"].append(finding(
                        "tls-self-signed", "low", 0.5, str(info["issuer"]),
                        "issuer == subject, looks self-signed (or this is an internal CA) - verify manually",
                        tier="CANDIDATE",
                    ))
                try:
                    expires = datetime.strptime(info["not_after"], "%b %d %H:%M:%S %Y %Z")
                    days_left = (expires - datetime.utcnow()).days
                    if days_left < 0:
                        info["findings"].append(finding("tls-expired", "high", 0.95, info["not_after"], "certificate is expired", tier="VERIFIED"))
                    elif days_left < 30:
                        info["findings"].append(finding("tls-expiring-soon", "low", 0.8, info["not_after"], f"certificate expires in {days_left} days", tier="INFO"))
                except (ValueError, TypeError):
                    pass
    except Exception as e:  # noqa: BLE001
        info["error"] = str(e)
    return info


# --------------------------------------------------------------------------
# Headers - informational only, never labeled as vulnerabilities on their own
# --------------------------------------------------------------------------

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS not set",
    "content-security-policy": "CSP not set",
    "x-frame-options": "X-Frame-Options not set (CSP frame-ancestors may cover this instead)",
    "x-content-type-options": "X-Content-Type-Options not set",
    "referrer-policy": "Referrer-Policy not set",
    "permissions-policy": "Permissions-Policy not set",
}

TECH_FINGERPRINTS = {
    "server": "Web server", "x-powered-by": "Backend framework/runtime",
    "x-aspnet-version": "ASP.NET", "x-generator": "CMS/generator",
    "via": "Proxy/CDN", "cf-ray": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront", "x-served-by": "Fastly/Varnish",
}


def analyze_headers(headers: dict) -> dict:
    """Missing headers are informational context, not findings - a missing
    CSP on a static marketing page and a missing CSP on an app handling
    session tokens are not the same severity, and this function can't tell
    them apart, so it doesn't pretend to."""
    missing = [note for h, note in SECURITY_HEADERS.items() if h not in headers]
    tech = {label: headers[h] for h, label in TECH_FINGERPRINTS.items() if h in headers}
    return {"missing_security_headers_info": missing, "technologies": tech}


# --------------------------------------------------------------------------
# Cookies - real multi-Set-Cookie parsing, per-attribute checks
# --------------------------------------------------------------------------

def _raw_set_cookie_headers(url: str, budget: "RequestBudget") -> list:
    if not budget.allow():
        return []
    headers = {"User-Agent": USER_AGENT}
    try:
        if HAVE_REQUESTS:
            r = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=False, verify=True)
            raw_headers = r.raw.headers
            if hasattr(raw_headers, "get_all"):
                return raw_headers.get_all("Set-Cookie") or []
            if hasattr(raw_headers, "getlist"):
                return raw_headers.getlist("Set-Cookie") or []
            single = r.headers.get("set-cookie")
            return [single] if single else []
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.headers.get_all("Set-Cookie") or []
    except Exception:  # noqa: BLE001
        return []


def analyze_cookies(base: str, budget: "RequestBudget") -> list:
    """Parses every Set-Cookie header individually (not a merged string), so
    a cookie literally named 'secure_token' can't accidentally satisfy a
    substring check for the Secure flag."""
    findings = []
    is_https = base.startswith("https://")
    for raw in _raw_set_cookie_headers(base, budget):
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0].strip()
        attr_names = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
        samesite = next((p.split("=", 1)[1] for p in parts[1:] if p.lower().startswith("samesite=")), None)

        issues = []
        if is_https and "secure" not in attr_names:
            issues.append("missing Secure flag on an HTTPS-served cookie")
        if "httponly" not in attr_names:
            issues.append("missing HttpOnly flag")
        if not samesite:
            issues.append("missing SameSite attribute")
        elif samesite.lower() == "none" and "secure" not in attr_names:
            issues.append("SameSite=None without Secure flag (rejected by modern browsers, but misconfigured)")

        if issues:
            # These are hardening gaps, not proven vulnerabilities on their own -
            # e.g. missing HttpOnly only matters in combination with an actual
            # XSS elsewhere. Tier stays INFO regardless of severity label.
            severity = "medium" if "httponly" not in attr_names else "low"
            findings.append(finding(
                "cookie-flags", severity, 1.0, raw, "; ".join(issues), tier="INFO", cookie=name,
            ))
    return findings


# --------------------------------------------------------------------------
# Sensitive path / file disclosure - content-validated, not just HTTP 200
# --------------------------------------------------------------------------

# Paths that are only informational inventory even when reachable.
INFO_PATHS = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/security.txt", "/humans.txt"]

# Paths where a 200 needs content validation before it means anything.
SENSITIVE_PATH_VALIDATORS = {
    "/.env": lambda body: bool(re.search(r"^[A-Z0-9_]{2,}\s*=\s*.+$", body, re.M)),
    "/.git/config": lambda body: "[core]" in body or "repositoryformatversion" in body,
    "/.git/HEAD": lambda body: body.strip().startswith("ref:"),
    "/wp-config.php.bak": lambda body: "DB_PASSWORD" in body or "define(" in body,
    "/config.json": lambda body: bool(re.search(r'"(password|secret|api[_-]?key)"\s*:', body, re.I)),
    "/.aws/credentials": lambda body: "aws_access_key_id" in body.lower(),
}


def check_paths(base: str, budget: "RequestBudget") -> dict:
    inventory = []
    findings = []
    for path in INFO_PATHS:
        status, headers, body = http_get(base + path, budget=budget)
        if status and status < 400:
            inventory.append({"path": path, "status": status, "content_type": headers.get("content-type", "")})

    for path, validator in SENSITIVE_PATH_VALIDATORS.items():
        status, headers, body = http_get(base + path, budget=budget)
        if not status or status >= 400 or not body:
            continue
        if validator(body):
            findings.append(finding(
                "sensitive-file-disclosure", "high", 0.9, body[:200].replace("\n", " "),
                f"{path} returned 200 AND content matches expected sensitive-file structure",
                tier="VERIFIED", url=base + path,
            ))
        else:
            inventory.append({"path": path, "status": status, "note": "reachable but content did not match expected structure (likely a custom 200/soft-404 page) - low signal"})
    return {"inventory": inventory, "findings": findings}


# --------------------------------------------------------------------------
# Secrets scanning over HTML/JS bodies
# --------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.95),
    ("aws_secret_key_assignment", re.compile(r"aws_secret_access_key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]", re.I), 0.9),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 0.9),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"), 0.9),
    ("stripe_live_key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), 0.95),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), 0.98),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), 0.5),
    ("generic_api_key_assignment", re.compile(r"(?:api[_-]?key|secret|token)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,64}['\"]", re.I), 0.35),
]

# Patterns that LOOK like secrets but are meant to be public - excluded before
# they can generate noise (e.g. Stripe publishable keys are, by design, safe
# to ship in client-side JS; only sk_live_/rk_live_ secret keys matter).
PUBLIC_KEY_EXCLUSIONS = [
    re.compile(r"\bpk_(live|test)_[0-9a-zA-Z]{16,}\b"),   # Stripe PUBLISHABLE key
    re.compile(r"\bG-[A-Z0-9]{6,10}\b"),                   # GA4 measurement ID
    re.compile(r"\bUA-\d{4,10}-\d{1,2}\b"),                # Universal Analytics ID
    re.compile(r"\b6L[0-9A-Za-z_-]{38}\b"),                # reCAPTCHA site key
]


def scan_secrets(label: str, body: str) -> list:
    findings = []
    if not body:
        return findings
    for name, pattern, confidence in SECRET_PATTERNS:
        for m in pattern.finditer(body):
            matched_text = m.group(0)
            if any(excl.search(matched_text) for excl in PUBLIC_KEY_EXCLUSIONS):
                continue
            snippet = body[max(0, m.start() - 20):m.end() + 10]
            findings.append(finding(
                "secret-exposure", severity_for_confidence(confidence), confidence,
                snippet.replace("\n", " "), f"pattern '{name}' matched in {label}",
                tier="VERIFIED" if confidence >= 0.8 else "CANDIDATE", url=label,
            ))
    return findings


# --------------------------------------------------------------------------
# Public-suffix-aware apex domain extraction
# --------------------------------------------------------------------------

# A naive "last two labels" heuristic is WRONG for multi-label public
# suffixes: 'www.example.co.uk'.split('.')[-2:] gives 'co.uk', which would
# scope subdomain/wayback enumeration to the ENTIRE .co.uk TLD - a
# different organization's domains, not the target's. This is a curated
# subset of the most common such suffixes as a fallback; tldextract (if
# installed) uses the real, actively-maintained public suffix list and is
# always preferred when available.
_COMMON_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
    "co.jp", "co.kr", "co.nz", "co.za", "co.in", "co.il", "co.id",
    "com.au", "net.au", "org.au", "com.br", "com.cn", "com.mx", "com.sg",
    "com.hk", "com.tw", "com.tr", "com.ar", "com.co", "com.pe",
    "github.io", "gitlab.io", "herokuapp.com", "netlify.app", "vercel.app",
    "web.app", "pages.dev", "s3.amazonaws.com", "cloudfront.net", "azurewebsites.net",
    "firebaseapp.com", "appspot.com",
}


def get_apex_domain(host: str) -> tuple[str, str]:
    """Returns (apex_domain, method). method is 'tldextract' when the real
    public suffix list was available, 'ip-literal' when the host is an IP
    address (domain-suffix splitting is meaningless there - naively taking
    the last two dot-separated labels of 127.0.0.1 would produce '0.1'),
    or 'heuristic' when falling back to the curated set above + naive
    last-two-labels - callers should surface that distinction rather than
    silently trusting the heuristic."""
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return host, "ip-literal"
    except ValueError:
        pass
    try:
        import tldextract  # optional; not in stdlib
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}", "tldextract"
    except ImportError:
        pass
    labels = host.lower().split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _COMMON_MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:]), "heuristic"
    if len(labels) >= 2:
        return ".".join(labels[-2:]), "heuristic"
    return host, "heuristic"


# --------------------------------------------------------------------------
# Passive subdomains / wayback
# --------------------------------------------------------------------------

def crtsh_subdomains(domain: str, budget: "RequestBudget") -> dict:
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


def get_wayback_urls(domain: str, budget: "RequestBudget", limit: int = 800) -> dict:
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


# --------------------------------------------------------------------------
# Crawler: same-origin pages, JS files, forms, endpoint extraction
# --------------------------------------------------------------------------

def extract_links(base: str, host: str, body: str) -> list:
    hrefs = re.findall(r'<a[^>]+href=["\']([^"\'#][^"\']*)["\']', body or "", re.I)
    out = []
    for h in hrefs:
        u = urllib.parse.urljoin(base + "/", h)
        if same_host(u, host) and u.startswith(("http://", "https://")):
            out.append(u.split("#")[0])
    return sorted(set(out))


def extract_forms(body: str) -> list:
    forms = []
    for form_match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", body or "", re.I | re.S):
        attrs, inner = form_match.group(1), form_match.group(2)
        action = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
        method = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
        inputs = re.findall(r'<input\b([^>]*)>', inner, re.I)
        input_names = []
        has_csrf = False
        for inp in inputs:
            name_m = re.search(r'name=["\']([^"\']*)["\']', inp, re.I)
            if name_m:
                input_names.append(name_m.group(1))
                if re.search(r"csrf|xsrf|authenticity_token|_token", name_m.group(1), re.I):
                    has_csrf = True
        method_val = (method.group(1) if method else "GET").upper()
        forms.append({
            "action": action.group(1) if action else "",
            "method": method_val,
            "inputs": input_names,
            "has_csrf_token_field": has_csrf,
        })
    return forms


def extract_js_endpoints(base: str, host: str, body: str, budget: "RequestBudget", max_files: int = 10) -> dict:
    out = {"js_files": [], "endpoints": [], "secrets": []}
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body or "", re.I)
    checked = 0
    for src in script_srcs:
        if checked >= max_files:
            break
        js_url = urllib.parse.urljoin(base + "/", src)
        if not same_host(js_url, host):
            continue  # third-party JS (analytics/CDNs) - not this target's attack surface
        status, _, js_body = http_get(js_url, budget=budget)
        checked += 1
        if status and status < 400 and js_body:
            out["js_files"].append(js_url)
            for m in re.findall(r'["\'](/[a-zA-Z0-9_\-/{}.]{2,80}?)["\']', js_body):
                if any(m.lower().endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".svg", ".css", ".woff", ".woff2")):
                    continue
                out["endpoints"].add(m) if isinstance(out["endpoints"], set) else out["endpoints"].append(m)
            out["secrets"].extend(scan_secrets(js_url, js_body))
    out["endpoints"] = sorted(set(out["endpoints"]))[:300]
    return out


def crawl(base: str, host: str, homepage_body: str, budget: "RequestBudget", max_pages: int = 8) -> dict:
    """Shallow, scope-bounded crawl of same-origin links from the homepage.
    Collects forms and page URLs for downstream parameter testing."""
    result = {"pages": [], "forms": [], "urls_with_params": []}
    visited = {base + "/"}
    queue = extract_links(base, host, homepage_body)[:max_pages]

    def record(page_url: str, page_body: str):
        forms = extract_forms(page_body)
        for f in forms:
            f["page"] = page_url
        result["forms"].extend(forms)
        if urllib.parse.urlparse(page_url).query:
            result["urls_with_params"].append(page_url)

    if urllib.parse.urlparse(base).query or homepage_body:
        record(base, homepage_body)

    for url in queue:
        if url in visited:
            continue
        visited.add(url)
        status, _, body, _ = fetch_in_scope(url, host, budget)
        if status and status < 400 and body:
            result["pages"].append(url)
            record(url, body)

    return result


# --------------------------------------------------------------------------
# Active checks: reflection (per-parameter, baseline-diffed), CORS, redirect
# --------------------------------------------------------------------------

INJECTABLE_PARAMS_DEFAULT = ["q", "search", "query", "name", "id", "keyword", "s"]
REDIRECT_PARAMS = ["redirect", "url", "next", "dest", "destination", "continue", "return", "returnUrl", "r"]


def _rand_token(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


REFLECTION_METACHARS = "\"'><"  # the actual breakout characters we test survival of, not just an alnum marker


class _ReflectionContextParser(HTMLParser):
    """Walks the response HTML once (real parser, not sliding-window regex)
    and records the DOM location(s) our marker landed in: a tag attribute
    value, raw text, <script>/<style> content, or a comment. Best-effort -
    stdlib html.parser can diverge from a browser's HTML5 parser on
    malformed markup, so this narrows down context, it doesn't replace
    manual confirmation with a real browser."""

    def __init__(self, marker: str):
        super().__init__(convert_charrefs=True)
        self.marker = marker
        self.contexts: list = []
        self._in_script = False
        self._in_style = False

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        if t == "script":
            self._in_script = True
        elif t == "style":
            self._in_style = True
        for name, value in attrs:
            if value and self.marker in value:
                self.contexts.append(("html-attribute", f"{tag}[{name}]"))

    def handle_endtag(self, tag):
        t = tag.lower()
        if t == "script":
            self._in_script = False
        elif t == "style":
            self._in_style = False

    def handle_data(self, data):
        if self.marker not in data:
            return
        if self._in_script:
            self.contexts.append(("script-block", "script"))
        elif self._in_style:
            self.contexts.append(("style-block", "style"))
        else:
            self.contexts.append(("html-text", "text"))

    def handle_comment(self, data):
        if self.marker in data:
            self.contexts.append(("html-comment", "comment"))


def _survival_state(body: str, marker: str) -> str:
    """Checks whether the EXACT metacharacters we injected (\"'><) survived
    unescaped immediately before the marker - direct proof of breakout
    capability, not an inference from unrelated markup elsewhere on the
    page. This is the actual fix for 'reflection without executable-context
    proof': the payload now carries real metacharacters, and we check
    whether THOSE specific characters came back raw."""
    idx = body.find(marker)
    if idx == -1:
        return "not-found"
    before = body[max(0, idx - len(REFLECTION_METACHARS)):idx]
    if before.endswith(REFLECTION_METACHARS):
        return "unescaped"
    encoded_forms = ["&quot;&#39;&gt;&lt;", "&#34;&#39;&gt;&lt;", "%22%27%3E%3C"]
    if any(before.endswith(ef) for ef in encoded_forms):
        return "encoded"
    if any(c in before for c in REFLECTION_METACHARS):
        return "partial"  # some but not all metacharacters survived - a filter is doing SOMETHING, may be bypassable
    return "stripped"


def _classify_reflection(body: str, marker: str) -> tuple[str, str]:
    """Returns (dom_context, survival_state)."""
    survival = _survival_state(body, marker)
    parser = _ReflectionContextParser(marker)
    try:
        parser.feed(body)
    except Exception:  # noqa: BLE001
        pass
    context = parser.contexts[0][0] if parser.contexts else "unknown"
    return context, survival


def _reflection_probe() -> tuple[str, str]:
    marker = f"rXf{_rand_token(6)}"
    payload = f"{REFLECTION_METACHARS}{marker}"
    return marker, payload


def _reflection_finding(param: str, url: str, status: int | None, body: str, marker: str) -> dict | None:
    """Shared scoring logic for both the synthetic and discovered-URL
    reflection tests, so the tier/confidence policy lives in exactly one
    place. Only 'unescaped' (proven metachar survival) reaches VERIFIED;
    everything else is explicitly weaker signal."""
    if not body or marker not in body:
        return None
    context, survival = _classify_reflection(body, marker)
    idx = body.find(marker)
    snippet = body[max(0, idx - 40):idx + 40].replace("\n", " ")

    if survival == "unescaped":
        confidence, severity, tier = 0.85, "high", "VERIFIED"
        context_note = context if context != "unknown" else "a context the parser couldn't cleanly resolve (often because the injected markup itself broke normal tag structure - consistent with a real breakout)"
        note = (f"param='{param}' reflected with the exact injected metacharacters (\"'><) unescaped immediately "
                f"before it, in {context_note} - real breakout proof; a WAF/CSP could still block actual exploitation, confirm manually")
    elif survival == "partial":
        confidence, severity, tier = 0.5, "medium", "CANDIDATE"
        note = f"param='{param}' reflected in {context} with SOME injected metacharacters surviving unescaped - partial filter, worth manual bypass attempts"
    elif survival == "encoded":
        confidence, severity, tier = 0.15, "info", "INFO"
        note = f"param='{param}' reflected in {context} but metacharacters were HTML/URL-encoded - looks properly escaped"
    else:  # stripped
        confidence, severity, tier = 0.2, "info", "INFO"
        note = f"param='{param}' marker text reflected in {context} but injected metacharacters were stripped - low exploitability signal"

    return finding("reflected-input", severity, confidence, snippet, note, tier=tier, param=param, url=url, status=status)


def test_reflection_isolated(base: str, param_names: list, budget: "RequestBudget") -> list:
    """Synthetic single-param tests against the bare origin, for common param
    names that may not appear in any crawled URL (e.g. search boxes that
    submit via JS)."""
    findings = []
    for param in param_names:
        marker, payload = _reflection_probe()
        _, _, base_body = http_get(f"{base}/?{param}=baseline{_rand_token(4)}", budget=budget)
        status, _, body = http_get(f"{base}/?{param}={urllib.parse.quote(payload)}", budget=budget)
        if base_body and marker in base_body:
            continue  # reflected even in an unrelated baseline - not caused by our input
        f = _reflection_finding(param, f"{base}/?{param}=...", status, body, marker)
        if f:
            findings.append(f)
    return findings


def _param_variants(url: str, replacement: str) -> list:
    """For a URL with existing query params, yield (param_name, variant_url)
    pairs where exactly ONE parameter is replaced and all others keep their
    original values - this is the fix for the all-params-get-the-same-value
    bug: ?id=X&name=alice&sort=date now tests id alone, then name alone,
    then sort alone, instead of replacing all three at once."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    out = []
    for i, (k, _v) in enumerate(qs):
        new_qs = list(qs)
        new_qs[i] = (k, replacement)
        variant = parsed._replace(query=urllib.parse.urlencode(new_qs)).geturl()
        out.append((k, variant))
    return out


def test_reflection_on_urls(urls: list, host: str, budget: "RequestBudget", max_urls: int = 15, max_params: int = 6) -> list:
    """Real per-parameter isolated testing on actually-discovered URLs with
    multiple query params, against each URL's own unmodified baseline."""
    findings = []
    tested_urls = 0
    for url in urls:
        if tested_urls >= max_urls:
            break
        if not same_host(url, host):
            continue
        variants = _param_variants(url, "placeholder")
        if not variants:
            continue
        tested_urls += 1
        _, _, baseline_body = http_get(url, budget=budget)
        for param, _variant in variants[:max_params]:
            marker, payload = _reflection_probe()
            variant_url = next((v for p2, v in _param_variants(url, payload) if p2 == param), None)
            if not variant_url:
                continue
            status, _, body = http_get(variant_url, budget=budget)
            if baseline_body and marker in baseline_body:
                continue
            f = _reflection_finding(param, url, status, body, marker)
            if f:
                findings.append(f)
    return findings


def check_open_redirect(base: str, budget: "RequestBudget") -> list:
    findings = []
    canary = "https://example.com/recon-open-redirect-check"
    for param in REDIRECT_PARAMS:
        url = f"{base}/?{param}={urllib.parse.quote(canary, safe='')}"
        status, headers, _ = http_get(url, budget=budget, allow_redirects=False)
        if status in (301, 302, 303, 307, 308):
            location = headers.get("location", "")
            if location.startswith(canary) or "example.com" in location:
                findings.append(finding(
                    "open-redirect", "medium", 0.8, f"{status} -> {location}",
                    f"param='{param}' redirects to attacker-supplied external URL - directly observed, about as conclusive as a blind check gets",
                    tier="VERIFIED", param=param, url=url,
                ))
    return findings


def check_cors_misconfig(base: str, budget: "RequestBudget") -> list:
    """Configuration finding only - this cannot verify whether the reflected
    origin actually gets to read authenticated/sensitive data, since that
    requires a real cross-origin browser context with credentials. Treat as
    'worth checking with a browser PoC', not confirmed data exposure."""
    findings = []
    probes = ["https://recon-cors-check.invalid", "null"]
    for probe_origin in probes:
        status, headers, _ = http_get(base, extra_headers={"Origin": probe_origin}, budget=budget)
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
        if acao == probe_origin and acac == "true":
            findings.append(finding(
                "cors-misconfig", "high", 0.85, f"Origin: {probe_origin} -> ACAO: {acao}, ACAC: {acac}",
                "reflects arbitrary Origin AND allows credentials - confirm with a real cross-origin fetch() PoC before reporting as data exposure",
                tier="CANDIDATE",
            ))
        elif acao == "*" and acac == "true":
            findings.append(finding(
                "cors-misconfig", "info", 0.3, f"ACAO: *, ACAC: {acac}",
                "ACAO=* with ACAC=true is invalid per spec and browsers reject it - usually not exploitable, informational only",
                tier="INFO",
            ))
    return findings


# --------------------------------------------------------------------------
# CSRF indicator (heuristic, not proof - SameSite/anti-CSRF headers can
# protect a form with no visible token field)
# --------------------------------------------------------------------------

def check_csrf_indicators(forms: list) -> list:
    """Absence of a visible token field is weak signal by design: modern
    frameworks very commonly protect state-changing requests via
    SameSite=Strict/Lax cookies or a custom header token set by JS, neither
    of which appears anywhere in the HTML this parses. Stays INFO tier and
    low confidence so it doesn't read as a confirmed gap."""
    findings = []
    for f in forms:
        if f["method"] in ("POST", "PUT", "PATCH", "DELETE") and not f["has_csrf_token_field"]:
            findings.append(finding(
                "csrf-indicator", "low", 0.3, json.dumps(f),
                f"state-changing form (method={f['method']}) on {f.get('page','?')} has no visible CSRF token input - "
                "very common with SameSite-cookie or header-token protection patterns invisible to HTML parsing; "
                "weak signal on its own, verify manually",
                tier="INFO", url=f.get("page", ""),
            ))
    return findings


# --------------------------------------------------------------------------
# Injection-class DETECTION (single-shot, non-destructive signals only).
#
# These are indicators, not exploitation: SQLi/command-injection detection
# uses one timing probe per dialect/param (not iterative extraction), path
# traversal detection is a single canary request per OS pattern (not
# recursive filesystem walking), and SSTI detection evaluates one safe
# arithmetic expression. None of these dump data, execute attacker-chosen
# commands, or read arbitrary files beyond the one fixed canary path used to
# prove the class exists. Turning a positive signal into confirmed
# extraction is a deliberate manual next step for the authorized tester,
# using a dialect-aware tool (sqlmap, commix, etc.) under their own
# rate/scope control - this script does not auto-escalate into that.
# --------------------------------------------------------------------------

SQL_ERROR_SIGNATURES = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysqli?_", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"pg_query\(\)|postgresql.*error", re.I),
    re.compile(r"ORA-\d{5}"),
    re.compile(r"sqlite3?\.OperationalError|SQLITE_ERROR", re.I),
    re.compile(r"System\.Data\.SqlClient\.SqlException", re.I),
]

SQL_TIME_PAYLOADS = {
    "mysql/generic": "' OR SLEEP(5)-- -",
    "postgres": "' OR pg_sleep(5)-- -",
    "mssql": "'; WAITFOR DELAY '0:0:5'--",
}

SSTI_PAYLOADS = [("{{7*7}}", "49"), ("${7*7}", "49"), ("#{7*7}", "49"), ("<%= 7*7 %>", "49")]

CMDI_TIME_PAYLOADS = ["; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)"]

TRAVERSAL_PAYLOADS = {
    "../" * 6 + "etc/passwd": re.compile(r"root:.*:0:0:"),
    "..\\" * 6 + "windows\\win.ini": re.compile(r"\[fonts\]", re.I),
}

TIMING_THRESHOLD = 4.0  # minimum absolute seconds over baseline before a delay is even considered


def _timed_get(url: str, budget: "RequestBudget") -> tuple[int | None, str, float]:
    t0 = time.monotonic()
    status, _, body = http_get(url, budget=budget)
    return status, body, time.monotonic() - t0


def _baseline_timing(url: str, budget: "RequestBudget", samples: int = 2) -> tuple[float, float, str]:
    """Multiple baseline samples so a single slow request can't be mistaken
    for injection-induced delay - returns (mean, stdev, last_body)."""
    elapseds, last_body = [], ""
    for _ in range(samples):
        _, body, e = _timed_get(url, budget)
        elapseds.append(e)
        last_body = body
    mean = sum(elapseds) / len(elapseds)
    stdev = (sum((e - mean) ** 2 for e in elapseds) / len(elapseds)) ** 0.5 if len(elapseds) > 1 else 0.0
    return mean, stdev, last_body


def _confirmed_timing_signal(test_url: str, budget: "RequestBudget", baseline_mean: float, baseline_stdev: float,
                              threshold: float = TIMING_THRESHOLD) -> dict | None:
    """Requires the delay to clear BOTH an absolute threshold and a
    variance-aware margin (3 standard deviations over the observed
    baseline), then requires it to reproduce on a second, independent
    request before calling it a signal at all. A single-sample timing
    check is exactly what generates false positives from ordinary network
    jitter, GC pauses, or a momentarily busy server - this doesn't
    eliminate that risk, but it substantially narrows it."""
    margin = max(threshold, 3 * baseline_stdev)
    status1, _, elapsed1 = _timed_get(test_url, budget)
    if status1 is None or (elapsed1 - baseline_mean) < margin:
        return None
    status2, _, elapsed2 = _timed_get(test_url, budget)
    if status2 is None or (elapsed2 - baseline_mean) < margin * 0.7:
        return None  # didn't reproduce - treat as a one-off blip, not a real signal
    return {
        "baseline_mean_s": round(baseline_mean, 2), "baseline_stdev_s": round(baseline_stdev, 3),
        "trial1_s": round(elapsed1, 2), "trial2_s": round(elapsed2, 2), "margin_required_s": round(margin, 2),
    }


def check_sqli_indicators(base: str, param_names: list, budget: "RequestBudget") -> list:
    findings = []
    for param in param_names:
        baseline_mean, baseline_stdev, baseline_body = _baseline_timing(f"{base}/?{param}=1", budget)

        _, _, err_body = http_get(f"{base}/?{param}={urllib.parse.quote(chr(39))}", budget=budget)
        for sig in SQL_ERROR_SIGNATURES:
            if err_body and sig.search(err_body) and not (baseline_body and sig.search(baseline_body)):
                findings.append(finding(
                    "sqli-indicator", "high", 0.75, sig.pattern,
                    f"param='{param}' single-quote probe surfaced a SQL error signature absent from baseline - "
                    "error-based SQLi indicator, confirm manually before further testing",
                    tier="CANDIDATE", param=param,
                ))
                break

        for dialect, payload in SQL_TIME_PAYLOADS.items():
            evidence = _confirmed_timing_signal(f"{base}/?{param}={urllib.parse.quote(payload)}", budget, baseline_mean, baseline_stdev)
            if evidence:
                findings.append(finding(
                    "sqli-indicator", "high", 0.65, json.dumps(evidence),
                    f"param='{param}' time-based probe ({dialect}) reproduced a delay of {evidence['margin_required_s']}s+ over a "
                    f"{2}-sample baseline (mean={evidence['baseline_mean_s']}s, stdev={evidence['baseline_stdev_s']}s) "
                    "on two independent trials - blind SQLi indicator",
                    tier="CANDIDATE", param=param,
                ))
                break
    return findings


def check_ssti_indicators(base: str, param_names: list, budget: "RequestBudget") -> list:
    findings = []
    for param in param_names:
        for payload, expected in SSTI_PAYLOADS:
            status, _, body = http_get(f"{base}/?{param}={urllib.parse.quote(payload)}", budget=budget)
            if body and expected in body and payload not in body:
                findings.append(finding(
                    "ssti-indicator", "high", 0.75, f"payload={payload} -> response contains '{expected}'",
                    f"param='{param}' template expression was evaluated server-side rather than reflected literally - "
                    "direct proof of template evaluation, about as conclusive as a blind scan gets; confirm impact manually",
                    tier="VERIFIED", param=param,
                ))
                break
    return findings


def check_command_injection_indicators(base: str, param_names: list, budget: "RequestBudget") -> list:
    findings = []
    for param in param_names:
        baseline_mean, baseline_stdev, _ = _baseline_timing(f"{base}/?{param}=1", budget)
        for payload in CMDI_TIME_PAYLOADS:
            evidence = _confirmed_timing_signal(f"{base}/?{param}={urllib.parse.quote(payload)}", budget, baseline_mean, baseline_stdev)
            if evidence:
                findings.append(finding(
                    "command-injection-indicator", "high", 0.6, json.dumps(evidence),
                    f"param='{param}' shell-metacharacter timing probe ({payload!r}) reproduced a delay over baseline "
                    "on two independent trials - blind OS command injection indicator",
                    tier="CANDIDATE", param=param,
                ))
                break
    return findings


def check_path_traversal_indicators(base: str, budget: "RequestBudget") -> list:
    findings = []
    for suffix, signature in TRAVERSAL_PAYLOADS.items():
        url = f"{base}/{suffix}"
        status, _, body = http_get(url, budget=budget)
        if status == 200 and body and signature.search(body):
            findings.append(finding(
                "path-traversal-indicator", "high", 0.75, body[:150].replace("\n", " "),
                "traversal payload returned a recognizable system-file signature - confirm manually, "
                "do not pull further files with this tool",
                tier="VERIFIED", url=url,
            ))
    return findings


GRAPHQL_INTROSPECTION_QUERY = {"query": "{__schema{queryType{name}mutationType{name}types{name kind}}}"}
GRAPHQL_CANDIDATE_PATHS = ["/graphql", "/api/graphql", "/graphql/console", "/v1/graphql"]
GRAPHQL_SENSITIVE_KEYWORDS = ("password", "secret", "ssn", "creditcard", "credit_card", "apikey", "api_key", "privatekey")


def check_graphql_introspection(base: str, budget: "RequestBudget") -> list:
    """Read-only: sends the standard introspection query and checks whether
    the schema is exposed. Introspection being enabled is extremely common
    and often deliberate (many public APIs ship it on purpose), so on its
    own this is INFO, not a vulnerability - it only escalates to CANDIDATE
    if the returned type/field names themselves look sensitive. Does not
    attempt authorization bypass on resolvers - that needs field-by-field
    manual review of the schema."""
    findings = []
    for path in GRAPHQL_CANDIDATE_PATHS:
        status, headers, body = http_get(
            base + path, method="POST", budget=budget,
            extra_headers={"Content-Type": "application/json"}, json_body=GRAPHQL_INTROSPECTION_QUERY,
        )
        if status == 200 and body and '"__schema"' in body and '"types"' in body:
            hits = sorted({kw for kw in GRAPHQL_SENSITIVE_KEYWORDS if kw in body.lower()})
            if hits:
                findings.append(finding(
                    "graphql-introspection-enabled", "medium", 0.5, f"sensitive-looking names in schema: {hits}",
                    f"{path} exposes its schema via introspection AND contains sensitive-looking type/field names "
                    f"({', '.join(hits)}) - review those specifically for unauthenticated access",
                    tier="CANDIDATE", url=base + path,
                ))
            else:
                findings.append(finding(
                    "graphql-introspection-enabled", "info", 0.3, body[:150].replace("\n", " "),
                    f"{path} accepted a standard introspection query - common and often intentional on public APIs; "
                    "review the schema manually if this endpoint is expected to be private",
                    tier="INFO", url=base + path,
                ))
    return findings


def _b64url_decode(segment: str) -> bytes:
    import base64
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def inspect_jwts(label: str, body: str) -> list:
    """Passive: decodes any JWT-shaped token found in a response body and
    flags structurally risky claims as SEPARATE findings, each scored on its
    own merit rather than bundled into one blanket 'jwt-structural-risk'.
    Does not forge or resend tokens - that would need to know which
    endpoint actually treats the token as an authorization decision, which
    a blind scan can't determine safely."""
    findings = []
    if not body:
        return findings
    for m in re.finditer(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", body):
        token = m.group(0)
        try:
            header = json.loads(_b64url_decode(token.split(".")[0]))
            payload = json.loads(_b64url_decode(token.split(".")[1]))
        except Exception:  # noqa: BLE001
            continue

        if str(header.get("alg", "")).lower() == "none":
            findings.append(finding(
                "jwt-alg-none", "high", 0.6, f"header={header}",
                "observed token's header has alg='none' - if the server accepts this unmodified it's a full auth "
                "bypass; confirm by resending a copy with the signature stripped, using YOUR OWN session token",
                tier="CANDIDATE", url=label,
            ))
        if "exp" not in payload:
            findings.append(finding(
                "jwt-no-exp", "info", 0.2, f"payload_keys={list(payload.keys())}",
                "token has no 'exp' claim - may be a deliberately long-lived non-session token (e.g. an API key "
                "formatted as a JWT); only relevant if this specific token is actually used for session auth",
                tier="INFO", url=label,
            ))
        if header.get("alg") in ("HS256", "HS384", "HS512") and any(
            k in str(payload).lower() for k in ("admin", "role", "is_admin", "scope")
        ):
            findings.append(finding(
                "jwt-symmetric-alg-privilege-claims", "info", 0.2,
                f"alg={header.get('alg')} payload_keys={list(payload.keys())}",
                "symmetric alg (HS*) token carries privilege-looking claims - worth an OFFLINE weak-secret check "
                "(e.g. hashcat against a wordlist) using your own captured token; not attempted here",
                tier="INFO", url=label,
            ))
    return findings


# --------------------------------------------------------------------------
# OOB / blind SSRF via a researcher-owned collaborator domain
# --------------------------------------------------------------------------

def check_oob_collaborator(base: str, collaborator_domain: str, budget: "RequestBudget") -> list:
    """Injects unique subdomains of a *researcher-owned* OOB listener into
    common SSRF-prone parameters/headers. Requires --collaborator-domain
    pointed at infrastructure you control (e.g. app.interactsh.com) - this
    tool never talks to a bundled third-party listener."""
    injected = []
    ssrf_params = ["url", "uri", "path", "dest", "redirect", "callback", "webhook", "feed", "src", "target"]
    for param in ssrf_params:
        token = _rand_token(10)
        canary_url = f"http://{token}.{collaborator_domain}/"
        http_get(f"{base}/?{param}={urllib.parse.quote(canary_url, safe='')}", budget=budget)
        injected.append({"vector": f"param:{param}", "token": token, "canary": canary_url})

    header_token = _rand_token(10)
    header_canary = f"{header_token}.{collaborator_domain}"
    http_get(base, extra_headers={
        "X-Forwarded-For": header_canary, "X-Forwarded-Host": header_canary,
        "Referer": f"http://{header_canary}/",
    }, budget=budget)
    injected.append({"vector": "headers:X-Forwarded-For/Host,Referer", "token": header_token, "canary": header_canary})
    return injected


# --------------------------------------------------------------------------
# Authenticated dual-session IDOR/BOLA candidate detection
# --------------------------------------------------------------------------

def find_id_like_urls(urls: list, host: str) -> list:
    """Filters discovered URLs down to ones with a numeric path segment or
    numeric query value - candidates for object-ID substitution testing."""
    out = []
    for u in urls:
        if not same_host(u, host):
            continue
        if re.search(r"/\d{2,}(?:/|$)", u) or re.search(r"[?&]\w*id\w*=\d+", u, re.I):
            out.append(u)
    return sorted(set(out))


def _content_similarity(a: str, b: str) -> float:
    """Real structural similarity (difflib ratio on whitespace-normalized
    text) instead of a crude length-ratio - two completely different user
    profile pages can easily land within 15% of each other's byte length by
    coincidence, which was the old check's actual failure mode."""
    if not a or not b:
        return 0.0
    a_n = re.sub(r"\s+", " ", a)[:20000]
    b_n = re.sub(r"\s+", " ", b)[:20000]
    return difflib.SequenceMatcher(None, a_n, b_n, autojunk=True).quick_ratio()


def test_idor_candidates(urls: list, host: str, cookie_a: str, cookie_b: str, budget: "RequestBudget", max_urls: int = 20) -> list:
    """For each ID-like URL: fetch it anonymously, as account A, and as
    account B (two sessions the tester owns).

    The old version just checked whether both accounts got a similarly-sized
    2xx response - which is nearly meaningless on its own, since a genuinely
    public/shared resource (docs, static assets, a public listing) would
    trivially "pass" that check too, without anything being an access-
    control bug. This version requires:
      1. the anonymous response to differ meaningfully from the authenticated
         one (proves the resource is actually access-gated, not public)
      2. a real content-similarity metric (difflib, not length-ratio) between
         account A's and account B's responses
      3. a minimum content size, so two near-empty/error pages can't
         trivially "match"

    It still cannot prove the object belongs to a different owner - only
    that access wasn't differentiated by session - so this stays CANDIDATE
    tier and capped confidence regardless of how similar the responses are.
    """
    findings = []
    candidates = find_id_like_urls(urls, host)[:max_urls]
    for url in candidates:
        anon_status, _, anon_body = http_get(url, budget=budget)
        status_a, _, body_a = http_get(url, budget=budget, extra_headers={"Cookie": cookie_a})
        status_b, _, body_b = http_get(url, budget=budget, extra_headers={"Cookie": cookie_b})

        if not (status_a and status_b and status_a < 300 and status_b < 300):
            continue
        if len(body_a or "") < 80 or len(body_b or "") < 80:
            continue  # too small to meaningfully compare - avoids matching on trivial/empty pages

        anon_differs = anon_status is None or anon_status >= 400 or _content_similarity(anon_body or "", body_a) < 0.6
        if not anon_differs:
            continue  # anonymous access looks just as successful - likely a public resource, not user-scoped

        similarity = _content_similarity(body_a, body_b)
        if similarity >= 0.85:
            confidence = min(0.5, 0.2 + similarity * 0.3)
            findings.append(finding(
                "idor-candidate", "high", confidence,
                f"anon={anon_status}, account A={status_a} ({len(body_a)}b), account B={status_b} ({len(body_b)}b), "
                f"A/B content similarity={similarity:.2f}",
                "resource looks access-gated (anonymous request failed/differed) but both authenticated sessions "
                "received near-identical content for the same object URL - manually confirm the object actually "
                "belongs to a different account before reporting; this cannot prove ownership on its own",
                tier="CANDIDATE", url=url,
            ))
    return findings


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def run(target: str, active: bool = False, collaborator_domain: str | None = None,
        wayback: bool = False, js: bool = False, crawl_pages: int = 8,
        cookie_a: str | None = None, cookie_b: str | None = None,
        max_requests: int = 400) -> dict:
    base, host = normalize_target(target)
    apex, apex_method = get_apex_domain(host)
    budget = RequestBudget(max_requests=max_requests)

    report = {
        "target": base, "host": host,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "findings": [], "inventory": {},
    }

    def add(findings: list) -> None:
        for f in findings:
            report["findings"].append(f)
            print_finding(f)

    banner(f"Target: {base}  (host: {host})")

    banner("DNS resolution")
    report["dns"] = resolve_dns(host)
    for a in report["dns"]["addresses"]:
        print(f"  {a}")
    if report["dns"]["error"]:
        print(color(f"  DNS error: {report['dns']['error']}", "31"))

    banner("HTTP fingerprint (scope-bounded fetch)")
    status, headers, homepage_body, redirect_chain = fetch_in_scope(base, host, budget)
    report["http_status"] = status
    print(f"  Status: {status}")
    if redirect_chain:
        print(f"  Redirect chain: {' -> '.join(redirect_chain)}")
        if not same_host(redirect_chain[-1], host):
            print(color(f"  [info] final hop leaves authorized host ({host}) - not followed further", "33"))
    header_analysis = analyze_headers(headers)
    report["inventory"]["technologies"] = header_analysis["technologies"]
    report["inventory"]["missing_security_headers_info"] = header_analysis["missing_security_headers_info"]
    if header_analysis["technologies"]:
        print(color("  Technologies:", "1"))
        for label, val in header_analysis["technologies"].items():
            print(f"    - {label}: {val}")
    if header_analysis["missing_security_headers_info"]:
        print(color("  Missing headers (informational, not findings):", "36"))
        for note in header_analysis["missing_security_headers_info"]:
            print(f"    - {note}")

    banner("Cookies")
    add(analyze_cookies(base, budget))

    banner("TLS")
    report["tls"] = get_tls_info(host)
    if report["tls"].get("error"):
        print(color(f"  TLS error: {report['tls']['error']}", "31"))
    else:
        print(f"  Protocol: {report['tls'].get('protocol')}  Issuer: {report['tls'].get('issuer', {}).get('organizationName', '?')}  Expires: {report['tls'].get('not_after')}")
        add(report["tls"]["findings"])

    banner("Sensitive paths (content-validated)")
    path_results = check_paths(base, budget)
    report["inventory"]["paths"] = path_results["inventory"]
    for p in path_results["inventory"]:
        print(f"  {p['status']} {p['path']}" + (f"  ({p.get('content_type','')})" if "content_type" in p else f"  - {p.get('note','')}"))
    add(path_results["findings"])

    banner("Secrets scan (homepage)")
    add(scan_secrets(base, homepage_body))

    banner("Passive subdomains (crt.sh)")
    if apex_method == "ip-literal":
        print(color(f"  [info] target host is an IP literal ({host}) - domain-based subdomain/wayback "
                     "enumeration doesn't apply, skipping.", "36"))
        report["inventory"]["subdomains"] = {"count": 0, "subdomains": [], "error": "skipped: IP-literal target"}
    else:
        print(f"  Apex domain for enumeration: {apex}  (method: {apex_method})")
        if apex_method == "heuristic":
            print(color("  [info] no tldextract installed - using a curated fallback list for multi-label TLDs "
                         "(.co.uk, .com.au, etc). Run `pip install tldextract` for full public-suffix accuracy.", "36"))
        report["inventory"]["subdomains"] = crtsh_subdomains(apex, budget)
    sd = report["inventory"]["subdomains"]
    if sd["error"]:
        print(color(f"  {sd['error']}", "33"))
    else:
        print(f"  {sd['count']} unique subdomains found")
        for s in sd["subdomains"][:30]:
            print(f"    - {s}")

    wayback_urls = []
    if wayback:
        banner("Historical URLs (Wayback, passive)")
        if apex_method == "ip-literal":
            print(color("  [info] IP-literal target, skipping Wayback lookup.", "36"))
            wb = {"count": 0, "urls": [], "error": "skipped: IP-literal target"}
        else:
            wb = get_wayback_urls(apex, budget)
        report["inventory"]["wayback"] = wb
        wayback_urls = wb["urls"]
        if wb["error"]:
            print(color(f"  {wb['error']}", "33"))
        else:
            print(f"  {wb['count']} historical URLs found")

    crawl_result = {"pages": [], "forms": [], "urls_with_params": []}
    if js or active:
        banner(f"Same-origin crawl (max {crawl_pages} pages, scope-bounded)")
        crawl_result = crawl(base, host, homepage_body, budget, max_pages=crawl_pages)
        report["inventory"]["crawled_pages"] = crawl_result["pages"]
        report["inventory"]["forms"] = crawl_result["forms"]
        print(f"  {len(crawl_result['pages'])} pages crawled, {len(crawl_result['forms'])} forms found")

    if js:
        banner("JS endpoint + secrets extraction")
        js_result = extract_js_endpoints(base, host, homepage_body, budget)
        report["inventory"]["js_files"] = js_result["js_files"]
        report["inventory"]["js_endpoints"] = js_result["endpoints"]
        print(f"  {len(js_result['js_files'])} same-origin JS files fetched, {len(js_result['endpoints'])} candidate endpoints extracted")
        add(js_result["secrets"])

    if active:
        banner("Form / CSRF indicator inventory")
        add(check_csrf_indicators(crawl_result["forms"]))
        for f in crawl_result["forms"]:
            print(f"  {f['method']:6s} {f['action'] or '(same page)'}  fields={f['inputs']}  csrf_field={f['has_csrf_token_field']}")

        banner("Open redirect")
        add(check_open_redirect(base, budget))

        banner("CORS")
        add(check_cors_misconfig(base, budget))

        banner("Reflected-input: synthetic single-param probes")
        add(test_reflection_isolated(base, INJECTABLE_PARAMS_DEFAULT, budget))

        param_urls = sorted(set(crawl_result["urls_with_params"] + wayback_urls))
        banner(f"Reflected-input: per-parameter isolated testing on {min(len(param_urls), 15)} discovered URLs")
        add(test_reflection_on_urls(param_urls, host, budget))

        discovered_params = sorted({k for u in param_urls for k in urllib.parse.parse_qs(urllib.parse.urlparse(u).query)})
        # capped tighter than before: the statistically-confirmed timing probes (SQLi/cmdi) now take
        # 2 baseline + up to 4 confirmation requests per param per dialect/payload, so this list directly
        # multiplies request cost - keep it modest by default and raise --max-requests for full coverage.
        injection_param_set = sorted(set(INJECTABLE_PARAMS_DEFAULT + discovered_params))[:8]

        banner(f"SQL injection indicators ({len(injection_param_set)} params, single-shot per dialect)")
        add(check_sqli_indicators(base, injection_param_set, budget))

        banner("SSTI indicators (safe arithmetic probe)")
        add(check_ssti_indicators(base, injection_param_set, budget))

        banner("OS command injection indicators (timing-only)")
        add(check_command_injection_indicators(base, injection_param_set, budget))

        banner("Path traversal indicators (single canary per OS)")
        add(check_path_traversal_indicators(base, budget))

        banner("GraphQL introspection")
        add(check_graphql_introspection(base, budget))

        banner("JWT structural inspection (passive, homepage body)")
        add(inspect_jwts(base, homepage_body))

    if collaborator_domain:
        banner(f"OOB / blind SSRF probes -> {collaborator_domain}")
        print("  Check YOUR OWN collaborator dashboard for interactions matching these tokens:")
        report["inventory"]["oob"] = check_oob_collaborator(base, collaborator_domain, budget)
        for i in report["inventory"]["oob"]:
            print(f"    - {i['vector']:45s} token={i['token']}")
    elif active:
        print(color("\n  [info] Skipping OOB/blind-SSRF injection: no --collaborator-domain given (see --help).", "36"))

    if cookie_a and cookie_b:
        all_urls = sorted(set(crawl_result["urls_with_params"] + wayback_urls + crawl_result["pages"]))
        banner(f"Authenticated IDOR/BOLA candidates ({min(len(find_id_like_urls(all_urls, host)), 20)} ID-like URLs tested)")
        print("  Using two tester-supplied sessions - never third-party accounts.")
        add(test_idor_candidates(all_urls, host, cookie_a, cookie_b, budget))
    elif active:
        print(color("\n  [info] Skipping IDOR/BOLA testing: needs --cookie-a and --cookie-b from two accounts you control.", "36"))

    report["requests_made"] = budget.count
    report["findings"].sort(key=lambda f: (-{"high": 3, "medium": 2, "low": 1, "info": 0}[f["severity"]], -f["confidence"]))
    return report


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Authorized bug bounty recon + evidence-based vulnerability triage.",
        epilog="Out of scope by design (bystander/third-party blast radius, not effort): "
               "HTTP request smuggling, live OAuth-flow attacks. SQLi/SSTI/command-injection/"
               "path-traversal/GraphQL/JWT are detection-only here (single-shot signals) - "
               "escalate a positive finding to sqlmap/commix/etc. under your own control.",
    )
    ap.add_argument("target", help="URL or domain, e.g. https://example.com or example.com")
    ap.add_argument("--json", metavar="FILE", help="write full structured report (findings + inventory) to a JSON file")
    ap.add_argument("--yes", action="store_true", help="skip the authorization prompt")
    ap.add_argument("--active", action="store_true",
                     help="enable low-impact active checks: crawl, forms/CSRF indicators, open redirect, CORS, per-parameter reflection testing")
    ap.add_argument("--collaborator-domain", metavar="DOMAIN",
                     help="YOUR OWN Interactsh/Burp Collaborator domain for blind-SSRF OOB canaries. Never defaults to a third party.")
    ap.add_argument("--cookie-a", metavar="COOKIE", help="Cookie header value for authenticated test account A (IDOR/BOLA testing)")
    ap.add_argument("--cookie-b", metavar="COOKIE", help="Cookie header value for authenticated test account B (IDOR/BOLA testing)")
    ap.add_argument("--wayback", action="store_true", help="pull historical URLs from the Wayback Machine (passive)")
    ap.add_argument("--js", action="store_true", help="crawl + fetch same-origin JS, extract candidate endpoints and scan for secrets")
    ap.add_argument("--crawl-pages", type=int, default=8, help="max same-origin pages to crawl for forms/params (default 8)")
    ap.add_argument("--all", action="store_true", help="shorthand for --active --wayback --js")
    ap.add_argument("--max-requests", type=int, default=400, help="hard cap on outbound requests this run makes (default 400)")
    args = ap.parse_args()

    if args.all:
        args.active = True
        args.wayback = True
        args.js = True

    if bool(args.cookie_a) != bool(args.cookie_b):
        print(color("Both --cookie-a and --cookie-b are required together for IDOR/BOLA testing.", "31"))
        return 1

    if not args.yes:
        print(color("AUTHORIZATION CHECK", "1;33"))
        print("Only scan targets you are explicitly authorized to test (in-scope bug bounty asset or your own).")
        print("Active checks, OOB probes, and authenticated testing send real requests - make sure they're in scope.")
        ans = input(f"Confirm you are authorized to scan '{args.target}'? [y/N] ").strip().lower()
        if ans not in ("y", "yes"):
            print("Aborted.")
            return 1

    report = run(
        args.target, active=args.active, collaborator_domain=args.collaborator_domain,
        wayback=args.wayback, js=args.js, crawl_pages=args.crawl_pages,
        cookie_a=args.cookie_a, cookie_b=args.cookie_b, max_requests=args.max_requests,
    )

    banner("Summary")
    by_sev = {}
    for f in report["findings"]:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    if by_sev:
        print("  " + "  ".join(f"{k}={v}" for k, v in sorted(by_sev.items(), key=lambda x: -{"high": 3, "medium": 2, "low": 1, "info": 0}[x[0]])))
    else:
        print("  no findings above informational level")
    print(f"  {report['requests_made']} requests made this run")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        print(color(f"\nFull structured report written to {args.json}", "32"))

    return 0


if __name__ == "__main__":
    sys.exit(main())
