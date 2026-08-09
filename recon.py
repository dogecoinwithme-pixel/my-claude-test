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


def finding(check: str, severity: str, confidence: float, evidence: str, note: str, **extra) -> dict:
    """Structured, evidence-based finding. severity: info/low/medium/high.
    confidence: 0.0-1.0, how sure the heuristic is this is real and exploitable."""
    f = {"check": check, "severity": severity, "confidence": round(confidence, 2), "evidence": evidence, "note": note}
    f.update(extra)
    return f


def print_finding(f: dict) -> None:
    sev_color = {"info": "36", "low": "33", "medium": "33;1", "high": "31;1"}.get(f["severity"], "0")
    tag = f["severity"].upper()
    loc = f.get("url") or f.get("param") or f.get("cookie") or ""
    print(color(f"  [{tag} conf={f['confidence']}]", sev_color) + f" {f['check']} {loc} - {f['note']}")


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
            if urllib.parse.urlparse(location).netloc != host:
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
                    ))
                if info["issuer"] == info["subject"]:
                    info["findings"].append(finding(
                        "tls-self-signed", "low", 0.5, str(info["issuer"]),
                        "issuer == subject, looks self-signed (or this is an internal CA) - verify manually",
                    ))
                try:
                    expires = datetime.strptime(info["not_after"], "%b %d %H:%M:%S %Y %Z")
                    days_left = (expires - datetime.utcnow()).days
                    if days_left < 0:
                        info["findings"].append(finding("tls-expired", "high", 0.95, info["not_after"], "certificate is expired"))
                    elif days_left < 30:
                        info["findings"].append(finding("tls-expiring-soon", "low", 0.8, info["not_after"], f"certificate expires in {days_left} days"))
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
            severity = "medium" if "httponly" not in attr_names else "low"
            findings.append(finding(
                "cookie-flags", severity, 1.0, raw, "; ".join(issues), cookie=name,
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
                f"{path} returned 200 AND content matches expected sensitive-file structure", url=base + path,
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


def scan_secrets(label: str, body: str) -> list:
    findings = []
    if not body:
        return findings
    for name, pattern, confidence in SECRET_PATTERNS:
        for m in pattern.finditer(body):
            snippet = body[max(0, m.start() - 20):m.end() + 10]
            findings.append(finding(
                "secret-exposure", "high" if confidence >= 0.8 else "medium", confidence,
                snippet.replace("\n", " "), f"pattern '{name}' matched in {label}", url=label,
            ))
    return findings


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
        if urllib.parse.urlparse(u).netloc == host and u.startswith(("http://", "https://")):
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
        if urllib.parse.urlparse(js_url).netloc != host:
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


def _classify_reflection(body: str, marker: str) -> tuple[str, bool]:
    """Returns (context, looks_unescaped). looks_unescaped is True only if the
    marker appears adjacent to raw <, ", or ' - i.e. it could break out of an
    attribute/tag - not just present as inert text."""
    idx = body.find(marker)
    if idx == -1:
        return "not-found", False
    window = body[max(0, idx - 30):idx + len(marker) + 10]
    unescaped = bool(re.search(r'[<"\']' + re.escape(marker), window)) or bool(re.search(re.escape(marker) + r'[<>"\']', window))
    before_tag = body[max(0, idx - 200):idx]
    if re.search(r"<script\b[^>]*>[^<]*$", before_tag, re.I):
        context = "script-block"
    elif re.search(r'=["\']?[^"\'>]*$', before_tag):
        context = "html-attribute"
    else:
        context = "html-body"
    return context, unescaped


def test_reflection_isolated(base: str, param_names: list, budget: "RequestBudget") -> list:
    """Synthetic single-param tests against the bare origin, for common param
    names that may not appear in any crawled URL (e.g. search boxes that
    submit via JS)."""
    findings = []
    for param in param_names:
        marker = f"rXf{_rand_token(6)}"
        base_status, _, base_body = http_get(f"{base}/?{param}=baseline{_rand_token(4)}", budget=budget)
        status, _, body = http_get(f"{base}/?{param}={urllib.parse.quote(marker)}", budget=budget)
        if not body or marker not in body:
            continue
        if base_body and marker in base_body:
            continue  # reflected even in unrelated baseline - not caused by our input
        context, unescaped = _classify_reflection(body, marker)
        confidence = 0.75 if unescaped and context in ("html-attribute", "script-block", "html-body") else 0.3
        findings.append(finding(
            "reflected-input", "medium" if confidence >= 0.6 else "low", confidence,
            body[max(0, body.find(marker) - 40):body.find(marker) + 40].replace("\n", " "),
            f"param='{param}' reflected {'unescaped' if unescaped else 'as encoded/inert text'} in {context} - verify manually before reporting",
            param=param, url=f"{base}/?{param}=...", status=status,
        ))
    return findings


def _param_variants(url: str, marker: str) -> list:
    """For a URL with existing query params, yield (param_name, variant_url)
    pairs where exactly ONE parameter is replaced with the marker and all
    others keep their original values - this is the fix for the
    all-params-get-the-same-value bug."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    out = []
    for i, (k, _v) in enumerate(qs):
        new_qs = list(qs)
        new_qs[i] = (k, marker)
        variant = parsed._replace(query=urllib.parse.urlencode(new_qs)).geturl()
        out.append((k, variant))
    return out


def test_reflection_on_urls(urls: list, host: str, budget: "RequestBudget", max_urls: int = 15, max_params: int = 6) -> list:
    """Real per-parameter isolated testing on actually-discovered URLs with
    multiple query params, exactly like: ?id=X&name=alice&sort=date ->
    test id alone, then name alone, then sort alone, each against its own
    unmodified baseline."""
    findings = []
    tested_urls = 0
    for url in urls:
        if tested_urls >= max_urls:
            break
        if urllib.parse.urlparse(url).netloc != host:
            continue
        variants = _param_variants(url, "placeholder")
        if not variants:
            continue
        tested_urls += 1
        _, _, baseline_body = http_get(url, budget=budget)
        for param, _variant in variants[:max_params]:
            marker = f"rXf{_rand_token(6)}"
            variant_url = None
            for p2, v2 in _param_variants(url, marker):
                if p2 == param:
                    variant_url = v2
                    break
            if not variant_url:
                continue
            status, _, body = http_get(variant_url, budget=budget)
            if not body or marker not in body:
                continue
            if baseline_body and marker in baseline_body:
                continue
            context, unescaped = _classify_reflection(body, marker)
            confidence = 0.8 if unescaped and context in ("html-attribute", "script-block") else (0.55 if unescaped else 0.25)
            findings.append(finding(
                "reflected-input", "medium" if confidence >= 0.6 else "low", confidence,
                body[max(0, body.find(marker) - 40):body.find(marker) + 40].replace("\n", " "),
                f"param='{param}' isolated-tested on discovered URL, reflected {'unescaped' if unescaped else 'as encoded/inert text'} in {context}",
                param=param, url=url, status=status,
            ))
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
                    f"param='{param}' redirects to attacker-supplied external URL", param=param, url=url,
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
            ))
        elif acao == "*" and acac == "true":
            findings.append(finding(
                "cors-misconfig", "info", 0.3, f"ACAO: *, ACAC: {acac}",
                "ACAO=* with ACAC=true is invalid per spec and browsers reject it - usually not exploitable, informational only",
            ))
    return findings


# --------------------------------------------------------------------------
# CSRF indicator (heuristic, not proof - SameSite/anti-CSRF headers can
# protect a form with no visible token field)
# --------------------------------------------------------------------------

def check_csrf_indicators(forms: list) -> list:
    findings = []
    for f in forms:
        if f["method"] in ("POST", "PUT", "PATCH", "DELETE") and not f["has_csrf_token_field"]:
            findings.append(finding(
                "csrf-indicator", "low", 0.4, json.dumps(f),
                f"state-changing form (method={f['method']}) on {f.get('page','?')} has no visible CSRF token input - "
                "may still be protected by SameSite cookies or a header-based token invisible to HTML parsing; verify manually",
                url=f.get("page", ""),
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

TIMING_THRESHOLD = 4.0  # seconds over baseline before a delay counts as signal


def check_sqli_indicators(base: str, param_names: list, budget: "RequestBudget") -> list:
    findings = []
    for param in param_names:
        t0 = time.monotonic()
        _, _, base_body = http_get(f"{base}/?{param}=1", budget=budget)
        baseline_elapsed = time.monotonic() - t0

        _, _, err_body = http_get(f"{base}/?{param}={urllib.parse.quote(chr(39))}", budget=budget)
        for sig in SQL_ERROR_SIGNATURES:
            if err_body and sig.search(err_body) and not (base_body and sig.search(base_body)):
                findings.append(finding(
                    "sqli-indicator", "high", 0.75, sig.pattern,
                    f"param='{param}' single-quote probe surfaced a SQL error signature absent from baseline - "
                    "error-based SQLi indicator, confirm manually before further testing",
                    param=param,
                ))
                break

        for dialect, payload in SQL_TIME_PAYLOADS.items():
            t0 = time.monotonic()
            status, _, _ = http_get(f"{base}/?{param}={urllib.parse.quote(payload)}", budget=budget)
            elapsed = time.monotonic() - t0
            if status is not None and elapsed - baseline_elapsed > TIMING_THRESHOLD:
                findings.append(finding(
                    "sqli-indicator", "high", 0.6, f"baseline={baseline_elapsed:.2f}s test={elapsed:.2f}s dialect={dialect}",
                    f"param='{param}' time-based probe ({dialect}) added ~5s vs baseline - blind SQLi indicator; "
                    "re-test once before reporting to rule out network jitter",
                    param=param,
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
                    "ssti-indicator", "high", 0.7, f"payload={payload} -> response contains '{expected}'",
                    f"param='{param}' template expression was evaluated server-side rather than reflected literally - "
                    "SSTI indicator, confirm manually",
                    param=param,
                ))
                break
    return findings


def check_command_injection_indicators(base: str, param_names: list, budget: "RequestBudget") -> list:
    findings = []
    for param in param_names:
        t0 = time.monotonic()
        http_get(f"{base}/?{param}=1", budget=budget)
        baseline_elapsed = time.monotonic() - t0
        for payload in CMDI_TIME_PAYLOADS:
            t0 = time.monotonic()
            status, _, _ = http_get(f"{base}/?{param}={urllib.parse.quote(payload)}", budget=budget)
            elapsed = time.monotonic() - t0
            if status is not None and elapsed - baseline_elapsed > TIMING_THRESHOLD:
                findings.append(finding(
                    "command-injection-indicator", "high", 0.55,
                    f"baseline={baseline_elapsed:.2f}s test={elapsed:.2f}s payload={payload!r}",
                    f"param='{param}' shell-metacharacter timing probe added ~5s vs baseline - blind OS command "
                    "injection indicator; re-test once before reporting to rule out jitter",
                    param=param,
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
                "path-traversal-indicator", "high", 0.7, body[:150].replace("\n", " "),
                "traversal payload returned a recognizable system-file signature - confirm manually, "
                "do not pull further files with this tool",
                url=url,
            ))
    return findings


GRAPHQL_INTROSPECTION_QUERY = {"query": "{__schema{queryType{name}mutationType{name}types{name kind}}}"}
GRAPHQL_CANDIDATE_PATHS = ["/graphql", "/api/graphql", "/graphql/console", "/v1/graphql"]


def check_graphql_introspection(base: str, budget: "RequestBudget") -> list:
    """Read-only: sends the standard introspection query and checks whether
    the schema is exposed. Does not attempt authorization bypass on
    resolvers - that needs field-by-field manual review of the schema."""
    findings = []
    for path in GRAPHQL_CANDIDATE_PATHS:
        status, headers, body = http_get(
            base + path, method="POST", budget=budget,
            extra_headers={"Content-Type": "application/json"}, json_body=GRAPHQL_INTROSPECTION_QUERY,
        )
        if status == 200 and body and '"__schema"' in body and '"types"' in body:
            findings.append(finding(
                "graphql-introspection-enabled", "medium", 0.85, body[:150].replace("\n", " "),
                f"{path} accepted a standard introspection query and returned the schema - "
                "review exposed types/mutations for sensitive fields or unauthenticated write access",
                url=base + path,
            ))
    return findings


def _b64url_decode(segment: str) -> bytes:
    import base64
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def inspect_jwts(label: str, body: str) -> list:
    """Passive: decodes any JWT-shaped token found in a response body and
    flags structurally risky claims. Does not forge or resend tokens - that
    would need to know which endpoint actually treats the token as an
    authorization decision, which a blind scan can't determine safely."""
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
        issues = []
        if str(header.get("alg", "")).lower() == "none":
            issues.append("header alg='none' - server-side acceptance would be a full auth bypass")
        if "exp" not in payload:
            issues.append("no 'exp' claim - token may never expire")
        if header.get("alg") in ("HS256", "HS384", "HS512") and any(
            k in str(payload).lower() for k in ("admin", "role", "is_admin", "scope")
        ):
            issues.append("symmetric alg (HS*) carrying privilege claims - worth testing for a weak/guessable signing secret offline (e.g. with hashcat), not attempted here")
        if issues:
            findings.append(finding(
                "jwt-structural-risk", "medium", 0.5, f"header={header} payload_keys={list(payload.keys())}",
                "; ".join(issues), url=label,
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
        if urllib.parse.urlparse(u).netloc != host:
            continue
        if re.search(r"/\d{2,}(?:/|$)", u) or re.search(r"[?&]\w*id\w*=\d+", u, re.I):
            out.append(u)
    return sorted(set(out))


def test_idor_candidates(urls: list, host: str, cookie_a: str, cookie_b: str, budget: "RequestBudget", max_urls: int = 20) -> list:
    """For each ID-like URL, fetch as account A and account B (two sessions
    the tester owns). If BOTH accounts get an identical-shaped 2xx response
    to a resource presumably scoped to one account, that's a horizontal
    access-control candidate worth manual confirmation - this cannot itself
    prove the object belongs to a different user, only that access wasn't
    differentiated by session."""
    findings = []
    candidates = find_id_like_urls(urls, host)[:max_urls]
    for url in candidates:
        status_a, _, body_a = http_get(url, budget=budget, extra_headers={"Cookie": cookie_a})
        status_b, _, body_b = http_get(url, budget=budget, extra_headers={"Cookie": cookie_b})
        if status_a and status_b and status_a < 300 and status_b < 300:
            len_a, len_b = len(body_a or ""), len(body_b or "")
            similar_length = len_a and len_b and abs(len_a - len_b) / max(len_a, len_b) < 0.15
            if similar_length:
                findings.append(finding(
                    "idor-candidate", "high", 0.55,
                    f"account A: {status_a} ({len_a}b), account B: {status_b} ({len_b}b)",
                    "both sessions received a similarly-shaped 2xx response for the same object URL - "
                    "manually confirm the object actually belongs to a different account before reporting",
                    url=url,
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
    apex = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
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
        if urllib.parse.urlparse(redirect_chain[-1]).netloc != host:
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
        injection_param_set = sorted(set(INJECTABLE_PARAMS_DEFAULT + discovered_params))[:10]

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
