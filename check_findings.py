#!/usr/bin/env python3
"""
check_findings.py — Manual verification of discovered endpoints from a scan report.

Reads a JSON report produced by crypto_vuln_tester.py and makes unauthenticated
requests to every discovered endpoint, showing you exactly what comes back.
This helps you judge whether "HTTP 200" actually means data is exposed.

Usage:
    python check_findings.py --report reports/scan_20260314_082400.json
    python check_findings.py --report reports/scan_20260314_082400.json --cookie "session=abc123"
    python check_findings.py --report reports/scan_20260314_082400.json --key-only

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

import argparse
import json
import sys
import time

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from modules.key_detector import KeyDetector

# ── ANSI colours ──────────────────────────────────────────────────────────────
R    = "\033[0m"
RED  = "\033[91m"
YEL  = "\033[93m"
BLU  = "\033[94m"
GRN  = "\033[92m"
CYAN = "\033[96m"
DIM  = "\033[2m"
BOLD = "\033[1m"

detector = KeyDetector()


def status_color(code: int) -> str:
    if code == 200:
        return GRN
    if code in (401, 403):
        return BLU   # auth enforced — expected
    if code == 404:
        return DIM
    return YEL


def verdict(code: int, body: str, keys_found: list) -> tuple[str, str]:
    """Return (label, color) verdict for a response."""
    if keys_found:
        return "CRYPTO KEY MATERIAL DETECTED", RED
    if code in (401, 403):
        return "AUTH ENFORCED — protected", BLU
    if code == 404:
        return "Not found", DIM
    if code == 200:
        # Is the body empty or a generic stub?
        stripped = body.strip()
        if not stripped or stripped in ("{}", "[]", "null", '{"data":null}'):
            return "HTTP 200 but body is empty/stub — likely gated", YEL
        if '"error"' in body.lower() or '"message"' in body.lower() and '"route' in body.lower():
            return "HTTP 200 but returns error/route-not-found message — false positive", YEL
        return "HTTP 200 with real-looking body — REVIEW MANUALLY", RED
    return f"HTTP {code}", DIM


def check_endpoint(session: requests.Session, ep: dict, delay: float, snippet_len: int) -> dict:
    url    = ep["url"]
    method = ep.get("method", "GET").upper()

    try:
        time.sleep(delay)
        resp = session.request(method, url, timeout=(6, 10))
        body = resp.text
        keys = detector.detect(body)
        label, col = verdict(resp.status_code, body, keys)

        return {
            "url":        url,
            "method":     method,
            "status":     resp.status_code,
            "body_len":   len(resp.content),
            "snippet":    body[:snippet_len].replace("\n", " ").strip(),
            "keys_found": keys,
            "label":      label,
            "color":      col,
            "key_related": ep.get("key_related", False),
        }
    except requests.exceptions.RequestException as e:
        return {
            "url":        url,
            "method":     method,
            "status":     0,
            "body_len":   0,
            "snippet":    f"Request failed: {e}",
            "keys_found": [],
            "label":      "CONNECTION ERROR",
            "color":      DIM,
            "key_related": ep.get("key_related", False),
        }


def print_result(r: dict, verbose: bool):
    col   = r["color"]
    sc    = r["status"] or "ERR"
    sc_c  = status_color(r["status"]) if r["status"] else DIM
    key_tag = f"  {CYAN}[KEY-RELATED]{R}" if r["key_related"] else ""

    print(f"\n  {sc_c}HTTP {sc}{R}{key_tag}")
    print(f"  {BOLD}{r['method']} {r['url']}{R}")
    print(f"  {col}▶ {r['label']}{R}")
    print(f"  {DIM}Body size: {r['body_len']} bytes{R}")

    if r["keys_found"]:
        print(f"  {RED}{BOLD}  !! KEY MATERIAL FOUND !!")
        for k in r["keys_found"]:
            print(f"     Type    : {k.get('type_name', k.get('type', '?'))}")
            print(f"     Redacted: {k.get('redacted', 'REDACTED')}{R}")

    if verbose or r["status"] == 200:
        snippet = r["snippet"]
        if snippet:
            print(f"  {DIM}Response preview:{R}")
            # Wrap long lines for readability
            for i in range(0, min(len(snippet), 400), 120):
                print(f"    {DIM}{snippet[i:i+120]}{R}")


def main():
    parser = argparse.ArgumentParser(
        description="Manual endpoint verifier — reads a scan report and checks each endpoint",
    )
    parser.add_argument("--report",    required=True,
                        help="Path to JSON report from crypto_vuln_tester.py")
    parser.add_argument("--cookie",    default=None,
                        help="Session cookie e.g. 'session=abc123'")
    parser.add_argument("--token",     default=None,
                        help="Bearer token / API key")
    parser.add_argument("--delay",     type=float, default=0.5,
                        help="Seconds between requests (default 0.5)")
    parser.add_argument("--key-only",  action="store_true",
                        help="Only check endpoints flagged as key-related")
    parser.add_argument("--snippet",   type=int, default=300,
                        help="Max response preview characters (default 300)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable SSL certificate verification")
    parser.add_argument("--verbose",   action="store_true",
                        help="Show response preview for every endpoint, not just 200s")
    args = parser.parse_args()

    # ── Load report ───────────────────────────────────────────────────────────
    try:
        with open(args.report) as f:
            report = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"{RED}Cannot read report: {e}{R}")
        sys.exit(1)

    target    = report.get("meta", {}).get("target", "unknown")
    endpoints = report.get("discovered_endpoints", [])

    if not endpoints:
        print(f"{YEL}No discovered endpoints in report.{R}")
        sys.exit(0)

    if args.key_only:
        endpoints = [e for e in endpoints if e.get("key_related")]
        print(f"{DIM}--key-only: checking {len(endpoints)} key-related endpoints{R}")

    # ── Build session ─────────────────────────────────────────────────────────
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json, text/html, */*",
    })
    if args.token:
        t = args.token
        session.headers["Authorization"] = t if t.startswith("Bearer ") else f"Bearer {t}"
    if args.cookie:
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                name, _, value = pair.partition("=")
                session.cookies.set(name.strip(), value.strip())
    session.verify = not args.no_verify

    # ── Banner ────────────────────────────────────────────────────────────────
    print(f"\n{CYAN}{BOLD}  ╔══════════════════════════════════════╗")
    print(f"  ║   MANUAL ENDPOINT VERIFICATION     ║")
    print(f"  ╚══════════════════════════════════════╝{R}")
    print(f"  Target  : {BOLD}{target}{R}")
    print(f"  Report  : {args.report}")
    print(f"  Checking: {len(endpoints)} endpoint(s)")
    auth_note = "unauthenticated" if not args.cookie and not args.token else "with provided credentials"
    print(f"  Auth    : {auth_note}")
    print(f"  {YEL}Checking what actually comes back from each endpoint ...{R}")

    # ── Check each endpoint ───────────────────────────────────────────────────
    results = []
    for ep in endpoints:
        r = check_endpoint(session, ep, args.delay, args.snippet)
        results.append(r)
        print_result(r, args.verbose)

    # ── Summary ───────────────────────────────────────────────────────────────
    total      = len(results)
    key_hits   = [r for r in results if r["keys_found"]]
    real_200   = [r for r in results if r["status"] == 200 and not r["keys_found"]
                  and "empty" not in r["label"] and "false positive" not in r["label"]
                  and "error" not in r["label"].lower()]
    protected  = [r for r in results if r["status"] in (401, 403)]
    empty_200  = [r for r in results if r["status"] == 200 and (
                  "empty" in r["label"] or "false positive" in r["label"])]

    W = 54
    print(f"\n{GRN}{BOLD}╔{'═'*W}╗")
    print(f"║{'VERIFICATION SUMMARY':^{W}}║")
    print(f"╚{'═'*W}╝{R}")
    print(f"  Total endpoints checked : {total}")
    print(f"  {RED}{BOLD}Key material found      : {len(key_hits)}{R}")
    print(f"  {RED}Real data (200, review) : {len(real_200)}{R}")
    print(f"  {YEL}HTTP 200 but stub/empty : {len(empty_200)}{R}")
    print(f"  {BLU}Auth enforced (401/403) : {len(protected)}{R}")

    if key_hits:
        print(f"\n  {RED}{BOLD}!! CRITICAL — KEY MATERIAL EXPOSED !!")
        for r in key_hits:
            print(f"     {r['url']}")
        print(f"{R}")
        print(f"  {YEL}Next step: Screenshot the response, document the impact,")
        print(f"  and report through the authorized bug bounty channel.{R}")
    elif real_200:
        print(f"\n  {YEL}Endpoints returning real-looking data (manual review needed):{R}")
        for r in real_200:
            print(f"    HTTP 200  {r['url']}")
        print(f"\n  {DIM}Open each in a browser (logged out) and look at the actual")
        print(f"  response. If it returns your data or someone else's — that's a finding.{R}")
    else:
        print(f"\n  {GRN}No obvious unauthenticated data exposure detected.")
        print(f"  The HTTP 200s appear to be stubs or auth-gated responses.{R}")

    print()


if __name__ == "__main__":
    main()
