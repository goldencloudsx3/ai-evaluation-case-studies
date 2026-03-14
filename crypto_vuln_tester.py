#!/usr/bin/env python3
"""
Crypto Vulnerability Tester
============================
Tests blockchain/crypto websites for IDOR vulnerabilities that expose
private and public cryptographic keys — the exact vulnerability class
described in:

  "How I was able to access any public/private keys in a blockchain website"
  https://infosecwriteups.com/how-i-was-able-to-access-any-public-private-keys-in-a-blockchain-website-ae0346da91bb

VULNERABILITY CLASS:
  IDOR (Insecure Direct Object Reference) on wallet/key management API
  endpoints. Attacker authenticates, discovers their own numeric ID,
  then enumerates adjacent IDs to access other users' private keys.

USAGE:
  python crypto_vuln_tester.py --target https://example.com [OPTIONS]

  --target      Target base URL (REQUIRED — must have written authorization)
  --id          Your known user/wallet ID (for adjacent enumeration)
  --token       Bearer token or API key for authenticated requests
  --cookie      Session cookie string (name=value)
  --max-ids     Number of IDs to enumerate (default: 20)
  --delay       Delay between requests in seconds (default: 0.5)
  --no-crawl    Skip site crawling, only test known API patterns
  --output-dir  Directory to save reports (default: ./reports)
  --verbose     Verbose output
  --no-html     Skip HTML report generation
  --no-json     Skip JSON report generation

FOR AUTHORIZED SECURITY TESTING ONLY.
Unauthorized use against systems you do not own or have explicit
written permission to test is illegal.
"""

import sys
import argparse
import time
import datetime

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from modules.idor_scanner import IDORScanner, IDORScanResult
from modules.crawler import APICrawler
from modules.reporter import Reporter


BANNER = r"""
  ____                  _          __     __    _ _____         _
 / ___|_ __ _   _ _ __ | |_ ___   \ \   / /_ _| |_   _|__  ___| |_ ___ _ __
| |   | '__| | | | '_ \| __/ _ \   \ \ / / _` | | | |/ _ \/ __| __/ _ \ '__|
| |___| |  | |_| | |_) | || (_) |   \ V / (_| | | | |  __/\__ \ ||  __/ |
 \____|_|   \__, | .__/ \__\___/     \_/ \__,_|_| |_|\___||___/\__\___|_|
            |___/|_|

  Blockchain / Crypto Key Exposure & IDOR Scanner
  For authorized security testing only
"""

AUTHORIZATION_DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════╗
║                    ⚠  AUTHORIZATION REQUIRED  ⚠                     ║
║                                                                      ║
║  This tool tests for vulnerabilities in web applications.            ║
║  You MUST have explicit written authorization from the target        ║
║  system owner before running this tool.                              ║
║                                                                      ║
║  Unauthorized use is illegal under the Computer Fraud and Abuse      ║
║  Act (CFAA), Computer Misuse Act, and similar laws worldwide.        ║
║                                                                      ║
║  By proceeding you confirm you have written authorization.           ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def build_session(args) -> requests.Session:
    """Build a configured requests.Session from CLI auth arguments."""
    session = requests.Session()

    # Default headers — look like a browser to avoid trivial bot detection
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
    })

    # Bearer token / API key
    if args.token:
        if args.token.startswith("Bearer "):
            session.headers["Authorization"] = args.token
        else:
            session.headers["Authorization"] = f"Bearer {args.token}"

    # Cookie-based session
    if args.cookie:
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                name, _, value = pair.partition("=")
                session.cookies.set(name.strip(), value.strip())

    # Disable SSL verification if requested (for testing environments)
    session.verify = not args.no_verify

    return session


def confirm_authorization(target: str) -> bool:
    """Prompt the user to confirm they have authorization to test the target."""
    print(AUTHORIZATION_DISCLAIMER)
    print(f"  Target: {target}\n")
    response = input(
        "  Do you have explicit written authorization to test this target? [yes/NO]: "
    ).strip().lower()
    return response in ("yes", "y")


def print_phase(name: str):
    """Print a phase header."""
    print(f"\n{'─'*60}")
    print(f"  PHASE: {name}")
    print(f"{'─'*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Crypto Vulnerability Tester — IDOR & Key Exposure Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--target", required=True,
        help="Target base URL (e.g. https://example.com)",
    )
    parser.add_argument(
        "--id", dest="seed_id", type=int, default=None,
        help="Your known user/wallet ID (enables adjacent ID enumeration)",
    )
    parser.add_argument(
        "--token", default=None,
        help="Bearer token or API key for authenticated requests",
    )
    parser.add_argument(
        "--cookie", default=None,
        help="Session cookie string (e.g. 'session=abc123; token=xyz')",
    )
    parser.add_argument(
        "--max-ids", type=int, default=20,
        help="Number of IDs to enumerate (default: 20)",
    )
    parser.add_argument(
        "--delay", type=float, default=0.5,
        help="Delay between requests in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--no-crawl", action="store_true",
        help="Skip site crawling",
    )
    parser.add_argument(
        "--output-dir", default="reports",
        help="Directory to save reports (default: ./reports)",
    )
    parser.add_argument(
        "--no-html", action="store_true",
        help="Skip HTML report generation",
    )
    parser.add_argument(
        "--no-json", action="store_true",
        help="Skip JSON report generation",
    )
    parser.add_argument(
        "--no-verify", action="store_true",
        help="Disable SSL certificate verification",
    )
    parser.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip authorization confirmation prompt",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose output",
    )

    args = parser.parse_args()

    # Normalize target URL
    target = args.target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    print(BANNER)

    # Authorization check
    if not args.yes:
        if not confirm_authorization(target):
            print("\n  Aborted. Obtain written authorization before testing.\n")
            sys.exit(1)

    session = build_session(args)
    reporter = Reporter(output_dir=args.output_dir)

    # ──────────────────────────────────────────────────────────
    # PHASE 1: Reachability check
    # ──────────────────────────────────────────────────────────
    print_phase("1/4 — Reachability Check")
    try:
        resp = session.get(target, timeout=10)
        print(f"  [+] Target reachable: HTTP {resp.status_code}")
        if "blockchain" in resp.text.lower() or "wallet" in resp.text.lower() or "crypto" in resp.text.lower():
            print("  [+] Crypto/blockchain indicators found in homepage")
    except requests.exceptions.RequestException as e:
        print(f"  [!] Cannot reach target: {e}")
        sys.exit(1)

    # ──────────────────────────────────────────────────────────
    # PHASE 2: Crawl & Endpoint Discovery
    # ──────────────────────────────────────────────────────────
    crawl_result = None
    auth_info = {"scheme": "unknown", "notes": []}

    if not args.no_crawl:
        print_phase("2/4 — Endpoint Discovery & Crawling")
        crawler = APICrawler(
            session=session,
            delay=args.delay,
            max_pages=30,
            verbose=args.verbose,
        )

        print("  [*] Detecting authentication scheme...")
        auth_info = crawler.detect_auth_scheme(target)
        print(f"  [+] Auth scheme: {auth_info['scheme']}")
        for note in auth_info.get("notes", []):
            print(f"  [!] {note}")

        print("  [*] Crawling site for API endpoints...")
        crawl_result = crawler.crawl(target)
        print(f"  [+] Crawled {crawl_result.pages_crawled} pages, "
              f"analyzed {crawl_result.js_files_analyzed} JS files")

        print("  [*] Fuzzing common crypto API paths...")
        wordlist_hits = crawler.wordlist_fuzz(target)
        crawl_result.endpoints.extend(wordlist_hits)
        print(f"  [+] Wordlist: {len(wordlist_hits)} responsive endpoints found")

        reporter.print_discovered_endpoints(crawl_result)
    else:
        print_phase("2/4 — Endpoint Discovery [SKIPPED]")

    # ──────────────────────────────────────────────────────────
    # PHASE 3: IDOR Scan
    # ──────────────────────────────────────────────────────────
    print_phase("3/4 — IDOR Key Exposure Scan")

    if args.seed_id:
        print(f"  [*] Using seed ID {args.seed_id} for adjacent enumeration")
    else:
        print("  [*] No seed ID provided — using sequential 1..N enumeration")
        print("  [!] TIP: Use --id <your_user_id> for more targeted results")

    print(f"  [*] Enumerating up to {args.max_ids} IDs per endpoint pattern")
    print(f"  [*] Testing {len([p for p in __import__('modules.idor_scanner', fromlist=['KEY_ENDPOINT_PATTERNS']).KEY_ENDPOINT_PATTERNS])} endpoint patterns\n")

    scanner = IDORScanner(
        session=session,
        delay=args.delay,
        max_ids=args.max_ids,
        verbose=args.verbose,
    )

    start_time = time.time()
    idor_result = scanner.scan(target, seed_id=args.seed_id)
    elapsed = time.time() - start_time

    print(f"  [+] Scan complete in {elapsed:.1f}s")
    print(f"  [+] Tested {idor_result.endpoints_tested} endpoint+ID combinations")
    print(f"  [+] Found {len(idor_result.findings)} findings")

    # ──────────────────────────────────────────────────────────
    # PHASE 4: Reporting
    # ──────────────────────────────────────────────────────────
    print_phase("4/4 — Report Generation")

    reporter.print_console_summary(target, idor_result, crawl_result, auth_info)

    saved_files = []

    if not args.no_json:
        json_path = reporter.save_json(target, idor_result, crawl_result, auth_info)
        saved_files.append(("JSON", json_path))
        print(f"  [+] JSON report saved: {json_path}")

    if not args.no_html:
        html_path = reporter.save_html(target, idor_result, crawl_result, auth_info)
        saved_files.append(("HTML", html_path))
        print(f"  [+] HTML report saved: {html_path}")

    print()

    # Exit code: non-zero if critical findings
    critical_count = sum(1 for f in idor_result.findings if f.severity == "CRITICAL")
    if critical_count > 0:
        print(f"  ⚠  CRITICAL FINDINGS: {critical_count} — see report for details")
        sys.exit(2)
    elif idor_result.findings:
        print(f"  !  {len(idor_result.findings)} non-critical findings — see report")
        sys.exit(1)
    else:
        print("  ✓  No key exposure findings detected.")
        sys.exit(0)


if __name__ == "__main__":
    main()
