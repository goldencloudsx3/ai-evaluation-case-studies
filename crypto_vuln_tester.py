#!/usr/bin/env python3
"""
Crypto Vulnerability Tester
Usage:  python crypto_vuln_tester.py --target https://example.com

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

import sys
import argparse
import time
import threading
import itertools
import signal

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from modules.idor_scanner import IDORScanner, KEY_ENDPOINT_PATTERNS
from modules.crawler import APICrawler
from modules.reporter import Reporter

# ── ANSI colours ──────────────────────────────────────────────────────────────
R  = "\033[0m"
RED  = "\033[91m"
YEL  = "\033[93m"
BLU  = "\033[94m"
GRN  = "\033[92m"
DIM  = "\033[2m"
BOLD = "\033[1m"

SEV_COLOR = {"CRITICAL": RED, "HIGH": YEL, "MEDIUM": BLU, "LOW": GRN, "INFO": DIM}

BANNER = f"""{BOLD}
  Crypto Vulnerability Tester
  IDOR / Key-Exposure Scanner for Blockchain Sites
  For authorized security testing only{R}
"""

AUTH_NOTICE = f"""
{YEL}┌─────────────────────────────────────────────────────┐
│  You must have explicit written authorization from  │
│  the target owner before scanning.  Unauthorized    │
│  use is illegal (CFAA, CMA, and similar laws).      │
└─────────────────────────────────────────────────────┘{R}
"""


# ── Spinner ───────────────────────────────────────────────────────────────────

class Spinner:
    """Thread-safe terminal spinner with live counter."""

    def __init__(self, label: str):
        self.label   = label
        self._stop   = threading.Event()
        self._count  = 0
        self._lock   = threading.Lock()
        self._thread = threading.Thread(target=self._spin, daemon=True)

    def increment(self):
        with self._lock:
            self._count += 1

    def _spin(self):
        frames = itertools.cycle(["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
        while not self._stop.is_set():
            with self._lock:
                n = self._count
            sys.stdout.write(f"\r  {next(frames)} {self.label}  [{n} requests]   ")
            sys.stdout.flush()
            time.sleep(0.1)

    def start(self):
        self._thread.start()

    def stop(self, final_label: str = ""):
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join()
        label = final_label or self.label
        with self._lock:
            n = self._count
        sys.stdout.write(f"\r  {GRN}✓{R} {label}  [{n} requests]          \n")
        sys.stdout.flush()


# ── Helpers ───────────────────────────────────────────────────────────────────

def status(icon: str, msg: str, color: str = ""):
    print(f"  {color}{icon}{R}  {msg}")


def section(title: str):
    width = 62
    print(f"\n{DIM}{'─' * width}{R}")
    print(f"  {BOLD}{title}{R}")
    print(f"{DIM}{'─' * width}{R}")


def build_session(args) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
    })
    if args.token:
        s.headers["Authorization"] = (
            args.token if args.token.startswith("Bearer ") else f"Bearer {args.token}"
        )
    if args.cookie:
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                name, _, value = pair.partition("=")
                s.cookies.set(name.strip(), value.strip())
    s.verify = not args.no_verify
    return s


# ── Summary box ───────────────────────────────────────────────────────────────

def print_summary(target, idor_result, crawl_result, auth_info, report_files):
    """Print the final nutshell findings box."""
    findings  = idor_result.findings
    n_crit    = sum(1 for f in findings if f.severity == "CRITICAL")
    n_high    = sum(1 for f in findings if f.severity == "HIGH")
    n_med     = sum(1 for f in findings if f.severity == "MEDIUM")
    n_low     = sum(1 for f in findings if f.severity in ("LOW", "INFO"))
    n_total   = len(findings)

    W = 66
    bar = "═" * W

    print(f"\n{BOLD}╔{bar}╗")
    print(f"║{'FINDINGS SUMMARY':^{W}}║")
    print(f"╚{bar}╝{R}")

    # ── Scan stats ────────────────────────────────────────────────────────────
    pages = getattr(crawl_result, "pages_crawled", 0) if crawl_result else 0
    eps   = getattr(crawl_result, "endpoints", []) if crawl_result else []
    print(f"\n  Target   : {BOLD}{target}{R}")
    print(f"  Auth     : {auth_info.get('scheme', 'none detected')}")
    print(f"  Scanned  : {idor_result.endpoints_tested} endpoint×ID combos"
          f"  |  {pages} pages crawled  |  {len(eps)} API endpoints found")

    # ── Verdict ───────────────────────────────────────────────────────────────
    print()
    if n_total == 0:
        print(f"  {GRN}{BOLD}VERDICT: CLEAN{R}  — No key exposure findings detected.")
        print(f"  {DIM}(A clean result does not guarantee the target is fully secure.){R}")
    else:
        verdict_color = RED if n_crit else YEL if n_high else BLU
        parts = []
        if n_crit: parts.append(f"{RED}{n_crit} critical{R}")
        if n_high: parts.append(f"{YEL}{n_high} high{R}")
        if n_med:  parts.append(f"{BLU}{n_med} medium{R}")
        if n_low:  parts.append(f"{GRN}{n_low} low/info{R}")
        print(f"  {verdict_color}{BOLD}VERDICT: VULNERABLE{R}  ({', '.join(parts)})")

    # ── Per-finding detail ────────────────────────────────────────────────────
    if findings:
        print(f"\n  {BOLD}Findings:{R}")
        grouped = {}
        for f in findings:
            grouped.setdefault(f.severity, []).append(f)

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if sev not in grouped:
                continue
            col = SEV_COLOR.get(sev, "")
            for f in grouped[sev]:
                tag = f"[{sev}]"
                # Title line
                if f.keys_found:
                    kind = f.keys_found[0].get("type_name", "Unknown key type")
                    title = f"Key exposed — {kind}"
                elif f.differential:
                    title = "IDOR candidate — response deviates from baseline"
                else:
                    title = "Crypto fields in response — review for key exposure"

                print(f"\n  {col}{BOLD}{tag}{R}  {title}")
                print(f"         URL      : {f.endpoint}")
                print(f"         ID tried : {f.reference_id}")
                print(f"         Evidence : {f.evidence}")

                if f.keys_found:
                    for k in f.keys_found:
                        print(f"         Key type : {k.get('type_name','?')}  →  {k.get('redacted','REDACTED')}")

                # Fix hint
                if sev == "CRITICAL" and f.keys_found:
                    print(f"         {YEL}Fix      : Never return raw key material in API responses.{R}")
                    print(f"                    Add ownership check: verify requesting user owns this resource.")
                elif f.differential:
                    print(f"         {YEL}Fix      : Add object-level authorization on this endpoint.{R}")
                elif sev == "MEDIUM":
                    print(f"         {YEL}Fix      : Audit this endpoint — crypto fields returned without auth check.{R}")

    # ── Discovered key-related endpoints ─────────────────────────────────────
    if crawl_result:
        key_eps = [e for e in crawl_result.endpoints if e.key_related]
        if key_eps:
            print(f"\n  {BOLD}Key-related endpoints (manual review recommended):{R}")
            for ep in key_eps[:12]:          # cap display at 12
                auth_tag = f"  {YEL}[AUTH REQUIRED]{R}" if ep.auth_required else ""
                ok_col   = GRN if ep.status_code == 200 else DIM
                print(f"    {ok_col}HTTP {ep.status_code}{R}  {ep.url}{auth_tag}")
            if len(key_eps) > 12:
                print(f"    {DIM}… and {len(key_eps)-12} more — see report{R}")

    # ── GraphQL note ──────────────────────────────────────────────────────────
    for note in auth_info.get("notes", []):
        print(f"\n  {YEL}[!]{R} {note}")

    # ── Report files ─────────────────────────────────────────────────────────
    if report_files:
        print(f"\n  {BOLD}Reports saved:{R}")
        for label, path in report_files:
            print(f"    {label:5}  {path}")

    print(f"\n{DIM}{'─' * (W + 2)}{R}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Crypto Vulnerability Tester — IDOR & Key Exposure Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target",    required=True,
                        help="Target base URL  e.g. https://example.com")
    parser.add_argument("--id",        dest="seed_id", type=int, default=None,
                        help="Optional anchor ID seen on a public page")
    parser.add_argument("--token",     default=None,
                        help="Optional Bearer token / API key")
    parser.add_argument("--cookie",    default=None,
                        help="Optional session cookie  e.g. 'session=abc123'")
    parser.add_argument("--max-ids",   type=int, default=30,
                        help="IDs to enumerate per endpoint (default 30)")
    parser.add_argument("--delay",     type=float, default=0.3,
                        help="Seconds between requests (default 0.3)")
    parser.add_argument("--no-crawl",  action="store_true",
                        help="Skip crawling — test patterns only")
    parser.add_argument("--output-dir",default="reports",
                        help="Report output directory (default ./reports)")
    parser.add_argument("--no-html",   action="store_true")
    parser.add_argument("--no-json",   action="store_true")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable SSL verification")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Skip authorization confirmation")
    parser.add_argument("--verbose","-v", action="store_true")
    parser.add_argument("--auto-retry", type=int, default=0, metavar="N",
                        help="Auto-retry up to N times if the scan fails or hangs (default: 0)")
    parser.add_argument("--retry-delay", type=float, default=30.0, metavar="SECS",
                        help="Seconds to wait between retries (default: 30)")
    args = parser.parse_args()

    target = args.target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    print(BANNER)

    # Authorization gate
    if not args.yes:
        print(AUTH_NOTICE)
        print(f"  Target: {BOLD}{target}{R}\n")
        ans = input("  Confirm you have written authorization to test this target [yes/NO]: ").strip().lower()
        if ans not in ("yes", "y"):
            print("\n  Aborted.\n")
            sys.exit(1)
        print()

    max_attempts = 1 + max(0, args.auto_retry)
    last_exit_code = 0

    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            print(f"\n{YEL}  ↻ Retry {attempt - 1}/{args.auto_retry} — waiting {args.retry_delay:.0f}s …{R}\n")
            time.sleep(args.retry_delay)

        last_exit_code = _run_scan(args, target)

        if last_exit_code != 3:   # 3 = scan aborted / incomplete
            break
        if attempt == max_attempts:
            print(f"\n{RED}  ✗ All {args.auto_retry} retries exhausted.{R}\n")

    sys.exit(last_exit_code if last_exit_code != 3 else 1)


def _run_scan(args, target) -> int:
    """
    Execute one full scan pass.
    Returns:  0 = clean, 1 = findings, 2 = critical findings, 3 = scan incomplete/crashed.
    """
    session  = build_session(args)
    reporter = Reporter(output_dir=args.output_dir)

    # ── 1. Reachability ───────────────────────────────────────────────────────
    sys.stdout.write(f"  {'·'} Checking reachability ...")
    sys.stdout.flush()
    try:
        resp = session.get(target, timeout=(6, 10))
        crypto_hint = any(
            kw in resp.text.lower()
            for kw in ("blockchain", "wallet", "crypto", "private key", "mnemonic")
        )
        hint_str = f"  {GRN}(crypto indicators found){R}" if crypto_hint else ""
        sys.stdout.write(f"\r  {GRN}✓{R} Reachable  HTTP {resp.status_code}{hint_str}                  \n")
        sys.stdout.flush()
    except requests.exceptions.RequestException as e:
        sys.stdout.write(f"\r  {RED}✗{R} Cannot reach target: {e}\n")
        return 3

    # ── 2. Endpoint discovery ─────────────────────────────────────────────────
    crawl_result = None
    auth_info    = {"scheme": "none", "notes": []}

    if not args.no_crawl:
        sys.stdout.write(f"  {'·'} Discovering endpoints ...")
        sys.stdout.flush()
        crawler = APICrawler(session=session, delay=args.delay * 0.6, max_pages=30)
        auth_info    = crawler.detect_auth_scheme(target)
        crawl_result = crawler.crawl(target)
        wordlist_hits = crawler.wordlist_fuzz(target)
        crawl_result.endpoints.extend(wordlist_hits)
        key_ep_count = len([e for e in crawl_result.endpoints if e.key_related])
        sys.stdout.write(
            f"\r  {GRN}✓{R} Endpoints  "
            f"{crawl_result.pages_crawled} pages | "
            f"{len(crawl_result.endpoints)} endpoints found | "
            f"{key_ep_count} key-related"
            f"                        \n"
        )
        sys.stdout.flush()
        if auth_info.get("scheme") != "none":
            status("·", f"Auth scheme detected: {auth_info['scheme']}", DIM)
    else:
        status("·", "Endpoint discovery skipped (--no-crawl)", DIM)

    # ── 3. IDOR scan ──────────────────────────────────────────────────────────
    n_patterns = len([p for p in KEY_ENDPOINT_PATTERNS if p != "/graphql"])
    scanner    = IDORScanner(
        session=session,
        delay=args.delay,
        max_ids=args.max_ids,
        verbose=args.verbose,
    )

    spinner = Spinner(f"Scanning {n_patterns} endpoint patterns × {args.max_ids} IDs")
    spinner.start()

    # Patch scanner to tick the spinner on each request
    _orig_test = scanner._test_endpoint
    def _tracked_test(base_url, pattern, obj_id, baseline):
        spinner.increment()
        return _orig_test(base_url, pattern, obj_id, baseline)
    scanner._test_endpoint = _tracked_test

    # ── Signal handler: save partial results on SIGINT/SIGTERM ────────────────
    _scan_interrupted = threading.Event()

    def _handle_signal(signum, frame):
        _scan_interrupted.set()
        spinner.stop("Scan interrupted — saving partial results …")
        # Save whatever findings exist so far
        partial = scanner._partial_result if hasattr(scanner, "_partial_result") else None
        if partial and (partial.findings or partial.endpoints_tested > 0):
            _save_reports(args, reporter, target, partial, crawl_result, auth_info, partial=True)
        sys.exit(1)

    old_sigint  = signal.signal(signal.SIGINT,  _handle_signal)
    old_sigterm = signal.signal(signal.SIGTERM, _handle_signal)

    try:
        t0          = time.time()
        idor_result = scanner.scan(target, seed_id=args.seed_id)
        elapsed     = time.time() - t0
    except Exception as e:
        spinner.stop(f"Scan error: {e}")
        # Restore signals
        signal.signal(signal.SIGINT,  old_sigint)
        signal.signal(signal.SIGTERM, old_sigterm)
        partial = getattr(scanner, "_partial_result", None)
        if partial and (partial.findings or partial.endpoints_tested > 0):
            print(f"\n  {YEL}[!]{R} Saving partial results from {partial.endpoints_tested} probes tested so far …")
            _save_reports(args, reporter, target, partial, crawl_result, auth_info, partial=True)
        return 3
    finally:
        signal.signal(signal.SIGINT,  old_sigint)
        signal.signal(signal.SIGTERM, old_sigterm)

    spinner.stop(f"IDOR scan complete  ({elapsed:.1f}s)")

    # ── 4. Reports ────────────────────────────────────────────────────────────
    report_files = _save_reports(args, reporter, target, idor_result, crawl_result, auth_info)

    # ── Summary ───────────────────────────────────────────────────────────────
    print_summary(target, idor_result, crawl_result, auth_info, report_files)

    n_crit = sum(1 for f in idor_result.findings if f.severity == "CRITICAL")
    return 2 if n_crit else 1 if idor_result.findings else 0


def _save_reports(args, reporter, target, idor_result, crawl_result, auth_info, partial=False):
    tag = " (partial)" if partial else ""
    sys.stdout.write(f"  {'·'} Saving reports{tag} ...")
    sys.stdout.flush()
    report_files = []
    if not args.no_json:
        p = reporter.save_json(target, idor_result, crawl_result, auth_info)
        report_files.append(("JSON", p))
    if not args.no_html:
        p = reporter.save_html(target, idor_result, crawl_result, auth_info)
        report_files.append(("HTML", p))
    sys.stdout.write(f"\r  {GRN}✓{R} Reports saved{tag}                              \n")
    sys.stdout.flush()
    return report_files


if __name__ == "__main__":
    main()
