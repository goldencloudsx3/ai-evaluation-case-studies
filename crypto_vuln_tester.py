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
R    = "\033[0m"
RED  = "\033[91m"
YEL  = "\033[93m"
BLU  = "\033[94m"
GRN  = "\033[92m"
CYAN = "\033[96m"
MAG  = "\033[95m"
DIM  = "\033[2m"
BOLD = "\033[1m"

SEV_COLOR = {"CRITICAL": RED, "HIGH": YEL, "MEDIUM": BLU, "LOW": GRN, "INFO": DIM}

_BW = 52
BANNER = (
    f"\n{GRN}{BOLD}"
    f"  ╔{'═'*_BW}╗\n"
    f"  ║{'C R Y P T O   V U L N   T E S T E R':^{_BW}}║\n"
    f"  ║{'─'*_BW}║\n"
    f"  ║{'IDOR  ·  KEY-EXPOSURE  ·  BLOCKCHAIN':^{_BW}}║\n"
    f"  ╚{'═'*_BW}╝{R}\n"
    f"  {DIM}{'[ authorized security testing only ]':^{_BW+4}}{R}\n"
)



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
        frames = itertools.cycle(["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"])
        while not self._stop.is_set():
            with self._lock:
                n = self._count
            sys.stdout.write(f"\r  {CYAN}{next(frames)}{R} {self.label}  {DIM}[{n:>5} req]{R}   ")
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
        sys.stdout.write(f"\r  {GRN}✔{R} {BOLD}{label}{R}  {DIM}[{n} req]{R}          \n")
        sys.stdout.flush()


# ── Helpers ───────────────────────────────────────────────────────────────────

def status(icon: str, msg: str, color: str = ""):
    print(f"  {color}{icon}{R}  {msg}")


def section(title: str):
    width = 62
    print(f"\n{CYAN}  ▸ {BOLD}{title}{R}")
    print(f"{DIM}  {'╌'*width}{R}")


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

    print(f"\n{GRN}{BOLD}╔{bar}╗")
    print(f"║{'◈  SCAN COMPLETE  ·  FINDINGS SUMMARY  ◈':^{W}}║")
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
        print(f"  {GRN}{BOLD}▶ VERDICT ◀  ACCESS SECURE{R}  — No key exposure findings detected.")
        print(f"  {DIM}(A clean result does not guarantee the target is fully secure.){R}")
    else:
        verdict_color = RED if n_crit else YEL if n_high else BLU
        parts = []
        if n_crit: parts.append(f"{RED}{n_crit} critical{R}")
        if n_high: parts.append(f"{YEL}{n_high} high{R}")
        if n_med:  parts.append(f"{BLU}{n_med} medium{R}")
        if n_low:  parts.append(f"{GRN}{n_low} low/info{R}")
        print(f"  {verdict_color}{BOLD}▶ VERDICT ◀  VULNERABLE{R}  ({', '.join(parts)})")

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
                        fp_note = k.get("false_positive_note", "")
                        validated = k.get("validated")
                        val_tag = (
                            f"  {GRN}[✔ CHECKSUM OK]{R}" if validated is True
                            else f"  {YEL}[✘ CHECKSUM FAIL — likely false positive]{R}" if validated is False
                            else ""
                        )
                        print(f"         Key type : {k.get('type_name','?')}  →  {k.get('redacted','REDACTED')}{val_tag}")
                        if fp_note:
                            print(f"         {YEL}Note     : {fp_note}{R}")

                # False positive risk banner
                if f.false_positive_risk:
                    print(f"         {MAG}[FP RISK] : {f.false_positive_risk}{R}")

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

    # ── OpenSSL key confirmation (HackerMD Phase 2 validation protocol) ───────
    pem_findings = [
        f for f in findings
        if f.keys_found and any(k.get("type") == "rsa_pem_key" for k in f.keys_found)
    ]
    if pem_findings:
        print(f"\n  {CYAN}{BOLD}◈  PEM KEY CONFIRMATION — OpenSSL Validation Steps{R}")
        print(f"  {DIM}{'╌'*62}{R}")
        print(f"  {DIM}# Phase 2: Validate the key is real before reporting{R}")
        print(f"  {YEL}  cat > extracted.key << 'EOF'{R}")
        print(f"  {DIM}  -----BEGIN RSA PRIVATE KEY-----{R}")
        print(f"  {DIM}  <paste key material here>{R}")
        print(f"  {DIM}  -----END RSA PRIVATE KEY-----{R}")
        print(f"  {YEL}  EOF{R}")
        print()
        print(f"  {YEL}  openssl rsa -in extracted.key -check -noout{R}"
              f"  {DIM}# → RSA key ok{R}")
        print(f"  {YEL}  openssl rsa -in extracted.key -text -noout{R} "
              f"  {DIM}# → shows bit-length, modulus, publicExponent{R}")
        print()
        print(f"  {DIM}  Confirmed real? Check if key signs JWT tokens:{R}")
        print(f"  {DIM}  Look for TRACK_PRIVATE_KEY / config objects in the same JS bundle{R}")
        print(f"  {DIM}  Find ACTUAL endpoints via DevTools → Network → XHR before testing{R}")

    # ── OPSEC endpoint discovery protocol (HackerMD Mistake #1) ──────────────
    if n_total > 0:
        print(f"\n  {CYAN}{BOLD}◈  OPSEC — Endpoint Discovery Protocol{R}")
        print(f"  {DIM}{'╌'*62}{R}")
        print(f"  {DIM}Do NOT guess routes. Capture real traffic instead:{R}")
        _steps = [
            "Open target website in browser",
            "DevTools → Network tab → Filter XHR / Fetch",
            "Perform real actions: login, trade, deposit",
            "Capture ACTUAL API calls from the traffic tab",
            "Test forged tokens ONLY on those real endpoints",
        ]
        for i, step in enumerate(_steps, 1):
            print(f"    {DIM}{i}.{R} {step}")
        print()
        print(f"  {DIM}HTTP 200 + {{\"msg\": \"route not found\"}} ≠ token accepted{R}")
        print(f"  {DIM}HTTP 200 + {{\"user_id\": ..., \"balance\": ...}}  = real exploitation{R}")

    # ── Final checklist (HackerMD — Before You Ever Report Again) ─────────────
    if n_crit > 0:
        print(f"\n  {GRN}{BOLD}◈  FINAL CHECKLIST — Before Submitting Any Bug Report{R}")
        print(f"  {DIM}{'╌'*62}{R}")
        _checklist = [
            ("Captured real API traffic (not guesses)",         True),
            ("Tested on actual working endpoints",               True),
            ("Got real data back (not error messages)",          True),
            ("Screenshot proof captured",                        True),
            ("CIA triad impact demonstrated:",                   True),
            ("  Confidentiality  →  Data accessed",             False),
            ("  Integrity        →  Data modified",             False),
            ("  Availability     →  Service disrupted",         False),
            ("Report is under 1000 words",                       True),
            ("Steps are reproducible by anyone",                 True),
            ("Impact is shown, not theorized",                   True),
        ]
        for item, show_box in _checklist:
            prefix = f"  {DIM}□{R} " if show_box else "      "
            print(f"  {prefix}{item}")
        print(f"\n  {DIM}If you can't check all these boxes — keep testing.{R}")

    # ── Report files ─────────────────────────────────────────────────────────
    if report_files:
        print(f"\n  {BOLD}Reports saved:{R}")
        for label, path in report_files:
            print(f"    {label:5}  {path}")

    print(f"\n{GRN}{DIM}{'═' * (W + 2)}{R}\n")


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
        print(f"  Target: {BOLD}{target}{R}\n")
        ans = input(f"  {CYAN}▸{R} Confirm written authorization to test this target {DIM}[yes/NO]{R}: ").strip().lower()
        if ans not in ("yes", "y"):
            print(f"\n  {RED}{BOLD}[ ABORTED ]{R}\n")
            sys.exit(1)
        print()

    max_attempts = 1 + max(0, args.auto_retry)
    last_exit_code = 0

    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            print(f"\n{CYAN}  ↺ {BOLD}RETRY {attempt - 1}/{args.auto_retry}{R}{CYAN} — waiting {args.retry_delay:.0f}s …{R}\n")
            time.sleep(args.retry_delay)

        last_exit_code = _run_scan(args, target)

        if last_exit_code != 3:   # 3 = scan aborted / incomplete
            break
        if attempt == max_attempts:
            print(f"\n{RED}  ✘ {BOLD}ALL RETRIES EXHAUSTED{R}{RED}  ({args.auto_retry} attempts).{R}\n")

    sys.exit(last_exit_code if last_exit_code != 3 else 1)


def _run_scan(args, target) -> int:
    """
    Execute one full scan pass.
    Returns:  0 = clean, 1 = findings, 2 = critical findings, 3 = scan incomplete/crashed.
    """
    session  = build_session(args)
    reporter = Reporter(output_dir=args.output_dir)

    # ── 1. Reachability ───────────────────────────────────────────────────────
    sys.stdout.write(f"  {DIM}◌{R} Checking reachability ...")
    sys.stdout.flush()
    try:
        resp = session.get(target, timeout=(6, 10))
        crypto_hint = any(
            kw in resp.text.lower()
            for kw in ("blockchain", "wallet", "crypto", "private key", "mnemonic")
        )
        hint_str = f"  {CYAN}(crypto indicators found){R}" if crypto_hint else ""
        sys.stdout.write(f"\r  {GRN}◉{R} {BOLD}REACHABLE{R}  HTTP {resp.status_code}{hint_str}                  \n")
        sys.stdout.flush()
    except requests.exceptions.RequestException as e:
        sys.stdout.write(f"\r  {RED}✘{R} {BOLD}UNREACHABLE{R}  {e}\n")
        return 3

    # ── 2. Endpoint discovery ─────────────────────────────────────────────────
    crawl_result = None
    auth_info    = {"scheme": "none", "notes": []}

    if not args.no_crawl:
        sys.stdout.write(f"  {DIM}◌{R} Discovering endpoints ...")
        sys.stdout.flush()
        crawler = APICrawler(session=session, delay=args.delay * 0.6, max_pages=30)
        auth_info    = crawler.detect_auth_scheme(target)
        crawl_result = crawler.crawl(target)
        wordlist_hits = crawler.wordlist_fuzz(target)
        crawl_result.endpoints.extend(wordlist_hits)
        key_ep_count = len([e for e in crawl_result.endpoints if e.key_related])
        sys.stdout.write(
            f"\r  {GRN}◉{R} {BOLD}ENDPOINTS{R}  "
            f"{crawl_result.pages_crawled} pages · "
            f"{len(crawl_result.endpoints)} found · "
            f"{CYAN}{key_ep_count} key-related{R}"
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
    sys.stdout.write(f"  {DIM}◌{R} Saving reports{tag} ...")
    sys.stdout.flush()
    report_files = []
    if not args.no_json:
        p = reporter.save_json(target, idor_result, crawl_result, auth_info)
        report_files.append(("JSON", p))
    if not args.no_html:
        p = reporter.save_html(target, idor_result, crawl_result, auth_info)
        report_files.append(("HTML", p))
    sys.stdout.write(f"\r  {GRN}◉{R} {BOLD}REPORTS SAVED{R}{tag}                              \n")
    sys.stdout.flush()
    return report_files


if __name__ == "__main__":
    main()
