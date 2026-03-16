#!/usr/bin/env python3
"""
KittyPaw Scanner — Crypto Vulnerability Testing Engine
Repo  : https://github.com/goldencloudsx3/GitSheild
Alerts: t.me/Kittypawscannerbot

Modules: IDOR · Key Exposure · JWT · Security Headers · Token Entropy
Platforms: Immunefi · Code4rena · HackerOne · Bugcrowd · Sherlock · Any web3 target

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

import os
import sys
import argparse
import time
import threading
import itertools
import signal
import random

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from modules.idor_scanner    import IDORScanner, KEY_ENDPOINT_PATTERNS
from modules.crawler         import APICrawler
from modules.reporter        import Reporter
from modules.jwt_analyzer    import JWTAnalyzer
from modules.header_analyzer import HeaderAnalyzer
from modules.token_analyzer  import TokenAnalyzer

# Telegram is optional — imported lazily so missing token doesn't break scan
_TelegramNotifier = None

# ── ANSI colours ───────────────────────────────────────────────────────────────
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

_BW = 56
BANNER = (
    f"\n{GRN}{BOLD}"
    f"  ╔{'═'*_BW}╗\n"
    f"  ║{'K I T T Y P A W   S C A N N E R':^{_BW}}║\n"
    f"  ║{'─'*_BW}║\n"
    f"  ║{'IDOR · KEY-EXPOSURE · JWT · HEADERS · TOKENS':^{_BW}}║\n"
    f"  ║{'github.com/goldencloudsx3/GitSheild':^{_BW}}║\n"
    f"  ╚{'═'*_BW}╝{R}\n"
    f"  {DIM}{'[ authorized security testing only ]':^{_BW+4}}{R}\n"
)

# ── User-Agent pool (rotate to avoid trivial UA-based blocking) ────────────────
_USER_AGENTS = [
    # Chrome on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Safari on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
]


def _random_ua() -> str:
    return random.choice(_USER_AGENTS)


# ── Spinner ────────────────────────────────────────────────────────────────────

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


# ── Helpers ────────────────────────────────────────────────────────────────────

def status(icon: str, msg: str, color: str = ""):
    print(f"  {color}{icon}{R}  {msg}")


def section(title: str):
    width = 62
    print(f"\n{CYAN}  ▸ {BOLD}{title}{R}")
    print(f"{DIM}  {'╌'*width}{R}")


def build_session(args) -> requests.Session:
    """
    Build a requests Session with:
    - Rotating User-Agent on first build
    - Optional Bearer token / cookie
    - Optional 403-bypass headers (--bypass-headers flag)
    - Optional proxy (--proxy)
    - SSL verification toggle
    """
    s = requests.Session()
    s.headers.update({
        "User-Agent":      _random_ua(),
        "Accept":          "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        # Pretend we're a real browser navigation
        "Sec-Fetch-Dest":  "empty",
        "Sec-Fetch-Mode":  "cors",
        "Sec-Fetch-Site":  "same-origin",
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

    # ── 403 bypass headers (common WAF/CDN evasion technique) ─────────────────
    # These headers are widely documented in public bug-bounty write-ups and
    # OWASP testing guides.  They instruct WAFs/proxies to treat the request
    # as originating from localhost / an internal network.
    if getattr(args, "bypass_headers", False):
        s.headers.update({
            "X-Forwarded-For":          "127.0.0.1",
            "X-Originating-IP":         "127.0.0.1",
            "X-Remote-IP":              "127.0.0.1",
            "X-Remote-Addr":            "127.0.0.1",
            "X-Client-IP":              "127.0.0.1",
            "X-Host":                   "127.0.0.1",
            "X-Forwarded-Host":         "localhost",
            "X-Custom-IP-Authorization":"127.0.0.1",
        })
        status("[bypass]", "403-bypass headers active (X-Forwarded-For etc.)", YEL)

    # ── Proxy support (Burp Suite / mitmproxy) ─────────────────────────────────
    proxy_url = getattr(args, "proxy", None)
    if proxy_url:
        s.proxies = {"http": proxy_url, "https": proxy_url}
        status("[proxy]", f"Routing through {proxy_url}", YEL)

    s.verify = not getattr(args, "no_verify", False)
    return s


# ── Session request wrapper with 429 backoff ──────────────────────────────────

def _patched_get(session: requests.Session, tg=None, target: str = ""):
    """
    Wrap session.get to transparently handle:
      - HTTP 429 Too Many Requests  → exponential backoff (up to 4 retries)
      - requests.exceptions.ConnectionError → short retry
      - requests.exceptions.ChunkedEncodingError → graceful None return
    """
    original_get = session.get

    def _get(url, **kwargs):
        backoff = 5.0
        for attempt in range(5):
            try:
                resp = original_get(url, **kwargs)
                if resp.status_code == 429:
                    retry_after = float(resp.headers.get("Retry-After", backoff))
                    retry_after = min(retry_after, 120)   # cap at 2 min
                    print(f"\n  {YEL}[429]{R} Rate limited → waiting {retry_after:.0f}s  ({url[:60]})")
                    if tg:
                        tg.send_rate_limited(target, url, retry_after)
                    time.sleep(retry_after)
                    backoff = min(backoff * 2, 120)
                    # Rotate User-Agent on retry
                    session.headers["User-Agent"] = _random_ua()
                    continue
                return resp
            except requests.exceptions.ChunkedEncodingError:
                return None
            except requests.exceptions.ConnectionError as e:
                if attempt < 2:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                return None
            except requests.exceptions.RequestException:
                return None
        return None

    session.get = _get
    return session


# ── Extra findings printer (headers / JWT / tokens) ───────────────────────────

def _print_extra_findings(section_title: str, findings: list):
    print(f"\n  {BOLD}{section_title}:{R}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        col = SEV_COLOR.get(sev, "")
        for f in group:
            print(f"\n  {col}{BOLD}[{sev}]{R}  {f.title}")
            print(f"         {f.description}")
            print(f"         {DIM}Evidence     :{R} {f.evidence}")
            print(f"         {YEL}Recommendation:{R} {f.recommendation}")


# ── Summary box ───────────────────────────────────────────────────────────────

def print_summary(
    target, idor_result, crawl_result, auth_info, report_files,
    header_result=None, jwt_result=None, token_result=None,
):
    findings  = idor_result.findings
    n_crit    = sum(1 for f in findings if f.severity == "CRITICAL")
    n_high    = sum(1 for f in findings if f.severity == "HIGH")
    n_med     = sum(1 for f in findings if f.severity == "MEDIUM")
    n_low     = sum(1 for f in findings if f.severity in ("LOW", "INFO"))
    n_total   = len(findings)

    W   = 66
    bar = "═" * W

    print(f"\n{GRN}{BOLD}╔{bar}╗")
    print(f"║{'◈  KITTYPAW SCAN COMPLETE  ·  FINDINGS SUMMARY  ◈':^{W}}║")
    print(f"╚{bar}╝{R}")

    pages = getattr(crawl_result, "pages_crawled", 0) if crawl_result else 0
    eps   = getattr(crawl_result, "endpoints", [])    if crawl_result else []
    print(f"\n  Target   : {BOLD}{target}{R}")
    print(f"  Auth     : {auth_info.get('scheme', 'none detected')}")
    challenge_skipped = getattr(idor_result, "challenge_pages_skipped", 0)
    challenge_note = (
        f"  |  {YEL}{challenge_skipped} bot-challenge page(s) suppressed{R}"
        if challenge_skipped else ""
    )
    print(f"  Scanned  : {idor_result.endpoints_tested} endpoint×ID combos"
          f"  |  {pages} pages crawled  |  {len(eps)} API endpoints found"
          f"{challenge_note}")

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
                        fp_note   = k.get("false_positive_note", "")
                        validated = k.get("validated")
                        val_tag   = (
                            f"  {GRN}[✔ CHECKSUM OK]{R}"  if validated is True
                            else f"  {YEL}[✘ CHECKSUM FAIL — likely false positive]{R}" if validated is False
                            else ""
                        )
                        print(f"         Key type : {k.get('type_name','?')}  →  {k.get('redacted','REDACTED')}{val_tag}")
                        if fp_note:
                            print(f"         {YEL}Note     : {fp_note}{R}")

                if f.false_positive_risk:
                    print(f"         {MAG}[FP RISK] : {f.false_positive_risk}{R}")

                if sev == "CRITICAL" and f.keys_found:
                    print(f"         {YEL}Fix      : Never return raw key material in API responses.{R}")
                    print(f"                    Add ownership check: verify requesting user owns this resource.")
                elif f.differential:
                    print(f"         {YEL}Fix      : Add object-level authorization on this endpoint.{R}")
                elif sev == "MEDIUM":
                    print(f"         {YEL}Fix      : Audit this endpoint — crypto fields returned without auth check.{R}")

    if crawl_result:
        key_eps = [e for e in crawl_result.endpoints if e.key_related]
        if key_eps:
            print(f"\n  {BOLD}Key-related endpoints (manual review recommended):{R}")
            for ep in key_eps[:12]:
                auth_tag = f"  {YEL}[AUTH REQUIRED]{R}" if ep.auth_required else ""
                ok_col   = GRN if ep.status_code == 200 else DIM
                print(f"    {ok_col}HTTP {ep.status_code}{R}  {ep.url}{auth_tag}")
            if len(key_eps) > 12:
                print(f"    {DIM}… and {len(key_eps)-12} more — see report{R}")

    for note in auth_info.get("notes", []):
        print(f"\n  {YEL}[!]{R} {note}")

    # PEM key confirmation steps
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

    if n_crit > 0:
        print(f"\n  {GRN}{BOLD}◈  FINAL CHECKLIST — Before Submitting Any Bug Report{R}")
        print(f"  {DIM}{'╌'*62}{R}")
        _checklist = [
            ("Captured real API traffic (not guesses)",       True),
            ("Tested on actual working endpoints",             True),
            ("Got real data back (not error messages)",        True),
            ("Screenshot proof captured",                      True),
            ("CIA triad impact demonstrated:",                 True),
            ("  Confidentiality  →  Data accessed",           False),
            ("  Integrity        →  Data modified",           False),
            ("  Availability     →  Service disrupted",       False),
            ("Report is under 1000 words",                     True),
            ("Steps are reproducible by anyone",               True),
            ("Impact is shown, not theorized",                 True),
        ]
        for item, show_box in _checklist:
            prefix = f"  {DIM}□{R} " if show_box else "      "
            print(f"  {prefix}{item}")
        print(f"\n  {DIM}If you can't check all these boxes — keep testing.{R}")

    if header_result and header_result.findings:
        _print_extra_findings("Security Header Findings", header_result.findings)

    if jwt_result and jwt_result.findings:
        _print_extra_findings("JWT Vulnerability Findings", jwt_result.findings)

    if token_result and token_result.findings:
        _print_extra_findings("Token & Password Hash Findings", token_result.findings)

    if report_files:
        print(f"\n  {BOLD}Reports saved:{R}")
        for label, path in report_files:
            print(f"    {label:5}  {path}")

    print(f"\n{GRN}{DIM}{'═' * (W + 2)}{R}\n")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    # Load .env if python-dotenv is available (silently skip if not installed)
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    parser = argparse.ArgumentParser(
        description="KittyPaw Scanner — IDOR, Key Exposure, JWT & Header Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python crypto_vuln_tester.py --target https://example.com\n"
            "  python crypto_vuln_tester.py --target https://example.com --bypass-headers\n"
            "  python crypto_vuln_tester.py --target https://example.com "
            "--telegram-token 123:ABC --telegram-chat-id -100xxx\n"
        ),
    )
    # ── Target ────────────────────────────────────────────────────────────────
    parser.add_argument("--target",    required=True,
                        help="Target base URL  e.g. https://example.com")
    parser.add_argument("--id",        dest="seed_id", type=int, default=None,
                        help="Optional anchor ID seen on a public page")
    # ── Auth ──────────────────────────────────────────────────────────────────
    parser.add_argument("--token",     default=None,
                        help="Optional Bearer token / API key")
    parser.add_argument("--cookie",    default=None,
                        help="Optional session cookie  e.g. 'session=abc123'")
    # ── Scan tuning ───────────────────────────────────────────────────────────
    parser.add_argument("--max-ids",   type=int, default=30,
                        help="IDs to enumerate per endpoint (default 30)")
    parser.add_argument("--delay",     type=float, default=0.3,
                        help="Base seconds between requests (default 0.3)")
    parser.add_argument("--timeout",   type=float, default=10.0,
                        help="Per-request read timeout in seconds (default 10)")
    parser.add_argument("--no-crawl",  action="store_true",
                        help="Skip crawling — test patterns only")
    parser.add_argument("--no-headers",action="store_true",
                        help="Skip HTTP security header analysis")
    parser.add_argument("--no-jwt",    action="store_true",
                        help="Skip JWT vulnerability analysis")
    parser.add_argument("--no-tokens", action="store_true",
                        help="Skip token entropy / password-hash analysis")
    # ── Bypass & evasion ──────────────────────────────────────────────────────
    parser.add_argument("--bypass-headers", action="store_true",
                        help="Add X-Forwarded-For/X-Custom-IP-Authorization bypass headers")
    parser.add_argument("--proxy",     default=None, metavar="URL",
                        help="HTTP proxy  e.g. http://127.0.0.1:8080  (Burp Suite)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable SSL certificate verification")
    # ── Output ────────────────────────────────────────────────────────────────
    parser.add_argument("--output-dir",default="reports",
                        help="Report output directory (default ./reports)")
    parser.add_argument("--no-html",   action="store_true")
    parser.add_argument("--no-json",   action="store_true")
    # ── Telegram alerts ───────────────────────────────────────────────────────
    parser.add_argument("--telegram-token",   default=None, metavar="TOKEN",
                        help="Telegram bot token (or set TELEGRAM_TOKEN env var)")
    parser.add_argument("--telegram-chat-id", default=None, metavar="CHAT_ID",
                        help="Telegram chat ID (or set TELEGRAM_CHAT_ID env var)")
    # ── UX ────────────────────────────────────────────────────────────────────
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Skip authorization confirmation")
    parser.add_argument("--verbose","-v", action="store_true")
    parser.add_argument("--auto-retry", type=int, default=0, metavar="N",
                        help="Auto-retry up to N times if the scan fails (default: 0)")
    parser.add_argument("--retry-delay", type=float, default=30.0, metavar="SECS",
                        help="Seconds to wait between retries (default: 30)")
    args = parser.parse_args()

    target = args.target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    print(BANNER)

    # ── Telegram setup ────────────────────────────────────────────────────────
    tg = None
    tg_token   = args.telegram_token   or os.environ.get("TELEGRAM_TOKEN",   "")
    tg_chat_id = args.telegram_chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")

    if tg_token and tg_chat_id:
        from modules.telegram_notifier import TelegramNotifier
        tg = TelegramNotifier(token=tg_token, chat_id=tg_chat_id)
        tg.test()
    elif tg_token or tg_chat_id:
        print(f"  {YEL}[!]{R} Telegram: provide BOTH --telegram-token AND --telegram-chat-id to enable alerts.\n")
    else:
        print(f"  {DIM}ℹ  Telegram alerts disabled (no token/chat-id set){R}")

    # ── Authorization gate ────────────────────────────────────────────────────
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

        last_exit_code = _run_scan(args, target, tg=tg)

        if last_exit_code != 3:
            break
        if attempt == max_attempts:
            print(f"\n{RED}  ✘ {BOLD}ALL RETRIES EXHAUSTED{R}{RED}  ({args.auto_retry} attempts).{R}\n")

    sys.exit(last_exit_code if last_exit_code != 3 else 1)


def _run_scan(args, target, tg=None) -> int:
    """
    Execute one full scan pass.
    Returns: 0=clean, 1=findings, 2=critical findings, 3=scan incomplete/crashed.
    """
    session  = build_session(args)
    # Patch session.get for 429 backoff and connection-error handling
    session  = _patched_get(session, tg=tg, target=target)
    reporter = Reporter(output_dir=args.output_dir)

    if tg:
        tg.send_scan_start(target)

    t_scan_start = time.time()

    # ── 1. Reachability ───────────────────────────────────────────────────────
    sys.stdout.write(f"  {DIM}◌{R} Checking reachability ...")
    sys.stdout.flush()
    try:
        resp = session.get(target, timeout=(6, getattr(args, "timeout", 10)))
        if resp is None:
            raise requests.exceptions.ConnectionError("No response returned")
        crypto_hint = any(
            kw in resp.text.lower()
            for kw in ("blockchain", "wallet", "crypto", "private key", "mnemonic",
                       "defi", "nft", "token", "solana", "ethereum", "web3")
        )
        hint_str = f"  {CYAN}(crypto indicators found){R}" if crypto_hint else ""
        sys.stdout.write(f"\r  {GRN}◉{R} {BOLD}REACHABLE{R}  HTTP {resp.status_code}{hint_str}                  \n")
        sys.stdout.flush()
    except Exception as e:
        sys.stdout.write(f"\r  {RED}✘{R} {BOLD}UNREACHABLE{R}  {e}\n")
        # Offer SSL hint
        if "SSL" in str(e) or "certificate" in str(e).lower():
            print(f"  {YEL}[tip]{R} SSL error — try adding  --no-verify  to skip cert checks.")
        if tg:
            tg.send_error(target, str(e))
        return 3

    # ── 2. Endpoint discovery ─────────────────────────────────────────────────
    crawl_result = None
    auth_info    = {"scheme": "none", "notes": []}

    if not args.no_crawl:
        sys.stdout.write(f"  {DIM}◌{R} Discovering endpoints ...")
        sys.stdout.flush()
        try:
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
        except Exception as e:
            sys.stdout.write(f"\r  {YEL}[!]{R} Crawl error (continuing): {e}\n")
            crawl_result = None
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

    _orig_test = scanner._test_endpoint

    def _tracked_test(base_url, pattern, obj_id, baseline):
        spinner.increment()
        finding = _orig_test(base_url, pattern, obj_id, baseline)
        # Real-time Telegram alert for CRITICAL/HIGH findings
        if finding and tg:
            tg.send_finding(finding)
        return finding

    scanner._test_endpoint = _tracked_test

    _scan_interrupted = threading.Event()

    def _handle_signal(signum, frame):
        _scan_interrupted.set()
        spinner.stop("Scan interrupted — saving partial results …")
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
        signal.signal(signal.SIGINT,  old_sigint)
        signal.signal(signal.SIGTERM, old_sigterm)
        partial = getattr(scanner, "_partial_result", None)
        if partial and (partial.findings or partial.endpoints_tested > 0):
            print(f"\n  {YEL}[!]{R} Saving partial results …")
            _save_reports(args, reporter, target, partial, crawl_result, auth_info, partial=True)
        if tg:
            tg.send_error(target, str(e))
        return 3
    finally:
        signal.signal(signal.SIGINT,  old_sigint)
        signal.signal(signal.SIGTERM, old_sigterm)

    spinner.stop(f"IDOR scan complete  ({elapsed:.1f}s)")

    # ── 4. Security header analysis ───────────────────────────────────────────
    header_result = None
    if not args.no_headers:
        sys.stdout.write(f"  {DIM}◌{R} Analysing security headers ...")
        sys.stdout.flush()
        try:
            header_result = HeaderAnalyzer(session=session).analyze(target)
            n_hdr = len(header_result.findings)
            # Real-time Telegram alert for header findings
            if tg and header_result:
                for hf in header_result.findings:
                    tg.send_header_finding(hf)
            sys.stdout.write(
                f"\r  {GRN}◉{R} {BOLD}HEADERS{R}  "
                f"{header_result.headers_checked} checked · "
                f"{CYAN}{n_hdr} finding(s){R}"
                f"                          \n"
            )
        except Exception as e:
            sys.stdout.write(f"\r  {YEL}[!]{R} Header analysis error (continuing): {e}\n")
        sys.stdout.flush()
    else:
        status("·", "Security header analysis skipped (--no-headers)", DIM)

    # ── 5. JWT vulnerability analysis ─────────────────────────────────────────
    jwt_result = None
    if not args.no_jwt:
        sys.stdout.write(f"  {DIM}◌{R} Analysing JWT tokens ...")
        sys.stdout.flush()
        try:
            jwt_result = JWTAnalyzer(session=session, delay=args.delay).analyze(
                target, crawl_result=crawl_result
            )
            n_jwt = len(jwt_result.findings)
            if tg and jwt_result:
                for jf in jwt_result.findings:
                    tg.send_jwt_finding(jf)
            sys.stdout.write(
                f"\r  {GRN}◉{R} {BOLD}JWT{R}  "
                f"{jwt_result.tokens_found} token(s) found · "
                f"{CYAN}{n_jwt} finding(s){R}"
                f"                          \n"
            )
        except Exception as e:
            sys.stdout.write(f"\r  {YEL}[!]{R} JWT analysis error (continuing): {e}\n")
        sys.stdout.flush()
    else:
        status("·", "JWT analysis skipped (--no-jwt)", DIM)

    # ── 6. Token entropy & password-hash analysis ─────────────────────────────
    token_result = None
    if not args.no_tokens:
        sys.stdout.write(f"  {DIM}◌{R} Analysing tokens & password hashing ...")
        sys.stdout.flush()
        try:
            token_result = TokenAnalyzer(session=session, delay=args.delay).analyze(
                target, crawl_result=crawl_result
            )
            n_tok = len(token_result.findings)
            sys.stdout.write(
                f"\r  {GRN}◉{R} {BOLD}TOKENS{R}  "
                f"{token_result.tokens_sampled} endpoint(s) probed · "
                f"{CYAN}{n_tok} finding(s){R}"
                f"                          \n"
            )
        except Exception as e:
            sys.stdout.write(f"\r  {YEL}[!]{R} Token analysis error (continuing): {e}\n")
        sys.stdout.flush()
    else:
        status("·", "Token / hash analysis skipped (--no-tokens)", DIM)

    # ── 7. Reports ────────────────────────────────────────────────────────────
    report_files = _save_reports(
        args, reporter, target, idor_result, crawl_result, auth_info,
        header_result=header_result, jwt_result=jwt_result, token_result=token_result,
    )

    # ── Telegram summary ──────────────────────────────────────────────────────
    total_elapsed = time.time() - t_scan_start
    if tg:
        tg.send_summary(
            target, idor_result,
            header_result=header_result,
            jwt_result=jwt_result,
            token_result=token_result,
            report_files=report_files,
            elapsed=total_elapsed,
        )

    # ── Console summary ───────────────────────────────────────────────────────
    print_summary(
        target, idor_result, crawl_result, auth_info, report_files,
        header_result=header_result, jwt_result=jwt_result, token_result=token_result,
    )

    n_crit = sum(1 for f in idor_result.findings if f.severity == "CRITICAL")
    return 2 if n_crit else 1 if idor_result.findings else 0


def _save_reports(
    args, reporter, target, idor_result, crawl_result, auth_info,
    partial=False, header_result=None, jwt_result=None, token_result=None,
):
    tag = " (partial)" if partial else ""
    sys.stdout.write(f"  {DIM}◌{R} Saving reports{tag} ...")
    sys.stdout.flush()
    report_files = []
    try:
        if not args.no_json:
            p = reporter.save_json(
                target, idor_result, crawl_result, auth_info,
                header_result=header_result, jwt_result=jwt_result, token_result=token_result,
            )
            report_files.append(("JSON", p))
        if not args.no_html:
            p = reporter.save_html(
                target, idor_result, crawl_result, auth_info,
                header_result=header_result, jwt_result=jwt_result, token_result=token_result,
            )
            report_files.append(("HTML", p))
    except Exception as e:
        sys.stdout.write(f"\r  {YEL}[!]{R} Report save error: {e}\n")
        sys.stdout.flush()
        return report_files
    sys.stdout.write(f"\r  {GRN}◉{R} {BOLD}REPORTS SAVED{R}{tag}                              \n")
    sys.stdout.flush()
    return report_files


if __name__ == "__main__":
    main()
