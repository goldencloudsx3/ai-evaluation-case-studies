#!/usr/bin/env python3
"""
KittyPaw Scanner — Auto-Hunt CLI
Scrapes Immunefi bounty programs, finds their GitHub orgs,
and deep-scans repos for leaked secrets.

Usage:
  python3 autohunt.py                          # top 10 Immunefi targets
  python3 autohunt.py --org https://github.com/uniswap
  python3 autohunt.py --repo https://github.com/uniswap/v3-core
  python3 autohunt.py --max-repos 5 --no-external-tools

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

from __future__ import annotations

import os
import sys
import argparse
import logging
import time
from datetime import datetime, timezone
from typing import List, Optional

from dotenv import load_dotenv

load_dotenv()

from modules.immunefi_scraper   import ImmunefiScraper, BountyTarget
from modules.github_deep_scanner import GitHubDeepScanner, DeepScanResult
from modules.smart_prioritizer  import SmartPrioritizer, PrioritizedFinding
from modules.reporter           import Reporter
from modules.telegram_notifier  import TelegramNotifier

# ── ANSI ──────────────────────────────────────────────────────────────────────
R    = "\033[0m"
RED  = "\033[91m"
YEL  = "\033[93m"
GRN  = "\033[92m"
CYAN = "\033[96m"
MAG  = "\033[95m"
BOLD = "\033[1m"
DIM  = "\033[2m"

SEV_ICON = {"CRITICAL": f"{RED}🔴{R}", "HIGH": f"{YEL}🟠{R}",
            "MEDIUM": f"{CYAN}🟡{R}", "LOW": f"{GRN}🟢{R}", "INFO": f"{DIM}⚪{R}"}

_W = 62

BANNER = f"""\n{CYAN}{BOLD}  ╔══════════════════════════════════════════════════════════════╗
  ║                                                              ║
  ║     /\\_____/\\    K I T T Y P A W   S C A N N E R              ║
  ║    /  o   o  \\   ─────────────────────────────────            ║
  ║   ( ==  ^  == )  IDOR · KEY-EXPOSURE · JWT                    ║
  ║    )  =====  (   HEADERS · TOKENS · WEB3                      ║
  ║   (    ___    )  ─────────────────────────────────            ║
  ║    \\___|_|___/   t.me/Kittypawscannerbot                      ║
  ║        | |       Immunefi · HackerOne · Bugcrowd              ║
  ║       _| |_      [ authorized testing only ]                  ║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝{R}\n"""


def _sec(title: str) -> None:
    print(f"\n{CYAN}  ▸ {BOLD}{title}{R}")
    print(f"{DIM}  {'╌'*_W}{R}")


def _status(icon: str, msg: str, color: str = "") -> None:
    print(f"  {color}{icon}{R}  {msg}")


def _print_finding(pf: PrioritizedFinding, idx: int) -> None:
    icon = SEV_ICON.get(pf.severity, "  ")
    ver  = f" {GRN}[VERIFIED]{R}" if pf.verified else ""
    print(f"  {icon}{ver}  {BOLD}{pf.severity}{R}  score={pf.score}")
    print(f"       {DIM}repo:{R} {pf.repo_or_url}")
    print(f"       {DIM}loc :{R} {pf.location}")
    print(f"       {DIM}desc:{R} {pf.description}")
    if pf.redacted:
        print(f"       {DIM}hint:{R} {pf.redacted}")
    print()


def _flash_critical(pf: PrioritizedFinding) -> None:
    w = 60
    print(f"\n{RED}{BOLD}  ╔{'█'*w}╗")
    print(f"  ║{'  🔴  CRITICAL GIT FINDING  🔴  ':^{w}}║")
    print(f"  ║{'█'*w}╣")
    print(f"  ║  {'REPO :':<8} {pf.repo_or_url[:w-12]:<{w-10}}║")
    print(f"  ║  {'FILE :':<8} {pf.location[:w-12]:<{w-10}}║")
    print(f"  ║  {'TYPE :':<8} {pf.description[:w-12]:<{w-10}}║")
    print(f"  ╚{'═'*w}╝{R}\n")


# ── Core scan logic ───────────────────────────────────────────────────────────

def run_hunt(args) -> int:
    """
    Full hunt: Immunefi scrape → GitHub deep scan → prioritize → report.
    Returns exit code: 0=clean, 1=findings, 2=critical
    """
    tg = _init_telegram()

    scanner = GitHubDeepScanner(
        github_token=os.getenv("GITHUB_TOKEN"),
        use_gitleaks=not args.no_external_tools,
        use_trufflehog=not args.no_external_tools,
    )
    prioritizer = SmartPrioritizer()
    reporter    = Reporter(output_dir=args.output_dir)

    all_results: List[DeepScanResult] = []
    all_findings: List[PrioritizedFinding] = []

    # ── Target selection ──────────────────────────────────────────────────────
    targets: List[BountyTarget] = []

    if args.repo:
        # Single repo mode
        _sec("Single Repo Scan")
        _status("🔍", f"Target: {args.repo}", CYAN)
        result = scanner.scan_repo(args.repo)
        all_results.append(result)

    elif args.org:
        # Single org mode
        _sec("Org Scan")
        _status("🔍", f"Org: {args.org}  max-repos={args.max_repos}", CYAN)
        results = scanner.scan_org(args.org, max_repos=args.max_repos)
        all_results.extend(results)

    else:
        # Full Immunefi auto-hunt
        _sec("Immunefi Target Discovery")
        scraper = ImmunefiScraper()
        _status("⟳", "Fetching Immunefi bounty programs …", DIM)
        targets = scraper.fetch(top_n=args.top_n)

        if not targets:
            _status("✘", "No Immunefi targets found — check network", RED)
            return 1

        _status("✔", f"Found {len(targets)} programs", GRN)
        print()
        for i, t in enumerate(targets, 1):
            gh = t.github_org_url or f"{DIM}no GitHub{R}"
            print(f"  {i:>2}. {BOLD}{t.name:<28}{R}  ${t.max_usd:>10,}   {gh}")

        _sec("Deep Scanning GitHub Orgs")
        for t in targets:
            if not t.github_org_url:
                _status("⊘", f"{t.name} — no GitHub org, skipping", DIM)
                continue
            _status("⟳", f"Scanning {t.github_org_url} …", CYAN)
            results = scanner.scan_org(t.github_org_url, max_repos=args.max_repos)
            all_results.extend(results)

    # ── Prioritize all findings ───────────────────────────────────────────────
    _sec("Prioritizing Findings")
    raw_findings = []
    for result in all_results:
        raw_findings.extend(result.findings)
        if result.error:
            _status("!", f"{result.repo_name}: {result.error}", YEL)

    all_findings = prioritizer.rank(raw_findings)

    total_repos  = len(all_results)
    total_blobs  = sum(r.blobs_scanned for r in all_results)
    total_commits= sum(r.commits_seen for r in all_results)

    _status("✔", (
        f"{total_repos} repos  ·  "
        f"{total_blobs} dangling blobs  ·  "
        f"{total_commits} commits"
    ), GRN)

    # ── Print findings ────────────────────────────────────────────────────────
    if all_findings:
        _sec(f"Findings  ({len(all_findings)} total)")
        for i, pf in enumerate(all_findings, 1):
            if pf.severity == "CRITICAL":
                _flash_critical(pf)
                if tg:
                    tg.send_raw(
                        f"🔴 <b>CRITICAL GIT FINDING</b>\n\n"
                        f"<b>Repo:</b> {pf.repo_or_url}\n"
                        f"<b>File:</b> {pf.location}\n"
                        f"<b>Type:</b> {pf.description}\n"
                        f"<b>Hint:</b> {pf.redacted or '—'}\n"
                        f"<b>Verified:</b> {'yes' if pf.verified else 'no'}"
                    )
            else:
                _print_finding(pf, i)
    else:
        _status("✔", "No findings — all repos appear clean", GRN)

    # ── Generate reports ──────────────────────────────────────────────────────
    _sec("Reports")
    ts      = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    target_label = (
        args.repo or args.org
        or (targets[0].name if targets else "immunefi_hunt")
    )
    json_path, html_path = reporter.save_git_report(all_findings, all_results, target_label)
    disc_path = reporter.save_disclosure_draft(all_findings, target_label, args.output_dir)

    _status("📄", f"JSON   : {json_path}", DIM)
    _status("📄", f"HTML   : {html_path}", DIM)
    if disc_path:
        _status("📝", f"Draft  : {disc_path}", YEL)

    # ── Telegram summary ──────────────────────────────────────────────────────
    if tg:
        crit = sum(1 for f in all_findings if f.severity == "CRITICAL")
        high = sum(1 for f in all_findings if f.severity == "HIGH")
        verdict = "🔴 CRITICAL FINDINGS" if crit else ("🟠 HIGH FINDINGS" if high else "🟢 CLEAN")
        tg.send_raw(
            f"🐾 <b>KittyPaw Auto-Hunt Complete</b>\n\n"
            f"<b>Target:</b> {target_label}\n"
            f"<b>Verdict:</b> {verdict}\n\n"
            f"📊 <b>Stats:</b>\n"
            f"  • Repos scanned: {total_repos}\n"
            f"  • Dangling blobs: {total_blobs}\n"
            f"  • Findings: {len(all_findings)} "
            f"({crit} crit / {high} high)\n\n"
            f"📁 Reports saved to {args.output_dir}/"
        )

    # ── Exit code ─────────────────────────────────────────────────────────────
    crit_count = sum(1 for f in all_findings if f.severity == "CRITICAL")
    if crit_count:
        return 2
    return 1 if all_findings else 0


def _init_telegram() -> Optional[TelegramNotifier]:
    token   = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if token and chat_id:
        return TelegramNotifier(token, chat_id)
    return None


# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_args():
    p = argparse.ArgumentParser(
        description="KittyPaw Auto-Hunt — GitHub deep scanner + Immunefi integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 autohunt.py                           # Immunefi top-10 auto-hunt
  python3 autohunt.py --org https://github.com/uniswap
  python3 autohunt.py --repo https://github.com/uniswap/v3-core
  python3 autohunt.py --top-n 5 --max-repos 3 --no-external-tools
        """,
    )
    p.add_argument("--targets", action="store_true",
                   help="List current Immunefi bounty targets and exit (no scanning)")
    p.add_argument("--repo",   metavar="URL", help="Scan a single GitHub repo")
    p.add_argument("--org",    metavar="URL", help="Scan all public repos in a GitHub org")
    p.add_argument("--top-n",  metavar="N",   type=int, default=10,
                   help="Number of Immunefi targets to hunt (default 10)")
    p.add_argument("--max-repos", metavar="N", type=int, default=10,
                   help="Max repos to scan per org (default 10)")
    p.add_argument("--no-external-tools", action="store_true",
                   help="Skip gitleaks + trufflehog, use only built-in key_detector")
    p.add_argument("--output-dir", metavar="DIR", default="reports",
                   help="Directory for reports (default: reports/)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Skip authorization confirmation")
    return p.parse_args()


def _cmd_targets(top_n: int = 10) -> int:
    """List current Immunefi bounty targets without scanning."""
    from modules.immunefi_scraper import ImmunefiScraper
    _sec("Immunefi Bounty Targets")
    _status("⟳", "Fetching programs …", DIM)
    targets = ImmunefiScraper().fetch(top_n=top_n)
    if not targets:
        _status("✘", "Could not fetch targets — check network", RED)
        return 1
    print()
    print(f"  {'#':>2}  {'Program':<30}  {'Max Bounty':>14}  Bounty URL")
    print(f"  {'─'*2}  {'─'*30}  {'─'*14}  {'─'*40}")
    for i, t in enumerate(targets, 1):
        payout = f"${t.max_usd:,}" if t.max_usd else "unknown"
        url    = t.bounty_url or ""
        print(f"  {i:>2}. {BOLD}{t.name:<30}{R}  {GRN}{payout:>14}{R}  {DIM}{url}{R}")
    print()
    _status("✔", f"{len(targets)} programs listed", GRN)
    return 0


def main() -> int:
    args = _parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    print(BANNER)

    if args.targets:
        return _cmd_targets(args.top_n)

    if not args.yes:
        print(f"  {YEL}⚠  Only scan repos you are authorized to test.{R}")
        answer = input("  Confirm written authorization [yes/NO]: ").strip().lower()
        if answer != "yes":
            print("  Aborted.")
            return 0

    os.makedirs(args.output_dir, exist_ok=True)
    return run_hunt(args)


if __name__ == "__main__":
    sys.exit(main())
