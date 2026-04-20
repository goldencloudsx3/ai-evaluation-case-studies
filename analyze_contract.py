#!/usr/bin/env python3
"""
KittyPaw Smart Contract Analyzer

Deep-dive vulnerability scanner for Solidity contracts.
Analyzes source from local files, GitHub Gists, or raw URLs.

Usage:
  python3 analyze_contract.py --gist derri666/1e528e405be45dd2af67ef32656ffe25
  python3 analyze_contract.py --gist 1e528e405be45dd2af67ef32656ffe25
  python3 analyze_contract.py --file path/to/Contract.sol
  python3 analyze_contract.py --file path/to/Contract.sol --no-html

FOR AUTHORIZED SECURITY RESEARCH AND BUG BOUNTY USE ONLY.
"""

import sys
import argparse
import urllib.request
import json
from pathlib import Path

# Add project root so modules/ is importable regardless of cwd
sys.path.insert(0, str(Path(__file__).parent))

from modules.solidity_analyzer import SolidityAnalyzer, fetch_gist, VULN_CATALOG
from modules.solidity_report_generator import (
    print_console_report,
    save_json_report,
    save_html_report,
)

REPORTS_DIR = Path(__file__).parent / "reports"

# ── Banner ─────────────────────────────────────────────────────────────────────

def _banner():
    GRAD = ["\033[38;5;213m", "\033[38;5;207m", "\033[38;5;201m",
            "\033[38;5;165m", "\033[38;5;129m"]
    RST = "\033[0m"
    BOLD = "\033[1m"
    lines = [
        r"  /\_____/\   KittyPaw Smart Contract Analyzer",
        r" /  o   o  \  ─────────────────────────────────────",
        r"( ==  ^  == ) Solidity static analysis engine",
        r" )         (  Detects: reentrancy · access control",
        r"(           ) fund theft · front-running · and more",
        r" \  |||||  /  ",
        r"  \_______/   FOR AUTHORIZED SECURITY RESEARCH ONLY",
    ]
    for i, ln in enumerate(lines):
        col = GRAD[i % len(GRAD)]
        print(f"{col}{BOLD}{ln}{RST}")
    print()


# ── Gist ID normalization ──────────────────────────────────────────────────────

def _parse_gist_id(arg: str) -> str:
    """Accept 'user/id', 'id', or full URL."""
    arg = arg.strip().rstrip("/")
    if "/" in arg:
        return arg.split("/")[-1]
    return arg


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="KittyPaw — Solidity vulnerability analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    src_group = parser.add_mutually_exclusive_group(required=True)
    src_group.add_argument("--gist", metavar="USER/ID_or_ID",
                           help="GitHub Gist ID (or user/id form)")
    src_group.add_argument("--file", metavar="PATH",
                           help="Local .sol file path")

    parser.add_argument("--no-html", action="store_true",
                        help="Skip HTML report generation")
    parser.add_argument("--no-json", action="store_true",
                        help="Skip JSON report generation")
    parser.add_argument("--out-dir", metavar="DIR", default=str(REPORTS_DIR),
                        help=f"Output directory for reports (default: {REPORTS_DIR})")

    args = parser.parse_args()
    _banner()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    analyzer = SolidityAnalyzer()
    all_findings = []
    contract_name = "Unknown"

    # ── Load source ────────────────────────────────────────────────────────────
    if args.gist:
        gist_id = _parse_gist_id(args.gist)
        print(f"  Fetching gist {gist_id} ...\n")
        try:
            files = fetch_gist(gist_id)
        except Exception as e:
            print(f"\033[91m  ERROR: Could not fetch gist: {e}\033[0m")
            sys.exit(1)

        sol_files = {k: v for k, v in files.items() if k.endswith(".sol")}
        if not sol_files:
            print("\033[93m  No .sol files found in gist.\033[0m")
            sys.exit(0)

        for fname, content in sol_files.items():
            print(f"  Analyzing {fname} ({len(content)} bytes) ...")
            findings = analyzer.analyze(content, fname)
            all_findings.extend(findings)
            contract_name = fname.replace(".sol", "")

    elif args.file:
        sol_path = Path(args.file)
        if not sol_path.exists():
            print(f"\033[91m  ERROR: File not found: {sol_path}\033[0m")
            sys.exit(1)
        content = sol_path.read_text()
        contract_name = sol_path.stem
        print(f"  Analyzing {sol_path.name} ({len(content)} bytes) ...\n")
        all_findings = analyzer.analyze(content, sol_path.name)

    # ── Console output ─────────────────────────────────────────────────────────
    if not all_findings:
        print("\033[92m  No vulnerabilities detected.\033[0m")
        sys.exit(0)

    print_console_report(all_findings, contract_name)

    # ── Save reports ───────────────────────────────────────────────────────────
    prefix = contract_name.lower().replace(" ", "_")

    if not args.no_json:
        json_path = out_dir / f"{prefix}_audit.json"
        save_json_report(all_findings, json_path)
        print(f"  \033[92mJSON report:\033[0m {json_path}")

    if not args.no_html:
        html_path = out_dir / f"{prefix}_audit.html"
        save_html_report(all_findings, html_path, contract_name)
        print(f"  \033[92mHTML report:\033[0m {html_path}")

    print()

    # ── Exit code ──────────────────────────────────────────────────────────────
    if any(f.severity == "CRITICAL" for f in all_findings):
        sys.exit(2)
    elif any(f.severity == "HIGH" for f in all_findings):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
