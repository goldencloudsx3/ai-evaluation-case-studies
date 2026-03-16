#!/usr/bin/env python3
"""
KittyPaw Scanner — Telegram Bot HQ
Two-way command bot. Run once and control everything from Telegram.

Commands:
  /hunt              — Scrape Immunefi + deep-scan top 10 programs
  /scan <github_url> — Deep-scan one specific repo or org
  /targets           — List current Immunefi bounty targets
  /report            — Send latest HTML report as a file
  /earnings <$> <program> — Log a confirmed bounty payout
  /status            — Check tool versions + scanner health

Usage:
  python3 telegram_bot.py

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

from __future__ import annotations

import os
import sys
import json
import time
import shutil
import logging
import threading
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
TOKEN   = os.getenv("TELEGRAM_TOKEN", "")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
REPORTS = Path(os.getenv("REPORT_DIR", "reports"))
EARNINGS_FILE = Path("earnings.json")
POLL_TIMEOUT  = 30       # long-polling timeout in seconds
_API          = f"https://api.telegram.org/bot{TOKEN}"


class KittyPawBot:
    """
    Long-polling Telegram bot.  Receives commands and dispatches them
    to scanner modules in background threads.
    """

    def __init__(self):
        if not TOKEN or not CHAT_ID:
            sys.exit("❌  Set TELEGRAM_TOKEN and TELEGRAM_CHAT_ID in .env first.")
        self._offset        = 0
        self._active_scan   = None   # threading.Thread or None
        self._scan_lock     = threading.Lock()
        REPORTS.mkdir(parents=True, exist_ok=True)

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        log.info("🐾 KittyPaw Bot HQ starting …")
        self._send("🐾 <b>KittyPaw Bot HQ online</b>\n\n"
                   "Commands:\n"
                   "  /hunt — auto-scan Immunefi top 10\n"
                   "  /scan &lt;url&gt; — scan a specific repo/org\n"
                   "  /targets — list Immunefi programs\n"
                   "  /report — get latest HTML report\n"
                   "  /earnings $amount program — log bounty\n"
                   "  /status — health check")
        while True:
            try:
                updates = self._get_updates()
                for update in updates:
                    self._handle(update)
            except KeyboardInterrupt:
                log.info("Shutting down.")
                self._send("🐾 KittyPaw Bot HQ offline.")
                break
            except Exception as exc:
                log.error("Poll error: %s", exc)
                time.sleep(5)

    # ── Update handling ───────────────────────────────────────────────────────

    def _handle(self, update: dict) -> None:
        msg  = update.get("message") or {}
        text = (msg.get("text") or "").strip()
        chat = str(msg.get("chat", {}).get("id", ""))

        # Only respond to the configured chat
        if chat != CHAT_ID:
            return

        if not text.startswith("/"):
            return

        parts   = text.split(maxsplit=1)
        command = parts[0].lower().split("@")[0]  # strip @botname suffix
        args    = parts[1] if len(parts) > 1 else ""

        dispatch = {
            "/hunt":     self._cmd_hunt,
            "/scan":     self._cmd_scan,
            "/targets":  self._cmd_targets,
            "/report":   self._cmd_report,
            "/earnings": self._cmd_earnings,
            "/status":   self._cmd_status,
        }

        handler = dispatch.get(command)
        if handler:
            try:
                handler(args)
            except Exception as exc:
                self._send(f"❌ Error: {exc}")
        else:
            self._send("Unknown command. Try /status for help.")

    # ── Commands ──────────────────────────────────────────────────────────────

    def _cmd_hunt(self, _args: str) -> None:
        if self._scan_running():
            self._send("⏳ A scan is already running. Wait for it to finish.")
            return
        self._send("🐾 <b>Auto-Hunt starting…</b>\nScraping Immunefi + scanning top 10 programs.\nI'll message you when done.")
        t = threading.Thread(target=self._run_autohunt, kwargs={"extra_args": []}, daemon=True)
        with self._scan_lock:
            self._active_scan = t
        t.start()

    def _cmd_scan(self, args: str) -> None:
        url = args.strip()
        if not url:
            self._send("Usage: /scan &lt;github_url&gt;\nExample: /scan https://github.com/uniswap/v3-core")
            return
        if self._scan_running():
            self._send("⏳ A scan is already running.")
            return
        if "github.com/" in url:
            parts = url.rstrip("/").split("github.com/")[1].split("/")
            flag  = "--repo" if len(parts) >= 2 else "--org"
        else:
            self._send("❌ Only GitHub URLs are supported.")
            return
        self._send(f"🔍 Scanning <code>{url}</code> …\nI'll message you when done.")
        t = threading.Thread(
            target=self._run_autohunt,
            kwargs={"extra_args": [flag, url]},
            daemon=True,
        )
        with self._scan_lock:
            self._active_scan = t
        t.start()

    def _cmd_targets(self, _args: str) -> None:
        self._send("⟳ Fetching Immunefi targets …")
        try:
            from modules.immunefi_scraper import ImmunefiScraper
            targets = ImmunefiScraper().fetch(top_n=10)
            if not targets:
                self._send("❌ Could not fetch targets — check network.")
                return
            lines = ["🎯 <b>Top Immunefi Targets</b>\n"]
            for i, t in enumerate(targets, 1):
                payout = f"${t.max_usd:,}" if t.max_usd else "unknown"
                gh     = t.github_org_url or "no GitHub"
                lines.append(f"  {i}. <b>{t.name}</b> — {payout}\n     {gh}")
            self._send("\n".join(lines))
        except Exception as exc:
            self._send(f"❌ Error: {exc}")

    def _cmd_report(self, _args: str) -> None:
        # Find the most recent HTML report
        html_files = sorted(REPORTS.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not html_files:
            self._send("📭 No reports found yet. Run /hunt or /scan first.")
            return
        latest = html_files[0]
        self._send_document(str(latest), caption=f"📄 Latest report: {latest.name}")

        # Also send disclosure draft if one exists
        drafts = sorted(REPORTS.glob("disclosure_*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
        if drafts:
            self._send_document(str(drafts[0]), caption=f"📝 Disclosure draft: {drafts[0].name}")

    def _cmd_earnings(self, args: str) -> None:
        parts = args.strip().split(maxsplit=1)
        if len(parts) < 2:
            self._send("Usage: /earnings &lt;amount&gt; &lt;program&gt;\nExample: /earnings $500 Uniswap")
            return
        amount, program = parts[0], parts[1]
        entry = {
            "date":    datetime.now(timezone.utc).isoformat(),
            "amount":  amount,
            "program": program,
        }
        records = []
        if EARNINGS_FILE.exists():
            try:
                records = json.loads(EARNINGS_FILE.read_text())
            except Exception:
                pass
        records.append(entry)
        EARNINGS_FILE.write_text(json.dumps(records, indent=2))

        total = self._calc_earnings(records)
        self._send(
            f"💰 <b>Bounty logged!</b>\n\n"
            f"  Program : {program}\n"
            f"  Amount  : {amount}\n"
            f"  Date    : {entry['date'][:10]}\n\n"
            f"📊 Total confirmed: <b>{total}</b>"
        )

    def _cmd_status(self, _args: str) -> None:
        gl_ver  = self._tool_version("gitleaks", ["gitleaks", "version"])
        th_ver  = self._tool_version("trufflehog", ["trufflehog", "--version"])
        git_ver = self._tool_version("git", ["git", "--version"])
        disk_gb = self._free_disk_gb()
        reports = list(REPORTS.glob("*.html"))
        last    = max((p.stat().st_mtime for p in reports), default=None)
        last_s  = datetime.fromtimestamp(last, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if last else "never"

        running = "🟡 Scan in progress" if self._scan_running() else "🟢 Idle"

        self._send(
            f"🐾 <b>KittyPaw Bot — Status</b>\n\n"
            f"  Scanner  : {running}\n"
            f"  git      : {git_ver}\n"
            f"  gitleaks : {gl_ver}\n"
            f"  trufflehog: {th_ver}\n"
            f"  Disk free: {disk_gb:.1f} GB\n"
            f"  Reports  : {len(reports)} HTML files\n"
            f"  Last scan: {last_s}\n\n"
            f"{'⚠ Install gitleaks: brew install gitleaks' if gl_ver == 'not found' else ''}\n"
            f"{'⚠ Install trufflehog: brew install trufflehog' if th_ver == 'not found' else ''}"
        )

    # ── Background scan runner ────────────────────────────────────────────────

    def _run_autohunt(self, extra_args: list) -> None:
        cmd = [sys.executable, "autohunt.py", "--yes"] + extra_args
        log.info("Running: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hour max
            )
            output_tail = (result.stdout or "")[-1000:]  # last 1000 chars
            if result.returncode == 2:
                self._send(f"🔴 <b>CRITICAL findings detected!</b>\n<pre>{output_tail}</pre>\nUse /report to get the full report.")
            elif result.returncode == 1:
                self._send(f"🟠 <b>Scan complete — findings detected.</b>\nUse /report for details.")
            else:
                self._send("🟢 <b>Scan complete — no findings.</b>")
        except subprocess.TimeoutExpired:
            self._send("⏱ Scan timed out after 1 hour.")
        except Exception as exc:
            self._send(f"❌ Scan crashed: {exc}")
        finally:
            with self._scan_lock:
                self._active_scan = None

    def _scan_running(self) -> bool:
        with self._scan_lock:
            return self._active_scan is not None and self._active_scan.is_alive()

    # ── Telegram API helpers ──────────────────────────────────────────────────

    def _get_updates(self) -> list:
        try:
            r = requests.get(
                f"{_API}/getUpdates",
                params={"offset": self._offset, "timeout": POLL_TIMEOUT},
                timeout=POLL_TIMEOUT + 5,
            )
            data = r.json()
            if not data.get("ok"):
                return []
            updates = data.get("result", [])
            if updates:
                self._offset = updates[-1]["update_id"] + 1
            return updates
        except requests.exceptions.Timeout:
            return []
        except Exception as exc:
            log.debug("getUpdates error: %s", exc)
            return []

    def _send(self, text: str) -> None:
        try:
            requests.post(
                f"{_API}/sendMessage",
                json={"chat_id": CHAT_ID, "text": text, "parse_mode": "HTML"},
                timeout=10,
            )
        except Exception as exc:
            log.warning("sendMessage failed: %s", exc)

    def _send_document(self, file_path: str, caption: str = "") -> None:
        try:
            with open(file_path, "rb") as f:
                requests.post(
                    f"{_API}/sendDocument",
                    data={"chat_id": CHAT_ID, "caption": caption},
                    files={"document": f},
                    timeout=30,
                )
        except Exception as exc:
            log.warning("sendDocument failed: %s", exc)

    # ── Misc helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _tool_version(name: str, cmd: list) -> str:
        if not shutil.which(name):
            return "not found"
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return (out.stdout or out.stderr or "").strip().splitlines()[0][:40]
        except Exception:
            return "error"

    @staticmethod
    def _free_disk_gb() -> float:
        try:
            st = os.statvfs("/")
            return st.f_bavail * st.f_frsize / 1e9
        except Exception:
            return -1.0

    @staticmethod
    def _calc_earnings(records: list) -> str:
        total = 0
        for r in records:
            amt = str(r.get("amount", "0")).replace("$", "").replace(",", "")
            try:
                total += float(amt)
            except ValueError:
                pass
        return f"${total:,.2f}"


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    bot = KittyPawBot()
    bot.run()
