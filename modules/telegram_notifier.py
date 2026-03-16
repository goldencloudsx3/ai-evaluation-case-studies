"""
KittyPaw Scanner — Telegram Alert Module

Sends real-time findings and scan summaries to a Telegram bot.
Requires a bot token (from @BotFather) and a chat_id.

Usage:
  from modules.telegram_notifier import TelegramNotifier
  tg = TelegramNotifier(token="123:ABC...", chat_id="-100xxx")
  tg.send_finding(finding)          # alert on individual findings
  tg.send_summary(target, result)   # summary at scan end
  tg.test()                         # verify bot is connected

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

import json
import time
import requests

# How long to wait on Telegram API calls before giving up (won't stall scan)
_TG_TIMEOUT = 8

# Minimum severity to alert on immediately (CRITICAL always alerts)
_ALERT_SEVERITIES = {"CRITICAL", "HIGH"}

# Telegram message length cap (4096 chars)
_TG_MAX = 4096

_SEV_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "⚪",
}


def _truncate(text: str, max_len: int = _TG_MAX - 50) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


class TelegramNotifier:
    """
    Lightweight Telegram notifier using the Bot API directly via requests.
    All send methods are fire-and-forget: failures are logged to stderr but
    never raise exceptions so the scan itself is never interrupted.
    """

    def __init__(self, token: str, chat_id: str):
        self.token   = token.strip()
        self.chat_id = str(chat_id).strip()
        self._base   = f"https://api.telegram.org/bot{self.token}"
        self._ok     = False   # set to True after successful test()

    # ── Low-level send ────────────────────────────────────────────────────────

    def _send(self, text: str, parse_mode: str = "HTML") -> bool:
        """POST a message.  Returns True on success, False on any error."""
        payload = {
            "chat_id":    self.chat_id,
            "text":       _truncate(text),
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        }
        try:
            r = requests.post(
                f"{self._base}/sendMessage",
                json=payload,
                timeout=_TG_TIMEOUT,
            )
            if r.status_code == 200 and r.json().get("ok"):
                return True
            # Common errors
            err = r.json().get("description", r.text[:120])
            print(f"  [Telegram] ⚠  API error: {err}")
            return False
        except requests.exceptions.ConnectionError:
            print("  [Telegram] ⚠  No internet — skipping notification.")
            return False
        except requests.exceptions.Timeout:
            print("  [Telegram] ⚠  Timeout reaching Telegram API — skipping.")
            return False
        except Exception as e:
            print(f"  [Telegram] ⚠  Unexpected error: {e}")
            return False

    # ── Public API ────────────────────────────────────────────────────────────

    def test(self) -> bool:
        """
        Verify the bot token and chat_id are valid.
        Sends a startup ping message.  Returns True if successful.
        """
        me_url = f"{self._base}/getMe"
        try:
            r = requests.get(me_url, timeout=_TG_TIMEOUT)
            if r.status_code != 200 or not r.json().get("ok"):
                print(f"  [Telegram] ✘  Invalid token — getMe failed: {r.text[:120]}")
                return False
            bot_name = r.json()["result"].get("username", "unknown")
            ok = self._send(
                f"🐾 <b>KittyPaw Scanner connected</b>\n"
                f"Bot: @{bot_name}\n"
                f"Chat ID: <code>{self.chat_id}</code>\n"
                f"Status: Online ✅"
            )
            self._ok = ok
            if ok:
                print(f"  [Telegram] ✔  Connected  (@{bot_name})")
            return ok
        except Exception as e:
            print(f"  [Telegram] ✘  Connection test failed: {e}")
            return False

    def send_scan_start(self, target: str) -> None:
        """Announce that a scan has started."""
        self._send(
            f"🐾 <b>KittyPaw Scanner — Scan Started</b>\n\n"
            f"🎯 <b>Target:</b> <code>{target}</code>\n"
            f"⏱ <b>Time:</b> {_now()}\n\n"
            f"<i>Will alert on CRITICAL / HIGH findings in real-time.</i>"
        )

    def send_finding(self, finding) -> None:
        """
        Send an immediate alert for a single IDORFinding.
        Only fires for CRITICAL / HIGH severity to avoid spam.
        """
        sev = getattr(finding, "severity", "UNKNOWN")
        if sev not in _ALERT_SEVERITIES:
            return

        icon    = _SEV_ICON.get(sev, "⚪")
        keys    = getattr(finding, "keys_found", [])
        key_str = ""
        if keys:
            key_types = [k.get("type_name", "?") for k in keys[:3]]
            key_str   = "\n🗝 <b>Key types:</b> " + ", ".join(key_types)

        fp_risk = getattr(finding, "false_positive_risk", "")
        fp_str  = f"\n⚠️ <i>FP risk: {fp_risk[:120]}</i>" if fp_risk else ""

        self._send(
            f"{icon} <b>[{sev}] KittyPaw Finding</b>\n\n"
            f"🌐 <b>URL:</b> <code>{finding.endpoint}</code>\n"
            f"🔑 <b>ID tested:</b> <code>{finding.reference_id}</code>\n"
            f"📡 <b>HTTP:</b> {finding.status_code}\n"
            f"📋 <b>Evidence:</b> {finding.evidence}"
            f"{key_str}"
            f"{fp_str}\n\n"
            f"⏱ {_now()}"
        )

    def send_header_finding(self, finding) -> None:
        """Send an alert for a HIGH/CRITICAL header finding."""
        sev = getattr(finding, "severity", "UNKNOWN")
        if sev not in _ALERT_SEVERITIES:
            return
        icon = _SEV_ICON.get(sev, "⚪")
        self._send(
            f"{icon} <b>[{sev}] Header Finding</b>\n\n"
            f"🏷 <b>{finding.title}</b>\n"
            f"📋 {finding.description}\n"
            f"🔧 <i>{finding.recommendation}</i>\n\n"
            f"⏱ {_now()}"
        )

    def send_jwt_finding(self, finding) -> None:
        """Send an alert for a HIGH/CRITICAL JWT finding."""
        sev = getattr(finding, "severity", "UNKNOWN")
        if sev not in _ALERT_SEVERITIES:
            return
        icon = _SEV_ICON.get(sev, "⚪")
        self._send(
            f"{icon} <b>[{sev}] JWT Finding</b>\n\n"
            f"🔐 <b>{finding.title}</b>\n"
            f"📋 {finding.description}\n"
            f"🔧 <i>{finding.recommendation}</i>\n\n"
            f"⏱ {_now()}"
        )

    def send_summary(
        self,
        target: str,
        idor_result,
        header_result=None,
        jwt_result=None,
        token_result=None,
        report_files=None,
        elapsed: float = 0.0,
    ) -> None:
        """
        Send a complete scan summary message.
        Called once at the end of every scan.
        """
        findings = getattr(idor_result, "findings", [])
        n_crit   = sum(1 for f in findings if f.severity == "CRITICAL")
        n_high   = sum(1 for f in findings if f.severity == "HIGH")
        n_med    = sum(1 for f in findings if f.severity == "MEDIUM")
        n_low    = sum(1 for f in findings if f.severity in ("LOW", "INFO"))
        n_total  = len(findings)

        eps_tested     = getattr(idor_result, "endpoints_tested", 0)
        challenge_skip = getattr(idor_result, "challenge_pages_skipped", 0)

        # Verdict line
        if n_total == 0:
            verdict = "✅ <b>CLEAN</b> — No key exposure detected"
        elif n_crit:
            verdict = f"🔴 <b>VULNERABLE</b> — {n_crit} CRITICAL finding(s)"
        elif n_high:
            verdict = f"🟠 <b>VULNERABLE</b> — {n_high} HIGH finding(s)"
        else:
            verdict = f"🟡 <b>FINDINGS</b> — {n_med} MEDIUM / {n_low} LOW"

        # Extra module counts
        hdr_count = len(getattr(header_result, "findings", [])) if header_result else 0
        jwt_count = len(getattr(jwt_result,    "findings", [])) if jwt_result    else 0
        tok_count = len(getattr(token_result,  "findings", [])) if token_result  else 0

        challenge_line = (
            f"\n⚠️ {challenge_skip} bot-challenge page(s) suppressed (Cloudflare/WAF)"
            if challenge_skip else ""
        )

        report_line = ""
        if report_files:
            fmts = [label for label, _ in report_files]
            report_line = f"\n📁 <b>Reports:</b> {', '.join(fmts)} saved"

        elapsed_str = f"{elapsed:.1f}s" if elapsed else ""

        self._send(
            f"🐾 <b>KittyPaw Scanner — Scan Complete</b>\n\n"
            f"🎯 <b>Target:</b> <code>{target}</code>\n\n"
            f"{verdict}\n\n"
            f"📊 <b>Stats:</b>\n"
            f"  • Endpoint×ID combos tested: {eps_tested}\n"
            f"  • IDOR findings: {n_crit} crit / {n_high} high / {n_med} med / {n_low} low\n"
            f"  • Header findings: {hdr_count}\n"
            f"  • JWT findings: {jwt_count}\n"
            f"  • Token findings: {tok_count}"
            f"{challenge_line}"
            f"{report_line}\n\n"
            f"⏱ Finished: {_now()}"
            + (f"  ({elapsed_str})" if elapsed_str else "")
        )

    def send_error(self, target: str, error: str) -> None:
        """Send a scan error notification."""
        self._send(
            f"❌ <b>KittyPaw Scanner — Scan Error</b>\n\n"
            f"🎯 <b>Target:</b> <code>{target}</code>\n"
            f"💥 <b>Error:</b> <code>{str(error)[:400]}</code>\n\n"
            f"⏱ {_now()}"
        )

    def send_rate_limited(self, target: str, url: str, retry_in: float) -> None:
        """Notify when the scanner hit a rate limit and is backing off."""
        self._send(
            f"⏳ <b>Rate Limited</b>\n\n"
            f"🎯 Target: <code>{target}</code>\n"
            f"🌐 URL: <code>{url[:200]}</code>\n"
            f"⏱ Backing off {retry_in:.0f}s …"
        )


    def send_raw(self, text: str) -> None:
        """Send an arbitrary HTML-formatted message. Used by autohunt and telegram_bot."""
        self._send(text)


def _now() -> str:
    """Current UTC time as a clean string."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
