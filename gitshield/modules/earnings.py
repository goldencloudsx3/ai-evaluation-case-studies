"""
GitShield — Earnings Tracker

Log confirmed bounty payouts via Telegram (/bounty command).
Tracks totals, per-platform breakdown, win rate, and running history.
Data stored in ~/gitshield/earnings.json.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional

log = logging.getLogger("gitshield.earnings")

_BASE_DIR = Path.home() / "gitshield"
_EARNINGS_FILE = _BASE_DIR / "earnings.json"


# ── Data model ────────────────────────────────────────────────────────────────

def _load() -> dict:
    if _EARNINGS_FILE.exists():
        try:
            return json.loads(_EARNINGS_FILE.read_text())
        except Exception:
            pass
    return {"entries": [], "total_usd": 0}


def _save(data: dict) -> None:
    _BASE_DIR.mkdir(parents=True, exist_ok=True)
    _EARNINGS_FILE.write_text(json.dumps(data, indent=2))


# ── Public API ────────────────────────────────────────────────────────────────

def log_bounty(amount_usd: float, platform: str, project: str, notes: str = "") -> dict:
    """
    Record a confirmed bounty payout.

    Args:
        amount_usd: Payout in USD (numeric).
        platform:   e.g. "Immunefi", "HackerOne", "Bugcrowd", "Direct".
        project:    Target project/company name.
        notes:      Optional free-text (finding type, severity, etc.).

    Returns the new entry dict.
    """
    data = _load()
    entry = {
        "id": len(data["entries"]) + 1,
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "amount_usd": float(amount_usd),
        "platform": platform.strip(),
        "project": project.strip(),
        "notes": notes.strip(),
    }
    data["entries"].append(entry)
    data["total_usd"] = sum(e["amount_usd"] for e in data["entries"])
    _save(data)
    log.info(f"Bounty logged: ${amount_usd:,.0f} from {platform} / {project}")
    return entry


def get_summary() -> dict:
    """Return aggregated earnings stats."""
    data = _load()
    entries = data.get("entries", [])
    if not entries:
        return {
            "total_usd": 0,
            "count": 0,
            "platforms": {},
            "highest_single": 0,
            "this_month_usd": 0,
        }

    by_platform: Dict[str, float] = {}
    for e in entries:
        p = e.get("platform", "Unknown")
        by_platform[p] = by_platform.get(p, 0) + e["amount_usd"]

    this_month = datetime.now(timezone.utc).strftime("%Y-%m")
    this_month_total = sum(
        e["amount_usd"] for e in entries
        if e.get("date", "").startswith(this_month)
    )

    return {
        "total_usd": data.get("total_usd", 0),
        "count": len(entries),
        "platforms": by_platform,
        "highest_single": max(e["amount_usd"] for e in entries),
        "this_month_usd": this_month_total,
        "recent": entries[-5:],   # last 5 entries
    }


def get_recent(n: int = 10) -> List[dict]:
    data = _load()
    return data.get("entries", [])[-n:]


# ── Telegram message formatters ───────────────────────────────────────────────

def format_earnings_message() -> str:
    s = get_summary()
    if s["count"] == 0:
        return (
            "📊 *GitShield Earnings*\n\n"
            "No bounties logged yet.\n"
            "Use: `/bounty <amount> <platform> <project>` to record a payout."
        )

    lines = ["📊 *GitShield Earnings Tracker*\n"]
    lines.append(f"💰 *Total Earned:*  `${s['total_usd']:,.0f}`")
    lines.append(f"📅 *This Month:*    `${s['this_month_usd']:,.0f}`")
    lines.append(f"🏆 *Biggest:*       `${s['highest_single']:,.0f}`")
    lines.append(f"✅ *Payouts:*       `{s['count']}`\n")

    if s["platforms"]:
        lines.append("*By Platform:*")
        for plat, total in sorted(s["platforms"].items(), key=lambda x: -x[1]):
            lines.append(f"  ▸ {plat}: `${total:,.0f}`")

    recent = s.get("recent", [])
    if recent:
        lines.append("\n*Recent Payouts:*")
        for e in reversed(recent):
            lines.append(
                f"  `{e['date']}`  `${e['amount_usd']:,.0f}`  "
                f"{e['platform']} / {e['project']}"
            )

    return "\n".join(lines)


def format_bounty_logged_message(entry: dict) -> str:
    data = _load()
    total = data.get("total_usd", 0)
    return (
        f"✅ *Bounty logged!*\n\n"
        f"💵 Amount:    `${entry['amount_usd']:,.0f}`\n"
        f"🏠 Platform:  `{entry['platform']}`\n"
        f"🎯 Project:   `{entry['project']}`\n"
        f"📅 Date:      `{entry['date']}`\n"
        f"\n🏦 *Running total: `${total:,.0f}`*"
        + (f"\n📝 Notes: _{entry['notes']}_" if entry.get("notes") else "")
    )


def parse_bounty_command(text: str) -> Optional[tuple]:
    """
    Parse '/bounty 2500 Immunefi ProjectName optional notes' into
    (amount_usd, platform, project, notes).  Returns None on parse failure.
    """
    parts = text.strip().split(None, 3)
    # parts[0] = "/bounty", parts[1] = amount, parts[2] = platform, parts[3] = project+notes
    if len(parts) < 4:
        return None
    try:
        amount = float(parts[1].replace("$", "").replace(",", ""))
    except ValueError:
        return None
    platform = parts[2]
    rest = parts[3] if len(parts) > 3 else ""
    # Split rest into project (first word) and optional notes
    rest_parts = rest.split(None, 1)
    project = rest_parts[0] if rest_parts else "Unknown"
    notes = rest_parts[1] if len(rest_parts) > 1 else ""
    return amount, platform, project, notes
