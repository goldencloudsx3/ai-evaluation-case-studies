"""
GitShield — Immunefi Target Scraper

Fetches active bug bounty programs from Immunefi's public API,
extracts GitHub org URLs from each program, and ranks by max payout.
"""

import re
import json
import logging
import requests
from dataclasses import dataclass, field
from typing import List, Optional

log = logging.getLogger("gitshield.immunefi")

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/122.0.0.0 Safari/537.36",
    "Accept": "application/json, text/html, */*",
}

# Immunefi public endpoints (tried in order)
_ENDPOINTS = [
    "https://immunefi.com/immunefi.json",
    "https://immunefi.com/api/explore/",
    "https://immunefi.com/explore.json",
]

_GITHUB_RE = re.compile(
    r'https?://(?:www\.)?github\.com/([a-zA-Z0-9._-]+)(?:/[a-zA-Z0-9._-]+)*'
)


@dataclass
class BountyProgram:
    name: str
    slug: str
    max_bounty_usd: int
    github_orgs: List[str] = field(default_factory=list)
    website: str = ""
    assets_in_scope: int = 0

    @property
    def immunefi_url(self) -> str:
        return f"https://immunefi.com/bug-bounty/{self.slug}/"

    @property
    def bounty_display(self) -> str:
        if self.max_bounty_usd >= 1_000_000:
            return f"${self.max_bounty_usd / 1_000_000:.1f}M"
        if self.max_bounty_usd >= 1_000:
            return f"${self.max_bounty_usd // 1_000}k"
        return f"${self.max_bounty_usd:,}"


def fetch_targets(min_bounty_usd: int = 10_000, limit: int = 20) -> List[BountyProgram]:
    """
    Fetch Immunefi programs, filter by minimum payout, return sorted by max payout desc.

    Args:
        min_bounty_usd: Only include programs with max bounty >= this value.
        limit:          Cap on number of programs returned.
    """
    raw = _fetch_raw()
    if not raw:
        log.warning("Could not fetch Immunefi programs — check connectivity")
        return []

    programs = []
    for item in raw:
        max_b = _parse_bounty(
            item.get("maxBounty") or item.get("max_bounty") or item.get("bounty", 0)
        )
        if max_b < min_bounty_usd:
            continue

        name = item.get("project") or item.get("name") or item.get("id", "Unknown")
        slug = (item.get("id") or item.get("slug") or
                name.lower().replace(" ", "-").replace("/", "-"))

        programs.append(BountyProgram(
            name=name,
            slug=slug,
            max_bounty_usd=max_b,
            github_orgs=_extract_github_orgs(item),
            website=item.get("website") or item.get("project_url", ""),
            assets_in_scope=len(item.get("assets", [])) if isinstance(item.get("assets"), list) else 0,
        ))

    programs.sort(key=lambda p: p.max_bounty_usd, reverse=True)
    log.info(f"Immunefi: {len(programs)} programs ≥ ${min_bounty_usd:,} (of {len(raw)} total)")
    return programs[:limit]


def _fetch_raw() -> list:
    """Try each Immunefi endpoint; return raw program list on first success."""
    for url in _ENDPOINTS:
        try:
            r = requests.get(url, headers=_HEADERS, timeout=15)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    return data
                if isinstance(data, dict):
                    for key in ("data", "programs", "bounties", "results", "items"):
                        if isinstance(data.get(key), list):
                            return data[key]
        except Exception as e:
            log.debug(f"Immunefi fetch failed ({url}): {e}")

    # Last resort: scrape HTML for embedded Next.js __NEXT_DATA__ JSON
    return _scrape_html_fallback()


def _scrape_html_fallback() -> list:
    """Extract program data from Immunefi's SSG-rendered HTML page."""
    try:
        r = requests.get("https://immunefi.com/explore/", headers=_HEADERS, timeout=20)
        if r.status_code != 200:
            return []
        # Next.js embeds full page data in <script id="__NEXT_DATA__">
        m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', r.text, re.S)
        if not m:
            return []
        page_data = json.loads(m.group(1))
        # Navigate to the bounties list (path varies by site version)
        def _find_list(obj, depth=0):
            if depth > 8:
                return None
            if isinstance(obj, list) and obj and isinstance(obj[0], dict):
                if any(k in obj[0] for k in ("maxBounty", "project", "bounty")):
                    return obj
            if isinstance(obj, dict):
                for v in obj.values():
                    result = _find_list(v, depth + 1)
                    if result:
                        return result
            return None

        return _find_list(page_data) or []
    except Exception as e:
        log.debug(f"Immunefi HTML fallback failed: {e}")
        return []


def _parse_bounty(val) -> int:
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str):
        cleaned = val.replace("$", "").replace(",", "").replace("+", "").strip()
        try:
            return int(float(cleaned))
        except ValueError:
            return 0
    return 0


def _extract_github_orgs(program_data: dict) -> List[str]:
    """Extract unique GitHub org/repo URLs from all fields in a program record."""
    orgs: set = set()

    def _scan(obj, depth=0):
        if depth > 5:
            return
        if isinstance(obj, str):
            for m in _GITHUB_RE.finditer(obj):
                # Normalize to org-level URL (drop /repo suffix)
                orgs.add(f"https://github.com/{m.group(1)}")
        elif isinstance(obj, dict):
            for v in obj.values():
                _scan(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                _scan(item, depth + 1)

    _scan(program_data)
    return sorted(orgs)


def format_targets_message(programs: List[BountyProgram]) -> str:
    """Format a Telegram-ready summary of top targets."""
    if not programs:
        return "⚠️ No Immunefi targets fetched — check connectivity or lower --min-bounty."

    lines = [f"🎯 *Immunefi Top Targets* ({len(programs)} programs)\n"]
    for i, p in enumerate(programs, 1):
        gh = f"{len(p.github_orgs)} GitHub org(s)" if p.github_orgs else "no GitHub found"
        lines.append(f"`{i:02d}.` *{p.name}* — {p.bounty_display}  ·  {gh}")

    lines.append(f"\n_Use /hunt to auto-scan all targets with GitHub orgs._")
    return "\n".join(lines)
