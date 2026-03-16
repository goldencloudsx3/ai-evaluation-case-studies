#!/usr/bin/env python3
"""
KittyPaw Scanner — Immunefi Target Scraper
Fetches active bounty programs, extracts GitHub org URLs, ranks by max payout.
"""

from __future__ import annotations

import re
import json
import logging
from dataclasses import dataclass, field
from typing import List, Optional

import requests

log = logging.getLogger(__name__)

_EXPLORE   = "https://immunefi.com/explore/"
_HEADERS   = {"User-Agent": "Mozilla/5.0 (compatible; KittyPawScanner/2.0)"}
_TIMEOUT   = 15

_GH_ORG_RE = re.compile(
    r'https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)(?:/[^"\s]*)?'
)


@dataclass
class BountyTarget:
    name:           str
    max_usd:        int
    github_org_url: Optional[str]
    github_org:     Optional[str]
    scope_urls:     List[str] = field(default_factory=list)
    bounty_url:     str = ""

    def __str__(self) -> str:
        payout = f"${self.max_usd:,}" if self.max_usd else "unknown"
        gh     = self.github_org_url or "no GitHub"
        return f"{self.name:<30} max={payout:<12} {gh}"


class ImmunefiScraper:
    """Fetch active bug bounty programs from Immunefi and extract GitHub orgs."""

    def __init__(self, timeout: int = _TIMEOUT):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(_HEADERS)

    # ── Public API ────────────────────────────────────────────────────────────

    def fetch(self, top_n: int = 20) -> List[BountyTarget]:
        """
        Return up to *top_n* bounty targets sorted by max payout (descending).
        Parses Immunefi's explore page (React Server Components streaming format).
        """
        targets = self._fetch_html()

        # Sort by payout descending
        targets.sort(key=lambda t: t.max_usd, reverse=True)
        return targets[:top_n]

    def _parse_json_item(self, item: dict) -> Optional[BountyTarget]:
        name = item.get("project") or item.get("name") or item.get("id", "")
        if not name:
            return None

        # Max payout — try several field names Immunefi has used over time
        max_usd = 0
        for key in ("maxBounty", "max_bounty", "maximumBounty", "bountyMax"):
            val = item.get(key)
            if val:
                try:
                    max_usd = int(str(val).replace(",", "").replace("$", "").strip())
                except ValueError:
                    pass
                break

        # GitHub links from assets, links, or description fields
        gh_url, gh_org = self._extract_github(item)

        scope_urls = self._extract_scope_urls(item)
        # RSC data has a relative "url" like "/bug-bounty/layerzero/information/"
        # or a slug field; normalise to an absolute Immunefi URL.
        raw_url = item.get("url") or item.get("link") or ""
        slug    = item.get("slug", "")
        if raw_url.startswith("/"):
            bounty_url = f"https://immunefi.com{raw_url}"
        elif raw_url:
            bounty_url = raw_url
        elif slug:
            bounty_url = f"https://immunefi.com/bug-bounty/{slug}/"
        else:
            bounty_url = ""

        return BountyTarget(
            name=name,
            max_usd=max_usd,
            github_org_url=gh_url,
            github_org=gh_org,
            scope_urls=scope_urls,
            bounty_url=bounty_url,
        )

    # ── Internal: HTML fetch (RSC streaming format) ───────────────────────────

    def _fetch_html(self) -> List[BountyTarget]:
        try:
            r = self.session.get(_EXPLORE, timeout=self.timeout)
            r.raise_for_status()
        except Exception as exc:
            log.error("HTML fetch failed: %s", exc)
            return []

        html = r.text
        targets: List[BountyTarget] = []

        # ── Method 1: RSC streaming chunks ────────────────────────────────────
        # Immunefi uses React Server Components: self.__next_f.push([1,"<json>"])
        rsc_chunks = re.findall(
            r'self\.__next_f\.push\(\[1,"(.+?)"\]\)', html, re.DOTALL
        )
        for chunk in rsc_chunks:
            try:
                # Use json.loads to properly unescape the string value
                unescaped = json.loads(f'"{chunk}"')
            except Exception:
                try:
                    unescaped = chunk.encode().decode("unicode_escape")
                except Exception:
                    continue

            if '"maxBounty"' not in unescaped:
                continue

            # Extract the bounties array: [{"contentfulId":..., "maxBounty":...}, ...]
            match = re.search(
                r'\[(\{"contentfulId".+?)\](?=,\s*"title")',
                unescaped,
                re.DOTALL,
            )
            if not match:
                continue
            try:
                items = json.loads("[" + match.group(1) + "]")
            except json.JSONDecodeError as exc:
                log.debug("RSC JSON decode failed: %s", exc)
                continue

            for item in items:
                try:
                    t = self._parse_json_item(item)
                    if t:
                        targets.append(t)
                except Exception as exc:
                    log.debug("Failed to parse RSC item: %s", exc)

            if targets:
                log.info("RSC parse: found %d bounty programs", len(targets))
                return targets

        # ── Method 2: Direct regex over raw HTML ──────────────────────────────
        # Extract project+maxBounty pairs directly without chunk parsing
        log.debug("RSC chunk parse yielded nothing — trying direct HTML regex")
        pairs = re.findall(
            r'"project"\s*:\s*"([^"]+)"[^}]{0,300}"maxBounty"\s*:\s*(\d+)',
            html,
        )
        if not pairs:
            # also try reversed field order
            pairs_r = re.findall(
                r'"maxBounty"\s*:\s*(\d+)[^}]{0,300}"project"\s*:\s*"([^"]+)"',
                html,
            )
            pairs = [(name, amt) for amt, name in pairs_r]

        seen_names: set = set()
        for name, amt in pairs:
            if name in seen_names:
                continue
            seen_names.add(name)
            # Try to find slug for this project
            slug_m = re.search(
                r'"slug"\s*:\s*"([^"]+)"[^}]{0,500}"project"\s*:\s*"' + re.escape(name) + '"',
                html,
            )
            slug = slug_m.group(1) if slug_m else name.lower().replace(" ", "-")
            targets.append(BountyTarget(
                name=name,
                max_usd=int(amt),
                github_org_url=None,
                github_org=None,
                bounty_url=f"https://immunefi.com/bug-bounty/{slug}/",
            ))

        if targets:
            log.info("Direct regex parse: found %d programs", len(targets))
            return targets

        # ── Method 3: GitHub org URL extraction ───────────────────────────────
        log.warning("All parse methods failed — extracting GitHub org URLs only")
        seen: set = set()
        for m in _GH_ORG_RE.finditer(html):
            org = m.group(1)
            if org.lower() in ("torvalds", "github", "features", "apps"):
                continue
            if org in seen:
                continue
            seen.add(org)
            targets.append(BountyTarget(
                name=org, max_usd=0,
                github_org_url=f"https://github.com/{org}",
                github_org=org,
            ))

        return targets

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_github(self, item: dict):
        """Return (github_org_url, github_org) from any field in *item*."""
        # Fields that commonly contain GitHub links
        candidates = []
        for key in ("githubOrg", "github", "repoUrl", "sourceCode", "links", "assets", "description"):
            val = item.get(key)
            if not val:
                continue
            if isinstance(val, str):
                candidates.append(val)
            elif isinstance(val, list):
                for v in val:
                    if isinstance(v, str):
                        candidates.append(v)
                    elif isinstance(v, dict):
                        candidates.extend(str(x) for x in v.values() if x)
            elif isinstance(val, dict):
                candidates.extend(str(x) for x in val.values() if x)

        for text in candidates:
            m = _GH_ORG_RE.search(str(text))
            if m:
                org = m.group(1)
                # Skip github.com/torvalds etc. — only real project orgs
                if org.lower() in ("torvalds", "github", "features", "apps"):
                    continue
                return f"https://github.com/{org}", org

        return None, None

    def _extract_scope_urls(self, item: dict) -> List[str]:
        urls: List[str] = []
        assets = item.get("assets") or item.get("scope") or []
        if isinstance(assets, list):
            for asset in assets:
                if isinstance(asset, dict):
                    url = asset.get("url") or asset.get("address") or ""
                    if url:
                        urls.append(url)
                elif isinstance(asset, str):
                    urls.append(asset)
        return urls


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    top = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    scraper = ImmunefiScraper()
    print(f"\nFetching top {top} Immunefi bounty targets …\n")
    targets = scraper.fetch(top_n=top)
    if not targets:
        print("No targets found — check network or Immunefi URL changes.")
        sys.exit(1)
    for i, t in enumerate(targets, 1):
        print(f"  {i:>2}. {t}")
    print(f"\nTotal: {len(targets)} targets\n")
