#!/usr/bin/env python3
"""
KittyPaw Scanner — Smart Prioritizer
Ranks findings from all scanner modules by exploitability and impact.
Deduplicates by (repo/endpoint, value_hash) to suppress repeated alerts.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import List, Union, Any

# Import finding types from sibling modules
try:
    from modules.github_deep_scanner import GitFinding
    from modules.idor_scanner import IDORFinding
except ImportError:
    GitFinding = Any      # type: ignore
    IDORFinding = Any     # type: ignore


# ── Scoring table ─────────────────────────────────────────────────────────────
#
# Each entry: (keywords_in_description_or_type, score_bonus, forced_severity)
# Evaluated in order — first match wins the severity override.

_RULES = [
    # TruffleHog verified findings are the gold standard
    ("trufflehog",          100, "CRITICAL"),
    # Wallet private keys
    ("ethereum private",     90, "CRITICAL"),
    ("bitcoin wif",          90, "CRITICAL"),
    ("solana private",       90, "CRITICAL"),
    ("xpriv",                90, "CRITICAL"),
    # Seed phrases
    ("mnemonic",             90, "CRITICAL"),
    ("bip39",                90, "CRITICAL"),
    ("seed phrase",          90, "CRITICAL"),
    # Keystore / PEM
    ("keystore",             85, "CRITICAL"),
    ("rsa private",          85, "CRITICAL"),
    ("pem private",          85, "CRITICAL"),
    ("ec private",           85, "CRITICAL"),
    # Exchange / withdraw-capable keys
    ("withdraw",             70, "HIGH"),
    ("exchange api",         70, "HIGH"),
    ("trading key",          70, "HIGH"),
    # JWT / session secrets
    ("jwt secret",           60, "HIGH"),
    ("hmac secret",          60, "HIGH"),
    ("session secret",       60, "HIGH"),
    # Generic gitleaks (unverified)
    ("gitleaks",             40, "MEDIUM"),
    # IDOR with key material
    ("idor",                 35, "MEDIUM"),
    # Read-only / low-impact keys
    ("read-only",            20, "LOW"),
    ("api key",              20, "LOW"),
    ("public key",            5, "INFO"),
    ("eth address",           5, "INFO"),
]

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class PrioritizedFinding:
    source_type:  str          # "git" | "idor" | "header" | "jwt" | "token"
    severity:     str
    score:        int
    repo_or_url:  str
    location:     str          # file path, endpoint, header name
    description:  str
    redacted:     str = ""
    verified:     bool = False
    raw_finding:  Any = field(default=None, repr=False)

    def __str__(self) -> str:
        v = " ✓VERIFIED" if self.verified else ""
        return (
            f"[{self.severity}]{v} score={self.score:>3}  "
            f"{self.repo_or_url}:{self.location}\n"
            f"        {self.description}"
        )


class SmartPrioritizer:
    """
    Accepts findings from any KittyPaw module and returns a ranked,
    deduplicated list of PrioritizedFinding objects.
    """

    def __init__(self):
        self._seen_hashes: set = set()

    def rank(self, findings: list) -> List[PrioritizedFinding]:
        """
        Score, filter duplicates, and sort all findings.
        *findings* can be a mix of GitFinding, IDORFinding, or plain dicts.
        """
        prioritized: List[PrioritizedFinding] = []

        for f in findings:
            pf = self._convert(f)
            if pf is None:
                continue
            key = self._dedup_key(pf)
            if key in self._seen_hashes:
                continue
            self._seen_hashes.add(key)
            prioritized.append(pf)

        prioritized.sort(key=lambda x: (x.score, _SEVERITY_ORDER.get(x.severity, 0)), reverse=True)
        return prioritized

    def reset(self) -> None:
        """Clear dedup cache (call between separate scan sessions)."""
        self._seen_hashes.clear()

    # ── Conversion helpers ────────────────────────────────────────────────────

    def _convert(self, finding: Any) -> "PrioritizedFinding | None":
        # GitFinding
        if hasattr(finding, "finding_type") and hasattr(finding, "repo"):
            return self._from_git(finding)
        # IDORFinding
        if hasattr(finding, "endpoint") and hasattr(finding, "keys_found"):
            return self._from_idor(finding)
        # Generic dict (header, jwt, token findings)
        if isinstance(finding, dict):
            return self._from_dict(finding)
        return None

    def _from_git(self, f) -> PrioritizedFinding:
        desc  = f.description or f.finding_type
        score, severity = self._score(desc, base_severity=f.severity, verified=f.verified)
        return PrioritizedFinding(
            source_type="git",
            severity=severity,
            score=score,
            repo_or_url=f.repo,
            location=f.file_path or f.commit_hash[:8] if f.commit_hash else "",
            description=desc,
            redacted=f.redacted,
            verified=f.verified,
            raw_finding=f,
        )

    def _from_idor(self, f) -> PrioritizedFinding:
        key_types = ", ".join(k.get("type_name", "") for k in (f.keys_found or []))
        desc      = key_types or f"IDOR on {f.endpoint}"
        score, severity = self._score(desc, base_severity=f.severity)
        return PrioritizedFinding(
            source_type="idor",
            severity=severity,
            score=score,
            repo_or_url=getattr(f, "target", ""),
            location=f.endpoint,
            description=desc,
            redacted=getattr(f, "evidence", "")[:80],
            raw_finding=f,
        )

    def _from_dict(self, f: dict) -> PrioritizedFinding:
        desc     = f.get("description") or f.get("title") or "Finding"
        sev      = f.get("severity", "MEDIUM").upper()
        score, severity = self._score(desc, base_severity=sev)
        return PrioritizedFinding(
            source_type=f.get("category", "other"),
            severity=severity,
            score=score,
            repo_or_url=f.get("target") or f.get("url", ""),
            location=f.get("endpoint") or f.get("header") or "",
            description=desc,
            raw_finding=f,
        )

    # ── Scoring engine ────────────────────────────────────────────────────────

    @staticmethod
    def _score(description: str, base_severity: str = "MEDIUM",
               verified: bool = False) -> tuple[int, str]:
        desc_lower = description.lower()
        score      = _SEVERITY_ORDER.get(base_severity.upper(), 2) * 10
        severity   = base_severity.upper()

        for keyword, bonus, forced_sev in _RULES:
            if keyword in desc_lower:
                score    += bonus
                # Upgrade severity if the rule forces a higher one
                if _SEVERITY_ORDER.get(forced_sev, 0) > _SEVERITY_ORDER.get(severity, 0):
                    severity = forced_sev
                break  # first match wins severity override

        if verified:
            score += 50

        return score, severity

    @staticmethod
    def _dedup_key(pf: PrioritizedFinding) -> str:
        raw = f"{pf.repo_or_url}|{pf.location}|{pf.redacted or pf.description}"
        return hashlib.sha1(raw.encode(), usedforsecurity=False).hexdigest()


# ── Standalone demo ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    from modules.github_deep_scanner import GitFinding

    demo_findings = [
        GitFinding("org/repo", ".env", "abc123", "key_detector", "HIGH",
                   "Raw hex 64-char string", "deadbeef***"),
        GitFinding("org/repo", "config/secrets.js", "def456", "trufflehog",
                   "CRITICAL", "TruffleHog verified: Ethereum private key",
                   "0x1234***", verified=True),
        GitFinding("org/repo2", "deploy.sh", "789abc", "gitleaks",
                   "MEDIUM", "gitleaks: possible API key", "sk-***"),
    ]

    p = SmartPrioritizer()
    ranked = p.rank(demo_findings)
    print("\nRanked findings:\n")
    for pf in ranked:
        print(f"  {pf}\n")
