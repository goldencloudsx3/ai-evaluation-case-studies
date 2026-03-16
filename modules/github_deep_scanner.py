#!/usr/bin/env python3
"""
KittyPaw Scanner — GitHub Deep Scanner
Clones repos, unpacks git history, finds dangling blobs, runs gitleaks/trufflehog,
and scans deleted content with built-in key_detector.

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

from __future__ import annotations

import os
import re
import json
import shutil
import logging
import hashlib
import tempfile
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import requests

from modules.key_detector import KeyDetector

log = logging.getLogger(__name__)

_GH_API       = "https://api.github.com"
_TIMEOUT      = 20
_MAX_BLOB_KB  = 512      # skip blobs larger than this (avoid huge binaries)
_WORK_DIR     = os.path.join(tempfile.gettempdir(), "kittypaw_repos")


@dataclass
class GitFinding:
    repo:          str
    file_path:     str
    commit_hash:   str
    finding_type:  str       # "gitleaks" | "trufflehog" | "key_detector" | "git_config"
    severity:      str       # CRITICAL / HIGH / MEDIUM / LOW
    description:   str
    redacted:      str = ""
    source:        str = ""  # gitleaks / trufflehog / built-in
    verified:      bool = False

    def __str__(self) -> str:
        v = " [VERIFIED]" if self.verified else ""
        return f"[{self.severity}]{v} {self.repo}:{self.file_path} — {self.description}"


@dataclass
class DeepScanResult:
    repo_url:      str
    repo_name:     str
    findings:      List[GitFinding] = field(default_factory=list)
    blobs_scanned: int = 0
    commits_seen:  int = 0
    error:         Optional[str] = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")


class GitHubDeepScanner:
    """
    Deep-scans one or more GitHub repositories for leaked secrets.

    Usage:
        scanner = GitHubDeepScanner(github_token="ghp_...")
        results = scanner.scan_org("https://github.com/someorg", max_repos=5)
        results = scanner.scan_repo("https://github.com/someorg/somerepo")
    """

    def __init__(
        self,
        github_token:       Optional[str] = None,
        use_gitleaks:       bool = True,
        use_trufflehog:     bool = True,
        max_blob_kb:        int  = _MAX_BLOB_KB,
        work_dir:           str  = _WORK_DIR,
    ):
        self.github_token   = github_token or os.getenv("GITHUB_TOKEN")
        self.use_gitleaks   = use_gitleaks and self._tool_available("gitleaks")
        self.use_trufflehog = use_trufflehog and self._tool_available("trufflehog")
        self.max_blob_kb    = max_blob_kb
        self.work_dir       = work_dir
        self.key_detector   = KeyDetector()

        os.makedirs(self.work_dir, exist_ok=True)

        if not self.use_gitleaks:
            log.warning("gitleaks not found — install with: brew install gitleaks")
        if not self.use_trufflehog:
            log.warning("trufflehog not found — install with: brew install trufflehog")

    # ── Public API ────────────────────────────────────────────────────────────

    def scan_org(self, org_url: str, max_repos: int = 10) -> List[DeepScanResult]:
        """List all public repos for an org and deep-scan each one."""
        org = self._parse_org(org_url)
        if not org:
            log.error("Could not parse org from URL: %s", org_url)
            return []

        repos = self._list_org_repos(org, max_repos)
        log.info("Scanning %d repos in %s", len(repos), org)

        results = []
        for repo_url in repos:
            result = self.scan_repo(repo_url)
            results.append(result)
        return results

    def scan_repo(self, repo_url: str) -> DeepScanResult:
        """Full deep scan of a single repository."""
        repo_name = self._parse_repo_name(repo_url)
        result    = DeepScanResult(repo_url=repo_url, repo_name=repo_name)
        clone_dir = os.path.join(self.work_dir, repo_name.replace("/", "_"))

        try:
            log.info("Cloning %s …", repo_url)
            self._clone(repo_url, clone_dir)

            # 1 — Dangling blob scan (deleted files, orphaned commits)
            blobs = self._get_dangling_blobs(clone_dir)
            result.blobs_scanned = len(blobs)
            for blob_hash in blobs:
                findings = self._scan_blob(clone_dir, blob_hash, repo_name)
                result.findings.extend(findings)

            # 2 — Gitleaks full history scan
            if self.use_gitleaks:
                result.findings.extend(self._run_gitleaks(clone_dir, repo_name))

            # 3 — TruffleHog scan (verified secrets only)
            if self.use_trufflehog:
                result.findings.extend(self._run_trufflehog(repo_url, repo_name))

            # 4 — Commit count for stats
            result.commits_seen = self._count_commits(clone_dir)

        except Exception as exc:
            log.error("Scan failed for %s: %s", repo_url, exc)
            result.error = str(exc)
        finally:
            self._cleanup(clone_dir)

        return result

    def scan_exposed_git_config(self, target_url: str) -> List[GitFinding]:
        """
        Check if target exposes /.git/config — a common server misconfiguration.
        Looks for embedded tokens in remote URLs.
        """
        findings: List[GitFinding] = []
        url = target_url.rstrip("/") + "/.git/config"
        try:
            r = requests.get(url, timeout=_TIMEOUT,
                             headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200 and "[core]" in r.text:
                # Look for credentials embedded in remote URL
                for line in r.text.splitlines():
                    if "url = " in line:
                        m = re.search(r'https?://([^@\s]+)@', line)
                        if m:
                            token_hint = m.group(1)
                            redacted   = token_hint[:4] + "***"
                            findings.append(GitFinding(
                                repo=target_url,
                                file_path=".git/config",
                                commit_hash="",
                                finding_type="git_config",
                                severity="CRITICAL",
                                description="Credentials embedded in .git/config remote URL",
                                redacted=redacted,
                                source="built-in",
                                verified=False,
                            ))
                if not findings:
                    # Still a HIGH finding — exposes internal repo structure
                    findings.append(GitFinding(
                        repo=target_url,
                        file_path=".git/config",
                        commit_hash="",
                        finding_type="git_config",
                        severity="HIGH",
                        description=".git/config is publicly exposed (leaks repo structure)",
                        redacted="",
                        source="built-in",
                    ))
        except Exception:
            pass
        return findings

    # ── Clone + git operations ────────────────────────────────────────────────

    def _clone(self, repo_url: str, dest: str) -> None:
        if os.path.exists(dest):
            shutil.rmtree(dest)
        auth_url = self._inject_token(repo_url)
        self._run(["git", "clone", "--mirror", "--quiet", auth_url, dest])

    def _get_dangling_blobs(self, repo_dir: str) -> List[str]:
        """Return list of unreachable blob hashes (deleted/orphaned content)."""
        try:
            out = self._run(
                ["git", "-C", repo_dir, "fsck", "--unreachable", "--no-progress"],
                capture=True
            )
            blobs = []
            for line in out.splitlines():
                # Format: "unreachable blob <hash>"
                parts = line.split()
                if len(parts) == 3 and parts[0] == "unreachable" and parts[1] == "blob":
                    blobs.append(parts[2])
            return blobs
        except Exception as exc:
            log.debug("fsck failed: %s", exc)
            return []

    def _scan_blob(self, repo_dir: str, blob_hash: str, repo_name: str) -> List[GitFinding]:
        """Restore a dangling blob and scan its content with key_detector."""
        findings: List[GitFinding] = []
        try:
            # Check size first — skip huge blobs
            size_out = self._run(
                ["git", "-C", repo_dir, "cat-file", "-s", blob_hash],
                capture=True
            ).strip()
            size_kb = int(size_out) / 1024
            if size_kb > self.max_blob_kb:
                return findings

            content = self._run(
                ["git", "-C", repo_dir, "cat-file", "blob", blob_hash],
                capture=True
            )

            detected = self.key_detector.detect(content)
            for key_hit in detected:
                findings.append(GitFinding(
                    repo=repo_name,
                    file_path=f"<dangling blob {blob_hash[:8]}>",
                    commit_hash=blob_hash,
                    finding_type="key_detector",
                    severity=key_hit.get("severity", "HIGH"),
                    description=key_hit.get("type_name", "Key material in deleted content"),
                    redacted=key_hit.get("redacted", ""),
                    source="built-in",
                ))
        except Exception as exc:
            log.debug("Blob scan %s failed: %s", blob_hash[:8], exc)
        return findings

    def _count_commits(self, repo_dir: str) -> int:
        try:
            out = self._run(
                ["git", "-C", repo_dir, "rev-list", "--count", "--all"],
                capture=True
            ).strip()
            return int(out)
        except Exception:
            return 0

    # ── External tool runners ─────────────────────────────────────────────────

    def _run_gitleaks(self, repo_dir: str, repo_name: str) -> List[GitFinding]:
        findings: List[GitFinding] = []
        report_path = os.path.join(self.work_dir, f"gl_{repo_name.replace('/', '_')}.json")
        try:
            self._run([
                "gitleaks", "detect",
                "--source", repo_dir,
                "--report-format", "json",
                "--report-path", report_path,
                "--no-git",
                "--exit-code", "0",   # don't exit non-zero on findings
            ])
            if not os.path.exists(report_path):
                return findings
            with open(report_path) as f:
                data = json.load(f)
            for item in (data if isinstance(data, list) else []):
                findings.append(GitFinding(
                    repo=repo_name,
                    file_path=item.get("File", ""),
                    commit_hash=item.get("Commit", ""),
                    finding_type="gitleaks",
                    severity="HIGH",
                    description=item.get("Description", item.get("RuleID", "gitleaks match")),
                    redacted=item.get("Secret", "")[:8] + "***" if item.get("Secret") else "",
                    source="gitleaks",
                ))
        except Exception as exc:
            log.debug("gitleaks failed: %s", exc)
        finally:
            if os.path.exists(report_path):
                os.unlink(report_path)
        return findings

    def _run_trufflehog(self, repo_url: str, repo_name: str) -> List[GitFinding]:
        findings: List[GitFinding] = []
        auth_url = self._inject_token(repo_url)
        try:
            out = self._run(
                ["trufflehog", "git", auth_url,
                 "--json", "--only-verified", "--no-update"],
                capture=True
            )
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                det = item.get("DetectorName", item.get("detector_name", "trufflehog"))
                raw = item.get("Raw", item.get("raw", ""))
                redacted = str(raw)[:8] + "***" if raw else ""
                findings.append(GitFinding(
                    repo=repo_name,
                    file_path=item.get("SourceMetadata", {})
                                  .get("Data", {})
                                  .get("Git", {})
                                  .get("file", ""),
                    commit_hash=item.get("SourceMetadata", {})
                                    .get("Data", {})
                                    .get("Git", {})
                                    .get("commit", ""),
                    finding_type="trufflehog",
                    severity="CRITICAL",
                    description=f"TruffleHog verified: {det}",
                    redacted=redacted,
                    source="trufflehog",
                    verified=True,
                ))
        except Exception as exc:
            log.debug("trufflehog failed: %s", exc)
        return findings

    # ── GitHub API ────────────────────────────────────────────────────────────

    def _list_org_repos(self, org: str, max_repos: int) -> List[str]:
        headers: dict = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        urls: List[str] = []
        page = 1
        while len(urls) < max_repos:
            try:
                r = requests.get(
                    f"{_GH_API}/orgs/{org}/repos",
                    params={"per_page": min(100, max_repos - len(urls)), "page": page, "type": "public"},
                    headers=headers,
                    timeout=_TIMEOUT,
                )
                r.raise_for_status()
                repos = r.json()
                if not repos:
                    break
                for repo in repos:
                    clone_url = repo.get("clone_url") or repo.get("html_url", "")
                    if clone_url:
                        urls.append(clone_url)
                page += 1
                if len(repos) < 100:
                    break
            except Exception as exc:
                log.error("GitHub API failed for org %s: %s", org, exc)
                break

        return urls[:max_repos]

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _inject_token(self, url: str) -> str:
        if self.github_token and "github.com" in url:
            url = url.replace("https://", f"https://{self.github_token}@")
        return url

    @staticmethod
    def _parse_org(url: str) -> Optional[str]:
        m = re.match(r'https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/?$', url)
        return m.group(1) if m else None

    @staticmethod
    def _parse_repo_name(url: str) -> str:
        url = url.rstrip("/").removesuffix(".git")
        parts = url.split("/")
        if len(parts) >= 2:
            return f"{parts[-2]}/{parts[-1]}"
        return parts[-1]

    @staticmethod
    def _tool_available(name: str) -> bool:
        return shutil.which(name) is not None

    @staticmethod
    def _run(cmd: list, capture: bool = False) -> str:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode not in (0, 1):  # 1 = findings found (normal for scanners)
            raise RuntimeError(result.stderr.strip() or f"Command failed: {' '.join(cmd)}")
        return result.stdout or ""

    @staticmethod
    def _cleanup(path: str) -> None:
        try:
            if os.path.exists(path):
                shutil.rmtree(path)
        except Exception:
            pass
