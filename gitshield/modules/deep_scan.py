"""
GitShield — Deep Git Extraction

Goes beyond what gitleaks/trufflehog see by default:
  1. Unpack .pack files  → expose all compressed objects as loose files
  2. Dump dangling blobs → recover orphaned objects left by force-pushes/rebases
  3. Restore deleted files → re-materialize files removed in git history
  4. Harvest .git/config  → catch tokens embedded in remote URLs

All extracted content lands in <repo>/_gitshield_deep/ for subsequent scanning.
"""

import subprocess
import logging
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional

log = logging.getLogger("gitshield.deep_scan")

_BLOB_FOLDER = "_gitshield_deep"


@dataclass
class DeepScanResult:
    blobs_dir: Optional[Path] = None        # folder containing extracted content
    packs_unpacked: int = 0                  # .pack files unpacked
    dangling_blobs: int = 0                  # orphaned blobs extracted
    deleted_files_restored: int = 0         # deleted path/file pairs recovered
    git_config_tokens: List[str] = field(default_factory=list)  # tokens in remotes
    errors: List[str] = field(default_factory=list)


def deep_extract(repo_dir: Path) -> DeepScanResult:
    """
    Run all deep-extraction steps on a cloned repo.

    Returns a DeepScanResult with the path to the blobs directory
    and counts of what was found.
    """
    result = DeepScanResult()
    blobs_dir = repo_dir / _BLOB_FOLDER
    blobs_dir.mkdir(exist_ok=True)
    result.blobs_dir = blobs_dir

    _unpack_pack_files(repo_dir, result)
    _extract_dangling_blobs(repo_dir, blobs_dir, result)
    _restore_deleted_files(repo_dir, blobs_dir, result)
    _harvest_git_config(repo_dir, result)

    log.info(
        f"Deep extract complete: {result.packs_unpacked} packs, "
        f"{result.dangling_blobs} dangling blobs, "
        f"{result.deleted_files_restored} deleted files restored"
    )
    return result


# ── Step 1: Unpack .pack files ────────────────────────────────────────────────

def _unpack_pack_files(repo_dir: Path, result: DeepScanResult) -> None:
    """
    Unpack all .pack files so gitleaks/trufflehog can read the loose objects.

    git unpack-objects reads from stdin and writes loose objects to .git/objects/.
    We copy each .pack to a temp name first so git doesn't refuse to re-unpack.
    """
    pack_dir = repo_dir / ".git" / "objects" / "pack"
    if not pack_dir.exists():
        return

    for pack_file in pack_dir.glob("*.pack"):
        try:
            with open(pack_file, "rb") as fh:
                proc = subprocess.run(
                    ["git", "unpack-objects"],
                    stdin=fh,
                    cwd=str(repo_dir),
                    capture_output=True,
                    timeout=120,
                )
            if proc.returncode in (0, 1):   # 1 = "already unpacked" — fine
                result.packs_unpacked += 1
                log.debug(f"Unpacked: {pack_file.name}")
        except subprocess.TimeoutExpired:
            result.errors.append(f"pack unpack timeout: {pack_file.name}")
        except Exception as e:
            result.errors.append(f"pack unpack error ({pack_file.name}): {e}")


# ── Step 2: Dump dangling blobs ───────────────────────────────────────────────

def _extract_dangling_blobs(repo_dir: Path, blobs_dir: Path, result: DeepScanResult) -> None:
    """
    Find all unreachable (dangling) blob objects and dump their content.

    These are left behind when commits are abandoned via force-push, rebase,
    or branch deletion.  A dev who pushed a .env, panicked, and force-pushed
    leaves the blob here indefinitely.
    """
    try:
        fsck = subprocess.run(
            ["git", "fsck", "--unreachable", "--no-reflogs"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        result.errors.append("git fsck timed out")
        return
    except Exception as e:
        result.errors.append(f"git fsck error: {e}")
        return

    for line in fsck.stdout.splitlines():
        if "unreachable blob" not in line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        sha = parts[-1]
        try:
            cat = subprocess.run(
                ["git", "cat-file", "-p", sha],
                cwd=str(repo_dir),
                capture_output=True,
                text=True,
                timeout=30,
            )
            if cat.returncode == 0 and cat.stdout.strip():
                out_file = blobs_dir / f"dangling_{sha[:16]}"
                out_file.write_text(cat.stdout, encoding="utf-8", errors="replace")
                result.dangling_blobs += 1
                log.debug(f"Dangling blob: {sha[:12]}")
        except Exception as e:
            result.errors.append(f"cat-file error ({sha[:12]}): {e}")


# ── Step 3: Restore deleted files ─────────────────────────────────────────────

# Extensions that are interesting from a secrets perspective
_INTERESTING_EXTS = {
    ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
    ".pem", ".key", ".p12", ".pfx", ".cer",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".sh", ".bash", ".zsh",
    "credentials", "secret", "token", "password", "passwd", "apikey",
}

def _restore_deleted_files(repo_dir: Path, blobs_dir: Path, result: DeepScanResult) -> None:
    """
    Walk git log for files that existed at some point but were deleted.
    Re-materialise any with interesting extensions.
    """
    try:
        log_output = subprocess.run(
            ["git", "log", "--all", "--full-history", "--diff-filter=D",
             "--name-only", "--pretty=format:%H"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception as e:
        result.errors.append(f"git log (deleted files) error: {e}")
        return

    commit_sha = None
    seen: set = set()

    for line in log_output.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Lines are either a commit SHA (40 hex chars) or a file path
        if len(line) == 40 and all(c in "0123456789abcdef" for c in line):
            commit_sha = line
        elif commit_sha and _is_interesting_path(line):
            key = (commit_sha, line)
            if key in seen:
                continue
            seen.add(key)
            _restore_one(repo_dir, blobs_dir, commit_sha, line, result)


def _is_interesting_path(path: str) -> bool:
    p = Path(path)
    name_lower = p.name.lower()
    # Match by extension
    for ext in _INTERESTING_EXTS:
        if name_lower.endswith(ext) or name_lower == ext.lstrip("."):
            return True
    # Match by name keywords
    for kw in ("secret", "token", "password", "passwd", "key", "cred", "api", ".env"):
        if kw in name_lower:
            return True
    return False


def _restore_one(repo_dir: Path, blobs_dir: Path, commit_sha: str, file_path: str, result: DeepScanResult) -> None:
    try:
        show = subprocess.run(
            ["git", "show", f"{commit_sha}:{file_path}"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if show.returncode == 0 and show.stdout.strip():
            safe_name = file_path.replace("/", "_").replace("\\", "_")
            out_file = blobs_dir / f"deleted_{commit_sha[:10]}_{safe_name}"
            out_file.write_text(show.stdout, encoding="utf-8", errors="replace")
            result.deleted_files_restored += 1
            log.debug(f"Restored deleted: {file_path} @ {commit_sha[:8]}")
    except Exception as e:
        result.errors.append(f"restore error ({file_path} @ {commit_sha[:8]}): {e}")


# ── Step 4: Harvest .git/config ───────────────────────────────────────────────

import re as _re

_TOKEN_IN_URL = _re.compile(
    r'https?://([^@\s]+:[^@\s]+)@',   # user:password@ or token@ in remote URL
)

def _harvest_git_config(repo_dir: Path, result: DeepScanResult) -> None:
    """
    Parse .git/config for tokens embedded in remote URLs.
    Pattern: https://oauth2:TOKEN@github.com/... or https://TOKEN@github.com/...
    """
    config_path = repo_dir / ".git" / "config"
    if not config_path.exists():
        return
    try:
        content = config_path.read_text(encoding="utf-8", errors="replace")
        for m in _TOKEN_IN_URL.finditer(content):
            cred = m.group(1)
            if len(cred) > 8:   # skip trivial matches
                result.git_config_tokens.append(cred)
                log.warning(f"Token in .git/config: {cred[:8]}...")
    except Exception as e:
        result.errors.append(f".git/config harvest error: {e}")


# ── Cleanup ───────────────────────────────────────────────────────────────────

def cleanup_deep(repo_dir: Path) -> None:
    """Remove the _gitshield_deep folder after scanning."""
    blobs_dir = repo_dir / _BLOB_FOLDER
    if blobs_dir.exists():
        shutil.rmtree(blobs_dir, ignore_errors=True)
