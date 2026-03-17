#!/usr/bin/env python3
"""
GitShield — All-in-One GitHub Secret Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Modes:
  --mode private   Watch your own repos for new commits
  --mode public    Monitor GitHub public events
  --mode target    Scan a specific repo on demand

Telegram commands:
  /scan <url>      Deep-scan a specific repo
  /deep <url>      Force deep mode (dangling blobs + pack files) on a repo
  /hunt            Pull top Immunefi targets and scan all with GitHub orgs
  /targets         Show current Immunefi target list
  /report          Generate disclosure draft for most recent critical finding
  /bounty <amount> <platform> <project> [notes]
                   Log a confirmed bounty payout
  /earnings        Show earnings dashboard
  /status          Scanner stats
  /repos           List watched repos
  /help            Command reference
"""

import os
import sys
import json
import subprocess
import requests
import time
import logging
import argparse
import shutil
import hashlib
import threading
from datetime import datetime, timezone
from pathlib import Path

# ── Import GitShield modules ──────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from modules import immunefi, deep_scan, disclosure, earnings
from modules import ui

# ── Load .env if present ──────────────────────────────────────────────────────
env_path = Path(__file__).parent / ".env"
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

# ── Config ────────────────────────────────────────────────────────────────────
GITHUB_TOKEN      = os.getenv("GITHUB_TOKEN", "")
GITHUB_USERNAME   = os.getenv("GITHUB_USERNAME", "")
TELEGRAM_TOKEN    = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID  = os.getenv("TELEGRAM_CHAT_ID", "")
RESEARCHER_NAME   = os.getenv("RESEARCHER_NAME", "Security Researcher")
RESEARCHER_CONTACT = os.getenv("RESEARCHER_CONTACT", "")
IMMUNEFI_MIN_BOUNTY = int(os.getenv("IMMUNEFI_MIN_BOUNTY", "10000"))
DEEP_SCAN_DEFAULT = os.getenv("DEEP_SCAN_DEFAULT", "true").lower() == "true"

BASE_DIR          = Path.home() / "gitshield"
REPOS_DIR         = BASE_DIR / "repos"
REPORTS_DIR       = BASE_DIR / "reports"
STATE_FILE        = BASE_DIR / "state.json"
LOG_FILE          = BASE_DIR / "gitshield.log"

PRIVATE_POLL  = 300   # 5 min
PUBLIC_POLL   = 90    # 90 sec
TELEGRAM_POLL = 5     # 5 sec

GITHUB_HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

# ── Logging ───────────────────────────────────────────────────────────────────
BASE_DIR.mkdir(parents=True, exist_ok=True)
REPOS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("gitshield")

# ── Tool check ────────────────────────────────────────────────────────────────
def check_tools():
    missing = []
    for tool in ["gitleaks", "trufflehog", "git"]:
        if not shutil.which(tool):
            missing.append(tool)
    if missing:
        log.warning(f"Missing tools: {', '.join(missing)}")
        log.warning("Install: brew install gitleaks trufflehog git")
    return missing

# ── State ─────────────────────────────────────────────────────────────────────
def load_state():
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {
        "repos": {},
        "scanned_public": [],
        "last_findings": [],       # most recent critical findings for /report
        "immunefi_targets": [],    # cached target list from last /targets
        "stats": {"total_scans": 0, "leaks_found": 0},
    }

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

# ── Telegram ──────────────────────────────────────────────────────────────────
def tg_send(msg, parse_mode="Markdown"):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": parse_mode},
            timeout=10,
        )
    except Exception as e:
        log.error(f"Telegram send error: {e}")

def tg_send_file(path, caption=""):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        with open(path, "rb") as f:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument",
                data={"chat_id": TELEGRAM_CHAT_ID, "caption": caption},
                files={"document": f},
                timeout=30,
            )
    except Exception as e:
        log.error(f"Telegram file send error: {e}")

def tg_get_updates(offset=None):
    try:
        params = {"timeout": 10}
        if offset:
            params["offset"] = offset
        r = requests.get(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getUpdates",
            params=params, timeout=15,
        )
        return r.json().get("result", [])
    except:
        return []

# ── GitHub API ────────────────────────────────────────────────────────────────
def get_my_repos():
    repos, page = [], 1
    while True:
        r = requests.get(
            f"https://api.github.com/user/repos?per_page=100&page={page}&type=all",
            headers=GITHUB_HEADERS, timeout=15,
        )
        data = r.json()
        if not isinstance(data, list) or not data:
            break
        repos.extend(data)
        page += 1
    return repos

def get_latest_commit(repo_full_name, use_auth=True):
    headers = GITHUB_HEADERS if use_auth else {"Accept": "application/vnd.github.v3+json"}
    try:
        r = requests.get(
            f"https://api.github.com/repos/{repo_full_name}/commits?per_page=1",
            headers=headers, timeout=10,
        )
        data = r.json()
        if isinstance(data, list) and data:
            return data[0]["sha"]
    except:
        pass
    return None

def get_org_repos(org: str, limit: int = 100) -> list:
    """
    Fetch ALL repos from a GitHub org (or user), including archived ones.
    Sorted by priority: infra/devops repos first, then by most recently pushed.

    Expert note: DevOps / infra repos (containing 'deploy', 'infra', 'ops',
    'config', 'secrets', 'terraform', 'ansible', 'k8s') have the highest
    density of leaked credentials.  Archived repos are included because devs
    often leave .env files in them — they're forgotten but still public.
    """
    headers = GITHUB_HEADERS if GITHUB_TOKEN else {}
    all_repos, page = [], 1
    while True:
        for url_tmpl in (
            f"https://api.github.com/orgs/{org}/repos?per_page=100&page={page}&sort=pushed",
            f"https://api.github.com/users/{org}/repos?per_page=100&page={page}&sort=pushed",
        ):
            try:
                r = requests.get(url_tmpl, headers=headers, timeout=15)
                data = r.json()
                if isinstance(data, list) and data:
                    all_repos.extend(data)
                    break   # found on this endpoint
            except Exception:
                pass
        else:
            break   # neither endpoint returned data — done
        if len(data) < 100:
            break   # last page
        page += 1

    if not all_repos:
        log.warning(f"No repos found for org/user: {org}")
        return []

    return _prioritise_repos(all_repos)[:limit]


# Keywords that flag a repo as high-value for credential hunting
_INFRA_KEYWORDS = {
    "deploy", "infra", "ops", "devops", "config", "secret", "terraform",
    "ansible", "helm", "k8s", "kubernetes", "docker", "compose", "ci",
    "pipeline", "env", "vault", "credential", "key", "cert", "ssl", "tls",
    "aws", "gcp", "azure", "cloud",
}

def _priority_score(repo: dict) -> int:
    """Higher = scan first. Infra repos score highest."""
    score = 0
    name = (repo.get("name", "") + " " + repo.get("description", "")).lower()
    if any(kw in name for kw in _INFRA_KEYWORDS):
        score += 100
    if repo.get("archived"):
        score += 30   # archived = forgotten, often contains stale secrets
    if not repo.get("fork"):
        score += 20   # original repos > forks
    score += min(repo.get("stargazers_count", 0) // 10, 20)  # star signal
    return score

def _prioritise_repos(repos: list) -> list:
    return sorted(repos, key=_priority_score, reverse=True)

def get_public_events(etag=None):
    headers = {"Accept": "application/vnd.github.v3+json"}
    if etag:
        headers["If-None-Match"] = etag
    try:
        r = requests.get("https://api.github.com/events", headers=headers, timeout=15)
        new_etag = r.headers.get("ETag")
        if r.status_code == 304:
            return [], etag
        return r.json(), new_etag
    except:
        return [], etag

# ── Git Operations ────────────────────────────────────────────────────────────
def clone_or_pull(clone_url, repo_dir, use_auth=True, full_history=False):
    """
    Clone or update a repo.

    full_history=True  → no --depth flag; fetches every commit.
                         Required for dangling blob extraction and deleted-file
                         recovery because git fsck only sees locally-fetched objects.
    full_history=False → --depth=200 (faster, still covers most recent leaks).
    """
    if use_auth and GITHUB_TOKEN:
        clone_url = clone_url.replace("https://", f"https://{GITHUB_TOKEN}@")
    if repo_dir.exists():
        # Unshallow if we need full history and the existing clone is shallow
        if full_history:
            subprocess.run(
                ["git", "-C", str(repo_dir), "fetch", "--unshallow"],
                capture_output=True, timeout=300,
            )
        else:
            subprocess.run(
                ["git", "-C", str(repo_dir), "pull", "--ff-only"],
                capture_output=True, timeout=60,
            )
    else:
        clone_flags = [] if full_history else ["--depth=200"]
        subprocess.run(
            ["git", "clone"] + clone_flags + [clone_url, str(repo_dir)],
            capture_output=True, timeout=600,
        )

# ── Scanning ──────────────────────────────────────────────────────────────────
def run_gitleaks(repo_dir, report_prefix):
    report_path = REPORTS_DIR / f"{report_prefix}_gitleaks.json"
    subprocess.run(
        ["gitleaks", "detect", "--source", str(repo_dir),
         "--log-opts=--all", "-v",
         "--report-format", "json",
         "--report-path", str(report_path)],
        capture_output=True, text=True, timeout=300,
    )
    if report_path.exists():
        try:
            data = json.loads(report_path.read_text())
            return data if isinstance(data, list) else []
        except:
            pass
    return []

def run_trufflehog(scan_path, report_prefix):
    """Run TruffleHog on a path (repo dir or extracted blobs dir)."""
    report_path = REPORTS_DIR / f"{report_prefix}_trufflehog.json"
    findings = []
    try:
        result = subprocess.run(
            ["trufflehog", "filesystem", str(scan_path), "--json", "--no-update"],
            capture_output=True, text=True, timeout=300,
        )
        report_path.write_text(result.stdout)
        for line in result.stdout.strip().splitlines():
            try:
                findings.append(json.loads(line))
            except:
                pass
    except Exception as e:
        log.error(f"TruffleHog error: {e}")
    return findings

def scan_repo(repo_dir, repo_name, repo_full_name,
              commit_sha=None, source="private", do_deep=False):
    """
    Full scan: gitleaks + trufflehog, optionally with deep extraction first.
    Returns (report_data, json_path, html_path).
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix = f"{repo_name}_{timestamp}"
    log.info(f"Scanning {repo_full_name}  [deep={do_deep}]")

    deep_result = None
    if do_deep:
        tg_send(f"🔬 *Deep extraction started*\n`{repo_full_name}`")
        deep_result = deep_scan.deep_extract(repo_dir)
        log.info(
            f"Deep: {deep_result.packs_unpacked} packs, "
            f"{deep_result.dangling_blobs} dangling blobs, "
            f"{deep_result.deleted_files_restored} deleted files"
        )

    gl_findings = run_gitleaks(repo_dir, prefix)

    # TruffleHog on repo + extracted blobs folder (if deep)
    th_findings = run_trufflehog(repo_dir, prefix)
    if deep_result and deep_result.blobs_dir and deep_result.blobs_dir.exists():
        th_deep = run_trufflehog(deep_result.blobs_dir, f"{prefix}_deep")
        th_findings.extend(th_deep)

    # Surface .git/config token hits as TH-style findings
    if deep_result:
        for token in deep_result.git_config_tokens:
            th_findings.append({
                "DetectorName": "git_config_token",
                "Verified": False,
                "SourceMetadata": {"Data": {"Filesystem": {"file": ".git/config"}}},
                "_raw": token,
            })

    total = len(gl_findings) + len(th_findings)

    # Update state stats
    state = load_state()
    state["stats"]["total_scans"] = state["stats"].get("total_scans", 0) + 1
    if total > 0:
        state["stats"]["leaks_found"] = state["stats"].get("leaks_found", 0) + total
        # Cache findings for /report command
        state["last_findings"] = {
            "repo_full_name": repo_full_name,
            "repo_url": f"https://github.com/{repo_full_name}",
            "gitleaks": gl_findings[:5],
            "trufflehog": th_findings[:5],
        }
    save_state(state)

    report_data = {
        "repo": repo_full_name,
        "commit": commit_sha,
        "timestamp": timestamp,
        "source": source,
        "deep": do_deep,
        "deep_stats": {
            "packs_unpacked": deep_result.packs_unpacked if deep_result else 0,
            "dangling_blobs": deep_result.dangling_blobs if deep_result else 0,
            "deleted_files_restored": deep_result.deleted_files_restored if deep_result else 0,
        } if deep_result else {},
        "gitleaks": gl_findings,
        "trufflehog": th_findings,
        "total_findings": total,
    }

    json_path = REPORTS_DIR / f"{prefix}_report.json"
    json_path.write_text(json.dumps(report_data, indent=2))

    html_path = REPORTS_DIR / f"{prefix}_report.html"
    generate_html_report(report_data, html_path)

    # Cleanup extracted blobs after scanning
    if deep_result:
        deep_scan.cleanup_deep(repo_dir)

    return report_data, json_path, html_path

# ── HTML Report ───────────────────────────────────────────────────────────────
def generate_html_report(data, output_path):
    repo        = data["repo"]
    commit      = data.get("commit", "N/A")
    timestamp   = data["timestamp"]
    source      = data["source"]
    gl          = data["gitleaks"]
    th          = data["trufflehog"]
    total       = data["total_findings"]
    deep_stats  = data.get("deep_stats", {})
    status       = "CRITICAL" if total > 0 else "CLEAN"
    status_color = "#ff3c3c" if total > 0 else "#00ff9d"

    def gl_rows():
        if not gl:
            return "<tr><td colspan='4' style='text-align:center;color:#666;padding:20px'>No findings</td></tr>"
        rows = ""
        for f in gl:
            rule  = f.get("RuleID", "unknown")
            file_ = f.get("File", "?")
            line  = f.get("StartLine", "?")
            rows += f"""
            <tr>
                <td><span class="badge badge-HIGH">HIGH</span></td>
                <td><code>{rule}</code></td>
                <td><code>{file_}</code></td>
                <td>{line}</td>
            </tr>"""
        return rows

    def th_rows():
        if not th:
            return "<tr><td colspan='4' style='text-align:center;color:#666;padding:20px'>No findings</td></tr>"
        rows = ""
        for f in th:
            detector = f.get("DetectorName", "unknown")
            verified = f.get("Verified", False)
            sev      = "CRITICAL" if verified else "MEDIUM"
            sev_cls  = "critical" if verified else "medium"
            src      = f.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
            file_    = src.get("file", "?")
            line_    = src.get("line", "?")
            rows += f"""
            <tr>
                <td><span class="badge badge-{sev_cls}">{sev}</span></td>
                <td><code>{detector}</code></td>
                <td><code>{file_}</code></td>
                <td>{line_} {"✓ VERIFIED LIVE" if verified else ""}</td>
            </tr>"""
        return rows

    deep_banner = ""
    if data.get("deep"):
        ds = deep_stats
        deep_banner = f"""
  <div class="deep-banner">
    🔬 Deep scan active &nbsp;·&nbsp;
    {ds.get('packs_unpacked', 0)} packs unpacked &nbsp;·&nbsp;
    {ds.get('dangling_blobs', 0)} dangling blobs &nbsp;·&nbsp;
    {ds.get('deleted_files_restored', 0)} deleted files restored
  </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GitShield Report — {repo}</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg:#0a0a0f;--surface:#111118;--border:#1e1e2e;
    --accent:#7c3aed;--accent2:#06b6d4;--text:#e2e8f0;--muted:#4a5568;
    --clean:#00ff9d;--warn:#f59e0b;--danger:#ff3c3c;--critical:#ff0060;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;min-height:100vh}}
  body::before{{content:'';position:fixed;top:0;left:0;right:0;bottom:0;
    background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.03) 2px,rgba(0,0,0,.03) 4px);
    pointer-events:none;z-index:1000}}
  .header{{background:linear-gradient(135deg,#0d0d1a 0%,#120d1f 100%);
    border-bottom:1px solid var(--border);padding:40px 60px;position:relative;overflow:hidden}}
  .header::after{{content:'GITSHIELD';position:absolute;right:-20px;top:50%;transform:translateY(-50%);
    font-size:120px;font-family:'Syne',sans-serif;font-weight:800;color:rgba(124,58,237,.04);
    letter-spacing:-5px;pointer-events:none;user-select:none}}
  .header-top{{display:flex;align-items:center;gap:16px;margin-bottom:24px}}
  .logo{{width:40px;height:40px;background:linear-gradient(135deg,var(--accent),var(--accent2));
    border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px}}
  .brand{{font-family:'Syne',sans-serif;font-weight:800;font-size:18px;letter-spacing:4px}}
  .status-pill{{margin-left:auto;padding:8px 20px;border-radius:100px;font-family:'Syne',sans-serif;
    font-weight:700;font-size:14px;letter-spacing:3px;border:2px solid {status_color};
    color:{status_color};animation:pulse 2s ease-in-out infinite}}
  @keyframes pulse{{0%,100%{{box-shadow:0 0 20px {status_color}22}}50%{{box-shadow:0 0 40px {status_color}44}}}}
  .repo-name{{font-family:'Syne',sans-serif;font-weight:800;font-size:32px;margin-bottom:8px}}
  .meta{{display:flex;gap:24px;color:var(--muted);font-size:12px}}
  .meta .dot{{width:6px;height:6px;border-radius:50%;background:var(--accent);display:inline-block;margin-right:6px}}
  .deep-banner{{background:rgba(6,182,212,.1);border:1px solid rgba(6,182,212,.3);border-radius:8px;
    padding:12px 20px;margin:16px 0 0;font-size:13px;color:var(--accent2)}}
  .container{{max-width:1200px;margin:0 auto;padding:40px 60px}}
  .stats-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:48px}}
  .stat-card{{background:var(--surface);border:1px solid var(--border);border-radius:12px;
    padding:24px;position:relative;overflow:hidden}}
  .stat-card::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px;
    background:linear-gradient(90deg,var(--accent),var(--accent2));opacity:.6}}
  .stat-label{{font-size:11px;letter-spacing:2px;color:var(--muted);text-transform:uppercase;margin-bottom:12px}}
  .stat-value{{font-family:'Syne',sans-serif;font-size:36px;font-weight:800;line-height:1}}
  .stat-value.danger{{color:var(--danger)}}.stat-value.clean{{color:var(--clean)}}
  .stat-value.warn{{color:var(--warn)}}.stat-value.accent{{color:var(--accent2)}}
  .section{{margin-bottom:40px}}
  .section-header{{display:flex;align-items:center;gap:12px;margin-bottom:20px;
    padding-bottom:12px;border-bottom:1px solid var(--border)}}
  .section-title{{font-family:'Syne',sans-serif;font-weight:700;font-size:16px;
    letter-spacing:3px;text-transform:uppercase}}
  .section-badge{{background:var(--border);color:var(--muted);border-radius:100px;padding:3px 10px;font-size:11px}}
  .tool-tag{{margin-left:auto;font-size:10px;letter-spacing:2px;color:var(--accent2);
    border:1px solid var(--accent2);padding:3px 10px;border-radius:100px;opacity:.7}}
  table{{width:100%;border-collapse:collapse;background:var(--surface);
    border-radius:12px;overflow:hidden;border:1px solid var(--border)}}
  thead tr{{background:rgba(124,58,237,.1);border-bottom:1px solid var(--border)}}
  th{{text-align:left;padding:14px 20px;font-size:10px;letter-spacing:2px;
    text-transform:uppercase;color:var(--muted);font-weight:400}}
  td{{padding:14px 20px;font-size:13px;border-bottom:1px solid var(--border);vertical-align:middle}}
  tr:last-child td{{border-bottom:none}}tr:hover td{{background:rgba(124,58,237,.05)}}
  code{{background:rgba(255,255,255,.05);padding:2px 8px;border-radius:4px;
    font-size:12px;color:var(--accent2);word-break:break-all}}
  .badge{{display:inline-block;padding:3px 10px;border-radius:100px;font-size:10px;font-weight:700;letter-spacing:1px}}
  .badge-HIGH{{background:rgba(255,60,60,.15);color:#ff6b6b;border:1px solid rgba(255,60,60,.3)}}
  .badge-critical{{background:rgba(255,0,96,.15);color:#ff0060;border:1px solid rgba(255,0,96,.4)}}
  .badge-medium{{background:rgba(245,158,11,.15);color:#f59e0b;border:1px solid rgba(245,158,11,.3)}}
  .footer{{margin-top:60px;padding-top:24px;border-top:1px solid var(--border);
    display:flex;justify-content:space-between;color:var(--muted);font-size:11px;letter-spacing:1px}}
</style>
</head>
<body>
<div class="header">
  <div class="header-top">
    <div class="logo">🛡</div>
    <div class="brand">GITSHIELD</div>
    <div class="status-pill">{status}</div>
  </div>
  <div class="repo-name">{repo}</div>
  <div class="meta">
    <span><span class="dot"></span>Commit: {str(commit)[:12] if commit else 'N/A'}</span>
    <span><span class="dot"></span>{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}</span>
    <span><span class="dot"></span>Source: {source.upper()}</span>
  </div>
  {deep_banner}
</div>
<div class="container">
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Total Findings</div>
      <div class="stat-value {'danger' if total > 0 else 'clean'}">{total}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Gitleaks</div>
      <div class="stat-value {'warn' if gl else 'clean'}">{len(gl)}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">TruffleHog</div>
      <div class="stat-value {'warn' if th else 'clean'}">{len(th)}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Verified Live</div>
      <div class="stat-value {'danger' if any(f.get('Verified') for f in th) else 'accent'}">
        {sum(1 for f in th if f.get('Verified', False))}
      </div>
    </div>
  </div>
  <div class="section">
    <div class="section-header">
      <div class="section-title">Gitleaks Findings</div>
      <div class="section-badge">{len(gl)} issues</div>
      <div class="tool-tag">GITLEAKS</div>
    </div>
    <table>
      <thead><tr><th>Severity</th><th>Rule</th><th>File</th><th>Line</th></tr></thead>
      <tbody>{gl_rows()}</tbody>
    </table>
  </div>
  <div class="section">
    <div class="section-header">
      <div class="section-title">TruffleHog Findings</div>
      <div class="section-badge">{len(th)} issues</div>
      <div class="tool-tag">TRUFFLEHOG</div>
    </div>
    <table>
      <thead><tr><th>Severity</th><th>Detector</th><th>File</th><th>Line / Status</th></tr></thead>
      <tbody>{th_rows()}</tbody>
    </table>
  </div>
  {_immunefi_checklist(gl, th, data.get('deep', False), data.get('deep_stats', {}))}
  <div class="footer">
    <span>⬡ GitShield Security Scanner</span>
    <span>Generated {timestamp} · Gitleaks + TruffleHog</span>
  </div>
</div>
</body>
</html>"""
    output_path.write_text(html)


def _immunefi_checklist(gl: list, th: list, deep: bool, deep_stats: dict) -> str:
    """
    Return an HTML block with the Immunefi pre-submission compliance checklist.
    Items that GitShield can auto-assess are pre-filled with pass/warn state.
    Items requiring manual action are shown as interactive checkboxes.

    Key Immunefi rule for secret exposure (v2.3):
      • Leaked key in git history WITH NO proof of production use → OUT OF SCOPE by default
      • Leaked key WITH proof it is live in production → potentially in scope (Web/App: Critical)
      • TruffleHog Verified=True is the clearest signal of production use.
    """
    if not gl and not th:
        return ""   # clean scan — no checklist needed

    verified_live   = sum(1 for f in th if f.get("Verified", False))
    total_findings  = len(gl) + len(th)
    has_crypto_key  = any(
        t in f.get("DetectorName", "").lower() + f.get("RuleID", "").lower()
        for f in (th + gl)
        for t in ("eth", "btc", "bitcoin", "ethereum", "private", "mnemonic",
                  "seed", "solana", "wif", "xpriv", "keystore")
    )

    # ── Auto-assessed items ────────────────────────────────────────────────────
    def _auto(ok: bool, label: str, detail: str = "") -> str:
        icon   = "✓" if ok else "⚠"
        cls    = "auto-pass" if ok else "auto-warn"
        detail_html = f'<span class="chk-detail">{detail}</span>' if detail else ""
        return f'<li class="chk-item {cls}"><span class="chk-icon">{icon}</span>{label}{detail_html}</li>'

    # ── Manual checkbox items ──────────────────────────────────────────────────
    def _manual(label: str, detail: str = "", warn: bool = False) -> str:
        cls = "manual-warn" if warn else "manual"
        detail_html = f'<span class="chk-detail">{detail}</span>' if detail else ""
        return (
            f'<li class="chk-item {cls}">'
            f'<input type="checkbox" class="chk-box"> {label}{detail_html}'
            f'</li>'
        )

    # Build checklist sections
    validity_items = [
        _auto(verified_live > 0,
              "Key verified live by TruffleHog",
              "CRITICAL — out of scope without proof of production use" if verified_live == 0 else f"{verified_live} key(s) confirmed active"),
        _auto(deep,
              "Full git history scanned (deep mode)",
              "dangling blobs + pack files checked" if deep else "Run with --deep for complete coverage"),
        _auto(bool(deep_stats.get("dangling_blobs")),
              f"Dangling blobs extracted ({deep_stats.get('dangling_blobs', 0)} found)",
              "Force-pushed deletions recovered") if deep else "",
    ]

    scope_items = [
        _manual("Confirm program is active on Immunefi with &gt; $10k max bounty",
                "Check immunefi.com/explore — verify bug bounty page is live"),
        _manual("Confirm leaked key / asset is listed in the program's in-scope assets",
                "Leaked keys are OUT OF SCOPE by default unless program explicitly includes them",
                warn=True),
        _manual("Select correct impact type from the program's dropdown",
                "Web/App: 'Retrieve sensitive server data (blockchain keys)' → CRITICAL. Do NOT create custom impact."),
        _manual("Verify key is NOT a test / example / placeholder key",
                "Check if key controls a real funded wallet; test keys = automatic rejection",
                warn=has_crypto_key and not verified_live),
        _manual("Confirm key has NOT been rotated / revoked since discovery",
                "Submit within hours of discovery — rotated keys = invalid report"),
    ]

    poc_items = [
        _manual("Prepare Proof of Concept demonstrating live key control",
                "For crypto keys: show wallet balance via etherscan/solscan. For API keys: show authenticated API call with the key.",
                warn=True),
        _manual("Calculate funds at risk (wallet balance × token price at submission time)",
                "Required for Critical submissions — quantify exact USD value at risk"),
        _manual("For smart contract bugs: use Foundry/Hardhat mainnet fork",
                "Unit tests are NOT accepted. Must reflect actual deployed contract state."),
        _manual("PoC goes in the dedicated PoC field, NOT embedded in description",
                "Immunefi's form has a separate PoC field — use it"),
    ]

    report_items = [
        _manual("Title format: '[Vulnerability Type] in [Repo/Contract] leads to [Impact]'",
                "Example: 'Exposed ETH Private Key in deployment script gives full wallet control'"),
        _manual("Description explains how key ended up exposed (git history / dangling blob / deleted file)",
                "Include commit SHA, file path, and when it was introduced"),
        _manual("Recommendation section included (rotate key, purge git history, add pre-commit hooks)",
                "Optional but significantly strengthens payout justification"),
        _manual("Report written entirely in English",
                "Non-English reports are automatically rejected"),
        _manual("All form fields filled — no empty sections"),
        _manual("Payout wallet address is an EOA (externally owned account)",
                "Smart contract wallets and CEX wallets are NOT supported"),
    ]

    disclosure_items = [
        _manual("Submit ONLY through the Immunefi dashboard — no direct project contact",
                "Contacting the project directly voids your payout and risks a ban",
                warn=True),
        _manual("Do NOT publicly disclose — not even that a report exists",
                "Disclosure before fix + payment = ban + payout forfeiture",
                warn=True),
        _manual("KYC ready for Critical submission (government ID required)",
                "Immunefi uses an external KYC service — have ID ready before submission"),
        _manual("Check for duplicates — search if the same key was previously reported",
                "Only the first fully-complete escalated report counts"),
    ]

    def _section(title: str, items: list, color: str = "#7c3aed") -> str:
        rows = "\n".join(i for i in items if i)
        return f"""
    <div class="chk-section">
      <div class="chk-section-title" style="color:{color}">{title}</div>
      <ul class="chk-list">{rows}</ul>
    </div>"""

    scope_color = "#ff3c3c" if not verified_live else "#7c3aed"

    # ── Eligibility banner ─────────────────────────────────────────────────────
    if verified_live > 0:
        elig_class = "elig-yes"
        elig_icon  = "◉"
        elig_text  = (
            f"{verified_live} key(s) verified live by TruffleHog — "
            f"<strong>potentially in scope for Critical (Web/App)</strong>. "
            "Complete the checklist below before submitting."
        )
    else:
        elig_class = "elig-warn"
        elig_icon  = "⚠"
        elig_text  = (
            "No keys verified live by TruffleHog. "
            "<strong>Leaked keys without proof of production use are OUT OF SCOPE by default on Immunefi.</strong> "
            "You must manually verify the key is active before submitting."
        )

    return f"""
  <div class="section">
    <div class="section-header">
      <div class="section-title">Immunefi Pre-Submission Checklist</div>
      <div class="section-badge">{total_findings} finding(s)</div>
      <div class="tool-tag">IMMUNEFI v2.3</div>
    </div>

    <div class="elig-banner {elig_class}">
      <span class="elig-icon">{elig_icon}</span>
      {elig_text}
    </div>

    <div class="chk-grid">
      {_section("1 · Validity &amp; Evidence", validity_items, "#06b6d4")}
      {_section("2 · Scope Verification", scope_items, scope_color)}
      {_section("3 · Proof of Concept", poc_items, "#f59e0b")}
      {_section("4 · Report Quality", report_items, "#7c3aed")}
      {_section("5 · Disclosure Rules", disclosure_items, "#ff3c3c")}
    </div>

    <div class="chk-sources">
      Sources: Immunefi Severity System v2.3 · Bug Report Submission Checklist ·
      Common Vulnerability Exclusion List · PoC Guidelines
    </div>
  </div>

<style>
  .elig-banner{{display:flex;align-items:flex-start;gap:14px;padding:18px 24px;
    border-radius:12px;margin-bottom:28px;font-size:14px;line-height:1.5}}
  .elig-yes{{background:rgba(0,255,157,.08);border:1px solid rgba(0,255,157,.25);color:#e2e8f0}}
  .elig-warn{{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.3);color:#e2e8f0}}
  .elig-icon{{font-size:20px;margin-top:1px;flex-shrink:0}}
  .elig-yes .elig-icon{{color:#00ff9d}}
  .elig-warn .elig-icon{{color:#f59e0b}}
  .chk-grid{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px}}
  .chk-section{{background:var(--surface);border:1px solid var(--border);
    border-radius:12px;padding:20px}}
  .chk-section-title{{font-family:'Syne',sans-serif;font-weight:700;font-size:12px;
    letter-spacing:2px;text-transform:uppercase;margin-bottom:14px}}
  .chk-list{{list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:8px}}
  .chk-item{{display:flex;align-items:flex-start;gap:10px;font-size:12px;
    line-height:1.4;color:var(--text)}}
  .chk-icon{{flex-shrink:0;font-size:13px;font-weight:700;margin-top:1px}}
  .auto-pass .chk-icon{{color:#00ff9d}}
  .auto-warn .chk-icon{{color:#f59e0b}}
  .chk-box{{flex-shrink:0;margin-top:3px;accent-color:#7c3aed;width:14px;height:14px;cursor:pointer}}
  .chk-detail{{display:block;font-size:11px;color:var(--muted);margin-top:2px;margin-left:24px}}
  .manual-warn{{color:#f59e0b}}
  .chk-sources{{font-size:11px;color:var(--muted);padding-top:12px;
    border-top:1px solid var(--border);text-align:center}}
  @media(max-width:900px){{.chk-grid{{grid-template-columns:1fr}}}}
</style>"""

# ── Telegram Alerts ───────────────────────────────────────────────────────────
def alert_findings(report_data, json_path, html_path):
    repo     = report_data["repo"]
    commit   = report_data.get("commit", "N/A")
    total    = report_data["total_findings"]
    gl       = report_data["gitleaks"]
    th       = report_data["trufflehog"]
    verified = sum(1 for f in th if f.get("Verified", False))

    if total == 0:
        log.info(f"✅ Clean: {repo}")
        return

    msg  = f"🚨 *SECRET LEAK DETECTED*\n\n"
    msg += f"*Repo:* `{repo}`\n"
    msg += f"*Commit:* `{str(commit)[:12]}`\n"
    msg += f"*Total Findings:* `{total}`\n"
    if verified:
        msg += f"*⚠️ VERIFIED LIVE KEYS:* `{verified}`\n"
    if report_data.get("deep"):
        ds = report_data.get("deep_stats", {})
        msg += (
            f"\n🔬 *Deep scan:* "
            f"{ds.get('packs_unpacked',0)} packs · "
            f"{ds.get('dangling_blobs',0)} dangling blobs · "
            f"{ds.get('deleted_files_restored',0)} deleted files\n"
        )
    msg += f"\n*Gitleaks ({len(gl)}):*\n"
    for f in gl[:3]:
        msg += f"  ▸ `{f.get('RuleID','?')}` → `{f.get('File','?')}`\n"
    if len(gl) > 3:
        msg += f"  _...+{len(gl)-3} more_\n"
    msg += f"\n*TruffleHog ({len(th)}):*\n"
    for f in th[:3]:
        det = f.get("DetectorName", "?")
        ver = " ✓ LIVE" if f.get("Verified") else ""
        msg += f"  ▸ `{det}`{ver}\n"
    if len(th) > 3:
        msg += f"  _...+{len(th)-3} more_\n"
    msg += f"\n_Rotate any exposed keys immediately._\n"
    if verified:
        msg += (
            f"\n✅ *Immunefi eligibility:* Key(s) verified live — "
            f"potentially in scope as Critical (Web/App).\n"
            f"Use /report then complete the pre-submission checklist in the HTML report."
        )
    else:
        msg += (
            f"\n⚠️ *Immunefi eligibility:* No keys verified live. "
            f"Leaked keys without proof of production use are OUT OF SCOPE by default.\n"
            f"Manually verify key is active before submitting to Immunefi."
        )

    tg_send(msg)
    tg_send_file(html_path, caption=f"📊 Report: {repo}")
    tg_send_file(json_path, caption=f"📄 JSON: {repo}")
    ui.print_scan_result(
        repo, total, len(gl), len(th), verified,
        deep_stats=report_data.get("deep_stats") if report_data.get("deep") else None,
    )
    log.warning(f"🚨 LEAK: {repo} — {total} findings ({verified} verified live)")

# ── Target scan helper ────────────────────────────────────────────────────────
def _parse_repo_url(repo_url: str):
    """Return (full_name, clone_url) from a GitHub URL or 'org/repo' string."""
    repo_url = repo_url.strip().rstrip("/")
    if not repo_url.startswith("http"):
        repo_url = f"https://github.com/{repo_url}"
    parts = repo_url.replace("https://github.com/", "").split("/")
    if len(parts) < 2:
        return None, None
    full_name  = f"{parts[0]}/{parts[1]}"
    clone_url  = f"https://github.com/{full_name}.git"
    return full_name, clone_url

def run_target_scan(repo_url: str, do_deep: bool = None):
    if do_deep is None:
        do_deep = DEEP_SCAN_DEFAULT
    full_name, clone_url = _parse_repo_url(repo_url)
    if not full_name:
        log.error(f"Invalid repo URL: {repo_url}")
        tg_send(f"❌ Invalid repo URL: `{repo_url}`")
        return None
    repo_name = full_name.split("/")[-1]
    repo_dir  = REPOS_DIR / f"target_{repo_name}"

    ui.print_scan_start(full_name, mode="target", deep=do_deep)
    tg_send(f"🔍 *Scan started*\n`{full_name}`" + (" · 🔬 deep mode" if do_deep else ""))

    try:
        clone_or_pull(clone_url, repo_dir, use_auth=bool(GITHUB_TOKEN),
                      full_history=do_deep)
        report_data, json_path, html_path = scan_repo(
            repo_dir, repo_name, full_name, source="target", do_deep=do_deep
        )
        alert_findings(report_data, json_path, html_path)
        if report_data["total_findings"] == 0:
            tg_send(f"✅ *Clean scan*\n`{full_name}` — no secrets found.")
        return report_data, json_path, html_path
    except Exception as e:
        log.error(f"Target scan error: {e}")
        tg_send(f"❌ *Scan failed*\n`{full_name}`\n`{e}`")
        return None

# ── Hunt mode — Immunefi + GitHub org scanning ────────────────────────────────
def run_hunt(min_bounty: int = None):
    """Pull Immunefi targets and deep-scan all repos for programs with GitHub orgs."""
    if min_bounty is None:
        min_bounty = IMMUNEFI_MIN_BOUNTY

    ui.print_banner(mode="hunt")
    ui.divider("IMMUNEFI TARGETS")
    tg_send(f"🎯 *Hunt started*\nFetching Immunefi targets ≥ ${min_bounty:,}…")
    programs = immunefi.fetch_targets(min_bounty_usd=min_bounty, limit=15)

    if not programs:
        tg_send("⚠️ No targets fetched from Immunefi. Try again later.")
        return

    with_orgs = [p for p in programs if p.github_orgs]
    tg_send(
        f"📋 {len(programs)} programs fetched · "
        f"{len(with_orgs)} have GitHub orgs\n"
        f"Starting deep scans…"
    )

    # Cache targets in state
    state = load_state()
    state["immunefi_targets"] = [
        {"name": p.name, "slug": p.slug, "max_bounty_usd": p.max_bounty_usd,
         "github_orgs": p.github_orgs, "bounty_display": p.bounty_display}
        for p in programs
    ]
    save_state(state)

    total_repos_scanned = 0
    total_findings = 0

    for program in with_orgs:
        for org_url in program.github_orgs:
            org_name = org_url.rstrip("/").split("/")[-1]
            # get_org_repos returns ALL repos, infra/devops prioritised first
            repos = get_org_repos(org_name)
            infra_count = sum(1 for r in repos if _priority_score(r) >= 100)
            ui.print_hunt_target(
                with_orgs.index(program) + 1,
                program.name, program.bounty_display,
                org_name, len(repos),
            )
            ui.info(f"{infra_count} infra/devops repos (scanned first)")
            tg_send(
                f"🏢 *{program.name}* ({program.bounty_display})\n"
                f"  org: `{org_name}` · {len(repos)} repos"
                f" ({infra_count} infra-priority)"
            )
            for repo_info in repos:
                clone_url = repo_info.get("clone_url", "")
                full_name = repo_info.get("full_name", "")
                if not clone_url or not full_name:
                    continue
                repo_name = repo_info.get("name", full_name.split("/")[-1])
                repo_dir  = REPOS_DIR / f"hunt_{repo_name}"
                archived  = repo_info.get("archived", False)
                try:
                    ui.info(
                        f"scanning {full_name}"
                        + (" [archived]" if archived else "")
                    )
                    clone_or_pull(clone_url, repo_dir,
                                  use_auth=bool(GITHUB_TOKEN),
                                  full_history=True)
                    report_data, json_path, html_path = scan_repo(
                        repo_dir, repo_name, full_name,
                        source=f"hunt/{program.name}", do_deep=True
                    )
                    alert_findings(report_data, json_path, html_path)
                    total_repos_scanned += 1
                    total_findings += report_data["total_findings"]
                except Exception as e:
                    log.error(f"Hunt scan error ({full_name}): {e}")

    tg_send(
        f"✅ *Hunt complete*\n"
        f"  Repos scanned: `{total_repos_scanned}`\n"
        f"  Total findings: `{total_findings}`\n"
        + (f"  _Use /report to draft a disclosure._" if total_findings > 0 else "  _No secrets found this run._")
    )

# ── Disclosure command ────────────────────────────────────────────────────────
def cmd_report():
    """Generate a disclosure draft for the most recent critical finding."""
    state = load_state()
    last = state.get("last_findings")
    if not last:
        tg_send("ℹ️ No recent findings to draft a disclosure for.\nRun /scan or /hunt first.")
        return

    repo_full = last.get("repo_full_name", "unknown/repo")
    repo_url  = last.get("repo_url", f"https://github.com/{repo_full}")
    th_list   = last.get("trufflehog", [])
    gl_list   = last.get("gitleaks", [])

    ctx = None
    # Prefer a verified-live TruffleHog finding
    for f in th_list:
        if f.get("Verified"):
            ctx = disclosure.from_trufflehog_finding(
                f, repo_full, repo_url,
                verified_live=True,
                additional_findings=len(th_list) + len(gl_list) - 1,
                researcher_name=RESEARCHER_NAME,
                researcher_contact=RESEARCHER_CONTACT,
            )
            break
    # Fall back to first TH finding
    if not ctx and th_list:
        ctx = disclosure.from_trufflehog_finding(
            th_list[0], repo_full, repo_url,
            additional_findings=len(th_list) + len(gl_list) - 1,
            researcher_name=RESEARCHER_NAME,
            researcher_contact=RESEARCHER_CONTACT,
        )
    # Fall back to first gitleaks finding
    if not ctx and gl_list:
        ctx = disclosure.from_gitleaks_finding(
            gl_list[0], repo_full, repo_url,
            additional_findings=len(gl_list) - 1,
            researcher_name=RESEARCHER_NAME,
            researcher_contact=RESEARCHER_CONTACT,
        )

    if not ctx:
        tg_send("ℹ️ Could not build disclosure context from cached findings.")
        return

    draft = disclosure.generate_draft(ctx)
    draft_path = REPORTS_DIR / f"disclosure_{repo_full.replace('/', '_')}.txt"
    draft_path.write_text(draft)

    tg_send(f"📝 *Disclosure draft generated for* `{repo_full}`")
    tg_send_file(draft_path, caption=f"Responsible Disclosure — {repo_full}")

# ── Scan modes ────────────────────────────────────────────────────────────────
def run_private_mode():
    ui.print_banner(mode="private")
    ui.info("Watching your repos for new commits…")
    tg_send("🔒 *GitShield started — Private Mode*")
    while True:
        try:
            repos = get_my_repos()
            state = load_state()
            for repo in repos:
                full_name  = repo["full_name"]
                clone_url  = repo["clone_url"]
                repo_dir   = REPOS_DIR / repo["name"]
                latest_sha = get_latest_commit(full_name, use_auth=True)
                if not latest_sha:
                    continue
                if latest_sha == state["repos"].get(full_name):
                    continue
                log.info(f"New commit in {full_name}: {latest_sha[:7]}")
                clone_or_pull(clone_url, repo_dir, use_auth=True)
                report_data, json_path, html_path = scan_repo(
                    repo_dir, repo["name"], full_name, latest_sha,
                    source="private", do_deep=DEEP_SCAN_DEFAULT,
                )
                alert_findings(report_data, json_path, html_path)
                state["repos"][full_name] = latest_sha
                save_state(state)
        except Exception as e:
            log.error(f"Private mode error: {e}")
        time.sleep(PRIVATE_POLL)

def run_public_mode():
    ui.print_banner(mode="public")
    ui.info("Monitoring GitHub public events firehose…")
    tg_send("🌐 *GitShield started — Public Mode*")
    etag = None
    state = load_state()
    scanned = set(state.get("scanned_public", []))
    while True:
        try:
            events, etag = get_public_events(etag)
            push_events  = [e for e in events if e.get("type") == "PushEvent"]
            for event in push_events:
                full_name = event.get("repo", {}).get("name", "")
                if not full_name or full_name in scanned:
                    continue
                repo_name = full_name.split("/")[-1]
                repo_dir  = REPOS_DIR / f"pub_{hashlib.md5(full_name.encode()).hexdigest()[:8]}_{repo_name}"
                try:
                    clone_or_pull(f"https://github.com/{full_name}.git", repo_dir, use_auth=False)
                    report_data, json_path, html_path = scan_repo(
                        repo_dir, repo_name, full_name, source="public", do_deep=False
                    )
                    alert_findings(report_data, json_path, html_path)
                    scanned.add(full_name)
                    state["scanned_public"] = list(scanned)[-500:]
                    save_state(state)
                except Exception as e:
                    log.error(f"Public scan error {full_name}: {e}")
        except Exception as e:
            log.error(f"Public mode error: {e}")
        time.sleep(PUBLIC_POLL)

# ── Telegram bot ──────────────────────────────────────────────────────────────
def run_telegram_listener():
    if not TELEGRAM_TOKEN:
        return
    log.info("💬 Telegram bot started")
    offset = None
    while True:
        try:
            updates = tg_get_updates(offset)
            for update in updates:
                offset = update["update_id"] + 1
                msg     = update.get("message", {})
                text    = msg.get("text", "").strip()
                chat_id = str(msg.get("chat", {}).get("id", ""))
                if chat_id != TELEGRAM_CHAT_ID:
                    continue
                _handle_command(text)
        except Exception as e:
            log.error(f"Telegram listener error: {e}")
        time.sleep(TELEGRAM_POLL)

def _handle_command(text: str):
    cmd = text.split()[0].lower() if text else ""

    if cmd == "/scan" and len(text) > 6:
        url = text[6:].strip()
        threading.Thread(
            target=run_target_scan, args=(url,), kwargs={"do_deep": False}, daemon=True
        ).start()

    elif cmd == "/deep" and len(text) > 6:
        url = text[6:].strip()
        threading.Thread(
            target=run_target_scan, args=(url,), kwargs={"do_deep": True}, daemon=True
        ).start()

    elif cmd == "/hunt":
        # Optional: /hunt 50000 (custom min bounty)
        parts = text.split()
        min_b = None
        if len(parts) > 1:
            try:
                min_b = int(parts[1].replace("$", "").replace(",", ""))
            except ValueError:
                pass
        threading.Thread(target=run_hunt, kwargs={"min_bounty": min_b}, daemon=True).start()

    elif cmd == "/targets":
        state = load_state()
        cached = state.get("immunefi_targets", [])
        if cached:
            programs = [
                immunefi.BountyProgram(
                    name=t["name"], slug=t["slug"],
                    max_bounty_usd=t["max_bounty_usd"],
                    github_orgs=t.get("github_orgs", []),
                )
                for t in cached
            ]
            tg_send(immunefi.format_targets_message(programs))
        else:
            tg_send("No targets cached yet. Use /hunt to fetch.")

    elif cmd == "/report":
        threading.Thread(target=cmd_report, daemon=True).start()

    elif cmd == "/bounty":
        parsed = earnings.parse_bounty_command(text)
        if parsed:
            amount, platform, project, notes = parsed
            entry = earnings.log_bounty(amount, platform, project, notes)
            tg_send(earnings.format_bounty_logged_message(entry))
        else:
            tg_send(
                "❌ Usage: `/bounty <amount> <platform> <project> [notes]`\n"
                "Example: `/bounty 2500 Immunefi ProjectName critical eth key`"
            )

    elif cmd == "/earnings":
        tg_send(earnings.format_earnings_message())

    elif cmd == "/status":
        state = load_state()
        stats = state.get("stats", {})
        tg_send(
            f"📊 *GitShield Status*\n\n"
            f"*Total scans:*  `{stats.get('total_scans', 0)}`\n"
            f"*Leaks found:* `{stats.get('leaks_found', 0)}`\n"
            f"*Repos watched:* `{len(state.get('repos', {}))}`\n"
            f"*Public scanned:* `{len(state.get('scanned_public', []))}`\n"
            f"*Immunefi targets cached:* `{len(state.get('immunefi_targets', []))}`"
        )

    elif cmd == "/repos":
        state = load_state()
        repos = list(state.get("repos", {}).keys())
        if repos:
            repo_list = "\n".join([f"  ▸ `{r}`" for r in repos[:20]])
            tg_send(f"👀 *Watched Repos ({len(repos)}):*\n{repo_list}")
        else:
            tg_send("No repos being watched yet.")

    elif cmd == "/help":
        tg_send(
            "🛡 *GitShield Commands*\n\n"
            "`/scan <url>`   — Scan a repo (standard)\n"
            "`/deep <url>`   — Scan + deep extraction (blobs, packs)\n"
            "`/hunt [min$]`  — Fetch Immunefi targets + deep scan all\n"
            "`/targets`      — Show cached Immunefi target list\n"
            "`/report`       — Draft disclosure for last finding\n"
            "`/bounty <$> <platform> <project>` — Log a paid bounty\n"
            "`/earnings`     — Earnings dashboard\n"
            "`/status`       — Scanner stats\n"
            "`/repos`        — List watched repos\n"
            "`/help`         — This message"
        )

# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="GitShield — All-in-One GitHub Secret Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--mode", choices=["private", "public", "target", "hunt"],
                        default="private")
    parser.add_argument("--target", type=str, help="Repo URL for target mode")
    parser.add_argument("--deep", action="store_true", help="Enable deep extraction")
    parser.add_argument("--no-deep", action="store_true", help="Disable deep extraction")
    parser.add_argument("--min-bounty", type=int, default=IMMUNEFI_MIN_BOUNTY,
                        help="Minimum Immunefi bounty USD for /hunt (default: 10000)")
    args = parser.parse_args()

    # Banner is printed per-mode so deep/hunt modes show correctly
    if args.mode in ("target",):
        ui.print_banner(mode=args.mode)

    missing = check_tools()
    if "gitleaks" in missing and "trufflehog" in missing:
        log.error("Both gitleaks and trufflehog are missing. Install at least one.")
        sys.exit(1)

    # Resolve deep flag
    global DEEP_SCAN_DEFAULT
    if args.deep:
        DEEP_SCAN_DEFAULT = True
    elif args.no_deep:
        DEEP_SCAN_DEFAULT = False

    # Always run Telegram listener in background
    if TELEGRAM_TOKEN:
        threading.Thread(target=run_telegram_listener, daemon=True).start()
        ui.print_bot_ready(TELEGRAM_TOKEN[:10], TELEGRAM_CHAT_ID)

    if args.mode == "private":
        if not GITHUB_TOKEN:
            log.error("GITHUB_TOKEN required for private mode")
            sys.exit(1)
        run_private_mode()

    elif args.mode == "public":
        run_public_mode()

    elif args.mode == "target":
        if not args.target:
            log.error("--target <repo_url> required for target mode")
            sys.exit(1)
        run_target_scan(args.target, do_deep=DEEP_SCAN_DEFAULT)

    elif args.mode == "hunt":
        run_hunt(min_bounty=args.min_bounty)

if __name__ == "__main__":
    main()
