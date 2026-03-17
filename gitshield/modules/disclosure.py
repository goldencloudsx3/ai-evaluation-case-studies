"""
GitShield — Responsible Disclosure Draft Generator

For each critical finding, generates a ready-to-send disclosure email:
  - Professional subject line
  - Complete timeline
  - Affected file, commit SHA, key type
  - Impact assessment by key type
  - Step-by-step remediation advice
  - Researcher contact info (from .env)

Output: plain text (copy-paste into email) + HTML version
"""

import os
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import List, Optional


# ── Key type descriptions ─────────────────────────────────────────────────────

_KEY_DESCRIPTIONS = {
    "aws_access_key":         ("AWS Access Key",         "full access to AWS resources depending on attached IAM policy"),
    "aws_secret_key":         ("AWS Secret Key",         "combined with the Access Key ID, grants full AWS API access"),
    "github_token":           ("GitHub Personal Access Token", "code read/write, repo deletion, secrets access"),
    "github_oauth":           ("GitHub OAuth Token",     "account-level GitHub access"),
    "slack_token":            ("Slack API Token",        "message history, file access, potential workspace data exfiltration"),
    "private_key_rsa":        ("RSA Private Key",        "server authentication bypass, data decryption, signing"),
    "private_key_ec":         ("EC Private Key",         "cryptographic signing and decryption"),
    "eth_private_key":        ("Ethereum/EVM Private Key", "full control of the associated wallet — funds can be drained immediately"),
    "wif_key":                ("Bitcoin WIF Private Key","full control of the associated Bitcoin wallet"),
    "mnemonic":               ("BIP-39 Mnemonic Seed Phrase", "derives ALL wallets for the associated HD wallet — total fund loss risk"),
    "solana_private_key":     ("Solana Private Key",     "full control of the associated Solana wallet"),
    "xpriv":                  ("BIP-32 Extended Private Key (xpriv)", "derives all child private keys in the HD wallet tree"),
    "keystore_json":          ("Encrypted Ethereum Keystore", "wallet private key protected only by the keystore password"),
    "stripe_key":             ("Stripe API Key",         "payment processing — charge cards, read customer data"),
    "sendgrid_key":           ("SendGrid API Key",       "send email as the account, access contact lists"),
    "twilio_key":             ("Twilio API Key",         "send SMS/calls, read communication logs"),
    "google_api_key":         ("Google API Key",         "access Google Cloud services at account expense"),
    "infura_key":             ("Infura API Key",         "blockchain RPC access, potential rate-limit abuse"),
    "alchemy_key":            ("Alchemy API Key",        "blockchain RPC access"),
    "generic":                ("Exposed Secret",         "sensitive credential — impact depends on the service it belongs to"),
}

def _describe_key(key_type: str) -> tuple:
    """Return (human_name, impact_sentence) for a key type."""
    k = key_type.lower().replace("-", "_")
    for pattern, desc in _KEY_DESCRIPTIONS.items():
        if pattern in k:
            return desc
    return _KEY_DESCRIPTIONS["generic"]


# ── Dataclass for a single finding ───────────────────────────────────────────

@dataclass
class DisclosureContext:
    repo_full_name: str         # e.g. "org/repo"
    repo_url: str               # e.g. "https://github.com/org/repo"
    key_type: str               # raw type string from detector
    file_path: str
    commit_sha: str
    line_number: Optional[int] = None
    detector: str = "GitShield" # "Gitleaks" / "TruffleHog"
    verified_live: bool = False
    additional_findings: int = 0  # other findings in same repo
    program_name: str = ""      # Immunefi program name if known
    researcher_name: str = ""
    researcher_contact: str = ""


# ── Draft generator ───────────────────────────────────────────────────────────

def generate_draft(ctx: DisclosureContext) -> str:
    """Return a complete plain-text responsible disclosure email."""
    researcher_name = ctx.researcher_name or os.getenv("RESEARCHER_NAME", "Security Researcher")
    researcher_contact = ctx.researcher_contact or os.getenv("RESEARCHER_CONTACT", "[your contact]")

    key_name, impact = _describe_key(ctx.key_type)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    sha_short = ctx.commit_sha[:12] if ctx.commit_sha else "N/A"
    verified_note = "TruffleHog has *verified this credential is live*.\n" if ctx.verified_live else ""
    additional_note = (
        f"\nNote: {ctx.additional_findings} additional finding(s) were identified "
        f"in the same repository during this scan.\n"
        if ctx.additional_findings > 0 else ""
    )
    severity = "CRITICAL" if ctx.verified_live else "HIGH"
    program_note = f"\nThis report is submitted in connection with the {ctx.program_name} bug bounty program on Immunefi." if ctx.program_name else ""

    # ── Immunefi scope warning ────────────────────────────────────────────────
    scope_warning = ""
    if not ctx.verified_live:
        scope_warning = (
            "\n"
            "⚠  IMMUNEFI SCOPE WARNING\n"
            "─────────────────────────────────────────────────────────────────\n"
            "Immunefi v2.3 classifies leaked keys in git history as OUT OF SCOPE\n"
            "by default UNLESS you can prove the key is actively used in production.\n"
            "TruffleHog did NOT verify this key as live.\n"
            "\n"
            "Before submitting to Immunefi you MUST:\n"
            "  1. Manually verify the key is live (check wallet balance, test API call)\n"
            "  2. Confirm the program's scope page lists leaked keys as in-scope\n"
            "  3. Select impact: Web/App → 'Retrieve sensitive server data (blockchain keys)'\n"
            "\n"
            "If you cannot prove production use, this report will be REJECTED.\n"
            "─────────────────────────────────────────────────────────────────\n"
        )

    subject = f"Responsible Disclosure — Exposed {key_name} in {ctx.repo_full_name}"

    body = f"""Subject: {subject}
{scope_warning}

Dear {_guess_team_name(ctx.repo_full_name)} Security Team,

I am a security researcher conducting authorized research on public code repositories.
I have identified a critical security vulnerability in your GitHub repository that
requires immediate attention.{program_note}

──────────────────────────────────────────────────
SUMMARY
──────────────────────────────────────────────────
Severity:       {severity}
Finding Type:   {key_name}
Repository:     {ctx.repo_url}
File:           {ctx.file_path}
Line:           {ctx.line_number if ctx.line_number else "N/A"}
Commit SHA:     {ctx.commit_sha}
Detected by:    {ctx.detector}
{verified_note}
──────────────────────────────────────────────────
IMPACT
──────────────────────────────────────────────────
An exposed {key_name} allows an attacker to gain {impact}.

This secret was found in git commit history ({sha_short}), meaning it may have
been publicly accessible since that commit was pushed, even if the file was
subsequently modified or deleted.{additional_note}

──────────────────────────────────────────────────
REPRODUCTION
──────────────────────────────────────────────────
The finding can be reproduced by examining the affected commit:

  git clone {ctx.repo_url}
  git show {ctx.commit_sha}:{ctx.file_path}

──────────────────────────────────────────────────
RECOMMENDED REMEDIATION
──────────────────────────────────────────────────
1. IMMEDIATE — Revoke / rotate the exposed credential right now.
   Do not wait — assume it may already have been accessed.

2. Purge from git history using BFG Repo Cleaner (recommended):
     java -jar bfg.jar --delete-files <filename> <repo>
     git reflog expire --expire=now --all
     git gc --prune=now --aggressive
     git push --force

   Or with git filter-repo:
     git filter-repo --path {ctx.file_path} --invert-paths

3. Audit access logs for the exposed credential to check for unauthorized use.

4. Add pre-commit protection to prevent future leaks:
     brew install gitleaks
     gitleaks protect --staged  # add to .pre-commit-config.yaml

5. Add the secret pattern to your .gitignore and consider using a secrets manager
   (AWS Secrets Manager, HashiCorp Vault, or GitHub Encrypted Secrets).

──────────────────────────────────────────────────
TIMELINE
──────────────────────────────────────────────────
{today}  —  Finding discovered during authorized security research
{today}  —  Responsible disclosure sent to security contact

──────────────────────────────────────────────────
DISCLOSURE POLICY
──────────────────────────────────────────────────
I am following responsible disclosure principles. I have not exploited this
vulnerability beyond confirming its existence. I request a response within
72 hours to confirm receipt and your remediation timeline.

I am happy to provide additional technical details or verify remediation.

Regards,
{researcher_name}
{researcher_contact}
"""
    return body


def generate_subject(ctx: DisclosureContext) -> str:
    key_name, _ = _describe_key(ctx.key_type)
    return f"Responsible Disclosure — Exposed {key_name} in {ctx.repo_full_name}"


def from_gitleaks_finding(finding: dict, repo_full_name: str, repo_url: str, **kwargs) -> DisclosureContext:
    """Build a DisclosureContext from a gitleaks JSON finding dict."""
    return DisclosureContext(
        repo_full_name=repo_full_name,
        repo_url=repo_url,
        key_type=finding.get("RuleID", "generic"),
        file_path=finding.get("File", "unknown"),
        commit_sha=finding.get("Commit", ""),
        line_number=finding.get("StartLine"),
        detector="Gitleaks",
        **kwargs,
    )


def from_trufflehog_finding(finding: dict, repo_full_name: str, repo_url: str, **kwargs) -> DisclosureContext:
    """Build a DisclosureContext from a trufflehog JSON finding dict."""
    src = finding.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
    commit = finding.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("commit", "")
    return DisclosureContext(
        repo_full_name=repo_full_name,
        repo_url=repo_url,
        key_type=finding.get("DetectorName", "generic"),
        file_path=src.get("file", "unknown"),
        commit_sha=commit,
        line_number=src.get("line"),
        detector="TruffleHog",
        verified_live=finding.get("Verified", False),
        **kwargs,
    )


def _guess_team_name(repo_full_name: str) -> str:
    """Extract a likely org/project name from the repo path."""
    parts = repo_full_name.split("/")
    return parts[0].replace("-", " ").replace("_", " ").title() if parts else "Security"
