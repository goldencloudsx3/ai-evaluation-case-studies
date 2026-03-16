"""
Token & Password Hash Analyzer

Detects two classes of vulnerability:

1. PREDICTABLE TOKEN PATTERNS
   - Low Shannon entropy (likely guessable)
   - Sequential token/session ID values
   - Timestamp-seeded tokens (Unix time as token value)
   - Short token length (insufficient keyspace)

2. WEAK PASSWORD HASHING
   - MD5 / SHA-1 function calls in served JavaScript
   - Presence of raw MD5 (32 hex) or SHA-1 (40 hex) hashes in API responses
   - Detection of bcrypt/argon2/scrypt is noted as good practice

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

import re
import math
import time
from dataclasses import dataclass, field
from typing import List, Optional

import requests


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class TokenFinding:
    severity: str
    title: str
    description: str
    evidence: str
    recommendation: str
    category: str = ""   # entropy / sequential / timestamp / hashing / length


@dataclass
class TokenResult:
    findings: List[TokenFinding] = field(default_factory=list)
    tokens_sampled: int = 0
    errors: List[str] = field(default_factory=list)


# ── Regex patterns for weak hashing ──────────────────────────────────────────

# Weak hash function calls in JavaScript / server-side source
WEAK_HASH_SOURCE_PATTERNS = [
    (re.compile(r'\bmd5\s*\(', re.IGNORECASE),
     "MD5 function call"),
    (re.compile(r'\bsha1\s*\(', re.IGNORECASE),
     "SHA-1 function call"),
    (re.compile(r'hashlib\s*\.\s*md5\b', re.IGNORECASE),
     "Python hashlib.md5"),
    (re.compile(r'hashlib\s*\.\s*sha1\b', re.IGNORECASE),
     "Python hashlib.sha1"),
    (re.compile(r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']', re.IGNORECASE),
     "Java MD5 MessageDigest"),
    (re.compile(r'MessageDigest\.getInstance\s*\(\s*["\']SHA-1["\']', re.IGNORECASE),
     "Java SHA-1 MessageDigest"),
    (re.compile(r'CryptoJS\s*\.\s*MD5\b'),
     "CryptoJS MD5"),
    (re.compile(r'CryptoJS\s*\.\s*SHA1\b'),
     "CryptoJS SHA1"),
    (re.compile(r'new\s+MD5\s*\(', re.IGNORECASE),
     "MD5 constructor instantiation"),
    (re.compile(r'\.createHash\s*\(\s*["\']md5["\']', re.IGNORECASE),
     "Node.js crypto.createHash('md5')"),
    (re.compile(r'\.createHash\s*\(\s*["\']sha1["\']', re.IGNORECASE),
     "Node.js crypto.createHash('sha1')"),
]

# Patterns that suggest raw hash values appear in API responses
# (not cryptographic keys — these are password-storage red flags)
MD5_HASH_RE  = re.compile(r'\b[0-9a-f]{32}\b', re.IGNORECASE)
SHA1_HASH_RE = re.compile(r'\b[0-9a-f]{40}\b', re.IGNORECASE)

# Good hash indicators — used to annotate when strong hashing IS present
STRONG_HASH_RE = re.compile(
    r'(\$2[ayb]\$\d+\$|\$argon2|\$scrypt\$|\$pbkdf2)'
)

# Endpoints likely to return session tokens or respond to auth operations
TOKEN_PROBE_PATHS = [
    "/",
    "/api/auth/login",
    "/api/login",
    "/api/token",
    "/api/refresh",
    "/api/session",
    "/api/me",
    "/api/user/profile",
    "/api/nonce",
    "/api/csrf-token",
    "/api/auth/csrf",
]

# Minimum token entropy bits/char to be considered safe
ENTROPY_THRESHOLD = 3.5    # bits per character
MIN_TOKEN_LENGTH  = 16     # characters


# ── Helpers ────────────────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((n / total) * math.log2(n / total) for n in freq.values())


def _is_sequential(values: List[str]) -> bool:
    """
    Return True if the list of strings looks numerically sequential
    (constant difference between consecutive integer values).
    """
    if len(values) < 3:
        return False
    nums = []
    for v in values:
        try:
            nums.append(int(v))
        except (ValueError, TypeError):
            return False
    diffs = {nums[i + 1] - nums[i] for i in range(len(nums) - 1)}
    return len(diffs) == 1   # all gaps identical


def _looks_like_timestamp(token: str) -> Optional[int]:
    """
    Return the token value as an int if it is within ±1 hour of now
    (suggesting it was seeded with the current Unix timestamp).
    """
    try:
        val = int(token)
    except (ValueError, TypeError):
        return None
    now = int(time.time())
    return val if abs(val - now) < 3600 else None


def _extract_json_tokens(data: dict) -> List[str]:
    """Recursively collect string values from common token-like keys."""
    token_keys = {
        "token", "access_token", "accesstoken", "refresh_token",
        "session_id", "sessionid", "sid", "nonce", "csrf_token",
        "csrftoken", "xsrf_token",
    }
    found = []

    def _walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in token_keys and isinstance(v, str):
                    found.append(v)
                else:
                    _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(data)
    return found


# ── Main analyzer ──────────────────────────────────────────────────────────────

class TokenAnalyzer:
    """
    Probes auth-related endpoints, collects tokens/session IDs, and evaluates
    them for predictability.  Also scans served JavaScript for weak password
    hashing function calls.
    """

    def __init__(self, session: requests.Session, delay: float = 0.3):
        self.session = session
        self.delay   = delay

    def analyze(self, target: str, crawl_result=None) -> TokenResult:
        result = TokenResult()

        # ── Build probe URL list ───────────────────────────────────────────────
        probe_urls = [target.rstrip("/") + p for p in TOKEN_PROBE_PATHS]
        if crawl_result:
            for ep in crawl_result.endpoints:
                if any(kw in ep.url.lower()
                       for kw in ("token", "session", "auth", "login", "nonce", "csrf")):
                    probe_urls.append(ep.url)

        collected_tokens: List[str] = []
        seen_urls: set = set()

        for url in probe_urls[:30]:
            if url in seen_urls:
                continue
            seen_urls.add(url)

            try:
                resp = self.session.get(url, timeout=(5, 8))
                result.tokens_sampled += 1

                # ── Weak hashing in JavaScript source ─────────────────────────
                ct = resp.headers.get("content-type", "")
                if "javascript" in ct or "html" in ct or url.endswith(".js"):
                    self._scan_source_hashing(url, resp.text, result)

                # ── Collect session cookies ────────────────────────────────────
                for cookie in resp.cookies:
                    if any(kw in cookie.name.lower()
                           for kw in ("session", "token", "sid", "sess", "auth")):
                        collected_tokens.append(cookie.value)

                # ── Collect tokens from JSON body ──────────────────────────────
                if "application/json" in ct:
                    try:
                        collected_tokens.extend(_extract_json_tokens(resp.json()))
                    except Exception:
                        pass

                # ── Detect MD5/SHA-1 hashes in API responses ───────────────────
                if "application/json" in ct:
                    self._scan_response_hashes(url, resp.text, result)

                time.sleep(self.delay * 0.5)

            except requests.exceptions.RequestException as exc:
                result.errors.append(f"{url}: {exc}")

        # ── Evaluate collected tokens ──────────────────────────────────────────
        for token in collected_tokens:
            self._evaluate_token(token, result)

        # ── Sequential pattern check (across multiple samples) ────────────────
        if _is_sequential(collected_tokens):
            result.findings.append(TokenFinding(
                severity="CRITICAL",
                title="Sequential Token / Session ID Pattern",
                description=(
                    "Collected tokens increase by a constant value — they are "
                    "essentially a counter. An attacker can trivially enumerate "
                    "all valid session IDs and impersonate any user."
                ),
                evidence=f"Sampled values: {collected_tokens[:5]}",
                recommendation=(
                    "Generate session identifiers using a CSPRNG "
                    "(e.g. Python: secrets.token_hex(32), "
                    "Node.js: crypto.randomBytes(32).toString('hex'))."
                ),
                category="sequential",
            ))

        return result

    # ── Token evaluation helpers ───────────────────────────────────────────────

    def _evaluate_token(self, token: str, result: TokenResult):
        """Run all predictability checks against a single token value."""

        # Length check
        if len(token) < MIN_TOKEN_LENGTH:
            result.findings.append(TokenFinding(
                severity="HIGH",
                title=f"Short Token (length {len(token)})",
                description=(
                    f"Token is only {len(token)} characters long. "
                    f"The minimum recommended length is {MIN_TOKEN_LENGTH} characters "
                    "to provide sufficient keyspace against brute-force guessing."
                ),
                evidence=f"Token: {token[:30]}{'...' if len(token) > 30 else ''}",
                recommendation=(
                    "Generate tokens with at least 128 bits of randomness "
                    "(e.g. 32 hex characters from secrets.token_hex(16))."
                ),
                category="length",
            ))
            return   # skip further checks on obviously bad token

        # Entropy check
        entropy = _shannon_entropy(token)
        if entropy < ENTROPY_THRESHOLD:
            result.findings.append(TokenFinding(
                severity="HIGH",
                title="Low Entropy Token — Likely Predictable",
                description=(
                    f"Shannon entropy of {entropy:.2f} bits/char is below the "
                    f"{ENTROPY_THRESHOLD} bits/char threshold. Low entropy indicates "
                    "the token may be generated from a limited character set or "
                    "a weak RNG, making it brute-forceable."
                ),
                evidence=f"Token: {token[:30]}...  entropy={entropy:.2f} bits/char",
                recommendation=(
                    "Use os.urandom() or secrets.token_urlsafe() to generate tokens. "
                    "Aim for at least 128 bits of effective entropy."
                ),
                category="entropy",
            ))

        # Timestamp seed check
        ts_val = _looks_like_timestamp(token)
        if ts_val is not None:
            result.findings.append(TokenFinding(
                severity="HIGH",
                title="Timestamp-Seeded Token Detected",
                description=(
                    f"Token value ({token}) closely matches the current Unix "
                    "timestamp. An attacker who knows approximately when an "
                    "account was created can enumerate the full range of "
                    "possible tokens within seconds."
                ),
                evidence=f"Token: {token}  |  Now: {int(time.time())}",
                recommendation=(
                    "Never use time.time() or Date.now() as a token seed or value. "
                    "Use a CSPRNG (secrets.token_hex in Python, "
                    "crypto.randomUUID in Node.js)."
                ),
                category="timestamp",
            ))

    # ── Source & response scanning ─────────────────────────────────────────────

    def _scan_source_hashing(self, url: str, source: str, result: TokenResult):
        """
        Scan JavaScript / HTML source for weak hash function calls.
        Reports at most one finding per URL to avoid flooding.
        """
        for pattern, description in WEAK_HASH_SOURCE_PATTERNS:
            if pattern.search(source):
                result.findings.append(TokenFinding(
                    severity="HIGH",
                    title=f"Weak Hash Function in Source: {description}",
                    description=(
                        f"{description} detected in source at {url}. "
                        "MD5 and SHA-1 are cryptographically broken — collisions "
                        "can be computed in seconds on commodity hardware. "
                        "Using them for password storage allows offline dictionary "
                        "attacks after a database breach."
                    ),
                    evidence=f"Pattern '{description}' matched in {url}",
                    recommendation=(
                        "For password hashing, use bcrypt, scrypt, or argon2. "
                        "For data integrity, use SHA-256 or SHA-3. "
                        "Never use MD5 or SHA-1 for security-sensitive operations."
                    ),
                    category="hashing",
                ))
                return  # one finding per URL is enough

    def _scan_response_hashes(self, url: str, body: str, result: TokenResult):
        """
        Detect bare MD5 (32 hex) or SHA-1 (40 hex) hash strings in API responses.
        These may indicate plaintext password hashes stored in the database and
        returned via the API.
        """
        # Avoid flagging known-good strong hash formats
        if STRONG_HASH_RE.search(body):
            return

        # Count candidate hashes (exclude things that look like crypto keys
        # which are already covered by key_detector)
        md5_hits  = MD5_HASH_RE.findall(body)
        sha1_hits = SHA1_HASH_RE.findall(body)

        # Filter: ignore strings also matched as part of 64-char hex (private keys)
        md5_hits  = [h for h in md5_hits  if len(h) == 32]
        sha1_hits = [h for h in sha1_hits if len(h) == 40]

        if md5_hits:
            result.findings.append(TokenFinding(
                severity="MEDIUM",
                title="Possible MD5 Hash Values in API Response",
                description=(
                    f"{len(md5_hits)} 32-character hex string(s) detected in the API "
                    "response from {url}. These may be MD5 password hashes being "
                    "returned to the client — or stored/compared server-side."
                ),
                evidence=f"Examples: {md5_hits[0]}, {md5_hits[1] if len(md5_hits) > 1 else ''}",
                recommendation=(
                    "If these are password hashes, migrate to argon2id or bcrypt "
                    "immediately. Never return password hashes in API responses."
                ),
                category="hashing",
            ))

        if sha1_hits:
            result.findings.append(TokenFinding(
                severity="MEDIUM",
                title="Possible SHA-1 Hash Values in API Response",
                description=(
                    f"{len(sha1_hits)} 40-character hex string(s) found in the API "
                    "response from {url}. SHA-1 is broken (SHAttered collision attack). "
                    "Using it for password storage or HMAC-based tokens is insecure."
                ),
                evidence=f"Examples: {sha1_hits[0]}",
                recommendation=(
                    "Replace SHA-1 with SHA-256 (minimum) for integrity checks, "
                    "or argon2id for password hashing."
                ),
                category="hashing",
            ))
