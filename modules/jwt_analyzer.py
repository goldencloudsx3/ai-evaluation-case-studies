"""
JWT Vulnerability Analyzer

Tests for common JWT security misconfigurations:
  - alg:none bypass
  - Algorithm confusion (RS256 → HS256)
  - Weak HMAC secrets (brute-force from common wordlist)
  - Sensitive data exposed in unencrypted payload
  - Tokens observed in responses/cookies

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

import re
import json
import base64
import hmac
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

import requests


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class JWTFinding:
    severity: str
    title: str
    description: str
    evidence: str
    recommendation: str
    token_snippet: str = ""
    endpoint: str = ""


@dataclass
class JWTResult:
    findings: List[JWTFinding] = field(default_factory=list)
    tokens_found: int = 0
    endpoints_tested: int = 0
    errors: List[str] = field(default_factory=list)


# ── Constants ──────────────────────────────────────────────────────────────────

# Common weak secrets used in dev/misconfigured deployments
WEAK_SECRETS = [
    "secret", "password", "123456", "test", "key", "admin",
    "jwt_secret", "your-secret", "your-256-bit-secret", "your-secret-key",
    "changeme", "1234567890", "secretkey", "mysecret", "jwtkey",
    "token", "access_token", "secret123", "jwt_key", "hmac_secret",
    "supersecret", "verysecret", "topsecret", "private", "privatekey",
    "apikey", "api_key", "appkey", "app_secret", "dev_secret",
    "", "null", "undefined",
]

# Payload fields that should never appear unencrypted in a JWT
SENSITIVE_PAYLOAD_FIELDS = {
    "password", "passwd", "secret", "private_key", "privatekey",
    "mnemonic", "seed", "seed_phrase", "ssn", "credit_card",
    "card_number", "cvv", "pin", "api_secret", "api_key",
}

# JWT regex: three base64url segments separated by dots
JWT_RE = re.compile(
    r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
)

# ── Helpers ────────────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    """Base64url decode with automatic padding."""
    s = s.replace('-', '+').replace('_', '/')
    pad = 4 - (len(s) % 4)
    if pad != 4:
        s += '=' * pad
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def _parse_jwt(token: str) -> Optional[Dict[str, Any]]:
    """Parse a JWT string into header, payload, and raw parts."""
    parts = token.split('.')
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return {"header": header, "payload": payload, "parts": parts}
    except Exception:
        return None


def _make_alg_none_token(original_token: str) -> Optional[str]:
    """Build an alg:none variant of the given token (empty signature)."""
    parsed = _parse_jwt(original_token)
    if not parsed:
        return None
    new_header = dict(parsed["header"])
    new_header["alg"] = "none"
    h_enc = _b64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
    p_enc = parsed["parts"][1]
    return f"{h_enc}.{p_enc}."     # trailing dot = empty signature


def _crack_hmac_secret(token: str) -> Optional[str]:
    """Try to verify an HMAC-signed JWT against a list of weak secrets."""
    parsed = _parse_jwt(token)
    if not parsed:
        return None
    alg = parsed["header"].get("alg", "").upper()
    if alg not in ("HS256", "HS384", "HS512"):
        return None

    header_payload = f"{parsed['parts'][0]}.{parsed['parts'][1]}"
    try:
        sig = _b64url_decode(parsed["parts"][2])
    except Exception:
        return None

    hash_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    hash_fn = hash_map[alg]

    for secret in WEAK_SECRETS:
        try:
            expected = hmac.new(
                secret.encode(), header_payload.encode(), hash_fn
            ).digest()
            if hmac.compare_digest(expected, sig):
                return secret
        except Exception:
            continue
    return None


# ── Main analyzer ──────────────────────────────────────────────────────────────

class JWTAnalyzer:
    """
    Scans HTTP responses and auth endpoints for JWT tokens, then tests
    each discovered token for common vulnerabilities.
    """

    def __init__(self, session: requests.Session, delay: float = 0.3):
        self.session = session
        self.delay = delay

    def analyze(self, target: str, crawl_result=None) -> JWTResult:
        result = JWTResult()
        tokens_seen: Dict[str, str] = {}   # token → source URL

        # ── Collect JWT tokens from responses ─────────────────────────────────
        probe_urls = [
            target,
            f"{target}/api/auth/login",
            f"{target}/api/login",
            f"{target}/api/token",
            f"{target}/api/refresh",
            f"{target}/auth",
            f"{target}/api/me",
            f"{target}/api/user/profile",
        ]
        if crawl_result:
            for ep in crawl_result.endpoints:
                probe_urls.append(ep.url)

        seen_urls: set = set()
        for url in probe_urls[:60]:
            if url in seen_urls:
                continue
            seen_urls.add(url)
            try:
                resp = self.session.get(url, timeout=(5, 8))
                result.endpoints_tested += 1

                # Body
                for token in JWT_RE.findall(resp.text):
                    if token not in tokens_seen:
                        tokens_seen[token] = url

                # Cookies
                for cookie in resp.cookies:
                    for token in JWT_RE.findall(cookie.value):
                        if token not in tokens_seen:
                            tokens_seen[token] = url

                # Auth/token response headers
                for hdr in ("Authorization", "X-Auth-Token", "X-Access-Token"):
                    val = resp.headers.get(hdr, "")
                    for token in JWT_RE.findall(val):
                        if token not in tokens_seen:
                            tokens_seen[token] = url

            except requests.exceptions.RequestException as exc:
                result.errors.append(f"{url}: {exc}")

        result.tokens_found = len(tokens_seen)

        # ── Analyse each token ─────────────────────────────────────────────────
        for token, source_url in tokens_seen.items():
            snippet = token[:40] + "..."
            parsed = _parse_jwt(token)
            if not parsed:
                continue

            alg = parsed["header"].get("alg", "?")

            # 1. Token already uses alg:none
            if alg.lower() == "none":
                result.findings.append(JWTFinding(
                    severity="CRITICAL",
                    title="JWT Algorithm: none (unsigned token accepted)",
                    description=(
                        "A JWT with alg=none was found in a server response. "
                        "This means the server is issuing tokens without any "
                        "cryptographic signature — any payload can be trusted."
                    ),
                    evidence=f"Token header: {json.dumps(parsed['header'])}",
                    recommendation=(
                        "Reject all tokens with alg=none. Whitelist only the "
                        "specific algorithm your server uses (e.g. RS256)."
                    ),
                    token_snippet=snippet,
                    endpoint=source_url,
                ))

            # 2. alg:none attack surface (server uses a real alg, but may not enforce it)
            elif _make_alg_none_token(token) is not None:
                result.findings.append(JWTFinding(
                    severity="MEDIUM",
                    title="JWT alg:none Attack Surface",
                    description=(
                        f"Token found with alg={alg}. Manually verify whether the server "
                        "rejects tokens where the header is changed to alg=none, or where "
                        "the signature segment is removed entirely."
                    ),
                    evidence=(
                        f"alg:{alg} token observed at {source_url}. "
                        f"Test by submitting: {_make_alg_none_token(token)[:60]}..."
                    ),
                    recommendation=(
                        "Hardcode the expected algorithm server-side — never trust "
                        "the 'alg' field from the token header itself."
                    ),
                    token_snippet=snippet,
                    endpoint=source_url,
                ))

            # 3. Weak HMAC secret
            if alg.upper() in ("HS256", "HS384", "HS512"):
                cracked = _crack_hmac_secret(token)
                if cracked:
                    result.findings.append(JWTFinding(
                        severity="CRITICAL",
                        title="JWT Weak HMAC Secret — Token Forgeable",
                        description=(
                            f"The HMAC signing secret was cracked from the wordlist: '{cracked}'. "
                            "An attacker can sign arbitrary tokens with this secret and impersonate "
                            "any user."
                        ),
                        evidence=f"Algorithm: {alg} | Secret: '{cracked}'",
                        recommendation=(
                            "Replace the secret with a cryptographically random value of at least "
                            "256 bits (e.g. openssl rand -hex 32). Rotate all issued tokens."
                        ),
                        token_snippet=snippet,
                        endpoint=source_url,
                    ))

            # 4. Algorithm confusion risk (asymmetric → symmetric)
            if alg.upper() in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"):
                result.findings.append(JWTFinding(
                    severity="HIGH",
                    title="JWT Algorithm Confusion Risk (asymmetric → HS256)",
                    description=(
                        f"Token uses asymmetric algorithm {alg}. If the server does not "
                        "explicitly reject HS256, an attacker can re-sign a forged token "
                        "using the server's *public* key as the HMAC secret."
                    ),
                    evidence=(
                        f"alg:{alg} observed. Manually test by changing header to "
                        "alg=HS256 and signing with the server public key."
                    ),
                    recommendation=(
                        "Never derive the verification algorithm from the token header. "
                        "Hardcode 'RS256' (or whichever algorithm you use) in the server "
                        "JWT library configuration."
                    ),
                    token_snippet=snippet,
                    endpoint=source_url,
                ))

            # 5. Sensitive data in unencrypted payload
            payload_keys_lower = {k.lower() for k in parsed["payload"].keys()}
            exposed = SENSITIVE_PAYLOAD_FIELDS & payload_keys_lower
            if exposed:
                result.findings.append(JWTFinding(
                    severity="HIGH",
                    title="Sensitive Data Exposed in JWT Payload",
                    description=(
                        "The JWT payload contains sensitive fields. JWT payloads are "
                        "base64-encoded, NOT encrypted — anyone with the token can read "
                        "the payload without the secret key."
                    ),
                    evidence=f"Sensitive fields found: {', '.join(sorted(exposed))}",
                    recommendation=(
                        "Remove sensitive data from JWT payloads. "
                        "Use JWE (JSON Web Encryption) if payload confidentiality is required."
                    ),
                    token_snippet=snippet,
                    endpoint=source_url,
                ))

        return result
