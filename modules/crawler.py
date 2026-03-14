"""
API Endpoint Crawler & Fuzzer for Crypto/Blockchain Sites

Discovers API endpoints on a target blockchain/crypto website by:
1. Spidering visible links and JS references
2. Fuzzing common crypto-related endpoint paths
3. Analyzing JavaScript bundles for hidden API routes
4. Detecting authentication parameter patterns

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

import re
import time
import random
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
from typing import Optional

import requests
from bs4 import BeautifulSoup


# Wordlist of crypto/blockchain specific API paths to probe
CRYPTO_API_WORDLIST = [
    # Wallet management
    "api/wallet", "api/wallets", "api/wallet/create", "api/wallet/list",
    "api/wallet/export", "api/wallet/import", "api/wallet/backup",
    # Key management
    "api/keys", "api/key", "api/keypair", "api/keypairs",
    "api/key/export", "api/key/generate", "api/key/import",
    "api/private-key", "api/private_key", "api/publickey",
    # Account/user endpoints
    "api/account", "api/accounts", "api/account/keys",
    "api/user", "api/users", "api/user/wallet", "api/user/keys",
    "api/profile", "api/profile/wallet",
    # Address management
    "api/address", "api/addresses", "api/address/generate",
    "api/address/derive",
    # Seed/mnemonic
    "api/mnemonic", "api/seed", "api/seed-phrase", "api/recovery",
    "api/recovery-phrase", "api/backup",
    # Keystore
    "api/keystore", "api/keystore/export", "api/keystore/download",
    "api/vault", "api/vault/keys",
    # Signing
    "api/sign", "api/sign/transaction", "api/signer",
    # Transaction endpoints (may reveal key material)
    "api/transaction", "api/tx", "api/transfer",
    # Node/validator
    "api/node", "api/validator", "api/validator/keys",
    # Auth endpoints (to understand session/token model)
    "api/auth", "api/auth/login", "api/auth/token",
    "api/login", "api/logout", "api/register",
    # Admin (often misconfigured)
    "api/admin", "api/admin/users", "api/admin/wallets",
    "admin/api", "admin/api/keys",
    # Version prefixes
    "api/v1/wallet", "api/v1/keys", "api/v1/user",
    "api/v2/wallet", "api/v2/keys", "api/v2/user",
    "api/v3/wallet", "api/v3/keys",
    # GraphQL
    "graphql", "api/graphql", "v1/graphql",
    # REST discovery
    "api", "api/docs", "api/swagger", "api/openapi.json",
    "swagger.json", "openapi.json", "api-docs",
    ".well-known/openid-configuration",
    # Common JS SPA patterns
    "static/js", "_next/static", "assets/js",
]

# Regex to find API routes embedded in JavaScript
JS_API_ROUTE_PATTERNS = [
    re.compile(r'["\'](/api/[a-zA-Z0-9/_\-{}:?&=.]+)["\']'),
    re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']'),
    re.compile(r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']'),
    re.compile(r'url\s*[=:]\s*["\']([/a-zA-Z0-9_\-{}:?&=.]+)["\']'),
    re.compile(r'endpoint\s*[=:]\s*["\']([/a-zA-Z0-9_\-{}:?&=.]+)["\']'),
    re.compile(r'baseURL\s*[=:]\s*["\']([^"\']+)["\']'),
    re.compile(r'path\s*[=:]\s*["\']([/a-zA-Z0-9_\-{}:?&=.]+)["\']'),
]

# Key-related terms to flag in discovered endpoints
KEY_RELATED_TERMS = {
    "key", "keys", "wallet", "wallets", "private", "secret", "mnemonic",
    "seed", "keystore", "vault", "keypair", "wif", "xpriv", "address",
    "account", "export", "backup", "recovery", "sign",
}


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str
    source: str  # "crawl", "wordlist", "js_analysis"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    key_related: bool = False
    response_size: int = 0
    auth_required: bool = False
    notes: str = ""


@dataclass
class CrawlResult:
    target: str
    endpoints: list = field(default_factory=list)
    js_files_analyzed: int = 0
    pages_crawled: int = 0
    errors: list = field(default_factory=list)

    @property
    def key_related_endpoints(self):
        return [e for e in self.endpoints if e.key_related]


class APICrawler:
    """
    Discovers and probes API endpoints on blockchain/crypto websites.
    Focuses on finding key management endpoints that may be vulnerable to IDOR.
    """

    def __init__(
        self,
        session: requests.Session,
        delay: float = 0.3,
        max_pages: int = 50,
        verbose: bool = False,
    ):
        self.session = session
        self.delay = delay
        self.max_pages = max_pages
        self.verbose = verbose
        self._visited = set()

    def _probe(self, url: str, method: str = "GET") -> tuple:
        """Probe a URL and return (status_code, content_type, response_size, body)."""
        try:
            time.sleep(self.delay + random.uniform(0, 0.1))
            resp = self.session.request(method, url, timeout=8)
            ct = resp.headers.get("Content-Type", "")
            return resp.status_code, ct, len(resp.content), resp.text
        except requests.exceptions.RequestException as e:
            return None, None, 0, ""

    def _is_key_related(self, url: str) -> bool:
        """Check if a URL path contains crypto key-related terms."""
        url_lower = url.lower()
        return any(term in url_lower for term in KEY_RELATED_TERMS)

    def _extract_links(self, base_url: str, html: str) -> list:
        """Extract all links from an HTML page."""
        links = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            base_domain = urlparse(base_url).netloc

            for tag in soup.find_all(["a", "link", "script", "form"]):
                href = tag.get("href") or tag.get("src") or tag.get("action")
                if href:
                    full_url = urljoin(base_url, href)
                    if urlparse(full_url).netloc == base_domain:
                        links.append(full_url)
        except Exception:
            pass
        return links

    def _extract_js_routes(self, js_content: str, base_url: str) -> list:
        """Extract API routes from JavaScript source code."""
        routes = []
        for pattern in JS_API_ROUTE_PATTERNS:
            for match in pattern.finditer(js_content):
                path = match.group(1)
                if path.startswith("http"):
                    routes.append(path)
                elif path.startswith("/"):
                    routes.append(urljoin(base_url, path))
                elif "api" in path.lower():
                    routes.append(urljoin(base_url, "/" + path))
        return list(set(routes))

    def _analyze_js_files(self, base_url: str, html: str) -> list:
        """Find and analyze JavaScript files for embedded API routes."""
        discovered = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            base_domain = urlparse(base_url).netloc

            for script in soup.find_all("script", src=True):
                src = script.get("src", "")
                js_url = urljoin(base_url, src)
                if urlparse(js_url).netloc != base_domain:
                    continue

                status, ct, size, body = self._probe(js_url)
                if status == 200 and body:
                    routes = self._extract_js_routes(body, base_url)
                    for route in routes:
                        if route not in self._visited:
                            discovered.append(route)
        except Exception:
            pass
        return discovered

    def crawl(self, base_url: str) -> CrawlResult:
        """
        Spider the target site starting from base_url.
        Discovers pages, JS files, and API endpoints.
        """
        result = CrawlResult(target=base_url)
        queue = [base_url]
        js_routes = []

        while queue and result.pages_crawled < self.max_pages:
            url = queue.pop(0)
            if url in self._visited:
                continue
            self._visited.add(url)

            status, ct, size, body = self._probe(url)
            result.pages_crawled += 1

            if status is None:
                result.errors.append(f"Failed to reach: {url}")
                continue

            # Record API endpoints found during crawl
            if "/api/" in url or self._is_key_related(url):
                ep = DiscoveredEndpoint(
                    url=url,
                    method="GET",
                    source="crawl",
                    status_code=status,
                    content_type=ct,
                    key_related=self._is_key_related(url),
                    response_size=size,
                    auth_required=(status in (401, 403)),
                )
                result.endpoints.append(ep)

            if ct and "html" in ct and body:
                # Crawl links
                links = self._extract_links(url, body)
                queue.extend([l for l in links if l not in self._visited])

                # Analyze JS files for routes
                js_routes.extend(self._analyze_js_files(url, body))
                result.js_files_analyzed += 1

        # Add JS-discovered routes
        for route in set(js_routes):
            if route not in self._visited:
                status, ct, size, _ = self._probe(route)
                ep = DiscoveredEndpoint(
                    url=route,
                    method="GET",
                    source="js_analysis",
                    status_code=status,
                    content_type=ct,
                    key_related=self._is_key_related(route),
                    response_size=size,
                    auth_required=(status in (401, 403)),
                )
                result.endpoints.append(ep)

        return result

    def wordlist_fuzz(self, base_url: str) -> list:
        """
        Fuzz common crypto API paths from wordlist.
        Returns list of DiscoveredEndpoint for responsive paths.
        """
        found = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in CRYPTO_API_WORDLIST:
            url = f"{base}/{path.lstrip('/')}"
            if url in self._visited:
                continue
            self._visited.add(url)

            status, ct, size, body = self._probe(url)
            if status is None:
                continue

            # Only record endpoints that respond (not 404)
            if status not in (404, 410):
                ep = DiscoveredEndpoint(
                    url=url,
                    method="GET",
                    source="wordlist",
                    status_code=status,
                    content_type=ct,
                    key_related=self._is_key_related(url),
                    response_size=size,
                    auth_required=(status in (401, 403)),
                    notes=f"Wordlist hit: HTTP {status}",
                )
                found.append(ep)

                # If it's a Swagger/OpenAPI doc, parse it for more endpoints
                if status == 200 and ("swagger" in url or "openapi" in url or "api-docs" in url):
                    ep.notes += " [API SPEC FOUND - check for key endpoints]"

        return found

    def detect_auth_scheme(self, base_url: str) -> dict:
        """
        Probe the target to understand how authentication works.
        This helps craft valid requests for IDOR testing.
        """
        info = {
            "scheme": "unknown",
            "login_endpoint": None,
            "token_field": None,
            "notes": [],
        }

        # Try common login endpoints
        login_paths = [
            "/api/auth/login", "/api/login", "/login", "/api/auth",
            "/api/v1/auth/login", "/auth/login",
        ]

        for path in login_paths:
            url = urljoin(base_url, path)
            status, ct, size, body = self._probe(url, "GET")
            if status is not None and status not in (404, 410):
                info["login_endpoint"] = url
                # Check response for token hints
                if body:
                    if "bearer" in body.lower() or "jwt" in body.lower():
                        info["scheme"] = "JWT/Bearer"
                        info["token_field"] = "Authorization: Bearer <token>"
                    elif "cookie" in body.lower() or "session" in body.lower():
                        info["scheme"] = "Cookie/Session"
                    elif "api_key" in body.lower() or "apikey" in body.lower():
                        info["scheme"] = "API Key"
                break

        # Check for GraphQL introspection
        gql_url = urljoin(base_url, "/graphql")
        introspection = '{"query": "{ __schema { types { name fields { name } } } }"}'
        try:
            resp = self.session.post(
                gql_url,
                data=introspection,
                headers={"Content-Type": "application/json"},
                timeout=8,
            )
            if resp.status_code == 200 and "__schema" in resp.text:
                info["notes"].append("GraphQL introspection enabled — full schema exposed")
        except Exception:
            pass

        return info
