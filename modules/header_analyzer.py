"""
HTTP Security Header Analyzer

Checks for missing or misconfigured security headers that protect against:
  - HSTS (HTTP Strict Transport Security) — forces HTTPS
  - Content-Security-Policy (CSP) — XSS mitigation
  - X-Frame-Options / CSP frame-ancestors — clickjacking protection
  - X-Content-Type-Options — MIME sniffing protection
  - Cookie security flags (Secure, HttpOnly, SameSite)
  - Mixed content (HTTP resources on HTTPS pages)
  - Server version disclosure

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict

import requests


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class HeaderFinding:
    severity: str        # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    description: str
    evidence: str
    recommendation: str
    category: str = ""   # hsts / csp / xframe / cookie / mixed / disclosure


@dataclass
class HeaderResult:
    findings: List[HeaderFinding] = field(default_factory=list)
    headers_checked: int = 0
    cookies_checked: int = 0
    errors: List[str] = field(default_factory=list)


# ── Analyzer ───────────────────────────────────────────────────────────────────

class HeaderAnalyzer:
    """
    Fetches the target's root response and audits its HTTP security headers
    and cookie attributes for common misconfigurations.
    """

    def __init__(self, session: requests.Session):
        self.session = session

    def analyze(self, target: str) -> HeaderResult:
        result = HeaderResult()

        try:
            resp = self.session.get(target, timeout=(6, 10))
        except requests.exceptions.RequestException as exc:
            result.errors.append(str(exc))
            return result

        # Normalize header names to lowercase for case-insensitive lookups
        headers: Dict[str, str] = {k.lower(): v for k, v in resp.headers.items()}
        result.headers_checked = len(headers)

        self._check_hsts(target, headers, result)
        self._check_csp(headers, result)
        self._check_xframe(headers, result)
        self._check_xcontent_type(headers, result)
        self._check_referrer_policy(headers, result)
        self._check_permissions_policy(headers, result)

        if target.startswith("https://"):
            self._check_mixed_content(resp, result)

        self._check_cookies(resp, result)
        self._check_server_disclosure(headers, result)

        return result

    # ── Individual checks ──────────────────────────────────────────────────────

    def _check_hsts(self, target: str, headers: Dict, result: HeaderResult):
        """HTTP Strict Transport Security."""
        if not target.startswith("https://"):
            return

        hsts = headers.get("strict-transport-security")
        if not hsts:
            result.findings.append(HeaderFinding(
                severity="MEDIUM",
                title="Missing HSTS Header",
                description=(
                    "Strict-Transport-Security is not set on this HTTPS response. "
                    "Without HSTS, the browser's first connection can be intercepted "
                    "before the redirect to HTTPS happens (SSL-stripping attack)."
                ),
                evidence="Strict-Transport-Security header absent from HTTPS response",
                recommendation=(
                    "Add: Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains; preload"
                ),
                category="hsts",
            ))
            return

        # max-age value check
        m = re.search(r'max-age=(\d+)', hsts, re.IGNORECASE)
        if m:
            max_age = int(m.group(1))
            if max_age < 31536000:
                result.findings.append(HeaderFinding(
                    severity="LOW",
                    title="HSTS max-age Too Short",
                    description=(
                        f"HSTS max-age is {max_age} seconds ({max_age // 86400} days). "
                        "The minimum recommended value is 31536000 (1 year). "
                        "A short max-age means the protection expires quickly and "
                        "the site re-enters the preload list eligibility window."
                    ),
                    evidence=f"Strict-Transport-Security: {hsts}",
                    recommendation="Set max-age to at least 31536000 (1 year).",
                    category="hsts",
                ))
        else:
            result.findings.append(HeaderFinding(
                severity="MEDIUM",
                title="HSTS Missing max-age Directive",
                description="HSTS header present but max-age is missing or unparseable.",
                evidence=f"Strict-Transport-Security: {hsts}",
                recommendation="Add a valid max-age directive: max-age=31536000",
                category="hsts",
            ))

        if "includesubdomains" not in hsts.lower():
            result.findings.append(HeaderFinding(
                severity="LOW",
                title="HSTS Missing includeSubDomains",
                description=(
                    "Subdomains are not covered by HSTS. An attacker who controls "
                    "a subdomain could serve HTTP content and steal cookies scoped "
                    "to the parent domain."
                ),
                evidence=f"Strict-Transport-Security: {hsts}",
                recommendation="Append includeSubDomains to the HSTS header.",
                category="hsts",
            ))

    def _check_csp(self, headers: Dict, result: HeaderResult):
        """Content Security Policy."""
        csp = headers.get("content-security-policy")
        if not csp:
            result.findings.append(HeaderFinding(
                severity="HIGH",
                title="Missing Content-Security-Policy Header",
                description=(
                    "No CSP is set. Without CSP, a successful XSS attack can "
                    "exfiltrate JWT tokens, wallet private keys, mnemonics, and "
                    "session cookies from the page."
                ),
                evidence="Content-Security-Policy header absent",
                recommendation=(
                    "Start with a restrictive policy: "
                    "Content-Security-Policy: default-src 'self'; "
                    "script-src 'self'; object-src 'none'"
                ),
                category="csp",
            ))
            return

        csp_lower = csp.lower()

        if "'unsafe-inline'" in csp_lower:
            result.findings.append(HeaderFinding(
                severity="HIGH",
                title="CSP Allows 'unsafe-inline' Scripts",
                description=(
                    "The CSP includes 'unsafe-inline', which permits inline "
                    "<script> blocks and event handlers. This largely negates "
                    "XSS protection because injected inline scripts will execute."
                ),
                evidence=f"Content-Security-Policy: {csp[:150]}",
                recommendation=(
                    "Remove 'unsafe-inline'. Replace inline scripts with external "
                    "files, or use nonces/hashes: script-src 'nonce-{random}'"
                ),
                category="csp",
            ))

        if "'unsafe-eval'" in csp_lower:
            result.findings.append(HeaderFinding(
                severity="MEDIUM",
                title="CSP Allows 'unsafe-eval'",
                description=(
                    "'unsafe-eval' permits eval(), setTimeout(string), "
                    "and similar dynamic code execution. This widens the XSS "
                    "attack surface even if inline scripts are blocked."
                ),
                evidence=f"Content-Security-Policy: {csp[:150]}",
                recommendation=(
                    "Remove 'unsafe-eval'. Refactor any code relying on eval(). "
                    "Many frameworks offer safe alternatives."
                ),
                category="csp",
            ))

        # Wildcard source check
        for directive in ("default-src *", "script-src *", "connect-src *"):
            if directive in csp_lower:
                result.findings.append(HeaderFinding(
                    severity="HIGH",
                    title=f"CSP Wildcard Source in '{directive.split()[0]}'",
                    description=(
                        f"The directive '{directive}' allows resources from any origin. "
                        "This defeats the purpose of CSP — injected scripts can load "
                        "exfiltration payloads from attacker-controlled domains."
                    ),
                    evidence=f"Content-Security-Policy: {csp[:150]}",
                    recommendation=(
                        "Replace wildcard with explicit trusted origins: "
                        f"{directive.split()[0]} 'self' https://trusted.cdn.example.com"
                    ),
                    category="csp",
                ))

    def _check_xframe(self, headers: Dict, result: HeaderResult):
        """Clickjacking protection via X-Frame-Options or CSP frame-ancestors."""
        xfo = headers.get("x-frame-options", "").strip().upper()
        csp = headers.get("content-security-policy", "").lower()
        has_frame_ancestors = "frame-ancestors" in csp

        if not xfo and not has_frame_ancestors:
            result.findings.append(HeaderFinding(
                severity="MEDIUM",
                title="Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)",
                description=(
                    "Neither X-Frame-Options nor a CSP frame-ancestors directive is set. "
                    "An attacker can embed this page in an iframe and overlay transparent "
                    "buttons to trick users into authorizing crypto transactions "
                    "(UI redressing / clickjacking)."
                ),
                evidence="X-Frame-Options absent; no frame-ancestors in Content-Security-Policy",
                recommendation=(
                    "Add one of:\n"
                    "  X-Frame-Options: DENY\n"
                    "  Content-Security-Policy: frame-ancestors 'none'\n"
                    "(CSP frame-ancestors is preferred — X-Frame-Options is deprecated.)"
                ),
                category="xframe",
            ))
            return

        if xfo == "ALLOWALL":
            result.findings.append(HeaderFinding(
                severity="HIGH",
                title="X-Frame-Options: ALLOWALL — Clickjacking Enabled",
                description=(
                    "X-Frame-Options is explicitly set to ALLOWALL, permitting "
                    "the page to be framed from any origin. This is equivalent "
                    "to having no protection at all."
                ),
                evidence=f"X-Frame-Options: {xfo}",
                recommendation="Change to X-Frame-Options: DENY or SAMEORIGIN",
                category="xframe",
            ))
        elif xfo == "SAMEORIGIN":
            # Informational — same-origin framing is allowed, which may be intentional
            result.findings.append(HeaderFinding(
                severity="INFO",
                title="X-Frame-Options: SAMEORIGIN (same-origin framing permitted)",
                description=(
                    "The page can be embedded in iframes from the same origin. "
                    "Verify this is intentional — if no feature requires self-framing, "
                    "consider upgrading to DENY."
                ),
                evidence=f"X-Frame-Options: {xfo}",
                recommendation=(
                    "If no same-origin iframe embedding is required, "
                    "use X-Frame-Options: DENY or CSP frame-ancestors 'none'"
                ),
                category="xframe",
            ))

    def _check_xcontent_type(self, headers: Dict, result: HeaderResult):
        """X-Content-Type-Options: nosniff."""
        val = headers.get("x-content-type-options", "").lower()
        if val != "nosniff":
            result.findings.append(HeaderFinding(
                severity="LOW",
                title="Missing X-Content-Type-Options: nosniff",
                description=(
                    "Without this header, browsers may MIME-sniff a response and "
                    "execute it as a different content type. An attacker who can "
                    "upload a file (e.g. an image) could serve it as JavaScript."
                ),
                evidence=(
                    f"X-Content-Type-Options: {headers.get('x-content-type-options', '(absent)')}"
                ),
                recommendation="Add: X-Content-Type-Options: nosniff",
                category="headers",
            ))

    def _check_referrer_policy(self, headers: Dict, result: HeaderResult):
        """Referrer-Policy."""
        if "referrer-policy" not in headers:
            result.findings.append(HeaderFinding(
                severity="INFO",
                title="Missing Referrer-Policy Header",
                description=(
                    "Without Referrer-Policy, the browser may send the full URL "
                    "(including query parameters containing wallet addresses or "
                    "token values) to third-party origins via the Referer header."
                ),
                evidence="Referrer-Policy header absent",
                recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
                category="headers",
            ))

    def _check_permissions_policy(self, headers: Dict, result: HeaderResult):
        """Permissions-Policy (formerly Feature-Policy)."""
        has_pp  = "permissions-policy" in headers
        has_fp  = "feature-policy" in headers
        if not has_pp and not has_fp:
            result.findings.append(HeaderFinding(
                severity="INFO",
                title="Missing Permissions-Policy Header",
                description=(
                    "No Permissions-Policy set. For a crypto platform, restricting "
                    "access to camera, microphone, geolocation, and payment APIs "
                    "reduces the attack surface if XSS occurs."
                ),
                evidence="Permissions-Policy header absent",
                recommendation=(
                    "Add: Permissions-Policy: "
                    "camera=(), microphone=(), geolocation=(), payment=(self)"
                ),
                category="headers",
            ))

    def _check_mixed_content(self, resp: requests.Response, result: HeaderResult):
        """Detect HTTP resources embedded in an HTTPS page."""
        content = resp.text
        # Match src=, href=, action= attributes pointing to http://
        http_refs = re.findall(
            r'(?:src|href|action|data-src)\s*=\s*["\']http://[^"\']{4,}["\']',
            content,
            re.IGNORECASE,
        )
        if http_refs:
            examples = "; ".join(r[:80] for r in http_refs[:3])
            result.findings.append(HeaderFinding(
                severity="HIGH",
                title=f"Mixed Content: {len(http_refs)} HTTP Resource(s) on HTTPS Page",
                description=(
                    f"This HTTPS page loads {len(http_refs)} resource(s) over plain HTTP. "
                    "An attacker on the network can intercept those HTTP requests, inject "
                    "malicious JavaScript, and steal tokens or keys displayed on the page."
                ),
                evidence=f"Examples: {examples}",
                recommendation=(
                    "Change all embedded resource URLs to HTTPS. "
                    "For resources you don't control, use protocol-relative URLs (//) "
                    "or host copies under your own HTTPS domain."
                ),
                category="mixed",
            ))

    def _check_cookies(self, resp: requests.Response, result: HeaderResult):
        """
        Inspect Set-Cookie headers for missing Secure, HttpOnly, and SameSite flags.
        Uses raw urllib3 header list to handle multiple Set-Cookie headers correctly.
        """
        try:
            raw_cookies = resp.raw.headers.getlist("Set-Cookie")
        except AttributeError:
            # Fallback: single Set-Cookie from CaseInsensitiveDict
            raw = resp.headers.get("Set-Cookie")
            raw_cookies = [raw] if raw else []

        result.cookies_checked = len(raw_cookies)

        for raw in raw_cookies:
            # Extract cookie name (first key=value pair)
            name_part = raw.split(";")[0].strip()
            name = name_part.split("=")[0].strip() if "=" in name_part else name_part
            lower = raw.lower()

            if "secure" not in lower:
                result.findings.append(HeaderFinding(
                    severity="HIGH",
                    title=f"Cookie Missing Secure Flag: '{name}'",
                    description=(
                        f"Cookie '{name}' does not have the Secure flag. "
                        "It will be transmitted over plain HTTP if the browser "
                        "ever makes an HTTP request — enabling interception."
                    ),
                    evidence=f"Set-Cookie: {raw[:120]}",
                    recommendation=f"Add the Secure attribute to cookie '{name}'.",
                    category="cookie",
                ))

            if "httponly" not in lower:
                result.findings.append(HeaderFinding(
                    severity="HIGH",
                    title=f"Cookie Missing HttpOnly Flag: '{name}'",
                    description=(
                        f"Cookie '{name}' lacks HttpOnly. Client-side JavaScript can "
                        "read it directly — an XSS payload can exfiltrate this cookie "
                        "to an attacker-controlled server."
                    ),
                    evidence=f"Set-Cookie: {raw[:120]}",
                    recommendation=f"Add HttpOnly attribute to cookie '{name}'.",
                    category="cookie",
                ))

            if "samesite" not in lower:
                result.findings.append(HeaderFinding(
                    severity="MEDIUM",
                    title=f"Cookie Missing SameSite Attribute: '{name}'",
                    description=(
                        f"Cookie '{name}' has no SameSite attribute. "
                        "It will be sent in cross-site requests, enabling "
                        "Cross-Site Request Forgery (CSRF) attacks against "
                        "wallet and transaction endpoints."
                    ),
                    evidence=f"Set-Cookie: {raw[:120]}",
                    recommendation=f"Add SameSite=Strict or SameSite=Lax to cookie '{name}'.",
                    category="cookie",
                ))

    def _check_server_disclosure(self, headers: Dict, result: HeaderResult):
        """Server version and technology header disclosure."""
        for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
            val = headers.get(hdr)
            if val:
                result.findings.append(HeaderFinding(
                    severity="INFO",
                    title=f"Server Technology Disclosed via '{hdr}' Header",
                    description=(
                        f"The response reveals server/framework details: {val!r}. "
                        "This aids attackers in selecting exploits targeted at the "
                        "specific version."
                    ),
                    evidence=f"{hdr}: {val}",
                    recommendation=(
                        f"Remove or genericize the '{hdr}' header in your web server "
                        "or framework configuration."
                    ),
                    category="disclosure",
                ))
