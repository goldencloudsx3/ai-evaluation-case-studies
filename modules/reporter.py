"""
Vulnerability Report Generator

Produces structured reports (console + JSON + HTML) from scan results.
Reports are designed to be useful for remediation and bug bounty submissions.

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

import json
import datetime
from pathlib import Path


SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",   # Red
    "HIGH":     "\033[93m",   # Yellow
    "MEDIUM":   "\033[94m",   # Blue
    "LOW":      "\033[92m",   # Green
    "INFO":     "\033[97m",   # White
    "RESET":    "\033[0m",
}

SEVERITY_EMOJI = {
    "CRITICAL": "[!!!]",
    "HIGH":     "[!! ]",
    "MEDIUM":   "[ ! ]",
    "LOW":      "[   ]",
    "INFO":     "[inf]",
}

REMEDIATION_ADVICE_EXTRA = {
    "JWT": """
JWT SECURITY:
  1. Whitelist the accepted algorithm server-side — never trust alg from the token header.
  2. Reject tokens where alg=none or alg is absent.
  3. Use a cryptographically random HMAC secret (≥256 bits) or an RSA/EC key pair.
  4. Never store sensitive data (passwords, private keys, mnemonics) in unencrypted JWT payloads.
  5. For asymmetric algorithms, ensure the server never accepts HS256 signed with the public key.

REFERENCES:
  - OWASP JWT Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
  - PortSwigger JWT Attacks: https://portswigger.net/web-security/jwt
""",
    "HEADERS": """
HTTP SECURITY HEADERS:
  1. HSTS — Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  2. CSP — Implement a restrictive Content-Security-Policy; avoid 'unsafe-inline' and 'unsafe-eval'.
  3. X-Frame-Options — Add: X-Frame-Options: DENY  (or CSP frame-ancestors 'none').
  4. X-Content-Type-Options — Add: X-Content-Type-Options: nosniff
  5. Cookies — Set Secure, HttpOnly, and SameSite=Strict on all session cookies.
  6. Mixed Content — Ensure all resources load over HTTPS.

REFERENCES:
  - OWASP Secure Headers: https://owasp.org/www-project-secure-headers/
  - Mozilla Security Guidelines: https://infosec.mozilla.org/guidelines/web_security
""",
    "TOKENS": """
TOKEN & PASSWORD HASH SECURITY:
  1. Generate tokens with a CSPRNG: Python secrets.token_hex(32) / Node crypto.randomBytes(32).
  2. Never use sequential IDs or timestamps as session identifiers.
  3. Minimum token length: 128 bits of entropy.
  4. For password hashing use argon2id, bcrypt (cost ≥12), or scrypt — never MD5 or SHA-1.
  5. Never return password hashes in API responses.

REFERENCES:
  - OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
  - OWASP Session Management: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
""",
}

REMEDIATION_ADVICE = {
    "IDOR_KEY_EXPOSURE": """
REMEDIATION:
  1. Implement proper authorization checks on ALL key/wallet endpoints.
     Verify that the authenticated user owns the requested resource.
  2. Do NOT use sequential integer IDs for sensitive resources. Use
     UUIDs or other non-guessable identifiers.
  3. Never return private key material in API responses. If export is
     required, use one-time tokens with short expiry.
  4. Implement rate limiting on key endpoints.
  5. Log and alert on any attempt to access another user's keys.

REFERENCES:
  - OWASP Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - OWASP IDOR: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
""",
    "PRIVATE_KEY_IN_RESPONSE": """
REMEDIATION:
  1. NEVER return raw private keys, WIF keys, mnemonics, or seed phrases
     in HTTP responses.
  2. For wallet export features, encrypt key material client-side before
     transmission, or use hardware security modules (HSMs).
  3. If key backup is required, implement secure export flows:
     - Require additional authentication (2FA, PIN)
     - Use encrypted containers
     - Log the access event
  4. Audit all API endpoints for unintended key material leakage.
""",
    "GRAPHQL_INTROSPECTION": """
REMEDIATION:
  1. Disable GraphQL introspection in production.
  2. Implement field-level authorization — not all users should query all fields.
  3. Ensure sensitive fields (privateKey, mnemonic, etc.) are never exposed
     in the GraphQL schema, even if access-controlled.
""",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Crypto Vulnerability Scan Report</title>
<style>
  body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2em; }}
  h1 {{ color: #58a6ff; }}
  h2 {{ color: #79c0ff; border-bottom: 1px solid #30363d; padding-bottom: 4px; }}
  h3 {{ color: #d29922; }}
  .critical {{ color: #f85149; font-weight: bold; }}
  .high {{ color: #d29922; font-weight: bold; }}
  .medium {{ color: #58a6ff; }}
  .low {{ color: #3fb950; }}
  .info {{ color: #8b949e; }}
  .finding {{ background: #161b22; border-left: 4px solid; padding: 1em; margin: 1em 0; border-radius: 4px; }}
  .finding.critical {{ border-color: #f85149; }}
  .finding.high {{ border-color: #d29922; }}
  .finding.medium {{ border-color: #58a6ff; }}
  .finding.low {{ border-color: #3fb950; }}
  .code {{ background: #0d1117; padding: 0.5em; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
  .warning {{ background: #161b22; border: 1px solid #d29922; padding: 1em; margin: 1em 0; border-radius: 4px; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #30363d; padding: 8px 12px; text-align: left; }}
  th {{ background: #161b22; color: #58a6ff; }}
  tr:nth-child(even) {{ background: #0d1117; }}
</style>
</head>
<body>
<h1>🔐 Crypto Vulnerability Scan Report</h1>
<div class="warning">
  ⚠️ <strong>AUTHORIZED TESTING ONLY</strong> — This report was generated for
  security research purposes on a target for which explicit written authorization
  was obtained. Unauthorized use of these findings is illegal.
</div>

<h2>Scan Summary</h2>
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Target</td><td>{target}</td></tr>
  <tr><td>Scan Date</td><td>{scan_date}</td></tr>
  <tr><td>Endpoints Tested</td><td>{endpoints_tested}</td></tr>
  <tr><td>IDs Enumerated</td><td>{ids_tested}</td></tr>
  <tr><td>Total Findings</td><td>{total_findings}</td></tr>
  <tr><td>Critical</td><td class="critical">{critical_count}</td></tr>
  <tr><td>High</td><td class="high">{high_count}</td></tr>
  <tr><td>Medium</td><td class="medium">{medium_count}</td></tr>
  <tr><td>Low/Info</td><td class="low">{low_count}</td></tr>
</table>

<h2>Discovered Endpoints</h2>
{endpoints_html}

<h2>IDOR / Key Exposure Findings</h2>
{findings_html}

<h2>Security Header Findings</h2>
{header_findings_html}

<h2>JWT Vulnerability Findings</h2>
{jwt_findings_html}

<h2>Token &amp; Password Hash Findings</h2>
{token_findings_html}

<h2>Remediation Guidance</h2>
<pre class="code">{remediation}</pre>

<hr>
<p style="color: #8b949e; font-size: 0.8em;">
Generated by Crypto Vulnerability Tester |
For authorized security testing only |
{scan_date}
</p>
</body>
</html>
"""


class Reporter:
    """Generates console, JSON, and HTML reports from scan results."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def _severity_color(self, severity: str) -> str:
        return SEVERITY_COLORS.get(severity, "") + severity + SEVERITY_COLORS["RESET"]

    def print_console_summary(
        self,
        target: str,
        idor_result,
        crawl_result,
        auth_info: dict,
    ):
        """Print a colorized summary to the terminal."""
        c = SEVERITY_COLORS
        r = SEVERITY_COLORS["RESET"]

        print(f"\n{c['HIGH']}{'='*70}{r}")
        print(f"{c['HIGH']}  CRYPTO VULNERABILITY TESTER — SCAN RESULTS{r}")
        print(f"{c['HIGH']}{'='*70}{r}\n")
        print(f"  Target   : {target}")
        print(f"  Auth     : {auth_info.get('scheme', 'unknown')}")
        print(f"  Endpoints: {idor_result.endpoints_tested} tested")
        print(f"  IDs      : {idor_result.ids_tested} enumerated")
        print(f"  Findings : {len(idor_result.findings)}")

        if crawl_result:
            print(f"  Crawled  : {crawl_result.pages_crawled} pages, "
                  f"{crawl_result.js_files_analyzed} JS files analyzed")

        print()

        if not idor_result.findings:
            print(f"  {c['LOW']}[+] No key exposure findings detected.{r}")
            print(f"  {c['INFO']}    (This does not guarantee the target is secure.){r}\n")
            return

        # Group by severity
        by_severity = {}
        for f in idor_result.findings:
            by_severity.setdefault(f.severity, []).append(f)

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if sev not in by_severity:
                continue
            color = c.get(sev, "")
            print(f"{color}{SEVERITY_EMOJI[sev]} {sev} ({len(by_severity[sev])} findings){r}")
            for finding in by_severity[sev]:
                print(f"     Endpoint : {finding.endpoint}")
                print(f"     ID       : {finding.reference_id}")
                print(f"     Evidence : {finding.evidence}")
                if finding.keys_found:
                    for k in finding.keys_found:
                        print(f"     Key Type : {k['type_name']} → {k['redacted']}")
                print()

        # Auth notes
        for note in auth_info.get("notes", []):
            print(f"  {c['HIGH']}[!] {note}{r}")
        print()

    def print_discovered_endpoints(self, crawl_result):
        """Print discovered API endpoints, highlighting key-related ones."""
        c = SEVERITY_COLORS
        r = SEVERITY_COLORS["RESET"]

        if not crawl_result:
            return

        key_eps = crawl_result.key_related_endpoints
        if not key_eps:
            print(f"  {c['INFO']}No key-related API endpoints discovered.{r}\n")
            return

        print(f"\n{c['MEDIUM']}[*] Key-Related Endpoints Discovered:{r}")
        for ep in key_eps:
            status_color = c["CRITICAL"] if ep.status_code == 200 else c["INFO"]
            auth_note = " [AUTH REQUIRED]" if ep.auth_required else ""
            print(
                f"  {status_color}HTTP {ep.status_code}{r}  "
                f"{ep.url}{auth_note}"
                f"  [{ep.source}]"
            )
        print()

    def save_json(
        self,
        target: str,
        idor_result,
        crawl_result,
        auth_info: dict,
        header_result=None,
        jwt_result=None,
        token_result=None,
    ) -> str:
        """Save scan results as JSON."""
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"scan_{timestamp}.json"

        # Convert findings to dicts (safe — redacted values only)
        findings_data = []
        for f in idor_result.findings:
            findings_data.append({
                "endpoint": f.endpoint,
                "reference_id": f.reference_id,
                "status_code": f.status_code,
                "severity": f.severity,
                "evidence": f.evidence,
                "keys_found": [
                    {k: v for k, v in kf.items() if k != "match"}  # exclude raw match
                    for kf in f.keys_found
                ],
                "response_snippet": f.response_snippet[:200],
            })

        endpoints_data = []
        if crawl_result:
            for ep in crawl_result.endpoints:
                endpoints_data.append({
                    "url": ep.url,
                    "method": ep.method,
                    "source": ep.source,
                    "status_code": ep.status_code,
                    "key_related": ep.key_related,
                    "auth_required": ep.auth_required,
                })

        # Serialize extra finding lists generically
        def _serialize_findings(findings):
            return [
                {
                    "severity":       f.severity,
                    "title":          f.title,
                    "description":    f.description,
                    "evidence":       f.evidence,
                    "recommendation": f.recommendation,
                    "category":       getattr(f, "category", ""),
                }
                for f in (findings or [])
            ]

        all_extra = (
            (header_result.findings if header_result else []) +
            (jwt_result.findings    if jwt_result    else []) +
            (token_result.findings  if token_result  else [])
        )
        n_extra_crit = sum(1 for f in all_extra if f.severity == "CRITICAL")
        n_extra_high = sum(1 for f in all_extra if f.severity == "HIGH")
        n_extra_med  = sum(1 for f in all_extra if f.severity == "MEDIUM")

        report = {
            "meta": {
                "tool": "Crypto Vulnerability Tester",
                "version": "2.0.0",
                "scan_date": datetime.datetime.utcnow().isoformat(),
                "target": target,
                "authorization": "AUTHORIZED TESTING ONLY",
            },
            "auth_info": auth_info,
            "summary": {
                "endpoints_tested": idor_result.endpoints_tested,
                "ids_tested": idor_result.ids_tested,
                "total_findings": len(idor_result.findings) + len(all_extra),
                "idor_critical": sum(1 for f in idor_result.findings if f.severity == "CRITICAL"),
                "idor_high":     sum(1 for f in idor_result.findings if f.severity == "HIGH"),
                "idor_medium":   sum(1 for f in idor_result.findings if f.severity == "MEDIUM"),
                "extra_critical": n_extra_crit,
                "extra_high":     n_extra_high,
                "extra_medium":   n_extra_med,
            },
            "idor_findings": findings_data,
            "header_findings": _serialize_findings(
                header_result.findings if header_result else []
            ),
            "jwt_findings": _serialize_findings(
                jwt_result.findings if jwt_result else []
            ),
            "token_findings": _serialize_findings(
                token_result.findings if token_result else []
            ),
            "discovered_endpoints": endpoints_data,
            "errors": idor_result.errors,
        }

        with open(filename, "w") as fh:
            json.dump(report, fh, indent=2)

        return str(filename)

    def save_html(
        self,
        target: str,
        idor_result,
        crawl_result,
        auth_info: dict,
        header_result=None,
        jwt_result=None,
        token_result=None,
    ) -> str:
        """Save scan results as HTML report."""
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"scan_{timestamp}.html"

        # Build findings HTML
        findings_html_parts = []
        for f in idor_result.findings:
            sev_class = f.severity.lower()
            keys_html = ""
            if f.keys_found:
                keys_html = "<ul>" + "".join(
                    f"<li><strong>{k['type_name']}</strong> ({k['severity']}): "
                    f"<code>{k['redacted']}</code></li>"
                    for k in f.keys_found
                ) + "</ul>"

            findings_html_parts.append(f"""
<div class="finding {sev_class}">
  <h3>[{f.severity}] IDOR Key Exposure</h3>
  <table>
    <tr><th>Endpoint</th><td><code>{f.endpoint}</code></td></tr>
    <tr><th>Reference ID</th><td><code>{f.reference_id}</code></td></tr>
    <tr><th>HTTP Status</th><td>{f.status_code}</td></tr>
    <tr><th>Evidence</th><td>{f.evidence}</td></tr>
  </table>
  {keys_html}
  <details>
    <summary>Response Snippet</summary>
    <pre class="code">{f.response_snippet[:300]}</pre>
  </details>
</div>
""")

        findings_html = "\n".join(findings_html_parts) if findings_html_parts else (
            "<p>No IDOR/key exposure findings.</p>"
        )

        # Build endpoints HTML
        endpoint_rows = ""
        if crawl_result:
            for ep in crawl_result.endpoints:
                key_flag = "✓" if ep.key_related else ""
                auth_flag = "⚠" if ep.auth_required else ""
                endpoint_rows += (
                    f"<tr>"
                    f"<td>{ep.status_code}</td>"
                    f"<td><code>{ep.url}</code></td>"
                    f"<td>{ep.source}</td>"
                    f"<td>{key_flag}</td>"
                    f"<td>{auth_flag}</td>"
                    f"</tr>\n"
                )

        endpoints_html = f"""
<table>
  <tr>
    <th>Status</th><th>URL</th><th>Source</th>
    <th>Key-Related</th><th>Auth Required</th>
  </tr>
  {endpoint_rows or '<tr><td colspan="5">No endpoints discovered</td></tr>'}
</table>
"""
        # ── Extra findings HTML (headers / JWT / tokens) ──────────────────────
        def _extra_findings_html(label: str, findings_list) -> str:
            if not findings_list:
                return f"<p>No {label} findings.</p>"
            parts = []
            for f in findings_list:
                sev_class = f.severity.lower()
                parts.append(f"""
<div class="finding {sev_class}">
  <h3>[{f.severity}] {f.title}</h3>
  <table>
    <tr><th>Description</th><td>{f.description}</td></tr>
    <tr><th>Evidence</th><td><code>{f.evidence}</code></td></tr>
    <tr><th>Recommendation</th><td>{f.recommendation}</td></tr>
  </table>
</div>""")
            return "\n".join(parts)

        header_html = _extra_findings_html(
            "security header", header_result.findings if header_result else []
        )
        jwt_html = _extra_findings_html(
            "JWT", jwt_result.findings if jwt_result else []
        )
        token_html = _extra_findings_html(
            "token / password hash", token_result.findings if token_result else []
        )

        all_extra = (
            (header_result.findings if header_result else []) +
            (jwt_result.findings    if jwt_result    else []) +
            (token_result.findings  if token_result  else [])
        )

        remediation = (
            REMEDIATION_ADVICE["IDOR_KEY_EXPOSURE"] +
            REMEDIATION_ADVICE["PRIVATE_KEY_IN_RESPONSE"] +
            REMEDIATION_ADVICE_EXTRA["JWT"] +
            REMEDIATION_ADVICE_EXTRA["HEADERS"] +
            REMEDIATION_ADVICE_EXTRA["TOKENS"]
        )

        findings = idor_result.findings
        html = HTML_TEMPLATE.format(
            target=target,
            scan_date=datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            endpoints_tested=idor_result.endpoints_tested,
            ids_tested=idor_result.ids_tested,
            total_findings=len(findings) + len(all_extra),
            critical_count=sum(1 for f in findings if f.severity == "CRITICAL"),
            high_count=sum(1 for f in findings if f.severity == "HIGH"),
            medium_count=sum(1 for f in findings if f.severity == "MEDIUM"),
            low_count=sum(1 for f in findings if f.severity in ("LOW", "INFO")),
            endpoints_html=endpoints_html,
            findings_html=findings_html,
            header_findings_html=header_html,
            jwt_findings_html=jwt_html,
            token_findings_html=token_html,
            remediation=remediation,
        )

        with open(filename, "w") as fh:
            fh.write(html)

        return str(filename)
