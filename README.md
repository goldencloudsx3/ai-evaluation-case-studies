# Crypto Vulnerability Tester

> **FOR AUTHORIZED SECURITY TESTING ONLY**
> Unauthorized use against systems you do not own or have explicit written permission to test is illegal under CFAA, CMA, and similar laws worldwide.

A CLI tool that tests blockchain/crypto websites for the **IDOR key exposure vulnerability** class — where insufficient authorization checks on wallet/key API endpoints allow an attacker to read other users' private and public cryptographic keys by enumerating object IDs.

---

## Vulnerability Background

The write-up this tool is modeled on describes a **Broken Access Control / IDOR** vulnerability on a blockchain wallet website:

1. The site exposed an API endpoint that returned wallet keypairs (private + public keys)
2. The endpoint accepted a user/wallet ID as a path or query parameter
3. **No authorization check** verified whether the requester owned the requested wallet
4. An attacker could authenticate, discover their own numeric ID, then enumerate adjacent IDs to access **any other user's private keys**

This falls under:
- [OWASP A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP WSTG-AUTHZ-04 – Testing for IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- CWE-639: Authorization Bypass Through User-Controlled Key

---

## Features

| Module | What it does |
|--------|-------------|
| `modules/idor_scanner.py` | Enumerates IDs on 30+ crypto API endpoint patterns, detects key material in responses |
| `modules/key_detector.py` | Regex + heuristic detection of ETH private keys, WIF keys, mnemonics, keystores, xpriv, Solana keys |
| `modules/crawler.py` | Spiders the target site, analyzes JS bundles for hidden API routes, wordlist-fuzzes 50+ crypto paths, detects auth scheme |
| `modules/reporter.py` | Console (colorized), JSON, and HTML reports with remediation guidance |
| `crypto_vuln_tester.py` | Main CLI entry point |

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Usage

### Basic scan (sequential ID enumeration)
```bash
python crypto_vuln_tester.py --target https://target.example.com
```

### Authenticated scan with known user ID (most effective)
```bash
# Register a test account, get your user ID from the API, then:
python crypto_vuln_tester.py \
  --target https://target.example.com \
  --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... \
  --id 42 \
  --max-ids 50
```

### Cookie-based session
```bash
python crypto_vuln_tester.py \
  --target https://target.example.com \
  --cookie "session=abc123; csrf_token=xyz" \
  --id 1337
```

### Skip crawling (faster, pattern-only)
```bash
python crypto_vuln_tester.py \
  --target https://target.example.com \
  --no-crawl \
  --max-ids 100
```

---

## How the Attack Works (Step-by-Step)

```
1. REGISTER
   └─ Create a free account on the target crypto/blockchain site

2. AUTHENTICATE
   └─ Login and capture the session token/cookie from browser DevTools

3. DISCOVER YOUR ID
   └─ Call /api/user/me or /api/profile — note your numeric user_id

4. ENUMERATE
   └─ The tool tries IDs: [your_id - 10] through [your_id + N]
      GET /api/wallet/41/keys  → 403 (good)
      GET /api/wallet/42/keys  → 200 {"privateKey": "0xYOUR_KEY"}
      GET /api/wallet/43/keys  → 200 {"privateKey": "0xOTHER_PERSON_KEY"}  ← IDOR!

5. REPORT
   └─ Save findings, generate HTML/JSON report for the security team
```

---

## CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `--target` | (required) | Target base URL |
| `--id` | None | Your known user/wallet ID for adjacent enumeration |
| `--token` | None | Bearer token or API key |
| `--cookie` | None | Session cookie (`name=value; name2=value2`) |
| `--max-ids` | 20 | Number of IDs to enumerate |
| `--delay` | 0.5 | Seconds between requests (be respectful) |
| `--no-crawl` | False | Skip site crawling |
| `--output-dir` | `./reports` | Report output directory |
| `--no-html` | False | Skip HTML report |
| `--no-json` | False | Skip JSON report |
| `--no-verify` | False | Disable SSL verification (test environments) |
| `--yes` / `-y` | False | Skip authorization confirmation prompt |
| `--verbose` / `-v` | False | Verbose output |

---

## Key Patterns Detected

The key detector (`modules/key_detector.py`) identifies:

| Pattern | Severity | Example |
|---------|----------|---------|
| Ethereum private key (hex) | CRITICAL | `0xac0974bec...` |
| Bitcoin WIF private key | CRITICAL | `5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS` |
| BIP39 mnemonic phrase | CRITICAL | `abandon ability able about above...` |
| Extended private key | CRITICAL | `xprv9s21ZrQH...` |
| Encrypted keystore JSON | CRITICAL | `{"version":3,"crypto":{...}}` |
| Solana/Substrate base58 key | CRITICAL | `5J...` (87 chars) |
| JSON `privateKey` field | CRITICAL | `{"privateKey": "..."}` |
| Raw 64-char hex | HIGH | May be a private key — requires review |
| Ethereum public key | LOW | `0x04...` (128 hex chars) |
| Ethereum address | INFO | `0x742d35Cc...` |

---

## Reports

Reports are saved to `./reports/` by default:

- **`scan_YYYYMMDD_HHMMSS.json`** — Machine-readable, suitable for automation
- **`scan_YYYYMMDD_HHMMSS.html`** — Human-readable with remediation guidance

---

## Remediation Guidance

If vulnerabilities are found, report the following to the target's security team:

### Immediate Fixes
1. **Add authorization checks** on every key/wallet endpoint — verify the requesting user owns the resource
2. **Switch from sequential IDs** to UUIDs or other non-guessable identifiers
3. **Never return raw private keys** in API responses — use encrypted export flows
4. **Rate-limit** key endpoints and alert on cross-user access patterns

### Secure Design
- Implement **Object-Level Authorization** (check ownership, not just authentication)
- For key export features: require additional auth factor, use one-time tokens, log all access
- Consider **client-side key management** (keys never leave the user's device)
- Use **HSMs** for any server-side key storage

### References
- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PortSwigger IDOR Lab](https://portswigger.net/web-security/access-control/idor)
- [Immunefi Web3 Bug Bounty](https://immunefi.com/)
- [HackenProof Web3 Security](https://hackenproof.com/)

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | Non-critical findings |
| 2 | Critical findings (private key exposure) |

---

## Legal

This tool is provided for **authorized penetration testing, bug bounty research, and security education only**. The authors assume no liability for misuse. Always obtain explicit written authorization before testing any system you do not own.
