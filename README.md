# 🐾 KittyPaw Scanner

> **Crypto / Web3 Vulnerability Scanner** — IDOR · Key Exposure · JWT · Security Headers · Token Entropy
>
> Real-time Telegram alerts · Multi-platform · Bug-bounty ready

```
  ╔════════════════════════════════════════════════════════╗
  ║            K I T T Y P A W   S C A N N E R            ║
  ║────────────────────────────────────────────────────────║
  ║       IDOR · KEY-EXPOSURE · JWT · HEADERS · TOKENS     ║
  ║          github.com/goldencloudsx3/GitSheild           ║
  ╚════════════════════════════════════════════════════════╝
```

**FOR AUTHORIZED SECURITY TESTING ONLY.**
Always obtain written permission before scanning any target.
Unauthorized use is illegal under CFAA, CMA, and similar laws worldwide.

---

## What Is This?

KittyPaw Scanner is a purpose-built vulnerability scanner for Web3 / crypto applications. It hunts the vulnerability classes that pay the most on bug bounty platforms:

| Module | What it finds | Payout potential |
|--------|--------------|-----------------|
| **IDOR Scanner** | Wallet/key endpoints with no access control | Critical · $5k–$250k+ |
| **Key Detector** | Exposed private keys, mnemonics, keystores | Critical · up to max bounty |
| **JWT Analyzer** | alg:none bypass, algorithm confusion, weak secrets | High · $2k–$50k |
| **Header Analyzer** | Missing HSTS, CSP, clickjacking protection | Low–Medium |
| **Token Analyzer** | Weak entropy, MD5/SHA-1 password hashing | Medium |

**Works without an account** — uses differential baseline analysis so you can probe endpoints without registering.

**Platforms:** Immunefi · Code4rena · HackerOne · Bugcrowd · Sherlock · YesWeHack · Intigriti · any web3 app with a public bug bounty.

---

## Mac Setup — Full Step-by-Step

Open **Terminal** (`⌘ Space` → type `Terminal` → Enter).

### Step 1 — Install Homebrew

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

After install, follow the on-screen instructions to add Homebrew to your PATH (Apple Silicon shows two `echo` + `eval` lines — run them).

### Step 2 — Install Python 3

```bash
brew install python3
python3 --version   # should show 3.11 or 3.12+
```

### Step 3 — Install Git

```bash
brew install git
git --version
```

### Step 4 — Add SSH key to GitHub

```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
# Press Enter for all prompts

cat ~/.ssh/id_ed25519.pub | pbcopy   # copies public key to clipboard
```

Go to **GitHub → Settings → SSH and GPG keys → New SSH key** → paste → save.

### Step 5 — Clone GitSheild

```bash
cd ~/Desktop
git clone git@github.com:goldencloudsx3/GitSheild.git
cd GitSheild
```

### Step 6 — Create Python virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
# Prompt now shows (.venv) — dependencies stay isolated
```

> Each new Terminal session: `cd ~/Desktop/GitSheild && source .venv/bin/activate`

### Step 7 — Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 8 — Configure .env

```bash
cp .env.example .env
open -e .env      # opens in TextEdit on Mac
```

Fill in:
```
TELEGRAM_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
```

Save and close.

### Step 9 — Get your Telegram Chat ID

1. Open Telegram → find **@Kittypawscannerbot**
2. Send the bot any message (e.g. `hello`)
3. Run:
   ```bash
   python get_chat_id.py --token YOUR_BOT_TOKEN
   ```
4. Copy the number shown and paste it into `.env` as `TELEGRAM_CHAT_ID`

### Step 10 — Test it works

```bash
python crypto_vuln_tester.py \
  --target https://example.com \
  --yes \
  --no-crawl --no-jwt --no-headers --no-tokens \
  --max-ids 3
```

You should see the KittyPaw banner, a reachability check, and a quick scan.
If Telegram is configured, you'll get a start + summary message in the bot.

---

## GitHub Repo — Permissions & Push

If you need to grant access or push from a collaborator account:

```bash
# Push your changes
git add -A
git commit -m "your message"
git push origin main
```

**To grant collaborator access:** Repo → **Settings → Collaborators → Add people**.

---

## Telegram Bot Setup

### Getting Your Bot Token

1. Telegram → search **@BotFather**
2. Send `/newbot`
3. Follow prompts → BotFather gives you a token like `123456789:ABCdef...`
4. Paste it into `.env` as `TELEGRAM_TOKEN=`

### What You Receive

| Event | Message |
|-------|---------|
| Scan starts | 🐾 Target + timestamp |
| CRITICAL finding | 🔴 URL, evidence, key type |
| HIGH finding | 🟠 URL, evidence |
| Rate limited 429 | ⏳ URL + backoff time |
| Scan complete | 📊 Full stats summary |
| Scan error | ❌ Error details |

---

## Usage

### Basic scan

```bash
python crypto_vuln_tester.py --target https://target.com
```

### With Telegram alerts (inline)

```bash
python crypto_vuln_tester.py \
  --target https://target.com \
  --telegram-token 123:ABC \
  --telegram-chat-id -100xxx
```

### Authenticated scan (Bearer token)

```bash
python crypto_vuln_tester.py --target https://target.com --token eyJhbGci...
```

### Session cookie

```bash
python crypto_vuln_tester.py --target https://target.com --cookie "session=abc123"
```

### Enable 403 bypass headers

```bash
python crypto_vuln_tester.py --target https://target.com --bypass-headers
```

Adds `X-Forwarded-For: 127.0.0.1`, `X-Custom-IP-Authorization: 127.0.0.1`, and related headers — widely documented public WAF bypass technique.

### Route through Burp Suite

```bash
python crypto_vuln_tester.py --target https://target.com --proxy http://127.0.0.1:8080 --no-verify
```

### Auto-retry on failure

```bash
python crypto_vuln_tester.py --target https://target.com --auto-retry 3 --retry-delay 60
```

### All flags

```
  --target            Base URL (required)
  --id                Seed integer ID from a public page
  --token             Bearer token / API key
  --cookie            Session cookie string
  --max-ids           IDs to enumerate per endpoint (default 30)
  --delay             Seconds between requests (default 0.3)
  --timeout           Per-request read timeout (default 10s)
  --no-crawl          Skip endpoint discovery
  --no-headers        Skip security header analysis
  --no-jwt            Skip JWT analysis
  --no-tokens         Skip token entropy analysis
  --bypass-headers    Add X-Forwarded-For / WAF bypass headers
  --proxy             HTTP proxy URL (Burp Suite etc.)
  --no-verify         Disable SSL certificate verification
  --output-dir        Report directory (default ./reports)
  --no-html           Skip HTML report
  --no-json           Skip JSON report
  --telegram-token    Telegram bot token
  --telegram-chat-id  Telegram chat ID
  --yes / -y          Skip authorization confirmation
  --verbose / -v      Verbose output
  --auto-retry N      Retry up to N times on failure
  --retry-delay S     Seconds between retries (default 30)
```

---

## Common Error Fixes

| Error | Fix |
|-------|-----|
| `SSL: CERTIFICATE_VERIFY_FAILED` | Add `--no-verify` |
| `ConnectionError: Max retries exceeded` | Check internet/VPN. Try `--delay 1.0` |
| `HTTP 403 everywhere` | Try `--bypass-headers` |
| `HTTP 429 everywhere` | Scanner auto-backs off. Also try `--delay 2.0` |
| `Telegram: Invalid token` | Double-check token from @BotFather |
| `Telegram: Chat not found` | Send a message to bot first, re-run `get_chat_id.py` |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` inside venv |
| `(.venv) not in prompt` | Run `source .venv/bin/activate` |
| `Reports not saving` | `mkdir -p reports` |
| `UnicodeDecodeError` on some sites | Scanner handles this; if it persists add `--no-crawl` |

---

## Manual Verification

After a scan, use `check_findings.py` to re-verify flagged endpoints:

```bash
python check_findings.py --report reports/scan_2026XXXX.json
python check_findings.py --report reports/scan_2026XXXX.json --token eyJ...
python check_findings.py --report reports/scan_2026XXXX.json --key-only
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings |
| `1` | Non-critical findings |
| `2` | CRITICAL (private key exposure) |
| `3` | Scan failed / incomplete |

---

## Bug Bounty Guide — Profit Potential (2026)

### Why Web3 IDOR Pays So Much

Most DeFi/crypto projects are built by blockchain engineers who understand cryptography perfectly but have limited API security experience. The result: wallet key management endpoints frequently lack the most basic access control.

A single IDOR on `/api/wallet/{id}/export` with no ownership check = full fund drain potential = maximum bounty.

### Platform Payouts

| Platform | Target type | IDOR/Key Exposure |
|----------|-------------|------------------|
| **Immunefi** | DeFi protocols | $5,000 – $10,000,000 |
| **HackerOne** | Web3 startups | $2,500 – $250,000 |
| **Bugcrowd** | Exchanges/wallets | $500 – $100,000 |
| **Code4rena** | Protocols + API | $1,000 – $50,000 |
| **Sherlock** | DeFi | $1,000 – $150,000 |
| **YesWeHack** | EU web3 | €500 – €50,000 |

### What This Tool Finds That Pays

**CRITICAL — Private Key Exposure**
- REST endpoint returning raw private key without auth check
- GraphQL field `privateKey` with no authorization resolver
- Mnemonic seed phrase in API response
- Encrypted keystore JSON in unauthenticated endpoint
- Private key hardcoded in JavaScript bundle (JS analysis module)

**HIGH — Wallet IDOR**
- Other users' wallet balances accessible by ID enumeration
- Transaction history exposed without ownership check

**HIGH — JWT Vulnerabilities**
- `alg: none` bypass → forge any user's token
- RS256→HS256 confusion → sign with server's public key

**MEDIUM — Misconfigs**
- Missing HSTS on a financial app
- Sensitive data in unencrypted JWT payload

### Workflow That Gets Paid

```
1.  Find a web3 target with a live bug bounty (Immunefi recommended)
2.  Run KittyPaw for initial recon + key-endpoint mapping
3.  Note key-related endpoints the scanner discovers
4.  Open the actual app in browser → DevTools → Network → XHR
5.  Perform real actions: login, deposit, view wallet
6.  Capture actual API calls with real IDs
7.  Test those real endpoints with forged/wrong IDs
8.  Document proof: curl command + screenshot of response
9.  Write a clear, concise report (under 1000 words)
10. Submit with CIA triad impact
```

### Report Template (CRITICAL finding)

```
Title: IDOR on /api/wallet/{id}/export exposes private key without authorization

Summary:
Any unauthenticated user can retrieve the private key for any wallet by
enumerating the wallet ID parameter on /api/wallet/{id}/export.

Steps to Reproduce:
1. GET https://target.com/api/wallet/1/export
2. GET https://target.com/api/wallet/2/export
3. Response contains { "privateKey": "0x..." }

Proof:
[Screenshot of response showing private key]

Impact:
Confidentiality: Full private key material exposed for all wallets
Integrity: Attacker can sign arbitrary transactions
Availability: All user funds can be drained

CVSS: 9.8 (Critical)

Remediation:
- Add ownership check: verify authenticated user owns wallet {id}
- Never return raw private key material in API responses
- Use one-time export tokens with short expiry if export is required
```

---

## Project Structure

```
GitSheild/
├── crypto_vuln_tester.py     ← Main entry point
├── check_findings.py         ← Manual endpoint verification
├── get_chat_id.py            ← Telegram chat ID finder
├── requirements.txt
├── .env.example              ← Copy → .env, fill in secrets
├── .gitignore
└── modules/
    ├── idor_scanner.py       ← IDOR + differential analysis
    ├── key_detector.py       ← Private key / mnemonic detection
    ├── crawler.py            ← Endpoint discovery + JS analysis
    ├── reporter.py           ← JSON + HTML report generation
    ├── jwt_analyzer.py       ← JWT vulnerability testing
    ├── header_analyzer.py    ← HTTP security headers audit
    ├── token_analyzer.py     ← Token entropy + hash analysis
    └── telegram_notifier.py  ← Real-time Telegram alerts
```

---

## Security Notes (Outside of Scope — Valid Risks for Manual Review)

> **Scan rate on small servers** — Default 0.3s delay is fine for most APIs but could stress very small production servers. Use `--delay 1.0` or higher on low-traffic targets to avoid unintentional DoS.

> **Report confidentiality** — `reports/` is `.gitignore`d by default. If you ever push a report with real key material to a public repo, those keys become public. Keep reports local or in a private repository.

> **Telegram token security** — Your bot token = API credentials. Anyone with it can post as your bot. Store in `.env` only. Never commit or share it.

> **Proxy trust** — When using `--proxy`, all traffic (including auth cookies/tokens) flows through it. Only use on a machine you fully control.

> **SSL bypass** — `--no-verify` disables TLS validation. Only use on internal/test targets or when a program explicitly allows it. Avoid on untrusted networks where MITM is possible.

---

*KittyPaw Scanner — built for authorized security research in the Web3 ecosystem.*
*Always hunt responsibly.*
