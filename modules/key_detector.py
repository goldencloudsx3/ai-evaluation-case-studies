"""
Cryptographic Key Pattern Detector

Detects exposure of private keys, mnemonics, keystores, and other
sensitive cryptographic material in HTTP responses from blockchain websites.

Covers:
- Bitcoin WIF private keys (compressed/uncompressed)
- Ethereum/EVM hex private keys
- BIP39 mnemonic seed phrases (12/18/24 words)
- Encrypted JSON keystores (eth_keystore)
- Extended private keys (xpriv/zpriv)
- Raw hex private key material
- Solana/Substrate base58 private keys

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

import re
import hashlib
from typing import Optional

# Base58 alphabet (Bitcoin)
_BASE58_ALPHA = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_BASE58_MAP   = {c: i for i, c in enumerate(_BASE58_ALPHA)}


def _base58_decode(s: str) -> Optional[bytes]:
    """Decode Base58 string to bytes. Returns None on invalid input."""
    try:
        n = 0
        for ch in s:
            digit = _BASE58_MAP.get(ord(ch))
            if digit is None:
                return None
            n = n * 58 + digit
        result = []
        while n > 0:
            result.append(n & 0xFF)
            n >>= 8
        for ch in s:
            if ch == '1':
                result.append(0)
            else:
                break
        result.reverse()
        return bytes(result)
    except Exception:
        return None


def _validate_wif(wif: str) -> bool:
    """
    Validate a Bitcoin WIF private key via Base58Check.
    Returns True only if the string is a structurally valid WIF key.
    Redacted/truncated strings (containing '...') always return False.
    """
    if '...' in wif or len(wif) < 51:
        return False
    decoded = _base58_decode(wif)
    if decoded is None or len(decoded) < 37:
        return False
    payload, checksum = decoded[:-4], decoded[-4:]
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    if digest[:4] != checksum:
        return False
    version = payload[0]
    if version not in (0x80, 0xEF):          # mainnet / testnet
        return False
    if len(payload) not in (33, 34):         # 32-byte key + version [+ compression flag]
        return False
    if len(payload) == 34 and payload[-1] != 0x01:
        return False
    return True

# BIP39 wordlist subset for mnemonic detection (common words)
# Full list would be 2048 words; we use a representative subset for heuristics
BIP39_SAMPLE_WORDS = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb",
    "abstract", "absurd", "abuse", "access", "accident", "account", "accuse",
    "achieve", "acid", "acoustic", "acquire", "across", "action", "actor",
    "actress", "actual", "adapt", "add", "addict", "address", "adjust",
    "admit", "adult", "advance", "advice", "aerobic", "afford", "afraid",
    "again", "age", "agent", "agree", "ahead", "aim", "air", "airport",
    "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley",
    "allow", "almost", "alone", "alpha", "already", "also", "alter", "always",
    "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor",
    "ancient", "anger", "angle", "angry", "animal", "ankle", "announce",
    "annual", "another", "answer", "antenna", "antique", "anxiety", "apart",
    "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue",
    "armed", "armor", "arrest", "arrive", "arrow", "artist", "artwork",
    "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete",
    "atom", "attack", "attend", "auction", "audit", "august", "aunt",
    "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
    "aware", "away", "awesome", "awful", "awkward", "axis",
    "baby", "balance", "bamboo", "banana", "banner", "bar", "barely",
    "bargain", "barrel", "base", "basic", "basket", "battle", "beach",
    "beauty", "because", "become", "beef", "before", "begin", "believe",
    "below", "belt", "bench", "benefit", "best", "betray", "better",
    "between", "beyond", "bicycle", "bind", "biology", "bird", "birth",
    "bitter", "black", "blade", "blame", "blanket", "blast", "bleak",
    "bless", "blind", "blood", "blossom", "blouse", "blue", "blur",
    "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus",
    "book", "boost", "border", "boring", "borrow", "boss", "bottom",
    "bounce", "box", "boy", "bracket", "brain", "brand", "brave", "bread",
    "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk",
    "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush",
    "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk",
    "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
    "business", "busy", "butter", "buyer", "buzz",
    "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call",
    "calm", "camera", "camp", "capable", "capital", "captain", "carbon",
    "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino",
    "castle", "casual", "catalog", "catch", "category", "cattle", "caught",
    "cause", "caution", "cave", "ceiling", "celery", "cement", "census",
    "century", "cereal", "certain", "chair", "chalk", "champion", "change",
    "chaos", "chapter", "charge", "chase", "chat", "cheap", "check",
    "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
    "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn",
    "cigar", "cinnamon", "circle", "citizen", "city", "civil", "claim",
    "clap", "clarify", "claw", "clay", "clean", "clerk", "clever", "click",
    "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close",
    "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch",
    "coach", "coast", "coconut", "code", "coffee", "coil", "coin",
    "collect", "color", "column", "combine", "come", "comfort", "comic",
    "common", "company", "concert", "conduct", "confirm", "congress",
    "connect", "consider", "control", "convince", "cook", "cool", "copper",
    "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch",
    "country", "couple", "course", "cousin", "cover", "coyote", "crack",
    "cradle", "craft", "cram", "crane", "crash", "crazy", "cream",
    "credit", "creek", "crew", "cricket", "crime", "crisp", "critic",
    "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble",
    "crunch", "crush", "cry", "crystal", "cube", "culture", "cup",
    "cupboard", "curious", "current", "curtain", "curve", "cushion",
    "custom", "cute", "cycle",
}

# Regex patterns for key material detection
PATTERNS = {
    # Ethereum private key: exactly 64 hex chars (often prefixed with 0x)
    "eth_private_key": re.compile(
        r'(?i)(?:private[_\s]?key|privateKey|secret)["\s:=]+["\']?(0x)?[0-9a-f]{64}["\']?',
        re.IGNORECASE,
    ),
    # Raw 64-char hex private key (no label) — lower confidence
    "raw_hex_64": re.compile(
        r'(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])',
    ),
    # Bitcoin WIF: starts with 5 (uncompressed), K or L (compressed), or c (testnet)
    "wif_key": re.compile(
        r'\b[5KLc][1-9A-HJ-NP-Za-km-z]{50,51}\b',
    ),
    # Extended private keys
    "xpriv": re.compile(
        r'\b(xprv|zprv|yprv|tprv|vprv)[1-9A-HJ-NP-Za-km-z]{107,108}\b',
    ),
    # Ethereum keystore JSON
    "keystore_json": re.compile(
        r'\{[^}]*"version"\s*:\s*[13][^}]*"crypto"\s*:[^}]*"ciphertext"[^}]*\}',
        re.DOTALL | re.IGNORECASE,
    ),
    # Mnemonic phrase hint: 12/18/24 sequential BIP39-like words
    "mnemonic_hint": re.compile(
        r'(?i)(?:mnemonic|seed[_\s]?phrase|recovery[_\s]?phrase|secret[_\s]?phrase)["\s:=]+["\']?([a-z]+ ){11,23}[a-z]+["\']?',
    ),
    # Solana full keypair as base58 — 64 bytes base58-encoded (~87-88 chars)
    # This is the format Phantom, Solflare, and solana-keygen use for exports
    "solana_private_key": re.compile(
        r'(?i)(?:private[_\s]?key|secret[_\s]?key|keypair)["\s:=]+["\']?[1-9A-HJ-NP-Za-km-z]{87,88}["\']?',
    ),
    # Solana keypair as Uint8Array / JSON integer array — [1,2,...,64 bytes]
    # This is what solana-keygen outputs and what many backend services store
    "solana_uint8array": re.compile(
        r'\[\s*(?:[0-9]{1,3}\s*,\s*){63}[0-9]{1,3}\s*\]',
    ),
    # Solana public key — 32 bytes base58 = 43-44 chars
    "solana_pubkey": re.compile(
        r'(?i)(?:public[_\s]?key|pubkey|owner)["\s:=]+["\']?[1-9A-HJ-NP-Za-km-z]{43,44}["\']?',
    ),
    # Generic JSON field named after private key material
    "json_private_field": re.compile(
        r'"(?:privateKey|private_key|secretKey|secret_key|privKey|priv_key)"\s*:\s*"([^"]{32,})"',
        re.IGNORECASE,
    ),
    # WIF in JSON value
    "json_wif": re.compile(
        r'"(?:wif|WIF|importFormat)"\s*:\s*"([5KLc][1-9A-HJ-NP-Za-km-z]{50,51})"',
    ),
    # PEM-encoded private key block (RSA/EC/DSA/OPENSSH) — the HackerMD finding type:
    # hardcoded inside JS bundles as TRACK_PRIVATE_KEY or similar config variables.
    # Matches the full -----BEGIN * PRIVATE KEY----- ... -----END * PRIVATE KEY----- block.
    "rsa_pem_key": re.compile(
        r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
        r'[\s\S]{64,3500}?'
        r'-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        re.MULTILINE,
    ),
    # Public key exposure (lower severity but still notable)
    "eth_public_key": re.compile(
        r'(?i)(?:public[_\s]?key|publicKey)["\s:=]+["\']?(0x)?[0-9a-f]{128}["\']?',
    ),
    # Ethereum address (informational — may indicate wallet data in response)
    "eth_address": re.compile(
        r'\b0x[0-9a-fA-F]{40}\b',
    ),
}

# Severity mapping
SEVERITY_MAP = {
    "eth_private_key": "CRITICAL",
    "wif_key": "CRITICAL",
    "xpriv": "CRITICAL",
    "keystore_json": "CRITICAL",
    "mnemonic_hint": "CRITICAL",
    "solana_private_key": "CRITICAL",
    "solana_uint8array": "CRITICAL",
    "json_private_field": "CRITICAL",
    "json_wif": "CRITICAL",
    "rsa_pem_key": "CRITICAL",
    "raw_hex_64": "HIGH",
    "solana_pubkey": "LOW",
    "eth_public_key": "LOW",
    "eth_address": "INFO",
}

# Human-readable type names
TYPE_NAMES = {
    "eth_private_key": "Ethereum Private Key",
    "wif_key": "Bitcoin WIF Private Key",
    "xpriv": "Extended Private Key (xpriv/zpriv)",
    "keystore_json": "Encrypted Keystore JSON",
    "mnemonic_hint": "BIP39 Mnemonic/Seed Phrase",
    "solana_private_key": "Solana Keypair (base58)",
    "solana_uint8array": "Solana Keypair (Uint8Array/JSON bytes)",
    "solana_pubkey": "Solana Public Key",
    "json_private_field": "JSON Private Key Field",
    "json_wif": "WIF Key in JSON",
    "rsa_pem_key": "PEM Private Key (RSA/EC/DSA/OpenSSH)",
    "raw_hex_64": "Raw 64-char Hex (possible private key)",
    "eth_public_key": "Ethereum Public Key",
    "eth_address": "Ethereum Address",
}


def _redact(value: str, keep_chars: int = 8) -> str:
    """Redact a sensitive value, keeping only the first N and last N chars."""
    if not value:
        return "***REDACTED***"
    if len(value) <= keep_chars * 2:
        return "***REDACTED***"
    return f"{value[:keep_chars]}...{value[-keep_chars:]}***REDACTED***"


class KeyDetector:
    """
    Scans text content (HTTP response bodies) for cryptographic key material.
    Returns structured findings with severity levels.
    """

    def detect(self, content: str) -> list:
        """
        Detect all key patterns in the given text content.

        Returns a list of KeyMatch dictionaries.
        """
        findings = []
        seen_matches = set()  # Deduplicate

        for pattern_name, pattern in PATTERNS.items():
            for match in pattern.finditer(content):
                matched_text = match.group(0)

                # Skip redacted / truncated patterns — they are never real key material
                if '...' in matched_text:
                    continue

                # Skip very short/common strings for low-signal patterns
                if pattern_name == "raw_hex_64":
                    # Extra validation: skip if it looks like a txid or block hash
                    # (we can't distinguish without context, flag it but lower priority)
                    if matched_text in seen_matches:
                        continue

                if matched_text in seen_matches:
                    continue
                seen_matches.add(matched_text)

                # WIF-specific: validate checksum before reporting
                validated = None
                if pattern_name in ("wif_key", "json_wif"):
                    # Extract the raw Base58 token from the match
                    wif_token_m = re.search(r'[5KLc][1-9A-HJ-NP-Za-km-z]{50,51}', matched_text)
                    wif_token = wif_token_m.group(0) if wif_token_m else matched_text
                    validated = _validate_wif(wif_token)
                    if not validated:
                        # Downgrade to LOW and mark as likely false positive
                        findings.append({
                            "type": pattern_name,
                            "type_name": TYPE_NAMES[pattern_name],
                            "severity": "LOW",
                            "match": matched_text,
                            "redacted": _redact(matched_text),
                            "validated": False,
                            "false_positive_note": "WIF Base58Check failed — likely JS token or encoding artifact",
                        })
                        continue

                entry = {
                    "type": pattern_name,
                    "type_name": TYPE_NAMES[pattern_name],
                    "severity": SEVERITY_MAP[pattern_name],
                    "match": matched_text,
                    "redacted": _redact(matched_text),
                }
                if validated is not None:
                    entry["validated"] = validated
                findings.append(entry)

        # Mnemonic phrase detection via word list heuristic
        mnemonic_finding = self._detect_mnemonic_wordlist(content)
        if mnemonic_finding:
            dup_key = mnemonic_finding["match"][:20]
            if dup_key not in seen_matches:
                findings.append(mnemonic_finding)
                seen_matches.add(dup_key)

        # Sort: CRITICAL first
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda x: severity_order.get(x["severity"], 99))

        return findings

    def _detect_mnemonic_wordlist(self, content: str) -> Optional[dict]:
        """
        Use BIP39 word list heuristic to detect mnemonic phrases in plain text.
        Looks for sequences of 12, 18, or 24 consecutive BIP39 words.
        """
        words = re.findall(r'\b[a-z]{3,8}\b', content.lower())
        if len(words) < 12:
            return None

        # Sliding window: check consecutive runs of BIP39 words
        for window_size in (24, 18, 12):
            for i in range(len(words) - window_size + 1):
                window = words[i:i + window_size]
                bip39_count = sum(1 for w in window if w in BIP39_SAMPLE_WORDS)
                # If >80% of words are in our BIP39 sample, flag it
                if bip39_count >= window_size * 0.8:
                    phrase = " ".join(window)
                    return {
                        "type": "mnemonic_wordlist",
                        "type_name": f"Likely BIP39 Mnemonic ({window_size} words)",
                        "severity": "CRITICAL",
                        "match": phrase,
                        "redacted": _redact(phrase, 6),
                    }
        return None

    def detect_in_json(self, response_json: dict, path: str = "") -> list:
        """
        Recursively walk a parsed JSON object looking for private key fields.
        More precise than regex on raw text.
        """
        findings = []
        sensitive_field_names = {
            "privatekey", "private_key", "secretkey", "secret_key",
            "privkey", "priv_key", "wif", "mnemonic", "seed", "seedphrase",
            "seed_phrase", "xpriv", "zpriv", "keystore", "privatekeyhex",
            # Solana-specific field names used by common wallet backends
            "keypair", "secretkey", "signingkey", "signing_key",
            "fullkeypair", "full_keypair", "encodedkey", "encoded_key",
        }

        if isinstance(response_json, dict):
            for key, value in response_json.items():
                current_path = f"{path}.{key}" if path else key
                if key.lower() in sensitive_field_names and isinstance(value, str) and len(value) > 10:
                    findings.append({
                        "type": "json_field",
                        "type_name": f"Sensitive JSON field: {key}",
                        "severity": "CRITICAL",
                        "match": value,
                        "redacted": _redact(value),
                        "json_path": current_path,
                    })
                elif isinstance(value, (dict, list)):
                    findings.extend(self.detect_in_json(value, current_path))

        elif isinstance(response_json, list):
            for i, item in enumerate(response_json):
                findings.extend(self.detect_in_json(item, f"{path}[{i}]"))

        return findings
