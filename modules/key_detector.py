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
import json
from dataclasses import dataclass
from typing import Optional

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
        r'(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])',
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
    # Solana/Substrate base58 private keys (~87-88 chars base58)
    "solana_private_key": re.compile(
        r'(?i)(?:private[_\s]?key|secret)["\s:=]+["\']?[1-9A-HJ-NP-Za-km-z]{87,88}["\']?',
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
    "json_private_field": "CRITICAL",
    "json_wif": "CRITICAL",
    "raw_hex_64": "HIGH",    # Could be a private key, needs manual review
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
    "solana_private_key": "Solana/Substrate Private Key",
    "json_private_field": "JSON Private Key Field",
    "json_wif": "WIF Key in JSON",
    "raw_hex_64": "Raw 64-char Hex (possible private key)",
    "eth_public_key": "Ethereum Public Key",
    "eth_address": "Ethereum Address",
}


@dataclass
class KeyMatch:
    pattern_type: str
    type_name: str
    severity: str
    match: str
    redacted: str  # Safe version for reporting


def _redact(value: str, keep_chars: int = 8) -> str:
    """Redact a sensitive value, keeping only the first N and last N chars."""
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

                # Skip very short/common strings for low-signal patterns
                if pattern_name == "raw_hex_64":
                    # Extra validation: skip if it looks like a txid or block hash
                    # (we can't distinguish without context, flag it but lower priority)
                    if matched_text in seen_matches:
                        continue

                if matched_text in seen_matches:
                    continue
                seen_matches.add(matched_text)

                findings.append({
                    "type": pattern_name,
                    "type_name": TYPE_NAMES[pattern_name],
                    "severity": SEVERITY_MAP[pattern_name],
                    "match": matched_text,
                    "redacted": _redact(matched_text),
                })

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
            "seed_phrase", "xpriv", "zpriv", "keystore", "privateKeyHex",
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
