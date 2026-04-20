"""
Solidity Audit Report Generator

Produces console, JSON, and HTML reports from SolidityAnalyzer findings.
Reuses severity constants from reporter.py for consistency.
"""

import json
import datetime
from pathlib import Path
from typing import Optional

from modules.solidity_analyzer import Finding

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[92m",
    "INFO":     "\033[97m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
}

SEVERITY_BARS = {
    "CRITICAL": "████████████ CRITICAL",
    "HIGH":     "█████████    HIGH",
    "MEDIUM":   "██████       MEDIUM",
    "LOW":      "███          LOW",
    "INFO":     "█            INFO",
}

_SEP = "─" * 72


def _c(sev: str, text: str) -> str:
    col = SEVERITY_COLORS.get(sev, "")
    rst = SEVERITY_COLORS["RESET"]
    return f"{col}{text}{rst}"


def print_console_report(findings: list[Finding], contract_name: str = "Contract"):
    bold = SEVERITY_COLORS["BOLD"]
    rst = SEVERITY_COLORS["RESET"]
    dim = SEVERITY_COLORS["DIM"]

    print(f"\n{bold}{'═'*72}{rst}")
    print(f"{bold}  KittyPaw Smart Contract Audit — {contract_name}{rst}")
    print(f"{bold}{'═'*72}{rst}")
    print(f"  {dim}Findings: {len(findings)}  |  "
          f"Critical: {sum(1 for f in findings if f.severity=='CRITICAL')}  |  "
          f"High: {sum(1 for f in findings if f.severity=='HIGH')}  |  "
          f"Medium: {sum(1 for f in findings if f.severity=='MEDIUM')}{rst}")
    print(f"{bold}{'═'*72}{rst}\n")

    for i, f in enumerate(findings, 1):
        sev_bar = _c(f.severity, f"  [{f.vuln_id}] {SEVERITY_BARS[f.severity]}")
        print(sev_bar)
        print(f"  {bold}{f.title}{rst}")
        print(f"  {dim}File: {f.file}:{f.line}  |  CWE: {f.cwe}  |  SWC: {f.swc}  |  "
              f"Feasibility: {f.feasibility}/10{rst}")
        print()
        print(f"  {bold}Description:{rst}")
        for line in f.description.split(". "):
            if line.strip():
                print(f"    {line.strip()}.")
        print()
        print(f"  {bold}Code:{rst}")
        for ln in f.code_snippet.splitlines():
            print(f"    {dim}{ln}{rst}")
        print()
        print(f"  {bold}Remediation:{rst}")
        for line in f.remediation.splitlines():
            print(f"    {line}")
        if f.exploit_poc:
            print()
            print(f"  {_c('CRITICAL', bold + 'Exploit PoC:' + rst)}")
            for ln in f.exploit_poc.splitlines():
                print(f"    {dim}{ln}{rst}")
        print(f"\n  {_SEP}\n")


def save_json_report(findings: list[Finding], out_path: Path) -> Path:
    report = {
        "tool": "KittyPaw SolidityAnalyzer",
        "generated": datetime.datetime.utcnow().isoformat() + "Z",
        "total": len(findings),
        "severity_counts": {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        },
        "findings": [f.to_dict() for f in findings],
    }
    out_path.write_text(json.dumps(report, indent=2))
    return out_path


_HTML_SEVERITY_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ffaa00",
    "MEDIUM":   "#4488ff",
    "LOW":      "#44cc44",
    "INFO":     "#aaaaaa",
}


def save_html_report(findings: list[Finding], out_path: Path, contract_name: str = "Contract") -> Path:
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    rows = ""
    for f in findings:
        col = _HTML_SEVERITY_COLORS[f.severity]
        rows += f"""
        <tr>
          <td><span style="color:{col};font-weight:bold">{f.vuln_id}</span></td>
          <td><span style="color:{col}">{f.severity}</span></td>
          <td>{f.title}</td>
          <td>{f.file}:{f.line}</td>
          <td>{f.feasibility}/10</td>
        </tr>"""

    details = ""
    for f in findings:
        col = _HTML_SEVERITY_COLORS[f.severity]
        poc_html = ""
        if f.exploit_poc:
            poc_html = f"""
            <h4 style="color:{col}">Exploit PoC</h4>
            <pre style="background:#1a1a2e;padding:12px;border-radius:6px;overflow-x:auto">{f.exploit_poc}</pre>"""

        details += f"""
        <div class="finding" style="border-left:4px solid {col};padding:16px;margin:16px 0;background:#1e1e2e;border-radius:0 8px 8px 0">
          <h3 style="color:{col};margin:0 0 8px">[{f.vuln_id}] {f.title}</h3>
          <div style="color:#888;font-size:0.85em;margin-bottom:12px">
            {f.file}:{f.line} | CWE: {f.cwe} | SWC: {f.swc} | Feasibility: {f.feasibility}/10
          </div>
          <h4>Description</h4>
          <p>{f.description}</p>
          <h4>Code</h4>
          <pre style="background:#0d1117;padding:12px;border-radius:6px;overflow-x:auto">{f.code_snippet}</pre>
          <h4>Remediation</h4>
          <pre style="background:#0d2010;padding:12px;border-radius:6px;overflow-x:auto">{f.remediation}</pre>
          {poc_html}
        </div>"""

    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    medium_count = sum(1 for f in findings if f.severity == "MEDIUM")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>KittyPaw Audit — {contract_name}</title>
  <style>
    body {{ background:#0d1117; color:#e6edf3; font-family:'Courier New',monospace; padding:24px; }}
    h1,h2,h3,h4 {{ color:#e6edf3; }}
    table {{ border-collapse:collapse; width:100%; margin:16px 0; }}
    th {{ background:#161b22; padding:10px 14px; text-align:left; color:#8b949e; }}
    td {{ padding:9px 14px; border-bottom:1px solid #21262d; }}
    tr:hover {{ background:#161b22; }}
    .stat {{ display:inline-block; padding:8px 18px; border-radius:6px; margin:6px; font-size:1.1em; font-weight:bold; }}
    a {{ color:#58a6ff; }}
  </style>
</head>
<body>
  <h1>&#x1F43E; KittyPaw Smart Contract Audit</h1>
  <p style="color:#8b949e">{contract_name} &nbsp;&bull;&nbsp; {now} &nbsp;&bull;&nbsp; KittyPaw SolidityAnalyzer</p>
  <div>
    <span class="stat" style="background:#3d0000;color:#ff4444">{critical_count} CRITICAL</span>
    <span class="stat" style="background:#3d2200;color:#ffaa00">{high_count} HIGH</span>
    <span class="stat" style="background:#001133;color:#4488ff">{medium_count} MEDIUM</span>
    <span class="stat" style="background:#0d2010;color:#44cc44">{sum(1 for f in findings if f.severity=='LOW')} LOW</span>
    <span class="stat" style="background:#1a1a1a;color:#aaaaaa">{sum(1 for f in findings if f.severity=='INFO')} INFO</span>
  </div>

  <h2>Summary</h2>
  <table>
    <tr><th>ID</th><th>Severity</th><th>Title</th><th>Location</th><th>Feasibility</th></tr>
    {rows}
  </table>

  <h2>Findings</h2>
  {details}

  <p style="color:#444;font-size:0.8em;margin-top:40px">
    Generated by KittyPaw Scanner &mdash; FOR AUTHORIZED SECURITY RESEARCH ONLY
  </p>
</body>
</html>"""

    out_path.write_text(html)
    return out_path
