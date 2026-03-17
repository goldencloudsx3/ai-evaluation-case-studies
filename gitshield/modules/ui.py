"""
GitShield — CLI Visual Layer

Neofetch-style layout:  ASCII shield (left)  ·  "GIT SHIELD" logo + info (right)

Design goals
  • Readable — GIT in violet, SHIELD in cyan; clear contrast between words
  • Compact  — 10-row panel, fits any ≥ 100-col terminal
  • Semantic — every status line uses colour to mean something
"""

import sys
import time
import re
import threading
from datetime import datetime

# ── ANSI palette ──────────────────────────────────────────────────────────────
R   = "\033[0m"
B   = "\033[1m"
DIM = "\033[2m"

# 256-colour
VI  = "\033[38;5;129m"   # violet      — "GIT"
P   = "\033[38;5;93m"    # purple
CY  = "\033[38;5;51m"    # bright cyan — "SHIELD"
C2  = "\033[38;5;45m"    # mid-cyan    — accents / borders
C3  = "\033[38;5;87m"    # pale cyan   — shield fill
GRN = "\033[38;5;82m"    # green       — success / live
GLD = "\033[38;5;220m"   # gold        — warnings / mode
RED = "\033[38;5;196m"   # red         — critical
DGY = "\033[38;5;240m"   # dark grey   — dim text / borders
LGY = "\033[38;5;252m"   # light grey  — label text
WHT = "\033[38;5;255m"   # white       — highlight

# ── ASCII shield — left column (10 visible rows, 22 chars wide) ───────────────
#
#      ╭──────────────────╮
#     ╭╯  ░░░░░░░░░░░░░  ╰╮
#     │  ░░ ╔══════════╗ ░░ │
#     │  ░░ ║          ║ ░░ │
#     │  ░░ ║    ◈     ║ ░░ │
#     │  ░░ ╚══════════╝ ░░ │
#     ╰╮  ░░░░░░░░░░░░░  ╭╯
#      ╰╮  ░░░░░░░░░░░  ╭╯
#       ╰─────────────────╯
#
_SH_C  = C2          # shield chrome (╔═╗║╚╝╭╯)
_SH_F  = C3          # shield fill (░)
_SH_DM = DIM + P     # ◈ inner icon

_SHIELD_RAW = [
    # raw text (no ANSI) — coloured below
    r"                      ",
    r"    ╭────────────────╮ ",
    r"   ╭╯░░░░░░░░░░░░░░░╰╮",
    r"   │░░╔════════════╗░░│",
    r"   │░░║            ║░░│",
    r"   │░░║     ◈      ║░░│",
    r"   │░░╚════════════╝░░│",
    r"   ╰╮░░░░░░░░░░░░░░░╭╯",
    r"    ╰╮░░░░░░░░░░░░░╭╯ ",
    r"     ╰──────────────╯  ",
]

def _coloured_shield() -> list:
    """Return the shield lines with ANSI colouring applied."""
    out = []
    for raw in _SHIELD_RAW:
        line = raw
        # chrome chars
        for ch in "╭╮╯╰│─╔═╗║╚╝":
            line = line.replace(ch, f"{_SH_C}{ch}{R}")
        # fill
        line = line.replace("░", f"{_SH_F}░{R}")
        # hexagon icon
        line = line.replace("◈", f"{_SH_DM}◈{R}")
        out.append(line)
    return out

# ── ANSI-Shadow for "GIT" (violet) and "SHIELD" (cyan) ───────────────────────
#  Each word is coloured separately so they're visually distinct.

# "GIT"  — 6 rows
_GIT = [
    f"{VI} ██████╗ ██╗████████╗{R}",
    f"{VI}██╔════╝ ██║╚══██╔══╝{R}",
    f"{VI}██║  ███╗██║   ██║   {R}",
    f"{VI}██║   ██║██║   ██║   {R}",
    f"{VI}╚██████╔╝██║   ██║   {R}",
    f"{VI} ╚═════╝ ╚═╝   ╚═╝   {R}",
]

# "SHIELD" — 6 rows
_SHIELD_TXT = [
    f"{CY}███████╗██╗  ██╗██╗███████╗██╗     ██████╗ {R}",
    f"{CY}██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗{R}",
    f"{CY}███████╗███████║██║█████╗  ██║     ██║  ██║{R}",
    f"{CY}╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║{R}",
    f"{CY}███████║██║  ██║██║███████╗███████╗██████╔╝{R}",
    f"{CY}╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ {R}",
]

# Space between GIT and SHIELD — 2 chars
_SEP = "  "

# ── Banner builder ─────────────────────────────────────────────────────────────

def print_banner(mode: str = "", version: str = "1.0", targets: int = 0,
                 deep: bool = True, telegram: bool = False):
    """
    Print the full startup banner.

    Layout  (12 total rows):
      row 0  — top border
      row 1  — shield[0] (blank)  |  blank
      rows 2–7  — shield[1-6]     |  GIT[0-5] + SHIELD[0-5]
      row 8  — shield[7]          |  blank
      row 9  — shield[8]          |  tagline / build info
      row 10 — shield[9]          |  blank
      row 11 — status bar
      row 12 — bottom border
    """
    shield_cols = _coloured_shield()
    logo_rows   = [f"{git}{_SEP}{shld}" for git, shld in zip(_GIT, _SHIELD_TXT)]

    # Right-side rows (10, matching shield height)
    tag = (
        f"{DGY}github secret scanner  ·  bug bounty edition{R}"
    )
    right = [
        "",                   # row 0 blank
        logo_rows[0],         # GIT + SHIELD row 1
        logo_rows[1],
        logo_rows[2],
        logo_rows[3],
        logo_rows[4],
        logo_rows[5],         # GIT + SHIELD row 6
        "",                   # row 7 blank
        f"  {tag}",           # row 8 tagline
        "",                   # row 9 blank
    ]

    top    = f"{DGY}╭{'─' * 98}╮{R}"
    mid    = f"{DGY}├{'─' * 98}┤{R}"
    bot    = f"{DGY}╰{'─' * 98}╯{R}"
    pipe   = f"{DGY}│{R}"

    print()
    print(top)

    for s_line, r_line in zip(shield_cols, right):
        s_vis = _vis(s_line)
        s_pad = " " * max(0, 24 - s_vis)
        row   = f"{pipe}  {s_line}{s_pad}{r_line}"
        print(row)

    print(mid)

    # Status bar
    mode_s    = f"{GLD}{B}{mode.upper():<10}{R}" if mode else f"{DGY}─{R}"
    deep_s    = f"{GRN}ON {R}" if deep else f"{DGY}off{R}"
    tgt_s     = f"{CY}{targets}{R}" if targets else f"{DGY}─{R}"
    tg_s      = f"{GRN}connected{R}" if telegram else f"{DGY}waiting{R}"
    ver_s     = f"{DGY}v{version}{R}"
    ts_s      = f"{DGY}{datetime.now().strftime('%Y-%m-%d  %H:%M')}{R}"

    sb = (
        f"  {DGY}mode{R} {mode_s}"
        f"  {DGY}│{R}  {DGY}deep{R} {deep_s}"
        f"  {DGY}│{R}  {DGY}targets{R} {tgt_s}"
        f"  {DGY}│{R}  {DGY}telegram{R} {tg_s}"
        f"  {DGY}│{R}  {ver_s}"
        f"  {DGY}│{R}  {ts_s}"
    )
    print(f"{pipe}{sb}")
    print(bot)
    print()


# ── Scan header ───────────────────────────────────────────────────────────────

def print_scan_start(repo: str, mode: str = "standard", deep: bool = False):
    deep_tag = f"  {CY}{DIM}🔬 deep{R}" if deep else ""
    bar = f"{DGY}┄" * 54 + R
    print(f"\n  {C2}┌{R}  {B}{WHT}{repo}{R}")
    print(f"  {C2}│{R}  {DGY}mode{R}  {GLD}{mode.upper()}{R}{deep_tag}"
          f"   {DGY}{datetime.now().strftime('%H:%M:%S')}{R}")
    print(f"  {C2}└{R}  {bar}\n")


def print_scan_result(repo: str, total: int, gl: int, th: int,
                      verified: int, deep_stats: dict = None):
    if total == 0:
        pill = f"{GRN}{B} CLEAN {R}"
    elif verified:
        pill = f"{RED}{B} CRITICAL {R}"
    else:
        pill = f"{GLD}{B} FINDINGS {R}"

    print(f"\n  {pill}  {DGY}{repo}{R}")
    print(f"  {'─' * 54}")
    print(f"  {_row('findings',    str(total),   RED if total   else GRN)}")
    print(f"  {_row('gitleaks',    str(gl),       GLD if gl      else DGY)}")
    print(f"  {_row('trufflehog',  str(th),       GLD if th      else DGY)}")
    if verified:
        print(f"  {_row('verified live', str(verified), RED)}")
    if deep_stats:
        print(f"  {DGY}  ·  deep extraction{R}")
        print(f"  {_row('  packs unpacked',        str(deep_stats.get('packs_unpacked', 0)),        CY)}")
        print(f"  {_row('  dangling blobs',         str(deep_stats.get('dangling_blobs', 0)),         CY)}")
        print(f"  {_row('  deleted files',          str(deep_stats.get('deleted_files_restored', 0)), CY)}")
    print()


def _row(label: str, value: str, vc: str) -> str:
    return f"{DGY}{label:<24}{R}  {vc}{B}{value}{R}"


# ── Hunt progress ─────────────────────────────────────────────────────────────

def print_hunt_target(idx: int, name: str, bounty: str, org: str, repo_count: int):
    num  = f"{DGY}[{idx:02d}]{R}"
    nm   = f"{WHT}{name:<28}{R}"
    bn   = f"{GRN}{bounty:<8}{R}"
    og   = f"{CY}{org:<32}{R}"
    rp   = f"{DGY}{repo_count} repos{R}"
    print(f"  {num}  {nm}  {bn}  {og}  {rp}")


# ── Log lines ─────────────────────────────────────────────────────────────────

def info(msg: str):
    _log(f"{C2}·{R}", msg)

def success(msg: str):
    _log(f"{GRN}✓{R}", msg)

def warn(msg: str):
    _log(f"{GLD}⚠{R}", f"{GLD}{msg}{R}")

def critical(msg: str):
    _log(f"{RED}◉{R}", f"{RED}{B}{msg}{R}")

def _log(icon: str, msg: str):
    ts = f"{DGY}{datetime.now().strftime('%H:%M:%S')}{R}"
    print(f"  {ts}  {icon}  {msg}")


# ── Section divider ───────────────────────────────────────────────────────────

def section(label: str = ""):
    if label:
        pad = max(0, 50 - len(label) - 2)
        print(f"\n  {DGY}{C2}──{R} {WHT}{B}{label}{R} {DGY}{'─' * pad}{R}\n")
    else:
        print(f"\n  {DGY}{'─' * 54}{R}\n")


# ── Spinner ───────────────────────────────────────────────────────────────────

class Spinner:
    _F = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def __init__(self, label: str = "working…"):
        self._label   = label
        self._running = False
        self._thread  = None

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def stop(self, ok: bool = True, msg: str = ""):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        # clear the spinner line
        sys.stdout.write(f"\r{' ' * (len(self._label) + 12)}\r")
        sys.stdout.flush()
        if msg:
            (success if ok else warn)(msg)

    def _run(self):
        i = 0
        while self._running:
            f = self._F[i % len(self._F)]
            sys.stdout.write(f"\r  {CY}{f}{R}  {DIM}{self._label}{R}  ")
            sys.stdout.flush()
            time.sleep(0.08)
            i += 1

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()


# ── Misc helpers ──────────────────────────────────────────────────────────────

def print_bot_ready(token_preview: str, chat_id: str):
    print(f"  {CY}◈{R}  Telegram bot  {DGY}token{R} {DIM}{token_preview}…{R}  {DGY}chat{R} {DIM}{chat_id}{R}")
    print()

def print_disclosure_ready(repo: str, path: str):
    print(f"\n  {GLD}┌─ DISCLOSURE DRAFT {'─'*34}{R}")
    print(f"  {GLD}│{R}  {DGY}repo{R}  {WHT}{repo}{R}")
    print(f"  {GLD}│{R}  {DGY}file{R}  {CY}{path}{R}")
    print(f"  {GLD}└{'─'*52}{R}\n")

def print_earnings_summary(total: float, count: int, this_month: float):
    print(f"\n  {GLD}◈  EARNINGS{R}   {DGY}{'─' * 38}{R}")
    print(f"  {_row('total earned',  f'${total:,.0f}',      GRN)}")
    print(f"  {_row('this month',    f'${this_month:,.0f}', GLD)}")
    print(f"  {_row('bounties paid', str(count),            WHT)}")
    print()


# ── Visible-length helper ─────────────────────────────────────────────────────

def _vis(s: str) -> int:
    return len(re.sub(r'\033\[[^m]*m', '', s))
