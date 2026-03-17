#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  KittyPaw Auto-Hunt — Continuous Background Runner
#
#  Usage:
#    chmod +x hunt_loop.sh
#    ./hunt_loop.sh              # runs in foreground (use tmux/screen for bg)
#
#  Recommended:
#    tmux new -s kittypaw
#    ./hunt_loop.sh
#    Ctrl-b d   (detach, keep running)
#    tmux attach -t kittypaw    (reattach)
#
#  Tune the vars below to match your setup.
# ─────────────────────────────────────────────────────────────────────────────

# ── Config ───────────────────────────────────────────────────────────────────
TOP_N=200          # Immunefi programs to target per cycle (covers ~all programs)
MAX_REPOS=30       # Repos to scan per GitHub org
SLEEP_BETWEEN=10   # Seconds between repos (avoids hammering GitHub)
CYCLE_PAUSE=3600   # Seconds to wait between full cycles (1 hour)
LOG_DIR="logs"
REPORT_DIR="reports"
PYTHON="${PYTHON:-python3}"
# ─────────────────────────────────────────────────────────────────────────────

mkdir -p "$LOG_DIR" "$REPORT_DIR"

CYAN="\033[96m"; BOLD="\033[1m"; GRN="\033[92m"
YEL="\033[93m";  RED="\033[91m"; DIM="\033[2m"; R="\033[0m"

banner() {
    echo -e "\n${CYAN}${BOLD}  ╔══════════════════════════════════════════════╗"
    echo -e "  ║  🐾  KittyPaw Hunt Loop  —  Cycle $CYCLE         ║"
    echo -e "  ║  top-n=$TOP_N  max-repos=$MAX_REPOS              ║"
    echo -e "  ╚══════════════════════════════════════════════╝${R}\n"
}

CYCLE=1
while true; do
    LOG="$LOG_DIR/hunt_$(date +%Y%m%d_%H%M%S).log"
    banner

    echo -e "  ${GRN}▸${R} Starting cycle ${BOLD}$CYCLE${R}  —  $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "  ${DIM}Logging to $LOG${R}\n"

    $PYTHON autohunt.py \
        --top-n "$TOP_N" \
        --max-repos "$MAX_REPOS" \
        --output-dir "$REPORT_DIR" \
        --yes \
        2>&1 | tee "$LOG"

    EXIT_CODE=${PIPESTATUS[0]}

    echo ""
    if [ "$EXIT_CODE" -eq 2 ]; then
        echo -e "  ${RED}${BOLD}🔴 CRITICAL findings detected — check $REPORT_DIR and Telegram${R}"
    elif [ "$EXIT_CODE" -eq 1 ]; then
        echo -e "  ${YEL}🟠 Findings saved to $REPORT_DIR${R}"
    else
        echo -e "  ${GRN}✔ Cycle $CYCLE clean${R}"
    fi

    echo -e "  ${DIM}Cycle $CYCLE done at $(date '+%H:%M:%S')  —  next in ${CYCLE_PAUSE}s${R}"
    CYCLE=$((CYCLE + 1))
    sleep "$CYCLE_PAUSE"
done
