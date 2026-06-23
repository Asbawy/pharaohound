#!/usr/bin/env python3
"""
theme.py — Pharaohound ANSI palette, severity levels, and banner art.
"""

from __future__ import annotations


# ═══════════════════════════════════════════════════════════════════════════════
# ANSI COLOR PALETTE — Pharaohound Theme
# ═══════════════════════════════════════════════════════════════════════════════
class Colors:
    """Pharaohound color palette for terminal output."""

    GOLD = "\033[38;5;220m"          # Pharaoh's gold
    TURQUOISE = "\033[38;5;45m"      # Faience turquoise
    LAPIS = "\033[38;5;27m"          # Lapis lazuli blue
    CARNELIAN = "\033[38;5;196m"     # Carnelian red (critical)
    PAPYRUS = "\033[38;5;230m"       # Papyrus white
    MALACHITE = "\033[38;5;82m"      # Malachite green
    AMETHYST = "\033[38;5;129m"      # Amethyst purple
    OCHRE = "\033[38;5;130m"         # Desert ochre
    OBSIDIAN = "\033[38;5;233m"      # Obsidian black
    SAND = "\033[38;5;179m"          # Desert sand
    NILE = "\033[38;5;30m"           # Nile river green
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"


# ═══════════════════════════════════════════════════════════════════════════════
# SEVERITY LEVELS
# ═══════════════════════════════════════════════════════════════════════════════
class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: Colors.CARNELIAN,
    Severity.HIGH: Colors.OCHRE,
    Severity.MEDIUM: Colors.GOLD,
    Severity.LOW: Colors.TURQUOISE,
    Severity.INFO: Colors.DIM,
}

SEVERITY_GLYPH = {
    Severity.CRITICAL: "▲",   # Pyramid — peak danger
    Severity.HIGH: "◆",        # Diamond — high value
    Severity.MEDIUM: "●",      # Sun disc
    Severity.LOW: "○",         # Empty sun
    Severity.INFO: "∙",
}


# ═══════════════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════════════
BANNER = rf"""{Colors.GOLD}
   ▄ ▄▄▄▄▄ ▄▄ ▄▄  ▄▄▄  ▄▄▄▄   ▄▄▄   ▄▄▄  ▄▄ ▄▄  ▄▄▄  ▄▄ ▄▄ ▄▄  ▄▄ ▄▄▄▄ 
▀██▀▀██ ██▄▄█ ▄█▀█▄ ██▀██ ▄█▀█▄ ▄█▀██ ██▄▄█ ▄█▀██ ██ ██ ███▄██ ██▀██
 ██▀▀▀  █▀▀██ ▓▓▀▒▒ ▓▓▀█▄ ▓▓▀▒▒ ▓▓ ▓▓ █▀▀██ ▓▓ ▓▓ ▓▓ █▀ ▓▓ ▀▓▓ ▓▓ ▓▓
 ▀▀     ▀▀ ▀▀ ▀▀ ▀▀ ▀▀ ▀▀ ▀▀ ▀▀  ▀▀▀  ▀▀ ▀▀  ▀▀▀  ▀▀▀▀  ▀▀  ▀▀ ▀▀▀▀ {Colors.RESET}
{Colors.TURQUOISE}                            ☥  P H A R A O H O U N D  ☥                            {Colors.RESET}
{Colors.DIM}              v1.0.0 | Streaming • Concurrent • Modular • Noob-Friendly                    {Colors.RESET}
"""


def colorize(text: str, color: str, bold: bool = False) -> str:
    """Wrap text in ANSI color codes."""
    prefix = color + (Colors.BOLD if bold else "")
    return f"{prefix}{text}{Colors.RESET}"


def severity_color(sev: str) -> str:
    return SEVERITY_COLORS.get(sev, Colors.DIM)


def severity_glyph(sev: str) -> str:
    return SEVERITY_GLYPH.get(sev, "∙")
