#!/usr/bin/env python3
"""
pharaohound.logging_setup — Unified ANSI-colorized logging schema.
"""

import logging
import sys
from .theme import Colors


class ColorLoggerHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            if record.levelno >= logging.ERROR:
                sys.stdout.write(f"  {Colors.CARNELIAN}[✗] {msg}{Colors.RESET}\n")
            elif record.levelno >= logging.WARNING:
                sys.stdout.write(f"  {Colors.OCHRE}[!] {msg}{Colors.RESET}\n")
            elif record.levelno >= logging.INFO:
                sys.stdout.write(f"  {Colors.TURQUOISE}[*] {msg}{Colors.RESET}\n")
            else:
                sys.stdout.write(f"  {Colors.DIM}[.] {msg}{Colors.RESET}\n")
            sys.stdout.flush()
        except Exception:
            self.handleError(record)


def setup_logging(verbose: bool = False) -> None:
    """Configure a unified, colorized logging schema for the framework."""
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("pharaohound")
    logger.setLevel(level)

    # Remove existing handlers
    for h in list(logger.handlers):
        logger.removeHandler(h)

    handler = ColorLoggerHandler()
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False
