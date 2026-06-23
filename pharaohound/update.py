#!/usr/bin/env python3
"""
update.py — Lightweight GitHub update check logic for Pharaohound.

Queries the GitHub API to check for newer releases of Pharaohound.
Ensures zero external dependencies and a strict timeout for safety on
offline or isolated networks.
"""

from __future__ import annotations
import json
import urllib.request
import urllib.error
from typing import Optional, Tuple

def parse_version(v_str: str) -> Tuple[int, ...]:
    """Parse a version string (e.g. 'v1.0.1' or '1.0.0') into a tuple of ints."""
    clean = v_str.lstrip("vV").strip()
    try:
        parts = []
        for x in clean.split("."):
            # strip non-numeric suffix if any (e.g. '1-beta')
            num_part = "".join(ch for ch in x if ch.isdigit())
            if num_part:
                parts.append(int(num_part))
            else:
                parts.append(0)
        return tuple(parts)
    except Exception:
        return (0,)

def check_for_updates(current_version: str, timeout: float = 1.0) -> Optional[str]:
    """
    Check the GitHub releases API for a newer tag.
    Returns the remote tag name if newer, else None.
    Handles all network, parsing, and timeout exceptions silently.
    """
    url = "https://api.github.com/repos/Asbawy/pharaohound/releases/latest"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Pharaohound-Update-Notifier"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status == 200:
                body = response.read().decode("utf-8", errors="replace")
                data = json.loads(body)
                remote_tag = data.get("tag_name")
                if remote_tag:
                    curr_parsed = parse_version(current_version)
                    remote_parsed = parse_version(remote_tag)
                    if remote_parsed > curr_parsed:
                        return remote_tag
    except Exception:
        # Silently ignore any DNS, timeout, proxy, SSL, or offline issues
        pass
    return None
