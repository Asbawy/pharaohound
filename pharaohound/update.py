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
    Check the GitHub releases API for a newer tag. Falls back to checking
    the tags API if the releases API fails or is empty (common when no official
    GitHub release is published yet).
    
    Returns the remote tag name if newer, else None.
    Handles all network, parsing, and timeout exceptions silently.
    """
    # 1. Try the official releases API first
    url_releases = "https://api.github.com/repos/Asbawy/pharaohound/releases/latest"
    req_releases = urllib.request.Request(
        url_releases,
        headers={"User-Agent": "Pharaohound-Update-Notifier"}
    )
    try:
        with urllib.request.urlopen(req_releases, timeout=timeout) as response:
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
        # Silently ignore and fall back to tags API
        pass

    # 2. Try the tags API as a fallback
    url_tags = "https://api.github.com/repos/Asbawy/pharaohound/tags"
    req_tags = urllib.request.Request(
        url_tags,
        headers={"User-Agent": "Pharaohound-Update-Notifier"}
    )
    try:
        with urllib.request.urlopen(req_tags, timeout=timeout) as response:
            if response.status == 200:
                body = response.read().decode("utf-8", errors="replace")
                tags = json.loads(body)
                if isinstance(tags, list) and len(tags) > 0:
                    curr_parsed = parse_version(current_version)
                    highest_tag = None
                    highest_version = curr_parsed
                    
                    for tag_obj in tags:
                        tag_name = tag_obj.get("name")
                        if tag_name:
                            parsed_tag = parse_version(tag_name)
                            if parsed_tag > highest_version:
                                highest_version = parsed_tag
                                highest_tag = tag_name
                    
                    if highest_tag:
                        return highest_tag
    except Exception:
        # Silently ignore any DNS, timeout, proxy, SSL, or offline issues
        pass

    return None
