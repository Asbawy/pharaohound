#!/usr/bin/env python3
"""
pharaohound.py — top-level launcher for the pharaohound package.

Run as:
    python pharaohound.py <directory_with_bloodhound_jsons>
    python pharaohound.py /data/bh/ --output ./reports/

Or, if installed:
    python -m pharaohound <dir>
"""

import os
import sys

# Allow running this file directly from the download dir without installation.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from pharaohound.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
