"""
Pharaohound v1.0.0
==================

A streaming, concurrent, modular BloodHound JSON analysis engine
that maps attack paths in Active Directory environments and produces
noob-friendly remediation/exploitation blueprints.

Usage:
    python pharaohound.py <directory_with_bloodhound_jsons>
    python -m pharaohound <directory>
"""

from .theme import Colors, Severity, SEVERITY_RANK

__version__ = "1.0.0"
__author__ = "Asbawy"
__license__ = "MIT"
