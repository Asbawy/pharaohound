"""
Pharaohound v2.0.0
==================

A streaming, concurrent, modular BloodHound JSON analysis engine
and Active Directory data collection framework. Collects AD data
via LDAP, maps attack paths, and produces noob-friendly
remediation/exploitation blueprints.

Usage:
    python -m pharaohound                    # Launch interactive framework shell
    python -m pharaohound <directory>         # Analyze existing BloodHound data
    python -m pharaohound collect -t DC -u U -p P -d DOMAIN
"""

from .theme import Colors, Severity, SEVERITY_RANK

__version__ = "2.0.0"
__author__ = "Asbawy"
__license__ = "MIT"
