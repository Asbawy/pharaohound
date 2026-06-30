"""
Pharaohound Auto-Exploitation Modules
=======================================
A modular framework for automating BloodHound-edge-based Active Directory
attacks. Each module corresponds to one (or more) BloodHound edges and
encapsulates the full exploitation logic, prerequisites checking, and
optional rollback support.
"""

from .base import ExploitModule, ExploitOutput, ExploitResult, ModuleOption, Severity
from .registry import ModuleRegistry

__all__ = [
    "ExploitModule",
    "ExploitOutput",
    "ExploitResult",
    "ModuleOption",
    "Severity",
    "ModuleRegistry",
]

__version__ = "2.0.0"
