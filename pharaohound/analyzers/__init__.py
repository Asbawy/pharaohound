"""
pharaohound.analyzers — modular analyzer plugins.

Every analyzer is a small class inheriting from `BaseAnalyzer`. The
registry auto-discovers any module in this package — drop a new file
in, define a `BaseAnalyzer` subclass, and it will be picked up on the
next run.
"""

# Importing every analyzer module forces the subclasses to register
# themselves with BaseAnalyzer.__subclasses__().
from . import (           # noqa: F401
    kerberoast,
    asrep,
    acl_abuse,
    delegation,
    gpo_abuse,
    laps,
    dcsync,
    local_admin,
    sessions,
    password_policy,
    trusts,
    sid_history,
    shadow_creds,
    high_value,
    pre_w2k,
    os_vulns,
    self_add_group,
    maq,
    gmsa,
    adcs,
    azure,
)

from .base import BaseAnalyzer, Finding
from .registry import REGISTRY

__all__ = ["BaseAnalyzer", "Finding", "REGISTRY"]
