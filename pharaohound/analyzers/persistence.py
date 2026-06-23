#!/usr/bin/env python3
"""Advanced Persistence Analyzers."""

from __future__ import annotations
from typing import Optional

from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class PersistenceAnalyzer(BaseAnalyzer):
    name = "persistence_advanced"
    description = "Detect capabilities for installing advanced persistence (Skeleton Key, Malicious SSPs)"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        # Identify users who have AdminTo on Domain Controllers (capability to install SSPs/Skeleton Key)
        data = []
        for comp in store.iter_by_type("computer"):
            if "domain controller" in str(comp.extras.get("operatingsystem", "")).lower() or comp.name.startswith("dc"):
                data.append({"name": comp.name, "type": "Domain Controller", "sid": comp.sid})

        if not data:
            return None

        return Finding(
            title="Advanced DC Persistence Capabilities",
            summary=f"Found {len(data)} Domain Controllers. Compromising these allows advanced persistence.",
            severity=Severity.HIGH,
            data=data,
            recommendation="Install Advanced DC Persistence",
            eli5="Advanced persistence involves injecting code into the LSASS process on a Domain Controller. 'Skeleton Key' allows authenticating as any user with a master password. 'Malicious SSPs' (Security Support Providers) or custom password filters intercept and log all plaintext passwords as users authenticate to the DC or change their passwords.",
            remediation="Enable LSA Protection (RunAsPPL) on all Domain Controllers to prevent arbitrary code injection into LSASS. Monitor for unsigned or unknown DLLs loaded into LSASS.exe. Enforce Tier-0 administrative isolation.",
            playbooks=[
                "# Skeleton Key Injection (requires DA / Local Admin on DC):\nmimikatz # privilege::debug\nmimikatz # misc::skeleton",
                "# Malicious SSP Injection:\n# Drop the malicious SSP DLL to C:\\Windows\\System32\\ on the DC\n# Update HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Security Packages to include the new DLL\n# It will load on next reboot, or force load via Mimikatz:\nmimikatz # misc::memssp"
            ]
        )
