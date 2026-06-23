#!/usr/bin/env python3
"""LAPS v2 & GPP cpassword analyzers."""

from __future__ import annotations
from typing import Optional

from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class LapsGppAnalyzer(BaseAnalyzer):
    name = "laps_gpp"
    description = "Detect legacy GPP cpasswords and Windows LAPS (v2) structures"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        for gpo in store.iter_by_type("gpo"):
            # A real analyzer might check GPO XML paths for cpassword
            # Or check if LAPS v2 is configured in the domain
            if gpo.extras.get("gpp_passwords"):
                data.append({"name": gpo.name, "type": "GPO (cpassword)", "sid": gpo.sid})
            if "laps" in gpo.name.lower():
                data.append({"name": gpo.name, "type": "GPO (LAPS)", "sid": gpo.sid})
                
        if not data:
            return None

        return Finding(
            title="GPP cpasswords & LAPS v2 Abuse",
            summary=f"Found {len(data)} GPOs related to Group Policy Preferences or LAPS.",
            severity=Severity.HIGH,
            data=data,
            recommendation="LAPS v2 / GPP Decryption",
            eli5="Legacy Group Policy Preferences (GPP) used a static AES key published by Microsoft to encrypt passwords (cpassword) deployed to endpoints. Anyone who can read the SYSVOL can decrypt them. Additionally, Windows LAPS (v2) passwords may be readable by compromised accounts with delegation.",
            remediation="Delete all GPP cpassword files from SYSVOL (they are no longer needed). Ensure Windows LAPS (v2) is configured to encrypt passwords, and restrict the accounts capable of decrypting them.",
            playbooks=[
                "# GPP cpassword Decryption:\n# Run gpp-decrypt against the AES-encrypted string found in SYSVOL:\ngpp-decrypt '<CPASSWORD_STRING>'",
                "# Search SYSVOL for cpasswords natively:\nfindstr /S /I cpassword \\\\<DOMAIN>\\SYSVOL\\<DOMAIN>\\policies\\*.xml",
                "# Windows LAPS (v2) Integration:\n# Use Get-LapsADPassword to extract encrypted LAPS passwords if your account has permission:\nGet-LapsADPassword -Identity <TARGET_HOST> -AsPlainText"
            ]
        )
