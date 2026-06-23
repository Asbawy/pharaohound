#!/usr/bin/env python3
"""Pre-Windows 2000 Compatible Access group members."""

from __future__ import annotations
from typing import Optional

from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class PreWindows2000Analyzer(BaseAnalyzer):
    name = "pre_windows_2000"
    description = "Detect Pre-Windows 2000 Compatible Access group members"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        for group in store.iter_by_type("group"):
            if "pre-windows 2000" not in group.name.lower():
                continue
            for member in group.extras.get("members", []):
                if not isinstance(member, dict):
                    continue
                member_sid = member.get("ObjectIdentifier") or ""
                member_type = member.get("ObjectType") or ""
                if not member_sid:
                    continue
                principal = store.resolve_sid(member_sid)
                data.append({
                    "member": principal.name,
                    "member_sid": member_sid,
                    "member_type": member_type or principal.object_type,
                    "group": group.name,
                    "severity": Severity.MEDIUM,
                })
        if not data:
            return None

        return Finding(
            title="Pre-Windows 2000 Compatible Access",
            summary=f"Found {len(data)} members in Pre-Windows 2000 group",
            severity=Severity.MEDIUM,
            data=data,
            recommendation="Remove AUTHENTICATED USERS if present. Only legacy apps need this group.",
            eli5=(
                "PRE-WINDOWS 2000 COMPATIBLE ACCESS is a backwards-compat group that allows "
                "anonymous / authenticated users to perform SAMR and LSA enumeration against the "
                "domain. It exists to support NT4-era apps. If 'Authenticated Users' or "
                "'ANONYMOUS LOGON' is in it, any attacker with a single foothold can enumerate "
                "users, groups, and other AD metadata via SAMR — exactly what BloodHound uses to "
                "build the graph in the first place. Disable SMB1, remove legacy apps, and prune "
                "the membership."
            ),
            remediation=(
                "Remove 'Authenticated Users' / 'ANONYMOUS LOGON' from this group. Disable "
                "Server-level SMB1. Apply RestrictAnonymous / RestrictAnonymousSAM registry "
                "settings. Audit SAMR calls (Event 4662 / 5145)."
            ),
            playbooks=[
                "# Enumerate SAMR anonymously\nenum4linux-ng -A <DC_IP>",
                "crackmapexec smb <DC_IP> -u '' -p '' --shares",
                "rpcclient -U '' -N <DC_IP> -c 'enumdomusers'",
            ],
        )
