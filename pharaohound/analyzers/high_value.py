#!/usr/bin/env python3
"""Non-admin users in high-value groups."""

from __future__ import annotations
from typing import Optional

from ..graph import is_in_high_value_group, high_value_group_membership
from ..models import ObjectStore, is_high_value_group_name
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class HighValueMembersAnalyzer(BaseAnalyzer):
    name = "high_value_members"
    description = "Find non-admin users in high-value groups"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        for group in store.iter_by_type("group"):
            if not (group.highvalue or is_high_value_group_name(group.name)):
                continue
            for member in group.extras.get("members", []):
                if not isinstance(member, dict):
                    continue
                member_sid = member.get("ObjectIdentifier") or ""
                member_type = member.get("ObjectType") or ""
                if member_type != "User" or not member_sid:
                    continue
                user = store.users.get(member_sid)
                if not user or not user.enabled:
                    continue
                if user.admincount:
                    continue
                hv_groups = high_value_group_membership(store, user.sid)
                data.append({
                    "user": user.name,
                    "user_sid": user.sid,
                    "group": group.name,
                    "all_high_value_groups": hv_groups,
                    "severity": Severity.HIGH,
                })
        if not data:
            return None

        return Finding(
            title="Non-Admin Users in High-Value Groups",
            summary=f"Found {len(data)} non-admin users in privileged groups",
            severity=Severity.HIGH,
            data=data,
            recommendation="Review each membership. Most of these should be PAW-only / Tier-0 admin accounts.",
            eli5=(
                "NON-ADMIN USER IN HIGH-VALUE GROUP means a regular user account sits inside a "
                "Tier-0 group (Domain Admins, Enterprise Admins, etc.). These accounts are prime "
                "targets because compromising them gives instant DA. They're often 'temporary' "
                "elevations that nobody removed. Defenders: enforce a strict Tier-0 model — only "
                "dedicated admin accounts (suffix -admin) should be in these groups, and they "
                "should only log on from PAWs. Audit Event 4728/4732 (member added)."
            ),
            remediation=(
                "Implement a Tiered Admin Model (Tier-0/1/2). Move daily-use accounts out of "
                "privileged groups. Use just-in-time (JIT) access via PAM instead of standing "
                "privilege. Audit group membership changes."
            ),
            playbooks=[
                "# Enumerate high-value group members\nGet-DomainGroupMember -Identity 'Domain Admins' -Recurse",
                "Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Select-Object Name, ObjectClass, Enabled",
            ],
        )
