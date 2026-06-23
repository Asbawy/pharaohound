#!/usr/bin/env python3
"""Non-privileged users with local-admin rights."""

from __future__ import annotations
from typing import Optional

from ..graph import is_in_high_value_group
from ..intelligence import intel_for_right
from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class LocalAdminAnalyzer(BaseAnalyzer):
    name = "local_admins"
    description = "Find non-privileged users with local admin rights"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        for comp in store.iter_by_type("computer"):
            for admin in comp.extras.get("local_admins", []):
                if not isinstance(admin, dict):
                    continue
                admin_sid = admin.get("ObjectIdentifier") or ""
                admin_type = admin.get("ObjectType") or ""
                if not admin_sid:
                    continue
                principal = store.resolve_sid(admin_sid)
                # Skip well-known SIDs (Everyone, Authenticated Users, etc.)
                if admin_sid in {"S-1-1-0", "S-1-5-11", "S-1-5-32-544"}:
                    continue

                sev = Severity.HIGH
                if admin_type == "User":
                    user = store.users.get(admin_sid)
                    if not user or not user.enabled:
                        continue
                    if user.admincount or is_in_high_value_group(store, admin_sid):
                        sev = Severity.MEDIUM
                elif admin_type == "Group":
                    group = store.groups.get(admin_sid)
                    if not group:
                        continue
                    if group.admincount or group.highvalue:
                        sev = Severity.MEDIUM

                data.append({
                    "principal": principal.name,
                    "principal_sid": admin_sid,
                    "principal_type": admin_type or principal.object_type,
                    "computer": comp.name,
                    "computer_sid": comp.sid,
                    "severity": sev,
                })

        if not data:
            return None

        intel = intel_for_right("AdminTo")
        return Finding(
            title="Non-Privileged Local Admins",
            summary=f"Found {len(data)} local admin edges on non-privileged accounts",
            severity=Severity.HIGH,
            data=data,
            recommendation=intel["short"],
            eli5=intel["eli5"],
            remediation=intel["remediation"],
            playbooks=intel["playbooks"].get("computer", []),
        )
