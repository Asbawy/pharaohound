#!/usr/bin/env python3
"""Kerberoastable users (SPN-enabled accounts)."""

from __future__ import annotations
from typing import Optional

from ..graph import is_in_high_value_group
from ..intelligence import intel_for_right
from ..models import ObjectStore, calculate_password_age
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class KerberoastAnalyzer(BaseAnalyzer):
    name = "kerberoastable_users"
    description = "Find Kerberoastable users (SPN-enabled accounts)"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        for user in store.iter_by_type("user"):
            if not user.enabled:
                continue
            if not user.extras.get("hasspn"):
                continue
            spns = user.extras.get("spns", [])
            pwd_age = calculate_password_age(user.extras.get("pwdlastset", 0))
            in_hv = is_in_high_value_group(store, user.sid)
            data.append({
                "name": user.name,
                "sid": user.sid,
                "spns": spns,
                "pwd_age_days": pwd_age,
                "in_high_value_group": in_hv,
                "severity": Severity.CRITICAL if in_hv else Severity.HIGH,
            })
        if not data:
            return None

        intel = intel_for_right("Kerberoastable")
        critical_count = sum(1 for d in data if d["severity"] == Severity.CRITICAL)
        return Finding(
            title="Kerberoastable Users",
            summary=f"Found {len(data)} accounts with SPNs ({critical_count} in high-value groups)",
            severity=Severity.CRITICAL if critical_count else Severity.HIGH,
            data=data,
            recommendation=intel["short"],
            eli5=intel["eli5"],
            remediation=intel["remediation"],
            playbooks=intel["playbooks"].get("user", []),
        )
