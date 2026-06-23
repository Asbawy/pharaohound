#!/usr/bin/env python3
"""Active logon sessions."""

from __future__ import annotations
from typing import Optional

from ..graph import is_in_high_value_group
from ..intelligence import intel_for_right
from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class SessionsAnalyzer(BaseAnalyzer):
    name = "active_sessions"
    description = "Find active logon sessions on computers"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        for comp in store.iter_by_type("computer"):
            for sess in comp.extras.get("sessions", []):
                if not isinstance(sess, dict):
                    continue
                user_sid = sess.get("UserSID") or sess.get("MemberId") or ""
                if not user_sid:
                    continue
                user = store.resolve_sid(user_sid)
                if not user.sid:
                    continue
                in_hv = is_in_high_value_group(store, user_sid)
                data.append({
                    "user": user.name,
                    "user_sid": user_sid,
                    "computer": comp.name,
                    "computer_sid": comp.sid,
                    "in_high_value_group": in_hv,
                    "severity": Severity.HIGH if in_hv else Severity.MEDIUM,
                })
        if not data:
            return None

        intel = intel_for_right("HasSession")
        return Finding(
            title="Active Sessions",
            summary=f"Found {len(data)} active session edges ({sum(1 for d in data if d['in_high_value_group'])} on high-value accounts)",
            severity=Severity.MEDIUM,
            data=data,
            recommendation=intel["short"],
            eli5=intel["eli5"],
            remediation=intel["remediation"],
            playbooks=intel["playbooks"].get("computer", []),
        )
