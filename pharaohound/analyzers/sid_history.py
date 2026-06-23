#!/usr/bin/env python3
"""Accounts with SID History."""

from __future__ import annotations
from typing import Optional

from ..intelligence import intel_for_right
from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class SIDHistoryAnalyzer(BaseAnalyzer):
    name = "sid_history"
    description = "Find accounts with SID History"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        for user in store.iter_by_type("user"):
            sid_history = user.extras.get("has_sid_history", [])
            if not sid_history:
                continue
            extra_sids = []
            for s in sid_history:
                if isinstance(s, dict):
                    extra_sids.append(s.get("ObjectIdentifier") or str(s))
                else:
                    extra_sids.append(str(s))
            data.append({
                "name": user.name,
                "sid": user.sid,
                "extra_sids": extra_sids,
                "count": len(extra_sids),
            })
        if not data:
            return None

        intel = intel_for_right("SIDHistory")
        return Finding(
            title="SID History Abuse",
            summary=f"Found {len(data)} accounts with SID History",
            severity=Severity.MEDIUM,
            data=data,
            recommendation=intel["short"],
            eli5=intel["eli5"],
            remediation=intel["remediation"],
            playbooks=intel["playbooks"].get("user", []),
        )
