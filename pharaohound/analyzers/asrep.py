#!/usr/bin/env python3
"""AS-REP Roastable users (DONT_REQ_PREAUTH)."""

from __future__ import annotations
from typing import Optional

from ..intelligence import intel_for_right
from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class ASRepRoastAnalyzer(BaseAnalyzer):
    name = "asrep_roastable_users"
    description = "Find AS-REP Roastable users"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        for user in store.iter_by_type("user"):
            if not user.enabled:
                continue
            if not user.extras.get("dontreqpreauth"):
                continue
            data.append({"name": user.name, "sid": user.sid})
        if not data:
            return None

        intel = intel_for_right("ASRepRoastable")
        return Finding(
            title="AS-REP Roastable Users",
            summary=f"Found {len(data)} accounts with DONT_REQ_PREAUTH",
            severity=Severity.HIGH,
            data=data,
            recommendation=intel["short"],
            eli5=intel["eli5"],
            remediation=intel["remediation"],
            playbooks=intel["playbooks"].get("user", []),
        )
