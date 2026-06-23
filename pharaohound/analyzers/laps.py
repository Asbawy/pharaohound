#!/usr/bin/env python3
"""LAPS password readers."""

from __future__ import annotations
from typing import Optional

from ..intelligence import intel_for_right
from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class LAPSReadersAnalyzer(BaseAnalyzer):
    name = "laps_readers"
    description = "Find accounts that can read LAPS passwords"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        # Walk every computer's ACEs for ReadLAPSPassword / AllExtendedRights
        for comp in store.iter_by_type("computer"):
            for ace in comp.aces:
                if not isinstance(ace, dict):
                    continue
                right = ace.get("RightName") or ""
                if right not in {"ReadLAPSPassword", "AllExtendedRights"}:
                    continue
                principal_sid = ace.get("PrincipalSID") or ""
                if not principal_sid:
                    continue
                principal = store.resolve_sid(principal_sid)
                data.append({
                    "reader": principal.name,
                    "reader_sid": principal_sid,
                    "reader_type": principal.object_type,
                    "target_computer": comp.name,
                    "target_sid": comp.sid,
                    "right": right,
                })
        if not data:
            return None

        # De-duplicate identical (reader, computer) pairs (e.g. both rights present)
        seen = set()
        deduped = []
        for d in data:
            k = (d["reader_sid"], d["target_sid"])
            if k in seen:
                continue
            seen.add(k)
            deduped.append(d)

        intel = intel_for_right("ReadLAPSPassword")
        return Finding(
            title="LAPS Password Readers",
            summary=f"Found {len(deduped)} LAPS password reading permissions",
            severity=Severity.HIGH,
            data=deduped,
            recommendation=intel["short"],
            eli5=intel["eli5"],
            remediation=intel["remediation"],
            playbooks=intel["playbooks"].get("computer", []),
        )
