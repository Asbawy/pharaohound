#!/usr/bin/env python3
"""
Dangerous ACL permissions between objects (GenericAll, WriteDacl, etc.).

This is the single most important analyzer. It walks every object's ACE
list, normalizes principal SIDs (handling nested groups via the graph
layer), and emits one finding per dangerous right.
"""

from __future__ import annotations
from typing import Optional

from ..graph import DANGEROUS_ACL_RIGHTS
from ..intelligence import intel_for_right, playbooks_for, remediation_for, eli5_for, severity_for
from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class DangerousACLAnalyzer(BaseAnalyzer):
    name = "dangerous_acls"
    description = "Find dangerous ACL permissions between objects"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        for obj in store.all_objects():
            if not obj.aces:
                continue
            for ace in obj.aces:
                if not isinstance(ace, dict):
                    continue
                right = ace.get("RightName") or ""
                if right not in DANGEROUS_ACL_RIGHTS:
                    continue
                principal_sid = ace.get("PrincipalSID") or ""
                if not principal_sid:
                    continue
                principal = store.resolve_sid(principal_sid)
                intel = intel_for_right(right)
                data.append({
                    "source_object": obj.name,
                    "source_type": obj.object_type,
                    "source_sid": obj.sid,
                    "principal": principal.name,
                    "principal_type": principal.object_type,
                    "principal_sid": principal_sid,
                    "right": right,
                    "short": intel["short"],
                    "severity": intel["severity"],
                })

        if not data:
            return None

        critical_count = sum(1 for d in data if d["severity"] == Severity.CRITICAL)
        # Pick the most-represented right to drive the Finding-level ELI5
        from collections import Counter
        right_counts = Counter(d["right"] for d in data)
        dominant_right = right_counts.most_common(1)[0][0]
        intel = intel_for_right(dominant_right)

        return Finding(
            title="Dangerous ACL Permissions",
            summary=(
                f"Found {len(data)} dangerous ACL edges "
                f"({critical_count} Critical). Most common: {dominant_right} "
                f"({right_counts[dominant_right]})"
            ),
            severity=Severity.CRITICAL if critical_count else Severity.HIGH,
            data=data,
            recommendation=intel["short"],
            eli5=intel["eli5"] + "\n\nSee the per-right ELI5 entries in the full report for details on each edge type.",
            remediation=intel["remediation"],
            playbooks=intel["playbooks"].get("user", []) + intel["playbooks"].get("group", []) + intel["playbooks"].get("computer", []),
        )
