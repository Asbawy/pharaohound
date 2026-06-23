#!/usr/bin/env python3
"""Shadow Credentials opportunities (GenericWrite/GenericAll on users/computers)."""

from __future__ import annotations
from typing import Optional

from ..intelligence import intel_for_right
from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class ShadowCredentialsAnalyzer(BaseAnalyzer):
    name = "shadow_credentials"
    description = "Find GenericWrite/GenericAll paths that enable Shadow Credentials"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        relevant_rights = {"GenericWrite", "GenericAll", "AddKeyCredentialLink", "AllExtendedRights"}
        for obj in store.all_objects():
            if obj.object_type not in {"user", "computer"}:
                continue
            for ace in obj.aces:
                if not isinstance(ace, dict):
                    continue
                right = ace.get("RightName") or ""
                if right not in relevant_rights:
                    continue
                principal_sid = ace.get("PrincipalSID") or ""
                if not principal_sid:
                    continue
                principal = store.resolve_sid(principal_sid)
                data.append({
                    "attacker": principal.name,
                    "attacker_sid": principal_sid,
                    "attacker_type": principal.object_type,
                    "target": obj.name,
                    "target_sid": obj.sid,
                    "target_type": obj.object_type,
                    "right": right,
                    "severity": Severity.CRITICAL,
                })
        if not data:
            return None

        # Dedupe (attacker, target) pairs
        seen = set()
        deduped = []
        for d in data:
            k = (d["attacker_sid"], d["target_sid"])
            if k in seen:
                continue
            seen.add(k)
            deduped.append(d)

        intel = intel_for_right("AddKeyCredentialLink")
        return Finding(
            title="Shadow Credentials Opportunities",
            summary=(
                f"Found {len(deduped)} GenericWrite/GenericAll paths enabling Shadow Credentials "
                f"on {len({d['target_sid'] for d in deduped})} unique targets"
            ),
            severity=Severity.CRITICAL,
            data=deduped,
            recommendation=intel["short"],
            eli5=intel["eli5"],
            remediation=intel["remediation"],
            playbooks=intel["playbooks"].get("user", []) + intel["playbooks"].get("computer", []),
        )
