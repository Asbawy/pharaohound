#!/usr/bin/env python3
"""GPO abuse paths."""

from __future__ import annotations
from typing import Optional

from ..graph import ou_contains_high_value
from ..intelligence import intel_for_right
from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class GPOAbuseAnalyzer(BaseAnalyzer):
    name = "gpo_abuse"
    description = "Find GPOs with weak permissions or linked to high-value OUs"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []

        # 1) Direct write access on GPOs
        dangerous = {"GenericWrite", "GenericAll", "WriteDacl", "WriteOwner", "Owns"}
        for gpo in store.iter_by_type("gpo"):
            for ace in gpo.aces:
                if not isinstance(ace, dict):
                    continue
                right = ace.get("RightName") or ""
                if right not in dangerous:
                    continue
                principal_sid = ace.get("PrincipalSID") or ""
                if not principal_sid:
                    continue
                principal = store.resolve_sid(principal_sid)
                data.append({
                    "gpo": gpo.name,
                    "gpo_sid": gpo.sid,
                    "attacker": principal.name,
                    "attacker_sid": principal_sid,
                    "attacker_type": principal.object_type,
                    "right": right,
                    "kind": "direct_write",
                })

        # 2) GPOs linked to high-value OUs
        for ou in store.iter_by_type("ou"):
            for link in ou.extras.get("gplink", []):
                if not isinstance(link, dict):
                    continue
                gpo_guid = link.get("GUID") or link.get("ObjectIdentifier") or ""
                # SharpHound sometimes stores GUID without curly braces
                if gpo_guid and gpo_guid not in store.gpos:
                    for cand in store.gpos.keys():
                        if cand.strip("{}").lower() == gpo_guid.strip("{}").lower():
                            gpo_guid = cand
                            break
                gpo = store.gpos.get(gpo_guid)
                if not gpo:
                    continue
                if ou_contains_high_value(store, ou.sid):
                    data.append({
                        "gpo": gpo.name,
                        "gpo_sid": gpo.sid,
                        "ou": ou.name,
                        "ou_sid": ou.sid,
                        "right": "GPLink",
                        "kind": "linked_to_high_value_ou",
                    })

        if not data:
            return None
        intel = intel_for_right("GPLink")
        return Finding(
            title="GPO Abuse Paths",
            summary=f"Found {len(data)} GPO abuse opportunities",
            severity=Severity.CRITICAL,
            data=data,
            recommendation=intel["short"],
            eli5=intel["eli5"],
            remediation=intel["remediation"],
            playbooks=intel["playbooks"].get("gpo", []),
        )
