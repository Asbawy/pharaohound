#!/usr/bin/env python3
"""Self-Add to Group Escalation analyzer."""

from __future__ import annotations
from typing import Optional

from ..models import ObjectStore, is_high_value_group_name
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class SelfAddGroupAnalyzer(BaseAnalyzer):
    name = "self_add_group"
    description = "Find accounts that can add themselves (or controlled accounts) to groups they are not in"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        relevant_rights = {"AddMember", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns"}
        
        # We walk every group in the domain.
        for target_group in store.iter_by_type("group"):
            for ace in target_group.aces:
                if not isinstance(ace, dict):
                    continue
                right = ace.get("RightName") or ""
                if right not in relevant_rights:
                    continue
                
                principal_sid = ace.get("PrincipalSID") or ""
                if not principal_sid:
                    continue
                
                # Skip self-edges (a group having rights on itself)
                if principal_sid == target_group.sid:
                    continue
                
                # Check transitive groups for the principal
                # If they are already in the target group, it's not a self-add escalation path.
                transitive_groups = store.transitive_groups_for(principal_sid)
                if target_group.sid in transitive_groups:
                    continue
                
                principal = store.resolve_sid(principal_sid)
                
                # Determine if target group is high value
                is_high_val = target_group.highvalue or is_high_value_group_name(target_group.name)
                
                data.append({
                    "principal": principal.name,
                    "principal_sid": principal_sid,
                    "principal_type": principal.object_type,
                    "target_group": target_group.name,
                    "target_group_sid": target_group.sid,
                    "right": right,
                    "is_high_value": is_high_val,
                    "severity": Severity.CRITICAL if is_high_val else Severity.HIGH,
                })

        if not data:
            return None

        # Dedupe (principal, target_group) pairs
        seen = set()
        deduped = []
        for d in data:
            k = (d["principal_sid"], d["target_group_sid"])
            if k in seen:
                continue
            seen.add(k)
            deduped.append(d)

        critical_count = sum(1 for d in deduped if d["is_high_value"])
        
        from ..intelligence import intel_for_right
        intel = intel_for_right("Self-Add to Group Escalation")

        return Finding(
            title="Self-Add to Group Escalation",
            summary=(
                f"Found {len(deduped)} self-add opportunities "
                f"({critical_count} High-Value Targets). Principal can write membership on a group "
                f"they are not currently in."
            ),
            severity=Severity.CRITICAL if critical_count else Severity.HIGH,
            data=deduped,
            recommendation=intel["short"],
            eli5=intel["eli5"],
            remediation=intel["remediation"],
            playbooks=intel["playbooks"].get("group", [])
        )
