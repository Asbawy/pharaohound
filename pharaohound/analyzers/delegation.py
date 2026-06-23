#!/usr/bin/env python3
"""Unconstrained + Constrained Delegation."""

from __future__ import annotations
from typing import Optional

from ..intelligence import intel_for_right
from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class UnconstrainedDelegationAnalyzer(BaseAnalyzer):
    name = "unconstrained_delegation"
    description = "Find computers with unconstrained delegation"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        for comp in store.iter_by_type("computer"):
            if not comp.extras.get("unconstraineddelegation"):
                continue
            data.append({
                "name": comp.name,
                "os": comp.extras.get("os", "Unknown"),
                "sid": comp.sid,
            })
        if not data:
            return None
        intel = intel_for_right("UnconstrainedDelegation")
        return Finding(
            title="Unconstrained Delegation",
            summary=f"Found {len(data)} computers with unconstrained delegation (TGT capture)",
            severity=Severity.CRITICAL,
            data=data,
            recommendation=intel["short"],
            eli5=intel["eli5"],
            remediation=intel["remediation"],
            playbooks=intel["playbooks"].get("computer", []),
        )


class ConstrainedDelegationAnalyzer(BaseAnalyzer):
    name = "constrained_delegation"
    description = "Find principals with constrained delegation"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        for user in store.iter_by_type("user"):
            delegated = user.extras.get("allowed_to_delegate", [])
            if not delegated:
                continue
            # Normalize targets: each may be a string or a dict
            targets = []
            for d in delegated:
                if isinstance(d, dict):
                    targets.append(d.get("ObjectIdentifier") or d.get("name") or str(d))
                else:
                    targets.append(str(d))
            data.append({
                "name": user.name,
                "type": "User",
                "sid": user.sid,
                "delegation_targets": targets,
                "trusted_to_auth": user.extras.get("trustedtoauth", False),
            })

        for comp in store.iter_by_type("computer"):
            delegated = comp.extras.get("allowed_to_delegate", [])
            if not delegated:
                continue
            targets = []
            for d in delegated:
                if isinstance(d, dict):
                    targets.append(d.get("ObjectIdentifier") or d.get("name") or str(d))
                else:
                    targets.append(str(d))
            data.append({
                "name": comp.name,
                "type": "Computer",
                "sid": comp.sid,
                "delegation_targets": targets,
                "trusted_to_auth": comp.extras.get("trustedtoauth", False),
            })

        if not data:
            return None
        intel = intel_for_right("AllowedToDelegate")
        return Finding(
            title="Constrained Delegation",
            summary=f"Found {len(data)} principals with constrained delegation",
            severity=Severity.HIGH,
            data=data,
            recommendation=intel["short"],
            eli5=intel["eli5"],
            remediation=intel["remediation"],
            playbooks=intel["playbooks"].get("user", []) + intel["playbooks"].get("computer", []),
        )
