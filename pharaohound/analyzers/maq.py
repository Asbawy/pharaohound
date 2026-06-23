#!/usr/bin/env python3
"""
Machine Account Quota (MAQ) analyzer.

Checks the domain's ms-DS-MachineAccountQuota. If > 0, any authenticated
user can create computer accounts, enabling Resource-Based Constrained
Delegation (RBCD) attacks against targets where they hold GenericWrite.
"""

from __future__ import annotations
from typing import Optional

from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class MachineAccountQuotaAnalyzer(BaseAnalyzer):
    name = "machine_account_quota"
    description = "Check if Machine Account Quota allows any user to create computer accounts (RBCD prerequisite)"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []

        for domain in store.iter_by_type("domain"):
            props = domain.properties
            # ms-DS-MachineAccountQuota is stored in domain properties
            # SharpHound exports it as 'machineaccountquota' (lowercase)
            maq = props.get("machineaccountquota")
            if maq is None:
                # Try alternative keys used by different SharpHound versions
                maq = props.get("ms-ds-machineaccountquota")
            if maq is None:
                maq = props.get("msds-machineaccountquota")

            # If MAQ isn't in the export, try the raw dict
            if maq is None:
                raw_props = domain.raw.get("Properties") or {}
                maq = raw_props.get("machineaccountquota")

            # Default MAQ is 10 if not found (Windows default)
            if maq is None:
                maq = 10  # Windows default

            try:
                maq = int(maq)
            except (ValueError, TypeError):
                maq = 10

            if maq > 0:
                data.append({
                    "domain": domain.name,
                    "domain_sid": domain.sid,
                    "machine_account_quota": maq,
                    "severity": Severity.HIGH,
                })

        if not data:
            return None

        from ..intelligence import intel_for_right
        intel = intel_for_right("MachineAccountQuota")

        total_domains = len(data)
        max_maq = max(d["machine_account_quota"] for d in data)

        return Finding(
            title="Machine Account Quota Abuse",
            summary=(
                f"{total_domains} domain(s) allow any authenticated user to create up to "
                f"{max_maq} computer account(s). This enables RBCD attacks."
            ),
            severity=Severity.HIGH,
            data=data,
            recommendation=intel["short"],
            eli5=intel["eli5"],
            remediation=intel["remediation"],
            playbooks=intel["playbooks"].get("domain", []),
        )
