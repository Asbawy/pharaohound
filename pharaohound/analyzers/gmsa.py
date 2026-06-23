#!/usr/bin/env python3
"""
gMSA Password Reader analyzer.

Detects principals that have ReadGMSAPassword rights on Group Managed
Service Accounts (gMSAs). gMSA passwords are 240-byte random values
auto-rotated by AD, but any principal with the read right can extract
the current password hash and authenticate as the service.
"""

from __future__ import annotations
from typing import Optional

from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class GmsaPasswordAnalyzer(BaseAnalyzer):
    name = "gmsa_password_readers"
    description = "Find principals that can read gMSA managed passwords"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        # ReadGMSAPassword appears as an ACE right in BloodHound exports
        relevant_rights = {"ReadGMSAPassword"}
        # gMSAs are typically exported as users with objectclass
        # msDS-GroupManagedServiceAccount. Check for the 'gmsa' flag
        # in properties, or the ReadGMSAPassword ACE on any user/computer.

        for obj in store.all_objects():
            for ace in obj.aces:
                if not isinstance(ace, dict):
                    continue
                right = ace.get("RightName") or ""
                if right not in relevant_rights:
                    continue

                principal_sid = ace.get("PrincipalSID") or ""
                if not principal_sid:
                    continue

                # Skip self-edges
                if principal_sid == obj.sid:
                    continue

                principal = store.resolve_sid(principal_sid)

                data.append({
                    "reader": principal.name,
                    "reader_sid": principal_sid,
                    "reader_type": principal.object_type,
                    "gmsa_account": obj.name,
                    "gmsa_sid": obj.sid,
                    "gmsa_type": obj.object_type,
                    "right": right,
                    "severity": Severity.HIGH,
                })

        if not data:
            return None

        # Deduplicate by (reader_sid, gmsa_sid)
        seen = set()
        deduped = []
        for d in data:
            k = (d["reader_sid"], d["gmsa_sid"])
            if k not in seen:
                seen.add(k)
                deduped.append(d)

        from ..intelligence import intel_for_right
        intel = intel_for_right("ReadGMSAPassword")

        return Finding(
            title="gMSA Password Readers",
            summary=(
                f"Found {len(deduped)} principal(s) that can read gMSA managed passwords. "
                f"gMSA passwords are auto-rotated 240-byte keys — if readable, instant service takeover."
            ),
            severity=Severity.HIGH,
            data=deduped,
            recommendation=intel["short"],
            eli5=intel["eli5"],
            remediation=intel["remediation"],
            playbooks=intel["playbooks"].get("user", []),
        )
