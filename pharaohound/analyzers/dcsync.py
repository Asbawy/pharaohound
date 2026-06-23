#!/usr/bin/env python3
"""Accounts with DCSync rights."""

from __future__ import annotations
from typing import Optional

from ..intelligence import intel_for_right
from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class DCSyncAnalyzer(BaseAnalyzer):
    name = "dcsync_rights"
    description = "Find accounts with DCSync rights"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        for dom in store.iter_by_type("domain"):
            for ace in dom.aces:
                if not isinstance(ace, dict):
                    continue
                right = ace.get("RightName") or ""
                if right != "DCSync":
                    continue
                principal_sid = ace.get("PrincipalSID") or ""
                if not principal_sid:
                    continue
                principal = store.resolve_sid(principal_sid)
                data.append({
                    "account": principal.name,
                    "account_sid": principal_sid,
                    "account_type": principal.object_type,
                    "domain": dom.name,
                    "domain_sid": dom.sid,
                })
        if not data:
            return None

        intel = intel_for_right("DCSync")
        return Finding(
            title="DCSync Rights",
            summary=f"Found {len(data)} accounts/groups with DCSync privileges",
            severity=Severity.CRITICAL,
            data=data,
            recommendation=intel["short"],
            eli5=intel["eli5"],
            remediation=intel["remediation"],
            playbooks=intel["playbooks"].get("domain", []),
        )
