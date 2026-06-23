#!/usr/bin/env python3
"""Honeytoken and Deception Filtering."""

from __future__ import annotations
from typing import Optional

from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class HoneytokenAnalyzer(BaseAnalyzer):
    name = "honeytoken_filtering"
    description = "Detect likely honeytokens to reduce operational risk"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        # Look for accounts that are named "admin", "password" or have suspicious SPNs/descriptions
        # and warn the operator not to touch them.
        suspicious_keywords = ["admin", "password", "test", "honey", "fake"]
        
        for user in store.iter_by_type("user"):
            name_lower = user.name.lower()
            if any(k in name_lower.split("@")[0] for k in suspicious_keywords):
                # Check for zero activity or specific honeytoken flags if possible
                # e.g., pwdlastset is very old, no lastlogon, etc.
                if not user.extras.get("lastlogontimestamp", 0) and not user.extras.get("lastlogon", 0):
                    data.append({
                        "name": user.name,
                        "type": "User",
                        "sid": user.sid,
                        "reason": "Suspicious name pattern with zero logon activity"
                    })

        if not data:
            return None

        return Finding(
            title="Likely Honeytokens Detected",
            summary=f"Found {len(data)} objects that exhibit honeytoken or deception trap characteristics.",
            severity=Severity.HIGH,
            data=data,
            recommendation="Honeytoken & Deception Filtering",
            eli5="Honeytokens are fake accounts or resources created specifically to trigger high-fidelity alerts when touched. These accounts often have alluring names like 'Admin' or 'Password' but show zero actual network activity.",
            remediation="Ensure these accounts are monitored in the SIEM and have strict alerts for any authentication or LDAP query attempts.",
            playbooks=[
                "# Do not interact with the following accounts. If they appear in attack paths, prune them from your plan."
            ]
        )
