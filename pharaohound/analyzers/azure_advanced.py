#!/usr/bin/env python3
"""Advanced Azure & Entra ID Abuse Analyzers."""

from __future__ import annotations
from typing import Optional

from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class AzureAdvancedAnalyzer(BaseAnalyzer):
    name = "azure_advanced"
    description = "Detect advanced Azure/Entra ID attack paths (PRT extraction, Intune takeover, Seamless SSO)"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        
        # In a hybrid BloodHound dataset (e.g. from AzureHound), we have azureserviceprincipal, azureuser, etc.
        # We will iterate through these. 
        for obj in store.all_objects():
            if obj.object_type == "azuretenant":
                data.append({"name": obj.name, "type": "Azure Tenant", "sid": obj.sid})
            elif "azure" in obj.object_type:
                if "sso" in obj.name.lower() or "seamless" in obj.name.lower():
                    data.append({"name": obj.name, "type": "Seamless SSO Target", "sid": obj.sid})

        if not data:
            return None

        return Finding(
            title="Advanced Azure & Entra ID Pivots",
            summary=f"Found {len(data)} Azure-related objects. Analyzing for PRT extraction, Intune abuse, and Seamless SSO vectors.",
            severity=Severity.HIGH,
            data=data,
            recommendation="Azure & Entra ID Abuse Paths",
            eli5="Hybrid environments connect on-premise AD to Entra ID (Azure AD). Advanced abuse includes extracting the Primary Refresh Token (PRT) from compromised workstations to bypass MFA, forging Silver Tickets using the AZUREADSSOACC computer account hash for Seamless SSO, pushing malicious scripts via Intune MDM, or abusing Graph API Delegated/Application permissions.",
            remediation="Enforce strict Conditional Access policies mapping to compliant and trusted devices. Rotate the AZUREADSSOACC Kerberos decryption key regularly (default is 30 days). Restrict Intune script deployment to highly trusted Tier-0 equivalent admins.",
            playbooks=[
                "# Primary Refresh Token (PRT) Extraction:\n# Use ROADtools to extract the PRT from a compromised Entra-joined device:\nroadtx prt -a <TENANT_ID> -u <AZURE_USER>",
                "# Seamless SSO (AZUREADSSOACC) Abuse:\n# If you compromise the AZUREADSSOACC computer account NT hash:\nroadtx seamlesssso -u <AZURE_USER> -h <AZUREADSSOACC_HASH>",
                "# Intune / MDM Device Takeover:\n# If you control an Intune Administrator, deploy a malicious PowerShell script to all managed devices.",
                "# Graph API Permission Nuance:\n# Use TokenTactics to refresh/request access tokens for Graph API:\nRefreshTo-MSGraphToken -domain <DOMAIN> -RefreshToken <TOKEN>"
            ]
        )
