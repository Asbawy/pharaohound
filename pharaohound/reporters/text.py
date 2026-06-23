#!/usr/bin/env python3
"""
reporters.text — Plain-text (ANSI-stripped) report writer.

Emits a self-contained .txt report suitable for archival / sharing in
ticketing systems. Format updated to be friendly to beginners.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List

from ..theme import Severity, SEVERITY_RANK

# ── Beginner-Friendly Glossary Database ──
GLOSSARY = {
    "Kerberoastable Users": {
        "concept": "Kerberoastable Users (SPN Accounts)",
        "explanation": "Active Directory accounts linked to specific services. Because they are service accounts, they are vulnerable to Kerberoasting.",
        "risk": "Attackers can request a security token for these accounts and attempt to guess the password offline on their own systems. If the password is weak, they will crack it and take over the service.",
        "fix": "Enforce long passwords (25+ characters) or transition to Group Managed Service Accounts (gMSAs)."
    },
    "AS-REP Roastable Users": {
        "concept": "AS-REP Roastable Users (No Pre-Authentication)",
        "explanation": "Accounts that don't require Kerberos pre-authentication when logging in.",
        "risk": "An attacker can ask the domain controller for an encrypted login credential package without knowing the password, then guess the password offline at very high speed.",
        "fix": "Ensure 'Do not require Kerberos preauthentication' is unchecked in Active Directory for all users."
    },
    "Dangerous ACL Permissions": {
        "concept": "Dangerous Access Control List (ACL) Permissions",
        "explanation": "Security configurations that grant one account direct control permissions (like GenericAll, WriteDacl, or WriteOwner) over another user or computer object.",
        "risk": "An attacker compromising the controlling account can directly force changes to the target object, such as resetting its password, writing malicious settings, or taking ownership.",
        "fix": "Audit and remove direct control permissions on sensitive objects and follow the least privilege model."
    },
    "Unconstrained Delegation": {
        "concept": "Unconstrained Delegation",
        "explanation": "Servers configured to allow unconstrained Kerberos delegation. They store the authentication ticket of any user who connects to them.",
        "risk": "If an attacker compromises this server, they can extract the cached login tickets (TGTs) of users (including administrators) who connected to the server, and masquerade as them across the network.",
        "fix": "Disable unconstrained delegation. Upgrade servers to use Constrained Delegation or Resource-Based Constrained Delegation."
    },
    "GPO Abuse Paths": {
        "concept": "Group Policy Object (GPO) Abuse",
        "explanation": "Policies that apply system configurations across the network, but have weak permissions that allow non-administrators to edit them.",
        "risk": "An attacker can modify the policy to push a malicious script or scheduled task. The script runs as 'SYSTEM' on all computers affected by the policy on the next automatic refresh.",
        "fix": "Ensure write access to Group Policies is restricted only to authorized Domain Administrators."
    },
    "LAPS Password Readers": {
        "concept": "LAPS (Local Administrator Password Solution) Readers",
        "explanation": "The Microsoft LAPS solution stores computer local admin passwords in Active Directory attributes. Weak permissions allow non-admins to read these values.",
        "risk": "An attacker can read the password in cleartext from Active Directory and log in to that computer as local Administrator.",
        "fix": "Remove permissions for 'Authenticated Users' or non-admin groups to read the 'ms-Mcs-AdmPwd' attribute."
    },
    "DCSync Rights": {
        "concept": "DCSync Replication Rights",
        "explanation": "Permissions that allow an account to pretend to be a Domain Controller and sync database information.",
        "risk": "An attacker with these rights can sync the password hashes of all domain users (including Domain Admins and the KRBTGT master key) from the active Domain Controller, taking over the entire domain.",
        "fix": "Restrict Directory Replication permissions only to actual Domain Controllers."
    },
    "Shadow Credentials Opportunities": {
        "concept": "Shadow Credentials",
        "explanation": "Vulnerabilities where an account has rights to write key credential attributes (like msDS-KeyCredentialLink) on another user or computer.",
        "risk": "An attacker writes their own public key to the target object and authenticates as them using certificates, taking over the account without resetting the password.",
        "fix": "Audit and restrict write rights on user and computer objects."
    },
    "Self-Add to Group Escalation": {
        "concept": "Self-Add to Group Escalation",
        "explanation": "Active Directory configuration issue where a user, group, or computer holds write permissions (like AddMember, GenericAll, GenericWrite, or WriteDacl) over a group they are not currently a member of.",
        "risk": "An attacker compromising the privileged account can add themselves or another account they control directly to the target group, gaining all the rights and access of that group (such as Domain Admins or Account Operators).",
        "fix": "Remove membership write permissions from non-administrative principals on group objects and enforce least privilege."
    },
    "Machine Account Quota Abuse": {
        "concept": "Machine Account Quota (MAQ)",
        "explanation": "A domain-wide setting that controls how many computer accounts a regular user can create. The Windows default is 10.",
        "risk": "Any authenticated domain user can create fake computer accounts, then use those accounts to set up a delegation attack (called RBCD) that allows them to impersonate Domain Admins on target servers.",
        "fix": "Set ms-DS-MachineAccountQuota to 0 so regular users cannot create computer accounts. Only Domain Admins should create machine accounts."
    },
    "gMSA Password Readers": {
        "concept": "Group Managed Service Account (gMSA) Password Readers",
        "explanation": "Windows-managed service accounts (gMSAs) have extremely strong auto-rotated passwords. However, certain accounts are configured to read those passwords from Active Directory.",
        "risk": "An attacker compromising an account that can read a gMSA password can extract the password hash and log in as the service account, which often has elevated domain privileges.",
        "fix": "Audit PrincipalsAllowedToRetrieveManagedPassword on every gMSA. Restrict read access to only the specific servers running the service."
    }
}


def _strip_ansi(text: str) -> str:
    import re
    return re.sub(r"\033\[[0-9;]*m", "", text)


def _format_item(item: Dict[str, Any]) -> str:
    # Trust relationships
    if "direction" in item and "source" in item and "target" in item:
        trans = "Transitive" if item.get("transitive") else "Non-transitive"
        sf = "SID Filtering: Enabled" if item.get("sid_filtering") else "SID Filtering: DISABLED"
        return f"{item['direction']} Trust: {item['source']} -> {item['target']} ({trans}, {sf})"
    
    # Machine Account Quota
    if "machine_account_quota" in item:
        return f"Domain: {item.get('domain')} [ms-DS-MachineAccountQuota = {item['machine_account_quota']}]"

    # Pre-Windows 2000 Compatible Access
    if "member" in item and "group" in item:
        return f"Member: {item['member']} ({item.get('member_type', 'unknown')}) -> Group: {item['group']}"

    # SID History
    if "extra_sids" in item:
        sids = ", ".join(item["extra_sids"][:3])
        if len(item["extra_sids"]) > 3:
            sids += f" and {len(item['extra_sids']) - 3} more"
        return f"User: {item.get('name')} [SID History: {sids}]"

    # AD CS misconfigurations
    if "esc" in item:
        esc = item.get("esc")
        tpl = item.get("template")
        ca = item.get("ca")
        container = item.get("container")
        enrollers = item.get("enrollers")
        principal = item.get("principal")
        right = item.get("right")
        computer = item.get("computer")
        
        detail = []
        if tpl:
            detail.append(f"Template: {tpl}")
        if ca:
            detail.append(f"CA: {ca}")
        if container:
            detail.append(f"Container: {container}")
        if computer:
            detail.append(f"DC: {computer}")
        if enrollers:
            detail.append(f"Enrollers: {', '.join(enrollers)}")
        if principal:
            detail.append(f"Principal: {principal}")
        if right:
            detail.append(f"Right: {right}")
        return f"[{esc}] " + " | ".join(detail)

    # Constrained Delegation
    if "delegation_targets" in item:
        targets_str = ", ".join(item["delegation_targets"][:3])
        if len(item["delegation_targets"]) > 3:
            targets_str += f" and {len(item['delegation_targets']) - 3} more"
        auth = " (with Protocol Transition)" if item.get("trusted_to_auth") else " (no Protocol Transition)"
        return f"{item.get('type', 'Principal')}: {item.get('name')}{auth} -> Targets: {targets_str}"

    # GPO Abuse linked to high-value OUs / Direct write
    if item.get("kind") == "linked_to_high_value_ou":
        return f"GPO: {item.get('gpo')} linked to High-Value OU: {item.get('ou')}"
    if item.get("kind") == "direct_write":
        return f"Attacker: {item.get('attacker')} has {item.get('right')} on GPO: {item.get('gpo')}"

    # gMSA Password Readers
    if "gmsa_account" in item:
        return f"Reader: {item.get('reader')} has {item.get('right')} on gMSA: {item.get('gmsa_account')}"

    # Fallback parts-based formatter
    parts = []
    for k in ("name", "user", "principal", "attacker", "reader", "account"):
        if k in item:
            parts.append(str(item[k]))
            break
    for k in ("computer", "target", "target_computer", "group", "gpo", "ou", "source_object"):
        if k in item:
            parts.append(f"-> {item[k]}")
            break
    if "right" in item:
        parts.append(f"[{item['right']}]")
    if "spns" in item and item["spns"]:
        parts.append(f"SPNs: {', '.join(item['spns'][:3])}")
    if "pwd_age_days" in item:
        parts.append(f"pwd_age={item['pwd_age_days']}d")
    if "os" in item:
        parts.append(f"OS={item['os']}")
    if "known_threats" in item:
        parts.append(f"({item['known_threats']})")
    if "in_high_value_group" in item and item["in_high_value_group"]:
        parts.append("[HIGH-VALUE]")
    return " ".join(parts) if parts else str(item)


def generate_text_report(
    filepath: str,
    stats: Dict[str, int],
    domain: str,
    findings: List[Dict[str, Any]],
    attack_paths: List[Dict[str, Any]],
    recommendations: List[Dict[str, Any]],
) -> str:
    lines: List[str] = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Cover ──
    lines.append("=" * 100)
    lines.append(" " * 40 + "PHARAOHOUND REPORT")
    lines.append("=" * 100)
    lines.append(f"Report Generated: {now}")
    lines.append(f"Domain Analyzed:  {domain}")
    lines.append(f"Tool Version:     1.0.0")
    lines.append("")

    # ── Stats ──
    lines.append("-" * 100)
    lines.append("  DOMAIN STATISTICS")
    lines.append("-" * 100)
    for k, v in stats.items():
        lines.append(f"  {k.capitalize():<15}: {v}")
    lines.append("")

    # ── Risk ──
    crit = sum(1 for f in findings if f["severity"] == Severity.CRITICAL)
    high = sum(1 for f in findings if f["severity"] == Severity.HIGH)
    med = sum(1 for f in findings if f["severity"] == Severity.MEDIUM)
    low = sum(1 for f in findings if f["severity"] == Severity.LOW)
    if crit > 5:
        risk = "CRITICAL — Domain is highly vulnerable"
    elif crit > 0:
        risk = "HIGH — Multiple critical paths to Domain Admin"
    elif high > 3:
        risk = "MEDIUM — Several high-risk findings"
    else:
        risk = "LOW — Relatively secure"

    lines.append("-" * 100)
    lines.append("  RISK ASSESSMENT")
    lines.append("-" * 100)
    lines.append(f"  Overall Domain Security Status: {risk}")
    lines.append(f"  Total Critical Risks: {crit}  |  High Risks: {high}  |  Medium Risks: {med}  |  Low Risks: {low}")
    lines.append("")

    # ── Findings ──
    lines.append("=" * 100)
    lines.append("  FINDINGS & VULNERABILITIES")
    lines.append("=" * 100)
    lines.append("")
    for f in sorted(findings, key=lambda x: SEVERITY_RANK.get(x["severity"], 99)):
        title = f['title']
        lines.append(f"  [{f['severity']}] {title.upper()}")
        lines.append(f"      Description:  {f['summary']}")
        
        # Insert beginner explanation if available
        if title in GLOSSARY:
            g = GLOSSARY[title]
            lines.append("")
            lines.append(f"      💡 What is this? (For Beginners):")
            lines.append(f"         {g['explanation']}")
            lines.append(f"      💥 What is the risk? (How it is abused):")
            lines.append(f"         {g['risk']}")
            lines.append(f"      🔧 How to fix this? (For Administrators):")
            lines.append(f"         {g['fix']}")
            lines.append("")

        if f.get("recommendation"):
            lines.append(f"      Immediate Action: {f['recommendation']}")
        if f.get("remediation"):
            lines.append(f"      Long-term Fix:    {f['remediation']}")
        if f.get("playbooks"):
            lines.append("      Admin Tool Blueprint (Examples):")
            for cmd in f["playbooks"]:
                lines.append(f"        $ {cmd}")
        if f.get("data"):
            lines.append(f"      Vulnerable Items ({len(f['data'])} items):")
            for i, item in enumerate(f["data"][:15], 1):
                lines.append(f"        {i}. {_format_item(item)}")
            if len(f["data"]) > 15:
                lines.append(f"        ... and {len(f['data']) - 15} more (see interactive HTML report)")
        lines.append("-" * 80)
        lines.append("")

    # ── Attack Paths ──
    lines.append("=" * 100)
    lines.append("  VULNERABILITY ATTACK CHAINS")
    lines.append("=" * 100)
    lines.append("")
    if not attack_paths:
        lines.append("  No clear attack paths detected.")
    for i, p in enumerate(attack_paths, 1):
        opsec = p.get('opsec_label', '')
        lines.append(f"  [Chain #{i}] [{p['severity']}] {p['name']}  [OpSec: {opsec}]")
        lines.append(f"      How it works: {p['summary']}")
        if p.get("prerequisites"):
            lines.append(f"      Prerequisites needed: {', '.join(p['prerequisites'])}")
        if p.get("tools"):
            lines.append(f"      Tools used by attackers: {', '.join(p['tools'])}")
        if p.get("detection_events"):
            lines.append(f"      ⚠ SOC Detection (Event IDs): {', '.join(p['detection_events'])}")
        lines.append("      Step-by-step Attack Steps:")
        for step in p["steps"]:
            for line in step.split("\n"):
                lines.append(f"        {line}")
        lines.append("")

    # ── Recommendations ──
    lines.append("=" * 100)
    lines.append("  PRIORITIZED REMEDIATION ACTIONS")
    lines.append("=" * 100)
    lines.append("")
    for r in recommendations:
        opsec = r.get('opsec_label', '')
        lines.append(f"  [Priority #{r['priority']}] [{r['severity']}] {r['title']}  [OpSec: {opsec}]")
        lines.append(f"      Vulnerable Condition: {r['action']}")
        lines.append(f"      Action Command:       {r['command']}")
        for alt in r.get("alt_commands", []):
            lines.append(f"      Alternative Command:  {alt}")
        if r.get("detection_events"):
            lines.append(f"      ⚠ SOC Detection (Event IDs): {', '.join(r['detection_events'])}")
        if r.get("defender_action"):
            lines.append(f"      Defender Action Item: {r['defender_action']}")
        lines.append("")

    lines.append("=" * 100)
    lines.append("  End of report.")
    lines.append("=" * 100)

    text = "\n".join(lines)
    text = _strip_ansi(text)

    # Write to file
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(text)
    return filepath
