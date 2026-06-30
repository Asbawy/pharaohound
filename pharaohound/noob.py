#!/usr/bin/env python3
"""
noob.py — "Pentest Noob" mode simplification engine.

When --noob is active, this module transforms Pharaohound output into
a drastically simplified format aimed at junior operators or clients:

  - Jargon is translated into plain "Step 1 → Step 2" instructions
  - Only CRITICAL/HIGH findings are shown
  - Data items are capped to prevent information overload
  - Attack paths are reduced to the single best path per type
  - Recommendations show only the single most reliable command
"""

from __future__ import annotations

from typing import Any, Dict, List

from .theme import Severity


# JARGON TRANSLATIONS — AD terms → plain English step-by-step
JARGON: Dict[str, Dict[str, str]] = {
    "Kerberoastable Users": {
        "what": "Service accounts with guessable passwords",
        "steps": (
            "Step 1: Run a tool to request an encrypted password file from Active Directory for this service account.\n"
            "Step 2: Use a password cracking program to guess the password offline (this is not detectable).\n"
            "Step 3: If the password is weak, you now have full access to this service account."
        ),
    },
    "AS-REP Roastable Users": {
        "what": "Accounts with a security setting turned off",
        "steps": (
            "Step 1: Send a special login request to the domain controller for this user (no password needed).\n"
            "Step 2: The domain controller replies with encrypted data that contains the password.\n"
            "Step 3: Crack the password offline. You don't even need a foothold to start this attack."
        ),
    },
    "Dangerous ACL Permissions": {
        "what": "Accounts that have excessive control over other accounts",
        "steps": (
            "Step 1: Find an account that has full control (like a master key) over another account.\n"
            "Step 2: Use that control to reset the target's password, or write a backdoor credential.\n"
            "Step 3: Log in as the target account with the new password."
        ),
    },
    "Shadow Credentials Opportunities": {
        "what": "Backdoor login using certificates (no password change needed)",
        "steps": (
            "Step 1: Write a special certificate credential to the target account (silent — no password is changed).\n"
            "Step 2: Use the certificate to log in as the target.\n"
            "Step 3: You now have the target's full access without anyone noticing a password reset."
        ),
    },
    "DCSync Rights": {
        "what": "Permission to copy every password in the entire network",
        "steps": (
            "Step 1: Run a single command to download every user's password hash from the domain controller.\n"
            "Step 2: Extract the special 'krbtgt' master key.\n"
            "Step 3: With the master key, you can create fake admin tickets that work forever."
        ),
    },
    "Unconstrained Delegation": {
        "what": "Servers that store admin login tickets in memory",
        "steps": (
            "Step 1: Get access to this server.\n"
            "Step 2: Trick the domain controller into sending its login ticket to this server.\n"
            "Step 3: Grab the ticket from memory and use it to become a domain controller yourself."
        ),
    },
    "GPO Abuse Paths": {
        "what": "Network policies you can edit to run code on many computers",
        "steps": (
            "Step 1: Edit the policy to include a malicious script or program.\n"
            "Step 2: Wait up to 90 minutes for computers to automatically download the policy.\n"
            "Step 3: Your code runs as SYSTEM (full admin) on every computer affected by the policy."
        ),
    },
    "LAPS Password Readers": {
        "what": "Ability to read the local admin password of computers",
        "steps": (
            "Step 1: Read the local administrator password stored in Active Directory.\n"
            "Step 2: Use the password to log in as local admin on that computer.\n"
            "Step 3: Once on the computer, look for cached domain admin credentials."
        ),
    },
    "Self-Add to Group Escalation": {
        "what": "Permission to add yourself to a powerful admin group",
        "steps": (
            "Step 1: You have permission to modify the membership of a group you are not in.\n"
            "Step 2: Add your own account to that group (e.g., Domain Admins).\n"
            "Step 3: Log out and log back in — you now have admin privileges."
        ),
    },
    "Machine Account Quota Abuse": {
        "what": "Anyone can create fake computer accounts in the network",
        "steps": (
            "Step 1: Create a new fake computer account in the domain (default allows up to 10).\n"
            "Step 2: Use the fake computer to set up a trust delegation attack (RBCD).\n"
            "Step 3: Impersonate a Domain Admin to access any target server."
        ),
    },
    "gMSA Password Readers": {
        "what": "Ability to read service account passwords managed by Windows",
        "steps": (
            "Step 1: Read the automatically-managed password of a service account.\n"
            "Step 2: Use the password hash to authenticate as that service account.\n"
            "Step 3: The service account often has elevated privileges in the domain."
        ),
    },
    "AD CS Misconfigurations": {
        "what": "Certificate settings that let anyone become Domain Admin using certificates",
        "steps": (
            "Step 1: Request a special certificate from the company's certificate server.\n"
            "Step 2: The certificate is misconfigured — you can put 'Administrator' as the identity.\n"
            "Step 3: Use the certificate to log in as Domain Admin — no password needed, very stealthy."
        ),
    },
}


def simplify_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Noob mode finding filter:
      - Keep only CRITICAL and HIGH severity
      - Cap data items at 3
      - Replace ELI5 with jargon translation
      - Add noob_mode flag
    """
    simplified = []
    for f in findings:
        if f.get("severity") not in (Severity.CRITICAL, Severity.HIGH):
            continue

        f = dict(f)  # shallow copy
        f["noob_mode"] = True

        title = f.get("title", "")
        if title in JARGON:
            j = JARGON[title]
            f["eli5"] = f"🐣 WHAT IS THIS: {j['what']}\n\n{j['steps']}"
            f["summary"] = j["what"]

        # Cap data items
        if f.get("data") and len(f["data"]) > 3:
            total = len(f["data"])
            f["data"] = f["data"][:3]
            f["summary"] += f" ({total} total — showing top 3)"

        # Single best playbook
        if f.get("playbooks") and len(f["playbooks"]) > 1:
            f["playbooks"] = [f["playbooks"][0]]

        simplified.append(f)

    return simplified


def simplify_paths(paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Noob mode path filter:
      - Keep only the single best (stealthiest) path per path-type prefix
      - Mark with noob_mode flag
    """
    seen_types: set = set()
    simplified = []
    for p in paths:
        # Classify by the prefix before ":"
        path_type = p["name"].split(":")[0].strip() if ":" in p["name"] else p["name"]
        if path_type in seen_types:
            continue
        seen_types.add(path_type)

        p = dict(p)
        p["noob_mode"] = True
        simplified.append(p)

    return simplified


def simplify_recommendations(recs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Noob mode recommendation filter:
      - Keep only priority 1–3 items
      - Remove alt_commands (show only the single best command)
      - Mark with noob_mode flag
    """
    simplified = []
    for r in recs:
        if r.get("priority", 99) > 3:
            continue
        r = dict(r)
        r["noob_mode"] = True
        r["alt_commands"] = []  # single command only
        simplified.append(r)

    return simplified
