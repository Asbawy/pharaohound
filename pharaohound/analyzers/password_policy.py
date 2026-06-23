#!/usr/bin/env python3
"""Password policy / weak password indicators."""

from __future__ import annotations
from typing import Optional

from ..models import ObjectStore, calculate_password_age
from ..theme import Severity
from .base import BaseAnalyzer, Finding


class PasswordPolicyAnalyzer(BaseAnalyzer):
    name = "password_policy"
    description = "Analyze password age indicators"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        old_passwords = []
        never_changed = []
        for user in store.iter_by_type("user"):
            if not user.enabled:
                continue
            pwd_age = calculate_password_age(user.extras.get("pwdlastset", 0))
            if pwd_age >= 99999:
                never_changed.append({
                    "name": user.name,
                    "sid": user.sid,
                    "severity": Severity.LOW,
                })
            elif pwd_age > 365:
                old_passwords.append({
                    "name": user.name,
                    "sid": user.sid,
                    "pwd_age_days": pwd_age,
                    "severity": Severity.MEDIUM,
                })

        findings = []
        if old_passwords:
            findings.append(Finding(
                title="Old Passwords (>365 days)",
                summary=f"Found {len(old_passwords)} accounts with passwords older than 1 year",
                severity=Severity.MEDIUM,
                data=old_passwords[:200],
                recommendation="Force password rotation. Old passwords are more likely cracked or in breach DBs.",
                eli5=(
                    "PASSWORD AGE > 365 DAYS means the user hasn't rotated their password in a year. "
                    "The longer a password lives, the more time an attacker has to crack it (offline), "
                    "phish it, or find it in a breach dump. NIST 800-63B actually says rotation can "
                    "hurt — but if rotation is mandatory in your org, enforce it sanely (e.g. annual "
                    "for users, much more frequent for service accounts). For service accounts, switch "
                    "to gMSAs."
                ),
                remediation="Enforce sane password rotation. Use gMSAs for service accounts. Audit pwdLastSet on a schedule.",
                playbooks=[
                    "# Identify stale passwords via PowerView\nGet-DomainUser -LDAPFilter '(pwdLastSet>=1)' | Select-Object name, @{Name='pwdAgeDays';Expression={[int]((Get-Date) - [datetime]::FromFileTime($_.pwdLastSet)).TotalDays}} | Sort-Object pwdAgeDays -Descending | Select -First 30",
                ],
            ))
        if never_changed:
            findings.append(Finding(
                title="Never-Changed Passwords",
                summary=f"Found {len(never_changed)} accounts whose password has never been set (pwdLastSet=0)",
                severity=Severity.LOW,
                data=never_changed[:200],
                recommendation="Investigate — usually default / service accounts that need rotation.",
                eli5=(
                    "PWDLASTSET = 0 means the user's password has never been set, or has been "
                    "explicitly reset to 'must change at next logon' and never changed. Common on "
                    "forgotten service accounts, default accounts, and stale test accounts. These "
                    "are prime targets because the password is often the original default."
                ),
                remediation="Audit pwdLastSet=0 accounts. Disable unused. Force reset on others.",
                playbooks=[
                    "Get-DomainUser -LDAPFilter '(pwdLastSet=0)' | Select-Object name, samaccountname, whencreated",
                ],
            ))

        if not findings:
            return None
        # Return the most-severe one as the "primary" finding; the engine handles multi
        return sorted(findings, key=lambda f: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(f.severity, 4))[0]
