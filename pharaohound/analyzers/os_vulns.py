#!/usr/bin/env python3
"""Outdated/vulnerable OS versions."""

from __future__ import annotations
from typing import Optional

from ..models import ObjectStore
from ..theme import Severity
from .base import BaseAnalyzer, Finding


# Mapping of OS name fragments to severity & known CVEs
VULN_OS_PATTERNS = [
    ("Windows Server 2003", Severity.CRITICAL, "MS08-067 (Conficker), EOL since 2015"),
    ("Windows Server 2008", Severity.HIGH, "EOL since 2020; BlueKeep (CVE-2019-0708) if RDP exposed"),
    ("Windows Server 2012", Severity.MEDIUM, "EOL October 2023; patch PetitPotam / PrintNightmare"),
    ("Windows XP",          Severity.CRITICAL, "MS08-067, EternalBlue, EOL since 2014"),
    ("Windows 7",           Severity.HIGH, "EOL since 2020; EternalBlue if SMB1 exposed"),
    ("Windows 8",           Severity.MEDIUM, "EOL since 2016; general exposure"),
    ("Windows Vista",       Severity.CRITICAL, "EOL since 2017; multiple unpatched vulns"),
    ("Windows 2000",        Severity.CRITICAL, "EOL since 2010; treat as fully owned"),
]


class OSVulnerabilitiesAnalyzer(BaseAnalyzer):
    name = "computer_os_vulnerabilities"
    description = "Identify computers with outdated/vulnerable OS versions"

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        data = []
        for comp in store.iter_by_type("computer"):
            os_name = comp.extras.get("os", "Unknown") or "Unknown"
            for pattern, sev, notes in VULN_OS_PATTERNS:
                if pattern.lower() in os_name.lower():
                    data.append({
                        "computer": comp.name,
                        "computer_sid": comp.sid,
                        "os": os_name,
                        "known_threats": notes,
                        "severity": sev,
                    })
                    break
        if not data:
            return None

        return Finding(
            title="Outdated Operating Systems",
            summary=f"Found {len(data)} computers running outdated/vulnerable OS versions",
            severity=Severity.HIGH,
            data=data,
            recommendation="Decommission or upgrade. Apply security patches immediately.",
            eli5=(
                "OUTDATED OS means the computer is running a Windows version past end-of-life "
                "(no security patches) or with known unpatched vulnerabilities (EternalBlue, "
                "BlueKeep, PetitPotam, PrintNightmare, Zerologon, etc.). A single unpatched box "
                "is often the cheapest foothold into a domain — attackers will scan for these "
                "first. Defender priorities: (1) decommission EOL systems, (2) isolate those that "
                "must stay (VLAN/segmentation), (3) patch Internet-exposed EOL systems "
                "*immediately*."
            ),
            remediation=(
                "Inventory all OS versions. Upgrade or decommission EOL hosts. For EOL hosts "
                "that must stay, isolate on a quarantine VLAN and apply mitigations (disable "
                "SMB1, RDP NLA, firewall). Track via Defender for Endpoint / Lansweeper / "
                "similar."
            ),
            playbooks=[
                "# Check for EternalBlue (CVE-2017-0144)\ncrackmapexec smb <TARGET_SUBNET> -u '' -p '' -M ms17-010",
                "# BlueKeep scanner\nrdpscan <TARGET_HOST>",
                "# Zerologon (CVE-2020-1472)\npython3 zerologon_tester.py <NETBIOS_NAME> <DC_IP>",
                "# PetitPotam (CVE-2021-36942)\npython3 PetitPotam.py -u '' -p '' <LISTENER> <DC_IP>",
            ],
        )
