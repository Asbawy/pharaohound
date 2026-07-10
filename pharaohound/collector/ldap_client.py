#!/usr/bin/env python3
"""
ldap_client.py — LDAP connection management for Pharaohound collector.

Provides a unified LDAP client that supports:
  - NTLM authentication (DOMAIN\\user + password)
  - Simple bind (user DN + password)
  - Kerberos authentication (uses existing ccache/TGT)
  - SSL/STARTTLS connections
  - Custom DNS server for DC discovery
  - Automatic domain/naming context detection
"""

from __future__ import annotations

import ssl
import os
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from ..theme import Colors

try:
    from ldap3 import (  # type: ignore
        ALL,
        ALL_ATTRIBUTES,
        ALL_OPERATIONAL_ATTRIBUTES,
        AUTO_BIND_NO_TLS,
        AUTO_BIND_TLS_BEFORE_BIND,
        ANONYMOUS,
        Connection,
        KERBEROS,
        NTLM,
        SASL,
        Server,
        SIMPLE,
        SUBTREE,
        Tls,
    )
    _HAVE_LDAP3 = True
except ImportError:
    _HAVE_LDAP3 = False


# LDAP ATTRIBUTE LISTS
# Attributes requested per object type to minimize query payload.

USER_ATTRIBUTES = [
    "objectSid", "sAMAccountName", "distinguishedName", "cn", "name",
    "userAccountControl", "userPrincipalName", "memberOf", "primaryGroupID",
    "servicePrincipalName", "adminCount", "description", "displayName",
    "mail", "title", "department", "pwdLastSet", "lastLogonTimestamp",
    "lastLogon", "whenCreated", "whenChanged", "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity", "sIDHistory",
    "msDS-GroupMSAMembership", "objectClass", "nTSecurityDescriptor",
]

GROUP_ATTRIBUTES = [
    "objectSid", "sAMAccountName", "distinguishedName", "cn", "name",
    "member", "memberOf", "adminCount", "description", "groupType",
    "objectClass", "nTSecurityDescriptor", "whenCreated", "whenChanged",
]

COMPUTER_ATTRIBUTES = [
    "objectSid", "sAMAccountName", "distinguishedName", "cn", "name",
    "dNSHostName", "operatingSystem", "operatingSystemVersion",
    "operatingSystemServicePack", "userAccountControl", "primaryGroupID",
    "servicePrincipalName", "memberOf", "adminCount", "lastLogonTimestamp",
    "lastLogon", "whenCreated", "whenChanged", "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
    "msLAPS-Password", "msLAPS-PasswordExpirationTime",
    "objectClass", "nTSecurityDescriptor",
]

DOMAIN_ATTRIBUTES = [
    "objectSid", "distinguishedName", "name", "dc",
    "msDS-Behavior-Version", "ms-DS-MachineAccountQuota",
    "objectClass", "nTSecurityDescriptor",
    "whenCreated", "whenChanged",
]

GPO_ATTRIBUTES = [
    "objectSid", "distinguishedName", "cn", "name", "displayName",
    "gPCFileSysPath", "gPCFunctionalityVersion",
    "objectClass", "nTSecurityDescriptor", "whenCreated", "whenChanged",
]

OU_ATTRIBUTES = [
    "objectSid", "distinguishedName", "name", "ou", "description",
    "gPLink", "gPOptions",
    "objectClass", "nTSecurityDescriptor", "whenCreated", "whenChanged",
]

CONTAINER_ATTRIBUTES = [
    "objectSid", "distinguishedName", "name", "cn", "description",
    "objectClass", "nTSecurityDescriptor", "whenCreated", "whenChanged",
]

CERTTEMPLATE_ATTRIBUTES = [
    "objectSid", "distinguishedName", "cn", "name", "displayName",
    "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
    "msPKI-Private-Key-Flag", "msPKI-RA-Signature",
    "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy",
    "pKIExpirationPeriod", "pKIOverlapPeriod",
    "msPKI-Template-Schema-Version", "msPKI-Minimal-Key-Size",
    "objectClass", "nTSecurityDescriptor", "whenCreated", "whenChanged",
]

CA_ATTRIBUTES = [
    "objectSid", "distinguishedName", "cn", "name", "displayName",
    "dNSHostName", "certificateTemplates", "cACertificate",
    "objectClass", "nTSecurityDescriptor", "whenCreated", "whenChanged",
]

TRUST_ATTRIBUTES = [
    "objectSid", "distinguishedName", "cn", "name",
    "trustPartner", "trustDirection", "trustType", "trustAttributes",
    "flatName", "securityIdentifier",
    "objectClass", "whenCreated", "whenChanged",
]


# USER-ACCOUNT-CONTROL FLAGS
UAC_FLAGS = {
    0x0002: "ACCOUNTDISABLE",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x0200: "NORMAL_ACCOUNT",
    0x0800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x1000: "WORKSTATION_TRUST_ACCOUNT",
    0x2000: "SERVER_TRUST_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x20000: "MNS_LOGON_ACCOUNT",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x200000: "USE_DES_KEY_ONLY",
    0x400000: "DONT_REQ_PREAUTH",
    0x800000: "PASSWORD_EXPIRED",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x4000000: "PARTIAL_SECRETS_ACCOUNT",
}


def parse_uac(uac_value: int) -> Dict[str, bool]:
    """Parse a userAccountControl integer into a dict of flag booleans."""
    return {
        "enabled": not bool(uac_value & 0x0002),
        "password_not_required": bool(uac_value & 0x0020),
        "normal_account": bool(uac_value & 0x0200),
        "dont_expire_password": bool(uac_value & 0x10000),
        "trusted_for_delegation": bool(uac_value & 0x80000),  # unconstrained
        "not_delegated": bool(uac_value & 0x100000),
        "use_des_key_only": bool(uac_value & 0x200000),
        "dont_req_preauth": bool(uac_value & 0x400000),
        "trusted_to_auth_for_delegation": bool(uac_value & 0x1000000),
        "server_trust_account": bool(uac_value & 0x2000),
        "workstation_trust_account": bool(uac_value & 0x1000),
    }


# LDAP CLIENT
class LDAPClient:
    """
    Unified LDAP client for Active Directory enumeration.

    Supports NTLM, simple bind, and Kerberos authentication.
    Handles connection lifecycle, paged queries, and error recovery.
    """

    def __init__(
        self,
        target: str,
        port: Optional[int] = None,
        secure: bool = False,
        timeout: int = 10,
        page_size: int = 1000,
        dns_server: Optional[str] = None,
    ) -> None:
        if not _HAVE_LDAP3:
            raise ImportError(
                "The 'ldap3' package is required for data collection. "
                "Install it with: pip install ldap3"
            )

        self.target = target
        self.secure = secure
        self.timeout = timeout
        self.page_size = page_size
        self.dns_server = dns_server

        # Determine port
        if port:
            self.port = port
        elif secure:
            self.port = 636
        else:
            self.port = 389

        self._server: Optional[Any] = None
        self._conn: Optional[Any] = None
        self._domain_dn: str = ""
        self._domain_name: str = ""
        self._domain_sid: str = ""
        self._config_dn: str = ""
        self._schema_dn: str = ""

    @property
    def domain_dn(self) -> str:
        return self._domain_dn

    @property
    def domain_name(self) -> str:
        return self._domain_name

    @property
    def domain_sid(self) -> str:
        return self._domain_sid

    @property
    def config_dn(self) -> str:
        return self._config_dn

    @property
    def schema_dn(self) -> str:
        return self._schema_dn

    @property
    def connected(self) -> bool:
        return self._conn is not None and self._conn.bound

    def connect_ntlm(self, domain: str, username: str, password: str) -> bool:
        """Connect using NTLM authentication."""
        try:
            tls_config = None
            if self.secure:
                tls_config = Tls(validate=ssl.CERT_NONE)

            self._server = Server(
                self.target,
                port=self.port,
                use_ssl=self.secure,
                tls=tls_config,
                get_info=ALL,
                connect_timeout=self.timeout,
            )

            # NTLM requires the NetBIOS domain name, not the FQDN.
            # Strip everything after the first dot (HERCULES.HTB → HERCULES).
            netbios_domain = domain.split(".")[0].upper()
            ntlm_user = f"{netbios_domain}\\{username}"
            self._conn = Connection(
                self._server,
                user=ntlm_user,
                password=password,
                authentication=NTLM,
                auto_bind=True,
                receive_timeout=self.timeout,
            )

            self._detect_naming_contexts()
            return True

        except Exception as e:
            print(f"  {Colors.CARNELIAN}[✗] NTLM bind failed: {e}{Colors.RESET}")
            return False

    def connect_simple(self, bind_dn: str, password: str) -> bool:
        """Connect using simple bind."""
        try:
            tls_config = None
            if self.secure:
                tls_config = Tls(validate=ssl.CERT_NONE)

            self._server = Server(
                self.target,
                port=self.port,
                use_ssl=self.secure,
                tls=tls_config,
                get_info=ALL,
                connect_timeout=self.timeout,
            )

            self._conn = Connection(
                self._server,
                user=bind_dn,
                password=password,
                authentication=SIMPLE,
                auto_bind=True,
                receive_timeout=self.timeout,
            )

            self._detect_naming_contexts()
            return True

        except Exception as e:
            print(f"  {Colors.CARNELIAN}[✗] Simple bind failed: {e}{Colors.RESET}")
            return False

    def connect_kerberos(self) -> bool:
        """Connect using Kerberos authentication (requires valid TGT in ccache)."""
        try:
            tls_config = None
            if self.secure:
                tls_config = Tls(validate=ssl.CERT_NONE)

            self._server = Server(
                self.target,
                port=self.port,
                use_ssl=self.secure,
                tls=tls_config,
                get_info=ALL,
                connect_timeout=self.timeout,
            )

            self._conn = Connection(
                self._server,
                authentication=SASL,
                sasl_mechanism=KERBEROS,
                auto_bind=True,
                receive_timeout=self.timeout,
            )

            self._detect_naming_contexts()
            return True

        except Exception as e:
            print(f"  {Colors.CARNELIAN}[✗] Kerberos bind failed: {e}{Colors.RESET}")
            return False

    def connect_kerberos_with_password(
        self, domain: str, username: str, password: str, dc_host: str, kdc_host: Optional[str] = None
    ) -> bool:
        """
        Connect using Kerberos by programmatically obtaining a TGT.

        Uses impacket to get a TGT with the provided credentials, saves it
        to a ccache file, then binds to LDAP via SASL/Kerberos. This mirrors
        how bloodhound-python authenticates and works in environments where
        NTLM is restricted.

        Args:
            domain:   AD domain name (e.g., 'hercules.htb')
            username: Username (e.g., 'natalie.a')
            password: Password
            dc_host:  DC FQDN (e.g., 'dc.hercules.htb') — required for SPN
            kdc_host: KDC IP address (optional, defaults to self.target)
        """
        # Check impacket availability
        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT  # type: ignore
            from impacket.krb5.types import Principal  # type: ignore
            from impacket.krb5 import constants as krb5_constants  # type: ignore
            from impacket.krb5.ccache import CCache  # type: ignore
        except ImportError:
            print(
                f"  {Colors.OCHRE}[!] impacket is not installed — Kerberos fallback unavailable.{Colors.RESET}\n"
                f"  {Colors.DIM}    Install with: pip install impacket{Colors.RESET}"
            )
            return False

        try:
            # 1. Get TGT using impacket
            domain_upper = domain.upper()
            user_principal = Principal(
                username, type=krb5_constants.PrincipalNameType.NT_PRINCIPAL.value
            )

            print(f"  {Colors.DIM}  Getting TGT for {username}@{domain_upper}…{Colors.RESET}")
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                user_principal,
                password,
                domain_upper,
                lmhash=b"",
                nthash=b"",
                aesKey=None,
                kdcHost=kdc_host or self.target,
            )

            # 2. Save TGT to ccache file
            ccache = CCache()
            ccache.fromTGT(tgt, oldSessionKey, sessionKey)
            ccache_file = tempfile.mktemp(suffix=".ccache", prefix="pharaohound_")
            ccache.saveFile(ccache_file)
            self._ccache_file = ccache_file

            # 3. Set KRB5CCNAME so GSSAPI/ldap3 can find the ticket
            os.environ["KRB5CCNAME"] = f"FILE:{ccache_file}"
            print(f"  {Colors.DIM}  TGT obtained, connecting to {dc_host}…{Colors.RESET}")

            # 4. Connect to LDAP using the DC hostname (required for SPN matching)
            tls_config = None
            if self.secure:
                tls_config = Tls(validate=ssl.CERT_NONE)

            self._server = Server(
                dc_host,
                port=self.port,
                use_ssl=self.secure,
                tls=tls_config,
                get_info=ALL,
                connect_timeout=self.timeout,
            )

            self._conn = Connection(
                self._server,
                authentication=SASL,
                sasl_mechanism=KERBEROS,
                auto_bind=True,
                receive_timeout=self.timeout,
            )

            self._detect_naming_contexts()
            return True

        except Exception as e:
            print(f"  {Colors.CARNELIAN}[✗] Kerberos (TGT) bind failed: {e}{Colors.RESET}")
            return False

    def disconnect(self) -> None:
        """Close the LDAP connection and clean up credentials."""
        if self._conn:
            try:
                self._conn.unbind()
            except Exception:
                pass
            self._conn = None
        self._server = None

        # Clean up ccache file if we created one
        ccache_file = getattr(self, "_ccache_file", None)
        if ccache_file:
            try:
                os.remove(ccache_file)
            except OSError:
                pass
            self._ccache_file = None

    def _detect_naming_contexts(self) -> None:
        """Auto-detect domain DN, configuration DN, etc. from RootDSE."""
        if not self._server or not self._server.info:
            return

        info = self._server.info

        # Default naming context = domain DN
        if hasattr(info, "other") and "defaultNamingContext" in info.other:
            self._domain_dn = info.other["defaultNamingContext"][0]
        elif hasattr(info, "naming_contexts") and info.naming_contexts:
            # Pick the shortest one that doesn't start with CN=Configuration
            candidates = [
                nc for nc in info.naming_contexts
                if not nc.upper().startswith("CN=CONFIGURATION")
                and not nc.upper().startswith("CN=SCHEMA")
                and not nc.upper().startswith("DC=DOMAINDNSZONES")
                and not nc.upper().startswith("DC=FORESTDNSZONES")
            ]
            if candidates:
                self._domain_dn = min(candidates, key=len)

        # Configuration naming context
        if hasattr(info, "other") and "configurationNamingContext" in info.other:
            self._config_dn = info.other["configurationNamingContext"][0]
        else:
            # Construct from domain DN
            parts = self._domain_dn.split(",")
            forest_parts = [p for p in parts if p.upper().startswith("DC=")]
            if forest_parts:
                self._config_dn = "CN=Configuration," + ",".join(forest_parts)

        # Schema naming context
        if hasattr(info, "other") and "schemaNamingContext" in info.other:
            self._schema_dn = info.other["schemaNamingContext"][0]
        else:
            self._schema_dn = f"CN=Schema,{self._config_dn}"

        # Derive domain name from DN (DC=corp,DC=local → CORP.LOCAL)
        dc_parts = []
        for part in self._domain_dn.split(","):
            part = part.strip()
            if part.upper().startswith("DC="):
                dc_parts.append(part[3:])
        self._domain_name = ".".join(dc_parts).upper()

        # Query for domain SID
        self._query_domain_sid()

    def _query_domain_sid(self) -> None:
        """Query the domain object to get its SID."""
        if not self._conn or not self._domain_dn:
            return
        try:
            self._conn.search(
                search_base=self._domain_dn,
                search_filter="(objectClass=domain)",
                search_scope="BASE",
                attributes=["objectSid"],
            )
            if self._conn.entries:
                sid_raw = self._conn.entries[0]["objectSid"].value
                if isinstance(sid_raw, bytes):
                    self._domain_sid = _sid_bytes_to_string(sid_raw)
                elif isinstance(sid_raw, str):
                    self._domain_sid = sid_raw
        except Exception:
            pass

    def paged_search(
        self,
        search_base: str,
        search_filter: str,
        attributes: List[str],
        search_scope: str = "SUBTREE",
        controls: Optional[List] = None,
    ) -> List[Any]:
        """
        Execute a paged LDAP search and return all entries.

        Uses the Simple Paged Results control (RFC 2696) to handle
        large result sets without hitting server-side size limits.
        """
        if not self._conn:
            return []

        scope_map = {
            "BASE": "BASE",
            "LEVEL": "LEVEL",
            "SUBTREE": "SUBTREE",
        }
        scope = scope_map.get(search_scope.upper(), "SUBTREE")

        all_entries = []
        try:
            # Use ldap3's built-in paged search
            entry_generator = self._conn.extend.standard.paged_search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=scope,
                attributes=attributes,
                paged_size=self.page_size,
                generator=True,
                controls=controls,
            )

            for entry in entry_generator:
                if entry.get("type") == "searchResEntry":
                    all_entries.append(entry)

        except Exception as e:
            print(f"  {Colors.OCHRE}[!] Paged search error: {e}{Colors.RESET}")

        return all_entries

    def search(
        self,
        search_base: str,
        search_filter: str,
        attributes: List[str],
        search_scope: str = "SUBTREE",
    ) -> List[Any]:
        """Execute a single (non-paged) LDAP search."""
        if not self._conn:
            return []

        try:
            self._conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=search_scope,
                attributes=attributes,
            )
            return list(self._conn.entries)
        except Exception as e:
            print(f"  {Colors.OCHRE}[!] Search error: {e}{Colors.RESET}")
            return []


# SID BINARY PARSER
def _sid_bytes_to_string(sid_bytes: bytes) -> str:
    """Convert a binary SID (from LDAP) to its string representation (S-1-5-...)."""
    if not sid_bytes or len(sid_bytes) < 8:
        return ""

    revision = sid_bytes[0]
    sub_authority_count = sid_bytes[1]
    authority = int.from_bytes(sid_bytes[2:8], byteorder="big")

    sub_authorities = []
    for i in range(sub_authority_count):
        offset = 8 + (i * 4)
        if offset + 4 <= len(sid_bytes):
            sub_auth = int.from_bytes(sid_bytes[offset:offset + 4], byteorder="little")
            sub_authorities.append(str(sub_auth))

    return f"S-{revision}-{authority}-" + "-".join(sub_authorities)


def sid_string_to_bytes(sid_string: str) -> bytes:
    """Convert a SID string (S-1-5-...) to its binary representation."""
    parts = sid_string.split("-")
    if len(parts) < 3 or parts[0] != "S":
        return b""

    revision = int(parts[1])
    authority = int(parts[2])
    sub_authorities = [int(p) for p in parts[3:]]

    sid = bytearray()
    sid.append(revision)
    sid.append(len(sub_authorities))
    sid.extend(authority.to_bytes(6, byteorder="big"))
    for sa in sub_authorities:
        sid.extend(sa.to_bytes(4, byteorder="little"))

    return bytes(sid)
