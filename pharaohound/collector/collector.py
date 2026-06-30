#!/usr/bin/env python3
"""
collector.py — Main AD data collection orchestrator.

The ADCollector class coordinates LDAP enumeration of all AD object types,
manages the collection lifecycle, and outputs BloodHound-compatible JSON files.

Usage:
    collector = ADCollector(
        target="10.10.10.10",
        username="user",
        password="pass",
        domain="CORP.LOCAL",
    )
    collector.connect()
    collector.collect(method="All")
    # Files are saved to output_dir, prompts user to start analysis.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, List, Optional

from .enumerators import (
    ACLEnumerator,
    CertAuthorityEnumerator,
    CertTemplateEnumerator,
    ComputerEnumerator,
    ContainerEnumerator,
    DomainEnumerator,
    GPOEnumerator,
    GroupEnumerator,
    OUEnumerator,
    UserEnumerator,
)
from .ldap_client import LDAPClient
from .output import CollectionOutput
from .resolver import DNSResolver, SIDResolver
from ..theme import Colors


# COLLECTION METHODS
COLLECTION_METHODS = {
    "All": [
        "users", "groups", "computers", "domains", "gpos",
        "ous", "containers", "cas", "certtemplates", "acls",
    ],
    "Default": [
        "users", "groups", "computers", "domains", "gpos", "ous", "containers",
    ],
    "DCOnly": [
        "users", "groups", "computers", "domains",
    ],
    "ObjectProps": [
        "users", "groups", "computers",
    ],
    "Trusts": [
        "domains",
    ],
    "Container": [
        "ous", "containers", "gpos",
    ],
    "CertServices": [
        "cas", "certtemplates",
    ],
    "ACL": [
        "acls",
    ],
}


def _spinner_frames() -> List[str]:
    """Return animation frames for the collection spinner."""
    return ["☥ ⋯", "☥ ⋱", "☥ ⋰", "☥ ⋯"]


# AD COLLECTOR
class ADCollector:
    """
    Main orchestrator for LDAP-based Active Directory data collection.

    Coordinates LDAP connection, enumeration of all object types,
    and output to BloodHound-compatible JSON files.
    """

    def __init__(
        self,
        target: str,
        username: str = "",
        password: str = "",
        domain: str = "",
        port: Optional[int] = None,
        secure: bool = False,
        auth_method: str = "ntlm",
        dns_server: Optional[str] = None,
        output_dir: str = ".",
        use_zip: bool = True,
        timeout: int = 10,
    ) -> None:
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain.upper() if domain else ""
        self.auth_method = auth_method.lower()
        self.dns_server = dns_server
        self.output_dir = output_dir
        self.use_zip = use_zip

        # Initialize LDAP client
        self.client = LDAPClient(
            target=target,
            port=port,
            secure=secure,
            timeout=timeout,
            dns_server=dns_server,
        )

        # Resolvers
        self.sid_resolver = SIDResolver()
        self.dns_resolver = DNSResolver(dns_server)

        # Collection state
        self._connected = False
        self._collection_stats: Dict[str, int] = {}
        self._output: Optional[CollectionOutput] = None

    @property
    def connected(self) -> bool:
        return self._connected and self.client.connected

    @property
    def collection_stats(self) -> Dict[str, int]:
        return dict(self._collection_stats)

    def connect(self) -> bool:
        """
        Establish LDAP connection using the configured auth method.

        Returns True if connected successfully.
        """
        print(f"\n{Colors.GOLD}[☥] Connecting to {Colors.TURQUOISE}{self.target}{Colors.GOLD}…{Colors.RESET}")

        success = False

        if self.auth_method == "ntlm":
            if not self.domain or not self.username or not self.password:
                print(f"  {Colors.CARNELIAN}[✗] NTLM requires domain, username, and password.{Colors.RESET}")
                return False
            print(f"  {Colors.DIM}Auth: NTLM ({self.domain}\\{self.username}){Colors.RESET}")
            success = self.client.connect_ntlm(self.domain, self.username, self.password)

        elif self.auth_method == "simple":
            if not self.username or not self.password:
                print(f"  {Colors.CARNELIAN}[✗] Simple bind requires username (DN) and password.{Colors.RESET}")
                return False
            print(f"  {Colors.DIM}Auth: Simple bind ({self.username}){Colors.RESET}")
            success = self.client.connect_simple(self.username, self.password)

        elif self.auth_method == "kerberos":
            print(f"  {Colors.DIM}Auth: Kerberos (ccache){Colors.RESET}")
            success = self.client.connect_kerberos()

        else:
            print(f"  {Colors.CARNELIAN}[✗] Unknown auth method: {self.auth_method}{Colors.RESET}")
            return False

        if success:
            self._connected = True
            # Update domain info from LDAP
            if self.client.domain_name:
                self.domain = self.client.domain_name
            if self.client.domain_sid:
                self.sid_resolver.set_domain(self.client.domain_sid, self.domain)

            print(
                f"  {Colors.MALACHITE}[✓]{Colors.RESET} "
                f"Connected! Domain: {Colors.TURQUOISE}{self.domain}{Colors.RESET} "
                f"(SID: {Colors.DIM}{self.client.domain_sid}{Colors.RESET})"
            )
            print(
                f"  {Colors.DIM}  Base DN: {self.client.domain_dn}{Colors.RESET}"
            )
            print(
                f"  {Colors.DIM}  Config DN: {self.client.config_dn}{Colors.RESET}"
            )
        else:
            print(f"  {Colors.CARNELIAN}[✗] Connection failed.{Colors.RESET}")

        return success

    def disconnect(self) -> None:
        """Disconnect from the LDAP server."""
        self.client.disconnect()
        self._connected = False
        print(f"  {Colors.DIM}[☥] Disconnected.{Colors.RESET}")

    def collect(self, method: str = "All") -> Optional[str]:
        """
        Run the full collection pipeline.

        Args:
            method: Collection method — one of the keys in COLLECTION_METHODS.

        Returns:
            Path to the output directory or ZIP file.
        """
        if not self.connected:
            print(f"  {Colors.CARNELIAN}[✗] Not connected. Call connect() first.{Colors.RESET}")
            return None

        method = method.strip()
        # Find matching method (case-insensitive)
        matched_method = None
        for key in COLLECTION_METHODS:
            if key.lower() == method.lower():
                matched_method = key
                break
        if not matched_method:
            print(f"  {Colors.CARNELIAN}[✗] Unknown collection method: {method}{Colors.RESET}")
            print(f"  {Colors.DIM}Available: {', '.join(COLLECTION_METHODS.keys())}{Colors.RESET}")
            return None

        types_to_collect = COLLECTION_METHODS[matched_method]

        # Initialize output
        self._output = CollectionOutput(
            output_dir=self.output_dir,
            use_zip=self.use_zip,
            domain_name=self.domain,
        )

        print(
            f"\n{Colors.GOLD}{'═' * 65}{Colors.RESET}"
        )
        print(
            f"{Colors.GOLD}  ☥  PHARAOHOUND DATA COLLECTION{Colors.RESET}"
        )
        print(
            f"{Colors.GOLD}{'═' * 65}{Colors.RESET}"
        )
        print(
            f"  {Colors.DIM}Target:  {self.target}{Colors.RESET}"
        )
        print(
            f"  {Colors.DIM}Domain:  {self.domain}{Colors.RESET}"
        )
        print(
            f"  {Colors.DIM}Method:  {matched_method} ({', '.join(types_to_collect)}){Colors.RESET}"
        )
        print(
            f"  {Colors.DIM}Output:  {self.output_dir} ({'ZIP' if self.use_zip else 'Directory'}){Colors.RESET}\n"
        )

        start_time = time.time()

        # ── Enumerate each type ──────────────────────────────────────────────
        if "domains" in types_to_collect:
            self._collect_type("domains", DomainEnumerator)

        if "users" in types_to_collect:
            self._collect_type("users", UserEnumerator)

        if "groups" in types_to_collect:
            self._collect_type("groups", GroupEnumerator)

        if "computers" in types_to_collect:
            self._collect_type("computers", ComputerEnumerator)

        if "gpos" in types_to_collect:
            self._collect_type("gpos", GPOEnumerator)

        if "ous" in types_to_collect:
            self._collect_type("ous", OUEnumerator)

        if "containers" in types_to_collect:
            self._collect_type("containers", ContainerEnumerator)

        if "cas" in types_to_collect:
            self._collect_type("cas", CertAuthorityEnumerator)

        if "certtemplates" in types_to_collect:
            self._collect_type("certtemplates", CertTemplateEnumerator)

        # ACL enrichment (post-processing)
        if "acls" in types_to_collect:
            self._collect_acls()

        # ── Finalize output ──────────────────────────────────────────────────
        elapsed = time.time() - start_time
        result = self._output.finalize()

        print(
            f"\n{Colors.GOLD}{'═' * 65}{Colors.RESET}"
        )
        print(
            f"  {Colors.MALACHITE}[✓]{Colors.RESET} "
            f"Collection complete in {Colors.TURQUOISE}{elapsed:.1f}s{Colors.RESET}"
        )
        print(
            f"  {Colors.DIM}  Total objects: {self._output.total_objects}{Colors.RESET}"
        )
        print(
            f"  {Colors.DIM}  SID cache: {self.sid_resolver.cache_size} entries{Colors.RESET}"
        )
        print(
            f"{Colors.GOLD}{'═' * 65}{Colors.RESET}\n"
        )

        return result

    def _collect_type(self, data_type: str, enumerator_cls: type) -> None:
        """Run a single enumerator and save its output."""
        label = data_type.capitalize()
        sys.stdout.write(
            f"  {Colors.TURQUOISE}[⚱]{Colors.RESET} "
            f"Enumerating {label}… "
        )
        sys.stdout.flush()

        try:
            enumerator = enumerator_cls(self.client, self.sid_resolver)
            start = time.time()
            objects = enumerator.enumerate()
            elapsed = time.time() - start

            count = len(objects)
            self._collection_stats[data_type] = count

            # Clear the "Enumerating..." line
            sys.stdout.write(f"\r")
            sys.stdout.flush()

            if objects:
                self._output.write(data_type, objects)
                print(
                    f"  {Colors.MALACHITE}[✓]{Colors.RESET} "
                    f"{label}: {Colors.TURQUOISE}{count}{Colors.RESET} objects "
                    f"({elapsed:.1f}s)"
                )
            else:
                print(
                    f"  {Colors.DIM}[—]{Colors.RESET} "
                    f"{label}: 0 objects ({elapsed:.1f}s)"
                )

        except Exception as e:
            sys.stdout.write(f"\r")
            sys.stdout.flush()
            print(
                f"  {Colors.CARNELIAN}[✗]{Colors.RESET} "
                f"{label}: {type(e).__name__}: {e}"
            )

    def _collect_acls(self) -> None:
        """Run ACL enrichment pass on collected objects."""
        print(
            f"  {Colors.DIM}[—]{Colors.RESET} "
            f"ACL parsing: Security descriptor parsing queued (basic mode)"
        )
        # Full SD parsing is complex and will be enhanced incrementally.
        # The existing analyzer pipeline handles ACE-based analysis from
        # SharpHound data, so this is a future enhancement.
