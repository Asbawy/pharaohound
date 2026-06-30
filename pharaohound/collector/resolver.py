#!/usr/bin/env python3
"""
resolver.py — SID and DNS resolution utilities for the collector.

Provides:
  - Well-known SID → name mapping (built-in SIDs like S-1-5-18, S-1-5-32-544, etc.)
  - SID cache for resolving SIDs to names during enumeration.
  - DNS resolution helper for computer hostnames.
"""

from __future__ import annotations

import socket
from typing import Dict, Optional


# WELL-KNOWN SIDS
WELL_KNOWN_SIDS: Dict[str, str] = {
    "S-1-0-0": "Nobody",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-8": "Proxy",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-13": "Terminal Server Users",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "Local System",
    "S-1-5-19": "Local Service",
    "S-1-5-20": "Network Service",
    # Builtin domain groups (S-1-5-32-xxx)
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "S-1-5-32-554": "Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "Remote Desktop Users",
    "S-1-5-32-556": "Network Configuration Operators",
    "S-1-5-32-557": "Incoming Forest Trust Builders",
    "S-1-5-32-558": "Performance Monitor Users",
    "S-1-5-32-559": "Performance Log Users",
    "S-1-5-32-560": "Windows Authorization Access Group",
    "S-1-5-32-561": "Terminal Server License Servers",
    "S-1-5-32-562": "Distributed COM Users",
    "S-1-5-32-568": "IIS_IUSRS",
    "S-1-5-32-569": "Cryptographic Operators",
    "S-1-5-32-573": "Event Log Readers",
    "S-1-5-32-574": "Certificate Service DCOM Access",
    "S-1-5-32-575": "RDS Remote Access Servers",
    "S-1-5-32-576": "RDS Endpoint Servers",
    "S-1-5-32-577": "RDS Management Servers",
    "S-1-5-32-578": "Hyper-V Administrators",
    "S-1-5-32-579": "Access Control Assistance Operators",
    "S-1-5-32-580": "Remote Management Users",
    "S-1-5-32-582": "Storage Replica Administrators",
}

# Domain-relative RID → name for common domain groups
DOMAIN_RIDS: Dict[int, str] = {
    500: "Administrator",
    501: "Guest",
    502: "krbtgt",
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    521: "Read-Only Domain Controllers",
    522: "Cloneable Domain Controllers",
    525: "Protected Users",
    526: "Key Admins",
    527: "Enterprise Key Admins",
    553: "RAS and IAS Servers",
    571: "Allowed RODC Password Replication Group",
    572: "Denied RODC Password Replication Group",
}


class SIDResolver:
    """
    Cache-backed SID-to-name resolver.

    Resolves well-known SIDs instantly and caches LDAP-resolved SIDs
    to avoid redundant queries during enumeration.
    """

    def __init__(self, domain_sid: str = "", domain_name: str = "") -> None:
        self.domain_sid = domain_sid
        self.domain_name = domain_name.upper()
        self._cache: Dict[str, str] = {}

        # Pre-populate with well-known SIDs
        for sid, name in WELL_KNOWN_SIDS.items():
            self._cache[sid] = name

    def set_domain(self, domain_sid: str, domain_name: str) -> None:
        """Set the domain SID and name, and pre-populate domain-relative RIDs."""
        self.domain_sid = domain_sid
        self.domain_name = domain_name.upper()
        for rid, name in DOMAIN_RIDS.items():
            full_sid = f"{domain_sid}-{rid}"
            self._cache[full_sid] = f"{name}@{self.domain_name}"

    def resolve(self, sid: str) -> Optional[str]:
        """Resolve a SID to a name, returning None if unknown."""
        return self._cache.get(sid)

    def cache(self, sid: str, name: str) -> None:
        """Cache a SID → name mapping."""
        if sid and name:
            self._cache[sid] = name

    def cache_bulk(self, mappings: Dict[str, str]) -> None:
        """Cache multiple SID → name mappings at once."""
        for sid, name in mappings.items():
            if sid and name:
                self._cache[sid] = name

    @property
    def cache_size(self) -> int:
        return len(self._cache)


class DNSResolver:
    """
    DNS resolution helper for computer hostnames.

    Supports custom DNS server or system default.
    """

    def __init__(self, dns_server: Optional[str] = None) -> None:
        self.dns_server = dns_server
        self._cache: Dict[str, str] = {}
        self._dns_available = False

        if dns_server:
            try:
                import dns.resolver as dns_resolver  # type: ignore
                self._resolver = dns_resolver.Resolver()
                self._resolver.nameservers = [dns_server]
                self._resolver.timeout = 3
                self._resolver.lifetime = 5
                self._dns_available = True
            except ImportError:
                self._resolver = None
        else:
            self._resolver = None

    def resolve(self, hostname: str) -> Optional[str]:
        """Resolve a hostname to an IP address."""
        if hostname in self._cache:
            return self._cache[hostname]

        ip = None

        # Try dnspython first if available and configured
        if self._dns_available and self._resolver:
            try:
                import dns.resolver as dns_resolver  # type: ignore
                answers = self._resolver.resolve(hostname, "A")
                if answers:
                    ip = str(answers[0])
            except Exception:
                pass

        # Fallback to system resolver
        if not ip:
            try:
                ip = socket.gethostbyname(hostname)
            except socket.gaierror:
                pass

        if ip:
            self._cache[hostname] = ip
        return ip

    @property
    def cache_size(self) -> int:
        return len(self._cache)
