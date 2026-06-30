#!/usr/bin/env python3
"""
enumerators.py — LDAP query classes for each AD object type.

Each enumerator queries Active Directory via the LDAPClient and transforms
the raw LDAP entries into BloodHound-compatible JSON dictionaries that match
the SharpHound v2/v5 schema exactly — so the existing Pharaohound parsers
can ingest them without modification.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .ldap_client import (
    LDAPClient,
    CA_ATTRIBUTES,
    CERTTEMPLATE_ATTRIBUTES,
    COMPUTER_ATTRIBUTES,
    CONTAINER_ATTRIBUTES,
    DOMAIN_ATTRIBUTES,
    GPO_ATTRIBUTES,
    GROUP_ATTRIBUTES,
    OU_ATTRIBUTES,
    TRUST_ATTRIBUTES,
    USER_ATTRIBUTES,
    parse_uac,
    _sid_bytes_to_string,
)
from .resolver import SIDResolver
from ..theme import Colors


# HELPERS
def _get_attr(entry: dict, attr: str, default: Any = None) -> Any:
    """Safely get an attribute from an LDAP entry dict."""
    attrs = entry.get("attributes", {})
    val = attrs.get(attr, default)
    if val is None:
        return default
    return val


def _get_attr_str(entry: dict, attr: str, default: str = "") -> str:
    val = _get_attr(entry, attr)
    if val is None:
        return default
    if isinstance(val, list):
        return str(val[0]) if val else default
    return str(val)


def _get_attr_int(entry: dict, attr: str, default: int = 0) -> int:
    val = _get_attr(entry, attr)
    if val is None:
        return default
    try:
        if isinstance(val, list):
            return int(val[0]) if val else default
        return int(val)
    except (ValueError, TypeError):
        return default


def _get_attr_bool(entry: dict, attr: str, default: bool = False) -> bool:
    val = _get_attr(entry, attr)
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return bool(val)


def _get_attr_list(entry: dict, attr: str) -> List[Any]:
    val = _get_attr(entry, attr)
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


def _get_sid(entry: dict) -> str:
    """Extract SID as string from an LDAP entry."""
    sid_raw = _get_attr(entry, "objectSid")
    if sid_raw is None:
        return ""
    if isinstance(sid_raw, bytes):
        return _sid_bytes_to_string(sid_raw)
    if isinstance(sid_raw, list):
        for item in sid_raw:
            if isinstance(item, bytes):
                return _sid_bytes_to_string(item)
            if isinstance(item, str) and item.startswith("S-"):
                return item
    if isinstance(sid_raw, str):
        return sid_raw
    return ""


def _filetime_to_epoch(filetime: int) -> int:
    """Convert Windows FILETIME (100ns since 1601) to Unix epoch seconds."""
    if not filetime or filetime <= 0:
        return 0
    try:
        return int(filetime / 10_000_000 - 11_644_473_600)
    except (ValueError, OverflowError):
        return 0


def _datetime_to_epoch(dt: Any) -> int:
    """Convert a datetime object to Unix epoch seconds."""
    if dt is None:
        return 0
    if isinstance(dt, datetime):
        try:
            return int(dt.replace(tzinfo=timezone.utc).timestamp())
        except (ValueError, OverflowError):
            return 0
    if isinstance(dt, (int, float)):
        return int(dt)
    return 0


def _parse_gplink(gplink_str: str) -> List[Dict[str, Any]]:
    """
    Parse a gPLink attribute value like:
    [LDAP://cn={GUID},cn=policies,cn=system,DC=...;0]
    into a list of {GUID, IsEnforced} dicts.
    """
    if not gplink_str:
        return []
    links = []
    # Split on ][
    parts = gplink_str.replace("[", "").split("]")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        # Format: LDAP://CN={GUID},...;status
        if ";" in part:
            dn_part, status = part.rsplit(";", 1)
        else:
            dn_part = part
            status = "0"
        # Extract the DN
        dn = dn_part.replace("LDAP://", "").replace("ldap://", "")
        # Extract GUID from DN
        guid = ""
        for component in dn.split(","):
            component = component.strip()
            if component.upper().startswith("CN={"):
                guid = component[3:]  # {GUID}
                break
        if dn:
            links.append({
                "GUID": guid,
                "DN": dn,
                "IsEnforced": status.strip() == "2",
            })
    return links


# BASE ENUMERATOR
class BaseEnumerator:
    """Base class for all AD object enumerators."""

    def __init__(self, client: LDAPClient, resolver: SIDResolver) -> None:
        self.client = client
        self.resolver = resolver
        self.domain_name = client.domain_name
        self.domain_dn = client.domain_dn

    def enumerate(self) -> List[Dict[str, Any]]:
        """Override in subclasses to enumerate objects."""
        raise NotImplementedError


# USER ENUMERATOR
class UserEnumerator(BaseEnumerator):
    """Enumerate all user objects from Active Directory."""

    def enumerate(self) -> List[Dict[str, Any]]:
        entries = self.client.paged_search(
            search_base=self.domain_dn,
            search_filter="(&(objectCategory=person)(objectClass=user))",
            attributes=USER_ATTRIBUTES,
        )

        results = []
        for entry in entries:
            obj = self._transform(entry)
            if obj:
                results.append(obj)
                # Cache SID → name
                sid = obj.get("ObjectIdentifier", "")
                name = obj.get("Properties", {}).get("name", "")
                if sid and name:
                    self.resolver.cache(sid, name)

        return results

    def _transform(self, entry: dict) -> Optional[Dict[str, Any]]:
        """Transform an LDAP user entry to BloodHound JSON format."""
        sid = _get_sid(entry)
        if not sid:
            return None

        sam = _get_attr_str(entry, "sAMAccountName")
        name = f"{sam}@{self.domain_name}" if sam else sid
        uac = _get_attr_int(entry, "userAccountControl", 0x200)
        uac_flags = parse_uac(uac)

        spns = _get_attr_list(entry, "servicePrincipalName")
        pwd_last_set = _get_attr(entry, "pwdLastSet")
        last_logon = _get_attr(entry, "lastLogonTimestamp") or _get_attr(entry, "lastLogon")

        # Convert datetime objects or FILETIME integers
        if isinstance(pwd_last_set, datetime):
            pwd_last_set = _datetime_to_epoch(pwd_last_set)
        elif isinstance(pwd_last_set, int):
            pwd_last_set = _filetime_to_epoch(pwd_last_set)
        else:
            pwd_last_set = 0

        if isinstance(last_logon, datetime):
            last_logon = _datetime_to_epoch(last_logon)
        elif isinstance(last_logon, int):
            last_logon = _filetime_to_epoch(last_logon)
        else:
            last_logon = 0

        allowed_to_delegate = _get_attr_list(entry, "msDS-AllowedToDelegateTo")
        sid_history_raw = _get_attr_list(entry, "sIDHistory")
        sid_history = []
        for sh in sid_history_raw:
            if isinstance(sh, bytes):
                sid_history.append({"ObjectIdentifier": _sid_bytes_to_string(sh), "ObjectType": "User"})
            elif isinstance(sh, str):
                sid_history.append({"ObjectIdentifier": sh, "ObjectType": "User"})

        primary_group_id = _get_attr_int(entry, "primaryGroupID", 513)
        primary_group_sid = f"{self.client.domain_sid}-{primary_group_id}" if self.client.domain_sid else ""

        properties = {
            "name": name,
            "domain": self.domain_name,
            "objectid": sid,
            "distinguishedname": _get_attr_str(entry, "distinguishedName"),
            "description": _get_attr_str(entry, "description"),
            "displayname": _get_attr_str(entry, "displayName"),
            "email": _get_attr_str(entry, "mail"),
            "title": _get_attr_str(entry, "title"),
            "enabled": uac_flags["enabled"],
            "admincount": _get_attr_bool(entry, "adminCount"),
            "hasspn": bool(spns),
            "serviceprincipalnames": spns,
            "dontreqpreauth": uac_flags["dont_req_preauth"],
            "unconstraineddelegation": uac_flags["trusted_for_delegation"],
            "trustedtoauth": uac_flags["trusted_to_auth_for_delegation"],
            "passwordnotreqd": uac_flags["password_not_required"],
            "pwdlastset": pwd_last_set,
            "lastlogon": last_logon,
            "pwdneverexpires": uac_flags["dont_expire_password"],
            "highvalue": False,
        }

        return {
            "ObjectIdentifier": sid,
            "Properties": properties,
            "Aces": [],
            "AllowedToDelegate": allowed_to_delegate,
            "HasSIDHistory": sid_history,
            "PrimaryGroupSID": primary_group_sid,
            "SPNTargets": [],
        }


# GROUP ENUMERATOR
class GroupEnumerator(BaseEnumerator):
    """Enumerate all group objects from Active Directory."""

    def enumerate(self) -> List[Dict[str, Any]]:
        entries = self.client.paged_search(
            search_base=self.domain_dn,
            search_filter="(objectClass=group)",
            attributes=GROUP_ATTRIBUTES,
        )

        results = []
        for entry in entries:
            obj = self._transform(entry)
            if obj:
                results.append(obj)
                sid = obj.get("ObjectIdentifier", "")
                name = obj.get("Properties", {}).get("name", "")
                if sid and name:
                    self.resolver.cache(sid, name)

        return results

    def _transform(self, entry: dict) -> Optional[Dict[str, Any]]:
        sid = _get_sid(entry)
        if not sid:
            return None

        sam = _get_attr_str(entry, "sAMAccountName")
        name = f"{sam}@{self.domain_name}" if sam else sid

        # Parse group members
        member_dns = _get_attr_list(entry, "member")
        members = []
        for dn in member_dns:
            if isinstance(dn, str):
                members.append({
                    "ObjectIdentifier": dn,
                    "ObjectType": "Unknown",
                })

        group_type = _get_attr_int(entry, "groupType", 0)
        is_security = bool(group_type & 0x80000000) if group_type else True

        # Detect high-value groups
        from ..models import is_high_value_group_name
        highvalue = is_high_value_group_name(name)

        properties = {
            "name": name,
            "domain": self.domain_name,
            "objectid": sid,
            "distinguishedname": _get_attr_str(entry, "distinguishedName"),
            "description": _get_attr_str(entry, "description"),
            "admincount": _get_attr_bool(entry, "adminCount"),
            "highvalue": highvalue,
        }

        return {
            "ObjectIdentifier": sid,
            "Properties": properties,
            "Aces": [],
            "Members": members,
        }


# COMPUTER ENUMERATOR
class ComputerEnumerator(BaseEnumerator):
    """Enumerate all computer objects from Active Directory."""

    def enumerate(self) -> List[Dict[str, Any]]:
        entries = self.client.paged_search(
            search_base=self.domain_dn,
            search_filter="(objectClass=computer)",
            attributes=COMPUTER_ATTRIBUTES,
        )

        results = []
        for entry in entries:
            obj = self._transform(entry)
            if obj:
                results.append(obj)
                sid = obj.get("ObjectIdentifier", "")
                name = obj.get("Properties", {}).get("name", "")
                if sid and name:
                    self.resolver.cache(sid, name)

        return results

    def _transform(self, entry: dict) -> Optional[Dict[str, Any]]:
        sid = _get_sid(entry)
        if not sid:
            return None

        sam = _get_attr_str(entry, "sAMAccountName").rstrip("$")
        dns_name = _get_attr_str(entry, "dNSHostName")
        name = f"{sam}.{self.domain_name}" if sam else (dns_name or sid)
        name = name.upper()

        uac = _get_attr_int(entry, "userAccountControl", 0x1000)
        uac_flags = parse_uac(uac)

        os_name = _get_attr_str(entry, "operatingSystem", "Unknown")
        os_version = _get_attr_str(entry, "operatingSystemVersion")
        os_sp = _get_attr_str(entry, "operatingSystemServicePack")

        allowed_to_delegate = _get_attr_list(entry, "msDS-AllowedToDelegateTo")

        # Check for LAPS
        has_laps = bool(
            _get_attr(entry, "ms-Mcs-AdmPwd")
            or _get_attr(entry, "msLAPS-Password")
            or _get_attr(entry, "ms-Mcs-AdmPwdExpirationTime")
            or _get_attr(entry, "msLAPS-PasswordExpirationTime")
        )

        primary_group_id = _get_attr_int(entry, "primaryGroupID", 515)
        primary_group_sid = f"{self.client.domain_sid}-{primary_group_id}" if self.client.domain_sid else ""

        last_logon = _get_attr(entry, "lastLogonTimestamp") or _get_attr(entry, "lastLogon")
        if isinstance(last_logon, datetime):
            last_logon = _datetime_to_epoch(last_logon)
        elif isinstance(last_logon, int):
            last_logon = _filetime_to_epoch(last_logon)
        else:
            last_logon = 0

        properties = {
            "name": name,
            "domain": self.domain_name,
            "objectid": sid,
            "distinguishedname": _get_attr_str(entry, "distinguishedName"),
            "operatingsystem": os_name,
            "operatingsystemversion": os_version,
            "operatingsystemservicepack": os_sp,
            "enabled": uac_flags["enabled"],
            "admincount": _get_attr_bool(entry, "adminCount"),
            "unconstraineddelegation": uac_flags["trusted_for_delegation"],
            "trustedtoauth": uac_flags["trusted_to_auth_for_delegation"],
            "haslaps": has_laps,
            "lastlogon": last_logon,
            "highvalue": False,
        }

        return {
            "ObjectIdentifier": sid,
            "Properties": properties,
            "Aces": [],
            "AllowedToDelegate": allowed_to_delegate,
            "AllowedToAct": [],
            "Sessions": [],
            "LocalAdmins": [],
            "RemoteDesktopUsers": [],
            "DcomUsers": [],
            "PSRemoteUsers": [],
            "PrimaryGroupSID": primary_group_sid,
        }


# DOMAIN ENUMERATOR
class DomainEnumerator(BaseEnumerator):
    """Enumerate domain head objects."""

    def enumerate(self) -> List[Dict[str, Any]]:
        entries = self.client.search(
            search_base=self.domain_dn,
            search_filter="(objectClass=domain)",
            attributes=DOMAIN_ATTRIBUTES,
            search_scope="BASE",
        )

        results = []
        # Process entries from ldap3 Entry objects
        if entries:
            obj = self._transform_entry(entries[0])
            if obj:
                results.append(obj)

        # Enumerate trusts
        trust_entries = self.client.paged_search(
            search_base=f"CN=System,{self.domain_dn}",
            search_filter="(objectClass=trustedDomain)",
            attributes=TRUST_ATTRIBUTES,
        )

        inbound = []
        outbound = []
        for te in trust_entries:
            trust = self._transform_trust(te)
            if trust:
                direction = trust.get("TrustDirection", 0)
                if direction in (1, 3):  # Inbound or Bidirectional
                    inbound.append(trust)
                if direction in (2, 3):  # Outbound or Bidirectional
                    outbound.append(trust)

        if results:
            results[0]["InboundTrusts"] = inbound
            results[0]["OutboundTrusts"] = outbound

        return results

    def _transform_entry(self, entry: Any) -> Optional[Dict[str, Any]]:
        """Transform from ldap3 Entry object."""
        sid = ""
        if hasattr(entry, "objectSid") and entry.objectSid.value:
            sid_val = entry.objectSid.value
            if isinstance(sid_val, bytes):
                sid = _sid_bytes_to_string(sid_val)
            else:
                sid = str(sid_val)

        if not sid:
            sid = self.client.domain_sid

        name = self.domain_name

        maq = 0
        try:
            maq = int(entry["ms-DS-MachineAccountQuota"].value or 0)
        except Exception:
            pass

        func_level = 0
        try:
            func_level = int(entry["msDS-Behavior-Version"].value or 0)
        except Exception:
            pass

        properties = {
            "name": name,
            "domain": self.domain_name,
            "objectid": sid,
            "distinguishedname": str(entry.entry_dn),
            "functionallevel": func_level,
            "ms-ds-machineaccountquota": maq,
            "highvalue": True,
        }

        return {
            "ObjectIdentifier": sid,
            "Properties": properties,
            "Aces": [],
            "ChildObjects": [],
            "InboundTrusts": [],
            "OutboundTrusts": [],
        }

    def _transform_trust(self, entry: dict) -> Optional[Dict[str, Any]]:
        trust_partner = _get_attr_str(entry, "trustPartner")
        trust_direction = _get_attr_int(entry, "trustDirection", 0)
        trust_type = _get_attr_int(entry, "trustType", 0)
        trust_attrs = _get_attr_int(entry, "trustAttributes", 0)

        sid_raw = _get_attr(entry, "securityIdentifier")
        target_sid = ""
        if isinstance(sid_raw, bytes):
            target_sid = _sid_bytes_to_string(sid_raw)
        elif isinstance(sid_raw, list) and sid_raw:
            if isinstance(sid_raw[0], bytes):
                target_sid = _sid_bytes_to_string(sid_raw[0])
            else:
                target_sid = str(sid_raw[0])
        elif isinstance(sid_raw, str):
            target_sid = sid_raw

        # Trust direction: 0=Disabled, 1=Inbound, 2=Outbound, 3=Bidirectional
        is_transitive = not bool(trust_attrs & 0x1)  # TRUST_ATTRIBUTE_NON_TRANSITIVE

        return {
            "TargetDomainName": trust_partner.upper(),
            "TargetDomainSid": target_sid,
            "TrustDirection": trust_direction,
            "TrustType": trust_type,
            "IsTransitive": is_transitive,
            "SidFilteringEnabled": bool(trust_attrs & 0x4),
        }


# GPO ENUMERATOR
class GPOEnumerator(BaseEnumerator):
    """Enumerate Group Policy Objects."""

    def enumerate(self) -> List[Dict[str, Any]]:
        entries = self.client.paged_search(
            search_base=self.domain_dn,
            search_filter="(objectClass=groupPolicyContainer)",
            attributes=GPO_ATTRIBUTES,
        )

        results = []
        for entry in entries:
            obj = self._transform(entry)
            if obj:
                results.append(obj)

        return results

    def _transform(self, entry: dict) -> Optional[Dict[str, Any]]:
        dn = _get_attr_str(entry, "distinguishedName")
        cn = _get_attr_str(entry, "cn")
        display_name = _get_attr_str(entry, "displayName") or cn
        gpc_path = _get_attr_str(entry, "gPCFileSysPath")

        # Use CN (GUID) as the identifier
        object_id = cn or dn

        properties = {
            "name": f"{display_name}@{self.domain_name}",
            "domain": self.domain_name,
            "objectid": object_id,
            "distinguishedname": dn,
            "displayname": display_name,
            "gpcpath": gpc_path,
            "highvalue": False,
        }

        return {
            "ObjectIdentifier": object_id,
            "Properties": properties,
            "Aces": [],
        }


# OU ENUMERATOR
class OUEnumerator(BaseEnumerator):
    """Enumerate Organizational Units."""

    def enumerate(self) -> List[Dict[str, Any]]:
        entries = self.client.paged_search(
            search_base=self.domain_dn,
            search_filter="(objectClass=organizationalUnit)",
            attributes=OU_ATTRIBUTES,
        )

        results = []
        for entry in entries:
            obj = self._transform(entry)
            if obj:
                results.append(obj)

        return results

    def _transform(self, entry: dict) -> Optional[Dict[str, Any]]:
        dn = _get_attr_str(entry, "distinguishedName")
        name = _get_attr_str(entry, "name") or _get_attr_str(entry, "ou")
        sid = _get_sid(entry) or dn

        gplink_raw = _get_attr_str(entry, "gPLink")
        gplinks = _parse_gplink(gplink_raw)

        properties = {
            "name": f"{name}@{self.domain_name}",
            "domain": self.domain_name,
            "objectid": sid,
            "distinguishedname": dn,
            "description": _get_attr_str(entry, "description"),
            "highvalue": False,
        }

        return {
            "ObjectIdentifier": sid,
            "Properties": properties,
            "Aces": [],
            "ChildObjects": [],
            "GPLink": gplinks,
        }


# CONTAINER ENUMERATOR
class ContainerEnumerator(BaseEnumerator):
    """Enumerate Container objects."""

    def enumerate(self) -> List[Dict[str, Any]]:
        entries = self.client.paged_search(
            search_base=self.domain_dn,
            search_filter="(objectClass=container)",
            attributes=CONTAINER_ATTRIBUTES,
        )

        results = []
        for entry in entries:
            obj = self._transform(entry)
            if obj:
                results.append(obj)

        return results

    def _transform(self, entry: dict) -> Optional[Dict[str, Any]]:
        dn = _get_attr_str(entry, "distinguishedName")
        name = _get_attr_str(entry, "name") or _get_attr_str(entry, "cn")
        sid = _get_sid(entry) or dn

        properties = {
            "name": f"{name}@{self.domain_name}",
            "domain": self.domain_name,
            "objectid": sid,
            "distinguishedname": dn,
            "description": _get_attr_str(entry, "description"),
            "highvalue": False,
        }

        return {
            "ObjectIdentifier": sid,
            "Properties": properties,
            "Aces": [],
            "ChildObjects": [],
        }


# CERTIFICATE AUTHORITY ENUMERATOR
class CertAuthorityEnumerator(BaseEnumerator):
    """Enumerate AD CS Certificate Authority objects from the PKI container."""

    def enumerate(self) -> List[Dict[str, Any]]:
        # CAs are stored under CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,...
        pki_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{self.client.config_dn}"

        entries = self.client.paged_search(
            search_base=pki_base,
            search_filter="(objectClass=pKIEnrollmentService)",
            attributes=CA_ATTRIBUTES,
        )

        results = []
        for entry in entries:
            obj = self._transform(entry)
            if obj:
                results.append(obj)

        return results

    def _transform(self, entry: dict) -> Optional[Dict[str, Any]]:
        dn = _get_attr_str(entry, "distinguishedName")
        name = _get_attr_str(entry, "name") or _get_attr_str(entry, "cn")
        sid = _get_sid(entry) or dn
        dns_name = _get_attr_str(entry, "dNSHostName")
        cert_templates = _get_attr_list(entry, "certificateTemplates")

        properties = {
            "name": f"{name}@{self.domain_name}",
            "domain": self.domain_name,
            "objectid": sid,
            "distinguishedname": dn,
            "caname": name,
            "dnsname": dns_name,
            "certificatetemplates": cert_templates,
            "highvalue": True,
        }

        return {
            "ObjectIdentifier": sid,
            "Properties": properties,
            "Aces": [],
        }


# CERTIFICATE TEMPLATE ENUMERATOR
class CertTemplateEnumerator(BaseEnumerator):
    """Enumerate AD CS Certificate Template objects."""

    # Well-known EKU OIDs
    EKU_MAP = {
        "1.3.6.1.5.5.7.3.2": "Client Authentication",
        "1.3.6.1.5.5.7.3.1": "Server Authentication",
        "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
        "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
        "2.5.29.37.0": "Any Purpose",
        "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
    }

    def enumerate(self) -> List[Dict[str, Any]]:
        template_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{self.client.config_dn}"

        entries = self.client.paged_search(
            search_base=template_base,
            search_filter="(objectClass=pKICertificateTemplate)",
            attributes=CERTTEMPLATE_ATTRIBUTES,
        )

        results = []
        for entry in entries:
            obj = self._transform(entry)
            if obj:
                results.append(obj)

        return results

    def _transform(self, entry: dict) -> Optional[Dict[str, Any]]:
        dn = _get_attr_str(entry, "distinguishedName")
        name = _get_attr_str(entry, "name") or _get_attr_str(entry, "cn")
        display_name = _get_attr_str(entry, "displayName") or name
        sid = _get_sid(entry) or dn

        ekus = _get_attr_list(entry, "pKIExtendedKeyUsage")
        app_policies = _get_attr_list(entry, "msPKI-Certificate-Application-Policy")
        effective_ekus = ekus or app_policies

        # Parse certificate name flag
        name_flag = _get_attr_int(entry, "msPKI-Certificate-Name-Flag", 0)
        enrollee_supplies_subject = bool(name_flag & 0x1)  # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT

        # Parse enrollment flag
        enrollment_flag = _get_attr_int(entry, "msPKI-Enrollment-Flag", 0)

        # Check for client authentication EKU
        client_auth = any(
            eku in ("1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.4", "2.5.29.37.0")
            for eku in effective_ekus
        )

        # Check for enrollment agent
        enrollment_agent = "1.3.6.1.4.1.311.20.2.1" in effective_ekus

        # Any purpose or no EKU
        any_purpose = "2.5.29.37.0" in effective_ekus
        no_eku = len(effective_ekus) == 0

        schema_version = _get_attr_int(entry, "msPKI-Template-Schema-Version", 1)
        ra_signatures = _get_attr_int(entry, "msPKI-RA-Signature", 0)
        requires_manager = bool(enrollment_flag & 0x2)  # CT_FLAG_PEND_ALL_REQUESTS

        properties = {
            "name": f"{name}@{self.domain_name}",
            "domain": self.domain_name,
            "objectid": sid,
            "distinguishedname": dn,
            "templatename": name,
            "displayname": display_name,
            "ekus": effective_ekus,
            "effectiveekus": effective_ekus,
            "clientauthentication": client_auth,
            "enrolleesuppliessubject": enrollee_supplies_subject,
            "enrollmentagent": enrollment_agent,
            "anypurpose": any_purpose,
            "requiresmanagerapproval": requires_manager,
            "authorizedsignatures": ra_signatures,
            "schemaversion": schema_version,
            "enabled": True,
            "highvalue": False,
        }

        return {
            "ObjectIdentifier": sid,
            "Properties": properties,
            "Aces": [],
        }


# ACL ENUMERATOR (Security Descriptors)
class ACLEnumerator(BaseEnumerator):
    """
    Parse security descriptors (nTSecurityDescriptor) on AD objects
    and populate the Aces arrays in the collected data.

    This is a post-processing step that enriches previously collected objects.
    """

    # Well-known AD rights GUIDs
    RIGHTS_GUIDS = {
        "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
        "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Certificate-Enrollment",
        "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "Certificate-AutoEnrollment",
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
        "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
        "bf9679c0-0de6-11d0-a285-00aa003049e2": "Member",
        "bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Self-Membership",
    }

    # BloodHound edge names for access rights
    ACCESS_RIGHTS_MAP = {
        0x10000000: "GenericAll",
        0x40000000: "GenericWrite",
        0x20000000: "GenericExecute",
        0x80000000: "GenericRead",
        0x00040000: "WriteDacl",
        0x00020000: "WriteOwner",
    }

    def enumerate(self) -> List[Dict[str, Any]]:
        """ACL enumeration is handled as post-processing, returns empty list."""
        return []

    def enrich_objects(
        self,
        objects: List[Dict[str, Any]],
        object_type: str,
    ) -> List[Dict[str, Any]]:
        """
        Re-query objects with nTSecurityDescriptor and parse ACLs.

        Note: Full SD parsing requires the SD_FLAGS control to request
        the DACL. This is a simplified version that captures the most
        common attack-relevant ACEs.
        """
        # For a full implementation, each object's nTSecurityDescriptor
        # would be parsed using the SDDL binary format.
        # This is a placeholder that returns the objects unchanged —
        # full SD parsing will be implemented in a future update.
        return objects
