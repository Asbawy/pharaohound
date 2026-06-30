#!/usr/bin/env python3
"""
models.py — Dataclasses for BloodHound AD objects + a unified ObjectStore.

Robust against SharpHound v4 / v5 format discrepancies: every accessor
normalizes None / missing / wrong-shape values to a safe default so the
analysis layer never crashes on shape mismatches.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# SAFETY HELPERS
def _safe_get(d: Optional[Dict[str, Any]], key: str, default: Any = None) -> Any:
    """Return d[key] if d is a dict and key is present, else default."""
    if not isinstance(d, dict):
        return default
    val = d.get(key, default)
    return default if val is None else val


def _as_list(val: Any) -> List[Any]:
    """Coerce None / scalar / list into a list."""
    if val is None:
        return []
    if isinstance(val, list):
        return val
    if isinstance(val, tuple):
        return list(val)
    return [val]


def _as_str(val: Any, default: str = "") -> str:
    if val is None:
        return default
    if isinstance(val, str):
        return val
    return str(val)


def _as_bool(val: Any, default: bool = False) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        return val.strip().lower() in {"true", "1", "yes", "y"}
    return default


def _as_int(val: Any, default: int = 0) -> int:
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _extract_sid(item: Any) -> str:
    """Pull a SID out of an ACE/Membership dict in any known shape."""
    if not isinstance(item, dict):
        return _as_str(item)
    return (
        _as_str(item.get("ObjectIdentifier"))
        or _as_str(item.get("PrincipalSID"))
        or _as_str(item.get("MemberId"))
        or ""
    )


def _extract_type(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    return _as_str(item.get("ObjectType")) or _as_str(item.get("PrincipalType")) or ""


# OBJECT DATACLASS
@dataclass
class ADObject:
    """Common shape shared by every BloodHound object type."""

    sid: str
    name: str
    object_type: str                       # user | group | computer | domain | gpo | ou | container
    properties: Dict[str, Any] = field(default_factory=dict)
    aces: List[Dict[str, Any]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    extras: Dict[str, Any] = field(default_factory=dict)

    # Common useful flags (precomputed for fast filtering)
    enabled: bool = True
    admincount: bool = False
    highvalue: bool = False

    @property
    def domain(self) -> str:
        return _as_str(self.properties.get("domain"))

    @property
    def distinguished_name(self) -> str:
        return _as_str(self.properties.get("distinguishedname"))

    def ace_summary(self) -> List[str]:
        return [_as_str(a.get("RightName")) for a in self.aces if isinstance(a, dict)]


# OBJECT STORE
class ObjectStore:
    """
    Central, type-aware registry of every AD object the parsers produced.

    All lookups use SIDs (or GUIDs for GPOs). The store also exposes
    convenience helpers that the analyzers rely on, e.g. `resolve_sid`,
    `all_objects`, and per-type iteration.
    """

    def __init__(self) -> None:
        self.users: Dict[str, ADObject] = {}
        self.groups: Dict[str, ADObject] = {}
        self.computers: Dict[str, ADObject] = {}
        self.domains: Dict[str, ADObject] = {}
        self.gpos: Dict[str, ADObject] = {}
        self.ous: Dict[str, ADObject] = {}
        self.containers: Dict[str, ADObject] = {}
        self.cas: Dict[str, ADObject] = {}            # AD CS Certificate Authorities
        self.certtemplates: Dict[str, ADObject] = {}   # AD CS Certificate Templates
        self.azure: Dict[str, ADObject] = {}           # Azure / Entra ID entities

        # Combined map for fast SID → ADObject lookup (any type)
        self._by_sid: Dict[str, ADObject] = {}

        # Build cache for transitive group memberships (populated lazily)
        self._transitive_memberships: Optional[Dict[str, set]] = None

    # ── Registration ────────────────────────────────────────────────────────
    def register(self, obj: ADObject) -> None:
        bucket = self._bucket(obj.object_type)
        bucket[obj.sid] = obj
        self._by_sid[obj.sid] = obj
        # Invalidate the transitive-membership cache
        self._transitive_memberships = None

    def _bucket(self, otype: str) -> Dict[str, ADObject]:
        return {
            "user": self.users,
            "group": self.groups,
            "computer": self.computers,
            "domain": self.domains,
            "gpo": self.gpos,
            "ou": self.ous,
            "container": self.containers,
            "ca": self.cas,
            "certtemplate": self.certtemplates,
            "azure": self.azure,
        }.get(otype, {})

    # ── Lookups ─────────────────────────────────────────────────────────────
    def resolve_sid(self, sid: str) -> ADObject:
        """Return the ADObject whose SID matches, or a placeholder."""
        if not sid:
            return ADObject(sid="", name="<unknown>", object_type="unknown")
        obj = self._by_sid.get(sid)
        if obj is not None:
            return obj
        # Some SharpHound exports prepend domain like "DOMAIN.SID" — try suffix match
        if "." in sid:
            suffix = sid.rsplit(".", 1)[-1]
            obj = self._by_sid.get(suffix)
            if obj is not None:
                return obj
        # Last resort: case-insensitive search
        lower = sid.lower()
        for key, obj in self._by_sid.items():
            if key.lower() == lower:
                return obj
        return ADObject(sid=sid, name=sid, object_type="unknown")

    def name_of(self, sid: str) -> str:
        return self.resolve_sid(sid).name

    def all_objects(self) -> List[ADObject]:
        return list(self._by_sid.values())

    def iter_by_type(self, otype: str):
        for obj in self._bucket(otype).values():
            yield obj

    # ── Stats ───────────────────────────────────────────────────────────────
    def stats(self) -> Dict[str, int]:
        return {
            "users": len(self.users),
            "groups": len(self.groups),
            "computers": len(self.computers),
            "domains": len(self.domains),
            "gpos": len(self.gpos),
            "ous": len(self.ous),
            "containers": len(self.containers),
            "cas": len(self.cas),
            "certtemplates": len(self.certtemplates),
            "azure": len(self.azure),
            "total": len(self._by_sid),
        }

    def primary_domain_name(self) -> str:
        for d in self.domains.values():
            if d.name:
                return d.name
        return "Unknown"

    # ── Transitive group memberships ────────────────────────────────────────
    def transitive_groups_for(self, sid: str) -> set:
        """Return the set of all group SIDs that `sid` is a member of, transitively."""
        if self._transitive_memberships is None:
            self._build_transitive_memberships()
        return self._transitive_memberships.get(sid, set())

    def _build_transitive_memberships(self) -> None:
        """
        Build a map: principal_sid -> set of every group SID it transitively belongs to.

        Uses an iterative BFS that handles nested groups and cycles.
        Group memberships are derived from each group's `Members` array
        (SharpHound emits {ObjectIdentifier, ObjectType} per member).
        """
        result: Dict[str, set] = {sid: set() for sid in self._by_sid.keys()}
        # Seed with direct memberships
        for g_sid, group in self.groups.items():
            for member in _as_list(group.raw.get("Members")):
                m_sid = _extract_sid(member)
                if m_sid:
                    result.setdefault(m_sid, set()).add(g_sid)
        # Also honor PrimaryGroupSID pointer on user/computer objects
        for obj in self._by_sid.values():
            pg = obj.raw.get("PrimaryGroupSID")
            if isinstance(pg, str) and pg:
                result.setdefault(obj.sid, set()).add(pg)

        # BFS to flatten nested groups
        changed = True
        while changed:
            changed = False
            for sid in list(result.keys()):
                current = result[sid]
                additions: set = set()
                for g in current:
                    # If g is itself a member of other groups, inherit them
                    additions |= result.get(g, set())
                if not additions.issubset(current):
                    result[sid] |= additions
                    changed = True
        self._transitive_memberships = result


# OBJECT BUILDERS — format-tolerant normalizers
def build_user(raw: Dict[str, Any]) -> ADObject:
    props = raw.get("Properties") or {}
    sid = _as_str(raw.get("ObjectIdentifier")) or _as_str(props.get("objectid"))
    name = _as_str(props.get("name")) or sid or "<unknown-user>"

    # `serviceprincipalnames` is sometimes a list, sometimes a single string
    spns = _as_list(props.get("serviceprincipalnames"))
    if not spns and _as_bool(props.get("hasspn")):
        spns = ["<spn-not-listed>"]

    obj = ADObject(
        sid=sid,
        name=name,
        object_type="user",
        properties=props,
        aces=_as_list(raw.get("Aces")),
        raw=raw,
        enabled=_as_bool(props.get("enabled"), True),
        admincount=_as_bool(props.get("admincount")),
        highvalue=False,
    )
    obj.extras = {
        "spns": spns,
        "hasspn": _as_bool(props.get("hasspn")) or bool(spns),
        "dontreqpreauth": _as_bool(props.get("dontreqpreauth")),
        "pwdlastset": _as_int(props.get("pwdlastset")),
        "lastlogon": _as_int(props.get("lastlogon")),
        "unconstraineddelegation": _as_bool(props.get("unconstraineddelegation")),
        "trustedtoauth": _as_bool(props.get("trustedtoauth")),
        "allowed_to_delegate": _as_list(raw.get("AllowedToDelegate")),
        "has_sid_history": _as_list(raw.get("HasSIDHistory")),
        "primary_group_sid": _as_str(raw.get("PrimaryGroupSID")),
    }
    return obj


def build_group(raw: Dict[str, Any]) -> ADObject:
    props = raw.get("Properties") or {}
    sid = _as_str(raw.get("ObjectIdentifier")) or _as_str(props.get("objectid"))
    name = _as_str(props.get("name")) or sid or "<unknown-group>"
    return ADObject(
        sid=sid,
        name=name,
        object_type="group",
        properties=props,
        aces=_as_list(raw.get("Aces")),
        raw=raw,
        admincount=_as_bool(props.get("admincount")),
        highvalue=_as_bool(props.get("highvalue")),
        extras={
            "members": _as_list(raw.get("Members")),
        },
    )


def build_computer(raw: Dict[str, Any]) -> ADObject:
    props = raw.get("Properties") or {}
    sid = _as_str(raw.get("ObjectIdentifier")) or _as_str(props.get("objectid"))
    name = _as_str(props.get("name")) or sid or "<unknown-computer>"
    return ADObject(
        sid=sid,
        name=name,
        object_type="computer",
        properties=props,
        aces=_as_list(raw.get("Aces")),
        raw=raw,
        enabled=_as_bool(props.get("enabled"), True),
        admincount=_as_bool(props.get("admincount")),
        extras={
            "os": _as_str(props.get("operatingsystem"), "Unknown"),
            "unconstraineddelegation": _as_bool(props.get("unconstraineddelegation")),
            "trustedtoauth": _as_bool(props.get("trustedtoauth")),
            "haslaps": _as_bool(props.get("haslaps")),
            "allowed_to_delegate": _as_list(raw.get("AllowedToDelegate")),
            "allowed_to_act": _as_list(raw.get("AllowedToAct")),
            "sessions": _as_list(raw.get("Sessions")),
            "local_admins": _as_list(raw.get("LocalAdmins")),
            "rdp": _as_list(raw.get("RemoteDesktopUsers")),
            "dcom": _as_list(raw.get("DcomUsers")),
            "psremote": _as_list(raw.get("PSRemoteUsers")),
        },
    )


def build_domain(raw: Dict[str, Any]) -> ADObject:
    props = raw.get("Properties") or {}
    sid = _as_str(raw.get("ObjectIdentifier")) or _as_str(props.get("objectid"))
    name = _as_str(props.get("name")) or sid or "<unknown-domain>"
    return ADObject(
        sid=sid,
        name=name,
        object_type="domain",
        properties=props,
        aces=_as_list(raw.get("Aces")),
        raw=raw,
        extras={
            "child_objects": _as_list(raw.get("ChildObjects")),
            "inbound_trusts": _as_list(raw.get("InboundTrusts")),
            "outbound_trusts": _as_list(raw.get("OutboundTrusts")),
        },
    )


def build_gpo(raw: Dict[str, Any]) -> ADObject:
    props = raw.get("Properties") or {}
    guid = _as_str(raw.get("ObjectIdentifier")) or _as_str(props.get("objectid"))
    name = _as_str(props.get("name")) or guid or "<unknown-gpo>"
    return ADObject(
        sid=guid,
        name=name,
        object_type="gpo",
        properties=props,
        aces=_as_list(raw.get("Aces")),
        raw=raw,
    )


def build_ou(raw: Dict[str, Any]) -> ADObject:
    props = raw.get("Properties") or {}
    guid = _as_str(raw.get("ObjectIdentifier")) or _as_str(props.get("objectid"))
    name = _as_str(props.get("name")) or guid or "<unknown-ou>"
    return ADObject(
        sid=guid,
        name=name,
        object_type="ou",
        properties=props,
        aces=_as_list(raw.get("Aces")),
        raw=raw,
        extras={
            "child_objects": _as_list(raw.get("ChildObjects")),
            "gplink": _as_list(raw.get("GPLink")),
        },
    )


def build_container(raw: Dict[str, Any]) -> ADObject:
    props = raw.get("Properties") or {}
    guid = _as_str(raw.get("ObjectIdentifier")) or _as_str(props.get("objectid"))
    name = _as_str(props.get("name")) or guid or "<unknown-container>"
    return ADObject(
        sid=guid,
        name=name,
        object_type="container",
        properties=props,
        aces=_as_list(raw.get("Aces")),
        raw=raw,
        extras={"child_objects": _as_list(raw.get("ChildObjects"))},
    )


def build_ca(raw: Dict[str, Any]) -> ADObject:
    """Build a Certificate Authority (AD CS) object."""
    props = raw.get("Properties") or {}
    guid = _as_str(raw.get("ObjectIdentifier")) or _as_str(props.get("objectid"))
    name = _as_str(props.get("name")) or _as_str(props.get("caname")) or guid or "<unknown-ca>"
    return ADObject(
        sid=guid,
        name=name,
        object_type="ca",
        properties=props,
        aces=_as_list(raw.get("Aces")),
        raw=raw,
        extras={
            "caname": _as_str(props.get("caname")),
            "dnsname": _as_str(props.get("dnsname")),
            "cert_chain": _as_list(props.get("certificatechain")),
            "flags": _as_str(props.get("flags")),
            "enrollmentagentrestrictions": _as_list(props.get("enrollmentagentrestrictions")),
            "has_editf_flag": _as_bool(props.get("haseditattrflag")),
            "manage_ca_principals": _as_list(raw.get("ManageCAPrincipals")),
            "manage_cert_principals": _as_list(raw.get("ManageCertPrincipals")),
            "enroll_principals": _as_list(raw.get("EnrollPrincipals")),
            "web_enrollment": _as_bool(props.get("webenrollment")),
        },
    )


def build_cert_template(raw: Dict[str, Any]) -> ADObject:
    """Build a Certificate Template (AD CS) object."""
    props = raw.get("Properties") or {}
    guid = _as_str(raw.get("ObjectIdentifier")) or _as_str(props.get("objectid"))
    name = _as_str(props.get("name")) or _as_str(props.get("templatename")) or guid or "<unknown-template>"
    ekus = _as_list(props.get("effectiveekus")) or _as_list(props.get("ekus"))
    return ADObject(
        sid=guid,
        name=name,
        object_type="certtemplate",
        properties=props,
        aces=_as_list(raw.get("Aces")),
        raw=raw,
        extras={
            "templatename": _as_str(props.get("templatename")),
            "displayname": _as_str(props.get("displayname")),
            "ekus": ekus,
            "client_auth": _as_bool(props.get("clientauthentication")),
            "enrollee_supplies_subject": _as_bool(props.get("enrolleesuppliessubject")),
            "enrollment_agent": _as_bool(props.get("enrollmentagent")),
            "any_purpose": _as_bool(props.get("anypurpose")),
            "no_eku": not bool(ekus),
            "requires_manager_approval": _as_bool(props.get("requiresmanagerapproval")),
            "authorized_signatures": _as_int(props.get("authorizedsignatures")),
            "schema_version": _as_int(props.get("schemaversion")),
            "enroll_principals": _as_list(raw.get("EnrollPrincipals")),
            "enabled": _as_bool(props.get("enabled"), True),
        },
    )


def build_azure_entity(raw: Dict[str, Any]) -> ADObject:
    """Build an Azure / Entra ID entity (service principal, app registration, device, etc.)."""
    props = raw.get("Properties") or {}
    oid = _as_str(raw.get("ObjectIdentifier")) or _as_str(props.get("objectid"))
    name = _as_str(props.get("name")) or _as_str(props.get("displayname")) or oid or "<unknown-azure>"
    return ADObject(
        sid=oid,
        name=name,
        object_type="azure",
        properties=props,
        aces=_as_list(raw.get("Aces")),
        raw=raw,
        extras={
            "azure_type": _as_str(props.get("type", "ServicePrincipal")),
            "appid": _as_str(props.get("appid")),
            "tenantid": _as_str(props.get("tenantid")),
            "serviceprincipaltype": _as_str(props.get("serviceprincipaltype")),
            "app_roles": _as_list(raw.get("AppRoleAssignments")),
            "owners": _as_list(raw.get("Owners")),
            "roles": _as_list(raw.get("Roles")),
            "inbound_control": _as_list(raw.get("InboundObjectControl")),
        },
    )


# Map of data_type → builder. Used by the parsers module.
BUILDERS = {
    "users": build_user,
    "groups": build_group,
    "computers": build_computer,
    "domains": build_domain,
    "gpos": build_gpo,
    "ous": build_ou,
    "containers": build_container,
    "cas": build_ca,
    "certtemplates": build_cert_template,
    "azureusers": build_azure_entity,
    "azuregroups": build_azure_entity,
    "azuredevices": build_azure_entity,
    "azuretenants": build_azure_entity,
    "azureserviceprincipals": build_azure_entity,
    "azureapps": build_azure_entity,
}


# HIGH-VALUE GROUP CATALOG
HIGH_VALUE_GROUPS = [
    "DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS",
    "ACCOUNT OPERATORS", "BACKUP OPERATORS", "SERVER OPERATORS",
    "PRINT OPERATORS", "DNSADMINS", "SCHEMA ADMINS",
    "ENTERPRISE KEY ADMINS", "KEY ADMINS", "CERT PUBLISHERS",
    "GROUP POLICY CREATOR OWNERS", "CRYPTOGRAPHIC OPERATORS",
]


def is_high_value_group_name(name: str) -> bool:
    upper = (name or "").upper()
    return any(hv in upper for hv in HIGH_VALUE_GROUPS)


# PASSWORD-AGE UTIL
def calculate_password_age(pwdlastset: int) -> int:
    """Return password age in days. Large sentinel if never set / unknown."""
    if not pwdlastset or pwdlastset <= 0:
        return 99999
    try:
        # BloodHound stores Windows FILETIME (100ns since 1601) OR unix epoch — handle both
        if pwdlastset > 10_000_000_000:        # FILETIME-style
            # Convert FILETIME (100ns ticks since 1601-01-01) to unix epoch
            unix = pwdlastset / 10_000_000 - 11_644_473_600
            pwd_date = datetime.fromtimestamp(unix, tz=timezone.utc)
        else:
            pwd_date = datetime.fromtimestamp(pwdlastset, tz=timezone.utc)
        return max(0, (datetime.now(tz=timezone.utc) - pwd_date).days)
    except (ValueError, OSError, OverflowError):
        return 99999
