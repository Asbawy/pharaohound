#!/usr/bin/env python3
"""
graph.py — Traversal helpers for BloodHound-derived object graphs.

Three problems this module solves:

1. **Nested group resolution** — "is User X *really* a member of Group Z
   through three layers of nested groups?"  Uses the ObjectStore's
   transitive-membership cache for an O(1) answer.

2. **ACL inheritance** — "User A has WriteDacl over Group B; can a member
   of Group A inherit that right?"  Computes the transitive closure of
   principal SIDs (direct + via group membership) so we never miss an
   attack path.

3. **Path enumeration** — for a given principal, find every object on
   which it has any dangerous right (directly or transitively).
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set, Tuple

from .models import ADObject, ObjectStore


# DANGEROUS RIGHTS CATALOG
DANGEROUS_ACL_RIGHTS: Set[str] = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
    "Owns", "AddMember", "ForceChangePassword", "AllExtendedRights",
    "AddKeyCredentialLink", "ReadLAPSPassword", "DCSync",
    "CanRBCD", "CanPSRemote", "ExecuteDCOM", "AllowedToDelegate",
}

# Rights that grant code-execution-ish primitives on a computer
LATERAL_RIGHTS: Set[str] = {"AdminTo", "CanPSRemote", "ExecuteDCOM", "AllowedToDelegate"}

# Rights that grant credential material
CRED_RIGHTS: Set[str] = {"ReadLAPSPassword", "HasSession", "DCSync"}


# ACL TRAVERSAL
def principal_closure(store: ObjectStore, sid: str) -> Set[str]:
    """
    Return every SID that the principal `sid` *acts as* — itself plus every
    group it transitively belongs to.  Used to answer "does this ACE apply
    to principal X?" by checking membership instead of just direct equality.
    """
    if not sid:
        return set()
    closure: Set[str] = {sid}
    closure |= store.transitive_groups_for(sid)
    return closure


def ace_applies_to_principal(store: ObjectStore, ace: dict, principal_sid: str) -> bool:
    """
    Does `ace` apply to `principal_sid`?

    Handles:
      - Direct match on PrincipalSID
      - Indirect match via nested group membership
      - "Everyone" / "Authenticated Users" / "Anonymous" SIDs
    """
    principal_sid = (principal_sid or "").strip()
    if not principal_sid:
        return False

    ace_principal = (ace.get("PrincipalSID") or "").strip()
    if not ace_principal:
        return False

    # Universal SIDs
    WELL_KNOWN = {
        "S-1-1-0",          # Everyone
        "S-1-5-11",         # Authenticated Users
        "S-1-5-7",          # Anonymous
        "S-1-5-32-545",     # Users (built-in)
    }
    if ace_principal in WELL_KNOWN:
        return True

    # Direct match
    if ace_principal == principal_sid:
        return True

    # Transitive — does the principal belong (transitively) to the ACE's group?
    closure = principal_closure(store, principal_sid)
    if ace_principal in closure:
        return True

    return False


def rights_for(store: ObjectStore, target_sid: str, principal_sid: str) -> List[str]:
    """
    Return all the rights that `principal_sid` holds against `target_sid`,
    taking nested group membership into account.
    """
    target = store.resolve_sid(target_sid)
    if not target.sid:
        return []
    rights: List[str] = []
    for ace in target.aces:
        if not isinstance(ace, dict):
            continue
        if ace_applies_to_principal(store, ace, principal_sid):
            r = ace.get("RightName") or ""
            if r:
                rights.append(r)
    return rights


def objects_targeted_by(
    store: ObjectStore,
    principal_sid: str,
    rights_filter: Optional[Set[str]] = None,
    target_types: Optional[Set[str]] = None,
) -> List[Tuple[ADObject, str]]:
    """
    Enumerate every (object, right) pair where `principal_sid` has at least
    one of `rights_filter` rights on `object`, restricted to `target_types`
    if provided.  Skips self-edges.
    """
    closure = principal_closure(store, principal_sid)
    WELL_KNOWN = {"S-1-1-0", "S-1-5-11", "S-1-5-7", "S-1-5-32-545"}
    matching_principals = closure | WELL_KNOWN

    results: List[Tuple[ADObject, str]] = []
    for obj in store.all_objects():
        if target_types and obj.object_type not in target_types:
            continue
        if obj.sid == principal_sid:
            continue
        for ace in obj.aces:
            if not isinstance(ace, dict):
                continue
            ace_p = (ace.get("PrincipalSID") or "").strip()
            if not ace_p:
                continue
            if ace_p not in matching_principals:
                continue
            right = ace.get("RightName") or ""
            if not right:
                continue
            if rights_filter and right not in rights_filter:
                continue
            results.append((obj, right))
    return results


# HIGH-VALUE GROUP MEMBERSHIP
def is_in_high_value_group(store: ObjectStore, sid: str) -> bool:
    """Is `sid` a transitive member of any high-value group?"""
    from .models import is_high_value_group_name

    groups = store.transitive_groups_for(sid)
    for g_sid in groups:
        group = store.groups.get(g_sid)
        if group and (group.highvalue or is_high_value_group_name(group.name)):
            return True
    return False


def high_value_group_membership(store: ObjectStore, sid: str) -> List[str]:
    """Return names of every high-value group `sid` transitively belongs to."""
    from .models import is_high_value_group_name

    out: List[str] = []
    for g_sid in store.transitive_groups_for(sid):
        group = store.groups.get(g_sid)
        if group and (group.highvalue or is_high_value_group_name(group.name)):
            out.append(group.name)
    return out


# OU HIGH-VALUE CHECK
def ou_contains_high_value(store: ObjectStore, ou_sid: str) -> bool:
    """Does this OU have any high-value computer or user as a child?"""
    ou = store.ous.get(ou_sid)
    if not ou:
        return False
    child_sids = [c.get("ObjectIdentifier") for c in ou.extras.get("child_objects", []) if isinstance(c, dict)]
    for csid in child_sids:
        if not csid:
            continue
        obj = store.resolve_sid(csid)
        if obj.object_type == "computer":
            if obj.extras.get("unconstraineddelegation") or obj.admincount:
                return True
        elif obj.object_type == "user":
            if is_in_high_value_group(store, obj.sid):
                return True
    return False
