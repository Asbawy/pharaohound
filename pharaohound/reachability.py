#!/usr/bin/env python3
"""
reachability.py — Compromised-user reachability engine.

Given one or more compromised principal SIDs, computes the transitive
closure of what those principals can reach (via group memberships and
ACL edges), then filters findings/attack-paths to only show what is
actually exploitable from that position.  This eliminates false
positives for a user running an engagement from a specific foothold.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from .graph import (
    DANGEROUS_ACL_RIGHTS,
    principal_closure,
    objects_targeted_by,
)
from .models import ADObject, ObjectStore


# FINDING CLASSIFICATION
# Findings that any authenticated user can exploit — always shown.
ALWAYS_RELEVANT = {
    "Kerberoastable Users",
    "AS-REP Roastable Users",
    "Password Policy Weaknesses",
    "Legacy OS Vulnerabilities",
    "Pre-Windows 2000 Access",
    "Active Directory Trust Issues",
    "SID History Abuse",
    "Machine Account Quota Abuse",
}

# Findings keyed by the principal/attacker field in data items.
# The value is the dict key containing the acting principal's name or SID.
PRINCIPAL_KEYED = {
    "Dangerous ACL Permissions":          ("principal_sid", "principal"),
    "LAPS Password Readers":              ("reader_sid", "reader"),
    "DCSync Rights":                      ("account_sid", "account"),
    "Shadow Credentials Opportunities":   ("attacker_sid", "attacker"),
    "GPO Abuse Paths":                    ("attacker_sid", "attacker"),
    "Unconstrained Delegation":           (None, "name"),        # special: need admin on the box
    "High-Value Group Membership":        ("sid", "name"),
    "Active Sessions":                    ("user_sid", "user"),
    "Local Admin Mapping":                ("principal_sid", "principal"),
    "Self-Add to Group Escalation":       ("principal_sid", "principal"),
    "gMSA Password Readers":              ("reader_sid", "reader"),
}


# REACHABILITY CONTEXT
class ReachabilityContext:
    """
    Represents the transitive reach of one or more compromised principals.

    Usage:
        ctx = ReachabilityContext(store, ["S-1-5-21-...-1001"])
        filtered = ctx.filter_findings(all_findings)
        filtered_paths = ctx.filter_attack_paths(all_paths)
    """

    def __init__(self, store: ObjectStore, compromised_sids: List[str]) -> None:
        self.store = store
        self.compromised_sids = set(compromised_sids)

        # Build the full closure: every SID any compromised user "acts as"
        self._closure: Set[str] = set()
        for sid in compromised_sids:
            self._closure |= principal_closure(store, sid)

        # Cache: SIDs of objects the compromised user has dangerous rights on
        self._reachable: Optional[Set[str]] = None

    @property
    def closure(self) -> Set[str]:
        """All SIDs the compromised user(s) act as (self + transitive groups)."""
        return self._closure

    @property
    def compromised_names(self) -> List[str]:
        """Human-readable names of directly compromised principals."""
        return [self.store.resolve_sid(sid).name for sid in self.compromised_sids]

    def can_act_as(self, sid: str) -> bool:
        """Is `sid` in the compromised user's transitive closure?"""
        return sid in self._closure

    def can_reach(self, target_sid: str) -> bool:
        """Does the compromised user hold any dangerous ACL right on `target_sid`?"""
        if self._reachable is None:
            self._build_reachable()
        return target_sid in self._reachable

    def _build_reachable(self) -> None:
        """Compute all objects the compromised users can reach via ACL edges."""
        self._reachable = set()
        for sid in self.compromised_sids:
            targets = objects_targeted_by(self.store, sid, DANGEROUS_ACL_RIGHTS)
            for obj, right in targets:
                self._reachable.add(obj.sid)

    # ── Finding filter ──────────────────────────────────────────────────────
    def filter_findings(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Filter findings to only those exploitable from the compromised user.
        Returns a new list; original is not modified.
        """
        filtered: List[Dict[str, Any]] = []
        for f in findings:
            result = self._filter_one_finding(f)
            if result is not None:
                filtered.append(result)
        return filtered

    def _filter_one_finding(
        self, f: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        title = f.get("title", "")

        # Always-relevant findings: keep all data items
        if title in ALWAYS_RELEVANT:
            return f

        # Principal-keyed findings: filter data items
        if title in PRINCIPAL_KEYED:
            sid_key, name_key = PRINCIPAL_KEYED[title]
            filtered_data = []
            for item in f.get("data", []):
                if self._item_is_reachable(item, sid_key, name_key):
                    filtered_data.append(item)

            if not filtered_data:
                return None  # no reachable items → drop the entire finding

            # Create a copy with filtered data and updated summary
            result = dict(f)
            result["data"] = filtered_data
            original_count = len(f.get("data", []))
            result["summary"] = (
                f"{f['summary']} "
                f"[Filtered: {len(filtered_data)}/{original_count} "
                f"reachable from {', '.join(self.compromised_names)}]"
            )
            return result

        # Unknown finding type — include it to be safe (no false negatives)
        return f

    def _item_is_reachable(
        self,
        item: Dict[str, Any],
        sid_key: Optional[str],
        name_key: str,
    ) -> bool:
        """
        Check if a single finding data item is reachable by the compromised user.
        Uses SID-based matching (exact) with name fallback.
        """
        # 1. Try exact SID match against closure
        if sid_key and sid_key in item:
            item_sid = item[sid_key]
            if item_sid and item_sid in self._closure:
                return True

        # 2. Fallback: resolve name to SID and check
        if name_key and name_key in item:
            item_name = item[name_key]
            if item_name:
                # Look up in store by name (case-insensitive)
                for obj in self.store.all_objects():
                    if obj.name and obj.name.upper() == item_name.upper():
                        if obj.sid in self._closure:
                            return True

        return False

    # ── Attack path filter ──────────────────────────────────────────────────
    def filter_attack_paths(
        self, paths: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Filter attack paths to only those starting from a principal the
        compromised user controls (directly or transitively).
        """
        filtered: List[Dict[str, Any]] = []
        for p in paths:
            if self._path_is_reachable(p):
                filtered.append(p)
        return filtered

    def _path_is_reachable(self, path: Dict[str, Any]) -> bool:
        """
        An attack path is reachable if:
        1. Its prerequisites mention controlling a principal in our closure, OR
        2. It requires "any domain credentials" (Kerberoast, AS-REP), OR
        3. It requires no credentials at all.
        """
        name = path.get("name", "")
        prereqs = path.get("prerequisites", [])

        # Kerberoast/AS-REP paths: any authenticated user can do this
        for keyword in ("any authenticated", "any domain", "username", "no credentials"):
            for p in prereqs:
                if keyword.lower() in p.lower():
                    return True

        # Check if the path references a principal in our closure
        # The path name format is: "Type: PRINCIPAL → right → TARGET"
        # Also check steps which reference controlling a specific principal
        steps = path.get("steps", [])
        all_text = name + " " + " ".join(prereqs) + " " + " ".join(steps)

        # Check every compromised principal name (and their group names)
        for sid in self._closure:
            obj = self.store.resolve_sid(sid)
            if obj.name and obj.name.upper() in all_text.upper():
                return True

        return False

    # ── Recommendation filter ───────────────────────────────────────────────
    def filter_recommendations(
        self, recommendations: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Filter recommendations to only those relevant to reachable findings.
        Recommendations without specific principal references are kept.
        """
        # Recommendations are generally always useful; but we can tag them
        # as "directly exploitable" vs "general hardening"
        return recommendations  # Keep all for now — they're defensive advice
