#!/usr/bin/env python3
"""
adcs.py — AD CS (Active Directory Certificate Services) Misconfiguration Analyzer.

Detects ESC1 through ESC13 certificate-based attack primitives by inspecting
Certificate Authority and Certificate Template objects ingested from Certipy
or SharpHound exports.

Each misconfiguration maps directly to a Certipy exploitation command and a
concrete remediation step.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .base import BaseAnalyzer, Finding
from ..models import ObjectStore, _as_bool, _as_list, _as_str, _as_int
from ..theme import Severity


# CLIENT AUTHENTICATION EKU OID
CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2"
ANY_PURPOSE_OID = "2.5.29.37.0"
ENROLLMENT_AGENT_OID = "1.3.6.1.4.1.311.20.2.1"
PKINIT_OID = "1.3.6.1.5.2.3.4"

# Well-known low-privilege SIDs that should NOT have enrollment rights
LOW_PRIV_SIDS = {
    "S-1-1-0",        # Everyone
    "S-1-5-11",       # Authenticated Users
    "S-1-5-7",        # Anonymous Logon
    "S-1-5-32-545",   # Users
}


def _has_eku(ekus: List[str], oid: str) -> bool:
    """Check if a specific EKU OID is present in the list."""
    return any(oid in e for e in ekus)


def _has_low_priv_enrollment(template) -> List[str]:
    """Return list of low-priv principals that can enroll in this template."""
    results = []
    enroll_principals = template.extras.get("enroll_principals", [])
    for ep in enroll_principals:
        if isinstance(ep, dict):
            sid = _as_str(ep.get("ObjectIdentifier", ""))
            name = _as_str(ep.get("Name", sid))
            if sid in LOW_PRIV_SIDS:
                results.append(name or sid)
        elif isinstance(ep, str):
            if ep in LOW_PRIV_SIDS:
                results.append(ep)
    return results


class ADCSAnalyzer(BaseAnalyzer):
    """
    Detect AD CS misconfigurations (ESC1 through ESC13).

    Requires Certificate Authority and/or Certificate Template objects
    to be ingested. If no AD CS data is present, the analyzer gracefully
    returns no findings.
    """

    name = "AD CS Misconfigurations"
    description = "Detects ESC1–ESC13 certificate abuse paths in Active Directory Certificate Services"

    def analyze(self, store: ObjectStore) -> Finding | None:
        templates = list(store.certtemplates.values())
        cas = list(store.cas.values())

        if not templates and not cas:
            return None  # No AD CS data ingested

        items: List[Dict[str, Any]] = []

        # ── ESC1: Client Auth + ENROLLEE_SUPPLIES_SUBJECT ────────────────────
        for tpl in templates:
            ekus = tpl.extras.get("ekus", [])
            if (
                tpl.extras.get("client_auth")
                or _has_eku(ekus, CLIENT_AUTH_OID)
                or _has_eku(ekus, PKINIT_OID)
            ):
                if tpl.extras.get("enrollee_supplies_subject"):
                    if not tpl.extras.get("requires_manager_approval"):
                        enrollers = _has_low_priv_enrollment(tpl)
                        items.append({
                            "esc": "ESC1",
                            "template": tpl.name,
                            "severity": Severity.CRITICAL,
                            "description": (
                                f"Template '{tpl.name}' allows Client Authentication and "
                                "ENROLLEE_SUPPLIES_SUBJECT is enabled. Any enrolling principal "
                                "can specify an arbitrary SAN (Subject Alternative Name) and "
                                "authenticate as any user, including Domain Admin."
                            ),
                            "enrollers": enrollers,
                            "playbook": (
                                f"certipy req -u '<DOMAIN_USER>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                                f"-template '{tpl.extras.get('templatename', tpl.name)}' "
                                f"-upn administrator@<DOMAIN> -dc-ip <DC_IP>"
                            ),
                        })

        # ── ESC2: Any Purpose EKU or No EKU ──────────────────────────────────
        for tpl in templates:
            ekus = tpl.extras.get("ekus", [])
            if tpl.extras.get("any_purpose") or _has_eku(ekus, ANY_PURPOSE_OID) or tpl.extras.get("no_eku"):
                enrollers = _has_low_priv_enrollment(tpl)
                label = "Any Purpose EKU" if (tpl.extras.get("any_purpose") or _has_eku(ekus, ANY_PURPOSE_OID)) else "No EKU defined"
                items.append({
                    "esc": "ESC2",
                    "template": tpl.name,
                    "severity": Severity.HIGH,
                    "description": (
                        f"Template '{tpl.name}' has {label}. This acts as a wildcard — "
                        "the issued certificate can be used for any purpose including "
                        "Client Authentication, making it abusable like ESC1."
                    ),
                    "enrollers": enrollers,
                    "playbook": (
                        f"certipy req -u '<DOMAIN_USER>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                        f"-template '{tpl.extras.get('templatename', tpl.name)}' -dc-ip <DC_IP>"
                    ),
                })

        # ── ESC3: Enrollment Agent Template ──────────────────────────────────
        for tpl in templates:
            ekus = tpl.extras.get("ekus", [])
            if tpl.extras.get("enrollment_agent") or _has_eku(ekus, ENROLLMENT_AGENT_OID):
                enrollers = _has_low_priv_enrollment(tpl)
                items.append({
                    "esc": "ESC3",
                    "template": tpl.name,
                    "severity": Severity.HIGH,
                    "description": (
                        f"Template '{tpl.name}' has the Enrollment Agent EKU. An enrolling "
                        "principal can request a certificate on behalf of another user, "
                        "effectively impersonating them."
                    ),
                    "enrollers": enrollers,
                    "playbook": (
                        f"certipy req -u '<DOMAIN_USER>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                        f"-template '{tpl.extras.get('templatename', tpl.name)}' -dc-ip <DC_IP> "
                        f"-on-behalf-of '<DOMAIN>\\\\administrator'"
                    ),
                })

        # ── ESC4: Write permissions on certificate templates ─────────────────
        for tpl in templates:
            for ace in tpl.aces:
                if not isinstance(ace, dict):
                    continue
                right = _as_str(ace.get("RightName", ""))
                if right in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "WriteProperty"):
                    principal_sid = _as_str(ace.get("PrincipalSID", ""))
                    principal_name = store.resolve_sid(principal_sid).name if principal_sid else "Unknown"
                    if principal_sid in LOW_PRIV_SIDS or not principal_sid:
                        items.append({
                            "esc": "ESC4",
                            "template": tpl.name,
                            "severity": Severity.CRITICAL,
                            "description": (
                                f"Template '{tpl.name}' has {right} granted to '{principal_name}'. "
                                "This allows overwriting the template to enable ESC1 conditions "
                                "(set ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU)."
                            ),
                            "principal": principal_name,
                            "right": right,
                            "playbook": (
                                f"certipy template -u '<DOMAIN_USER>' -p '<PASSWORD>' "
                                f"-template '{tpl.extras.get('templatename', tpl.name)}' "
                                f"-save-old -dc-ip <DC_IP>"
                            ),
                        })

        # ── ESC6: CA with EDITF_ATTRIBUTESUBJECTALTNAME2 flag ────────────────
        for ca in cas:
            if ca.extras.get("has_editf_flag"):
                items.append({
                    "esc": "ESC6",
                    "ca": ca.name,
                    "severity": Severity.CRITICAL,
                    "description": (
                        f"CA '{ca.name}' has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled. "
                        "This allows ANY certificate request to include an arbitrary SAN, "
                        "bypassing template restrictions — every template becomes ESC1."
                    ),
                    "playbook": (
                        f"certipy req -u '<DOMAIN_USER>' -p '<PASSWORD>' -ca '{ca.extras.get('caname', ca.name)}' "
                        f"-template User -upn administrator@<DOMAIN> -dc-ip <DC_IP>"
                    ),
                })

        # ── ESC7: Weak CA permissions (ManageCA / ManageCertificates) ────────
        for ca in cas:
            for ace in ca.aces:
                if not isinstance(ace, dict):
                    continue
                right = _as_str(ace.get("RightName", ""))
                if right in ("ManageCA", "ManageCertificates"):
                    principal_sid = _as_str(ace.get("PrincipalSID", ""))
                    principal_name = store.resolve_sid(principal_sid).name if principal_sid else "Unknown"
                    items.append({
                        "esc": "ESC7",
                        "ca": ca.name,
                        "severity": Severity.CRITICAL,
                        "description": (
                            f"CA '{ca.name}' grants {right} to '{principal_name}'. "
                            "ManageCA allows enabling the EDITF flag (creating ESC6). "
                            "ManageCertificates allows approving pending requests."
                        ),
                        "principal": principal_name,
                        "right": right,
                        "playbook": (
                            f"certipy ca -u '<DOMAIN_USER>' -p '<PASSWORD>' "
                            f"-ca '{ca.extras.get('caname', ca.name)}' -enable-template SubCA -dc-ip <DC_IP>"
                        ),
                    })

        # ── ESC8: HTTP Enrollment (Web Enrollment / CES / CEP) ───────────────
        for ca in cas:
            if ca.extras.get("web_enrollment"):
                items.append({
                    "esc": "ESC8",
                    "ca": ca.name,
                    "severity": Severity.HIGH,
                    "description": (
                        f"CA '{ca.name}' has HTTP-based enrollment (Web Enrollment/CES/CEP) enabled. "
                        "This is vulnerable to NTLM relay attacks — coerce a DC or privileged "
                        "user to authenticate to the enrollment endpoint and relay to the CA."
                    ),
                    "playbook": (
                        f"# Relay to CA web enrollment\n"
                        f"certipy relay -target 'http://{ca.extras.get('dnsname', '<CA_HOST>')}/certsrv/certfnsh.asp' "
                        f"-ca '{ca.extras.get('caname', ca.name)}' -template DomainController"
                    ),
                })

        # ── ESC5: Weak permissions on CA object or PKI containers ────────────
        for ca in cas:
            for ace in ca.aces:
                if not isinstance(ace, dict):
                    continue
                right = _as_str(ace.get("RightName", ""))
                if right in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "WriteProperty"):
                    principal_sid = _as_str(ace.get("PrincipalSID", ""))
                    principal_name = store.resolve_sid(principal_sid).name if principal_sid else "Unknown"
                    if principal_sid in LOW_PRIV_SIDS or not principal_sid:
                        items.append({
                            "esc": "ESC5",
                            "ca": ca.name,
                            "severity": Severity.CRITICAL,
                            "description": (
                                f"CA object '{ca.name}' has weak permission: '{right}' granted to '{principal_name}'. "
                                "An attacker can modify the CA configuration to grant themselves ManageCA/ManageCertificates "
                                "rights or enable the EDITF flag."
                            ),
                            "principal": principal_name,
                            "right": right,
                            "playbook": (
                                f"certipy ca -u '<DOMAIN_USER>' -p '<PASSWORD>' "
                                f"-ca '{ca.extras.get('caname', ca.name)}' -enable-template SubCA -dc-ip <DC_IP>"
                            )
                        })

        for container in store.containers.values():
            name_upper = container.name.upper()
            dn_upper = container.distinguished_name.upper()
            if "PUBLIC KEY SERVICES" in name_upper or "PUBLIC KEY SERVICES" in dn_upper or "ENROLLMENT SERVICES" in name_upper or "ENROLLMENT SERVICES" in dn_upper:
                for ace in container.aces:
                    if not isinstance(ace, dict):
                        continue
                    right = _as_str(ace.get("RightName", ""))
                    if right in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner"):
                        principal_sid = _as_str(ace.get("PrincipalSID", ""))
                        principal_name = store.resolve_sid(principal_sid).name if principal_sid else "Unknown"
                        if principal_sid in LOW_PRIV_SIDS or not principal_sid:
                            items.append({
                                "esc": "ESC5",
                                "container": container.name,
                                "severity": Severity.CRITICAL,
                                "description": (
                                    f"PKI container '{container.name}' has weak permissions: '{right}' granted to '{principal_name}'. "
                                    "An attacker can write new configuration objects (like a rogue CA or certificate template) to compromise the AD CS infrastructure."
                                ),
                                "principal": principal_name,
                                "right": right,
                                "playbook": f"# Write custom object to PKI container using Ldap / Certipy"
                            })

        # ── ESC9: No Strong Key Mapping Enforced ─────────────────────────────
        for tpl in templates:
            ekus = tpl.extras.get("ekus", [])
            if (
                tpl.extras.get("client_auth")
                or _has_eku(ekus, CLIENT_AUTH_OID)
                or _has_eku(ekus, PKINIT_OID)
            ):
                enrollers = _has_low_priv_enrollment(tpl)
                if enrollers:
                    flags = _as_int(tpl.properties.get("mspkienrollmentflags")) or _as_int(tpl.properties.get("mspki-enrollment-flags"))
                    # CT_FLAG_ENFORCE_STRONG_KEY_MAPPING = 0x00040000 (262144)
                    is_esc9 = False
                    if flags is not None and not (flags & 0x00040000):
                        is_esc9 = True
                    elif tpl.extras.get("schema_version", 2) < 3:
                        is_esc9 = True
                    
                    if is_esc9:
                        items.append({
                            "esc": "ESC9",
                            "template": tpl.name,
                            "severity": Severity.HIGH,
                            "description": (
                                f"Template '{tpl.name}' does not enforce strong key mapping (or uses weak mapping rules). "
                                "An attacker who can write to the 'msDS-KeyCredentialLink' attribute of a user can authenticate "
                                "as that user via PKINIT without triggering strong mapping verification."
                            ),
                            "enrollers": enrollers,
                            "playbook": (
                                f"certipy shadow auto -u '<DOMAIN_USER>' -p '<PASSWORD>' -account '<TARGET_USER>' -dc-ip <DC_IP>\n"
                                f"certipy req -u '<DOMAIN_USER>' -p '<PASSWORD>' -ca '<CA_NAME>' -template '{tpl.extras.get('templatename', tpl.name)}' -dc-ip <DC_IP>"
                            )
                        })

        # ── ESC10: Registry-level weak certificate-to-user mappings on DCs ──
        for computer in store.computers.values():
            if computer.properties.get("isdc") or computer.properties.get("is_dc"):
                binding = computer.properties.get("strongcertificatebindingenforcement")
                if binding is not None and _as_int(binding) in (0, 1):
                    items.append({
                        "esc": "ESC10",
                        "computer": computer.name,
                        "severity": Severity.HIGH,
                        "description": (
                            f"Domain Controller '{computer.name}' has StrongCertificateBindingEnforcement set to {binding}. "
                            "This allows certificate authentication with weak user-to-certificate mappings (e.g. bypassing UPN / altSecurityIdentities validation)."
                        ),
                        "playbook": f"# Exploit weak binding enforcement on DC via PKINIT and custom certificate mapping"
                    })

        # ── ESC13: Templates with Policy OIDs mapping to privileged groups ──
        for tpl in templates:
            policies = _as_list(tpl.properties.get("mspkicertificatepolicies")) or _as_list(tpl.properties.get("mspki-certificate-policies"))
            if policies:
                enrollers = _has_low_priv_enrollment(tpl)
                if enrollers:
                    items.append({
                        "esc": "ESC13",
                        "template": tpl.name,
                        "severity": Severity.HIGH,
                        "description": (
                            f"Template '{tpl.name}' has certificate policy OIDs: {', '.join(policies)}. "
                            "If any of these OIDs map to a privileged AD group, any enrolling principal "
                            "will gain the privileges of that group when authenticating with the issued certificate."
                        ),
                        "enrollers": enrollers,
                        "playbook": (
                            f"certipy req -u '<DOMAIN_USER>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                            f"-template '{tpl.extras.get('templatename', tpl.name)}' -dc-ip <DC_IP>"
                        )
                    })

        # ── ESC11: RPC encryption disabled on CA ─────────────────────────────
        for ca in cas:
            enc_req = ca.properties.get("enforceencryptionforrequests")
            if enc_req is None:
                enc_req = ca.properties.get("enforce_encryption_for_requests")
            
            interface_flags = ca.properties.get("interfaceflags")
            if interface_flags is None:
                interface_flags = ca.properties.get("interface_flags")
            
            is_esc11 = False
            if enc_req is not None:
                is_esc11 = not _as_bool(enc_req)
            elif interface_flags is not None:
                flags = _as_int(interface_flags)
                is_esc11 = (flags & 0x200) == 0
            
            if is_esc11:
                items.append({
                    "esc": "ESC11",
                    "ca": ca.name,
                    "severity": Severity.HIGH,
                    "description": (
                        f"CA '{ca.name}' does not enforce RPC encryption for certificate request interfaces "
                        "(enforceencryptionforrequests is False or IF_ENFORCEENCRYPTICERTREQUEST is not set). "
                        "This allows attackers to relay NTLM authentication to the CA's RPC interface."
                    ),
                    "playbook": (
                        f"certipy relay -target rpc://{ca.extras.get('dnsname', '<CA_HOST>')} "
                        f"-ca '{ca.extras.get('caname', ca.name)}' -template DomainController"
                    )
                })

        # ── ESC12: YubiHSM key storage ───────────────────────────────────────
        for ca in cas:
            yubihsm = ca.properties.get("yubihsm")
            if yubihsm is None:
                yubihsm = ca.properties.get("yubi_hsm")
            hsm = ca.properties.get("hsm")
            
            is_esc12 = _as_bool(yubihsm) or _as_bool(hsm)
            if is_esc12:
                items.append({
                    "esc": "ESC12",
                    "ca": ca.name,
                    "severity": Severity.HIGH,
                    "description": (
                        f"CA '{ca.name}' uses YubiHSM/HSM for private key storage. "
                        "If the YubiHSM Key Storage Provider authentication credentials are "
                        "stored in plaintext in the Windows Registry (AuthKeysetPassword), "
                        "a local unprivileged user on the CA server can retrieve them and forge certificates."
                    ),
                    "playbook": (
                        f"# Extract YubiHSM authentication password from CA registry:\n"
                        f"reg query HKLM\\SOFTWARE\\Yubico\\YubiHSM\\ /v AuthKeysetPassword"
                    )
                })

        if not items:
            return None

        # Sort by severity
        sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2}
        items.sort(key=lambda x: sev_order.get(x.get("severity", Severity.MEDIUM), 3))

        # Determine overall severity
        overall_sev = Severity.HIGH
        if any(i["severity"] == Severity.CRITICAL for i in items):
            overall_sev = Severity.CRITICAL

        # Build playbooks list
        playbooks = [i["playbook"] for i in items if i.get("playbook")]

        esc_types = sorted(set(i["esc"] for i in items))
        summary = (
            f"Found {len(items)} AD CS misconfiguration(s) across "
            f"{len(templates)} template(s) and {len(cas)} CA(s). "
            f"Affected ESC types: {', '.join(esc_types)}."
        )

        return Finding(
            title="AD CS Misconfigurations",
            severity=overall_sev,
            summary=summary,
            data=items,
            recommendation=(
                "Audit all certificate templates and CAs with Certipy: "
                "`certipy find -u '<USER>' -p '<PASS>' -dc-ip <DC_IP> -vulnerable`. "
                "Remove ENROLLEE_SUPPLIES_SUBJECT from templates, disable unused EKUs, "
                "restrict enrollment permissions, and disable the EDITF flag."
            ),
            eli5=(
                "Active Directory Certificate Services (AD CS) issues certificates that can "
                "be used to authenticate as any user. If the certificate templates or CA "
                "settings are misconfigured, an attacker can request a certificate as "
                "Domain Admin and take over the entire domain — without changing any "
                "passwords or triggering traditional security alerts. These are some of "
                "the stealthiest and most reliable privilege escalation paths available."
            ),
            remediation=(
                "1. Run `certipy find -vulnerable` to enumerate all misconfigured templates.\n"
                "2. Remove ENROLLEE_SUPPLIES_SUBJECT from templates (ESC1).\n"
                "3. Replace Any Purpose / empty EKU with specific EKUs (ESC2).\n"
                "4. Restrict enrollment agent templates (ESC3).\n"
                "5. Audit ACLs on certificate templates (ESC4).\n"
                "6. Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on CAs (ESC6).\n"
                "7. Restrict ManageCA/ManageCertificates permissions (ESC7).\n"
                "8. Disable HTTP enrollment or require EPA (ESC8).\n"
                "9. Require RPC Encryption (IF_ENFORCEENCRYPTICERTREQUEST) on CAs (ESC11).\n"
                "10. Secure or remove plaintext HSM credentials from CA Windows Registry (ESC12)."
            ),
            playbooks=playbooks[:5],  # Cap at 5 most relevant
        )
