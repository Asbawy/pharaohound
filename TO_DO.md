# ☥ Pharaohound Red Team Enhancements & Tactical Roadmap

This document outlines the strategic roadmap and technical implementation items to transform **Pharaohound** into a state-of-the-art diagnostic, path-finding, and automation engine for Red Team operators. The primary focus is on expanding AD/hybrid abuse coverage, defining strict OpSec ratings, and formatting execution playbooks for direct copy-paste.

---

## 🎯 1. OpSec-Aware Pathing & Risk Analysis

Red Team operations prioritize stealth. Attack paths should be prioritized not only by length (hops) but also by the probability of detection (Audit Noise).

### 🛡️ OpSec Scoring Matrix & Detection Footprints
Path priority scoring will use the following detection penalty system based on known Event IDs:

| Attack Primitive / Edge | Event ID Footprint | Noise Level | Penalty Weight | Description / Bypass Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **LAPS Read / AS-REP Roast** | N/A (Standard reads) | **Low** | `0` | Standard LDAP reads do not generate anomalies. Default target. |
| **Kerberoasting** | Event 4769 (TGS request) | **Low** | `2` | Look for RC4 encryption type (`0x17`) downgrade. Focus on old accounts. |
| **RBCD / Shadow Credentials** | Event 5136 / 4742 | **Medium** | `5` | Writes `msDS-AllowedToAct...` or `msDS-KeyCredentialLink`. |
| **AddMember / Self-Add Group** | Event 4728 / 4732 | **High** | `8` | Direct modification of high-value groups. Highly monitored. |
| **GPO / ACL Abuse** | Event 5136 / 5145 / 4670 | **High** | `8` | Editing templates in SYSVOL or altering DACLs on sensitive AD objects. |
| **ForceChangePassword** | Event 4724 | **Critical** | `10` | User account password reset. Triggers instant security alert. |

*   **Stealth Rating for Paths**: Rank attack paths using a scoring algorithm:
    $$\text{Score} = 100 - (\text{Path Length} \times 5) - \sum(\text{OpSec Penalty})$$
*   **Evasion Guidance**: Annotate playbooks with specific Event ID warnings (e.g., Event 4724, 4670, 5136) and suggested evasion flags (e.g., using `--session` instead of password resets, using LDAP/S over RPC).
*   **Interactive Session Correlator**: Cross-reference `HasSession` edges with `AdminTo` target computers. If local admin is available, map the exact process for dumping LSASS (using silent processes like `nanodump` or `comsvcs.dll` mini-dumps) to hijack cached high-value tokens.

---

## 📜 2. Advanced PKI & AD CS (Active Directory Certificate Services)

PKI misconfigurations provide the most reliable path to Domain Admins without changing passwords.

*   **Misconfiguration Analyzers (ESC1 to ESC8)**:
    *   **ESC1**: Client Authentication EKU + `ENROLLEE_SUPPLIES_SUBJECT` allowing SAN specification.
    *   **ESC2**: Template with Any Purpose EKU or no EKU (acting as a wildcard).
    *   **ESC3**: Enrollment Agent template allowing impersonation during cert request.
    *   **ESC4**: Write permissions (GenericAll/WriteDacl) on templates to overwrite them to ESC1.
    *   **ESC5**: Weak permissions on PKI containers or CA security descriptors.
    *   **ESC6**: CA configured with `EDITF_ATTRIBUTESUBJECTALTNAME2` flag enabled.
    *   **ESC7**: Weak CA permissions (ManageCA / ManageCertificates) allowing approval of pending requests.
    *   **ESC8**: NTLM Relay opportunities against HTTP Enrollment Web Services (CES/CEP/Enroll).
*   **Extended Misconfigurations (ESC9, ESC10, ESC11, ESC12, ESC13)**:
    *   **ESC9**: Template permitting certificate issuance where subject mapping ignores `msDS-KeyCredentialLink` or uses weak mapping rules.
    *   **ESC10**: Registry-level weak certificate-to-user mappings on Domain Controllers.
    *   **ESC11**: CA configured without requiring RPC request encryption, enabling NTLM relay attacks against the RPC endpoint.
    *   **ESC12**: CA private key stored in YubiHSM with authentication credentials stored in plaintext in the CA Windows Registry.
    *   **ESC13**: Templates with Policy OIDs mapping to privileged access groups (OAuth/OIDC resource access).
*   **Certipy Syntax Generator**: Inject dynamic Certipy CLI command templates directly into the playbooks (e.g., requesting, authenticating, and retrieving NT hashes via PKINIT).

---

## ☁️ 3. Hybrid AD & Azure (Entra ID) Attack Paths

On-premises Active Directory and Azure/Entra ID are highly connected in modern enterprise networks.

*   **Azure AD Connect Sync Server Takeover**: Detect if the current compromised host/user has rights to the Azure AD Connect server (usually storing MSOL_ sync credentials). Auto-inject cmdlets for decrypting sync account passwords.
*   **AppRoleAssignment & Owner Abuse**: Detect Service Principals or App Registrations owned by compromised users that hold high privilege Graph API roles (e.g., `RoleManagement.ReadWrite.Directory`).
*   **Azure VM Contributor Pivots**: Map instances where virtual machines running on-premises workloads (such as hybrid runbook workers or domain controllers hosted in Azure) can be compromised via Azure VM Contributor / Command Execution privileges.

---

## 🛠️ 4. Tactical Execution & Variable Interpolation

Operators should not have to manually edit commands before copy-pasting.

*   **Variables Configuration File**: Support an environment JSON/YAML file:
    ```json
    {
      "domain_controller": "10.10.10.10",
      "dc_hostname": "DC01.CORP.LOCAL",
      "attacker_host": "10.10.14.5",
      "compromised_password": "Password123!",
      "target_user": "Administrator",
      "controlled_computer": "EVIL-WORKSTATION$"
    }
    ```
*   **Playbook Interpolation**: Replace template placeholders (e.g., `<DC_IP>`, `<PASSWORD>`, `<TARGET_USER>`, `<CONTROLLED_HOST>$`) with configuration variables dynamically before rendering output to console or HTML reports.
*   **PowerShell Evasion Scripts**: Automatically embed AMSI (Antimalware Scan Interface) and ETW (Event Tracing for Windows) bypass payloads at the start of PowerShell-based playbooks when evasion mode is enabled (`--evasion`).

---

## 👶 5. "Pentest Noob" Mode (`--noob`)

Provides a simplified, high-signal layout for junior operators or clients.

*   **Ultra-Focused Output Filter**: Hide all intermediate hops and long chains. Output ONLY the single shortest path to a Domain Admin or Tier-0 target.
*   **Noob-Friendly Jargon Translation**: Replace complex AD terminology with step-by-step simple instructions (e.g., translate "Kerberoasting" to "Step 1: Get encrypted credential file from active service, Step 2: Crack it offline").
*   **High-Signal Graph Visuals**: Filter the generated HTML report graph to display only the compromised source node, the intermediate target nodes, and the final high-value target (hiding the background noise of standard users/groups).

---

## 📢 6. GitHub Update Notifier

To ensure operators are always running the latest version with the newest analyzers and bug fixes.

*   **Version Baseline**: Establish the initial stable release as `v1.0.0`.
*   **GitHub API Integration**: Fetch the latest release tag from GitHub (`https://api.github.com/repos/<owner>/pharaohound/releases/latest`).
*   **Non-Blocking & Offline Resilient**: Perform the HTTP request with a short, strict timeout (e.g., 1.5s) to guarantee no execution delays on air-gapped or offline networks.
*   **Update Notice**: Render a premium console alert banner notifying the user of the new version and command to pull/update if local version < remote version.

---

## 🧭 Technical Implementation Checklist

### 📡 Phase 1: Ingestion & Model Updates
- [x] **Extend JSON Parsers**: Add PKI/AD CS objects ingestion (`certificates.json`, `containers.json` or equivalent SharpHound outputs).
- [x] **Extend Azure Parsers**: Ingest Azure service principals, roles, and device ownerships.
- [x] **Dynamic Node and Edge Visualizer**: Render Vis.js icons and color schemes for CA, Certificate Template, and Azure Tenant nodes.
- [x] **Refactor Ingestion Fallback**: Stream character-by-character to prevent memory spikes when parsing large JSON exports without `ijson`.

### 🧠 Phase 2: Engine Intelligence & Logic
- [x] **Add AD CS Analyzers**: Subclass `BaseAnalyzer` to register misconfigurations (ESC1 to ESC13) in `pharaohound/analyzers/`.
- [x] **AD CS ESC11 & ESC12**: Detect CA RPC encryption status and YubiHSM key storage with exposed registry credentials.
- [x] **Add Machine Account Quota (MAQ) Checker**: Query `ms-DS-MachineAccountQuota` on domain heads and flag RBCD viability if MAQ > 0.
- [x] **Add gMSA password read analyzer**: Detect users with read access to `msDS-ManagedPassword` on gMSAs.
- [x] **Path Priority Optimizer**: Refactor `recommendations.py` to order attack paths using the OpSec-Aware scoring algorithm.

### 📦 Phase 3: Reporting & Formatting
- [x] **Interactive CLI Command Shell**: Implement a CLI shell (`--shell`) where the operator can navigate from node to node, automatically printing customized command sequences.
- [x] **Variable Interpolation Engine**: Integrate `--variables <config.json>` parsing and command placeholder replacement.
- [x] **CLI Noob Mode Flag**: Implement `--noob` flag to skip complex paths and output simplified text and HTML layout.

### 📢 Phase 4: GitHub Update Notifier & Versioning
- [x] **Release Versioning**: Update all version tags throughout the codebase and documentation to `1.0.0`.
- [x] **Lightweight GitHub Client**: Implement version checking logic using the standard library (`urllib.request`) to avoid external packages.
- [x] **Graceful Timeout handling**: Ensure connection failures or timeouts are handled silently with zero user disruption.
- [x] **CLI Notice Banner**: Design and print a visual update notification when a newer release is detected.

### 🔥 Phase 5: Advanced Offensive Operations & Evasion (Senior Red Team Enhancements)
*(Roadmap for v1.1.0+ / v2.0.0)*

- [x] **Advanced Persistence Analyzers**: Detect capabilities for installing Skeleton Key, Malicious SSPs, or Custom Password Filters on targeted Domain Controllers.
- [x] **Cross-Forest SID History Hopping**: Map out inter-forest trust relationships that allow SID History injection for Enterprise Admin escalation.
- [x] **EDR/XDR Evasion Guidance Engine**: Dynamically inject evasion flags into playbooks to bypass Microsoft Defender for Identity (MDI/ATA) alerts.
- [x] **Automated Ticket Forging Playbooks**: Generate precise Rubeus/Impacket commands for Golden/Silver Tickets when `krbtgt` or specific service accounts are compromised.
- [x] **DCSync Target Optimization**: Identify the "stealthiest" Domain Controller (e.g., outdated OS, lacking EDR agents based on metadata) to target for DCSync operations.
- [x] **Honeytoken & Deception Filtering**: Implement smart node pruning to detect and hide likely honeytokens (e.g., accounts named "admin", "password", with zero activity) to reduce operational risk.
- [x] **Pass-the-Certificate (PTC) Automation**: End-to-end playbooks for UnPAC-the-hash using Certipy/Rubeus after ESC1-13 exploitation.
- [x] **Primary Refresh Token (PRT) Extraction**: Map Azure paths reliant on PRT extraction (using tools like ROADtools) for seamless cloud pivot from compromised endpoints.
- [x] **Conditional Access Policy Bypass**: Analyze Entra ID CA policies to find gaps (e.g., exclusions for specific IP ranges or legacy authentication) to bypass MFA.
- [x] **SCCM / MECM Abuse Mapping**: Correlate Network Access Account (NAA) extraction or SCCM Admin rights to full domain takeover via application deployment.
- [x] **WSUS Exploitation Paths**: Map WSUS Administrators to the servers they control for automated malicious update injection (e.g., WSUSpect).
- [x] **Exchange Trusted Subsystem Escalation**: Map paths where Exchange servers have overly permissive rights on domain objects (PrivExchange/ExchangeAdmin escalation).
- [x] **Windows LAPS (v2) Integration**: Identify and automate the reading of encrypted LAPS passwords using compromised accounts with specific delegation.
- [x] **GPP cpassword Decryption**: Flag legacy Group Policy Preferences containing cpasswords and auto-generate decryption commands.
- [x] **Constrained Delegation Automation**: Generate complete S4U2Self/S4U2Proxy Rubeus chains for Kerberos Constrained Delegation abuse.
- [x] **Unconstrained Delegation + Coercion**: Map paths chaining Unconstrained Delegation servers with authentication coercion techniques (PetitPotam/SpoolSample).
- [x] **WebClient / WebDAV Coercion**: Highlight systems susceptible to WebClient coercion for NTLM relay attacks over HTTP to bypass SMB signing.
- [x] **Cross-Tenant Azure B2B Abuse**: Map external identities and guest accounts with overly privileged roles in target tenants for cross-tenant pivoting.
- [x] **Intune / MDM Device Takeover**: Map primary user relationships in Intune to push malicious PowerShell scripts via Microsoft Endpoint Manager.
- [x] **Seamless SSO (AZUREADSSOACC) Abuse**: Detect compromised AZUREADSSOACC accounts and generate commands for forging Silver Tickets for Entra ID access.
- [x] **Graph API Permission Nuance**: Differentiate between Azure Application permissions and Delegated permissions to provide exact access token commands (e.g., TokenTactics).
- [x] **Shadow Principal & PAM Trust Mapping**: Identify Bastion forests and shadow principal mappings to execute Red Forest (ESA) compromise.
- [x] **AS-REP Roasting Downgrade Automation**: Generate precise requests to target old accounts susceptible to RC4 downgrade for faster cracking.
- [x] **Kerberos Armoring (FAST) Bypass Notes**: Add playbook notes and techniques for bypassing Kerberos Armoring when requesting TGS/TGTs.
