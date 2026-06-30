#!/usr/bin/env python3
"""
shell.py — Pharaohound Framework Interactive Shell.

The primary interface for operators. When invoked with ``pharaohound``
(no arguments) or ``pharaohound --shell``, this module drops the user
into an interactive framework prompt with commands for:

  - Data collection (``collect``)
  - Data loading (``load``)
  - Analysis (``analyze``)
  - AD object exploration (``nodes``, ``find``, ``info``)
  - Attack path navigation (``paths``, ``path``)
  - Recommendations (``recs``)
  - Exploitation playbooks (``commands``, ``edges``)
  - Report export (``export``)
  - Framework variables (``set``, ``unset``, ``options``)
  - Status and utilities (``status``, ``banner``, ``clear``, ``history``)

Commands:
    collect            Start AD data collection (interactive prompts)
    load <dir>         Load BloodHound JSON files from a directory
    analyze            Run all analyzers on loaded data
    set <key> <val>    Set a framework variable
    unset <key>        Remove a framework variable
    options            Show current framework variables
    nodes [type]       List loaded AD objects
    find <name>        Search for a node by name
    info <name>        Show detailed information about a node
    paths              List all discovered attack paths
    path <index>       Show detailed steps for a specific attack path
    recs               Show prioritized recommendations
    commands <right>   Show exploitation playbooks for a BloodHound edge
    edges              List all known edge types
    stats              Show domain statistics
    export <fmt> [p]   Export report (text/html)
    status             Show framework status
    banner             Show the Pharaohound banner
    clear              Clear the terminal screen
    history            Show command history
    help               Show this help message
    exit / quit        Exit the shell
"""

from __future__ import annotations

import os
import sys
import shlex
from datetime import datetime
from typing import Any, Dict, List, Optional

from .intelligence import EDGE_INTELLIGENCE
from .models import ObjectStore
from .theme import Colors, colorize, BANNER
from .modules import ModuleRegistry, ExploitResult


# READLINE SETUP
_READLINE_AVAILABLE = False
try:
    if sys.platform == "win32":
        try:
            import pyreadline3 as readline  # type: ignore
            _READLINE_AVAILABLE = True
        except ImportError:
            try:
                import pyreadline as readline  # type: ignore
                _READLINE_AVAILABLE = True
            except ImportError:
                pass
    else:
        import readline  # type: ignore
        _READLINE_AVAILABLE = True
except ImportError:
    pass


# SHELL COMMANDS LIST (for tab completion)
SHELL_COMMANDS = [
    "collect", "load", "analyze",
    "set", "unset", "options", "show",
    "nodes", "find", "info",
    "paths", "path", "recs",
    "commands", "edges", "modules", "exploit",
    "compromised",
    "save", "restore", "sessions",
    "stats", "export", "status",
    "banner", "clear", "history",
    "help", "exit", "quit", "q",
]

COLLECTION_METHODS_LIST = [
    "All", "Default", "DCOnly", "ObjectProps",
    "Trusts", "Container", "CertServices", "ACL",
]

VARIABLE_KEYS = [
    "target", "username", "password", "domain",
    "auth_method", "dns_server", "output_dir",
    "collection_method", "use_zip", "secure",
    "dc_ip", "dc_host", "attacker_host",
    "new_password", "domain_sid", "ca_name", "template_name",
]


def _input_safe(prompt: str) -> Optional[str]:
    """Read input with graceful EOF/interrupt handling."""
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return None


# PHARAOHOUND FRAMEWORK SHELL
class PharaohoundShell:
    """
    Interactive framework shell — the primary Pharaohound interface.

    Manages the full operator workflow: collect → load → analyze → explore.
    """

    PROMPT_TEMPLATE = (
        "  {gold}☥{reset} {turquoise}pharaohound{reset}"
        "{context}> "
    )

    def __init__(
        self,
        store: Optional[ObjectStore] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
        attack_paths: Optional[List[Dict[str, Any]]] = None,
        recommendations: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.store = store or ObjectStore()
        self.findings = findings or []
        self.attack_paths = attack_paths or []
        self.recommendations = recommendations or []

        # Framework variables
        self.variables: Dict[str, str] = {}

        # Stateful Compromised Accounts
        self.compromised_sids: Set[str] = set()

        # State tracking
        self._data_loaded = store is not None and bool(store.all_objects())
        self._analyzed = bool(findings or attack_paths or recommendations)
        self._collection_path: Optional[str] = None
        self._command_history: List[str] = []

        # Exploit Modules
        self.registry = ModuleRegistry()
        self.registry.discover("pharaohound.modules")

        # Setup readline for tab completion
        self._setup_readline()

    def _setup_readline(self) -> None:
        """Configure readline for tab completion and history."""
        if not _READLINE_AVAILABLE:
            return

        def completer(text: str, state: int) -> Optional[str]:
            # Build completion candidates
            candidates = []
            line = readline.get_line_buffer().strip()
            parts = line.split()

            if not parts or (len(parts) == 1 and not line.endswith(" ")):
                # Complete command names
                candidates = [c for c in SHELL_COMMANDS if c.startswith(text.lower())]
            elif parts[0].lower() == "set" and len(parts) <= 2:
                # Complete variable keys
                candidates = [k for k in VARIABLE_KEYS if k.startswith(text.lower())]
            elif parts[0].lower() == "unset" and len(parts) <= 2:
                # Complete set variable keys
                candidates = [k for k in self.variables if k.startswith(text.lower())]
            elif parts[0].lower() == "nodes" and len(parts) <= 2:
                types = ["user", "group", "computer", "domain", "gpo", "ou", "container", "ca", "certtemplate", "azure"]
                candidates = [t for t in types if t.startswith(text.lower())]
            elif parts[0].lower() == "export" and len(parts) <= 2:
                candidates = [f for f in ["text", "html", "both"] if f.startswith(text.lower())]
            elif parts[0].lower() in ("find", "info") and self._data_loaded:
                # Complete with node names (first 50 matching)
                text_upper = text.upper()
                candidates = [
                    obj.name for obj in self.store.all_objects()
                    if text_upper in obj.name.upper()
                ][:50]
            elif parts[0].lower() == "commands":
                candidates = [
                    e for e in EDGE_INTELLIGENCE
                    if e.lower().startswith(text.lower())
                ]
            elif parts[0].lower() == "compromised" and len(parts) <= 2:
                candidates = [c for c in ["add", "remove", "list", "clear"] if c.startswith(text.lower())]
            elif parts[0].lower() == "compromised" and len(parts) > 2 and parts[1].lower() in ("add", "remove"):
                if self._data_loaded:
                    text_upper = text.upper()
                    candidates = [
                        obj.name for obj in self.store.all_objects()
                        if text_upper in obj.name.upper()
                    ][:50]
            elif parts[0].lower() in ("save", "restore") and len(parts) <= 2:
                # Complete with existing session names
                sess_dir = os.path.expanduser("~/.pharaohound/sessions") if sys.platform == "win32" else os.path.abspath(".sessions")
                if os.path.exists(sess_dir):
                    try:
                        candidates = [f[:-5] for f in os.listdir(sess_dir) if f.endswith(".json") and f[:-5].startswith(text.lower())]
                    except Exception:
                        pass

            try:
                return candidates[state]
            except IndexError:
                return None

        try:
            readline.set_completer(completer)
            readline.set_completer_delims(" \t")
            readline.parse_and_bind("tab: complete")
        except AttributeError:
            # E.g. pyreadline3 on Windows might lack set_completer
            pass
        except Exception:
            pass

    @property
    def _prompt(self) -> str:
        """Build the dynamic prompt with context indicators."""
        context_parts = []
        if self._data_loaded:
            domain = self.store.primary_domain_name()
            if domain and domain != "Unknown":
                context_parts.append(f"{Colors.DIM}({domain}){Colors.RESET}")
        if self._analyzed:
            context_parts.append(f"{Colors.MALACHITE}✓{Colors.RESET}")

        context = " " + " ".join(context_parts) if context_parts else ""

        return self.PROMPT_TEMPLATE.format(
            gold=Colors.GOLD,
            turquoise=Colors.TURQUOISE,
            reset=Colors.RESET,
            context=context,
        )

    # MAIN LOOP
    def run(self) -> None:
        """Main shell loop."""
        # Show welcome
        if not self._data_loaded:
            self._show_welcome()
        else:
            print(
                f"\n{colorize('[☥] Entering interactive shell. Type', Colors.GOLD)} "
                f"{colorize('help', Colors.TURQUOISE)} {colorize('for commands.', Colors.GOLD)}\n"
            )

        while True:
            line = _input_safe(self._prompt)
            if line is None:
                # Ctrl+C or Ctrl+D detected
                import time
                frames = ["☥ ⋯", "☥ ⋱", "☥ ⋰", "☥ ⋯"]
                
                # Render a brief spinning warning animation
                print()
                for _ in range(2):
                    for frame in frames:
                        sys.stdout.write(
                            f"\r  {Colors.CARNELIAN}[{frame}]{Colors.RESET} "
                            f"{Colors.GOLD}Warning: Interrupt detected!{Colors.RESET}"
                        )
                        sys.stdout.flush()
                        time.sleep(0.08)
                print()
                
                warning_prompt = (
                    f"  {colorize('[!]', Colors.CARNELIAN)} "
                    f"{colorize('Are you sure you want to exit Pharaohound? [y/N]:', Colors.GOLD)} "
                )
                try:
                    confirm = input(warning_prompt).strip().lower()
                    if confirm in ("y", "yes"):
                        print(f"\n  {colorize('[☥] Exiting Pharaohound. May the sands of time guide you…', Colors.GOLD)}")
                        break
                    else:
                        print(f"  {colorize('[✓] Resuming session.', Colors.MALACHITE)}\n")
                        continue
                except (KeyboardInterrupt, EOFError):
                    # Force exit on second consecutive interrupt
                    print(f"\n  {colorize('[☥] Exiting Pharaohound (forced).', Colors.GOLD)}")
                    break
            if not line:
                continue

            # Record history
            self._command_history.append(line)

            # Parse command
            parts = line.split(maxsplit=1)
            cmd = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            # Dispatch
            # Dispatch with smart error handling
            try:
                if cmd in ("exit", "quit", "q"):
                    print(f"{colorize('[☥] Exiting Pharaohound.', Colors.GOLD)}")
                    break
                elif cmd == "help":
                    self._cmd_help()
                elif cmd == "banner":
                    print(BANNER)
                elif cmd == "clear":
                    os.system("cls" if sys.platform == "win32" else "clear")
                elif cmd == "history":
                    self._cmd_history()
                elif cmd == "status":
                    self._cmd_status()
                elif cmd == "collect":
                    self._cmd_collect(arg)
                elif cmd == "load":
                    self._cmd_load(arg)
                elif cmd == "analyze":
                    self._cmd_analyze()
                elif cmd == "set":
                    self._cmd_set(arg)
                elif cmd == "unset":
                    self._cmd_unset(arg)
                elif cmd in ("options", "show"):
                    if cmd == "show" and arg.strip().lower() == "options":
                        self._cmd_options()
                    elif cmd == "options":
                        self._cmd_options()
                    elif cmd == "show" and not arg:
                        self._cmd_options()
                    else:
                        print(f"  {colorize('[?]', Colors.OCHRE)} Unknown: {line}. Type 'help'.")
                elif cmd == "stats":
                    self._cmd_stats()
                elif cmd == "nodes":
                    self._cmd_nodes(arg)
                elif cmd == "find":
                    self._cmd_find(arg)
                elif cmd == "info":
                    self._cmd_info(arg)
                elif cmd == "paths":
                    self._cmd_paths()
                elif cmd == "path":
                    self._cmd_path_detail(arg)
                elif cmd == "recs":
                    self._cmd_recs()
                elif cmd == "commands":
                    self._cmd_commands(arg)
                elif cmd == "edges":
                    self._cmd_edges()
                elif cmd == "modules":
                    self._cmd_modules()
                elif cmd == "exploit":
                    self._cmd_exploit(arg)
                elif cmd == "export":
                    self._cmd_export(arg)
                elif cmd == "compromised":
                    self._cmd_compromised(arg)
                elif cmd == "save":
                    self._cmd_save_session(arg)
                elif cmd == "restore":
                    self._cmd_restore_session(arg)
                elif cmd == "sessions":
                    self._cmd_sessions()
                else:
                    print(f"  {colorize('[?]', Colors.OCHRE)} Unknown command: {cmd}. Type 'help' for available commands.")
            except Exception as cmd_exc:
                print(f"\n  {colorize('[✗] COMMAND EXECUTION ERROR', Colors.CARNELIAN)}")
                print(f"  Failed to run '{cmd}' with argument '{arg or '(none)'}'.")
                print(f"  Error details: {cmd_exc}")
                print(f"  {colorize('Tip:', Colors.TURQUOISE)} Double-check variables, verify directory paths, or make sure files exist.")
                if "--debug" in sys.argv or "-v" in sys.argv:
                    import traceback
                    traceback.print_exc()
                print()

    # WELCOME & HELP
    def _show_welcome(self) -> None:
        """Show the framework welcome screen."""
        print(BANNER)
        print(f"{colorize('═' * 65, Colors.GOLD)}")
        print(f"{colorize('  ☥  PHARAOHOUND FRAMEWORK — Interactive Mode', Colors.GOLD)}")
        print(f"{colorize('═' * 65, Colors.GOLD)}\n")
        print(f"  {colorize('Quick Start:', Colors.TURQUOISE)}")
        print(f"    1. {colorize('collect', Colors.TURQUOISE)}              — Collect data from Active Directory via LDAP")
        print(f"    2. {colorize('load <dir>', Colors.TURQUOISE)}           — Load existing BloodHound JSON files")
        print(f"    3. {colorize('analyze', Colors.TURQUOISE)}              — Run all security analyzers")
        print(f"    4. {colorize('paths / recs', Colors.TURQUOISE)}         — Explore attack paths & recommendations")
        print(f"    5. {colorize('modules / exploit', Colors.TURQUOISE)}    — Run auto-exploitation modules")
        print(f"    6. {colorize('export html', Colors.TURQUOISE)}          — Generate HTML report\n")
        print(f"  Type {colorize('help', Colors.TURQUOISE)} for all commands.\n")

    HELP_TEXT = ""

    def _cmd_help(self) -> None:
        """Show all available commands."""
        print(f"\n{colorize('═' * 70, Colors.GOLD)}")
        print(f"{colorize('  ☥  PHARAOHOUND FRAMEWORK COMMANDS', Colors.GOLD)}")
        print(f"{colorize('═' * 70, Colors.GOLD)}\n")

        sections = [
            ("Collection & Loading", [
                ("collect", "Start AD data collection (prompts for target/creds)"),
                ("collect --target IP --user U --pass P", "Non-interactive collection"),
                ("load <directory>", "Load BloodHound JSON files from a directory"),
                ("analyze", "Run all security analyzers on loaded data"),
            ]),
            ("Framework Variables", [
                ("set <key> <value>", "Set a framework variable"),
                ("unset <key>", "Remove a framework variable"),
                ("options / show options", "Show all current variable settings"),
            ]),
            ("Exploration", [
                ("nodes [type]", "List loaded AD objects (user/group/computer/…)"),
                ("find <name>", "Search for a node by partial name match"),
                ("info <name>", "Show detailed properties and ACEs for a node"),
                ("stats", "Show domain statistics"),
            ]),
            ("Attack Analysis", [
                ("paths", "List all discovered attack paths with OpSec ratings"),
                ("path <number>", "Show detailed steps for a specific attack path"),
                ("recs", "Show prioritized recommendations"),
                ("commands <edge>", "Show exploitation playbooks for a BloodHound edge"),
                ("edges", "List all known edge types with intelligence"),
                ("modules", "List all available auto-exploitation modules"),
                ("exploit <module>", "Run an auto-exploitation module"),
            ]),
            ("Session Management", [
                ("save [name]", "Save the current work session state to disk"),
                ("restore <name>", "Restore a previously saved session state"),
                ("sessions", "List all saved sessions"),
            ]),
            ("Reporting & Utility", [
                ("export <fmt> [path]", "Export report (text / html / both)"),
                ("status", "Show framework status"),
                ("banner", "Show the Pharaohound banner"),
                ("clear", "Clear the terminal screen"),
                ("history", "Show command history"),
                ("help", "Show this help message"),
                ("exit / quit", "Exit the framework"),
            ]),
        ]

        for section_name, commands in sections:
            print(f"  {colorize(section_name, Colors.GOLD)}")
            for cmd, desc in commands:
                print(f"    {colorize(cmd, Colors.TURQUOISE):<45} {desc}")
            print()

    # COLLECT
    def _cmd_collect(self, arg: str) -> None:
        """Start AD data collection."""
        try:
            from .collector import ADCollector
        except ImportError as e:
            print(
                f"  {colorize('[✗]', Colors.CARNELIAN)} Collector dependencies not available: {e}\n"
                f"  {colorize('Install with:', Colors.DIM)} pip install ldap3"
            )
            return

        # Parse arguments or prompt interactively
        target = self.variables.get("target", "")
        username = self.variables.get("username", "")
        password = self.variables.get("password", "")
        domain = self.variables.get("domain", "")
        auth_method = self.variables.get("auth_method", "ntlm")
        dns_server = self.variables.get("dns_server")
        output_dir = self.variables.get("output_dir", ".")
        method = self.variables.get("collection_method", "All")
        use_zip = self.variables.get("use_zip", "true").lower() in ("true", "1", "yes")
        secure = self.variables.get("secure", "false").lower() in ("true", "1", "yes")

        # Parse inline arguments: collect --target X --user Y --pass Z
        if arg:
            tokens = shlex.split(arg)
            i = 0
            while i < len(tokens):
                if tokens[i] in ("--target", "-t") and i + 1 < len(tokens):
                    target = tokens[i + 1]; i += 2
                elif tokens[i] in ("--user", "-u") and i + 1 < len(tokens):
                    username = tokens[i + 1]; i += 2
                elif tokens[i] in ("--pass", "--password", "-p") and i + 1 < len(tokens):
                    password = tokens[i + 1]; i += 2
                elif tokens[i] in ("--domain", "-d") and i + 1 < len(tokens):
                    domain = tokens[i + 1]; i += 2
                elif tokens[i] == "--auth" and i + 1 < len(tokens):
                    auth_method = tokens[i + 1]; i += 2
                elif tokens[i] == "--dns-server" and i + 1 < len(tokens):
                    dns_server = tokens[i + 1]; i += 2
                elif tokens[i] in ("--output", "-o") and i + 1 < len(tokens):
                    output_dir = tokens[i + 1]; i += 2
                elif tokens[i] == "--method" and i + 1 < len(tokens):
                    method = tokens[i + 1]; i += 2
                elif tokens[i] == "--no-zip":
                    use_zip = False; i += 1
                elif tokens[i] == "--secure":
                    secure = True; i += 1
                else:
                    i += 1

        # Interactive prompts for missing required values
        if not target:
            target = _input_safe(f"  {colorize('Target DC IP/hostname:', Colors.TURQUOISE)} ")
            if not target:
                print(f"  {colorize('[!]', Colors.OCHRE)} Cancelled.")
                return
        if not domain:
            domain = _input_safe(f"  {colorize('Domain (e.g., CORP.LOCAL):', Colors.TURQUOISE)} ")
            if not domain:
                print(f"  {colorize('[!]', Colors.OCHRE)} Cancelled.")
                return
        if not username:
            username = _input_safe(f"  {colorize('Username:', Colors.TURQUOISE)} ")
            if not username:
                print(f"  {colorize('[!]', Colors.OCHRE)} Cancelled.")
                return
        if not password:
            password = _input_safe(f"  {colorize('Password:', Colors.TURQUOISE)} ")
            if not password:
                print(f"  {colorize('[!]', Colors.OCHRE)} Cancelled.")
                return

        # Store variables for reuse
        self.variables["target"] = target
        self.variables["username"] = username
        self.variables["domain"] = domain
        self.variables["auth_method"] = auth_method
        if dns_server:
            self.variables["dns_server"] = dns_server
        self.variables["output_dir"] = output_dir
        self.variables["collection_method"] = method

        # Create and run collector
        collector = ADCollector(
            target=target,
            username=username,
            password=password,
            domain=domain,
            auth_method=auth_method,
            dns_server=dns_server,
            output_dir=output_dir,
            use_zip=use_zip,
            secure=secure,
        )

        if not collector.connect():
            return

        result = collector.collect(method=method)
        collector.disconnect()

        if result:
            self._collection_path = result

            # Ask user if they want to load and analyze
            print()
            choice = _input_safe(
                f"  {colorize('Start analysis on collected data? [Y/n]:', Colors.GOLD)} "
            )
            if choice is None or choice.lower() in ("", "y", "yes"):
                self._cmd_load(result)
                if self._data_loaded:
                    self._cmd_analyze()

    # LOAD
    def _cmd_load(self, arg: str) -> None:
        """Load BloodHound JSON data from a directory."""
        directory = arg.strip()
        if directory.lower() == "--demo":
            self._load_demo_data()
            return

        if not directory:
            directory = _input_safe(f"  {colorize('Directory path:', Colors.TURQUOISE)} ")
            if not directory:
                print(f"  {colorize('[!]', Colors.OCHRE)} Usage: load <directory>")
                return
            if directory.lower() == "--demo":
                self._load_demo_data()
                return

        directory = os.path.abspath(directory)
        if not (os.path.isdir(directory) or (os.path.isfile(directory) and directory.lower().endswith(".zip"))):
            print(f"  {colorize('[✗]', Colors.CARNELIAN)} Not a directory or ZIP file: {directory}")
            return

        print(f"\n{colorize('[⚱] Loading data from:', Colors.TURQUOISE)} {directory}\n")

        from .parsers import load_directory
        self.store = load_directory(
            directory,
            log=lambda s: print(f"  {s}"),
        )

        if self.store.all_objects():
            self._data_loaded = True
            stats = self.store.stats()
            total = stats.get("total", 0)
            print(
                f"\n  {colorize('[✓]', Colors.MALACHITE)} "
                f"Loaded {colorize(str(total), Colors.TURQUOISE)} objects from "
                f"{colorize(self.store.primary_domain_name(), Colors.TURQUOISE)}\n"
            )
        else:
            self._data_loaded = False
            print(f"  {colorize('[✗]', Colors.CARNELIAN)} No BloodHound objects loaded.\n")

    def _load_demo_data(self) -> None:
        """Load a pre-populated mock dataset for training and demonstration."""
        from .models import ADObject
        self.store = ObjectStore()
        
        # 1. Primary Domain
        dom = ADObject(
            sid="S-1-5-21-3312384-884562-1102",
            name="CORP.LOCAL",
            object_type="domain",
            properties={"domain": "CORP.LOCAL", "distinguishedname": "DC=CORP,DC=LOCAL"}
        )
        self.store.register(dom)

        # 2. Users
        usr_jsmith = ADObject(
            sid="S-1-5-21-3312384-884562-1102-1105",
            name="JSMITH@CORP.LOCAL",
            object_type="user",
            properties={
                "domain": "CORP.LOCAL",
                "name": "JSMITH@CORP.LOCAL",
                "objectid": "S-1-5-21-3312384-884562-1102-1105",
                "enabled": True,
                "serviceprincipalnames": ["HTTP/sharepoint.corp.local"],
                "hasspn": True
            },
            aces=[
                {
                    "PrincipalSID": "S-1-5-21-3312384-884562-1102-1105",
                    "RightName": "WriteDacl",
                    "PrincipalType": "user"
                }
            ],
            enabled=True
        )
        usr_jsmith.extras = {
            "spns": ["HTTP/sharepoint.corp.local"],
            "hasspn": True,
        }
        self.store.register(usr_jsmith)

        # 3. Target Group (IT Support)
        grp_it = ADObject(
            sid="S-1-5-21-3312384-884562-1102-1050",
            name="IT_SUPPORT@CORP.LOCAL",
            object_type="group",
            properties={
                "domain": "CORP.LOCAL",
                "name": "IT_SUPPORT@CORP.LOCAL",
                "objectid": "S-1-5-21-3312384-884562-1102-1050"
            },
            aces=[
                {
                    "PrincipalSID": "S-1-5-21-3312384-884562-1102-1050",
                    "RightName": "GenericAll",
                    "PrincipalType": "group"
                }
            ]
        )
        grp_it.raw = {
            "Members": [
                {
                    "ObjectIdentifier": "S-1-5-21-3312384-884562-1102-1105",
                    "ObjectType": "user"
                }
            ]
        }
        self.store.register(grp_it)

        # 4. Domain Admins Group
        grp_da = ADObject(
            sid="S-1-5-21-3312384-884562-1102-512",
            name="DOMAIN ADMINS@CORP.LOCAL",
            object_type="group",
            properties={
                "domain": "CORP.LOCAL",
                "name": "DOMAIN ADMINS@CORP.LOCAL",
                "objectid": "S-1-5-21-3312384-884562-1102-512",
                "highvalue": True
            },
            highvalue=True
        )
        grp_da.raw = {
            "Members": [
                {
                    "ObjectIdentifier": "S-1-5-21-3312384-884562-1102-1050",
                    "ObjectType": "group"
                }
            ]
        }
        self.store.register(grp_da)

        # 5. Domain Controller Computer
        comp_dc = ADObject(
            sid="S-1-5-21-3312384-884562-1102-1000",
            name="DC01.CORP.LOCAL",
            object_type="computer",
            properties={
                "domain": "CORP.LOCAL",
                "name": "DC01.CORP.LOCAL",
                "objectid": "S-1-5-21-3312384-884562-1102-1000",
                "isdc": True
            }
        )
        self.store.register(comp_dc)

        # 6. CA and CertTemplate (ESC1 vulnerability)
        ca_obj = ADObject(
            sid="S-1-5-21-3312384-884562-1102-CA",
            name="CORP-CA",
            object_type="ca",
            properties={"domain": "CORP.LOCAL", "name": "CORP-CA"}
        )
        self.store.register(ca_obj)

        tpl_esc1 = ADObject(
            sid="S-1-5-21-3312384-884562-1102-TPL1",
            name="ESC1-TEMPLATE",
            object_type="certtemplate",
            properties={"domain": "CORP.LOCAL", "name": "ESC1-TEMPLATE"},
            aces=[]
        )
        tpl_esc1.extras = {
            "client_auth": True,
            "enrollee_supplies_subject": True,
            "requires_manager_approval": False,
            "enroll_principals": [
                {
                    "ObjectIdentifier": "S-1-5-11",  # Authenticated Users (Low-priv)
                    "Name": "Authenticated Users"
                }
            ]
        }
        self.store.register(tpl_esc1)

        self._data_loaded = True
        print(f"\n  {colorize('[✓]', Colors.MALACHITE)} Mock playground database populated successfully!")
        print(f"  Loaded {colorize('7', Colors.TURQUOISE)} objects in domain {colorize('CORP.LOCAL', Colors.TURQUOISE)}.")
        print(f"  Type {colorize('analyze', Colors.TURQUOISE)} to run checks on this mock AD topology.\n")

    # ANALYZE
    def _cmd_analyze(self) -> None:
        """Run all analyzers on loaded data."""
        if not self._data_loaded:
            print(f"  {colorize('[!]', Colors.OCHRE)} No data loaded. Use 'load <dir>' or 'collect' first.")
            return

        from .analyzers import REGISTRY
        from .analyzers.base import Finding
        from .attack_paths import build_attack_paths
        from .recommendations import build_recommendations

        print(f"\n{colorize('[☥] Running analyzers…', Colors.GOLD)}\n")

        findings: list[Finding] = []
        for cls in REGISTRY.all_analyzers():
            inst = cls()
            try:
                f = inst.analyze(self.store)
                if f is None:
                    continue
                findings.append(f)
                color = {
                    "CRITICAL": Colors.CARNELIAN, "HIGH": Colors.OCHRE,
                    "MEDIUM": Colors.GOLD, "LOW": Colors.TURQUOISE, "INFO": Colors.DIM,
                }.get(f.severity, Colors.DIM)
                print(f"  {color}[{f.severity:<8}]{Colors.RESET} {inst.name:<32} {Colors.DIM}({len(f.data)} items){Colors.RESET}")
            except Exception as e:
                print(f"  {Colors.CARNELIAN}[ERROR]{Colors.RESET}   {inst.name}: {type(e).__name__}: {e}")

        self.findings = [f.to_dict() for f in findings]
        self.attack_paths = build_attack_paths(self.store, self.findings)
        self.recommendations = build_recommendations(self.store, self.findings)

        # Apply compromised filtering (Reachability Analysis)
        if self.compromised_sids:
            from .reachability import ReachabilityContext
            print(f"  {colorize('[☥] Reachability Analysis active. Filtering to compromised foothold...', Colors.GOLD)}")
            ctx = ReachabilityContext(self.store, list(self.compromised_sids))
            self.findings = ctx.filter_findings(self.findings)
            self.attack_paths = ctx.filter_attack_paths(self.attack_paths)
            self.recommendations = ctx.filter_recommendations(self.recommendations)

        # Apply variable interpolation if variables are set
        if self.variables:
            from .tactical import PlaybookInterpolator
            interpolator = PlaybookInterpolator()
            interpolator._resolved = {k.upper(): v for k, v in self.variables.items()}
            if interpolator.loaded:
                self.findings = interpolator.interpolate_findings(self.findings)
                self.attack_paths = interpolator.interpolate_paths(self.attack_paths)
                self.recommendations = interpolator.interpolate_recommendations(self.recommendations)

        self._analyzed = True

        print(
            f"\n  {colorize('[✓]', Colors.MALACHITE)} Analysis complete: "
            f"{colorize(str(len(self.findings)), Colors.TURQUOISE)} findings, "
            f"{colorize(str(len(self.attack_paths)), Colors.TURQUOISE)} attack paths, "
            f"{colorize(str(len(self.recommendations)), Colors.TURQUOISE)} recommendations\n"
        )

    # VARIABLES
    def _cmd_set(self, arg: str) -> None:
        """Set a framework variable."""
        parts = arg.split(maxsplit=1)
        if len(parts) < 2:
            print(f"  {colorize('[!]', Colors.OCHRE)} Usage: set <key> <value>")
            print(f"  {colorize('Available keys:', Colors.DIM)} {', '.join(VARIABLE_KEYS)}")
            return

        key = parts[0].lower()
        value = parts[1]
        self.variables[key] = value
        # Mask password in display
        display_val = "********" if "pass" in key.lower() else value
        print(f"  {colorize('[✓]', Colors.MALACHITE)} {key} → {display_val}")

    def _cmd_unset(self, arg: str) -> None:
        """Remove a framework variable."""
        key = arg.strip().lower()
        if not key:
            print(f"  {colorize('[!]', Colors.OCHRE)} Usage: unset <key>")
            return
        if key in self.variables:
            del self.variables[key]
            print(f"  {colorize('[✓]', Colors.MALACHITE)} Unset: {key}")
        else:
            print(f"  {colorize('[!]', Colors.OCHRE)} Variable not set: {key}")

    def _cmd_options(self) -> None:
        """Show all framework variables."""
        print(f"\n  {colorize('Framework Variables:', Colors.GOLD)}")
        if not self.variables:
            print(f"    {colorize('(none set)', Colors.DIM)}")
        else:
            max_key = max(len(k) for k in self.variables)
            for key, value in sorted(self.variables.items()):
                display_val = "********" if "pass" in key.lower() else value
                print(f"    {colorize(key, Colors.TURQUOISE):<{max_key + 10}} = {display_val}")
        print()

    # STATUS
    def _cmd_status(self) -> None:
        """Show framework status."""
        print(f"\n  {colorize('Pharaohound Framework Status:', Colors.GOLD)}")

        # Data
        if self._data_loaded:
            stats = self.store.stats()
            print(
                f"    {colorize('Data:', Colors.TURQUOISE)} "
                f"{colorize('LOADED', Colors.MALACHITE)} — "
                f"{stats.get('total', 0)} objects from {self.store.primary_domain_name()}"
            )
        else:
            print(f"    {colorize('Data:', Colors.TURQUOISE)} {colorize('NOT LOADED', Colors.OCHRE)}")

        # Analysis
        if self._analyzed:
            print(
                f"    {colorize('Analysis:', Colors.TURQUOISE)} "
                f"{colorize('COMPLETE', Colors.MALACHITE)} — "
                f"{len(self.findings)} findings, "
                f"{len(self.attack_paths)} paths, "
                f"{len(self.recommendations)} recs"
            )
        else:
            print(f"    {colorize('Analysis:', Colors.TURQUOISE)} {colorize('NOT RUN', Colors.OCHRE)}")

        # Variables
        print(f"    {colorize('Variables:', Colors.TURQUOISE)} {len(self.variables)} set")

        # Collection
        if self._collection_path:
            print(f"    {colorize('Last collection:', Colors.TURQUOISE)} {self._collection_path}")

        print()

    # HISTORY
    def _cmd_history(self) -> None:
        """Show command history."""
        if not self._command_history:
            print(f"  {colorize('[!]', Colors.OCHRE)} No command history.")
            return
        print(f"\n  {colorize('Command History:', Colors.GOLD)}")
        for i, cmd in enumerate(self._command_history[-30:], 1):
            print(f"    {colorize(str(i), Colors.DIM):>6}  {cmd}")
        print()

    # STATS
    def _cmd_stats(self) -> None:
        if not self._data_loaded:
            print(f"  {colorize('[!]', Colors.OCHRE)} No data loaded.")
            return
        stats = self.store.stats()
        print(f"\n  {colorize('Domain Statistics:', Colors.GOLD)}")
        for k, v in stats.items():
            if v > 0:
                print(f"    {colorize(k.capitalize(), Colors.TURQUOISE)}: {v}")
        if self._analyzed:
            print(f"    {colorize('Findings:', Colors.OCHRE)} {len(self.findings)}")
            print(f"    {colorize('Attack Paths:', Colors.OCHRE)} {len(self.attack_paths)}")
            print(f"    {colorize('Recommendations:', Colors.OCHRE)} {len(self.recommendations)}")
        print()

    # NODES
    def _cmd_nodes(self, type_filter: str) -> None:
        if not self._data_loaded:
            print(f"  {colorize('[!]', Colors.OCHRE)} No data loaded.")
            return
        type_filter = type_filter.strip().lower()
        objects = self.store.all_objects()
        if type_filter:
            objects = [o for o in objects if o.object_type == type_filter]
        if not objects:
            print(f"  {colorize('[!]', Colors.OCHRE)} No objects found" +
                  (f" of type '{type_filter}'" if type_filter else "") + ".")
            return
        obj_title = f"Objects ({len(objects)}):"
        print(f"\n  {colorize(obj_title, Colors.GOLD)}")
        for i, obj in enumerate(sorted(objects, key=lambda o: o.name)[:50], 1):
            type_label = colorize(f"[{obj.object_type}]", Colors.DIM)
            flags = []
            if obj.admincount:
                flags.append(colorize("ADMIN", Colors.CARNELIAN))
            if obj.highvalue:
                flags.append(colorize("HIGH-VALUE", Colors.CARNELIAN))
            if obj.extras.get("hasspn"):
                flags.append(colorize("SPN", Colors.OCHRE))
            flag_str = f" ({', '.join(flags)})" if flags else ""
            print(f"    {i:>3}. {type_label} {obj.name}{flag_str}")
        if len(objects) > 50:
            more_msg = f"  ... and {len(objects) - 50} more"
            print(f"    {colorize(more_msg, Colors.DIM)}")
        print()

    # FIND
    def _cmd_find(self, query: str) -> None:
        if not self._data_loaded:
            print(f"  {colorize('[!]', Colors.OCHRE)} No data loaded.")
            return
        if not query:
            print(f"  {colorize('[!]', Colors.OCHRE)} Usage: find <name>")
            return
        query_upper = query.upper()
        matches = [o for o in self.store.all_objects() if query_upper in o.name.upper()]
        if not matches:
            print(f"  {colorize('[!]', Colors.OCHRE)} No objects matching '{query}'.")
            return
        search_title = f'Search results for "{query}" ({len(matches)} matches):'
        print(f"\n  {colorize(search_title, Colors.GOLD)}")
        for obj in matches[:20]:
            print(f"    {colorize(f'[{obj.object_type}]', Colors.DIM)} {obj.name} (SID: {obj.sid[:20]}...)")
        if len(matches) > 20:
            more_msg = f"  ... and {len(matches) - 20} more"
            print(f"    {colorize(more_msg, Colors.DIM)}")
        print()

    # INFO
    def _cmd_info(self, query: str) -> None:
        if not self._data_loaded:
            print(f"  {colorize('[!]', Colors.OCHRE)} No data loaded.")
            return
        if not query:
            print(f"  {colorize('[!]', Colors.OCHRE)} Usage: info <name>")
            return
        query_upper = query.upper()
        obj = None
        for o in self.store.all_objects():
            if o.name.upper() == query_upper:
                obj = o
                break
        if not obj:
            for o in self.store.all_objects():
                if query_upper in o.name.upper():
                    obj = o
                    break
        if not obj:
            print(f"  {colorize('[!]', Colors.OCHRE)} Object not found: {query}")
            return

        print(f"\n  {colorize('═' * 60, Colors.GOLD)}")
        print(f"  {colorize('Node:', Colors.GOLD)} {colorize(obj.name, Colors.TURQUOISE)}")
        print(f"  {colorize('Type:', Colors.DIM)} {obj.object_type}")
        print(f"  {colorize('SID:', Colors.DIM)}  {obj.sid}")
        if obj.domain:
            print(f"  {colorize('Domain:', Colors.DIM)} {obj.domain}")
        print(f"  {colorize('Enabled:', Colors.DIM)} {obj.enabled}")
        print(f"  {colorize('AdminCount:', Colors.DIM)} {obj.admincount}")

        interesting_keys = [
            "hasspn", "spns", "dontreqpreauth", "unconstraineddelegation",
            "trustedtoauth", "haslaps", "os", "has_editf_flag", "web_enrollment",
            "client_auth", "enrollee_supplies_subject", "azure_type",
        ]
        extras_shown = False
        for k in interesting_keys:
            if k in obj.extras and obj.extras[k]:
                if not extras_shown:
                    print(f"  {colorize('Properties:', Colors.GOLD)}")
                    extras_shown = True
                print(f"    {colorize(k, Colors.TURQUOISE)}: {obj.extras[k]}")

        if obj.aces:
            rights = [a.get("RightName", "") for a in obj.aces if isinstance(a, dict) and a.get("RightName")]
            unique_rights = sorted(set(rights))
            if unique_rights:
                aces_title = f"ACEs ({len(obj.aces)} total, {len(unique_rights)} unique rights):"
                print(f"  {colorize(aces_title, Colors.GOLD)}")
                for r in unique_rights[:10]:
                    print(f"    → {r}")

        print(f"  {colorize('═' * 60, Colors.GOLD)}\n")

    # PATHS
    def _cmd_paths(self) -> None:
        if not self._analyzed:
            print(f"  {colorize('[!]', Colors.OCHRE)} Run 'analyze' first.")
            return
        if not self.attack_paths:
            print(f"  {colorize('[✓]', Colors.MALACHITE)} No attack paths detected.")
            return
        paths_title = f"Attack Paths ({len(self.attack_paths)}):"
        print(f"\n  {colorize(paths_title, Colors.GOLD)}")
        for i, p in enumerate(self.attack_paths, 1):
            opsec = p.get("opsec_label", "")
            sev = p.get("severity", "")
            sev_colors = {"CRITICAL": Colors.CARNELIAN, "HIGH": Colors.OCHRE, "MEDIUM": Colors.GOLD}
            col = sev_colors.get(sev, Colors.DIM)
            print(f"    {colorize(f'{i:>3}.', Colors.TURQUOISE)} [{colorize(sev, col)}] {p['name']}  {opsec}")
        print(f"\n  {colorize('Use', Colors.DIM)} {colorize('path <number>', Colors.TURQUOISE)} {colorize('to see details.', Colors.DIM)}\n")

    def _cmd_path_detail(self, arg: str) -> None:
        if not self._analyzed:
            print(f"  {colorize('[!]', Colors.OCHRE)} Run 'analyze' first.")
            return
        try:
            idx = int(arg) - 1
        except (ValueError, TypeError):
            print(f"  {colorize('[!]', Colors.OCHRE)} Usage: path <number>  (e.g., 'path 1')")
            return
        if idx < 0 or idx >= len(self.attack_paths):
            print(f"  {colorize('[!]', Colors.OCHRE)} Invalid path index. Range: 1-{len(self.attack_paths)}")
            return
        p = self.attack_paths[idx]
        print(f"\n  {colorize('═' * 60, Colors.GOLD)}")
        print(f"  {colorize(f'Path {idx + 1}:', Colors.GOLD)} {colorize(p['name'], Colors.TURQUOISE)}")
        print(f"  {colorize('Severity:', Colors.DIM)} {p['severity']}  {p.get('opsec_label', '')}")
        print(f"  {colorize('Summary:', Colors.DIM)} {p['summary']}")
        if p.get("prerequisites"):
            print(f"  {colorize('Prerequisites:', Colors.DIM)} {', '.join(p['prerequisites'])}")
        if p.get("tools"):
            print(f"  {colorize('Tools:', Colors.DIM)} {', '.join(p['tools'])}")
        if p.get("detection_events"):
            print(f"  {colorize('⚠ Detection:', Colors.OCHRE)} {', '.join(p['detection_events'])}")
        print(f"  {colorize('Steps:', Colors.GOLD)}")
        for step in p.get("steps", []):
            for line in step.split("\n"):
                print(f"    {line}")
        print(f"  {colorize('═' * 60, Colors.GOLD)}\n")

    # RECS
    def _cmd_recs(self) -> None:
        if not self._analyzed:
            print(f"  {colorize('[!]', Colors.OCHRE)} Run 'analyze' first.")
            return
        if not self.recommendations:
            print(f"  {colorize('[✓]', Colors.MALACHITE)} No recommendations — domain looks healthy.")
            return
        recs_title = f"Recommendations ({len(self.recommendations)}):"
        print(f"\n  {colorize(recs_title, Colors.GOLD)}")
        for r in self.recommendations:
            sev_colors = {"CRITICAL": Colors.CARNELIAN, "HIGH": Colors.OCHRE, "MEDIUM": Colors.GOLD}
            col = sev_colors.get(r["severity"], Colors.DIM)
            opsec = r.get("opsec_label", "")
            priority = r.get("priority", 3)
            title = r.get("title", "")
            priority_label = f"[P{priority}]"
            print(f"  {colorize(priority_label, col)} {colorize(title, col)}  {opsec}")
            print(f"    {colorize('Action:', Colors.DIM)} {r.get('action', '')}")
            print(f"    {colorize('$', Colors.SAND)} {r.get('command', '')}")
            if r.get("alt_commands"):
                for alt in r["alt_commands"][:2]:
                    print(f"    {colorize('Alt:', Colors.DIM)} {alt}")
            print()

    # COMMANDS / EDGES
    def _cmd_commands(self, right: str) -> None:
        if not right:
            print(f"  {colorize('[!]', Colors.OCHRE)} Usage: commands <right>  (e.g., 'commands GenericAll')")
            return
        intel = EDGE_INTELLIGENCE.get(right)
        if not intel:
            for key, val in EDGE_INTELLIGENCE.items():
                if key.lower() == right.lower():
                    intel = val
                    right = key
                    break
        if not intel:
            print(f"  {colorize('[!]', Colors.OCHRE)} No intelligence entry for '{right}'.")
            print(f"  {colorize('Use', Colors.DIM)} {colorize('edges', Colors.TURQUOISE)} {colorize('to see available types.', Colors.DIM)}")
            return

        print(f"\n  {colorize('═' * 60, Colors.GOLD)}")
        print(f"  {colorize(right, Colors.TURQUOISE)} — {intel.get('short', '')}")
        print(f"  {colorize('Severity:', Colors.DIM)} {intel.get('severity', 'N/A')}")
        if intel.get("eli5"):
            print(f"\n  {colorize('ELI5:', Colors.AMETHYST)}")
            for line in intel["eli5"].split(". "):
                print(f"    {line.strip()}.")
        if intel.get("playbooks"):
            print(f"\n  {colorize('Exploitation Commands:', Colors.TURQUOISE)}")
            for target_type, cmds in intel["playbooks"].items():
                target_label = f"[{target_type}]:"
                print(f"    {colorize(target_label, Colors.OCHRE)}")
                for cmd in cmds:
                    print(f"      {colorize('$', Colors.SAND)} {cmd}")
        if intel.get("remediation"):
            print(f"\n  {colorize('Remediation:', Colors.MALACHITE)} {intel['remediation']}")
        print(f"  {colorize('═' * 60, Colors.GOLD)}\n")

    def _cmd_edges(self) -> None:
        edges_title = f"Known Edge/Right Types ({len(EDGE_INTELLIGENCE)}):"
        print(f"\n  {colorize(edges_title, Colors.GOLD)}")
        for key, val in sorted(EDGE_INTELLIGENCE.items()):
            sev = val.get("severity", "INFO")
            sev_colors = {"CRITICAL": Colors.CARNELIAN, "HIGH": Colors.OCHRE, "MEDIUM": Colors.GOLD, "LOW": Colors.TURQUOISE}
            col = sev_colors.get(sev, Colors.DIM)
            print(f"    {colorize(f'[{sev[:4]}]', col)} {colorize(key, Colors.TURQUOISE)}  — {val.get('short', '')}")
        print(f"\n  {colorize('Use', Colors.DIM)} {colorize('commands <edge>', Colors.TURQUOISE)} {colorize('for details.', Colors.DIM)}\n")

    # EXPORT
    def _cmd_export(self, arg: str) -> None:
        if not self._analyzed:
            print(f"  {colorize('[!]', Colors.OCHRE)} Run 'analyze' first.")
            return

        parts = arg.strip().split(maxsplit=1)
        fmt = parts[0].lower() if parts else "both"
        out_dir = parts[1] if len(parts) > 1 else "."

        if fmt not in ("text", "html", "both"):
            print(f"  {colorize('[!]', Colors.OCHRE)} Format must be: text, html, or both")
            return

        stats = self.store.stats()
        domain = self.store.primary_domain_name()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = os.path.abspath(out_dir)
        os.makedirs(out_dir, exist_ok=True)

        if fmt in ("text", "both"):
            from .reporters import generate_text_report
            path = os.path.join(out_dir, f"pharaohound_report_{ts}.txt")
            generate_text_report(path, stats, domain, self.findings, self.attack_paths, self.recommendations)
            print(f"  {colorize('[✓]', Colors.MALACHITE)} Text report: {path}")

        if fmt in ("html", "both"):
            from .reporters import generate_html_report
            path = os.path.join(out_dir, f"pharaohound_report_{ts}.html")
            generate_html_report(path, stats, domain, self.findings, self.attack_paths, self.recommendations)
            print(f"  {colorize('[✓]', Colors.MALACHITE)} HTML report: {path}")

        print()

    # AUTO-EXPLOITATION MODULES
    def _cmd_modules(self) -> None:
        """List all available auto-exploitation modules."""
        modules = self.registry.list_modules()
        if not modules:
            print(f"  {colorize('[!]', Colors.OCHRE)} No auto-exploitation modules found.")
            return

        print(f"\n  {colorize('Auto-Exploitation Modules', Colors.GOLD)} ({len(modules)}):")
        for mod in modules:
            sev = mod.get("severity", "INFO")
            sev_colors = {"CRITICAL": Colors.CARNELIAN, "HIGH": Colors.OCHRE, "MEDIUM": Colors.GOLD, "LOW": Colors.TURQUOISE}
            col = sev_colors.get(sev, Colors.DIM)
            edge = mod.get('edge_type', 'N/A')
            print(f"    {colorize(f'[{sev[:4]}]', col)} {colorize(mod['name'], Colors.TURQUOISE):<20} Edge: {edge:<15}")
            if mod.get('description'):
                print(f"        {colorize('Desc:', Colors.DIM)} {mod['description'][:80]}...")
        print(f"\n  {colorize('Use', Colors.DIM)} {colorize('exploit <module>', Colors.TURQUOISE)} {colorize('to run a module.', Colors.DIM)}\n")

    def _cmd_exploit(self, arg: str) -> None:
        """Run an auto-exploitation module."""
        import logging
        logger = logging.getLogger("pharaohound.shell")
        
        if not arg or arg.strip() in ("-h", "--help"):
            print(f"  {colorize('[!]', Colors.OCHRE)} Usage: exploit <module> [option=val ...]  (e.g., 'exploit GenericAll target=SUPPORT-DC$')")
            print(f"  {colorize('Use', Colors.DIM)} {colorize('modules', Colors.TURQUOISE)} {colorize('to see available exploits.', Colors.DIM)}")
            return

        # Parse module name and key=val options from arg
        tokens = shlex.split(arg)
        module_name = tokens[0]
        exploit_kwargs = {}
        for token in tokens[1:]:
            if "=" in token:
                k, v = token.split("=", 1)
                exploit_kwargs[k.strip()] = v.strip()

        module_cls = self.registry.get(module_name)
        
        # If not found by exact name, try to find by edge type
        if not module_cls:
            module_cls = self.registry.get_by_edge(module_name)
            
        if not module_cls:
            print(f"  {colorize('[✗]', Colors.CARNELIAN)} Exploit module '{module_name}' not found.")
            return

        print(f"\n{colorize('═' * 70, Colors.GOLD)}")
        print(f"  {colorize('☥  EXPLOIT MODULE:', Colors.GOLD)} {colorize(module_cls.name, Colors.TURQUOISE)}")
        print(f"{colorize('═' * 70, Colors.GOLD)}")
        
        # Instantiate the module
        try:
            # Try to build an LDAP connection if we have credentials
            connection = None
            target = self.variables.get("target") or self.variables.get("dc_ip")
            domain = self.variables.get("domain", "")
            username = self.variables.get("username", "")
            password = self.variables.get("password", "")
            
            if target and username and password:
                try:
                    from .collector.collector import ADCollector
                    auth_method = self.variables.get("auth_method", "ntlm")
                    dns_server = self.variables.get("dns_server")
                    secure = self.variables.get("secure", "false").lower() in ("true", "1", "yes")
                    
                    print(f"  {colorize('[☥] Establishing LDAP connection to target...', Colors.DIM)}")
                    collector = ADCollector(
                        target=target,
                        username=username,
                        password=password,
                        domain=domain,
                        auth_method=auth_method,
                        dns_server=dns_server,
                        secure=secure
                    )
                    if collector.connect():
                        connection = collector.client._conn
                    else:
                        print(f"  {colorize('[!]', Colors.OCHRE)} Could not establish LDAP connection. Exploit may fail.")
                except ImportError:
                    pass

            mod = module_cls(
                connection=connection, 
                config={
                    "credentials": {"username": username, "password": password}, 
                    "output_dir": self.variables.get("output_dir", ".")
                }
            )
        except Exception as e:
            print(f"  {colorize('[✗]', Colors.CARNELIAN)} Failed to initialize module: {e}")
            return

        # Prepare options: inline overrides > framework variables
        prepared_kwargs = {}
        for opt_name, opt in mod._options.items():
            if opt_name in exploit_kwargs:
                prepared_kwargs[opt_name] = exploit_kwargs[opt_name]
            elif opt_name in self.variables:
                prepared_kwargs[opt_name] = self.variables[opt_name]
            elif opt.required:
                # Prompt user for missing required options
                val = _input_safe(f"  {colorize(f'Enter {opt.display_name} ({opt_name})', Colors.TURQUOISE)}: ")
                if not val:
                    print(f"  {colorize('[!]', Colors.OCHRE)} Required option '{opt_name}' omitted. Aborting.")
                    return
                prepared_kwargs[opt_name] = val
                # Save it back to variables for next time
                self.variables[opt_name] = val

        # Validate options
        is_valid, err_msg = mod.validate(**prepared_kwargs)
        if not is_valid:
            print(f"  {colorize('[✗]', Colors.CARNELIAN)} Validation failed: {err_msg}")
            return

        # Check Prerequisites
        print(f"  {colorize('[☥] Checking prerequisites...', Colors.DIM)}")
        try:
            ready, msg = mod.check_prerequisites(**prepared_kwargs)
            if not ready:
                print(f"  {colorize('[✗]', Colors.CARNELIAN)} Prerequisites not met: {msg}")
                return
            print(f"  {colorize('[✓]', Colors.MALACHITE)} Prerequisites met.")
        except Exception as e:
            print(f"  {colorize('[✗]', Colors.CARNELIAN)} Error checking prerequisites: {e}")
            return

        # Run Exploit
        print(f"\n  {colorize('[!] FIRING EXPLOIT...', Colors.CARNELIAN)}")
        try:
            result = mod.exploit(**prepared_kwargs)
            
            print(f"\n  {colorize('═' * 60, Colors.GOLD)}")
            if result.success:
                print(f"  {colorize('[✓] EXPLOIT SUCCESSFUL', Colors.MALACHITE)}")
            else:
                if result.result_type == ExploitResult.PARTIAL:
                    print(f"  {colorize('[~] EXPLOIT PARTIALLY SUCCESSFUL', Colors.OCHRE)}")
                else:
                    print(f"  {colorize('[✗] EXPLOIT FAILED', Colors.CARNELIAN)}")
            
            print(f"  {colorize('Message:', Colors.DIM)} {result.message}")
            
            if result.data:
                print(f"\n  {colorize('Data extracted:', Colors.GOLD)}")
                for k, v in result.data.items():
                    print(f"    {k}: {v}")
                    
            if result.artifacts:
                print(f"\n  {colorize('Artifacts saved:', Colors.GOLD)}")
                for artifact in result.artifacts:
                    print(f"    → {artifact}")
            print(f"  {colorize('═' * 60, Colors.GOLD)}\n")
            
        except Exception as e:
            print(f"\n  {colorize('[✗] FATAL EXPLOIT ERROR', Colors.CARNELIAN)}")
            print(f"  {colorize('An unexpected error occurred while running the exploit:', Colors.DIM)}")
            print(f"  {e}")
            import traceback
            logger.debug(traceback.format_exc())

    # COMPROMISED ACCOUNTS MANAGEMENT
    def _cmd_compromised(self, arg: str) -> None:
        """Manage compromised footholds / accounts."""
        if not self._data_loaded:
            print(f"  {colorize('[!]', Colors.OCHRE)} Load data first to resolve names.")
            return

        parts = arg.strip().split(maxsplit=1)
        subcmd = parts[0].lower() if parts else "list"
        param = parts[1].strip() if len(parts) > 1 else ""

        if subcmd == "list" or not arg:
            print(f"\n  {colorize('Compromised Accounts/Footholds:', Colors.GOLD)}")
            if not self.compromised_sids:
                print(f"    {colorize('(none set — showing all findings and paths)', Colors.DIM)}")
            else:
                for idx, sid in enumerate(sorted(self.compromised_sids), 1):
                    obj = self.store.resolve_sid(sid)
                    print(f"    {idx}. [{obj.object_type}] {colorize(obj.name, Colors.TURQUOISE)} ({sid})")
            print()
        
        elif subcmd == "add":
            if not param:
                print(f"  {colorize('[!]', Colors.OCHRE)} Usage: compromised add <name_or_sid>")
                return
            
            # Resolve the account
            found_obj = None
            if param.upper().startswith("S-1-"):
                found_obj = self.store.resolve_sid(param)
                if not found_obj or not found_obj.name or found_obj.name == "Unknown":
                    found_obj = None
            else:
                # Find by exact name match
                for obj in self.store.all_objects():
                    if obj.name and obj.name.upper() == param.upper():
                        found_obj = obj
                        break
            
            if not found_obj:
                # Try partial match fallback
                matches = []
                for obj in self.store.all_objects():
                    if obj.name and param.upper() in obj.name.upper():
                        matches.append(obj)
                if len(matches) == 1:
                    found_obj = matches[0]
                elif len(matches) > 1:
                    print(f"  {colorize('[!]', Colors.OCHRE)} Ambiguous name '{param}'. Multiple matches:")
                    for m in matches[:5]:
                        print(f"    - {m.name}")
                    return
            
            if not found_obj:
                print(f"  {colorize('[✗]', Colors.CARNELIAN)} Could not resolve account: {param}")
                return
            
            self.compromised_sids.add(found_obj.sid)
            print(f"  {colorize('[✓]', Colors.MALACHITE)} Marked {colorize(found_obj.name, Colors.TURQUOISE)} as compromised.")
            print(f"  {colorize('Note: Run', Colors.DIM)} {colorize('analyze', Colors.GOLD)} {colorize('to recalculate reachable paths.', Colors.DIM)}")

        elif subcmd == "remove":
            if not param:
                print(f"  {colorize('[!]', Colors.OCHRE)} Usage: compromised remove <name_or_sid>")
                return
            
            target_sid = None
            if param.upper().startswith("S-1-"):
                target_sid = param
            else:
                for obj in self.store.all_objects():
                    if obj.name and obj.name.upper() == param.upper():
                        target_sid = obj.sid
                        break
            
            if target_sid in self.compromised_sids:
                self.compromised_sids.remove(target_sid)
                obj = self.store.resolve_sid(target_sid)
                print(f"  {colorize('[✓]', Colors.MALACHITE)} Removed compromised status from {colorize(obj.name, Colors.TURQUOISE)}.")
                print(f"  {colorize('Note: Run', Colors.DIM)} {colorize('analyze', Colors.GOLD)} {colorize('to recalculate reachable paths.', Colors.DIM)}")
            else:
                print(f"  {colorize('[!]', Colors.OCHRE)} Account '{param}' is not in the compromised list.")

        elif subcmd == "clear":
            self.compromised_sids.clear()
            print(f"  {colorize('[✓]', Colors.MALACHITE)} Cleared all compromised accounts.")
            print(f"  {colorize('Note: Run', Colors.DIM)} {colorize('analyze', Colors.GOLD)} {colorize('to recalculate reachable paths.', Colors.DIM)}")
        
        else:
            print(f"  {colorize('[!]', Colors.OCHRE)} Unknown subcommand: {subcmd}. Available: add, remove, list, clear")

    # SESSION SAVE & RESTORE
    def _get_session_dir(self) -> str:
        """Get or create the session directory."""
        # Save in user's home dir or .sessions in project path
        sess_dir = os.path.expanduser("~/.pharaohound/sessions") if sys.platform == "win32" else os.path.abspath(".sessions")
        os.makedirs(sess_dir, exist_ok=True)
        return sess_dir

    def _cmd_save_session(self, arg: str) -> None:
        """Save current session to file."""
        if not self._data_loaded:
            print(f"  {colorize('[!]', Colors.OCHRE)} Cannot save empty session. Load data and analyze first.")
            return

        domain = self.store.primary_domain_name().replace(".", "_").lower()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"session_{domain}_{ts}"

        session_name = arg.strip() or default_name
        if not session_name.endswith(".json"):
            session_name += ".json"

        sess_dir = self._get_session_dir()
        filepath = os.path.join(sess_dir, session_name)

        session_data = {
            "version": "2.0.0",
            "timestamp": datetime.now().isoformat(),
            "domain": self.store.primary_domain_name(),
            "collection_path": self._collection_path,
            "variables": self.variables,
            "compromised_sids": list(self.compromised_sids),
            "analyzed": self._analyzed,
            "findings": self.findings,
            "attack_paths": self.attack_paths,
            "recommendations": self.recommendations,
        }

        # Animate the save process
        import time
        print(f"\n  {colorize('[☥] Packing and sealing session state...', Colors.GOLD)}")
        for frame in [" ⚱ ⋯ ", " ⚱ ⋱ ", " ⚱ ⋰ ", " ⚱ ⋯ "]:
            sys.stdout.write(f"\r  {colorize(frame, Colors.TURQUOISE)} Writing state file...")
            sys.stdout.flush()
            time.sleep(0.1)
        print()

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(session_data, f, indent=2, default=str)
            print(
                f"  {colorize('[✓] SESSION SAVED SUCCESSFUL', Colors.MALACHITE)}\n"
                f"    Name: {colorize(os.path.basename(filepath)[:-5], Colors.TURQUOISE)}\n"
                f"    Path: {colorize(filepath, Colors.DIM)}\n"
            )
        except Exception as e:
            print(f"  {colorize('[✗] Failed to save session:', Colors.CARNELIAN)} {e}\n")

    def _cmd_sessions(self) -> None:
        """List all saved sessions."""
        sess_dir = self._get_session_dir()
        try:
            files = [f for f in os.listdir(sess_dir) if f.endswith(".json")]
        except Exception as e:
            print(f"  {colorize('[✗] Failed to read sessions:', Colors.CARNELIAN)} {e}")
            return

        print(f"\n  {colorize('Saved Pharaohound Sessions:', Colors.GOLD)}")
        if not files:
            print(f"    {colorize('(no saved sessions found)', Colors.DIM)}\n")
            return

        # Read meta for each
        for idx, filename in enumerate(sorted(files), 1):
            filepath = os.path.join(sess_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                dt = datetime.fromisoformat(data.get("timestamp", "")).strftime("%Y-%m-%d %H:%M:%S")
                domain = data.get("domain", "Unknown")
                vars_cnt = len(data.get("variables", {}))
                comp_cnt = len(data.get("compromised_sids", []))
                print(
                    f"    {idx}. {colorize(filename[:-5], Colors.TURQUOISE):<35} "
                    f"{colorize(f'({domain})', Colors.DIM):<25} "
                    f"Saved: {dt}  [vars={vars_cnt}, footholds={comp_cnt}]"
                )
            except Exception:
                print(f"    {idx}. {colorize(filename[:-5], Colors.CARNELIAN)} (CORRUPT)")
        print(f"\n  Use {colorize('restore <name>', Colors.TURQUOISE)} to resume a session.\n")

    def _cmd_restore_session(self, arg: str) -> None:
        """Restore session from file."""
        session_name = arg.strip()
        if not session_name:
            print(f"  {colorize('[!]', Colors.OCHRE)} Usage: restore <session_name>")
            self._cmd_sessions()
            return

        if not session_name.endswith(".json"):
            session_name += ".json"

        sess_dir = self._get_session_dir()
        filepath = os.path.join(sess_dir, session_name)

        if not os.path.exists(filepath):
            print(f"  {colorize('[✗] Session not found:', Colors.CARNELIAN)} {session_name[:-5]}")
            return

        print(f"\n  {colorize('[☥] Opening tomb and restoring session state...', Colors.GOLD)}")
        import time
        for frame in [" ☥ ⋯ ", " ☥ ⋱ ", " ☥ ⋰ ", " ☥ ⋯ "]:
            sys.stdout.write(f"\r  {colorize(frame, Colors.TURQUOISE)} Reconstructing memory graph...")
            sys.stdout.flush()
            time.sleep(0.15)
        print()

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Reconstruct variables and configurations
            self.variables = data.get("variables", {})
            self.compromised_sids = set(data.get("compromised_sids", []))
            self._collection_path = data.get("collection_path")

            # Reload AD Database objects in parallel
            if self._collection_path and os.path.exists(self._collection_path):
                print(f"  {colorize('[⚱] Reloading AD objects from source:', Colors.TURQUOISE)} {self._collection_path}\n")
                from .parsers import load_directory
                self.store = load_directory(
                    self._collection_path,
                    log=lambda s: print(f"    {s}"),
                )
                self._data_loaded = bool(self.store.all_objects())
            else:
                self.store = ObjectStore()
                self._data_loaded = False
                print(f"  {colorize('[!]', Colors.OCHRE)} Original data file no longer exists. Analyzing offline findings only.")

            # Load findings/recommendations
            self.findings = data.get("findings", [])
            self.attack_paths = data.get("attack_paths", [])
            self.recommendations = data.get("recommendations", [])
            self._analyzed = data.get("analyzed", False)

            # Display a beautiful summary panel
            print(f"\n{colorize('═' * 60, Colors.GOLD)}")
            print(f"  {colorize('[✓] SESSION RESTORED SUCCESSFULLY', Colors.MALACHITE)}")
            print(f"{colorize('═' * 60, Colors.GOLD)}")
            print(f"  Domain:          {colorize(data.get('domain', 'N/A'), Colors.TURQUOISE)}")
            if self._data_loaded:
                stats = self.store.stats()
                print(f"  Objects:         {colorize(str(stats.get('total', 0)), Colors.TURQUOISE)} loaded")
            print(f"  Findings:        {colorize(str(len(self.findings)), Colors.TURQUOISE)} restored")
            print(f"  Attack Paths:    {colorize(str(len(self.attack_paths)), Colors.TURQUOISE)} restored")
            print(f"  Compromised:     {colorize(str(len(self.compromised_sids)), Colors.TURQUOISE)} foothold(s) active")
            print(f"{colorize('═' * 60, Colors.GOLD)}\n")

        except Exception as e:
            print(f"  {colorize('[✗] Failed to restore session:', Colors.CARNELIAN)} {e}\n")

# ENTRY POINTS
def run_shell(
    store: ObjectStore,
    findings: List[Dict[str, Any]],
    attack_paths: List[Dict[str, Any]],
    recommendations: List[Dict[str, Any]],
) -> None:
    """Entry point for the interactive shell (post-analysis mode)."""
    from .logging_setup import setup_logging
    setup_logging(verbose=False)
    shell = PharaohoundShell(store, findings, attack_paths, recommendations)
    shell.run()


def run_framework() -> None:
    """Entry point for the framework mode (no prior data)."""
    from .logging_setup import setup_logging
    setup_logging(verbose=False)
    shell = PharaohoundShell()
    shell.run()
