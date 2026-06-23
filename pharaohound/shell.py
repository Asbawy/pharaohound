#!/usr/bin/env python3
"""
shell.py — Interactive CLI command shell for Pharaohound.

When invoked with --shell, this module drops the operator into an interactive
prompt after analysis is complete. The shell allows navigating AD objects,
querying attack paths, and printing customized exploitation commands.

Commands:
    nodes [type]       — List loaded AD objects (optionally filter by type)
    find <name>        — Search for a node by name
    info <name>        — Show detailed information about a node
    paths              — List all discovered attack paths
    path <index>       — Show detailed steps for a specific attack path
    recs               — Show prioritized recommendations
    commands <name>    — Show exploitation commands for a specific right/edge
    stats              — Show domain statistics
    help               — Show this help message
    exit / quit        — Exit the shell
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional

from .intelligence import intel_for_right, EDGE_INTELLIGENCE
from .models import ObjectStore
from .theme import Colors, colorize


def _input_safe(prompt: str) -> Optional[str]:
    """Read input with graceful EOF/interrupt handling."""
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return None


class PharaohoundShell:
    """
    Interactive exploration shell for post-analysis navigation.

    The operator can browse objects, view attack paths, and get
    copy-paste-ready exploitation commands.
    """

    HELP_TEXT = f"""{colorize('═══════════════════════════════════════════════════════════════════════════', Colors.GOLD)}
{colorize('  ☥  PHARAOHOUND INTERACTIVE SHELL', Colors.GOLD)}
{colorize('═══════════════════════════════════════════════════════════════════════════', Colors.GOLD)}

  {colorize('nodes [type]', Colors.TURQUOISE)}        List loaded AD objects (types: user, group, computer, gpo, ou, domain, ca, certtemplate, azure)
  {colorize('find <name>', Colors.TURQUOISE)}         Search for a node by partial name match
  {colorize('info <name>', Colors.TURQUOISE)}         Show detailed information about a node (ACEs, properties)
  {colorize('paths', Colors.TURQUOISE)}               List all discovered attack paths with OpSec ratings
  {colorize('path <index>', Colors.TURQUOISE)}        Show detailed steps for a specific attack path (1-indexed)
  {colorize('recs', Colors.TURQUOISE)}                Show prioritized recommendations
  {colorize('commands <right>', Colors.TURQUOISE)}     Show exploitation playbooks for a BloodHound edge/right
  {colorize('edges', Colors.TURQUOISE)}               List all known edge types with intelligence
  {colorize('stats', Colors.TURQUOISE)}               Show domain statistics
  {colorize('help', Colors.TURQUOISE)}                Show this help message
  {colorize('exit / quit', Colors.TURQUOISE)}         Exit the shell
"""

    def __init__(
        self,
        store: ObjectStore,
        findings: List[Dict[str, Any]],
        attack_paths: List[Dict[str, Any]],
        recommendations: List[Dict[str, Any]],
    ) -> None:
        self.store = store
        self.findings = findings
        self.attack_paths = attack_paths
        self.recommendations = recommendations

    def run(self) -> None:
        """Main shell loop."""
        print(f"\n{colorize('[☥] Entering interactive shell. Type', Colors.GOLD)} "
              f"{colorize('help', Colors.TURQUOISE)} {colorize('for commands.', Colors.GOLD)}\n")

        while True:
            line = _input_safe(f"  {colorize('☥', Colors.GOLD)} {colorize('pharaohound', Colors.TURQUOISE)}> ")
            if line is None:
                print(f"\n{colorize('[☥] Exiting shell.', Colors.GOLD)}")
                break
            if not line:
                continue

            parts = line.split(maxsplit=1)
            cmd = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            if cmd in ("exit", "quit", "q"):
                print(f"{colorize('[☥] Exiting shell.', Colors.GOLD)}")
                break
            elif cmd == "help":
                print(self.HELP_TEXT)
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
            else:
                print(f"  {colorize('[?]', Colors.OCHRE)} Unknown command: {cmd}. Type 'help' for available commands.")

    # ── Command implementations ──────────────────────────────────────────────

    def _cmd_stats(self) -> None:
        stats = self.store.stats()
        print(f"\n  {colorize('Domain Statistics:', Colors.GOLD)}")
        for k, v in stats.items():
            if v > 0:
                print(f"    {colorize(k.capitalize(), Colors.TURQUOISE)}: {v}")
        print(f"    {colorize('Findings:', Colors.OCHRE)} {len(self.findings)}")
        print(f"    {colorize('Attack Paths:', Colors.OCHRE)} {len(self.attack_paths)}")
        print(f"    {colorize('Recommendations:', Colors.OCHRE)} {len(self.recommendations)}")
        print()

    def _cmd_nodes(self, type_filter: str) -> None:
        type_filter = type_filter.strip().lower()
        objects = self.store.all_objects()
        if type_filter:
            objects = [o for o in objects if o.object_type == type_filter]
        if not objects:
            print(f"  {colorize('[!]', Colors.OCHRE)} No objects found" +
                  (f" of type '{type_filter}'" if type_filter else "") + ".")
            return
        print(f"\n  {colorize(f'Objects ({len(objects)}):', Colors.GOLD)}")
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
            print(f"    {colorize(f'  ... and {len(objects) - 50} more', Colors.DIM)}")
        print()

    def _cmd_find(self, query: str) -> None:
        if not query:
            print(f"  {colorize('[!]', Colors.OCHRE)} Usage: find <name>")
            return
        query_upper = query.upper()
        matches = [o for o in self.store.all_objects() if query_upper in o.name.upper()]
        if not matches:
            print(f"  {colorize('[!]', Colors.OCHRE)} No objects matching '{query}'.")
            return
        print(f"\n  {colorize(f'Search results for \"{query}\" ({len(matches)} matches):', Colors.GOLD)}")
        for obj in matches[:20]:
            print(f"    {colorize(f'[{obj.object_type}]', Colors.DIM)} {obj.name} (SID: {obj.sid[:20]}...)")
        if len(matches) > 20:
            print(f"    {colorize(f'  ... and {len(matches) - 20} more', Colors.DIM)}")
        print()

    def _cmd_info(self, query: str) -> None:
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
            # Try partial match
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

        # Show key extras
        interesting_keys = ["hasspn", "spns", "dontreqpreauth", "unconstraineddelegation",
                          "trustedtoauth", "haslaps", "os", "has_editf_flag", "web_enrollment",
                          "client_auth", "enrollee_supplies_subject", "azure_type"]
        extras_shown = False
        for k in interesting_keys:
            if k in obj.extras and obj.extras[k]:
                if not extras_shown:
                    print(f"  {colorize('Properties:', Colors.GOLD)}")
                    extras_shown = True
                print(f"    {colorize(k, Colors.TURQUOISE)}: {obj.extras[k]}")

        # Show ACEs summary
        if obj.aces:
            rights = [a.get("RightName", "") for a in obj.aces if isinstance(a, dict) and a.get("RightName")]
            unique_rights = sorted(set(rights))
            if unique_rights:
                print(f"  {colorize(f'ACEs ({len(obj.aces)} total, {len(unique_rights)} unique rights):', Colors.GOLD)}")
                for r in unique_rights[:10]:
                    print(f"    → {r}")

        print(f"  {colorize('═' * 60, Colors.GOLD)}\n")

    def _cmd_paths(self) -> None:
        if not self.attack_paths:
            print(f"  {colorize('[✓]', Colors.MALACHITE)} No attack paths detected.")
            return
        print(f"\n  {colorize(f'Attack Paths ({len(self.attack_paths)}):', Colors.GOLD)}")
        for i, p in enumerate(self.attack_paths, 1):
            opsec = p.get("opsec_label", "")
            sev = p.get("severity", "")
            sev_colors = {"CRITICAL": Colors.CARNELIAN, "HIGH": Colors.OCHRE, "MEDIUM": Colors.GOLD}
            col = sev_colors.get(sev, Colors.DIM)
            print(f"    {colorize(f'{i:>3}.', Colors.TURQUOISE)} [{colorize(sev, col)}] {p['name']}  {opsec}")
        print(f"\n  {colorize('Use', Colors.DIM)} {colorize('path <number>', Colors.TURQUOISE)} {colorize('to see details.', Colors.DIM)}\n")

    def _cmd_path_detail(self, arg: str) -> None:
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

    def _cmd_recs(self) -> None:
        if not self.recommendations:
            print(f"  {colorize('[✓]', Colors.MALACHITE)} No recommendations — domain looks healthy.")
            return
        print(f"\n  {colorize(f'Recommendations ({len(self.recommendations)}):', Colors.GOLD)}")
        for r in self.recommendations:
            sev_colors = {"CRITICAL": Colors.CARNELIAN, "HIGH": Colors.OCHRE, "MEDIUM": Colors.GOLD}
            col = sev_colors.get(r["severity"], Colors.DIM)
            opsec = r.get("opsec_label", "")
            priority = r.get("priority", 3)
            title = r.get("title", "")
            print(f"  {colorize(f'[P{priority}]', col)} {colorize(title, col)}  {opsec}")
            print(f"    {colorize('Action:', Colors.DIM)} {r.get('action', '')}")
            print(f"    {colorize('$', Colors.SAND)} {r.get('command', '')}")
            if r.get("alt_commands"):
                for alt in r["alt_commands"][:2]:
                    print(f"    {colorize('Alt:', Colors.DIM)} {alt}")
            print()

    def _cmd_commands(self, right: str) -> None:
        if not right:
            print(f"  {colorize('[!]', Colors.OCHRE)} Usage: commands <right>  (e.g., 'commands GenericAll')")
            return
        # Try exact match first, then case-insensitive
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
                print(f"    {colorize(f'[{target_type}]:', Colors.OCHRE)}")
                for cmd in cmds:
                    print(f"      {colorize('$', Colors.SAND)} {cmd}")
        if intel.get("remediation"):
            print(f"\n  {colorize('Remediation:', Colors.MALACHITE)} {intel['remediation']}")
        print(f"  {colorize('═' * 60, Colors.GOLD)}\n")

    def _cmd_edges(self) -> None:
        print(f"\n  {colorize(f'Known Edge/Right Types ({len(EDGE_INTELLIGENCE)}):', Colors.GOLD)}")
        for key, val in sorted(EDGE_INTELLIGENCE.items()):
            sev = val.get("severity", "INFO")
            sev_colors = {"CRITICAL": Colors.CARNELIAN, "HIGH": Colors.OCHRE, "MEDIUM": Colors.GOLD, "LOW": Colors.TURQUOISE}
            col = sev_colors.get(sev, Colors.DIM)
            print(f"    {colorize(f'[{sev[:4]}]', col)} {colorize(key, Colors.TURQUOISE)}  — {val.get('short', '')}")
        print(f"\n  {colorize('Use', Colors.DIM)} {colorize('commands <edge>', Colors.TURQUOISE)} {colorize('for details.', Colors.DIM)}\n")


def run_shell(
    store: ObjectStore,
    findings: List[Dict[str, Any]],
    attack_paths: List[Dict[str, Any]],
    recommendations: List[Dict[str, Any]],
) -> None:
    """Entry point for the interactive shell."""
    shell = PharaohoundShell(store, findings, attack_paths, recommendations)
    shell.run()
