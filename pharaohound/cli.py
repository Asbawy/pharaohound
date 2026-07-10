#!/usr/bin/env python3
"""
cli.py — Pharaohound CLI entry point.

Wires together parsers → user selection → analyzers → reachability filter
→ attack-path builder → reporters.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .analyzers import REGISTRY
from .analyzers.base import Finding
from .attack_paths import build_attack_paths
from .models import ADObject, ObjectStore
from .parsers import load_directory
from .reachability import ReachabilityContext
from .recommendations import build_recommendations
from .reporters import ConsoleReporter, generate_html_report, generate_text_report
from .theme import Colors
from .update import check_for_updates
from . import __version__


def _build_collect_parser() -> argparse.ArgumentParser:
    """Build the parser for the 'collect' subcommand."""
    p = argparse.ArgumentParser(
        prog="pharaohound collect",
        description="Collect AD data via LDAP and save as BloodHound-compatible JSON files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-t", "--target", required=True, help="Target Domain Controller IP or hostname")
    p.add_argument("-u", "--user", dest="coll_user", required=True, help="Username for authentication")
    p.add_argument("-p", "--pass", dest="coll_pass", required=True, help="Password for authentication")
    p.add_argument("-d", "--domain", dest="coll_domain", required=True, help="Domain name (e.g., CORP.LOCAL)")
    p.add_argument("--auth", default="ntlm", choices=["ntlm", "simple", "kerberos"],
                    help="Authentication method (default: ntlm)")
    p.add_argument("--dns-server", default=None, help="Custom DNS server IP")
    p.add_argument("-o", "--output", dest="coll_output", default=".", help="Output directory (default: cwd)")
    p.add_argument("--method", default="All",
                    choices=["All", "Default", "DCOnly", "ObjectProps", "Trusts", "Container", "CertServices", "ACL"],
                    help="Collection method (default: All)")
    p.add_argument("--no-zip", action="store_true", help="Save individual JSON files instead of ZIP")
    p.add_argument("--secure", action="store_true", help="Use LDAPS (SSL/TLS)")
    p.add_argument("--analyze", action="store_true", help="Automatically analyze after collection")
    return p


def _build_main_parser() -> argparse.ArgumentParser:
    """Build the main analysis parser."""
    p = argparse.ArgumentParser(
        prog="pharaohound",
        description="Pharaohound — BloodHound JSON Analysis Engine & AD Collection Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  pharaohound                                     # Launch interactive framework shell\n"
            "  pharaohound /path/to/bloodhound_jsons/           # Analyze existing data\n"
            "  pharaohound /path/to/jsons/ --user JSMITH@CORP.LOCAL\n"
            "  pharaohound collect --target 10.10.10.10 --user admin --pass 'P@ss' --domain CORP.LOCAL\n"
            "  pharaohound /path/to/jsons/ --all --output ./reports/\n"
        ),
    )
    p.add_argument("directory", nargs="?", help="Directory containing BloodHound JSON files (omit for interactive shell)")
    p.add_argument("-o", "--output", default=".", help="Output directory for reports (default: cwd)")
    p.add_argument(
        "--format", choices=["text", "html", "both", "console-only"], default="both",
        help="Report format (default: both = text + html + console)",
    )
    p.add_argument("--user", action="append", default=None,
                   help="Compromised user (USER@DOMAIN). Can be specified multiple times. Skips interactive selection.")
    p.add_argument("--all", action="store_true", dest="scan_all",
                   help="Run full unfiltered scan (skip user selection)")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    p.add_argument("--no-rich", action="store_true", help="Disable rich tables, use plain ASCII fallback")
    p.add_argument("--workers", type=int, default=None, help="Parallel parser worker count (default: min(8, n_files))")
    p.add_argument("--list-analyzers", action="store_true", help="List all available analyzers and exit")
    p.add_argument("--list-modules", action="store_true", help="List all auto-exploitation modules and exit")
    p.add_argument("--verbose", action="store_true", help="Verbose output")
    p.add_argument("--noob", action="store_true", help="Noob mode: simplified output with jargon-free language")
    p.add_argument("--evasion", action="store_true", help="Evasion mode: prepend AMSI/ETW bypass payloads to PowerShell playbooks")
    p.add_argument("--vars", "--variables", dest="variables", default=None,
                   help="Path to a JSON file with environment variables for command interpolation")
    p.add_argument("--shell", action="store_true",
                   help="Drop into an interactive shell after analysis for exploring results")
    return p


def parse_args(argv=None) -> argparse.Namespace:
    """
    Parse CLI arguments with manual 'collect' subcommand detection.

    Avoids argparse conflicts between subparsers and optional positional args
    by checking if the first argument is 'collect' before dispatching.
    """
    raw_argv = argv if argv is not None else sys.argv[1:]

    # Check if user invoked the 'collect' subcommand
    if raw_argv and raw_argv[0] == "collect":
        parser = _build_collect_parser()
        args = parser.parse_args(raw_argv[1:])
        args.subcommand = "collect"
        return args

    # Otherwise parse with the main parser
    parser = _build_main_parser()
    args = parser.parse_args(raw_argv)
    args.subcommand = None
    return args


def disable_colors() -> None:
    """Strip ANSI codes globally by patching the Colors class."""
    for attr in dir(Colors):
        if attr.isupper() and isinstance(getattr(Colors, attr), str):
            setattr(Colors, attr, "")


# USER SELECTION
def _resolve_user_by_name(store: ObjectStore, name: str) -> Optional[ADObject]:
    """Find a user by name (case-insensitive, supports USER@DOMAIN or just USER)."""
    name_upper = name.strip().upper()
    for user in store.users.values():
        if user.name.upper() == name_upper:
            return user
    # Try without @DOMAIN suffix
    base_name = name_upper.split("@")[0] if "@" in name_upper else name_upper
    for user in store.users.values():
        user_base = user.name.upper().split("@")[0]
        if user_base == base_name:
            return user
    return None


def select_compromised_users(store: ObjectStore, args: argparse.Namespace) -> Optional[List[str]]:
    """
    Interactive or argument-driven user selection.

    Returns:
        List of compromised user SIDs, or None for full unfiltered scan.
    """
    # --all flag: skip selection entirely
    if args.scan_all:
        return None

    # --user flag: resolve names to SIDs
    if args.user:
        resolved_sids = []
        for name in args.user:
            user = _resolve_user_by_name(store, name)
            if user:
                resolved_sids.append(user.sid)
                print(f"  {Colors.MALACHITE}[✓]{Colors.RESET} Compromised: {Colors.TURQUOISE}{user.name}{Colors.RESET} (SID: {user.sid})")
            else:
                print(f"  {Colors.CARNELIAN}[✗]{Colors.RESET} User not found: {name}")
        if not resolved_sids:
            print(f"\n{Colors.CARNELIAN}[✗] No valid users specified. Use --all for full scan.{Colors.RESET}")
            return None  # fallback to full scan
        print()
        return resolved_sids

    # Interactive selection
    enabled_users = sorted(
        [u for u in store.users.values() if u.enabled],
        key=lambda u: u.name,
    )
    if not enabled_users:
        print(f"  {Colors.OCHRE}[!] No enabled users found. Running full scan.{Colors.RESET}\n")
        return None

    print(f"{Colors.GOLD}{'═' * 75}{Colors.RESET}")
    print(f"{Colors.GOLD}  ☥  SELECT COMPROMISED USER(S){Colors.RESET}")
    print(f"{Colors.GOLD}{'═' * 75}{Colors.RESET}\n")
    print(f"  {Colors.DIM}Which user account(s) have you compromised?{Colors.RESET}")
    print(f"  {Colors.DIM}The analysis will show only what is reachable from your position.{Colors.RESET}\n")

    # Print numbered list with useful context
    for i, user in enumerate(enabled_users, 1):
        # Show useful flags next to each user
        tags = []
        if user.admincount:
            tags.append(f"{Colors.CARNELIAN}ADMIN{Colors.RESET}")
        if user.extras.get("hasspn"):
            tags.append(f"{Colors.OCHRE}SPN{Colors.RESET}")
        if user.extras.get("dontreqpreauth"):
            tags.append(f"{Colors.OCHRE}ASREP{Colors.RESET}")
        if user.extras.get("unconstraineddelegation"):
            tags.append(f"{Colors.CARNELIAN}UD{Colors.RESET}")
        tag_str = f" [{', '.join(tags)}]" if tags else ""
        print(f"  {Colors.TURQUOISE}{i:>4}{Colors.RESET}. {user.name}{tag_str}")

    print(f"\n  {Colors.DIM}─────────────────────────────────────────────────────{Colors.RESET}")
    print(f"  {Colors.DIM}Enter number(s) separated by commas, or type 'all' for full scan.{Colors.RESET}")
    print(f"  {Colors.DIM}Example: 1,3,5  or  all{Colors.RESET}\n")

    try:
        choice = input(f"  {Colors.GOLD}☥ Your choice: {Colors.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        print(f"\n  {Colors.OCHRE}[!] No selection. Running full scan.{Colors.RESET}\n")
        return None

    if not choice or choice.lower() == "all":
        print(f"\n  {Colors.MALACHITE}[✓] Running full unfiltered scan.{Colors.RESET}\n")
        return None

    # Parse comma-separated numbers
    selected_sids = []
    for part in choice.split(","):
        part = part.strip()
        try:
            idx = int(part)
            if 1 <= idx <= len(enabled_users):
                user = enabled_users[idx - 1]
                selected_sids.append(user.sid)
                print(f"  {Colors.MALACHITE}[✓]{Colors.RESET} Selected: {Colors.TURQUOISE}{user.name}{Colors.RESET}")
            else:
                print(f"  {Colors.CARNELIAN}[✗]{Colors.RESET} Invalid number: {part} (must be 1-{len(enabled_users)})")
        except ValueError:
            # Try as a username
            user = _resolve_user_by_name(store, part)
            if user:
                selected_sids.append(user.sid)
                print(f"  {Colors.MALACHITE}[✓]{Colors.RESET} Selected: {Colors.TURQUOISE}{user.name}{Colors.RESET}")
            else:
                print(f"  {Colors.CARNELIAN}[✗]{Colors.RESET} Not found: {part}")

    if not selected_sids:
        print(f"\n  {Colors.OCHRE}[!] No valid selection. Running full scan.{Colors.RESET}\n")
        return None

    print()
    return selected_sids


def run_collect(args: argparse.Namespace) -> int:
    """Handle the 'collect' subcommand."""
    try:
        from .collector import ADCollector
    except ImportError as e:
        print(f"{Colors.CARNELIAN}[✗] Collector dependencies missing: {e}{Colors.RESET}")
        print(f"{Colors.OCHRE}    Install with: pip install ldap3{Colors.RESET}")
        return 1

    collector = ADCollector(
        target=args.target,
        username=args.coll_user,
        password=args.coll_pass,
        domain=args.coll_domain,
        auth_method=args.auth,
        dns_server=args.dns_server,
        output_dir=args.coll_output,
        use_zip=not args.no_zip,
        secure=args.secure,
    )

    if not collector.connect():
        return 1

    result = collector.collect(method=args.method)
    collector.disconnect()

    if not result:
        return 1

    # Auto-analyze if requested
    if args.analyze and os.path.isdir(args.coll_output):
        print(f"\n{Colors.GOLD}[☥] Auto-analyzing collected data…{Colors.RESET}\n")
        # Re-run the analysis pipeline on the collected output
        analysis_argv = [args.coll_output, "--all", "-o", args.coll_output]
        return run(analysis_argv)

    return 0


def run(argv=None) -> int:
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass

    args = parse_args(argv)

    if args.no_color:
        disable_colors()

    from .logging_setup import setup_logging
    setup_logging(verbose=args.verbose)

    reporter = ConsoleReporter(use_rich=not args.no_rich)
    reporter.banner()

    # Check for updates from GitHub (non-blocking, 1.0s timeout)
    new_release = check_for_updates(__version__, timeout=1.0)
    if new_release:
        print(f"{Colors.GOLD}[📢] A newer version of Pharaohound is available: {Colors.TURQUOISE}{new_release}{Colors.GOLD} (Current: v{__version__}){Colors.RESET}")
        print(f"{Colors.GOLD}     Update via: {Colors.TURQUOISE}pip install --upgrade git+https://github.com/Asbawy/pharaohound.git{Colors.RESET}\n")

    # Handle 'collect' subcommand
    if hasattr(args, 'subcommand') and args.subcommand == "collect":
        return run_collect(args)

    if args.list_analyzers:
        print(f"{Colors.GOLD}[☥] Registered analyzers:{Colors.RESET}\n")
        for cls in REGISTRY.all_analyzers():
            inst = cls()
            print(f"  {Colors.TURQUOISE}{inst.name:<32}{Colors.RESET}  {inst.description}")
        return 0

    if args.list_modules:
        from .modules import ModuleRegistry
        registry = ModuleRegistry()
        registry.discover("pharaohound.modules")
        print(f"{Colors.GOLD}[☥] Registered auto-exploitation modules:{Colors.RESET}\n")
        for mod in registry.list_modules():
            print(f"  {Colors.TURQUOISE}{mod['name']:<20}{Colors.RESET} Edge: {mod['edge_type']:<15} {Colors.DIM}({mod['severity']}){Colors.RESET}")
            if mod.get('description'):
                print(f"      {Colors.DIM}{mod['description'][:80]}...{Colors.RESET}")
        return 0

    # No directory given = launch framework shell
    if not args.directory:
        from .shell import run_framework
        run_framework(show_banner=False)
        return 0

    directory = os.path.abspath(args.directory)
    if not (os.path.isdir(directory) or (os.path.isfile(directory) and directory.lower().endswith(".zip"))):
        print(f"{Colors.CARNELIAN}[✗] Not a directory or ZIP file: {directory}{Colors.RESET}")
        return 2

    # 1. PARSE
    print(f"{Colors.TURQUOISE}[⚱] Scanning BloodHound data in: {directory}{Colors.RESET}\n")
    store: ObjectStore = load_directory(
        directory,
        max_workers=args.workers,
        log=lambda s: print(s),
    )

    if not store.all_objects():
        print(f"\n{Colors.CARNELIAN}[✗] No BloodHound objects loaded. Exiting.{Colors.RESET}")
        return 1

    # 2. USER SELECTION
    compromised_sids = select_compromised_users(store, args)
    reachability_ctx: Optional[ReachabilityContext] = None

    if compromised_sids:
        reachability_ctx = ReachabilityContext(store, compromised_sids)
        user_names = ", ".join(reachability_ctx.compromised_names)
        closure_size = len(reachability_ctx.closure)
        print(f"{Colors.GOLD}[☥] Reachability context built for: {Colors.TURQUOISE}{user_names}{Colors.RESET}")
        print(f"  {Colors.DIM}  Effective identities (user + group memberships): {closure_size}{Colors.RESET}\n")

    # 3. ANALYZE
    print(f"{Colors.GOLD}[☥] Running {len(REGISTRY.all_analyzers())} analyzers…{Colors.RESET}\n")
    findings: list[Finding] = []
    for cls in REGISTRY.all_analyzers():
        inst = cls()
        try:
            f = inst.analyze(store)
            if f is None:
                if args.verbose:
                    print(f"  {Colors.DIM}[{inst.name}] no findings{Colors.RESET}")
                continue
            findings.append(f)
            color = {
                "CRITICAL": Colors.CARNELIAN, "HIGH": Colors.OCHRE,
                "MEDIUM": Colors.GOLD, "LOW": Colors.TURQUOISE, "INFO": Colors.DIM,
            }.get(f.severity, Colors.DIM)
            print(f"  {color}[{f.severity:<8}]{Colors.RESET} {inst.name:<32} {Colors.DIM}({len(f.data)} items){Colors.RESET}")
        except Exception as e:
            print(f"  {Colors.CARNELIAN}[ERROR]{Colors.RESET}   {inst.name}: {type(e).__name__}: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
    print()

    findings_dicts = [f.to_dict() for f in findings]

    # 4. BUILD ATTACK PATHS + RECOMMENDATIONS
    attack_paths = build_attack_paths(store, findings_dicts)
    recommendations = build_recommendations(store, findings_dicts)

    # 5. APPLY REACHABILITY FILTER
    if reachability_ctx:
        total_findings = len(findings_dicts)
        total_paths = len(attack_paths)

        findings_dicts = reachability_ctx.filter_findings(findings_dicts)
        attack_paths = reachability_ctx.filter_attack_paths(attack_paths)

        user_names = ", ".join(reachability_ctx.compromised_names)
        print(f"{Colors.GOLD}[☥] Reachability filter applied for: {Colors.TURQUOISE}{user_names}{Colors.RESET}")
        print(f"  {Colors.DIM}  Findings: {len(findings_dicts)}/{total_findings} reachable{Colors.RESET}")
        print(f"  {Colors.DIM}  Attack paths: {len(attack_paths)}/{total_paths} reachable{Colors.RESET}\n")

    # 5.5 VARIABLE INTERPOLATION
    if args.variables:
        from .tactical import PlaybookInterpolator
        interpolator = PlaybookInterpolator(args.variables)
        if interpolator.loaded:
            print(f"{Colors.TURQUOISE}[⚙] Variables loaded from: {args.variables}{Colors.RESET}")
            for k, v in list(interpolator.variables.items())[:6]:
                print(f"  {Colors.DIM}  {k} = {v}{Colors.RESET}")
            if len(interpolator.variables) > 6:
                print(f"  {Colors.DIM}  ... and {len(interpolator.variables) - 6} more{Colors.RESET}")
            print()
            findings_dicts = interpolator.interpolate_findings(findings_dicts)
            attack_paths = interpolator.interpolate_paths(attack_paths)
            recommendations = interpolator.interpolate_recommendations(recommendations)
    
    if args.evasion:
        from .tactical import EvasionEngine
        evasion_engine = EvasionEngine()
        findings_dicts = evasion_engine.inject_evasion(findings_dicts)
        recommendations = evasion_engine.inject_evasion_recs(recommendations)

    # 5.6 NOOB MODE SIMPLIFICATION
    if args.noob:
        from .noob import simplify_findings, simplify_paths, simplify_recommendations
        pre_f, pre_p, pre_r = len(findings_dicts), len(attack_paths), len(recommendations)
        findings_dicts = simplify_findings(findings_dicts)
        attack_paths = simplify_paths(attack_paths)
        recommendations = simplify_recommendations(recommendations)
        print(f"{Colors.GOLD}[🐣] NOOB MODE ACTIVE — Simplified output for clarity{Colors.RESET}")
        print(f"  {Colors.DIM}  Findings: {len(findings_dicts)}/{pre_f} (critical/high only){Colors.RESET}")
        print(f"  {Colors.DIM}  Attack paths: {len(attack_paths)}/{pre_p} (best per type){Colors.RESET}")
        print(f"  {Colors.DIM}  Recommendations: {len(recommendations)}/{pre_r} (priority 1-3 only){Colors.RESET}\n")

    # 6. CONSOLE REPORT
    stats = store.stats()
    domain = store.primary_domain_name()

    reporter.print_stats(stats)
    reporter.print_risk(findings_dicts)
    reporter.print_findings(findings_dicts)
    reporter.print_attack_paths(attack_paths)
    reporter.print_recommendations(recommendations)
    reporter.print_summary(findings_dicts, attack_paths, recommendations)

    # 7. FILE REPORTS
    if args.format in {"text", "both"}:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = os.path.abspath(args.output)
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"pharaohound_report_{ts}.txt")
        generate_text_report(out_path, stats, domain, findings_dicts, attack_paths, recommendations)
        print(f"{Colors.MALACHITE}[✓] Text report: {out_path}{Colors.RESET}")

    if args.format in {"html", "both"}:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = os.path.abspath(args.output)
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"pharaohound_report_{ts}.html")
        generate_html_report(out_path, stats, domain, findings_dicts, attack_paths, recommendations)
        print(f"{Colors.MALACHITE}[✓] HTML Graph report: {out_path}{Colors.RESET}")

    # 8. INTERACTIVE SHELL
    if args.shell:
        from .shell import run_shell
        run_shell(store, findings_dicts, attack_paths, recommendations, show_banner=False)

    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
