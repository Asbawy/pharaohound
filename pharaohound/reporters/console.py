#!/usr/bin/env python3
"""
reporters.console — Polished terminal output with ASCII tables.

Uses `rich` if available (it usually is on a modern pentest distro). Falls
back to a lightweight pure-ANSI table formatter so the tool keeps working
on minimal environments. The Pharaohound color theme is preserved in
both paths.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..theme import (
    Colors, Severity, SEVERITY_RANK, BANNER,
    colorize, severity_color, severity_glyph,
)
from .text import GLOSSARY

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    _HAVE_RICH = True
except ImportError:  # pragma: no cover
    _HAVE_RICH = False


# FALLBACK ASCII TABLE
import re as _re
_ANSI_RE = _re.compile(r"\033\[[0-9;]*m")


def _visible_len(s: str) -> int:
    """Length of `s` excluding ANSI escape sequences."""
    return len(_ANSI_RE.sub("", str(s)))


def _pad(s: str, width: int) -> str:
    """Left-justify `s` to `width` visible columns, preserving any ANSI codes."""
    s = str(s)
    pad = width - _visible_len(s)
    return s + (" " * max(0, pad))


def _ascii_table(headers: List[str], rows: List[List[str]], col_widths: List[int] | None = None) -> str:
    if not rows:
        return f"  (no rows)"
    n_cols = len(headers)
    if col_widths is None:
        col_widths = []
        for i in range(n_cols):
            w = _visible_len(headers[i])
            for r in rows:
                if i < len(r):
                    w = max(w, _visible_len(r[i]))
            col_widths.append(min(w + 1, 60))

    sep = "  " + "─┼─".join("─" * w for w in col_widths)
    top = "  " + "─┬─".join("─" * w for w in col_widths)
    bot = "  " + "─┴─".join("─" * w for w in col_widths)
    # Add leading + trailing corner pieces
    top = "  ┌" + top[3:] + "┐"
    bot = "  └" + bot[3:] + "┘"
    sep = "  ├" + sep[3:] + "┤"
    # Header row needs leading and trailing bars too
    def fmt_row(cells: List[str]) -> str:
        inner = " │ ".join(_pad(cells[i], col_widths[i]) for i in range(min(len(cells), n_cols)))
        return "  │ " + inner + " │" if inner else "  │"
    lines = [top, colorize(fmt_row(headers), Colors.GOLD, bold=True), sep]
    for r in rows:
        lines.append(fmt_row(r))
    lines.append(bot)
    return "\n".join(lines)


# CONSOLE REPORTER
class ConsoleReporter:
    def __init__(self, use_rich: bool = _HAVE_RICH) -> None:
        self.use_rich = use_rich and _HAVE_RICH
        if self.use_rich:
            self.console = Console(highlight=False, soft_wrap=False)

    # ── Output helpers ──────────────────────────────────────────────────────
    def _print(self, text: str = "") -> None:
        if self.use_rich:
            self.console.print(text, overflow="fold")
        else:
            print(text)

    def banner(self) -> None:
        self._print(BANNER)

    # ── Stats table ─────────────────────────────────────────────────────────
    def print_stats(self, stats: Dict[str, int]) -> None:
        self._print(colorize("  ☥  D O M A I N   S T A T I S T I C S", Colors.GOLD, bold=True))

        rows = [
            [colorize("Users", Colors.TURQUOISE),      str(stats.get("users", 0))],
            [colorize("Groups", Colors.TURQUOISE),     str(stats.get("groups", 0))],
            [colorize("Computers", Colors.TURQUOISE),  str(stats.get("computers", 0))],
            [colorize("GPOs", Colors.TURQUOISE),       str(stats.get("gpos", 0))],
            [colorize("OUs", Colors.TURQUOISE),        str(stats.get("ous", 0))],
            [colorize("Containers", Colors.TURQUOISE), str(stats.get("containers", 0))],
            [colorize("Domains", Colors.TURQUOISE),    str(stats.get("domains", 0))],
        ]
        # Conditional rows for PKI/Azure (only show if data present)
        if stats.get("cas", 0):
            rows.append([colorize("Certificate Authorities", Colors.TURQUOISE), str(stats["cas"])])
        if stats.get("certtemplates", 0):
            rows.append([colorize("Certificate Templates", Colors.TURQUOISE), str(stats["certtemplates"])])
        if stats.get("azure", 0):
            rows.append([colorize("Azure / Entra ID", Colors.TURQUOISE), str(stats["azure"])])
        rows.append([colorize("Total Objects", Colors.GOLD), str(stats.get("total", 0))])
        if self.use_rich:
            t = Table(title="Object Counts", box=box.ROUNDED, show_header=True, header_style="bold gold1")
            t.add_column("Type", style="turquoise2")
            t.add_column("Count", style="bold")
            for r in rows:
                t.add_row(r[0], r[1])
            self.console.print(t)
        else:
            print(_ascii_table(["Type", "Count"], rows))

    # ── Risk summary ────────────────────────────────────────────────────────
    def print_risk(self, findings: List[Dict[str, Any]]) -> None:
        sev_counts: Dict[str, int] = {s: 0 for s in Severity.__dict__.values() if isinstance(s, str)}
        for f in findings:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

        crit = sev_counts.get(Severity.CRITICAL, 0)
        high = sev_counts.get(Severity.HIGH, 0)
        med = sev_counts.get(Severity.MEDIUM, 0)
        low = sev_counts.get(Severity.LOW, 0)

        if crit > 5:
            risk_label = "CRITICAL — Domain is highly vulnerable"
            risk_color = Colors.CARNELIAN
        elif crit > 0:
            risk_label = "HIGH — Multiple critical paths to Domain Admin"
            risk_color = Colors.OCHRE
        elif high > 3:
            risk_label = "MEDIUM — Several high-risk findings"
            risk_color = Colors.GOLD
        else:
            risk_label = "LOW — Relatively secure"
            risk_color = Colors.MALACHITE

        self._print(colorize("  ☥  R I S K   A S S E S S M E N T", Colors.GOLD, bold=True))
        self._print(f"  Risk Level: {colorize(risk_label, risk_color, bold=True)}\n")

        rows = [
            [colorize(severity_glyph(Severity.CRITICAL), Colors.CARNELIAN), "Critical", str(crit)],
            [colorize(severity_glyph(Severity.HIGH),     Colors.OCHRE),     "High",     str(high)],
            [colorize(severity_glyph(Severity.MEDIUM),   Colors.GOLD),      "Medium",   str(med)],
            [colorize(severity_glyph(Severity.LOW),      Colors.TURQUOISE), "Low",      str(low)],
        ]
        if self.use_rich:
            t = Table(box=box.ROUNDED, show_header=True, header_style="bold gold1")
            t.add_column("")
            t.add_column("Severity")
            t.add_column("Count", justify="right")
            for r in rows:
                t.add_row(r[0], r[1], r[2])
            self.console.print(t)
        else:
            print(_ascii_table(["", "Severity", "Count"], rows))

    # ── Findings ────────────────────────────────────────────────────────────
    def print_findings(self, findings: List[Dict[str, Any]]) -> None:
        self._print(colorize("  ☥  F I N D I N G S", Colors.GOLD, bold=True))

        sorted_findings = sorted(findings, key=lambda f: SEVERITY_RANK.get(f["severity"], 99))
        for f in sorted_findings:
            self._print_finding(f)

    def _print_finding(self, f: Dict[str, Any]) -> None:
        sev = f["severity"]
        glyph = severity_glyph(sev)
        col = severity_color(sev)
        title = f.get("title", "")
        self._print(f"{colorize(glyph, col)} {colorize(title.upper(), col, bold=True)}")
        self._print(f"  {colorize('Severity:', Colors.DIM)}     {colorize(sev, col)}")
        self._print(f"  {colorize('Summary:', Colors.DIM)}      {f['summary']}")

        if title in GLOSSARY:
            g = GLOSSARY[title]
            self._print(f"  {colorize('💡 Concept:', Colors.GOLD)}     {g['explanation']}")
            self._print(f"  {colorize('💥 Risk:', Colors.CARNELIAN)}        {g['risk']}")
            self._print(f"  {colorize('🔧 Fix:', Colors.MALACHITE)}         {g['fix']}")

        if f.get("recommendation"):
            self._print(f"  {colorize('Action:', Colors.DIM)}        {f['recommendation']}")

        if f.get("eli5"):
            self._print(f"\n  {colorize('┌─ ELI5 ─────────────────────────────────────────────────────────────────', Colors.AMETHYST)}")
            for line in (f["eli5"] or "").split("\n"):
                self._print(f"  {colorize('│', Colors.AMETHYST)} {line}")
            self._print(f"  {colorize('└──────────────────────────────────────────────────────────────────────────', Colors.AMETHYST)}")

        if f.get("remediation"):
            self._print(f"\n  {colorize('Defender action:', Colors.MALACHITE)} {f['remediation']}")

        if f.get("playbooks"):
            self._print(f"\n  {colorize('Tool blueprints:', Colors.TURQUOISE, bold=True)}")
            for cmd in f["playbooks"]:
                self._print(f"    {colorize('$', Colors.SAND)} {cmd}")

        if f.get("data"):
            details_title = f"Details ({len(f['data'])} items):"
            self._print(f"\n  {colorize(details_title, Colors.DIM)}")
            for i, item in enumerate(f["data"][:8], 1):
                self._print(f"    {i}. {self._format_item(item)}")
            if len(f["data"]) > 8:
                more_count = len(f["data"]) - 8
                more_msg = f"… and {more_count} more (see HTML report for full list)"
                self._print(f"    {colorize(more_msg, Colors.DIM)}")
        self._print("")

    def _format_item(self, item: Dict[str, Any]) -> str:
        # Trust relationships
        if "direction" in item and "source" in item and "target" in item:
            trans = "Transitive" if item.get("transitive") else "Non-transitive"
            sf = "SID Filtering: Enabled" if item.get("sid_filtering") else colorize("SID Filtering: DISABLED", Colors.CARNELIAN)
            return f"{item['direction']} Trust: {item['source']} -> {item['target']} ({trans}, {sf})"
        
        # Machine Account Quota
        if "machine_account_quota" in item:
            return f"Domain: {item.get('domain')} [ms-DS-MachineAccountQuota = {item['machine_account_quota']}]"

        # Pre-Windows 2000 Compatible Access
        if "member" in item and "group" in item:
            return f"Member: {item['member']} ({item.get('member_type', 'unknown')}) -> Group: {item['group']}"

        # SID History
        if "extra_sids" in item:
            sids = ", ".join(item["extra_sids"][:3])
            if len(item["extra_sids"]) > 3:
                sids += f" and {len(item['extra_sids']) - 3} more"
            return f"User: {item.get('name')} [SID History: {sids}]"

        # AD CS misconfigurations
        if "esc" in item:
            esc = item.get("esc")
            tpl = item.get("template")
            ca = item.get("ca")
            container = item.get("container")
            enrollers = item.get("enrollers")
            principal = item.get("principal")
            right = item.get("right")
            computer = item.get("computer")
            
            detail = []
            if tpl:
                detail.append(f"Template: {tpl}")
            if ca:
                detail.append(f"CA: {ca}")
            if container:
                detail.append(f"Container: {container}")
            if computer:
                detail.append(f"DC: {computer}")
            if enrollers:
                detail.append(f"Enrollers: {', '.join(enrollers)}")
            if principal:
                detail.append(f"Principal: {principal}")
            if right:
                detail.append(f"Right: {right}")
            return f"[{esc}] " + " | ".join(detail)

        # Constrained Delegation
        if "delegation_targets" in item:
            targets_str = ", ".join(item["delegation_targets"][:3])
            if len(item["delegation_targets"]) > 3:
                targets_str += f" and {len(item['delegation_targets']) - 3} more"
            auth = " (with Protocol Transition)" if item.get("trusted_to_auth") else " (no Protocol Transition)"
            return f"{item.get('type', 'Principal')}: {item.get('name')}{auth} -> Targets: {targets_str}"

        # GPO Abuse linked to high-value OUs / Direct write
        if item.get("kind") == "linked_to_high_value_ou":
            return f"GPO: {item.get('gpo')} linked to High-Value OU: {item.get('ou')}"
        if item.get("kind") == "direct_write":
            return f"Attacker: {item.get('attacker')} has {item.get('right')} on GPO: {item.get('gpo')}"

        # gMSA Password Readers
        if "gmsa_account" in item:
            return f"Reader: {item.get('reader')} has {item.get('right')} on gMSA: {item.get('gmsa_account')}"

        # Fallback parts-based formatter
        parts = []
        for k in ("name", "user", "principal", "attacker", "reader", "account"):
            if k in item:
                parts.append(item[k])
                break
        for k in ("computer", "target", "target_computer", "group", "gpo", "ou", "source_object"):
            if k in item:
                parts.append(f"→ {item[k]}")
                break
        if "right" in item:
            parts.append(f"[{item['right']}]")
        if "spns" in item and item["spns"]:
            parts.append(f"SPNs: {', '.join(item['spns'][:2])}")
        if "pwd_age_days" in item:
            parts.append(f"pwd age: {item['pwd_age_days']}d")
        if "os" in item:
            parts.append(f"OS: {item['os']}")
        if "known_threats" in item:
            parts.append(f"({item['known_threats']})")
        if "in_high_value_group" in item and item["in_high_value_group"]:
            parts.append(colorize("(HIGH-VALUE)", Colors.CARNELIAN))
        return " ".join(str(p) for p in parts) if parts else str(item)

    # ── Attack paths ────────────────────────────────────────────────────────
    def print_attack_paths(self, paths: List[Dict[str, Any]]) -> None:
        self._print(colorize("  ⚔  A T T A C K   P A T H S", Colors.GOLD, bold=True))

        if not paths:
            self._print(f"  {colorize('No clear attack paths detected. The domain may be relatively secure.', Colors.MALACHITE)}\n")
            return

        for i, p in enumerate(paths, 1):
            col = severity_color(p["severity"])
            glyph = severity_glyph(p["severity"])
            opsec = p.get("opsec_label", "")
            path_title = f"Path {i}: {p['name']}"
            self._print(f"{colorize(glyph, col)} {colorize(path_title, col, bold=True)}  {opsec}")
            self._print(f"  {colorize('Summary:', Colors.DIM)} {p['summary']}")
            if p.get("prerequisites"):
                self._print(f"  {colorize('Prerequisites:', Colors.DIM)} {', '.join(p['prerequisites'])}")
            if p.get("tools"):
                self._print(f"  {colorize('Tools:', Colors.DIM)} {', '.join(p['tools'])}")
            if p.get("detection_events"):
                events_str = ", ".join(p["detection_events"])
                self._print(f"  {colorize('⚠ Detection:', Colors.OCHRE)} {events_str}")
            self._print(f"  {colorize('Steps:', Colors.DIM)}")
            for step in p["steps"]:
                for line in step.split("\n"):
                    self._print(f"    {line}")
            self._print("")

    # ── Recommendations ─────────────────────────────────────────────────────
    def print_recommendations(self, recs: List[Dict[str, Any]]) -> None:
        self._print(colorize("  ☥  P R I O R I T I Z E D   R E C O M M E N D A T I O N S", Colors.GOLD, bold=True))

        if not recs:
            self._print(f"  {colorize('No specific recommendations — domain looks healthy.', Colors.MALACHITE)}\n")
            return

        for r in recs:
            col = severity_color(r["severity"])
            opsec = r.get("opsec_label", "")
            priority_str = f"[P{r['priority']}]"
            self._print(f"{colorize(priority_str, col, bold=True)} {colorize(r['title'], col, bold=True)}  {opsec}")
            self._print(f"  {colorize('Action:', Colors.DIM)} {r['action']}")
            self._print(f"  {colorize('Command:', Colors.TURQUOISE)} {r['command']}")
            for alt in r.get("alt_commands", []):
                self._print(f"  {colorize('Alt:', Colors.DIM)}     {alt}")
            if r.get("detection_events"):
                events_str = ", ".join(r["detection_events"])
                self._print(f"  {colorize('⚠ SOC will see:', Colors.OCHRE)} {events_str}")
            if r.get("defender_action"):
                self._print(f"  {colorize('Defender:', Colors.MALACHITE)} {r['defender_action']}")
            self._print("")

    # ── Final summary ───────────────────────────────────────────────────────
    def print_summary(self, findings: List[Dict[str, Any]], attack_paths: List[Dict[str, Any]], recs: List[Dict[str, Any]]) -> None:
        self._print(colorize("  ☥  A N A L Y S I S   C O M P L E T E  ☥", Colors.GOLD, bold=True))

        crit = sum(1 for f in findings if f["severity"] == Severity.CRITICAL)
        high = sum(1 for f in findings if f["severity"] == Severity.HIGH)
        med = sum(1 for f in findings if f["severity"] == Severity.MEDIUM)
        low = sum(1 for f in findings if f["severity"] == Severity.LOW)
        total = crit + high + med + low

        self._print(f"  {colorize('▲', Colors.CARNELIAN)} Critical:        {crit}")
        self._print(f"  {colorize('◆', Colors.OCHRE)}     High:            {high}")
        self._print(f"  {colorize('●', Colors.GOLD)}      Medium:          {med}")
        self._print(f"  {colorize('○', Colors.TURQUOISE)}      Low:             {low}")
        self._print(f"  {colorize('∙', Colors.PAPYRUS)}      Total findings:  {total}")
        self._print(f"\n  {colorize('⚔  Attack Paths:', Colors.AMETHYST)} {len(attack_paths)}")
        self._print(f"  {colorize('☥  Recommendations:', Colors.MALACHITE)} {len(recs)}")
        self._print(f"\n{colorize('[☥] Pharaohound analysis complete. Review findings above. ☥', Colors.GOLD)}\n")
