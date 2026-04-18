import json
import sys

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .patterns import Severity
from .scanner import Finding

_console = Console(file=sys.stdout, legacy_windows=False, safe_box=True)

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold yellow",
    Severity.MEDIUM: "bold cyan",
}

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
}


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER[f.severity], f.file_path, f.line_number),
    )


def print_terminal_report(findings: list[Finding], scanned_path: str) -> None:
    if not findings:
        _console.print(
            Panel(
                "[bold green]CLEAN  No secrets or sensitive data detected.[/bold green]",
                title="[bold]SentinelEliteScan[/bold]",
                border_style="green",
            )
        )
        return

    counts: dict[Severity, int] = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    border = "red" if counts[Severity.CRITICAL] > 0 else "yellow"
    summary_parts = [f"[bold]Scanned:[/bold] {scanned_path}  |  [bold]Total:[/bold] {len(findings)}"]
    for sev in Severity:
        style = _SEVERITY_STYLE[sev]
        summary_parts.append(f"[{style}]{sev.value}[/{style}]: {counts[sev]}")

    _console.print()
    _console.print(
        Panel(
            "  ".join(summary_parts),
            title="[bold]SentinelEliteScan — Results[/bold]",
            border_style=border,
        )
    )
    _console.print()

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on grey23",
        expand=True,
        show_lines=False,
    )
    table.add_column("Severity", width=10, no_wrap=True)
    table.add_column("File", overflow="fold", ratio=4)
    table.add_column("Line", width=6, justify="right")
    table.add_column("Check", overflow="fold", ratio=3)
    table.add_column("Value (redacted)", overflow="fold", ratio=3)
    table.add_column("Commit", width=9, no_wrap=True)

    for f in _sort_findings(findings):
        style = _SEVERITY_STYLE[f.severity]
        commit_cell = f.commit_hash[:8] if f.commit_hash else ""
        table.add_row(
            Text(f.severity.value, style=style),
            f.file_path,
            str(f.line_number),
            f.pattern_name,
            f.matched_value,
            commit_cell,
        )

    _console.print(table)
    _console.print()

    seen_checks: set[str] = set()
    _console.print("[bold white]Check descriptions:[/bold white]")
    for f in _sort_findings(findings):
        if f.pattern_name not in seen_checks:
            seen_checks.add(f.pattern_name)
            style = _SEVERITY_STYLE[f.severity]
            _console.print(f"  [{style}] > [/{style}] [bold]{f.pattern_name}[/bold]: {f.description}")
    _console.print()


def print_json_report(findings: list[Finding], scanned_path: str) -> None:
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1

    report: dict = {
        "scanner": "SentinelEliteScan",
        "version": "1.0.0",
        "scanned_path": scanned_path,
        "summary": {"total": len(findings), **counts},
        "findings": [
            {
                "severity": f.severity.value,
                "file": f.file_path,
                "line": f.line_number,
                "check": f.pattern_name,
                "description": f.description,
                "value_redacted": f.matched_value,
                **({"entropy": round(f.entropy, 3)} if f.entropy is not None else {}),
                **({"commit": f.commit_hash} if f.commit_hash else {}),
            }
            for f in _sort_findings(findings)
        ],
    }

    print(json.dumps(report, indent=2))
