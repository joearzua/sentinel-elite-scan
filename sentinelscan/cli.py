import sys
from pathlib import Path

import click

from .report import print_json_report, print_terminal_report
from .scanner import Finding, scan_directory, scan_git_history


@click.group()
@click.version_option(package_name="sentinel-elite-scan")
def cli() -> None:
    """SentinelEliteScan — secrets, PAN, and PII scanner for codebases."""


@cli.command()
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option(
    "--git-history",
    is_flag=True,
    default=False,
    help="Scan all blobs in git history in addition to the working tree.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output findings as JSON to stdout.",
)
@click.option(
    "--no-fail",
    is_flag=True,
    default=False,
    help="Always exit 0, even when Critical findings are present.",
)
def scan(path: Path, git_history: bool, output_json: bool, no_fail: bool) -> None:
    """Scan PATH for secrets, payment card data, and PII."""
    findings: list[Finding] = []

    for finding in scan_directory(path):
        findings.append(finding)

    if git_history:
        try:
            for finding in scan_git_history(path):
                findings.append(finding)
        except RuntimeError as exc:
            click.echo(f"Warning: git history scan skipped — {exc}", err=True)

    # Deduplicate: same file + line + check name
    seen: set[tuple[str, int, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.file_path, f.line_number, f.pattern_name)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    if output_json:
        print_json_report(unique, str(path))
    else:
        print_terminal_report(unique, str(path))

    has_critical = any(f.severity.value == "CRITICAL" for f in unique)
    if has_critical and not no_fail:
        sys.exit(1)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
