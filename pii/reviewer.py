"""Print detection summary and prompt user for confirmation."""

from typing import Optional

import click

from pii.detector import Finding


def review(findings: list[Finding], skip_confirm: bool = False) -> Optional[list[Finding]]:
    """Print all detected findings and ask for confirmation.

    Returns the findings list if confirmed, None if cancelled.
    """
    click.echo(f"\nFound {len(findings)} PII field(s):\n")
    click.echo(f"  {'#':<4} {'Type':<14} {'Token':<18} {'Value':<40} {'Conf':>5}")
    click.echo(f"  {'-' * 4} {'-' * 14} {'-' * 18} {'-' * 40} {'-' * 5}")

    for i, f in enumerate(findings, 1):
        token = f.token or "—"
        value_display = f.value if len(f.value) <= 40 else f.value[:37] + "..."
        conf = f"{f.confidence:.0%}"
        click.echo(f"  {i:<4} {f.type:<14} {token:<18} {value_display:<40} {conf:>5}")

    click.echo()

    if skip_confirm:
        return findings

    if not click.confirm(f"Redact these {len(findings)} field(s)?", default=False):
        return None

    return findings
