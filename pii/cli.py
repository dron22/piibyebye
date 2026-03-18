import hashlib
import logging
import sys
import tempfile
from pathlib import Path

import click

from pii.detector import detect
from pii.extractor import extract
from pii.keystore import decrypt_keyfile, encrypt_keyfile
from pii.redactor import redact_pdf, unredact_pdf
from pii.reporter import report
from pii.reviewer import review
from pii.tokeniser import tokenise


@click.group()
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging (shows DOB classification decisions).")
@click.pass_context
def cli(ctx: click.Context, debug: bool) -> None:
    """Local PII redaction tool for PDFs. All processing is local — no data leaves your device."""
    if debug:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s %(message)s")


@cli.command()
@click.argument("input_pdf", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Output directory. Defaults to same directory as input.",
)
@click.option(
    "--opaque", is_flag=True, default=False, help="Use opaque tokens [REDACTED_001] instead of typed tokens [NAME_1]."
)
@click.option("--yes", "-y", is_flag=True, default=False, help="Skip confirmation prompt (for scripting).")
@click.option(
    "--report-file", type=click.Path(path_type=Path), default=None, help="Write audit report to file instead of stdout."
)
@click.option(
    "--diagnoses", is_flag=True, default=False, help="Also redact diagnosis codes (ICD-10). Disabled by default."
)
@click.option("--password", default=None, help="Encryption password (prefer interactive prompt).")
def redact(
    input_pdf: Path,
    output: Path | None,
    opaque: bool,
    yes: bool,
    report_file: Path | None,
    diagnoses: bool,
    password: str | None,
) -> None:
    """Detect and redact PII from INPUT_PDF. Produces a redacted PDF and an encrypted key file."""
    if not input_pdf.suffix.lower() == ".pdf":
        click.echo(f"Error: not a valid PDF file: {input_pdf}", err=True)
        sys.exit(1)

    out_dir = output or input_pdf.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    stem = input_pdf.stem
    redacted_path = out_dir / f"{stem}_redacted.pdf"
    key_path = out_dir / f"{stem}_redacted.key.enc"

    click.echo(f"Reading {input_pdf.name}...")
    pages = extract(str(input_pdf))

    if not any(p.chars for p in pages):
        click.echo("Error: no text could be extracted from this PDF.", err=True)
        sys.exit(1)

    click.echo("Detecting PII...")
    findings = detect(pages, include_diagnoses=diagnoses)

    if not findings:
        click.echo("No PII detected. No files written.")
        return

    confirmed = review(findings, skip_confirm=yes)
    if confirmed is None:
        click.echo("Redaction cancelled. No files written.")
        return

    tokenised = tokenise(confirmed, opaque=opaque)

    if password is None:
        password = click.prompt(
            "Enter encryption password for key file", hide_input=True, confirmation_prompt="Confirm password"
        )

    page_content = redact_pdf(str(input_pdf), tokenised, str(redacted_path))
    encrypt_keyfile(tokenised, password, str(key_path), page_content=page_content)
    report(tokenised, findings, report_file=str(report_file) if report_file else None)

    click.echo("\nRedaction complete.")
    click.echo(f"  Redacted:  {len(tokenised)} fields")
    click.echo(f"  PDF:       {redacted_path.name}")
    click.echo(f"  Key file:  {key_path.name}")
    click.echo("\nKeep your key file safe. Without it, redaction cannot be reversed.")


def _redact_for_hook(file_path: str) -> str:
    """Redact a PDF if not already redacted. Returns the redacted path.

    Redacted files are stored in /tmp/piibyebye/, keyed by SHA-256 of the original,
    so they are cleaned up by the OS and never clutter the source directory.
    """
    file_hash = hashlib.sha256(Path(file_path).read_bytes()).hexdigest()
    tmp_dir = Path(tempfile.gettempdir()) / "piibyebye"
    tmp_dir.mkdir(exist_ok=True)
    redacted_path = tmp_dir / f"{file_hash}.pdf"

    if not redacted_path.exists():
        pages = extract(file_path)
        findings = detect(pages)
        if findings:
            tokenise(findings)
            redact_pdf(str(file_path), findings, str(redacted_path))

    return str(redacted_path) if redacted_path.exists() else file_path


@cli.command()
def claude() -> None:
    """Claude Code PreToolUse hook — redacts PDFs before the model reads them.

    Add to ~/.claude/settings.json:

        "command": "pii claude"
    """
    import json

    data = json.load(sys.stdin)
    file_path = data.get("tool_input", {}).get("file_path", "")

    if data.get("tool_name") != "Read" or not file_path.endswith(".pdf"):
        return

    redacted_path = _redact_for_hook(file_path)
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "updatedInput": {"file_path": redacted_path},
                }
            }
        )
    )


@cli.command(name="help")
@click.pass_context
def help_cmd(ctx: click.Context) -> None:
    """Show this help message and exit."""
    click.echo(cli.get_help(ctx))


@cli.command()
def version() -> None:
    """Show the version and exit."""
    import importlib.metadata

    click.echo(importlib.metadata.version("piibyebye"))


@cli.command()
def web() -> None:
    """Launch the web UI."""
    import gradio as gr

    from pii.app import demo

    _, local_url, _ = demo.launch(
        theme=gr.themes.Default(primary_hue="slate"),
        prevent_thread_lock=True,
        quiet=True,
    )
    click.echo(f"* Running on {local_url}?__theme=dark")
    demo.block_thread()


@cli.command()
@click.argument("redacted_pdf", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("key_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Output directory. Defaults to same directory as input.",
)
@click.option("--password", default=None, help="Decryption password (prefer interactive prompt).")
def unredact(redacted_pdf: Path, key_file: Path, output: Path | None, password: str | None) -> None:
    """Restore a redacted PDF using KEY_FILE and your password."""
    out_dir = output or redacted_pdf.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    stem = redacted_pdf.stem.removesuffix("_redacted")
    restored_path = out_dir / f"{stem}_restored.pdf"

    if password is None:
        password = click.prompt("Enter decryption password", hide_input=True)

    try:
        key_map = decrypt_keyfile(str(key_file), password)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    unmatched = unredact_pdf(str(redacted_pdf), key_map, str(restored_path))

    if unmatched:
        click.echo(f"Warning: {len(unmatched)} token(s) not found in key file and were not restored:")
        for t in unmatched:
            click.echo(f"  {t}")

    restored_count = len(key_map) - len(unmatched)
    click.echo(f"Restored {restored_count} fields. Written to {restored_path.name}")
