"""Gradio web UI for local PII redaction."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import gradio as gr

from pii.detector import detect
from pii.extractor import extract
from pii.keystore import decrypt_keyfile, encrypt_keyfile
from pii.redactor import redact_pdf, unredact_pdf
from pii.tokeniser import tokenise


def _redact(pdf_path: str | None, password: str) -> tuple:
    if not pdf_path:
        raise gr.Error("Upload a PDF file.")
    if not password:
        raise gr.Error("Enter a password to protect the key file.")

    pages = extract(pdf_path)
    if not any(p.chars for p in pages):
        raise gr.Error("No text found. Only text-based PDFs are supported.")

    findings = detect(pages)
    if not findings:
        return [], None, None, "No PII detected in this document."

    tokenise(findings)

    tmp = tempfile.mkdtemp()
    stem = Path(pdf_path).stem
    redacted_path = os.path.join(tmp, f"{stem}_redacted.pdf")
    key_path = os.path.join(tmp, f"{stem}_redacted.key.enc")

    page_content = redact_pdf(pdf_path, findings, redacted_path)
    encrypt_keyfile(findings, password, key_path, page_content=page_content)

    seen: set[str] = set()
    table = []
    for f in findings:
        if f.token and f.token not in seen:
            table.append([f.token, f.type, f.value])
            seen.add(f.token)

    return table, redacted_path, key_path, f"{len(seen)} field(s) redacted."


def _unredact(pdf_path: str | None, key_path: str | None, password: str) -> tuple:
    if not pdf_path or not key_path:
        raise gr.Error("Upload both the redacted PDF and the key file.")
    if not password:
        raise gr.Error("Enter your password.")

    try:
        key_map = decrypt_keyfile(key_path, password)
    except ValueError:
        raise gr.Error("Wrong password or corrupted key file.")

    tmp = tempfile.mkdtemp()
    stem = Path(pdf_path).stem.removesuffix("_redacted")
    restored_path = os.path.join(tmp, f"{stem}_restored.pdf")

    unredact_pdf(pdf_path, key_map, restored_path)
    n = len(key_map.get("tokens", key_map))
    return restored_path, f"{n} field(s) restored."


with gr.Blocks(title="pii — Local PII Redaction") as demo:
    gr.Markdown(
        "# pii — Local PII Redaction\n"
        "Detect and black out personal information from PDFs. "
        "All processing is local — no data leaves your device."
    )

    with gr.Tab("Redact"):
        with gr.Row():
            with gr.Column():
                pdf_in = gr.File(label="Upload PDF", file_types=[".pdf"], type="filepath")
                pwd_in = gr.Textbox(label="Password (protects the key file)", type="password")
                redact_btn = gr.Button("Detect & Redact", variant="primary")
            with gr.Column():
                status_out = gr.Textbox(label="Status", interactive=False)
                table_out = gr.Dataframe(
                    headers=["Token", "Type", "Original Value"],
                    label="Detected PII",
                    interactive=False,
                )
                redacted_out = gr.File(label="Download redacted PDF")
                key_out = gr.File(label="Download key file (keep this safe)")

        redact_btn.click(
            _redact,
            inputs=[pdf_in, pwd_in],
            outputs=[table_out, redacted_out, key_out, status_out],
        )

    with gr.Tab("Restore"):
        with gr.Row():
            with gr.Column():
                redacted_in = gr.File(label="Redacted PDF", file_types=[".pdf"], type="filepath")
                key_in = gr.File(label="Key file (.key.enc)", type="filepath")
                pwd_restore = gr.Textbox(label="Password", type="password")
                restore_btn = gr.Button("Restore", variant="primary")
            with gr.Column():
                restore_status = gr.Textbox(label="Status", interactive=False)
                restored_out = gr.File(label="Download restored PDF")

        restore_btn.click(
            _unredact,
            inputs=[redacted_in, key_in, pwd_restore],
            outputs=[restored_out, restore_status],
        )
