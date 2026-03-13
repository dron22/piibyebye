"""Tests for PDF redaction and un-redaction round-trip."""

import tempfile
from pathlib import Path

import fitz
import pytest

from pii.detector import detect
from pii.extractor import extract
from pii.keystore import decrypt_keyfile, encrypt_keyfile
from pii.redactor import redact_pdf, unredact_pdf
from pii.tokeniser import tokenise

TESTDATA = Path(__file__).parent / "testdata"
INVOICE_PDF = TESTDATA / "sample_hospital_invoice_synthetic.pdf"


@pytest.mark.skipif(not INVOICE_PDF.exists(), reason="Sample PDF not found")
def test_redact_produces_valid_pdf():
    findings = tokenise(detect(extract(str(INVOICE_PDF))))
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        out_path = f.name
    redact_pdf(str(INVOICE_PDF), findings, out_path)
    doc = fitz.open(out_path)
    assert doc.page_count > 0
    doc.close()


@pytest.mark.skipif(not INVOICE_PDF.exists(), reason="Sample PDF not found")
def test_redacted_pdf_has_no_original_pii():
    findings = tokenise(detect(extract(str(INVOICE_PDF))))
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        out_path = f.name
    redact_pdf(str(INVOICE_PDF), findings, out_path)
    doc = fitz.open(out_path)
    full_text = "".join(page.get_text() for page in doc)
    doc.close()
    # Only assert on distinctive PII types — generic location names (ADDRESS) can legitimately
    # appear elsewhere in the document (e.g. bank city names) and are not checked here.
    distinctive = {"NAME", "AHV", "IBAN", "PATIENT_ID", "PHONE", "EMAIL", "INSURANCE"}
    for f in findings:
        if f.type in distinctive:
            assert f.value not in full_text, f"PII '{f.value}' still present after redaction"


@pytest.mark.skipif(not INVOICE_PDF.exists(), reason="Sample PDF not found")
def test_unredact_round_trip():
    findings = tokenise(detect(extract(str(INVOICE_PDF))))
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as r:
        redacted_path = r.name
    with tempfile.NamedTemporaryFile(suffix=".key.enc", delete=False) as k:
        key_path = k.name
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as u:
        restored_path = u.name
    password = "test-roundtrip-pw"
    redact_pdf(str(INVOICE_PDF), findings, redacted_path)
    encrypt_keyfile(findings, password, key_path)
    key_map = decrypt_keyfile(key_path, password)
    unmatched = unredact_pdf(redacted_path, key_map, restored_path)
    assert len(unmatched) == 0, f"Unmatched tokens: {unmatched}"
    doc = fitz.open(restored_path)
    full_text = "".join(page.get_text() for page in doc)
    doc.close()
    hits = sum(1 for f in findings if f.value in full_text)
    assert hits > 0, "No original values found in restored PDF"
