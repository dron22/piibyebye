"""Tests for PII detection — validated against sample PDFs."""

from pathlib import Path

import pytest

from pii.detector import Finding, detect
from pii.extractor import extract

TESTDATA = Path(__file__).parent / "testdata"
INVOICE_PDF = TESTDATA / "sample_hospital_invoice_synthetic.pdf"
SOCIAL_PDF = TESTDATA / "sample_social_security_notice_synthetic.pdf"

INVOICE_EXPECTED = {
    "NAME": ["Lara Meier"],
    "DOB": ["1991-07-14"],
    "PHONE": ["+41 79 555 01 72"],
    "PATIENT_ID": ["PT-49302817"],
    "AHV": ["756.9217.4821.09"],
    "IBAN": ["CH44 3199 9123 0000 5512 8"],
    "INSURANCE": ["HC-CH-992-118-440"],
}

SOCIAL_EXPECTED = {
    "NAME": ["Marco Bianchi"],
    "AHV": ["756.8356.9021.34"],
    "IBAN": ["CH93 0076 2011 6238 5295 7"],
    "EMAIL": ["marco.bianchi+avs@syntheticmail.example"],
}


def _detected_values(findings: list[Finding], pii_type: str) -> list[str]:
    return [f.value for f in findings if f.type == pii_type]


def _recall(expected: list[str], detected: list[str]) -> float:
    if not expected:
        return 1.0
    hits = sum(
        1 for exp in expected if any(exp.lower() in det.lower() or det.lower() in exp.lower() for det in detected)
    )
    return hits / len(expected)


@pytest.mark.skipif(not INVOICE_PDF.exists(), reason="Sample PDF not found")
def test_invoice_priority1_recall():
    pages = extract(str(INVOICE_PDF))
    findings = detect(pages)
    total_expected = sum(len(v) for v in INVOICE_EXPECTED.values())
    total_hits = 0
    for pii_type, expected_values in INVOICE_EXPECTED.items():
        detected = _detected_values(findings, pii_type)
        r = _recall(expected_values, detected)
        total_hits += r * len(expected_values)
        print(f"  {pii_type}: recall={r:.0%} detected={detected}")
    overall = total_hits / total_expected
    print(f"\nInvoice recall: {overall:.0%}")
    assert overall >= 0.90, f"Priority 1 recall {overall:.0%} < 90%"


@pytest.mark.skipif(not SOCIAL_PDF.exists(), reason="Sample PDF not found")
def test_social_security_priority1_recall():
    pages = extract(str(SOCIAL_PDF))
    findings = detect(pages)
    total_expected = sum(len(v) for v in SOCIAL_EXPECTED.values())
    total_hits = 0
    for pii_type, expected_values in SOCIAL_EXPECTED.items():
        detected = _detected_values(findings, pii_type)
        r = _recall(expected_values, detected)
        total_hits += r * len(expected_values)
        print(f"  {pii_type}: recall={r:.0%} detected={detected}")
    overall = total_hits / total_expected
    print(f"\nSocial notice recall: {overall:.0%}")
    assert overall >= 0.90, f"Priority 1 recall {overall:.0%} < 90%"


@pytest.mark.skipif(not INVOICE_PDF.exists(), reason="Sample PDF not found")
def test_ahv_detected_in_invoice():
    pages = extract(str(INVOICE_PDF))
    findings = detect(pages)
    ahv = _detected_values(findings, "AHV")
    assert any("756" in v for v in ahv), f"AHV not detected, got: {ahv}"


@pytest.mark.skipif(not SOCIAL_PDF.exists(), reason="Sample PDF not found")
def test_ahv_detected_spaced_format():
    pages = extract(str(SOCIAL_PDF))
    findings = detect(pages)
    ahv = _detected_values(findings, "AHV")
    assert any("756" in v for v in ahv), f"AHV not detected, got: {ahv}"


@pytest.mark.skipif(not INVOICE_PDF.exists(), reason="Sample PDF not found")
def test_no_pii_leaked_to_stdout(capsys):
    pages = extract(str(INVOICE_PDF))
    detect(pages)
    captured = capsys.readouterr()
    assert "Lara Meier" not in captured.out
    assert "756.9217" not in captured.out
