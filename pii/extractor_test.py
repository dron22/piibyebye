"""Tests for PDF text extraction."""

from pathlib import Path

from pii.extractor import PageText, extract

TESTDATA = Path(__file__).parent / "testdata"
INVOICE_PDF = TESTDATA / "sample_hospital_invoice_synthetic.pdf"


def test_extract_returns_pages():
    pages = extract(str(INVOICE_PDF))
    assert len(pages) > 0
    assert all(isinstance(p, PageText) for p in pages)


def test_extract_text_content():
    pages = extract(str(INVOICE_PDF))
    full_text = "".join(p.text for p in pages)
    assert "Lara Meier" in full_text
    assert "756" in full_text  # AHV number prefix


def test_extract_chars_have_valid_bboxes():
    pages = extract(str(INVOICE_PDF))
    for page in pages:
        for char in page.chars:
            x0, y0, x1, y1 = char.bbox
            assert x1 >= x0
            assert y1 >= y0
