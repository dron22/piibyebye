"""Tests for detection summary and confirmation prompt."""

from pii.detector import Finding
from pii.reviewer import review


def _finding(type_: str, value: str, token: str) -> Finding:
    f = Finding(type=type_, value=value, page=0, bbox=(0, 0, 10, 10), confidence=0.9)
    f.token = token
    return f


def test_skip_confirm_returns_findings():
    findings = [_finding("NAME", "Lara Meier", "[NAME_1]")]
    result = review(findings, skip_confirm=True)
    assert result == findings


def test_summary_printed(capsys):
    findings = [
        _finding("NAME", "Lara Meier", "[NAME_1]"),
        _finding("IBAN", "CH44 3199", "[IBAN_1]"),
    ]
    review(findings, skip_confirm=True)
    captured = capsys.readouterr()
    assert "NAME" in captured.out
    assert "IBAN" in captured.out
    assert "Lara Meier" in captured.out
    assert "[NAME_1]" in captured.out


def test_empty_findings(capsys):
    result = review([], skip_confirm=True)
    assert result == []
