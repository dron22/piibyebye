"""Detect PII in extracted page text and map findings back to bounding boxes."""

from dataclasses import dataclass
from typing import Optional

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

from pii.extractor import Char, PageText


@dataclass
class Finding:
    type: str
    value: str
    page: int
    bbox: tuple[float, float, float, float]
    confidence: float
    token: Optional[str] = None
    # Font info stored for un-redaction fidelity
    font_name: str = "helv"
    font_size: float = 10.0


def _build_engine() -> AnalyzerEngine:
    """Build Presidio AnalyzerEngine with English NER and custom Swiss recognisers."""
    configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
    }
    provider = NlpEngineProvider(nlp_configuration=configuration)
    nlp_engine = provider.create_engine()

    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(nlp_engine=nlp_engine)

    # Custom recognisers
    registry.add_recognizer(_ahv_recogniser())
    registry.add_recognizer(_swiss_insurance_recogniser())
    registry.add_recognizer(_patient_id_recogniser())
    registry.add_recognizer(_icd_code_recogniser())
    registry.add_recognizer(_iban_recogniser())
    registry.add_recognizer(_email_recogniser())

    return AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)


def _ahv_recogniser() -> PatternRecognizer:
    """AHV / AVS number in dotted, spaced, and compact formats."""
    return PatternRecognizer(
        supported_entity="AHV",
        patterns=[
            Pattern("AHV_DOTTED", r"\b756[.\s]?\d{4}[.\s]?\d{4}[.\s]?\d{2}\b", 0.95),
            Pattern("AHV_COMPACT", r"\b756\d{10}\b", 0.85),
        ],
        context=["ahv", "avs", "versicherungsnummer", "assurance"],
    )


def _swiss_insurance_recogniser() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="INSURANCE_NUM",
        patterns=[
            Pattern("SWISS_INS", r"\b(?:HC|INS|KK|KV)-CH-[\d-]{6,20}\b", 0.9),
        ],
        context=["insurance", "policy", "versicherung", "assurance", "poliz"],
    )


def _patient_id_recogniser() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="PATIENT_ID",
        patterns=[
            Pattern("PATIENT_ID", r"\bPT-\d{6,12}\b", 0.95),
        ],
        context=["patient", "id", "number"],
    )


def _icd_code_recogniser() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="ICD_CODE",
        patterns=[
            # ICD-10: letter + 2 digits + optional dot + 1-2 digits (e.g. S93.4, R07.9)
            Pattern("ICD10", r"\b[A-Z]\d{2}(?:\.\d{1,2})?\b", 0.8),
        ],
        context=["diagnosis", "icd", "code", "diagnose"],
    )


def _iban_recogniser() -> PatternRecognizer:
    """IBAN recogniser that does not require a valid checksum — covers synthetic data."""
    return PatternRecognizer(
        supported_entity="IBAN",
        patterns=[
            Pattern("IBAN_GENERIC", r"\b[A-Z]{2}\d{2}(?:[ \t]?[A-Z0-9]{4}){2,6}(?:[ \t]?[A-Z0-9]{1,4})?\b", 0.85),
        ],
        context=["iban", "account", "bank", "konto", "payment", "zahlungs"],
    )


def _email_recogniser() -> PatternRecognizer:
    """Email recogniser that accepts any TLD, including reserved ones like .example."""
    return PatternRecognizer(
        supported_entity="EMAIL",
        patterns=[
            Pattern("EMAIL", r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b", 0.9),
        ],
    )


# Map Presidio entity types to our typed token prefixes
_ENTITY_TO_TOKEN_TYPE = {
    "PERSON": "NAME",
    "EMAIL_ADDRESS": "EMAIL",
    "EMAIL": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "IBAN_CODE": "IBAN",
    "IBAN": "IBAN",
    "DATE_TIME": "DOB",
    "LOCATION": "ADDRESS",
    "AHV": "AHV",
    "INSURANCE_NUM": "INSURANCE",
    "PATIENT_ID": "PATIENT_ID",
    "ICD_CODE": "DIAGNOSIS",
    "US_SSN": "ID",
    "NRP": "ID",
    "MEDICAL_LICENSE": "ID",
}

_SUPPORTED_ENTITIES = list(_ENTITY_TO_TOKEN_TYPE.keys())

# Lazy-initialised engine (loading spaCy model is slow)
_engine: Optional[AnalyzerEngine] = None


def _get_engine() -> AnalyzerEngine:
    global _engine
    if _engine is None:
        _engine = _build_engine()
    return _engine


def detect(pages: list[PageText]) -> list[Finding]:
    """Run PII detection over all pages and return findings with bboxes."""
    engine = _get_engine()
    all_findings: list[Finding] = []

    for page in pages:
        if page.is_empty:
            continue

        text = page.text
        char_index = _build_char_index(page.chars)

        results = engine.analyze(text=text, language="en", entities=_SUPPORTED_ENTITIES)

        for result in results:
            value = text[result.start : result.end].strip()
            if not value:
                continue
            bbox = _span_to_bbox(char_index, result.start, result.end)
            if bbox is None:
                continue

            token_type = _ENTITY_TO_TOKEN_TYPE.get(result.entity_type, result.entity_type)
            font_name, font_size = _find_font(page.chars, result.start, result.end)

            all_findings.append(
                Finding(
                    type=token_type,
                    value=value,
                    page=page.page_num,
                    bbox=bbox,
                    confidence=result.score,
                    font_name=font_name,
                    font_size=font_size,
                )
            )

    return _deduplicate(all_findings)


def _build_char_index(chars: list[Char]) -> list[tuple[int, Char]]:
    """Map text string offset → Char object. Handles multi-char bboxes from OCR."""
    index = []
    offset = 0
    for char in chars:
        index.append((offset, char))
        offset += len(char.text)
    return index


def _span_to_bbox(
    char_index: list[tuple[int, Char]],
    start: int,
    end: int,
) -> Optional[tuple[float, float, float, float]]:
    """Merge bboxes of all chars in the span [start, end) into a single bbox."""
    x0s, y0s, x1s, y1s = [], [], [], []

    for offset, char in char_index:
        char_end = offset + len(char.text)
        if char_end <= start:
            continue
        if offset >= end:
            break
        x0, y0, x1, y1 = char.bbox
        x0s.append(x0)
        y0s.append(y0)
        x1s.append(x1)
        y1s.append(y1)

    if not x0s:
        return None
    return (min(x0s), min(y0s), max(x1s), max(y1s))


def _find_font(chars: list[Char], start: int, end: int) -> tuple[str, float]:
    """Return font name and size for the first char in the span (best effort)."""
    # PageText chars don't carry font info — return sensible defaults.
    # Un-redaction will use the PDF's existing font at that position.
    return "helv", 10.0


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove exact duplicate findings (same type, value, page, bbox)."""
    seen: set[tuple] = set()
    unique = []
    for f in findings:
        key = (f.type, f.value, f.page, f.bbox)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
