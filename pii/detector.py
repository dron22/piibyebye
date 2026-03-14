"""Detect PII in extracted page text and map findings back to bounding boxes."""

import logging
import re
from dataclasses import dataclass
from typing import Any, Optional

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

from pii.extractor import Char, PageText

log = logging.getLogger(__name__)


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
            # ICD-10 code optionally followed by " - description" to end of line.
            # e.g. "S93.4 - Sprain of ankle (synthetic ICD-10 code)"
            Pattern("ICD10", r"\b[A-Z]\d{2}(?:\.\d{1,2})?(?:\s*[-–]\s*[A-Za-z][^\n]*)?", 0.8),
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


# ── DOB detection ──────────────────────────────────────────────────────────────

# Finds all date-like values in text
_ANY_DATE_REGEX = re.compile(
    r"\b\d{4}-\d{2}-\d{2}\b"
    r"|\b\d{1,2}\.\d{1,2}\.\d{4}\b"
    r"|\b\d{1,2}/\d{1,2}/\d{4}\b"
    r"|\b\d{1,2}\s+(?:January|February|March|April|May|June|July|August"
    r"|September|October|November|December)\s+\d{4}\b"
    r"|\b(?:January|February|March|April|May|June|July|August"
    r"|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b",
    re.IGNORECASE,
)

# Labels that identify a date as a date of birth
_BIRTH_LABEL_REGEX = re.compile(
    r"(?:date\s+of\s+birth|birthdate|birthday|\bdob\b|\bborn\b"
    r"|geburtsdatum|geburtstag|\bgeboren\b"
    r"|date\s+de\s+naissance|\bnaissance\b|\bn[ée]e?\b"
    r"|data\s+di\s+nascita|\bnascita\b|\bnato\b|\bnata\b)"
    r"[^0-9\n]{0,30}",
    re.IGNORECASE,
)

# Labels that identify a date as definitively NOT a date of birth
_NON_BIRTH_LABEL_REGEX = re.compile(
    r"(?:invoice\s+date|notice\s+date|service\s+date|admission\s+date"
    r"|discharge\s+date|issue\s+date|payment\s+date|due\s+date"
    r"|generated|effective|report\s+date|statement\s+date|order\s+date"
    r"|claim\s+date|visit\s+date|procedure\s+date|start\s+date|end\s+date"
    r"|expir\w+\s+date|renewal\s+date|treatment\s+date|appointment\s+date)"
    r"[^0-9\n]{0,30}",
    re.IGNORECASE,
)

_LABEL_WINDOW = 80  # chars to look back for a label
_DOB_ANCHOR_TEXT = "date of birth born birthday geburtsdatum"
_DOB_EMBEDDING_THRESHOLD = 0.70

_dob_anchor_doc: Optional[Any] = None


def _get_dob_anchor(nlp: Any) -> Optional[Any]:
    global _dob_anchor_doc
    if _dob_anchor_doc is None:
        _dob_anchor_doc = nlp(_DOB_ANCHOR_TEXT)
    return _dob_anchor_doc


def _classify_date_label(preceding: str) -> str:
    """Return 'dob', 'non_dob', or 'unknown' based on the last label before the date.

    Taking the last match means the label closest to the date wins, so a
    'Date of birth' earlier on the same page cannot promote 'Notice date: <value>'.
    """
    birth_matches = list(_BIRTH_LABEL_REGEX.finditer(preceding))
    non_birth_matches = list(_NON_BIRTH_LABEL_REGEX.finditer(preceding))

    last_birth = birth_matches[-1].end() if birth_matches else -1
    last_non_birth = non_birth_matches[-1].end() if non_birth_matches else -1

    if last_birth == -1 and last_non_birth == -1:
        return "unknown"
    return "dob" if last_birth > last_non_birth else "non_dob"


# ── Presidio engine ────────────────────────────────────────────────────────────

# Map Presidio entity types to our typed token prefixes
_ENTITY_TO_TOKEN_TYPE = {
    "PERSON": "NAME",
    "EMAIL_ADDRESS": "EMAIL",
    "EMAIL": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "IBAN_CODE": "IBAN",
    "IBAN": "IBAN",
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

_engine: Optional[AnalyzerEngine] = None
_spacy_nlp: Optional[Any] = None


def _get_engine() -> AnalyzerEngine:
    global _engine, _spacy_nlp
    if _engine is None:
        _engine = _build_engine()
        try:
            # Reuse the spaCy model already loaded by Presidio — avoids a second load
            _spacy_nlp = _engine.nlp_engine.nlp["en"]  # type: ignore[attr-defined]
        except (AttributeError, KeyError):
            pass  # embedding fallback silently disabled
    return _engine


def detect(pages: list[PageText], include_diagnoses: bool = False) -> list[Finding]:
    """Run PII detection over all pages and return findings with bboxes.

    Diagnosis codes (ICD-10) are excluded by default; pass include_diagnoses=True to enable.
    """
    engine = _get_engine()
    all_findings: list[Finding] = []

    for page in pages:
        if page.is_empty:
            continue

        text = page.text
        char_index = _build_char_index(page.chars)

        # Presidio-based detection (everything except DOB)
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

        # DOB detection: regex classification first, embedding fallback for unknowns
        for match in _ANY_DATE_REGEX.finditer(text):
            value = match.group().strip()
            preceding = text[max(0, match.start() - _LABEL_WINDOW) : match.start()]
            label = _classify_date_label(preceding)

            log.debug(
                "DOB candidate %r on page %d — label=%s | preceding: %r",
                value,
                page.page_num,
                label,
                preceding.strip(),
            )

            if label == "non_dob":
                log.debug("  -> skip (non-birth label)")
                continue

            if label == "unknown":
                if _spacy_nlp is None:
                    log.debug("  -> skip (no spaCy model for embedding fallback)")
                    continue
                preceding_stripped = preceding.strip()
                sim = (
                    float(_spacy_nlp(preceding_stripped).similarity(_get_dob_anchor(_spacy_nlp)))
                    if preceding_stripped
                    else 0.0
                )
                log.debug("  -> embedding similarity=%.3f threshold=%.2f", sim, _DOB_EMBEDDING_THRESHOLD)
                if sim < _DOB_EMBEDDING_THRESHOLD:
                    log.debug("  -> skip (below threshold)")
                    continue
                log.debug("  -> accept (embedding)")
            else:
                log.debug("  -> accept (birth label)")

            bbox = _span_to_bbox(char_index, match.start(), match.end())
            if bbox is None:
                continue
            font_name, font_size = _find_font(page.chars, match.start(), match.end())
            confidence = 0.85 if label == "dob" else 0.65
            all_findings.append(
                Finding(
                    type="DOB",
                    value=value,
                    page=page.page_num,
                    bbox=bbox,
                    confidence=confidence,
                    font_name=font_name,
                    font_size=font_size,
                )
            )

    findings = _deduplicate(all_findings)
    if not include_diagnoses:
        findings = [f for f in findings if f.type != "DIAGNOSIS"]
    return findings


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


def _bbox_overlap_ratio(a: tuple[float, float, float, float], b: tuple[float, float, float, float]) -> float:
    """Return what fraction of the smaller bbox is covered by the intersection."""
    ix0, iy0 = max(a[0], b[0]), max(a[1], b[1])
    ix1, iy1 = min(a[2], b[2]), min(a[3], b[3])
    inter = max(0.0, ix1 - ix0) * max(0.0, iy1 - iy0)
    if inter == 0.0:
        return 0.0
    area_a = (a[2] - a[0]) * (a[3] - a[1])
    area_b = (b[2] - b[0]) * (b[3] - b[1])
    smaller = min(area_a, area_b)
    return inter / smaller if smaller > 0 else 0.0


_OVERLAP_THRESHOLD = 0.3  # suppress if 30%+ of the smaller bbox is already covered


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove exact duplicates, then suppress lower-confidence findings with overlapping bboxes."""
    seen: set[tuple] = set()
    unique = []
    for f in findings:
        key = (f.type, f.value, f.page, f.bbox)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Greedily accept findings in confidence order; drop any that overlap an accepted one.
    unique.sort(key=lambda f: f.confidence, reverse=True)
    accepted: list[Finding] = []
    for f in unique:
        if not any(a.page == f.page and _bbox_overlap_ratio(a.bbox, f.bbox) >= _OVERLAP_THRESHOLD for a in accepted):
            accepted.append(f)
    return accepted
