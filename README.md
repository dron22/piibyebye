# pii — Local PII Redaction Tool

Redact personal information from PDFs locally. No data leaves your device.

Detects and blacks out PII fields, produces a redacted PDF, and saves an encrypted key file so you can restore the original values later.

---

## Setup

```bash
pip install -e ".[dev]"
python -m spacy download en_core_web_lg
```

---

## Usage

### Redact a PDF

```bash
pii redact document.pdf
```

Detects PII, shows a summary, asks for confirmation, prompts for a password, then writes:
- `document_redacted.pdf` — PDF with PII blacked out and replaced by tokens
- `document_redacted.key.enc` — AES-encrypted key file (keep this safe)

**Options:**

```
--output, -o <dir>      Output directory (default: same as input)
--opaque                Use opaque tokens [REDACTED_001] instead of typed [NAME_1]
--yes, -y               Skip confirmation prompt (for scripting)
--report-file <path>    Write audit report to file instead of stdout
--ocr                   Enable OCR for scanned/image-only pages (requires tesseract)
--password <pwd>        Provide password inline (prefer interactive prompt)
```

**Examples:**

```bash
# Redact to a specific output folder
pii redact invoice.pdf --output ./redacted/

# Maximum privacy — opaque tokens hide even the PII type
pii redact invoice.pdf --opaque

# Scripted use — skip confirmation, provide password inline
pii redact invoice.pdf --yes --password "my-secret"

# Scanned document with OCR
pii redact scanned_form.pdf --ocr
```

### Restore a redacted PDF

```bash
pii unredact document_redacted.pdf document_redacted.key.enc
```

Prompts for the password used at redaction time, then writes `document_restored.pdf`.

```
--output, -o <dir>      Output directory (default: same as input)
--password <pwd>        Provide password inline (prefer interactive prompt)
```

---

## What gets detected

| Priority | PII Type | Examples |
|---|---|---|
| 1 | Full name | Lara Meier |
| 1 | AHV / AVS number | 756.9217.4821.09 |
| 1 | IBAN | CH44 3199 9123 0000 5512 8 |
| 1 | Phone number | +41 79 555 01 72 |
| 1 | Email address | user@example.com |
| 1 | Date of birth | 1991-07-14 |
| 1 | Patient ID | PT-49302817 |
| 1 | Insurance number | HC-CH-992-118-440 |
| 1 | National / passport ID | XK0002147 |
| 2 | Street address | Seestrasse 88, 8002 Zurich |
| 2 | Bank reference | RF18 0048 1200 0000 0000 9 |
| 3 | Diagnosis / ICD code | S93.4 - Sprain of ankle |
| 3 | Physician name | Dr. N. Keller |

---

## Key file

The key file is AES-256-GCM encrypted using a password you choose. It maps each token back to its original value:

```json
{
  "[NAME_1]": {"value": "Lara Meier", "type": "NAME", ...},
  "[AHV_1]":  {"value": "756.9217.4821.09", "type": "AHV", ...}
}
```

**Keep the key file safe.** Without it, redaction cannot be reversed. If you lose the password, the original values are unrecoverable.

---

## Development

```bash
make test       # run all tests
make lint       # check formatting, linting, types
make lint-fix   # auto-fix formatting and lint issues
make clean      # remove caches
```

---

## Architecture

```
pii/
├── cli.py          entry point — click commands
├── extractor.py    pymupdf text + bbox extraction, OCR
├── detector.py     Presidio PII detection + custom Swiss recognisers
├── reviewer.py     stdout summary + confirmation prompt
├── tokeniser.py    token generation and deduplication
├── redactor.py     PDF black box drawing + text overlay unredaction
├── keystore.py     AES-GCM key file encryption/decryption
└── reporter.py     audit summary
```

**Stack:** Python 3.11 · pymupdf · Microsoft Presidio · spaCy · cryptography · click
