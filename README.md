# PII Bye Bye — Local PII Redaction Tool

```
 ██████╗ ██╗██╗    ██████╗ ██╗   ██╗███████╗    ██████╗ ██╗   ██╗███████╗
 ██╔══██╗██║██║    ██╔══██╗╚██╗ ██╔╝██╔════╝    ██╔══██╗╚██╗ ██╔╝██╔════╝
 ██████╔╝██║██║    ██████╔╝ ╚████╔╝ █████╗      ██████╔╝ ╚████╔╝ █████╗
 ██╔═══╝ ██║██║    ██╔══██╗  ╚██╔╝  ██╔══╝      ██╔══██╗  ╚██╔╝  ██╔══╝
 ██║     ██║██║    ██████╔╝   ██║   ███████╗    ██████╔╝   ██║   ███████╗
 ╚═╝     ╚═╝╚═╝    ╚═════╝    ╚═╝   ╚══════╝    ╚═════╝    ╚═╝   ╚══════╝
```

Redact personal information from PDFs locally. No data leaves your device.

Detects and blacks out PII fields, produces a redacted PDF, and saves an encrypted key file so you can restore the original values later.

[How it works](docs/concept.md) — concept overview and design rationale

---

## Quick start — Web UI

```bash
# English only
pip install piibyebye

# With additional language support (de, fr, it, es — combine freely)
pip install "piibyebye[de,fr]"
pip install "piibyebye[all]"

pii web
```

Opens at `http://localhost:7860`. Upload a PDF, review detected fields, download the redacted PDF and key file. No command line knowledge needed.

---

## AI tool integration

Keep your PDFs private when working with AI coding tools. A hook can automatically redact documents before the model ever sees the content.

- [Claude Code](docs/claude.md)

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
--diagnoses             Also redact diagnosis codes / ICD-10 (disabled by default)
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

# Include diagnosis codes (ICD-10) in redaction
pii redact medical_report.pdf --diagnoses
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

## Sample documents

The `demo/` folder contains synthetic PDFs you can use to try the tool right away:

| File | Contents |
|---|---|
| `sample_hospital_invoice_synthetic.pdf` | Hospital invoice with names, dates, IBANs |
| `sample_social_security_notice_synthetic.pdf` | Social security letter with AHV number and address |

```bash
pii redact demo/sample_hospital_invoice_synthetic.pdf
```

---

## Development

```bash
pip install -e ".[dev]"          # English only
pip install -e ".[dev,de,fr]"    # with additional languages
```
