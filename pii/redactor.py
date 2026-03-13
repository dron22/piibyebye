"""Draw redaction boxes on PDF pages and overlay original values for un-redaction."""

import fitz  # pymupdf

from pii.detector import Finding

# Small padding around bboxes to ensure full coverage including descenders
_BBOX_PADDING = 1.0


def redact_pdf(input_path: str, findings: list[Finding], output_path: str) -> None:
    """Draw filled black rectangles over all finding bboxes, insert token placeholders, and save.

    Each redacted region has its token (e.g. [NAME_1]) written in white on the black box.
    This makes the token searchable for un-redaction and visible in the redacted document.
    """
    doc = fitz.open(input_path)

    # Group findings by page so we can apply redactions page-by-page
    by_page: dict[int, list[Finding]] = {}
    for finding in findings:
        by_page.setdefault(finding.page, []).append(finding)

    for page_num in range(doc.page_count):
        page = doc[page_num]
        page_findings = by_page.get(page_num, [])

        for finding in page_findings:
            x0, y0, x1, y1 = finding.bbox
            rect = fitz.Rect(
                x0 - _BBOX_PADDING,
                y0 - _BBOX_PADDING,
                x1 + _BBOX_PADDING,
                y1 + _BBOX_PADDING,
            )
            page.add_redact_annot(rect, fill=(0, 0, 0))

        # Apply redactions — permanently removes underlying text in annotated rects
        page.apply_redactions()

        # After applying redactions, insert the token as white text on the black box
        for finding in page_findings:
            if not finding.token:
                continue
            x0, y0, x1, y1 = finding.bbox
            box_height = (y1 + _BBOX_PADDING) - (y0 - _BBOX_PADDING)
            font_size = min(max(box_height * 0.75, 5.0), 9.0)
            page.insert_text(
                point=fitz.Point(x0, y1),
                text=finding.token,
                fontsize=font_size,
                color=(1, 1, 1),  # white text on black background
            )

    doc.save(output_path)
    doc.close()


def unredact_pdf(
    redacted_path: str,
    key_map: dict[str, dict],
    output_path: str,
) -> list[str]:
    """Overlay original values at token positions in the redacted PDF.

    key_map format: {token: {"value": str, "font_name": str, "font_size": float, ...}}

    Returns a list of tokens that were not found in the PDF text (unmatched).
    """
    doc = fitz.open(redacted_path)
    unmatched: list[str] = []

    for token, entry in key_map.items():
        value = entry.get("value", "")
        font_size = float(entry.get("font_size", 10.0))
        found = False

        for page in doc:
            # Search for the token text in the page
            hits = page.search_for(token)
            for rect in hits:
                found = True
                # Draw a white box over the black redaction box first
                page.draw_rect(rect, color=(1, 1, 1), fill=(1, 1, 1))
                # Insert original value as text
                page.insert_text(
                    point=fitz.Point(rect.x0, rect.y1 - 1),
                    text=value,
                    fontsize=font_size,
                    color=(0, 0, 0),
                )

        if not found:
            unmatched.append(token)

    doc.save(output_path)
    doc.close()
    return unmatched
