"""Draw redaction boxes on PDF pages and overlay original values for un-redaction."""

import base64
from typing import Any

import fitz  # pymupdf

from pii.detector import Finding

# Small padding around bboxes to ensure full coverage including descenders
_BBOX_PADDING = 1.0


def redact_pdf(input_path: str, findings: list[Finding], output_path: str) -> dict[int, bytes]:
    """Draw filled black rectangles over all finding bboxes, insert token placeholders, and save.

    Each redacted region has its token (e.g. [NAME_1]) written in white on the black box.

    Returns a dict mapping page number → original (decompressed) content stream bytes,
    captured before any modification. Pass this to encrypt_keyfile() so that unredact_pdf()
    can restore the PDF to a byte-identical state.
    """
    doc = fitz.open(input_path)

    by_page: dict[int, list[Finding]] = {}
    for finding in findings:
        by_page.setdefault(finding.page, []).append(finding)

    page_content: dict[int, bytes] = {}

    for page_num in range(doc.page_count):
        page = doc[page_num]
        page_findings = by_page.get(page_num, [])

        if not page_findings:
            continue

        # Capture original content stream BEFORE any modification.
        # apply_redactions() rewrites the stream destructively; this snapshot is
        # the only way to restore byte-identical content during unredaction.
        page_content[page_num] = page.read_contents()

        for finding in page_findings:
            x0, y0, x1, y1 = finding.bbox
            rect = fitz.Rect(
                x0 - _BBOX_PADDING,
                y0 - _BBOX_PADDING,
                x1 + _BBOX_PADDING,
                y1 + _BBOX_PADDING,
            )
            page.add_redact_annot(rect, fill=(0, 0, 0))

        # Permanently remove underlying text and burn black fill into content stream
        page.apply_redactions()

        # Insert token as white text centred inside the black box
        for finding in page_findings:
            if not finding.token:
                continue
            x0, y0, x1, y1 = finding.bbox
            box_w = (x1 + _BBOX_PADDING) - (x0 - _BBOX_PADDING)
            box_h = (y1 + _BBOX_PADDING) - (y0 - _BBOX_PADDING)

            # Start from height-based size, then shrink to fit width.
            font_size = min(box_h * 0.75, 9.0)
            text_w = fitz.get_text_length(finding.token, fontname="helv", fontsize=font_size)
            if text_w > box_w:
                font_size *= box_w / text_w
            font_size = max(font_size, 4.0)

            # Re-measure after possible shrink for horizontal centering.
            text_w = fitz.get_text_length(finding.token, fontname="helv", fontsize=font_size)
            x_pos = (x0 + x1) / 2 - text_w / 2

            # Vertical: baseline = box centre + ~35% of font size (cap-height offset).
            y_pos = (y0 + y1) / 2 + font_size * 0.35

            page.insert_text(
                point=fitz.Point(x_pos, y_pos),
                text=finding.token,
                fontsize=font_size,
                color=(1, 1, 1),
            )

    doc.save(output_path)
    doc.close()
    return page_content


def unredact_pdf(
    redacted_path: str,
    key_map: dict[str, Any],
    output_path: str,
) -> list[str]:
    """Restore a redacted PDF to its original state using the decrypted key map.

    If the key map contains page_content (captured during redact_pdf), the original
    content stream bytes are written back directly — producing output byte-identical
    to the original PDF's page content. Falls back to bbox-based restoration for
    key files generated before this change.

    Returns a list of tokens that could not be matched (empty for new key files).
    """
    doc = fitz.open(redacted_path)
    unmatched: list[str] = []

    # Detect key file format: v2 has nested {"tokens": ..., "page_content": ...}
    if "tokens" in key_map:
        tokens = key_map["tokens"]
        page_content_b64: dict[str, str] = key_map.get("page_content", {})
    else:
        tokens = key_map  # v1 format: flat token dict
        page_content_b64 = {}

    if page_content_b64:
        # New approach: restore original content streams directly.
        # The page is brought back to byte-identical state — original fonts,
        # sizes, colours, glyph positions, kerning, all intact.
        for page_num_str, content_b64 in page_content_b64.items():
            page_num = int(page_num_str)
            original_bytes = base64.b64decode(content_b64)
            page = doc[page_num]

            xrefs = page.get_contents()
            if xrefs:
                # Overwrite the (rewritten) content stream with the original bytes.
                doc.update_stream(xrefs[0], original_bytes)
                # Remove any extra streams that were added (e.g. by insert_text).
                if len(xrefs) > 1:
                    page.set_contents(xrefs[0])
    else:
        # Fallback for old key files: use stored bboxes to paint over redactions.
        page_jobs: dict[int, list[tuple[fitz.Rect, str, float]]] = {}

        for token, entry in tokens.items():
            value = entry.get("value", "")
            font_size = float(entry.get("font_size", 10.0))
            occurrences = entry.get("occurrences")

            if occurrences:
                for occ in occurrences:
                    x0, y0, x1, y1 = occ["bbox"]
                    rect = fitz.Rect(
                        x0 - _BBOX_PADDING,
                        y0 - _BBOX_PADDING,
                        x1 + _BBOX_PADDING,
                        y1 + _BBOX_PADDING,
                    )
                    page_jobs.setdefault(occ["page"], []).append((rect, value, font_size))
            else:
                found = False
                for page in doc:
                    for hit in page.search_for(token):
                        found = True
                        page_jobs.setdefault(page.number, []).append((hit, value, font_size))
                if not found:
                    unmatched.append(token)

        for page_num, jobs in page_jobs.items():
            page = doc[page_num]
            for rect, _value, _font_size in jobs:
                page.add_redact_annot(rect, fill=(1, 1, 1))
            page.apply_redactions()
            for rect, _value, _font_size in jobs:
                expanded = fitz.Rect(rect.x0 - 1, rect.y0 - 1, rect.x1 + 1, rect.y1 + 1)
                page.draw_rect(expanded, color=None, fill=(1, 1, 1))
                page.insert_text(
                    point=fitz.Point(rect.x0, rect.y1 - 1),
                    text=_value,
                    fontsize=_font_size,
                    color=(0, 0, 0),
                )

    doc.save(output_path)
    doc.close()
    return unmatched
