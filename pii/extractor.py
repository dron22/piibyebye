"""Extract text with character-level bounding boxes from PDF pages."""

from __future__ import annotations

from dataclasses import dataclass, field

import fitz  # pymupdf


@dataclass
class Char:
    text: str
    bbox: tuple[float, float, float, float]  # x0, y0, x1, y1
    page: int


@dataclass
class PageText:
    page_num: int
    chars: list[Char] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "".join(c.text for c in self.chars)

    @property
    def is_empty(self) -> bool:
        return not self.text.strip()


def extract(pdf_path: str) -> list[PageText]:
    """Extract text and character bboxes from a PDF."""
    doc = fitz.open(pdf_path)
    pages = [_extract_page(page, i) for i, page in enumerate(doc)]
    doc.close()
    return pages


def _extract_page(page: fitz.Page, page_num: int) -> PageText:
    """Extract characters with bboxes from a text-based PDF page."""
    page_text = PageText(page_num=page_num)

    raw = page.get_text("rawdict", flags=fitz.TEXT_PRESERVE_WHITESPACE)
    for block in raw.get("blocks", []):
        if block.get("type") != 0:  # 0 = text block
            continue
        for line in block.get("lines", []):
            last_bbox: tuple[float, float, float, float] = (0.0, 0.0, 0.0, 0.0)
            for span in line.get("spans", []):
                for char in span.get("chars", []):
                    c = char.get("c", "")
                    bbox = tuple(char.get("bbox", (0.0, 0.0, 0.0, 0.0)))
                    if c:
                        page_text.chars.append(Char(text=c, bbox=bbox, page=page_num))
                        last_bbox = bbox
            # Add newline after each line so PII at line-end gets a word boundary
            page_text.chars.append(Char(text="\n", bbox=last_bbox, page=page_num))

    return page_text
