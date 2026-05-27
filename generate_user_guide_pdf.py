from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


PAGE_WIDTH = 612  # Letter
PAGE_HEIGHT = 792
LEFT = 50
TOP = 48
BOTTOM = 48
FONT_SIZE_BODY = 10
FONT_SIZE_TITLE = 18
FONT_SIZE_SECTION = 13
FONT_SIZE_SUBSECTION = 11
LINE_HEIGHT = 14


@dataclass
class PdfLine:
    kind: str
    text: str


class PdfWriter:
    def __init__(self) -> None:
        self.objects: list[bytes] = []

    def add_object(self, body: bytes) -> int:
        self.objects.append(body)
        return len(self.objects)

    @staticmethod
    def _escape_text(text: str) -> str:
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def _make_stream(self, lines: list[str]) -> bytes:
        content = "\n".join(lines).encode("ascii", errors="ignore")
        return f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"\nendstream"

    def build(self, pages: list[list[PdfLine]], output_path: Path) -> None:
        font_obj = self.add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        mono_font_obj = self.add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

        page_obj_ids: list[int] = []

        for page in pages:
            content_lines: list[str] = []
            y = PAGE_HEIGHT - TOP

            for item in page:
                text = item.text
                if item.kind == "title":
                    content_lines.append(f"BT /F1 {FONT_SIZE_TITLE} Tf {LEFT} {y} Td ({self._escape_text(text)}) Tj ET")
                    y -= 28
                elif item.kind == "section":
                    content_lines.append(f"BT /F1 {FONT_SIZE_SECTION} Tf {LEFT} {y} Td ({self._escape_text(text)}) Tj ET")
                    y -= 20
                elif item.kind == "subsection":
                    content_lines.append(f"BT /F1 {FONT_SIZE_SUBSECTION} Tf {LEFT} {y} Td ({self._escape_text(text)}) Tj ET")
                    y -= 16
                elif item.kind == "code":
                    content_lines.append(f"BT /F2 {FONT_SIZE_BODY} Tf {LEFT} {y} Td ({self._escape_text(text)}) Tj ET")
                    y -= LINE_HEIGHT
                elif item.kind == "bullet":
                    content_lines.append(f"BT /F2 {FONT_SIZE_BODY} Tf {LEFT} {y} Td ({self._escape_text(text)}) Tj ET")
                    y -= LINE_HEIGHT
                else:
                    content_lines.append(f"BT /F2 {FONT_SIZE_BODY} Tf {LEFT} {y} Td ({self._escape_text(text)}) Tj ET")
                    y -= LINE_HEIGHT

                if y < BOTTOM:
                    raise ValueError("Page content overflowed; add another page")

            stream_obj = self.add_object(self._make_stream(content_lines))
            page_obj = self.add_object(
                (
                    f"<< /Type /Page /Parent 0 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
                    f"/Resources << /Font << /F1 {font_obj} 0 R /F2 {mono_font_obj} 0 R >> >> "
                    f"/Contents {stream_obj} 0 R >>"
                ).encode("ascii")
            )
            page_obj_ids.append(page_obj)

        pages_obj = self.add_object(
            f"<< /Type /Pages /Kids [{' '.join(f'{pid} 0 R' for pid in page_obj_ids)}] /Count {len(page_obj_ids)} >>".encode(
                "ascii"
            )
        )

        for page_obj_id in page_obj_ids:
            obj = self.objects[page_obj_id - 1]
            self.objects[page_obj_id - 1] = obj.replace(b"/Parent 0 0 R", f"/Parent {pages_obj} 0 R".encode("ascii"))

        info_obj = self.add_object(
            (
                "<< /Title (Turan User Guide) "
                "/Author (OpenAI Codex) "
                "/Subject (Living user guide for the Turan scanner and hardening assistant) "
                "/Producer (Custom PDF generator) >>"
            ).encode("ascii")
        )

        catalog_obj = self.add_object(f"<< /Type /Catalog /Pages {pages_obj} 0 R >>".encode("ascii"))

        pdf = bytearray()
        pdf.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

        offsets = [0]
        for idx, obj in enumerate(self.objects, start=1):
            offsets.append(len(pdf))
            pdf.extend(f"{idx} 0 obj\n".encode("ascii"))
            pdf.extend(obj)
            pdf.extend(b"\nendobj\n")

        xref_pos = len(pdf)
        pdf.extend(f"xref\n0 {len(self.objects) + 1}\n".encode("ascii"))
        pdf.extend(b"0000000000 65535 f \n")
        for off in offsets[1:]:
            pdf.extend(f"{off:010d} 00000 n \n".encode("ascii"))
        pdf.extend(
            (
                f"trailer\n<< /Size {len(self.objects) + 1} /Root {catalog_obj} 0 R /Info {info_obj} 0 R >>\n"
                f"startxref\n{xref_pos}\n%%EOF\n"
            ).encode("ascii")
        )

        output_path.write_bytes(pdf)

    @staticmethod
    def _wrap(text: str, width: int) -> list[str]:
        words = text.split()
        lines: list[str] = []
        current = ""
        for word in words:
            candidate = word if not current else f"{current} {word}"
            if len(candidate) <= width:
                current = candidate
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
        return lines or [""]


def render_markdown_lines(source: str) -> list[PdfLine]:
    lines = source.splitlines()
    items: list[PdfLine] = []
    in_code = False

    for raw_line in lines:
        line = raw_line.rstrip()
        stripped = line.strip()

        if stripped.startswith("```"):
            in_code = not in_code
            continue

        if in_code:
            items.append(PdfLine("code", line))
            continue

        if not stripped:
            items.append(PdfLine("blank", ""))
            continue

        if stripped.startswith("# "):
            items.append(PdfLine("title", stripped[2:].strip()))
            continue

        if stripped.startswith("## "):
            items.append(PdfLine("section", stripped[3:].strip()))
            continue

        if stripped.startswith("### "):
            items.append(PdfLine("subsection", stripped[4:].strip()))
            continue

        if stripped.startswith(("- ", "* ")):
            for idx, wrapped in enumerate(PdfWriter._wrap(stripped[2:].strip(), 86)):
                prefix = "- " if idx == 0 else "  "
                items.append(PdfLine("bullet", f"{prefix}{wrapped}"))
            continue

        if stripped[:2].isdigit() and ". " in stripped[:4]:
            for idx, wrapped in enumerate(PdfWriter._wrap(stripped, 86)):
                prefix = "" if idx == 0 else "  "
                items.append(PdfLine("bullet", f"{prefix}{wrapped}"))
            continue

        if stripped.startswith("|"):
            items.append(PdfLine("code", stripped))
            continue

        for wrapped in PdfWriter._wrap(stripped, 86):
            items.append(PdfLine("body", wrapped))

    return items


def paginate(items: list[PdfLine], max_lines_per_page: int = 42) -> list[list[PdfLine]]:
    pages: list[list[PdfLine]] = []
    current: list[PdfLine] = []
    line_count = 0

    for item in items:
        if item.kind == "blank":
            line_count += 1
            current.append(item)
            if line_count >= max_lines_per_page:
                pages.append(current)
                current = []
                line_count = 0
            continue

        line_count += 1
        current.append(item)
        if line_count >= max_lines_per_page:
            pages.append(current)
            current = []
            line_count = 0

    if current:
        pages.append(current)

    return pages or [[PdfLine("title", "Turan User Guide")]]


def main() -> None:
    root = Path(__file__).resolve().parent
    source_path = root / "docs" / "turan-user-guide.md"
    output_path = root / "turan-user-guide.pdf"
    markdown = source_path.read_text(encoding="utf-8")
    items = render_markdown_lines(markdown)
    pages = paginate(items)
    writer = PdfWriter()
    writer.build(pages, output_path)
    print(f"Wrote {output_path.resolve()}")


if __name__ == "__main__":
    main()
