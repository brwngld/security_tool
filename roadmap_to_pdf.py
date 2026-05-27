from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


PAGE_WIDTH = 612  # Letter
PAGE_HEIGHT = 792
LEFT = 50
TOP = 48
BOTTOM = 48
FONT_SIZE_BODY = 10
FONT_SIZE_TITLE = 18
FONT_SIZE_SECTION = 13
LINE_HEIGHT = 14


@dataclass
class LinkLine:
    text: str
    url: str


class PdfWriter:
    def __init__(self) -> None:
        self.objects: list[bytes] = []

    def add_object(self, body: bytes) -> int:
        self.objects.append(body)
        return len(self.objects)

    @staticmethod
    def _escape_text(text: str) -> str:
        return (
            text.replace("\\", "\\\\")
            .replace("(", "\\(")
            .replace(")", "\\)")
        )

    def _make_stream(self, lines: list[str]) -> bytes:
        content = "\n".join(lines).encode("ascii")
        return (
            f"<< /Length {len(content)} >>\nstream\n".encode("ascii")
            + content
            + b"\nendstream"
        )

    def build(self, pages: list[dict], output_path: Path) -> None:
        font_obj = self.add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        mono_font_obj = self.add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

        page_obj_ids: list[int] = []
        page_annots: list[list[int]] = []

        for page in pages:
            annots: list[int] = []
            content_lines: list[str] = []
            y = PAGE_HEIGHT - TOP

            for item in page["items"]:
                kind = item["kind"]
                if kind == "title":
                    content_lines.append(f"BT /F1 {FONT_SIZE_TITLE} Tf 50 {y} Td ({self._escape_text(item['text'])}) Tj ET")
                    y -= 28
                elif kind == "section":
                    content_lines.append(f"BT /F1 {FONT_SIZE_SECTION} Tf 50 {y} Td ({self._escape_text(item['text'])}) Tj ET")
                    y -= 20
                elif kind == "body":
                    for line in self._wrap(item["text"], 82):
                        content_lines.append(f"BT /F2 {FONT_SIZE_BODY} Tf 50 {y} Td ({self._escape_text(line)}) Tj ET")
                        y -= LINE_HEIGHT
                    y -= 2
                elif kind == "bullet":
                    for line in self._wrap(f"- {item['text']}", 80):
                        content_lines.append(f"BT /F2 {FONT_SIZE_BODY} Tf 50 {y} Td ({self._escape_text(line)}) Tj ET")
                        y -= LINE_HEIGHT
                    y -= 2
                elif kind == "link":
                    text = item["text"]
                    url = item["url"]
                    display = f"{text}: {url}"
                    content_lines.append(f"BT /F2 {FONT_SIZE_BODY} Tf 50 {y} Td ({self._escape_text(display)}) Tj ET")
                    text_width = max(len(display) * 6, 20)
                    rect = [50, y - 2, 50 + text_width, y + 10]
                    annots.append(self.add_object(
                        (
                            f"<< /Type /Annot /Subtype /Link /Rect [{rect[0]} {rect[1]} {rect[2]} {rect[3]}] "
                            f"/Border [0 0 0] /A << /S /URI /URI ({self._escape_text(url)}) >> >>"
                        ).encode("ascii")
                    ))
                    y -= LINE_HEIGHT + 2
                elif kind == "spacer":
                    y -= item.get("height", 10)

                if y < BOTTOM:
                    raise ValueError("Page content overflowed; add another page")

            stream_obj = self.add_object(self._make_stream(content_lines))
            page_obj = self.add_object(
                (
                    f"<< /Type /Page /Parent 0 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
                    f"/Resources << /Font << /F1 {font_obj} 0 R /F2 {mono_font_obj} 0 R >> >> "
                    f"/Contents {stream_obj} 0 R"
                    + (f" /Annots [{ ' '.join(f'{aid} 0 R' for aid in annots) }]" if annots else "")
                    + " >>"
                ).encode("ascii")
            )
            page_obj_ids.append(page_obj)
            page_annots.append(annots)

        pages_obj = self.add_object(
            (
                f"<< /Type /Pages /Kids [{' '.join(f'{pid} 0 R' for pid in page_obj_ids)}] "
                f"/Count {len(page_obj_ids)} >>"
            ).encode("ascii")
        )

        # Patch each page parent reference after the /Pages object exists.
        for idx, page_obj_id in enumerate(page_obj_ids):
            obj = self.objects[page_obj_id - 1]
            self.objects[page_obj_id - 1] = obj.replace(b"/Parent 0 0 R", f"/Parent {pages_obj} 0 R".encode("ascii"))

        info_obj = self.add_object(
            (
                "<< /Title (Python Web Security Roadmap) "
                "/Author (OpenAI Codex) "
                "/Subject (Learning roadmap for a Python web security scanner and hardening assistant) "
                "/Producer (Custom PDF generator) >>"
            ).encode("ascii")
        )

        catalog_obj = self.add_object(
            f"<< /Type /Catalog /Pages {pages_obj} 0 R >>".encode("ascii")
        )

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


def make_pages() -> list[dict]:
    resources = [
        LinkLine("HTTPX docs", "https://www.python-httpx.org/"),
        LinkLine("Beautiful Soup docs", "https://www.crummy.com/software/BeautifulSoup/bs4/doc/"),
        LinkLine("urllib.parse docs", "https://docs.python.org/3/library/urllib.parse.html"),
        LinkLine("ssl docs", "https://docs.python.org/3/library/ssl.html"),
        LinkLine("Typer docs", "https://typer.tiangolo.com/"),
        LinkLine("Rich docs", "https://rich.readthedocs.io/"),
        LinkLine("Pydantic docs", "https://docs.pydantic.dev/"),
        LinkLine("Jinja docs", "https://jinja.palletsprojects.com/"),
        LinkLine("pytest docs", "https://docs.pytest.org/"),
        LinkLine("OWASP WSTG", "https://owasp.org/www-project-web-security-testing-guide/"),
        LinkLine("OWASP HTTP Headers Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"),
        LinkLine("OWASP HSTS Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"),
        LinkLine("Apache security tips", "https://httpd.apache.org/docs/2.4/en/misc/security_tips.html"),
        LinkLine("Apache mod_headers", "https://httpd.apache.org/docs/current/en/mod/mod_headers.html"),
        LinkLine("NGINX security controls", "https://docs.nginx.com/nginx/admin-guide/security-controls/"),
        LinkLine("OWASP Juice Shop", "https://owasp.org/www-project-juice-shop"),
        LinkLine("DVWA", "https://www.dvwa.co.uk/"),
    ]

    page1 = {
        "items": [
            {"kind": "title", "text": "Python Web Security Scanner + Hardening Assistant"},
            {"kind": "body", "text": "A focused roadmap for building a v1 scanner first, then layering on reporting, hardening guidance, and tests."},
            {"kind": "section", "text": "Resource Stack"},
            *(
                {"kind": "link", "text": link.text, "url": link.url}
                for link in resources[:9]
            ),
            {"kind": "section", "text": "More References"},
            *(
                {"kind": "link", "text": link.text, "url": link.url}
                for link in resources[9:14]
            ),
        ]
    }

    page2 = {
        "items": [
            {"kind": "section", "text": "Roadmap"},
            {"kind": "bullet", "text": "Phase 1: HTTPX and urllib.parse for fetching pages, handling redirects, headers, cookies, status codes, and URL normalization."},
            {"kind": "bullet", "text": "Phase 2: Beautiful Soup for crawling links, forms, scripts, images, and page structure."},
            {"kind": "bullet", "text": "Phase 3: ssl and socket for certificate expiry, TLS basics, and hostname verification."},
            {"kind": "bullet", "text": "Phase 4: Pydantic for findings, scan results, and configuration models."},
            {"kind": "bullet", "text": "Phase 5: Typer and Rich for a clean CLI with tables, progress bars, and severity labels."},
            {"kind": "bullet", "text": "Phase 6: JSON and Jinja2 for machine-readable exports and HTML reports."},
            {"kind": "bullet", "text": "Phase 7: pytest for regression coverage and confidence as the scanner grows."},
            {"kind": "section", "text": "Practice Targets"},
            *(
                {"kind": "link", "text": link.text, "url": link.url}
                for link in resources[14:]
            ),
            {"kind": "section", "text": "What to Focus on First"},
            {"kind": "body", "text": "HTTP and HTTPS basics, security headers, cookies and session security, CORS, TLS and SSL basics, redirects, directory listing, exposed sensitive files, dangerous HTTP methods, server information disclosure, and WAF signals."},
            {"kind": "section", "text": "What to Skip for v1"},
            {"kind": "body", "text": "Skip ML features, AI features, advanced exploitation, malware analysis, Kubernetes, cloud security, async scanning, and a full database system until the core scanner is stable."},
        ]
    }

    return [page1, page2]


def main() -> None:
    output = Path("python-web-security-roadmap.pdf")
    writer = PdfWriter()
    writer.build(make_pages(), output)
    print(f"Wrote {output.resolve()}")


if __name__ == "__main__":
    main()
