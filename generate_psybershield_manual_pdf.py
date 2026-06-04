from __future__ import annotations

from pathlib import Path

from generate_user_guide_pdf import PdfWriter, paginate, render_markdown_lines


SOURCE_DOCS = [
    ("User Guide", "docs/turan-user-guide.md"),
    ("Architecture", "docs/architecture.md"),
    ("Changelog", "docs/changelog.md"),
]


def build_combined_markdown(root: Path) -> str:
    sections: list[str] = [
        "# PsyberShield Manual",
        "",
        "A combined manual covering usage, architecture notes, and project history.",
        "",
    ]

    for title, relative_path in SOURCE_DOCS:
        source_path = root / relative_path
        sections.extend(
            [
                f"## {title}",
                "",
                f"Source: `{relative_path}`",
                "",
                source_path.read_text(encoding="utf-8").rstrip(),
                "",
            ]
        )

    return "\n".join(sections)


def main() -> None:
    root = Path(__file__).resolve().parent
    output_path = root / "psybershield-manual.pdf"
    markdown = build_combined_markdown(root)
    items = render_markdown_lines(markdown)
    pages = paginate(items)
    writer = PdfWriter()
    writer.build(pages, output_path)
    print(f"Wrote {output_path.resolve()}")


if __name__ == "__main__":
    main()
