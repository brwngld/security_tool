from __future__ import annotations

from pathlib import Path

from rich.console import Group
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.table import Table


def render_stored_report_preview(report_file: str | Path):
    path = Path(report_file)
    suffix = path.suffix.lower()
    preview = Table(title="Stored Report")
    preview.add_column("Field", style="cyan", no_wrap=True)
    preview.add_column("Value", style="white")
    preview.add_row("Path", str(path))
    preview.add_row("Format", suffix.lstrip(".") or "unknown")
    preview.add_row("Size", f"{path.stat().st_size} bytes")

    text = path.read_text(encoding="utf-8")
    if suffix in {".md", ".markdown"}:
        return Group(preview, Markdown(text))
    if suffix in {".html", ".htm"}:
        return Group(preview, Syntax(text, "html", word_wrap=True, line_numbers=False))
    return Group(preview)
