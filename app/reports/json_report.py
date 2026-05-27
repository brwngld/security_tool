from __future__ import annotations

from pathlib import Path

from app.models import ScanResult


def write_json_report(result: ScanResult, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return path
