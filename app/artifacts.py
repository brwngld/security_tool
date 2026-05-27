from __future__ import annotations

from pathlib import Path

from app.models import ScanResult


def load_scan_result(input_path: str | Path) -> ScanResult:
    path = Path(input_path)
    return ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
