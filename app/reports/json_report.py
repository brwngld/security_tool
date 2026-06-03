from __future__ import annotations

from pathlib import Path

from app.models import ScanResult
from app.reports.branding import write_branded_json


def write_json_report(result: ScanResult, output_path: str | Path) -> Path:
    return write_branded_json(result, output_path, "scan")
