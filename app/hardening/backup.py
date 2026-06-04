from __future__ import annotations

from shutil import copy2
from pathlib import Path


def create_backup(stem: str, output_dir: str | Path = "backups") -> Path:
    source_path = Path(stem)
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    backup_file = path / f"{source_path.name}.bak"
    try:
        if source_path.exists():
            copy2(source_path, backup_file)
        else:
            backup_file.write_text("", encoding="utf-8")
    except PermissionError as exc:
        raise PermissionError(
            f"PsyberShield could not create a backup for {source_path}. "
            "If you are in the PsyberShield project root, try: sudo -E ./venv/bin/python -m app.main fix --local. "
            "Or point PsyberShield at an app-owned file."
        ) from exc
    return backup_file

