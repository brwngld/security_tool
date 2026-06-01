from __future__ import annotations

import shutil
import secrets
from pathlib import Path
from typing import Iterator

import pytest


@pytest.fixture
def workspace_temp_dir() -> Iterator[Path]:
    root = Path.cwd() / ".test-temp"
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"PsyberShield-{secrets.token_hex(4)}"
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)

