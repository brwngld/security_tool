from __future__ import annotations

import os
from pathlib import Path
from typing import Sequence

from pydantic import BaseModel, Field


SCAN_TARGET_KEYS = ("APP_URL", "TARGET_URL", "BASE_URL")


def build_no_scan_target_message(keys: Sequence[str] = SCAN_TARGET_KEYS) -> str:
    checked = [
        "command line URL",
        "--env-file",
        "project .env",
        "OS environment",
    ]
    lines = ["No scan target provided.", "", "Checked:"]
    lines.extend(f"- {name}: not set" for name in checked)
    lines.extend(
        [
            "",
            "Pass a URL:",
            "  python -m app.main scan https://example.com",
            "",
            "Or set:",
            "  APP_URL=http://127.0.0.1:5000",
            "",
            "Or point Turan at a file:",
            "  python -m app.main scan --env-file /path/to/autoentrytrack/.env",
        ]
    )
    return "\n".join(lines)


NO_SCAN_TARGET_MESSAGE = build_no_scan_target_message()


class ResolvedScanTarget(BaseModel):
    value: str
    source: str
    key: str | None = None


def resolve_env_file_path(root: Path | None = None) -> Path:
    root_path = Path.cwd() if root is None else Path(root)
    return root_path / ".env"


def read_env_path(env_path: Path) -> dict[str, str]:
    if not env_path.exists():
        return {}

    data: dict[str, str] = {}
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        data[key.strip()] = value.strip().strip("'\"")
    return data


def read_env_file(root: Path | None = None, env_file: Path | None = None) -> dict[str, str]:
    env_path = Path(env_file) if env_file is not None else resolve_env_file_path(root)
    return read_env_path(env_path)


def iter_env_paths(root: Path | None = None, env_file: Path | None = None) -> list[Path]:
    root_env_path = resolve_env_file_path(root)
    if env_file is None:
        return [root_env_path]

    env_file_path = Path(env_file)
    if env_file_path.resolve() == root_env_path.resolve():
        return [root_env_path]
    return [env_file_path, root_env_path]


def lookup_env_value(key: str, root: Path | None = None, env_file: Path | None = None) -> ResolvedScanTarget | None:
    for env_path in iter_env_paths(root, env_file):
        env_data = read_env_path(env_path)
        value = env_data.get(key)
        if value and value.strip():
            return ResolvedScanTarget(value=value.strip(), source=str(env_path), key=key)

    runtime_value = os.environ.get(key)
    if runtime_value and runtime_value.strip():
        return ResolvedScanTarget(value=runtime_value.strip(), source="environment", key=key)

    return None


def find_scan_target(
    root: Path | None = None,
    keys: Sequence[str] = SCAN_TARGET_KEYS,
    env_file: Path | None = None,
) -> ResolvedScanTarget | None:
    for key in keys:
        found = lookup_env_value(key, root, env_file)
        if found is not None:
            return found

    return None


def resolve_scan_target(
    explicit_url: str | None,
    root: Path | None = None,
    env_file: Path | None = None,
) -> ResolvedScanTarget:
    if explicit_url:
        return ResolvedScanTarget(value=explicit_url, source="command line", key="command line")

    target = find_scan_target(root, env_file=env_file)
    if target is None:
        raise ValueError(NO_SCAN_TARGET_MESSAGE)
    return target
