from __future__ import annotations

import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class NormalizedOutputPath:
    path: Path
    note: str | None = None


OPTIONAL_OUTPUT_FLAGS = {
    "--json-output",
    "--markdown-output",
    "--html-output",
    "--output",
    "--audit-log",
    "--log-file",
}


def _clean_output_base_name(value: str | None) -> str:
    cleaned = re.sub(r"[^a-z0-9._-]+", "-", (value or "output").strip().lower())
    return cleaned.strip("-") or "output"


def default_output_path(command_name: str | None, option_name: str, *, stamp: str | None = None) -> Path:
    if option_name in {"--audit-log", "--log-file"}:
        return Path("outputs") / "audit.log"

    suffix_map = {
        "--json-output": ".json",
        "--markdown-output": ".md",
        "--html-output": ".html",
        "--output": ".json",
    }
    suffix = suffix_map.get(option_name, ".txt")
    stamp_value = stamp or datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base_name = _clean_output_base_name(command_name)
    return Path("outputs") / f"{base_name}-{stamp_value}{suffix}"


def expand_optional_output_arguments(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    if not argv:
        return [], []

    command_name = next((token for token in argv[1:] if not token.startswith("-")), None)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    rewritten: list[str] = [argv[0]]
    notes: list[str] = []
    i = 1

    while i < len(argv):
        token = argv[i]
        if token in OPTIONAL_OUTPUT_FLAGS:
            next_token = argv[i + 1] if i + 1 < len(argv) else None
            if next_token is None or next_token.startswith("-"):
                default_path = default_output_path(command_name, token, stamp=stamp)
                rewritten.extend([token, default_path.as_posix()])
                notes.append(f"Using default output path for {token}: {default_path.as_posix()}")
                i += 1
                continue
        rewritten.append(token)
        i += 1

    return rewritten, notes


def normalize_output_path(value: str | Path | None, *, cwd: Path | None = None) -> NormalizedOutputPath | None:
    if value is None:
        return None

    path = Path(value)
    raw_value = str(value)
    root_dir = cwd or Path.cwd()

    if os.name == "nt" and path.drive == "" and path.root and raw_value.startswith(("\\", "/")):
        normalized = root_dir / raw_value.lstrip("\\/")
        return NormalizedOutputPath(
            path=normalized,
            note=f"Interpreted '{raw_value}' as: {normalized}",
        )

    return NormalizedOutputPath(path=path)
