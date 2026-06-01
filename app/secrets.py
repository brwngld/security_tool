from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from app.models import SecretExposureFinding, SecretExposureReport
from app.redaction import redact_text


_SECRET_EXTENSIONS = {
    ".conf",
    ".cfg",
    ".ini",
    ".json",
    ".py",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
    ".yaml",
    ".yml",
    ".toml",
    ".env",
    ".log",
    ".txt",
    ".md",
}

_SKIP_DIRECTORY_PARTS = {".git", ".pytest-cache", ".test-temp", "venv", ".venv", "node_modules", "outputs"}

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("authorization", re.compile(r"(?i)authorization:\s*bearer\s+([^\s]+)"), "Bearer token exposed in a file or log line."),
    ("password", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\",;#]+)"), "Password-like value exposed in a file or log line."),
    ("token", re.compile(r"(?i)(token|secret)\s*[:=]\s*['\"]?([^\s'\",;#]+)"), "Token-like value exposed in a file or log line."),
    ("api-key", re.compile(r"(?i)(api[_-]?key)\s*[:=]\s*['\"]?([^\s'\",;#]+)"), "API key-like value exposed in a file or log line."),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "Private key material appears in the file."),
    ("cookie", re.compile(r"(?i)(session|cookie)\s*[:=]\s*['\"]?([^\s'\",;#]+)"), "Session or cookie-like value exposed in a file or log line."),
]


def _iter_candidate_files(root: Path, extra_paths: Iterable[Path] | None = None) -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()

    def add(path: Path) -> None:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved in seen:
            return
        seen.add(resolved)
        files.append(path)

    for path in [root / ".env", root / "policy.json", root / "app" / "config.py", root / "nginx.conf"]:
        if path.exists() and path.is_file():
            add(path)

    for folder_name in ("logs", "app", "config", "conf", "systemd", "startup", "static", "public", "web", "www", "templates"):
        folder = root / folder_name
        if not folder.exists() or not folder.is_dir():
            continue
        for candidate in sorted(folder.rglob("*")):
            if candidate.is_file() and candidate.suffix.lower() in _SECRET_EXTENSIONS:
                add(candidate)

    for candidate in sorted(root.rglob("*")):
        if not candidate.is_file() or candidate.suffix.lower() not in _SECRET_EXTENSIONS:
            continue
        if any(part.lower() in _SKIP_DIRECTORY_PARTS for part in candidate.parts):
            continue
        add(candidate)

    for extra in extra_paths or []:
        candidate = Path(extra)
        if candidate.is_dir():
            for file_path in sorted(candidate.rglob("*")):
                if file_path.is_file() and file_path.suffix.lower() in _SECRET_EXTENSIONS:
                    add(file_path)
        elif candidate.is_file():
            add(candidate)

    return files


def analyze_secret_exposures(
    root: Path,
    *,
    extra_paths: Iterable[Path] | None = None,
    max_findings: int = 100,
) -> SecretExposureReport:
    root_path = Path(root)
    source_files = _iter_candidate_files(root_path, extra_paths)
    findings: list[SecretExposureFinding] = []

    for path in source_files:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line_number, line in enumerate(lines, start=1):
            if len(findings) >= max_findings:
                break
            for category, pattern, explanation in _SECRET_PATTERNS:
                if not pattern.search(line):
                    continue
                redacted = redact_text(line)
                severity = "critical" if category == "private-key" else "high"
                findings.append(
                    SecretExposureFinding(
                        id=f"secret-{len(findings) + 1}",
                        path=str(path),
                        line_number=line_number,
                        category=category,
                        severity=severity,
                        confidence="high",
                        title="Potential secret exposure detected",
                        evidence={
                            "line": redacted,
                            "pattern": category,
                            "source": path.name,
                        },
                        recommended_action=explanation,
                    )
                )
                break
        if len(findings) >= max_findings:
            break

    notes = [
        f"Scanned {len(source_files)} candidate file(s).",
        "Potential secrets were redacted before being stored in the report.",
    ]
    if not findings:
        notes.append("No obvious secret exposure was detected in the monitored files.")
    return SecretExposureReport(
        root=str(root_path),
        source_files=[str(path) for path in source_files],
        findings=findings,
        notes=notes,
    )
