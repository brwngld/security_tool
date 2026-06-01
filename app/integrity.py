from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Iterable

from app.context import resolve_application_context
from app.models import IntegrityFile, IntegrityFinding, IntegrityReport


_DEFAULT_FILE_CANDIDATES = [
    ".env",
    "policy.json",
    "config.json",
    "settings.py",
    "app/config.py",
    "app/main.py",
    "run.py",
    "wsgi.py",
    "gunicorn.conf.py",
    "uwsgi.ini",
    "Procfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "nginx.conf",
    "conf/nginx.conf",
]

_DEFAULT_DIRECTORY_CANDIDATES = [
    "static",
    "public",
    "web",
    "www",
    "templates",
    "app/static",
    "app/templates",
    "scripts",
    "bin",
    "systemd",
    "startup",
]

_MONITORED_EXTENSIONS = {
    ".conf",
    ".cfg",
    ".ini",
    ".json",
    ".py",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
    ".service",
    ".socket",
    ".timer",
    ".yaml",
    ".yml",
    ".toml",
    ".env",
    ".html",
    ".js",
    ".css",
}


def _safe_timestamp(path: Path) -> str | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return datetime.fromtimestamp(stat.st_mtime, UTC).isoformat()


def _sha256(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return sha256(data).hexdigest()


def _classify_path(path: Path, root: Path) -> tuple[str, str]:
    relative = path
    try:
        relative = path.relative_to(root)
    except ValueError:
        pass

    lower_parts = [part.lower() for part in relative.parts]
    lower_name = path.name.lower()

    if any(part in {"static", "public", "web", "www", "templates"} for part in lower_parts):
        return "webroot", "webroot"
    if any(part in {"scripts", "bin", "startup"} for part in lower_parts):
        return "startup", "startup"
    if any(part in {"systemd"} for part in lower_parts) or lower_name.endswith((".service", ".socket", ".timer")):
        return "startup", "service"
    if lower_name in {
        ".env",
        "policy.json",
        "config.json",
        "settings.py",
        "run.py",
        "wsgi.py",
        "gunicorn.conf.py",
        "uwsgi.ini",
        "procfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "nginx.conf",
    } or lower_name.endswith((".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml")):
        return "config", "config"
    if lower_name.endswith((".sh", ".ps1", ".bat", ".cmd")):
        return "startup", "script"
    if lower_name.endswith(".py"):
        return "config", "application"
    return "config", "file"


def _iter_monitored_files(root: Path, extra_paths: Iterable[Path]) -> list[Path]:
    candidates: list[Path] = []
    seen: set[Path] = set()

    def add_path(candidate: Path) -> None:
        resolved = candidate
        try:
            resolved = candidate.resolve()
        except OSError:
            pass
        if resolved in seen:
            return
        seen.add(resolved)
        candidates.append(candidate)

    for relative in _DEFAULT_FILE_CANDIDATES:
        add_path(root / relative)

    for relative_dir in _DEFAULT_DIRECTORY_CANDIDATES:
        directory = root / relative_dir
        if not directory.exists() or not directory.is_dir():
            continue
        for file_path in sorted(directory.rglob("*")):
            if file_path.is_file() and file_path.suffix.lower() in _MONITORED_EXTENSIONS:
                add_path(file_path)

    for extra_path in extra_paths:
        path = Path(extra_path)
        if path.is_dir():
            for file_path in sorted(path.rglob("*")):
                if file_path.is_file() and file_path.suffix.lower() in _MONITORED_EXTENSIONS:
                    add_path(file_path)
        elif path.exists():
            add_path(path)

    return candidates


def _load_baseline(baseline_path: Path | None) -> IntegrityReport | None:
    if baseline_path is None or not baseline_path.exists():
        return None
    try:
        return IntegrityReport.model_validate_json(baseline_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _build_finding(
    *,
    finding_id: str,
    file_item: IntegrityFile,
    baseline_item: IntegrityFile | None,
    severity: str,
    confidence: str,
    title: str,
    description: str,
    recommended_action: str,
) -> IntegrityFinding:
    evidence = {
        "path": file_item.path,
        "category": file_item.category,
        "kind": file_item.kind,
        "status": file_item.status,
        "sha256": file_item.sha256,
        "size": file_item.size,
        "modified_at": file_item.modified_at,
    }
    if baseline_item is not None:
        evidence["baseline_status"] = baseline_item.status
        evidence["baseline_sha256"] = baseline_item.sha256

    return IntegrityFinding(
        id=finding_id,
        path=file_item.path,
        category=file_item.category,
        kind=file_item.kind,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        evidence=evidence,
        recommended_action=recommended_action,
    )


def _severity_for_status(status: str, category: str) -> str:
    if status == "missing":
        return "high" if category in {"config", "startup"} else "medium"
    if status == "changed":
        return "high" if category in {"config", "startup"} else "medium"
    return "medium"


def analyze_integrity_sources(
    root: Path,
    *,
    baseline_path: Path | None = None,
    extra_paths: Iterable[Path] | None = None,
) -> IntegrityReport:
    root_path = Path(root)
    baseline_report = _load_baseline(Path(baseline_path) if baseline_path is not None else None)
    context = resolve_application_context(None, root_path, None, require_target=False)
    monitored = _iter_monitored_files(root_path, extra_paths or [])

    current_items: dict[str, IntegrityFile] = {}
    for path in monitored:
        exists = path.exists()
        if not exists:
            continue
        category, kind = _classify_path(path, root_path)
        current_item = IntegrityFile(
            path=str(path),
            category=category,
            kind=kind,
            exists=exists,
            status="unchanged",
            sha256=_sha256(path) if exists and path.is_file() else None,
            size=path.stat().st_size if exists and path.is_file() else None,
            modified_at=_safe_timestamp(path) if exists else None,
        )
        current_items[current_item.path] = current_item

    baseline_items: dict[str, IntegrityFile] = {}
    if baseline_report is not None:
        baseline_items = {item.path: item for item in baseline_report.files}

    combined_paths = sorted(set(current_items) | set(baseline_items))
    files: list[IntegrityFile] = []
    findings: list[IntegrityFinding] = []
    notes: list[str] = []

    if baseline_report is None:
        notes.append("No integrity baseline was supplied; captured a fresh snapshot only.")
    else:
        notes.append(f"Compared against baseline {baseline_path}")

    for path_text in combined_paths:
        current_item = current_items.get(path_text)
        baseline_item = baseline_items.get(path_text)

        if current_item is None and baseline_item is not None:
            missing_item = IntegrityFile(
                path=baseline_item.path,
                category=baseline_item.category,
                kind=baseline_item.kind,
                exists=False,
                status="missing",
                sha256=None,
                size=None,
                modified_at=None,
            )
            files.append(missing_item)
            findings.append(
                _build_finding(
                    finding_id=f"integrity-missing-{len(findings) + 1}",
                    file_item=missing_item,
                    baseline_item=baseline_item,
                    severity=_severity_for_status("missing", missing_item.category),
                    confidence="high",
                    title="Monitored file is missing",
                    description="A file that existed in the baseline is no longer present.",
                    recommended_action="Restore the file from backup and verify whether the change was expected.",
                )
            )
            continue

        if current_item is None:
            continue

        if baseline_item is None:
            current_item.status = "new"
            files.append(current_item)
            findings.append(
                _build_finding(
                    finding_id=f"integrity-new-{len(findings) + 1}",
                    file_item=current_item,
                    baseline_item=None,
                    severity="medium" if current_item.category in {"config", "startup"} else "low",
                    confidence="medium",
                    title="New monitored file appeared",
                    description="A new file appeared inside a monitored location.",
                    recommended_action="Confirm the file came from an approved deployment or maintenance task.",
                )
            )
            continue

        if current_item.sha256 != baseline_item.sha256 or current_item.size != baseline_item.size:
            current_item.status = "changed"
            files.append(current_item)
            findings.append(
                _build_finding(
                    finding_id=f"integrity-changed-{len(findings) + 1}",
                    file_item=current_item,
                    baseline_item=baseline_item,
                    severity=_severity_for_status("changed", current_item.category),
                    confidence="high",
                    title="Monitored file changed",
                    description="The file hash or size differs from the baseline snapshot.",
                    recommended_action="Review the diff, verify the change, and restore from backup if it was not authorized.",
                )
            )
            continue

        files.append(current_item)

    changed_count = sum(1 for file_item in files if file_item.status == "changed")
    missing_count = sum(1 for file_item in files if file_item.status == "missing")
    new_count = sum(1 for file_item in files if file_item.status == "new")

    if findings:
        notes.append(
            f"Integrity drift detected: {changed_count} changed, {missing_count} missing, {new_count} new."
        )
    else:
        notes.append("No integrity drift was detected in the monitored files.")

    monitored_paths = [str(path) for path in monitored]
    return IntegrityReport(
        context=context,
        root=str(root_path),
        baseline_path=str(baseline_path) if baseline_path is not None else None,
        monitored_paths=monitored_paths,
        files=files,
        findings=findings,
        notes=notes,
    )


def write_integrity_snapshot(report: IntegrityReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path
