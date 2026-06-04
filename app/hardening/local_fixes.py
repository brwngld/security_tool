from __future__ import annotations

import subprocess
from pathlib import Path
from shutil import copy2

from app.models import LocalFixResult, ScanResult
from app.hardening.nginx import security_header_snippet


def choose_local_fix_target(result: ScanResult) -> Path | None:
    if result.context is None:
        return None
    discovery = result.context.discovery
    supported_categories = {"server_info", "headers"}
    if not any(finding.category in supported_categories for finding in result.findings):
        return None
    if discovery.nginx_config:
        return Path(discovery.nginx_config)
    return None


def _ensure_server_tokens_off(text: str) -> tuple[str, bool]:
    if "server_tokens off;" in text:
        return text, False

    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith("server {"):
            indent = " " * (len(line) - len(line.lstrip()) + 4)
            lines.insert(index + 1, f"{indent}server_tokens off;")
            break
    else:
        lines.extend(["", "server_tokens off;"])

    updated = "\n".join(lines)
    if text.endswith("\n"):
        updated += "\n"
    return updated, True


def _ensure_security_headers(text: str) -> tuple[str, bool]:
    snippet_lines = security_header_snippet().strip().splitlines()
    if all(line.strip() in text for line in snippet_lines):
        return text, False

    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith("server {"):
            indent = " " * (len(line) - len(line.lstrip()) + 4)
            insert_block = [f"{indent}{snippet_line}" for snippet_line in snippet_lines]
            lines[index + 1:index + 1] = insert_block
            break
    else:
        lines.extend([""] + snippet_lines)

    updated = "\n".join(lines)
    if text.endswith("\n"):
        updated += "\n"
    return updated, True


def _validate_nginx_config(config_path: Path) -> tuple[bool, str, str]:
    command = ["nginx", "-t", "-c", str(config_path)]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    output = (completed.stdout or completed.stderr or "").strip() or "Validation completed."
    return completed.returncode == 0, " ".join(command), output


def apply_local_nginx_hardening_fix(
    config_path: Path,
    categories: list[str] | None = None,
    backup_path: Path | None = None,
) -> LocalFixResult:
    if not config_path.exists():
        return LocalFixResult(
            target_path=str(config_path),
            status="blocked",
            reason="The discovered Nginx config does not exist.",
            notes=["No file was changed."],
        )

    selected_categories = set(categories or ["server_info"])
    original_text = config_path.read_text(encoding="utf-8", errors="ignore")
    updated_text = original_text
    changed = False
    if "server_info" in selected_categories:
        updated_text, changed = _ensure_server_tokens_off(updated_text)
    header_changed = False
    if "headers" in selected_categories:
        updated_text, header_changed = _ensure_security_headers(updated_text)
        changed = changed or header_changed
    if not changed:
        return LocalFixResult(
            target_path=str(config_path),
            status="skipped",
            reason="The selected local hardening change is already present.",
            notes=["No edit was needed."],
        )

    try:
        if backup_path is None:
            backup_path = config_path.with_suffix(config_path.suffix + ".bak")
            copy2(config_path, backup_path)
        elif not backup_path.exists():
            copy2(config_path, backup_path)
    except PermissionError:
        return LocalFixResult(
            target_path=str(config_path),
            status="blocked",
            reason=(
                "PsyberShield could not create a backup for the discovered Nginx config. "
                "If you are in the PsyberShield project root, try: sudo -E ./venv/bin/python -m app.main fix --local. "
                "Or point PsyberShield at an app-owned file."
            ),
            notes=["No file was changed."],
        )

    try:
        config_path.write_text(updated_text, encoding="utf-8")
    except PermissionError:
        return LocalFixResult(
            target_path=str(config_path),
            status="blocked",
            reason=(
                "PsyberShield could not write the local fix to the discovered Nginx config. "
                "If you are in the PsyberShield project root, try: sudo -E ./venv/bin/python -m app.main fix --local. "
                "Or point PsyberShield at an app-owned file."
            ),
            backup_path=str(backup_path),
            notes=["The backup was created, but the file could not be updated."],
        )

    validated, validation_command, validation_output = _validate_nginx_config(config_path)
    if not validated:
        backup_text = backup_path.read_text(encoding="utf-8", errors="ignore")
        config_path.write_text(backup_text, encoding="utf-8")
        return LocalFixResult(
            target_path=str(config_path),
            status="rolled_back",
            reason="The Nginx validation check failed, so PsyberShield restored the backup.",
            backup_path=str(backup_path),
            validation_command=validation_command,
            validation_output=validation_output,
            notes=["The file was restored from backup."],
        )

    applied_parts = []
    if "server_info" in selected_categories:
        applied_parts.append("server_tokens off;")
    if header_changed:
        applied_parts.append("security headers")
    if not applied_parts:
        applied_parts.append("the selected local hardening change")

    return LocalFixResult(
        target_path=str(config_path),
        status="applied",
        reason=f"Inserted {' and '.join(applied_parts)} and the validation check passed.",
        backup_path=str(backup_path),
        validation_command=validation_command,
        validation_output=validation_output,
        notes=["Reload the service when you are ready."],
    )


def apply_local_nginx_banner_fix(config_path: Path, backup_path: Path | None = None) -> LocalFixResult:
    return apply_local_nginx_hardening_fix(config_path, categories=["server_info"], backup_path=backup_path)

