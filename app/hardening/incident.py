from __future__ import annotations

from pathlib import Path
import subprocess
from shutil import copy2

from app.hardening.backup import create_backup
from app.models import IncidentFinding, IncidentReport, LocalFixResult


_SCANNER_REGEX = r"(?:sqlmap|nikto|nmap|masscan|zgrab|curl|wget|python-requests|libwww-perl|go-http-client)"
_AUTH_REGEX = r"(?:failed password|invalid user|authentication failure|pam_unix|sudo:|accepted publickey)"
_PROBE_REGEX = r"(?:/\.env|/\.git|/\.git/config|/wp-login\.php|/wp-admin|/phpmyadmin|/server-status|/admin|/backup|/backup\.zip|/dump\.sql|/cgi-bin)"
_INJECTION_REGEX = r"(?:union\s+select|or\s+1=1|and\s+1=1|\.\./|%2e%2e|;\s*(?:curl|wget|id|cat|bash|sh)|\|\s*(?:curl|wget|id|cat|bash|sh)|\$\(|\{\{|<script|/etc/passwd)"


def _ensure_denylist_include(text: str, include_path: Path) -> tuple[str, bool]:
    include_line = f"include {include_path.as_posix()};"
    if include_line in text:
        return text, False

    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith("server {"):
            indent = " " * (len(line) - len(line.lstrip()) + 4)
            lines.insert(index + 1, f"{indent}{include_line}")
            break
    else:
        lines.extend(["", include_line])

    updated = "\n".join(lines)
    if text.endswith("\n"):
        updated += "\n"
    return updated, True


def _validate_nginx_config(config_path: Path) -> tuple[bool, str, str]:
    command = ["nginx", "-t", "-c", str(config_path)]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    output = (completed.stdout or completed.stderr or "").strip() or "Validation completed."
    return completed.returncode == 0, " ".join(command), output


def _build_denylist_text(blocked_ips: list[str]) -> str:
    lines = [
        "# Turan incident denylist",
        "# Generated automatically from suspicious log activity.",
        "",
    ]
    for ip in blocked_ips:
        lines.append(f"deny {ip};")
    lines.append("")
    return "\n".join(lines)


def _unique_nonempty(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        cleaned = value.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        ordered.append(cleaned)
    return ordered


def _collect_failregexes(report: IncidentReport) -> list[str]:
    categories = {finding.category for finding in report.findings}
    families = {finding.log_family for finding in report.findings if finding.log_family}
    patterns: list[str] = []

    if "scanner" in categories or "apache-access" in families or "nginx-access" in families:
        patterns.append(rf"<HOST>.*{_SCANNER_REGEX}")
    if "auth" in categories or "auth" in families or "systemd" in families:
        patterns.append(rf"<HOST>.*{_AUTH_REGEX}")
    if "probe" in categories:
        patterns.append(rf"<HOST>.*{_PROBE_REGEX}")
    if "injection" in categories:
        patterns.append(rf"<HOST>.*{_INJECTION_REGEX}")
    if "apache-error" in families:
        patterns.append(r"<HOST>.*(?:client denied by server configuration|file does not exist|script not found or unable to stat|mod_security|AH0[0-9]+)")

    if not patterns:
        patterns.append(r"<HOST>.*(?:sqlmap|nikto|failed password|invalid user|/\.env|union select)")

    return _unique_nonempty(patterns)


def build_fail2ban_artifact(report: IncidentReport) -> str:
    log_paths = _unique_nonempty(report.source_files[:5])
    primary_log_path = log_paths[0] if log_paths else "/var/log/nginx/access.log"
    failregexes = _collect_failregexes(report)
    lines = [
        "# Turan fail2ban-style incident filter",
        "# Generated from suspicious activity analysis.",
        "",
        "[INCLUDES]",
        "before = common.conf",
        "",
        "[Definition]",
        "failregex =",
    ]
    for pattern in failregexes:
        lines.append(f"    {pattern}")
    lines.extend(
        [
            "ignoreregex =",
            "",
            "[turan-incident]",
            "enabled = true",
            "filter = turan-incident",
            f"logpath = {primary_log_path}",
            "maxretry = 5",
            "findtime = 600",
            "bantime = 3600",
            "",
            "# Review the captured log lines before enabling this in production.",
        ]
    )
    return "\n".join(lines)


def write_fail2ban_artifact(report: IncidentReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_fail2ban_artifact(report), encoding="utf-8")
    return path


def apply_nginx_denylist(
    config_path: Path,
    blocked_ips: list[str],
    backup_path: Path | None = None,
) -> LocalFixResult:
    if not config_path.exists():
        return LocalFixResult(
            target_path=str(config_path),
            status="blocked",
            reason="The discovered Nginx config does not exist.",
            notes=["No file was changed."],
        )

    if not blocked_ips:
        return LocalFixResult(
            target_path=str(config_path),
            status="skipped",
            reason="No blocked IPs were produced by the incident analysis.",
            notes=["No file was changed."],
        )

    denylist_path = config_path.with_name("incident-denylist.conf")
    original_config = config_path.read_text(encoding="utf-8", errors="ignore")
    original_denylist = denylist_path.read_text(encoding="utf-8", errors="ignore") if denylist_path.exists() else None

    try:
        if backup_path is None:
            backup_path = create_backup(config_path, config_path.parent)
        elif not backup_path.exists():
            copy2(config_path, backup_path)
    except PermissionError:
        return LocalFixResult(
            target_path=str(config_path),
            status="blocked",
            reason="Turan could not create a backup for the discovered Nginx config.",
            notes=["No file was changed."],
        )

    denylist_text = _build_denylist_text(sorted(dict.fromkeys(blocked_ips)))
    denylist_path.write_text(denylist_text, encoding="utf-8")

    updated_config, changed = _ensure_denylist_include(original_config, denylist_path)
    if changed:
        config_path.write_text(updated_config, encoding="utf-8")

    validated, validation_command, validation_output = _validate_nginx_config(config_path)
    if not validated:
        config_path.write_text(original_config, encoding="utf-8")
        if original_denylist is None:
            denylist_path.unlink(missing_ok=True)
        else:
            denylist_path.write_text(original_denylist, encoding="utf-8")
        return LocalFixResult(
            target_path=str(config_path),
            status="rolled_back",
            reason="The Nginx validation check failed, so Turan restored the backup.",
            backup_path=str(backup_path),
            validation_command=validation_command,
            validation_output=validation_output,
            notes=["The config and denylist were restored."],
        )

    return LocalFixResult(
        target_path=str(config_path),
        status="applied",
        reason=f"Added a denylist include for {len(blocked_ips)} blocked IPs and the validation check passed.",
        backup_path=str(backup_path),
        validation_command=validation_command,
        validation_output=validation_output,
        notes=[f"Denylist written to {denylist_path.as_posix()}", "Reload the service when you are ready."],
    )


def apply_incident_containment(report: IncidentReport, config_path: Path) -> LocalFixResult:
    return apply_nginx_denylist(config_path, report.blocked_ips)
