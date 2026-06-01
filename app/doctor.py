from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
import socket
import sys
from dataclasses import dataclass
from shutil import which
from pathlib import Path
from typing import Literal, Sequence

from pydantic import BaseModel, Field

from app.context import ApplicationContext, resolve_application_context
from app.environment import lookup_env_value


DoctorStatus = Literal["ok", "warn", "info", "unknown"]


class DoctorCheck(BaseModel):
    name: str
    status: DoctorStatus
    summary: str
    details: dict[str, str] = Field(default_factory=dict)


class DoctorReport(BaseModel):
    root: str
    os_name: str
    os_release: str
    python_version: str
    context: ApplicationContext | None = None
    checks: list[DoctorCheck] = Field(default_factory=list)
    readiness_score: int | None = None


@dataclass
class _PortObservation:
    protocol: str
    state: str
    local_address: str
    remote_address: str
    pid: str | None = None
    process_name: str | None = None


def first_present_path(paths: Sequence[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None


def format_paths(paths: Sequence[Path]) -> str:
    visible = [str(path) for path in paths if path.exists()]
    return ", ".join(visible) if visible else "none found"


def is_weak_secret(value: str) -> bool:
    lowered = value.strip().lower()
    if len(value.strip()) < 16:
        return True
    return lowered in {
        "changeme",
        "change-me",
        "secret",
        "password",
        "dev",
        "test",
        "example",
    }


def check_env_file(root: Path, env_file: Path | None = None) -> DoctorCheck:
    env_path = Path(env_file) if env_file is not None else root / ".env"
    if env_path.exists():
        return DoctorCheck(name=".env", status="ok", summary="found", details={"path": str(env_path)})
    return DoctorCheck(name=".env", status="info", summary="not found", details={"path": str(env_path)})


def check_report_directory(root: Path) -> DoctorCheck:
    report_dir = root / "outputs"
    report_dir.mkdir(parents=True, exist_ok=True)
    probe = report_dir / ".doctor-write-test"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return DoctorCheck(name="Output folder", status="ok", summary="writable", details={"path": str(report_dir)})
    except OSError as exc:
        return DoctorCheck(name="Output folder", status="warn", summary="not writable", details={"error": exc.__class__.__name__})


def check_app_config_paths(root: Path, env_file: Path | None = None) -> DoctorCheck:
    candidates = [
        root / "policy.json",
        root / "policy.example.json",
        root / "config.json",
        root / "app" / "config.json",
        root / "app" / "config.py",
        root / "settings.py",
    ]
    if env_file is not None:
        candidates.insert(0, Path(env_file))
    else:
        candidates.insert(0, root / ".env")
    found = [path for path in candidates if path.exists()]
    if found:
        return DoctorCheck(
            name="App config paths",
            status="ok",
            summary="found",
            details={"paths": format_paths(found)},
        )
    return DoctorCheck(
        name="App config paths",
        status="warn",
        summary="none found",
        details={"searched": ", ".join(str(path) for path in candidates)},
    )


def check_nginx_paths(root: Path, nginx_config: Path | None = None) -> DoctorCheck:
    if nginx_config is not None:
        candidates = [Path(nginx_config)]
    else:
        candidates = [
            root / "nginx.conf",
            root / "conf" / "nginx.conf",
            Path(r"C:\nginx\conf\nginx.conf"),
            Path(r"C:\Program Files\nginx\conf\nginx.conf"),
            Path(r"C:\Program Files (x86)\nginx\conf\nginx.conf"),
            Path("/etc/nginx/nginx.conf"),
            Path("/usr/local/etc/nginx/nginx.conf"),
        ]
    found = [path for path in candidates if path.exists()]
    if found:
        return DoctorCheck(
            name="Nginx config paths",
            status="ok",
            summary="found",
            details={"paths": format_paths(found)},
        )
    return DoctorCheck(
        name="Nginx config paths",
        status="info",
        summary="not found",
        details={"searched": ", ".join(str(path) for path in candidates)},
    )


def check_nginx_hardening(root: Path, nginx_config: Path | None = None) -> DoctorCheck:
    if nginx_config is not None:
        candidates = [Path(nginx_config)]
    else:
        candidates = [
            root / "nginx.conf",
            root / "conf" / "nginx.conf",
            Path(r"C:\nginx\conf\nginx.conf"),
            Path(r"C:\Program Files\nginx\conf\nginx.conf"),
            Path(r"C:\Program Files (x86)\nginx\conf\nginx.conf"),
            Path("/etc/nginx/nginx.conf"),
            Path("/usr/local/etc/nginx/nginx.conf"),
        ]
    found = first_present_path(candidates)
    if found is None:
        return DoctorCheck(name="Nginx hardening", status="unknown", summary="config not found", details={})

    content = found.read_text(encoding="utf-8", errors="ignore").lower()
    server_tokens = "off" if "server_tokens off" in content else "on" if "server_tokens on" in content else "not set"
    https_configured = "configured" if "listen 443 ssl" in content or "ssl_certificate" in content else "not detected"
    status = "ok" if server_tokens == "off" and https_configured == "configured" else "warn"
    summary = f"HTTPS {https_configured}; server_tokens {server_tokens}"
    details = {"path": str(found)}
    return DoctorCheck(name="Nginx hardening", status=status, summary=summary, details=details)


def _run_port_command(command: list[str]) -> str:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError:
        return ""
    return (completed.stdout or completed.stderr or "").strip()


def _split_port(value: str) -> tuple[str, str | None]:
    text = value.strip().strip("[]")
    if text in {"", "*", "*:*"}:
        return text, None
    if text.count(":") == 1:
        host, port = text.rsplit(":", 1)
        return host, port if port.isdigit() else None
    host, sep, maybe_port = text.rpartition(":")
    if sep and maybe_port.isdigit():
        return host, maybe_port
    return text, None


def _is_loopback_host(host: str) -> bool:
    lowered = host.lower()
    if lowered in {"localhost", "::1"}:
        return True
    if lowered.startswith("127."):
        return True
    return False


def _is_public_ip(host: str) -> bool:
    candidate = host.split("%", 1)[0].strip("[]")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return address.is_global


def _parse_windows_netstat(output: str) -> list[_PortObservation]:
    observations: list[_PortObservation] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or not stripped.upper().startswith(("TCP", "UDP")):
            continue
        parts = stripped.split()
        if len(parts) < 4:
            continue

        protocol = parts[0].upper()
        local_address = parts[1]
        remote_address = parts[2] if len(parts) > 2 else ""
        state = ""
        pid = None

        if protocol == "UDP":
            if len(parts) >= 4 and parts[3].isdigit():
                pid = parts[3]
            observations.append(
                _PortObservation(
                    protocol=protocol,
                    state="LISTENING",
                    local_address=local_address,
                    remote_address=remote_address,
                    pid=pid,
                )
            )
            continue

        if len(parts) >= 4:
            state = parts[3].upper()
        if len(parts) >= 5 and parts[4].isdigit():
            pid = parts[4]

        observations.append(
            _PortObservation(
                protocol=protocol,
                state=state,
                local_address=local_address,
                remote_address=remote_address,
                pid=pid,
            )
        )
    return observations


def _parse_unix_port_output(output: str) -> list[_PortObservation]:
    observations: list[_PortObservation] = []
    user_re = re.compile(r'users:\(\("(?P<process>[^"]+)",pid=(?P<pid>\d+)')
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        if len(parts) < 5:
            continue
        protocol = parts[0].upper()
        state = parts[1].upper()
        local_address = parts[4]
        remote_address = parts[5] if len(parts) > 5 else ""
        match = user_re.search(stripped)
        pid = match.group("pid") if match else None
        process_name = match.group("process") if match else None
        observations.append(
            _PortObservation(
                protocol=protocol,
                state=state,
                local_address=local_address,
                remote_address=remote_address,
                pid=pid,
                process_name=process_name,
            )
        )
    return observations


def _collect_port_observations() -> tuple[list[_PortObservation], str | None]:
    system_name = platform.system().lower()
    commands: list[list[str]]
    if system_name.startswith("win"):
        commands = [["netstat", "-ano"]]
    else:
        commands = [["ss", "-tunap"], ["netstat", "-tunap"]]

    for command in commands:
        if which(command[0]) is None:
            continue
        output = _run_port_command(command)
        if not output:
            continue
        if command[0] == "netstat":
            return _parse_windows_netstat(output), " ".join(command)
        return _parse_unix_port_output(output), " ".join(command)

    return [], None


def check_process_and_port_activity() -> DoctorCheck:
    observations, command = _collect_port_observations()
    if not observations:
        return DoctorCheck(
            name="Process and port activity",
            status="info",
            summary="no port data captured",
            details={"command": command or "not available"},
        )

    public_listeners: list[str] = []
    outbound_connections: list[str] = []
    process_names: list[str] = []

    for observation in observations:
        process_label = observation.process_name or (f"pid={observation.pid}" if observation.pid else None)
        if process_label and process_label not in process_names:
            process_names.append(process_label)

        local_host, local_port = _split_port(observation.local_address)
        remote_host, remote_port = _split_port(observation.remote_address)
        state = observation.state.upper()

        if state in {"LISTEN", "LISTENING"}:
            if local_host and not _is_loopback_host(local_host):
                label = f"{observation.local_address}"
                if process_label:
                    label = f"{label} ({process_label})"
                public_listeners.append(label)
        elif state in {"ESTAB", "ESTABLISHED"}:
            if remote_host and _is_public_ip(remote_host):
                label = f"{observation.local_address} -> {observation.remote_address}"
                if process_label:
                    label = f"{label} ({process_label})"
                outbound_connections.append(label)

    if public_listeners or outbound_connections:
        details = {
            "command": command or "not available",
            "listeners": ", ".join(public_listeners[:4]) if public_listeners else "none",
            "outbound": ", ".join(outbound_connections[:4]) if outbound_connections else "none",
            "processes": ", ".join(process_names[:4]) if process_names else "none",
        }
        summary_bits = []
        if public_listeners:
            summary_bits.append(f"{len(public_listeners)} suspicious listener(s)")
        if outbound_connections:
            summary_bits.append(f"{len(outbound_connections)} outbound connection(s)")
        summary = "; ".join(summary_bits) if summary_bits else "activity captured"
        return DoctorCheck(name="Process and port activity", status="warn", summary=summary, details=details)

    details = {
        "command": command or "not available",
        "processes": ", ".join(process_names[:4]) if process_names else "none",
    }
    return DoctorCheck(name="Process and port activity", status="ok", summary="no suspicious listeners or outbound connections", details=details)


def check_local_ports(port_candidates: Sequence[int] | None = None) -> DoctorCheck:
    ports = list(port_candidates) if port_candidates is not None else [80, 443, 3000, 8000, 8080]
    open_ports: list[str] = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(0.2)
            if client.connect_ex(("127.0.0.1", port)) == 0:
                open_ports.append(str(port))

    if open_ports:
        return DoctorCheck(
            name="Open local ports",
            status="info",
            summary=f"listening on localhost: {', '.join(open_ports)}",
            details={"ports": ", ".join(open_ports)},
        )
    return DoctorCheck(name="Open local ports", status="info", summary="no common localhost ports responded", details={})


def check_setting(key: str, root: Path, env_file: Path | None = None) -> DoctorCheck:
    found = lookup_env_value(key, root, env_file)
    if found is None:
        return DoctorCheck(name=key, status="warn", summary="missing", details={})

    if key == "DEBUG" and found.value.strip().lower() in {"1", "true", "yes", "on"}:
        return DoctorCheck(name=key, status="warn", summary="enabled", details={"source": found.source})

    if key == "SECRET_KEY" and is_weak_secret(found.value):
        return DoctorCheck(name=key, status="warn", summary="present but weak", details={"source": found.source})

    return DoctorCheck(name=key, status="ok", summary="present", details={"source": found.source})


def check_secret_settings(root: Path, env_file: Path | None = None) -> list[DoctorCheck]:
    return [
        check_setting("DEBUG", root, env_file),
        check_setting("SECRET_KEY", root, env_file),
        check_setting("SERVER_NAME", root, env_file),
        check_setting("DATABASE_URL", root, env_file),
        check_setting("SMTP_PASSWORD", root, env_file),
    ]


def check_default_scan_target(context: ApplicationContext | None = None) -> DoctorCheck:
    if context is None or context.target is None:
        return DoctorCheck(
            name="Scan target",
            status="warn",
            summary="missing",
            details={"expected": "APP_URL, TARGET_URL, or BASE_URL"},
        )

    target = context.target
    return DoctorCheck(
        name="Scan target",
        status="ok",
        summary="discovered" if target.source == "discovery" else "present",
        details={"source": target.source, "key": target.key or "-", "value": target.value},
    )


def build_doctor_report(root: Path, checks: list[DoctorCheck], context: ApplicationContext | None = None) -> DoctorReport:
    return DoctorReport(
        root=str(root),
        os_name=platform.system(),
        os_release=platform.release(),
        python_version=sys.version.split()[0],
        context=context,
        checks=checks,
        readiness_score=calculate_readiness_score(checks),
    )


def calculate_readiness_score(checks: Sequence[DoctorCheck]) -> int | None:
    if not checks:
        return None

    status_weights = {
        "ok": 100,
        "info": 80,
        "warn": 45,
        "unknown": 60,
    }
    total = sum(status_weights.get(check.status, 60) for check in checks)
    return round(total / len(checks))


def run_server_checks(
    root: Path | None = None,
    env_file: Path | None = None,
    nginx_config: Path | None = None,
    port_candidates: Sequence[int] | None = None,
) -> DoctorReport:
    root_path = Path.cwd() if root is None else Path(root)
    context = resolve_application_context(None, root_path, env_file, nginx_config, require_target=False)
    discovered_env_file = Path(context.discovery.env_file) if context.discovery.env_file is not None else env_file
    checks = [
        check_env_file(root_path, discovered_env_file),
        check_default_scan_target(context),
        check_report_directory(root_path),
        check_app_config_paths(root_path, discovered_env_file),
        check_nginx_paths(root_path, nginx_config),
        check_nginx_hardening(root_path, nginx_config),
        check_process_and_port_activity(),
        check_local_ports(port_candidates),
    ]
    return build_doctor_report(root_path, checks, context=context)


def run_doctor_checks(
    root: Path | None = None,
    env_file: Path | None = None,
    port_candidates: Sequence[int] | None = None,
) -> DoctorReport:
    root_path = Path.cwd() if root is None else Path(root)
    context = resolve_application_context(None, root_path, env_file, require_target=False)
    discovered_env_file = Path(context.discovery.env_file) if context.discovery.env_file is not None else env_file
    checks = [
        check_env_file(root_path, discovered_env_file),
        check_default_scan_target(context),
        check_report_directory(root_path),
        check_app_config_paths(root_path, discovered_env_file),
        check_nginx_paths(root_path),
        check_nginx_hardening(root_path),
        check_process_and_port_activity(),
        check_local_ports(port_candidates),
        *check_secret_settings(root_path, discovered_env_file),
    ]
    return build_doctor_report(root_path, checks, context=context)
