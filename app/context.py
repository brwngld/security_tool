from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field

from app.environment import ResolvedScanTarget, find_scan_target, iter_env_paths


class DiscoverySignal(BaseModel):
    name: str
    status: str
    summary: str
    details: dict[str, str] = Field(default_factory=dict)


class DiscoveryReport(BaseModel):
    discovered: bool = False
    app_name: str | None = None
    target_url: str | None = None
    target_source: str | None = None
    public_url: str | None = None
    local_url: str | None = None
    env_file: str | None = None
    env_source: str | None = None
    nginx_config: str | None = None
    systemd_service: str | None = None
    signals: list[DiscoverySignal] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ApplicationContext(BaseModel):
    root: str
    target: ResolvedScanTarget | None = None
    discovery: DiscoveryReport = Field(default_factory=DiscoveryReport)


def _first_existing_path(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None


def _load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _clean_systemd_value(value: str) -> str:
    cleaned = value.strip()
    if cleaned.startswith("-"):
        cleaned = cleaned[1:].lstrip()
    return cleaned.strip().strip("'\"")


def _resolve_systemd_path(value: str, service_path: Path) -> Path:
    cleaned = _clean_systemd_value(value)
    path = Path(cleaned).expanduser()
    if path.is_absolute():
        return path
    return (service_path.parent / path).resolve()


def _build_env_paths(root: Path, env_file: Path | None = None) -> list[Path]:
    paths = [Path(path) for path in iter_env_paths(root, env_file)]
    return [path for path in paths if path.exists()]


def _discover_nginx_config(root: Path, nginx_config: Path | None = None) -> tuple[Path | None, str | None, str | None, list[DiscoverySignal], list[str]]:
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
            Path("/etc/nginx/conf.d/default.conf"),
            Path("/usr/local/etc/nginx/nginx.conf"),
        ]

    found = _first_existing_path(candidates)
    if found is None:
        return None, None, None, [], ["nginx config not found"]

    content = _load_text(found)
    ssl_enabled = bool(re.search(r"listen\s+443\s+ssl", content) or "ssl_certificate" in content.lower())
    server_name_match = re.search(r"server_name\s+([^;]+);", content, flags=re.IGNORECASE)
    proxy_pass_match = re.search(r"proxy_pass\s+(https?://[^;]+);", content, flags=re.IGNORECASE)

    public_url = None
    if server_name_match:
        server_name = server_name_match.group(1).split()[0].strip()
        if server_name and server_name not in {"_", "localhost"}:
            scheme = "https" if ssl_enabled else "http"
            public_url = f"{scheme}://{server_name}"
    local_url = None
    if proxy_pass_match:
        proxy_pass = proxy_pass_match.group(1).strip().rstrip("/")
        if "unix:" not in proxy_pass:
            local_url = proxy_pass

    signals = [
        DiscoverySignal(name="nginx config", status="ok", summary="found", details={"path": str(found)}),
    ]
    if server_name_match:
        signals.append(
            DiscoverySignal(
                name="server_name",
                status="ok",
                summary=server_name_match.group(1).strip(),
                details={"path": str(found)},
            )
        )
    if proxy_pass_match:
        signals.append(
            DiscoverySignal(
                name="proxy_pass",
                status="ok",
                summary=proxy_pass_match.group(1).strip(),
                details={"path": str(found)},
            )
        )

    notes = []
    if ssl_enabled:
        notes.append("nginx looks like it serves HTTPS")
    return found, public_url, local_url, signals, notes


def _discover_systemd_service(
    root: Path,
) -> tuple[Path | None, str | None, str | None, Path | None, str | None, list[DiscoverySignal], list[str]]:
    candidate_dirs = [
        root / "systemd",
        Path("/etc/systemd/system"),
        Path("/lib/systemd/system"),
        Path("/usr/lib/systemd/system"),
    ]
    service_files: list[Path] = []
    for directory in candidate_dirs:
        if directory.exists():
            service_files.extend(sorted(directory.glob("*.service"))[:10])

    found = _first_existing_path(service_files)
    if found is None:
        return None, None, None, None, None, [], ["systemd service not found"]

    content = _load_text(found)
    working_directory = re.search(r"WorkingDirectory\s*=\s*(.+)", content, flags=re.IGNORECASE)
    env_file = re.search(r"EnvironmentFile\s*=\s*(.+)", content, flags=re.IGNORECASE)
    exec_start = re.search(r"ExecStart\s*=\s*(.+)", content, flags=re.IGNORECASE)
    exec_env_file = re.search(r"--env-file(?:=|\s+)(\S+)", content, flags=re.IGNORECASE)
    port_match = re.search(r"(?:--host|--bind|-b)\s+([A-Za-z0-9_.:-]+):(\d+)", content)
    port_only_match = re.search(r"(?:--port)\s+(\d+)", content)

    local_url = None
    if port_match:
        host = port_match.group(1).split(":", 1)[0]
        port = port_match.group(2)
        local_url = f"http://{host}:{port}"
    elif port_only_match:
        local_url = f"http://127.0.0.1:{port_only_match.group(1)}"

    app_name = found.stem
    working_directory_path = None
    if working_directory:
        working_directory_path = _resolve_systemd_path(working_directory.group(1), found)
        app_name = working_directory_path.name or app_name

    env_file_path = None
    env_file_source = None
    if env_file:
        env_file_path = _resolve_systemd_path(env_file.group(1), found)
        env_file_source = "systemd EnvironmentFile"
    elif exec_env_file:
        env_file_path = _resolve_systemd_path(exec_env_file.group(1), found)
        env_file_source = "systemd ExecStart --env-file"
    elif working_directory_path is not None:
        env_file_path = working_directory_path / ".env"
        env_file_source = "systemd WorkingDirectory"

    signals = [
        DiscoverySignal(name="systemd service", status="ok", summary=found.name, details={"path": str(found)}),
    ]
    if working_directory:
        signals.append(
            DiscoverySignal(
                name="WorkingDirectory",
                status="ok",
                summary=working_directory.group(1).strip(),
                details={"path": str(found)},
            )
        )
    if env_file:
        signals.append(
            DiscoverySignal(
                name="EnvironmentFile",
                status="ok",
                summary=_clean_systemd_value(env_file.group(1)),
                details={"path": str(found)},
            )
        )
    elif exec_env_file:
        signals.append(
            DiscoverySignal(
                name="EnvironmentFile",
                status="ok",
                summary=_clean_systemd_value(exec_env_file.group(1)),
                details={"path": str(found)},
            )
        )
    if exec_start:
        signals.append(
            DiscoverySignal(
                name="ExecStart",
                status="ok",
                summary=exec_start.group(1).strip(),
                details={"path": str(found)},
            )
        )

    notes = []
    if local_url:
        notes.append("systemd points at a local app port")
    if env_file_path is not None:
        notes.append(f"systemd environment file detected at {env_file_path}")
    return found, local_url, app_name, env_file_path, env_file_source, signals, notes


def _probe_local_ports(port_candidates: list[int] | None = None) -> tuple[int | None, list[DiscoverySignal], list[str]]:
    import socket

    ports = list(port_candidates) if port_candidates is not None else [80, 443, 3000, 5000, 8000, 8080]
    open_ports: list[int] = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(0.2)
            if client.connect_ex(("127.0.0.1", port)) == 0:
                open_ports.append(port)

    if not open_ports:
        return None, [], ["no common localhost ports responded"]

    return (
        open_ports[0],
        [DiscoverySignal(name="open local ports", status="info", summary=", ".join(str(port) for port in open_ports), details={"ports": ", ".join(str(port) for port in open_ports)})],
        [f"localhost ports listening: {', '.join(str(port) for port in open_ports)}"],
    )


def discover_application_context(
    root: Path | None = None,
    env_file: Path | None = None,
    nginx_config: Path | None = None,
) -> DiscoveryReport:
    root_path = Path.cwd() if root is None else Path(root)
    report = DiscoveryReport()

    nginx_path, public_url, local_url, nginx_signals, nginx_notes = _discover_nginx_config(root_path, nginx_config)
    if nginx_path is not None:
        report.nginx_config = str(nginx_path)
        report.public_url = public_url
        report.local_url = local_url or report.local_url
        report.signals.extend(nginx_signals)
        report.notes.extend(nginx_notes)

    service_path, service_local_url, app_name, service_env_file, service_env_source, service_signals, service_notes = _discover_systemd_service(root_path)
    if service_path is not None:
        report.systemd_service = str(service_path)
        report.local_url = report.local_url or service_local_url
        report.app_name = report.app_name or app_name
        report.signals.extend(service_signals)
        report.notes.extend(service_notes)

    env_candidates: list[Path] = []
    env_source = None
    if env_file is not None:
        env_candidates.append(Path(env_file))
        env_source = "--env-file"
    elif service_env_file is not None:
        env_candidates.append(service_env_file)
        env_source = service_env_source
    env_candidates.extend(_build_env_paths(root_path, None))
    if env_candidates:
        report.env_file = str(env_candidates[0])
        if env_source is None:
            if env_candidates[0] == root_path / ".env":
                env_source = "project .env"
            else:
                env_source = "environment fallback"
        report.env_source = env_source

    configured_target_env_file = Path(report.env_file) if report.env_file is not None else None
    configured_target = find_scan_target(root_path, env_file=configured_target_env_file)
    if configured_target is not None:
        report.target_url = configured_target.value
        report.target_source = configured_target.source
        report.signals.append(
            DiscoverySignal(
                name="configured target",
                status="ok",
                summary=configured_target.value,
                details={"source": configured_target.source, "key": configured_target.key or "-"},
            )
        )
        report.notes.append(f"scan target configured in {configured_target.source}")

    open_port, port_signals, port_notes = _probe_local_ports()
    if open_port is not None and report.local_url is None:
        report.local_url = f"http://127.0.0.1:{open_port}"
    report.signals.extend(port_signals)
    report.notes.extend(port_notes)

    if report.app_name is None and report.systemd_service is not None:
        report.app_name = Path(report.systemd_service).stem

    report.discovered = bool(report.target_url or report.local_url or report.public_url or report.signals)
    return report


def resolve_application_context(
    explicit_url: str | None,
    root: Path | None = None,
    env_file: Path | None = None,
    nginx_config: Path | None = None,
    require_target: bool = False,
) -> ApplicationContext:
    root_path = Path.cwd() if root is None else Path(root)

    if explicit_url:
        return ApplicationContext(
            root=str(root_path),
            target=ResolvedScanTarget(value=explicit_url, source="command line", key="command line"),
            discovery=DiscoveryReport(discovered=False),
        )

    discovery = discover_application_context(root_path, env_file=env_file, nginx_config=nginx_config)
    target_env_file = env_file
    if target_env_file is None and discovery.env_file is not None:
        target_env_file = Path(discovery.env_file)

    target = find_scan_target(root_path, env_file=target_env_file)
    if target is None and discovery.local_url is not None:
        target = ResolvedScanTarget(value=discovery.local_url, source="discovery", key="discovered")
        discovery.target_url = discovery.local_url
        discovery.target_source = "discovery"
    elif target is None and discovery.public_url is not None:
        target = ResolvedScanTarget(value=discovery.public_url, source="discovery", key="discovered")
        discovery.target_url = discovery.public_url
        discovery.target_source = "discovery"

    if require_target and target is None:
        lines = [
            "No application target could be discovered.",
            "",
            "Checked:",
            "- command line URL: not set",
            f"- APP_URL / TARGET_URL / BASE_URL: {'found' if find_scan_target(root_path, env_file=target_env_file) else 'not found'}",
            f"- .env file: {discovery.env_file or 'not found'}",
            f"- nginx config: {discovery.nginx_config or 'not found'}",
            f"- systemd service: {discovery.systemd_service or 'not found'}",
            "- localhost ports: not found",
            "",
            "Pass a URL manually:",
            "  python -m app.main scan https://example.com",
            "",
            "Or set:",
            "  APP_URL=http://127.0.0.1:5000",
            "",
            "Or point Turan at a file:",
            "  python -m app.main scan --env-file /path/to/autoentrytrack/.env",
        ]
        raise ValueError("\n".join(lines))

    return ApplicationContext(root=str(root_path), target=target, discovery=discovery)


def summarize_application_context(context: ApplicationContext | None) -> str:
    if context is None:
        return "context not captured"

    pieces: list[str] = []
    if context.target is not None:
        pieces.append(f"target={context.target.value}")
    if context.discovery.app_name:
        pieces.append(f"app={context.discovery.app_name}")
    if context.discovery.public_url:
        pieces.append(f"public={context.discovery.public_url}")
    if context.discovery.local_url:
        pieces.append(f"local={context.discovery.local_url}")
    if context.discovery.env_source and context.discovery.env_file:
        pieces.append(f"env={context.discovery.env_source}")
    return ", ".join(pieces) if pieces else "context not captured"
