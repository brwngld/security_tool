from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from app.environment import read_env_file


WEB_CONFIG_DEFAULTS = {
    "PSHIELD_DATABASE_URL": "postgresql+psycopg://psybershield:Z6p^M1dL9!sJ4rVt&xB7$@127.0.0.1:5432/psybershield",
    "PSHIELD_SECRET_KEY": "4694adf6468e67!941b8c9e5c2a1f0b",
    "PSHIELD_OUTPUT_DIR": "outputs/web",
    "PSHIELD_WEB_HOST": "127.0.0.1",
    "PSHIELD_WEB_PORT": "8787",
}

WEB_CONFIG_KEYS = (
    "PSHIELD_DATABASE_URL",
    "PSHIELD_SECRET_KEY",
    "PSHIELD_OUTPUT_DIR",
    "PSHIELD_WEB_HOST",
    "PSHIELD_WEB_PORT",
    "PSHIELD_ADMIN_EMAIL",
    "PSHIELD_ADMIN_PASSWORD",
)


@dataclass(frozen=True)
class WebConfig:
    database_url: str
    secret_key: str
    output_dir: Path
    host: str
    port: int
    admin_email: str | None = None
    admin_password: str | None = None


@dataclass(frozen=True)
class WebConfigDiagnostics:
    env_path: Path
    sources: dict[str, str]
    messages: list[str]


def _config_value(
    key: str,
    default: str | None = None,
    *,
    env_data: dict[str, str],
    env_path: Path,
) -> tuple[str | None, str]:
    runtime_value = os.environ.get(key)
    if runtime_value and runtime_value.strip():
        return runtime_value.strip(), "live/process environment"
    file_value = env_data.get(key)
    if file_value and file_value.strip():
        return file_value.strip(), f".env at {env_path}"
    if default is not None:
        return default, "built-in default"
    return None, "missing"


def load_web_config_with_diagnostics(root: Path | None = None) -> tuple[WebConfig, WebConfigDiagnostics]:
    root_path = Path.cwd() if root is None else Path(root)
    env_path = root_path / ".env"
    env_data = read_env_file(root_path)
    values: dict[str, str | None] = {}
    sources: dict[str, str] = {}
    messages: list[str] = []

    for key in WEB_CONFIG_KEYS:
        values[key], sources[key] = _config_value(
            key,
            WEB_CONFIG_DEFAULTS.get(key),
            env_data=env_data,
            env_path=env_path,
        )

    if sources["PSHIELD_SECRET_KEY"] == "built-in default":
        messages.append("PSHIELD_SECRET_KEY was not found in the live/process environment or root .env; using an unsafe development default.")
    if sources["PSHIELD_DATABASE_URL"] == "built-in default":
        messages.append("PSHIELD_DATABASE_URL was not found in the live/process environment or root .env; using the PostgreSQL development default.")
    for key in ("PSHIELD_ADMIN_EMAIL", "PSHIELD_ADMIN_PASSWORD"):
        if sources[key] == "missing":
            messages.append(f"{key} was not found in the live/process environment or root .env; admin bootstrap will skip this value.")

    return (
        WebConfig(
            database_url=values["PSHIELD_DATABASE_URL"] or "",
            secret_key=values["PSHIELD_SECRET_KEY"] or "",
            output_dir=Path(values["PSHIELD_OUTPUT_DIR"] or "outputs/web"),
            host=values["PSHIELD_WEB_HOST"] or "127.0.0.1",
            port=int(values["PSHIELD_WEB_PORT"] or "8787"),
            admin_email=values["PSHIELD_ADMIN_EMAIL"],
            admin_password=values["PSHIELD_ADMIN_PASSWORD"],
        ),
        WebConfigDiagnostics(env_path=env_path, sources=sources, messages=messages),
    )


def load_web_config() -> WebConfig:
    config, _diagnostics = load_web_config_with_diagnostics()
    return config


def render_web_config_diagnostics(diagnostics: WebConfigDiagnostics) -> list[str]:
    lines = ["Web configuration sources:"]
    for key in WEB_CONFIG_KEYS:
        lines.append(f"- {key}: {diagnostics.sources.get(key, 'missing')}")
    if diagnostics.messages:
        lines.append("Configuration warnings:")
        lines.extend(f"- {message}" for message in diagnostics.messages)
    return lines
