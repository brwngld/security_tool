from __future__ import annotations

import json
from pathlib import Path

from app.context import ApplicationContext


def build_baseline_metadata(context: ApplicationContext | None, label: str | None) -> dict[str, str]:
    data: dict[str, str] = {}
    if label:
        data["label"] = label
    if context is not None:
        data["root"] = context.root
        if context.target is not None:
            data["target"] = context.target.value
            data["target_source"] = context.target.source
        if context.discovery.app_name:
            data["app_name"] = context.discovery.app_name
        if context.discovery.public_url:
            data["public_url"] = context.discovery.public_url
        if context.discovery.local_url:
            data["local_url"] = context.discovery.local_url
        if context.discovery.env_file:
            data["env_file"] = context.discovery.env_file
        if context.discovery.env_source:
            data["env_source"] = context.discovery.env_source
        if context.discovery.nginx_config:
            data["nginx_config"] = context.discovery.nginx_config
        if context.discovery.systemd_service:
            data["systemd_service"] = context.discovery.systemd_service
    return data


def write_baseline_metadata(output_path: Path, metadata: dict[str, str]) -> Path:
    meta_path = output_path.with_suffix(output_path.suffix + ".meta.json")
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return meta_path


def summarize_baseline_metadata(metadata: dict[str, str]) -> str:
    pieces: list[str] = []
    for key in ("target", "app_name", "public_url", "local_url"):
        value = metadata.get(key)
        if value:
            pieces.append(f"{key}={value}")
    env_source = metadata.get("env_source")
    if env_source:
        pieces.append(f"env_source={env_source}")
    return ", ".join(pieces) if pieces else "context not captured"
