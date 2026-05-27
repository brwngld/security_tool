from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field


class AppConfig(BaseModel):
    allowed_fix_level: int = Field(default=0, ge=0, le=3)
    require_backup_for_level_1: bool = True
    require_approval_for_level_2: bool = True
    block_level_3: bool = True
    redact_secrets_in_reports: bool = True
    redact_secrets_in_logs: bool = True
    audit_log_path: str = "outputs/audit.log"
    max_crawl_depth: int = Field(default=2, ge=0, le=10)
    max_pages: int = Field(default=100, ge=1, le=10_000)
    timeout_seconds: float = Field(default=10.0, gt=0)


def load_app_config(config_path: str | Path | None = None) -> AppConfig:
    if config_path is None:
        return AppConfig()

    path = Path(config_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    return AppConfig.model_validate(data)
