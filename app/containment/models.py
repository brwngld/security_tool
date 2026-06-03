from __future__ import annotations

from pydantic import BaseModel, Field


CONTAINMENT_ACTION_TYPES = (
    "block_ip",
    "rate_limit",
    "maintenance_mode",
    "quarantine_file",
    "kill_process",
    "disable_account",
    "manual_review",
)


class ContainmentRecommendation(BaseModel):
    id: str
    finding_id: str
    source: str
    action_type: str = Field(pattern=r"^(block_ip|rate_limit|maintenance_mode|quarantine_file|kill_process|disable_account|manual_review)$")
    target: str
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    response_label: str = Field(pattern=r"^(log only|report|recommend contain|safe contain)$")
    reason: str
    reversible: bool = True
    requires_approval: bool = True
    confidence: str = Field(default="medium", pattern=r"^(low|medium|high)$")
    artifact_hint: str | None = None


class ContainmentAction(BaseModel):
    id: str
    recommendation_id: str
    action_type: str = Field(pattern=r"^(block_ip|rate_limit|maintenance_mode|quarantine_file|kill_process|disable_account|manual_review)$")
    target: str
    mode: str = Field(default="dry_run", pattern=r"^(dry_run|apply)$")
    command_preview: str | None = None
    rollback_hint: str | None = None
    requires_approval: bool = True


class ContainmentResult(BaseModel):
    action_id: str
    status: str = Field(pattern=r"^(planned|skipped|generated|applied|blocked|failed)$")
    target: str
    message: str
    artifact_path: str | None = None
    rollback_path: str | None = None
    executed: bool = False
