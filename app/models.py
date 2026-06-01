from __future__ import annotations

from pydantic import BaseModel, Field, HttpUrl

from app.context import ApplicationContext


class Target(BaseModel):
    url: HttpUrl
    scheme: str = Field(pattern=r"^https?$")
    host: str
    port: int | None = None
    scope_root: HttpUrl | None = None


class Finding(BaseModel):
    id: str
    target_url: str
    affected_urls: list[str] = Field(default_factory=list)
    title: str
    description: str
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    category: str
    evidence: dict[str, str | int | bool | None] = Field(default_factory=dict)
    fix_level: int = Field(ge=0, le=3)
    risk_level: str = Field(pattern=r"^(low|medium|high|critical)$")
    confidence: str = Field(default="high", pattern=r"^(low|medium|high)$")
    requires_approval: bool = False
    backup_path: str | None = None
    rollback_command: str | None = None
    expected_impact: str = ""
    references: list[str] = Field(default_factory=list)


class FixPlan(BaseModel):
    finding_id: str
    fix_level: int = Field(ge=0, le=3)
    risk_level: str = Field(pattern=r"^(low|medium|high|critical)$")
    requires_approval: bool = False
    backup_path: str | None = None
    rollback_command: str | None = None
    expected_impact: str
    status: str = Field(default="proposed", pattern=r"^(proposed|approved|applied|blocked)$")
    approved_by: str | None = None
    approved_at: str | None = None
    applied_at: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class FixDecision(BaseModel):
    finding_id: str
    finding_title: str
    status: str = Field(pattern=r"^(ready|approval_required|blocked|skipped|generated)$")
    reason: str
    next_step: str
    rollback_command: str | None = None
    backup_path: str | None = None
    artifact_path: str | None = None


class LocalFixResult(BaseModel):
    target_path: str
    status: str = Field(pattern=r"^(applied|rolled_back|blocked|skipped)$")
    reason: str
    backup_path: str | None = None
    validation_command: str | None = None
    validation_output: str | None = None
    notes: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    target: Target
    context: ApplicationContext | None = None
    baseline_label: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    fix_plans: list[FixPlan] = Field(default_factory=list)
    scanned_urls: list[str] = Field(default_factory=list)
    crawl_seed_sources: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    waf_signals: list[str] = Field(default_factory=list)
    tls_summary: dict[str, str] = Field(default_factory=dict)
    scan_confidence: float = 1.0


class ComparisonFinding(BaseModel):
    finding_id: str
    title: str
    category: str
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    change: str = Field(pattern=r"^(fixed|new|unchanged)$")


class ComparisonResult(BaseModel):
    old_report: str
    new_report: str
    old_context: ApplicationContext | None = None
    new_context: ApplicationContext | None = None
    context_changes: list[str] = Field(default_factory=list)
    old_scanned_urls: list[str] = Field(default_factory=list)
    new_scanned_urls: list[str] = Field(default_factory=list)
    added_scanned_urls: list[str] = Field(default_factory=list)
    removed_scanned_urls: list[str] = Field(default_factory=list)
    fixed_findings: list[ComparisonFinding] = Field(default_factory=list)
    new_findings: list[ComparisonFinding] = Field(default_factory=list)
    unchanged_findings: list[ComparisonFinding] = Field(default_factory=list)
    old_risk_score: int = 0
    new_risk_score: int = 0
    risk_trend: str = Field(pattern=r"^(improved|worsened|unchanged)$")


class IncidentFinding(BaseModel):
    id: str
    source_file: str
    log_family: str = ""
    title: str
    category: str
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    confidence: str = Field(default="high", pattern=r"^(low|medium|high)$")
    description: str
    evidence: dict[str, str | int | bool | None] = Field(default_factory=dict)
    affected_ips: list[str] = Field(default_factory=list)
    recommended_action: str = ""
    block_action: str | None = None
    count: int = 0


class IncidentReport(BaseModel):
    context: ApplicationContext | None = None
    target: str | None = None
    source_files: list[str] = Field(default_factory=list)
    total_lines: int = 0
    findings: list[IncidentFinding] = Field(default_factory=list)
    suspect_ips: list[str] = Field(default_factory=list)
    blocked_ips: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    containment_applied: bool = False
    containment_target: str | None = None
    containment_artifact: str | None = None


class IntegrityFile(BaseModel):
    path: str
    category: str
    kind: str
    exists: bool = True
    status: str = Field(pattern=r"^(unchanged|new|changed|missing)$")
    sha256: str | None = None
    size: int | None = None
    modified_at: str | None = None


class IntegrityFinding(BaseModel):
    id: str
    path: str
    category: str
    kind: str
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    confidence: str = Field(default="high", pattern=r"^(low|medium|high)$")
    title: str
    description: str
    evidence: dict[str, str | int | bool | None] = Field(default_factory=dict)
    recommended_action: str = ""


class IntegrityReport(BaseModel):
    context: ApplicationContext | None = None
    root: str
    baseline_path: str | None = None
    monitored_paths: list[str] = Field(default_factory=list)
    files: list[IntegrityFile] = Field(default_factory=list)
    findings: list[IntegrityFinding] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
