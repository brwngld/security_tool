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
    confidence_label: str = ""
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


class WatchObservation(BaseModel):
    source: str
    kind: str
    status: str = Field(pattern=r"^(ok|warn|info|unknown)$")
    summary: str
    details: dict[str, str | int | bool | None] = Field(default_factory=dict)


class WatchFinding(BaseModel):
    id: str
    source: str
    category: str
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    title: str
    description: str
    evidence: dict[str, str | int | bool | None] = Field(default_factory=dict)
    recommended_action: str = ""
    response_label: str = Field(default="log only", pattern=r"^(log only|report|recommend contain|safe contain)$")


class WatchReport(BaseModel):
    context: ApplicationContext | None = None
    root: str
    mode: str = Field(default="snapshot", pattern=r"^(snapshot|follow)$")
    interval_seconds: float = Field(default=0.0, ge=0.0)
    compact: bool = False
    policy_path: str | None = None
    baseline_path: str | None = None
    sources: list[str] = Field(default_factory=list)
    observations: list[WatchObservation] = Field(default_factory=list)
    findings: list[WatchFinding] = Field(default_factory=list)
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_level: str = Field(default="low", pattern=r"^(info|low|medium|high|critical)$")
    response_label: str = Field(default="log only", pattern=r"^(log only|report|recommend contain|safe contain)$")
    notes: list[str] = Field(default_factory=list)
    cycles: int = Field(default=1, ge=1)
    last_run_at: str | None = None


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


class TimelineEvent(BaseModel):
    timestamp: str | None = None
    kind: str
    title: str
    source: str | None = None
    details: dict[str, str | int | bool | None] = Field(default_factory=dict)


class TimelineReport(BaseModel):
    incident_report: str | None = None
    audit_log: str | None = None
    events: list[TimelineEvent] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class DriftFinding(BaseModel):
    id: str
    category: str
    kind: str
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    title: str
    baseline_value: str | None = None
    current_value: str | None = None
    note: str = ""


class DriftReport(BaseModel):
    baseline_report: str
    current_report: str
    report_type: str
    summary: str
    findings: list[DriftFinding] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class SecretExposureFinding(BaseModel):
    id: str
    path: str
    line_number: int
    category: str
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    confidence: str = Field(default="high", pattern=r"^(low|medium|high)$")
    title: str
    evidence: dict[str, str | int | bool | None] = Field(default_factory=dict)
    recommended_action: str = ""


class SecretExposureReport(BaseModel):
    root: str
    source_files: list[str] = Field(default_factory=list)
    findings: list[SecretExposureFinding] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ReportBundleItem(BaseModel):
    path: str
    arcname: str
    kind: str
    size: int | None = None


class ReportBundle(BaseModel):
    output_path: str
    source_report: str
    items: list[ReportBundleItem] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class SoftwareComponent(BaseModel):
    name: str
    version: str | None = None
    kind: str = ""
    source: str = ""
    path: str | None = None
    status: str = Field(default="found", pattern=r"^(found|missing|error)$")
    evidence: str = ""


class VulnerabilityFinding(BaseModel):
    id: str
    component: str
    installed_version: str | None = None
    cve_id: str
    title: str
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    cvss: float | None = None
    affected_versions: str
    fixed_version: str | None = None
    reference: str
    recommended_action: str


class VulnerabilityReport(BaseModel):
    root: str
    components: list[SoftwareComponent] = Field(default_factory=list)
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    cve_matching: bool = False
