from __future__ import annotations

from pathlib import Path

from app.config import AppConfig
from app.hardening.applied_artifacts import write_applied_artifact
from app.hardening.local_notes import write_remediation_note
from app.models import Finding, FixDecision, FixPlan


def describe_fix_confidence(plan: FixPlan) -> str:
    if plan.fix_level <= 0:
        return "Report only"
    if plan.fix_level == 1:
        return "Generate artifact"
    if plan.fix_level == 2:
        return "Safe local fix"
    return "Needs manual approval"


def evaluate_fix_plan(finding: Finding, plan: FixPlan, policy: AppConfig) -> FixDecision:
    confidence_label = describe_fix_confidence(plan)
    if finding.fix_level > policy.allowed_fix_level:
        return FixDecision(
            finding_id=finding.id,
            finding_title=finding.title,
            status="approval_required",
            confidence_label=confidence_label,
            reason="Finding exceeds the allowed fix level.",
            next_step=plan.expected_impact,
            rollback_command=plan.rollback_command,
        )

    if plan.fix_level > policy.allowed_fix_level:
        return FixDecision(
            finding_id=finding.id,
            finding_title=finding.title,
            status="approval_required",
            confidence_label=confidence_label,
            reason="Fix plan exceeds the allowed fix level.",
            next_step=plan.expected_impact,
            rollback_command=plan.rollback_command,
        )

    if plan.fix_level >= 2 and policy.require_approval_for_level_2:
        return FixDecision(
            finding_id=finding.id,
            finding_title=finding.title,
            status="approval_required",
            confidence_label=confidence_label,
            reason="Level 2 needs approval.",
            next_step=plan.expected_impact,
            rollback_command=plan.rollback_command,
        )

    if plan.fix_level >= 3 and policy.block_level_3:
        return FixDecision(
            finding_id=finding.id,
            finding_title=finding.title,
            status="blocked",
            confidence_label=confidence_label,
            reason="Level 3 is blocked by policy.",
            next_step=plan.expected_impact,
            rollback_command=plan.rollback_command,
        )

    if policy.require_backup_for_level_1 and plan.fix_level >= 1 and not plan.backup_path:
        return FixDecision(
            finding_id=finding.id,
            finding_title=finding.title,
            status="blocked",
            confidence_label=confidence_label,
            reason="Level 1 fixes need a backup.",
            next_step=plan.expected_impact,
            rollback_command=plan.rollback_command,
        )

    if not plan.rollback_command:
        return FixDecision(
            finding_id=finding.id,
            finding_title=finding.title,
            status="blocked",
            confidence_label=confidence_label,
            reason="A rollback command is missing.",
            next_step=plan.expected_impact,
            rollback_command=plan.rollback_command,
        )

    return FixDecision(
        finding_id=finding.id,
        finding_title=finding.title,
        status="ready",
        confidence_label=confidence_label,
        reason="Policy allows this plan.",
        next_step=plan.expected_impact,
        rollback_command=plan.rollback_command,
    )


def execute_fix(
    finding: Finding,
    plan: FixPlan,
    policy: AppConfig,
    output_dir: str | Path = "outputs/remediation",
    backup_path: str | Path | None = None,
) -> str:
    decision = evaluate_fix_plan(finding, plan, policy)
    if decision.status != "ready":
        return decision.status
    artifact_path = write_applied_artifact(finding, plan)
    write_remediation_note(
        finding,
        plan,
        output_dir=output_dir,
        backup_path=backup_path,
        artifact_path=artifact_path,
    )
    return "generated"
