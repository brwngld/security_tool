from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from app.hardening.backup import create_backup
from app.hardening.recommendations import suggest_first_move
from app.models import Finding, FixPlan


def choose_first_move(finding: Finding) -> str:
    return suggest_first_move(finding)


def _display_path(path: str | Path) -> str:
    return Path(path).as_posix()


def remediation_note_path(finding: Finding, output_dir: str | Path = "outputs/remediation") -> Path:
    note_dir = Path(output_dir)
    note_dir.mkdir(parents=True, exist_ok=True)
    return note_dir / f"{finding.id}.md"


def create_remediation_note_backup(finding: Finding, output_dir: str | Path = "outputs/remediation") -> Path:
    note_path = remediation_note_path(finding, output_dir)
    backup_dir = note_path.parent.parent / "backups"
    return create_backup(note_path, backup_dir)


def write_remediation_note(
    finding: Finding,
    plan: FixPlan,
    output_dir: str | Path = "outputs/remediation",
    backup_path: str | Path | None = None,
    artifact_path: str | Path | None = None,
) -> Path:
    note_path = remediation_note_path(finding, output_dir)

    saved_at = datetime.now(timezone.utc).isoformat()
    severity_summary = {
        "info": "Low urgency. Worth fixing, but it should not block the scan.",
        "low": "Low urgency. This is a tidy-up item and a good first apply candidate.",
        "medium": "Medium urgency. It is still safe to document here, but it deserves attention.",
        "high": "High urgency. Keep this as a review note unless the policy allows more.",
        "critical": "Critical urgency. Keep it in preview mode until an admin signs off.",
    }
    lines = [
        f"# Remediation note for {finding.title}",
        "",
        f"- Severity summary: {severity_summary.get(finding.severity, 'Review this one before applying anything.')}",
        f"- First move: {choose_first_move(finding)}",
        f"- Finding: `{finding.id}`",
        f"- Category: `{finding.category}`",
        f"- Severity: `{finding.severity}`",
        f"- Target: `{finding.target_url}`",
        f"- Suggested next step: {plan.expected_impact}",
        f"- Rollback: {plan.rollback_command or 'Delete this note or restore the backup copy.'}",
        f"- Backup: `{_display_path(backup_path)}`" if backup_path is not None else "- Backup: not created",
        f"- Artifact: `{_display_path(artifact_path)}`" if artifact_path is not None else "- Artifact: not created",
        f"- Saved at: `{saved_at}`",
        "",
        "This file is local to the Turan workspace and can be removed safely after review.",
    ]
    note_path.write_text("\n".join(lines), encoding="utf-8")
    return note_path
