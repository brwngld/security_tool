from __future__ import annotations

from app.models import Finding, FixPlan


def suggest_next_step(finding: Finding) -> str:
    if finding.category == "headers":
        return f"Add {finding.evidence.get('header', 'the missing header')} in Nginx or the reverse proxy first."
    if finding.category == "cookies":
        return "Set Secure and HttpOnly where the cookie is issued first."
    if finding.category == "server_info":
        return "Hide the banner in the web server config first."
    if finding.category == "exposed_files":
        return f"Remove {finding.evidence.get('path', 'the exposed file')} or block it at the web root first."
    if finding.category == "tls":
        return "Renew or replace the certificate bundle first."
    if finding.category == "connectivity":
        return "Check the port, service, or proxy mapping first."
    return "Pick the smallest safe config change first."


def suggest_first_move(finding: Finding) -> str:
    return suggest_next_step(finding)


def suggest_rollback(finding: Finding) -> str:
    if finding.category == "headers":
        return "Put the previous header config back."
    if finding.category == "cookies":
        return "Restore the previous cookie settings."
    if finding.category == "server_info":
        return "Re-enable the banner only if you really need it."
    if finding.category == "exposed_files":
        return "Undo the web-root change if it caused the exposure."
    if finding.category == "tls":
        return "Revert to the last working certificate bundle."
    if finding.category == "connectivity":
        return "Recheck the service or port mapping before retrying."
    return "Revert the last config change if needed."


def choose_expected_impact(finding: Finding) -> str:
    report_only_text = "report only; no system change required."
    current_text = finding.expected_impact.strip().lower()
    if current_text and current_text != report_only_text:
        return finding.expected_impact
    return suggest_next_step(finding)


def recommend_fix(finding: Finding) -> FixPlan:
    return FixPlan(
        finding_id=finding.id,
        fix_level=finding.fix_level,
        risk_level=finding.risk_level,
        requires_approval=finding.requires_approval,
        backup_path=finding.backup_path,
        rollback_command=finding.rollback_command or suggest_rollback(finding),
        expected_impact=choose_expected_impact(finding),
    )
