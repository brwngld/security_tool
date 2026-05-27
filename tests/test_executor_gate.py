from app.config import AppConfig
from app.hardening.executor import execute_fix
from app.models import Finding, FixPlan


def test_executor_requires_approval_for_high_fix_level() -> None:
    finding = Finding(
        id="f1",
        target_url="https://example.com",
        title="test",
        description="test",
        severity="low",
        category="headers",
        fix_level=2,
        risk_level="medium",
    )
    plan = FixPlan(
        finding_id="f1",
        fix_level=2,
        risk_level="medium",
        backup_path="backups/f1.bak",
        rollback_command="echo rollback",
        expected_impact="limited",
    )
    policy = AppConfig(allowed_fix_level=1)
    assert execute_fix(finding, plan, policy) == "approval_required"

