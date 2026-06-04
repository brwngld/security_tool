from app.config import AppConfig
from app.hardening.executor import describe_fix_confidence, execute_fix
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


def test_describe_fix_confidence_maps_fix_levels() -> None:
    assert describe_fix_confidence(FixPlan(finding_id="f1", fix_level=0, risk_level="low", rollback_command="echo rollback", expected_impact="report")) == "Report only"
    assert describe_fix_confidence(FixPlan(finding_id="f1", fix_level=1, risk_level="low", rollback_command="echo rollback", expected_impact="artifact")) == "Generate artifact"
    assert describe_fix_confidence(FixPlan(finding_id="f1", fix_level=2, risk_level="medium", rollback_command="echo rollback", expected_impact="local")) == "Safe local fix"
    assert describe_fix_confidence(FixPlan(finding_id="f1", fix_level=3, risk_level="high", rollback_command="echo rollback", expected_impact="approval")) == "Needs manual approval"
