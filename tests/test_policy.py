from app.config import AppConfig
from app.models import Finding, FixPlan
from app.policy import approval_required, plan_requires_approval


def test_approval_required_for_higher_fix_level() -> None:
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
    assert approval_required(finding, 1) is True


def test_plan_requires_approval_for_level_two() -> None:
    policy = AppConfig(allowed_fix_level=2)
    plan = FixPlan(
        finding_id="f1",
        fix_level=2,
        risk_level="medium",
        expected_impact="safe",
    )
    assert plan_requires_approval(plan, policy) is True

