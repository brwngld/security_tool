from app.hardening.recommendations import recommend_fix
from app.models import Finding


def test_recommend_fix_uses_category_specific_next_steps() -> None:
    header_finding = Finding(
        id="h1",
        target_url="https://example.com",
        title="missing header",
        description="test",
        severity="low",
        category="headers",
        fix_level=0,
        risk_level="low",
        evidence={"header": "x-frame-options"},
    )
    exposed_file_finding = Finding(
        id="e1",
        target_url="https://example.com",
        title="file",
        description="test",
        severity="medium",
        category="exposed_files",
        fix_level=0,
        risk_level="low",
        evidence={"path": ".env"},
    )

    header_plan = recommend_fix(header_finding)
    exposed_file_plan = recommend_fix(exposed_file_finding)

    assert "Nginx" in header_plan.expected_impact
    assert "web root" in exposed_file_plan.expected_impact
