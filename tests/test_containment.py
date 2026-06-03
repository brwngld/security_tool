from app.containment import ContainmentAction, ContainmentResult, recommendations_from_watch_findings
from app.models import WatchFinding


def test_containment_models_are_dry_run_and_approval_oriented() -> None:
    action = ContainmentAction(
        id="action-1",
        recommendation_id="rec-1",
        action_type="block_ip",
        target="10.0.0.1",
        command_preview="deny 10.0.0.1;",
        rollback_hint="remove deny rule",
    )
    result = ContainmentResult(
        action_id=action.id,
        status="planned",
        target=action.target,
        message="No live action executed.",
    )

    assert action.mode == "dry_run"
    assert action.requires_approval is True
    assert result.executed is False


def test_recommendations_from_watch_findings_maps_incident_ip_to_block_recommendation() -> None:
    finding = WatchFinding(
        id="incident:probe",
        source="incident",
        category="scanner",
        severity="high",
        title="Suspicious probing",
        description="Repeated probing detected.",
        evidence={"affected_ips": "10.0.0.1, 10.0.0.2"},
        recommended_action="Review and contain if confirmed.",
        response_label="recommend contain",
    )

    recommendations = recommendations_from_watch_findings([finding])

    assert [recommendation.action_type for recommendation in recommendations] == ["block_ip", "block_ip"]
    assert [recommendation.target for recommendation in recommendations] == ["10.0.0.1", "10.0.0.2"]
    assert all(recommendation.requires_approval for recommendation in recommendations)


def test_recommendations_ignore_log_only_findings() -> None:
    finding = WatchFinding(
        id="integrity:low",
        source="integrity",
        category="config",
        severity="low",
        title="Low drift",
        description="Low-risk drift.",
        response_label="log only",
    )

    assert recommendations_from_watch_findings([finding]) == []
