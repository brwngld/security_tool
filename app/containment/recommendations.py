from __future__ import annotations

from app.containment.models import ContainmentRecommendation
from app.models import WatchFinding


def recommendations_from_watch_findings(findings: list[WatchFinding]) -> list[ContainmentRecommendation]:
    recommendations: list[ContainmentRecommendation] = []
    for finding in findings:
        if finding.response_label not in {"recommend contain", "safe contain"}:
            continue
        recommendations.extend(_recommendations_for_finding(finding))
    return recommendations


def _recommendations_for_finding(finding: WatchFinding) -> list[ContainmentRecommendation]:
    if finding.source == "incident":
        return _incident_recommendations(finding)
    if finding.source == "integrity":
        return [
            _recommendation(
                finding,
                action_type="quarantine_file",
                target=str(finding.evidence.get("path") or finding.id),
                reason="A monitored file changed and should be isolated only after human approval confirms it is suspicious.",
                reversible=True,
                confidence="medium",
                artifact_hint="future quarantine manifest",
            )
        ]
    if finding.source == "doctor" and finding.category == "process-port":
        return [
            _recommendation(
                finding,
                action_type="manual_review",
                target=str(finding.evidence.get("listeners") or finding.id),
                reason="A suspicious listener or connection needs ownership review before process termination is considered.",
                reversible=False,
                confidence="medium",
            )
        ]
    return [
        _recommendation(
            finding,
            action_type="manual_review",
            target=finding.id,
            reason="The finding is high risk, but no safe containment type is mapped yet.",
            reversible=False,
            confidence="low",
        )
    ]


def _incident_recommendations(finding: WatchFinding) -> list[ContainmentRecommendation]:
    ips = _ip_targets(finding)
    if not ips:
        return [
            _recommendation(
                finding,
                action_type="rate_limit",
                target=finding.category,
                reason="Suspicious request patterns were detected without a single isolated IP target.",
                reversible=True,
                confidence="medium",
                artifact_hint="future rate-limit artifact",
            )
        ]
    return [
        _recommendation(
            finding,
            action_type="block_ip",
            target=ip,
            reason="Repeated suspicious activity was attributed to this IP. Generate a deny rule before any live firewall change.",
            reversible=True,
            confidence="high",
            artifact_hint="future denylist artifact",
        )
        for ip in ips
    ]


def _ip_targets(finding: WatchFinding) -> list[str]:
    raw_ips = finding.evidence.get("ip") or finding.evidence.get("source_ip") or finding.evidence.get("affected_ip")
    if isinstance(raw_ips, str):
        return [raw_ips]
    affected = finding.evidence.get("affected_ips")
    if isinstance(affected, str):
        return [item.strip() for item in affected.split(",") if item.strip()]
    return []


def _recommendation(
    finding: WatchFinding,
    *,
    action_type: str,
    target: str,
    reason: str,
    reversible: bool,
    confidence: str,
    artifact_hint: str | None = None,
) -> ContainmentRecommendation:
    return ContainmentRecommendation(
        id=f"{finding.id}:{action_type}:{target}".replace(" ", "-"),
        finding_id=finding.id,
        source=finding.source,
        action_type=action_type,
        target=target,
        severity=finding.severity,
        response_label=finding.response_label,
        reason=reason,
        reversible=reversible,
        requires_approval=True,
        confidence=confidence,
        artifact_hint=artifact_hint,
    )
