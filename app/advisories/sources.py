from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.models import SoftwareComponent, VulnerabilityFinding


@dataclass(frozen=True)
class AdvisoryQuery:
    component: SoftwareComponent


class AdvisorySource(Protocol):
    name: str

    def match(self, query: AdvisoryQuery) -> list[VulnerabilityFinding]:
        ...


def advisory_sources() -> list[AdvisorySource]:
    from app.advisories.local import LocalRulesSource

    return [LocalRulesSource()]


def match_advisories(
    components: list[SoftwareComponent],
    sources: list[AdvisorySource] | None = None,
) -> list[VulnerabilityFinding]:
    active_sources = sources or advisory_sources()
    findings: list[VulnerabilityFinding] = []
    seen: set[tuple[str, str, str | None]] = set()
    for component in components:
        if component.status != "found":
            continue
        query = AdvisoryQuery(component=component)
        for source in active_sources:
            for finding in source.match(query):
                key = (finding.component, finding.cve_id, finding.installed_version)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)
    return findings
