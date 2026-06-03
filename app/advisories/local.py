from __future__ import annotations

import re
from dataclasses import dataclass

from app.advisories.sources import AdvisoryQuery
from app.models import VulnerabilityFinding


@dataclass(frozen=True)
class LocalAdvisory:
    component_names: tuple[str, ...]
    cve_id: str
    title: str
    severity: str
    cvss: float | None
    affected_versions: str
    fixed_version: str | None
    reference: str
    recommended_action: str
    exact_versions: tuple[str, ...] = ()
    min_version: str | None = None
    max_version: str | None = None


LOCAL_ADVISORIES: tuple[LocalAdvisory, ...] = (
    LocalAdvisory(
        component_names=("Apache httpd", "Apache apache2"),
        cve_id="CVE-2021-41773",
        title="Apache HTTP Server path traversal and file disclosure",
        severity="critical",
        cvss=9.8,
        affected_versions="Apache HTTP Server 2.4.49",
        fixed_version="2.4.50",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        recommended_action="Upgrade Apache HTTP Server to a fixed release and review path traversal exposure.",
        exact_versions=("2.4.49",),
    ),
    LocalAdvisory(
        component_names=("Apache httpd", "Apache apache2"),
        cve_id="CVE-2021-42013",
        title="Apache HTTP Server incomplete path traversal fix leading to path traversal and possible RCE",
        severity="critical",
        cvss=9.8,
        affected_versions="Apache HTTP Server 2.4.50",
        fixed_version="2.4.51",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        recommended_action="Upgrade Apache HTTP Server to 2.4.51 or newer and review exposed aliases/scripts.",
        exact_versions=("2.4.50",),
    ),
    LocalAdvisory(
        component_names=("OpenSSL",),
        cve_id="CVE-2022-3602",
        title="OpenSSL X.509 email address buffer overflow",
        severity="high",
        cvss=7.5,
        affected_versions="OpenSSL 3.0.0 through 3.0.6",
        fixed_version="3.0.7",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2022-3602",
        recommended_action="Upgrade OpenSSL to 3.0.7 or newer, or confirm the vendor has backported the fix.",
        min_version="3.0.0",
        max_version="3.0.6",
    ),
)


def _version_parts(version: str) -> tuple[int, ...]:
    cleaned = version.strip().lstrip("v")
    match = re.match(r"(\d+(?:\.\d+)*)", cleaned)
    if not match:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def _compare_versions(left: str, right: str) -> int:
    left_parts = _version_parts(left)
    right_parts = _version_parts(right)
    max_len = max(len(left_parts), len(right_parts))
    left_padded = left_parts + (0,) * (max_len - len(left_parts))
    right_padded = right_parts + (0,) * (max_len - len(right_parts))
    if left_padded < right_padded:
        return -1
    if left_padded > right_padded:
        return 1
    return 0


def _version_matches_advisory(version: str | None, advisory: LocalAdvisory) -> bool:
    if not version:
        return False
    normalized = version.strip().lstrip("v")
    if advisory.exact_versions and normalized in advisory.exact_versions:
        return True
    if advisory.min_version and _compare_versions(normalized, advisory.min_version) < 0:
        return False
    if advisory.max_version and _compare_versions(normalized, advisory.max_version) > 0:
        return False
    return advisory.min_version is not None or advisory.max_version is not None


class LocalRulesSource:
    name = "local-rules"

    def __init__(self, advisories: tuple[LocalAdvisory, ...] = LOCAL_ADVISORIES) -> None:
        self.advisories = advisories

    def match(self, query: AdvisoryQuery) -> list[VulnerabilityFinding]:
        component = query.component
        findings: list[VulnerabilityFinding] = []
        for advisory in self.advisories:
            if component.name not in advisory.component_names:
                continue
            if not _version_matches_advisory(component.version, advisory):
                continue
            findings.append(
                VulnerabilityFinding(
                    id=f"{component.name.lower().replace(' ', '-')}-{advisory.cve_id.lower()}",
                    component=component.name,
                    installed_version=component.version,
                    cve_id=advisory.cve_id,
                    title=advisory.title,
                    severity=advisory.severity,
                    cvss=advisory.cvss,
                    affected_versions=advisory.affected_versions,
                    fixed_version=advisory.fixed_version,
                    reference=advisory.reference,
                    recommended_action=advisory.recommended_action,
                )
            )
        return findings
