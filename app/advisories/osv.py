from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, Field

from app.advisories.sources import AdvisoryQuery
from app.models import VulnerabilityFinding

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


class OSVPackage(BaseModel):
    name: str
    ecosystem: str = "PyPI"


class OSVQuery(BaseModel):
    package: OSVPackage
    version: str


class OSVReference(BaseModel):
    type: str | None = None
    url: str


class OSVSeverity(BaseModel):
    type: str | None = None
    score: str


class OSVVulnerability(BaseModel):
    id: str
    summary: str | None = None
    details: str | None = None
    aliases: list[str] = Field(default_factory=list)
    references: list[OSVReference] = Field(default_factory=list)
    severity: list[OSVSeverity] = Field(default_factory=list)
    affected: list[dict[str, Any]] = Field(default_factory=list)
    database_specific: dict[str, Any] = Field(default_factory=dict)


class OSVResponse(BaseModel):
    vulns: list[OSVVulnerability] = Field(default_factory=list)


OSVFetcher = Callable[[OSVQuery], dict[str, Any]]


@dataclass
class OSVSource:
    cache_dir: Path | None = None
    timeout_seconds: float = 10.0
    fetcher: OSVFetcher | None = None

    name = "osv"

    def __post_init__(self) -> None:
        self.notes: list[str] = []

    def match(self, query: AdvisoryQuery) -> list[VulnerabilityFinding]:
        component = query.component
        if component.status != "found" or component.ecosystem != "PyPI" or not component.version:
            return []

        osv_query = OSVQuery(
            package=OSVPackage(name=component.name, ecosystem=component.ecosystem),
            version=component.version,
        )
        response_payload = self._load_or_fetch(osv_query)
        if response_payload is None:
            return []

        try:
            response = OSVResponse.model_validate(response_payload)
        except Exception as exc:
            self.notes.append(f"OSV response for {component.name} {component.version} could not be parsed: {exc}")
            return []

        return [
            _finding_from_osv_vulnerability(vulnerability, component.name, component.version)
            for vulnerability in response.vulns
        ]

    def _load_or_fetch(self, query: OSVQuery) -> dict[str, Any] | None:
        cache_path = self._cache_path(query)
        if cache_path is not None and cache_path.exists():
            try:
                return json.loads(cache_path.read_text(encoding="utf-8"))
            except Exception as exc:
                self.notes.append(f"OSV cache read failed for {query.package.name}: {exc}")

        try:
            payload = self._fetch(query)
        except Exception as exc:
            self.notes.append(f"OSV lookup failed for {query.package.name} {query.version}: {exc}")
            return None

        if cache_path is not None:
            try:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                cache_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            except Exception as exc:
                self.notes.append(f"OSV cache write failed for {query.package.name}: {exc}")
        return payload

    def _fetch(self, query: OSVQuery) -> dict[str, Any]:
        if self.fetcher is not None:
            return self.fetcher(query)

        request = urllib.request.Request(
            OSV_QUERY_URL,
            data=query.model_dump_json().encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(str(exc.reason)) from exc

    def _cache_path(self, query: OSVQuery) -> Path | None:
        if self.cache_dir is None:
            return None
        key = f"{query.package.ecosystem}:{query.package.name}:{query.version}"
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        safe_name = "".join(char if char.isalnum() or char in "._-" else "_" for char in query.package.name)
        return self.cache_dir / f"{query.package.ecosystem}-{safe_name}-{query.version}-{digest}.json"


def _finding_from_osv_vulnerability(vulnerability: OSVVulnerability, package: str, version: str) -> VulnerabilityFinding:
    cve_id = next((alias for alias in vulnerability.aliases if alias.startswith("CVE-")), vulnerability.id)
    fixed_version = _first_fixed_version(vulnerability)
    reference = _first_reference(vulnerability)
    severity, cvss = _severity_from_vulnerability(vulnerability)
    recommended_action = (
        f"Upgrade {package} to {fixed_version} or newer."
        if fixed_version
        else f"Review the OSV advisory for {package} and upgrade to a non-affected version."
    )
    return VulnerabilityFinding(
        id=f"{package.lower().replace(' ', '-')}-{vulnerability.id.lower()}",
        component=package,
        installed_version=version,
        cve_id=cve_id,
        title=vulnerability.summary or vulnerability.id,
        severity=severity,
        cvss=cvss,
        affected_versions=f"PyPI {package} {version}",
        fixed_version=fixed_version,
        reference=reference,
        recommended_action=recommended_action,
        confidence="confirmed",
        source="osv",
    )


def _first_reference(vulnerability: OSVVulnerability) -> str:
    if vulnerability.references:
        return vulnerability.references[0].url
    return f"https://osv.dev/vulnerability/{vulnerability.id}"


def _first_fixed_version(vulnerability: OSVVulnerability) -> str | None:
    for affected in vulnerability.affected:
        for version_range in affected.get("ranges", []):
            for event in version_range.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    return str(fixed)
    return None


def _severity_from_vulnerability(vulnerability: OSVVulnerability) -> tuple[str, float | None]:
    database_severity = vulnerability.database_specific.get("severity")
    if isinstance(database_severity, str):
        normalized = database_severity.lower()
        if normalized in {"critical", "high", "medium", "low"}:
            return normalized, None

    for severity in vulnerability.severity:
        cvss = _cvss_score(severity.score)
        if cvss is not None:
            return _severity_from_cvss(cvss), cvss
    return "medium", None


def _cvss_score(value: str) -> float | None:
    if value.replace(".", "", 1).isdigit():
        return float(value)
    for part in value.split("/"):
        if part.startswith("AV:"):
            break
    return None


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"
