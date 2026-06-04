from app.advisories import AdvisoryQuery, LocalRulesSource, advisory_sources, match_advisories
from app.models import SoftwareComponent


def test_local_rules_source_matches_exact_version() -> None:
    component = SoftwareComponent(name="Apache httpd", version="2.4.49", kind="web server", source="httpd -v")
    source = LocalRulesSource()

    findings = source.match(AdvisoryQuery(component=component))

    assert [finding.cve_id for finding in findings] == ["CVE-2021-41773"]
    assert findings[0].severity == "critical"


def test_local_rules_source_matches_version_range() -> None:
    component = SoftwareComponent(name="OpenSSL", version="3.0.6", kind="crypto library", source="openssl version")
    source = LocalRulesSource()

    findings = source.match(AdvisoryQuery(component=component))

    assert [finding.cve_id for finding in findings] == ["CVE-2022-3602"]


def test_match_advisories_dedupes_sources() -> None:
    component = SoftwareComponent(name="OpenSSL", version="3.0.6", kind="crypto library", source="openssl version")
    source = LocalRulesSource()

    findings = match_advisories([component], sources=[source, source])

    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2022-3602"


def test_advisory_sources_include_local_rules() -> None:
    sources = advisory_sources()

    assert any(source.name == "local-rules" for source in sources)
