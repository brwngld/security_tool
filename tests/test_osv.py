from app.advisories import AdvisoryQuery
from app.advisories.osv import OSVQuery, OSVSource
from app.models import SoftwareComponent


def test_osv_source_matches_pypi_dependency_and_writes_cache(workspace_temp_dir) -> None:
    cache_dir = workspace_temp_dir / "cache"
    calls: list[OSVQuery] = []

    def fake_fetcher(query: OSVQuery) -> dict:
        calls.append(query)
        return {
            "vulns": [
                {
                    "id": "PYSEC-2024-1",
                    "aliases": ["CVE-2024-0001"],
                    "summary": "Example dependency issue",
                    "references": [{"url": "https://osv.dev/vulnerability/PYSEC-2024-1"}],
                    "affected": [{"ranges": [{"events": [{"fixed": "2.0.0"}]}]}],
                    "database_specific": {"severity": "HIGH"},
                }
            ]
        }

    component = SoftwareComponent(
        name="example",
        version="1.0.0",
        kind="python dependency",
        source="requirements.txt",
        ecosystem="PyPI",
    )
    source = OSVSource(cache_dir=cache_dir, fetcher=fake_fetcher)

    findings = source.match(AdvisoryQuery(component=component))

    assert len(calls) == 1
    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2024-0001"
    assert findings[0].severity == "high"
    assert findings[0].fixed_version == "2.0.0"
    assert findings[0].confidence == "confirmed"
    assert findings[0].source == "osv"
    assert list(cache_dir.glob("*.json"))


def test_osv_source_uses_cache_when_network_fails(workspace_temp_dir) -> None:
    cache_dir = workspace_temp_dir / "cache"
    component = SoftwareComponent(
        name="example",
        version="1.0.0",
        kind="python dependency",
        source="requirements.txt",
        ecosystem="PyPI",
    )
    first_source = OSVSource(
        cache_dir=cache_dir,
        fetcher=lambda query: {"vulns": [{"id": "PYSEC-2024-1", "summary": "Cached issue"}]},
    )
    assert first_source.match(AdvisoryQuery(component=component))

    def failing_fetcher(query: OSVQuery) -> dict:
        raise RuntimeError("offline")

    cached_source = OSVSource(cache_dir=cache_dir, fetcher=failing_fetcher)
    findings = cached_source.match(AdvisoryQuery(component=component))

    assert [finding.cve_id for finding in findings] == ["PYSEC-2024-1"]
    assert cached_source.notes == []


def test_osv_source_gracefully_handles_offline_without_cache(workspace_temp_dir) -> None:
    def failing_fetcher(query: OSVQuery) -> dict:
        raise RuntimeError("offline")

    component = SoftwareComponent(
        name="example",
        version="1.0.0",
        kind="python dependency",
        source="requirements.txt",
        ecosystem="PyPI",
    )
    source = OSVSource(cache_dir=workspace_temp_dir / "cache", fetcher=failing_fetcher)

    findings = source.match(AdvisoryQuery(component=component))

    assert findings == []
    assert any("OSV lookup failed" in note for note in source.notes)
