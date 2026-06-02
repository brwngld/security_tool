from __future__ import annotations

from rich.console import Console

from app import main
from app.config import AppConfig
from app.context import ApplicationContext, DiscoveryReport, ResolvedScanTarget
from app.models import ScanResult, Target
from app.profiles import profile_summary_notes, resolve_profile_preset


def test_resolve_profile_preset_handles_known_profiles() -> None:
    quick = resolve_profile_preset("quick")
    safe_vps = resolve_profile_preset("safe-vps")

    assert quick is not None
    assert quick.timeout_seconds == 6.0
    assert safe_vps is not None
    assert safe_vps.max_pages == 120
    assert resolve_profile_preset("unknown") is None


def test_profile_summary_notes_cover_scan_and_crawl() -> None:
    preset = resolve_profile_preset("full")

    scan_notes = profile_summary_notes(preset, "scan")
    crawl_notes = profile_summary_notes(preset, "crawl")

    assert scan_notes[0].startswith("Profile full:")
    assert "Profile timeout: 15" in scan_notes[1]
    assert any("Profile crawl defaults" in note for note in crawl_notes)


def test_scan_profile_quick_applies_timeout_and_prints_note(monkeypatch) -> None:
    captured = {}
    recorded_console = Console(record=True, width=100)

    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "confirm_risky_command", lambda action, assume_yes=False: True)
    monkeypatch.setattr(
        main,
        "resolve_application_context",
        lambda url, root, env_file, require_target=True: ApplicationContext(
            root=str(root),
            target=ResolvedScanTarget(value=url or "https://example.com", source="command line", key="command line"),
            discovery=DiscoveryReport(),
        ),
    )
    monkeypatch.setattr(main, "load_app_config", lambda policy_path=None: AppConfig(timeout_seconds=12.0))
    monkeypatch.setattr(
        main,
        "scan_target",
        lambda url, timeout_seconds, auth_config=None: _capture_scan_result(captured, url, timeout_seconds),
    )

    main.scan(url="https://example.com", profile="quick")

    assert captured["timeout"] == 6.0
    assert "Profile quick" in recorded_console.export_text()


def test_crawl_profile_safe_vps_applies_crawl_defaults(monkeypatch) -> None:
    captured = {}
    recorded_console = Console(record=True, width=100)

    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "confirm_risky_command", lambda action, assume_yes=False: True)
    monkeypatch.setattr(
        main,
        "resolve_application_context",
        lambda url, root, env_file, require_target=True: ApplicationContext(
            root=str(root),
            target=ResolvedScanTarget(value=url or "https://example.com", source="command line", key="command line"),
            discovery=DiscoveryReport(),
        ),
    )
    monkeypatch.setattr(main, "load_app_config", lambda policy_path=None: AppConfig(timeout_seconds=12.0))
    monkeypatch.setattr(
        main,
        "crawl_target",
        lambda url, timeout_seconds, max_pages, max_crawl_depth, same_host_only, include_patterns, exclude_patterns, seed_robots, seed_sitemap, auth_config=None: _capture_crawl_result(
            captured,
            url,
            timeout_seconds,
            max_pages,
            max_crawl_depth,
            same_host_only,
            seed_robots,
            seed_sitemap,
        ),
    )

    main.crawl(
        url="https://example.com",
        profile="safe-vps",
        include=None,
        exclude=None,
        same_host_only=None,
        seed_robots=None,
        seed_sitemap=None,
    )

    assert captured["timeout"] == 10.0
    assert captured["max_pages"] == 120
    assert captured["max_depth"] == 2
    assert captured["same_host_only"] is True
    assert captured["seed_robots"] is True
    assert captured["seed_sitemap"] is True
    assert "Profile safe-vps" in recorded_console.export_text()


def _capture_scan_result(captured: dict, url: str, timeout_seconds: float) -> ScanResult:
    captured["timeout"] = timeout_seconds
    result = ScanResult(target=Target(url=url, scheme="https", host="example.com"))
    captured["result"] = result
    return result


def _capture_crawl_result(
    captured: dict,
    url: str,
    timeout_seconds: float,
    max_pages: int,
    max_crawl_depth: int,
    same_host_only: bool,
    seed_robots: bool,
    seed_sitemap: bool,
) -> ScanResult:
    captured.update(
        {
            "timeout": timeout_seconds,
            "max_pages": max_pages,
            "max_depth": max_crawl_depth,
            "same_host_only": same_host_only,
            "seed_robots": seed_robots,
            "seed_sitemap": seed_sitemap,
        }
    )
    result = ScanResult(target=Target(url=url, scheme="https", host="example.com"), scanned_urls=[url])
    captured["result"] = result
    return result
