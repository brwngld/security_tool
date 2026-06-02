from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProfilePreset:
    name: str
    summary: str
    timeout_seconds: float | None = None
    max_pages: int | None = None
    max_crawl_depth: int | None = None
    seed_robots: bool | None = None
    seed_sitemap: bool | None = None
    same_host_only: bool | None = None


_PROFILE_PRESETS: dict[str, ProfilePreset] = {
    "quick": ProfilePreset(
        name="quick",
        summary="fast first pass with shallow coverage",
        timeout_seconds=6.0,
        max_pages=20,
        max_crawl_depth=1,
        seed_robots=False,
        seed_sitemap=False,
        same_host_only=True,
    ),
    "full": ProfilePreset(
        name="full",
        summary="broader scan with sitemap and robots hints enabled",
        timeout_seconds=15.0,
        max_pages=300,
        max_crawl_depth=4,
        seed_robots=True,
        seed_sitemap=True,
        same_host_only=True,
    ),
    "safe-vps": ProfilePreset(
        name="safe-vps",
        summary="balanced VPS-friendly crawl with tight scope",
        timeout_seconds=10.0,
        max_pages=120,
        max_crawl_depth=2,
        seed_robots=True,
        seed_sitemap=True,
        same_host_only=True,
    ),
}


def resolve_profile_preset(profile_name: str | None) -> ProfilePreset | None:
    if profile_name is None:
        return None
    cleaned = profile_name.strip().lower()
    if not cleaned:
        return None
    return _PROFILE_PRESETS.get(cleaned)


def profile_summary_notes(profile: ProfilePreset | None, command_name: str) -> list[str]:
    if profile is None:
        return []

    notes = [f"Profile {profile.name}: {profile.summary}"]
    if profile.timeout_seconds is not None:
        notes.append(f"Profile timeout: {profile.timeout_seconds:g}s")

    if command_name == "crawl":
        notes.append(
            f"Profile crawl defaults: max pages {profile.max_pages}, max depth {profile.max_crawl_depth}, "
            f"seed robots {'on' if profile.seed_robots else 'off'}, seed sitemap {'on' if profile.seed_sitemap else 'off'}"
        )

    return notes
