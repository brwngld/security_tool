from __future__ import annotations

import re
import tomllib
from pathlib import Path

from app.models import SoftwareComponent


PINNED_REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.!+*-]+)"
)


def _component_from_dependency(name: str, version: str, source: Path) -> SoftwareComponent:
    return SoftwareComponent(
        name=name,
        version=version,
        kind="python dependency",
        source=source.as_posix(),
        status="found",
        evidence=f"{name}=={version}",
        ecosystem="PyPI",
    )


def parse_requirements_file(path: str | Path) -> list[SoftwareComponent]:
    req_path = Path(path)
    if not req_path.exists():
        return []
    components: list[SoftwareComponent] = []
    for line in req_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        match = PINNED_REQUIREMENT_RE.match(stripped)
        if not match:
            continue
        components.append(_component_from_dependency(match.group(1), match.group(2), req_path))
    return components


def _parse_dependency_string(value: str, source: Path) -> SoftwareComponent | None:
    match = PINNED_REQUIREMENT_RE.match(value)
    if not match:
        return None
    return _component_from_dependency(match.group(1), match.group(2), source)


def parse_pyproject_file(path: str | Path) -> list[SoftwareComponent]:
    pyproject_path = Path(path)
    if not pyproject_path.exists():
        return []
    try:
        payload = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    dependency_values: list[str] = []
    project_dependencies = payload.get("project", {}).get("dependencies", [])
    if isinstance(project_dependencies, list):
        dependency_values.extend(value for value in project_dependencies if isinstance(value, str))

    optional_dependencies = payload.get("project", {}).get("optional-dependencies", {})
    if isinstance(optional_dependencies, dict):
        for values in optional_dependencies.values():
            if isinstance(values, list):
                dependency_values.extend(value for value in values if isinstance(value, str))

    components: list[SoftwareComponent] = []
    for dependency in dependency_values:
        component = _parse_dependency_string(dependency, pyproject_path)
        if component is not None:
            components.append(component)
    return components


def discover_python_dependency_components(root: str | Path) -> tuple[list[SoftwareComponent], list[str]]:
    root_path = Path(root)
    components: list[SoftwareComponent] = []
    notes: list[str] = []

    candidates = [root_path / "requirements.txt", root_path / "pyproject.toml"]
    for candidate in candidates:
        before = len(components)
        if candidate.name == "requirements.txt":
            components.extend(parse_requirements_file(candidate))
        elif candidate.name == "pyproject.toml":
            components.extend(parse_pyproject_file(candidate))
        added = len(components) - before
        if candidate.exists():
            notes.append(f"Parsed {added} pinned Python dependency component(s) from {candidate.as_posix()}.")

    return components, notes
