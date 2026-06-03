from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from app.models import SoftwareComponent


REQUIREMENT_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?P<specifier>.*)?$"
)
DIRECT_REFERENCE_RE = re.compile(r"^\s*(?P<name>[A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*@\s*(?P<target>.+)$")
EXACT_SPECIFIERS = {"==", "==="}


@dataclass(frozen=True)
class ParsedDependency:
    name: str
    version: str | None
    version_specifier: str
    evidence: str


def _component_from_dependency(dependency: ParsedDependency, source: Path) -> SoftwareComponent:
    return SoftwareComponent(
        name=dependency.name,
        version=dependency.version,
        version_specifier=dependency.version_specifier,
        kind="python dependency",
        source=source.as_posix(),
        status="found",
        evidence=dependency.evidence,
        ecosystem="PyPI",
    )


def _strip_inline_comment(value: str) -> str:
    if " #" not in value:
        return value.strip()
    return value.split(" #", 1)[0].strip()


def parse_dependency_string(value: str) -> ParsedDependency | None:
    clean = _strip_inline_comment(value).strip()
    if not clean or clean.startswith(("#", "-")):
        return None
    clean = clean.split(";", 1)[0].strip()

    direct = DIRECT_REFERENCE_RE.match(clean)
    if direct:
        return ParsedDependency(
            name=direct.group("name"),
            version=None,
            version_specifier=f"@ {direct.group('target').strip()}",
            evidence=clean,
        )

    match = REQUIREMENT_RE.match(clean)
    if not match:
        return None

    name = match.group("name")
    if not name:
        return None

    version_specifier = _normalize_specifier((match.group("specifier") or "").strip())
    first_specifier, first_version = _first_version_specifier(version_specifier)
    concrete_version = first_version if first_specifier in EXACT_SPECIFIERS and first_version else None
    return ParsedDependency(
        name=name,
        version=concrete_version,
        version_specifier=version_specifier,
        evidence=clean,
    )


def _normalize_specifier(value: str) -> str:
    return re.sub(r"\s+", "", value)


def _first_version_specifier(value: str) -> tuple[str, str | None]:
    match = re.match(r"(===|==|~=|!=|>=|<=|>|<)([^,]+)", value)
    if not match:
        return "", None
    return match.group(1), match.group(2)


def parse_requirements_file(path: str | Path) -> list[SoftwareComponent]:
    req_path = Path(path)
    if not req_path.exists():
        return []
    components: list[SoftwareComponent] = []
    for line in req_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        dependency = parse_dependency_string(stripped)
        if dependency is None:
            continue
        components.append(_component_from_dependency(dependency, req_path))
    return components


def _parse_dependency_string(value: str, source: Path) -> SoftwareComponent | None:
    dependency = parse_dependency_string(value)
    if dependency is None:
        return None
    return _component_from_dependency(dependency, source)


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
            known_versions = sum(1 for component in components[before:] if component.version)
            notes.append(
                f"Parsed {added} Python dependency component(s) from {candidate.as_posix()} "
                f"({known_versions} exact version candidate(s) for OSV)."
            )

    return components, notes
