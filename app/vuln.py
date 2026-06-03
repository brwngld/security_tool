from __future__ import annotations

import platform
import re
import subprocess
from pathlib import Path
from typing import Callable

from app.advisories import advisory_sources, match_advisories
from app.dependencies import discover_python_dependency_components
from app.models import SoftwareComponent, VulnerabilityFinding, VulnerabilityReport

CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


COMMAND_PROBES: tuple[tuple[str, str, list[str], str], ...] = (
    ("Nginx", "web server", ["nginx", "-v"], r"nginx/([^\s]+)"),
    ("Apache httpd", "web server", ["httpd", "-v"], r"Apache/([^\s]+)"),
    ("Apache apache2", "web server", ["apache2", "-v"], r"Apache/([^\s]+)"),
    ("OpenSSL", "crypto library", ["openssl", "version"], r"OpenSSL\s+([^\s]+)"),
    ("Python", "runtime", ["python", "--version"], r"Python\s+([^\s]+)"),
    ("Node.js", "runtime", ["node", "--version"], r"v?([0-9][^\s]*)"),
    ("npm", "package manager", ["npm", "--version"], r"([0-9][^\s]*)"),
    ("PHP", "runtime", ["php", "-v"], r"PHP\s+([^\s]+)"),
)


def _run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )


def _first_line(text: str) -> str:
    return next((line.strip() for line in text.splitlines() if line.strip()), "")


def _extract_version(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text, flags=re.IGNORECASE)
    if not match:
        return None
    return match.group(1).strip()


def match_local_advisories(components: list[SoftwareComponent]) -> list[VulnerabilityFinding]:
    return match_advisories(components)


def _probe_command(
    name: str,
    kind: str,
    command: list[str],
    version_pattern: str,
    *,
    runner: CommandRunner,
) -> SoftwareComponent:
    try:
        completed = runner(command)
    except FileNotFoundError:
        return SoftwareComponent(
            name=name,
            kind=kind,
            source=" ".join(command),
            status="missing",
            evidence="command not found",
        )
    except Exception as exc:
        return SoftwareComponent(
            name=name,
            kind=kind,
            source=" ".join(command),
            status="error",
            evidence=str(exc),
        )

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    if completed.returncode != 0 and not output:
        return SoftwareComponent(
            name=name,
            kind=kind,
            source=" ".join(command),
            status="error",
            evidence=f"exit code {completed.returncode}",
        )

    version = _extract_version(output, version_pattern)
    status = "found" if completed.returncode == 0 or version else "error"
    return SoftwareComponent(
        name=name,
        version=version,
        kind=kind,
        source=" ".join(command),
        status=status,
        evidence=_first_line(output) or f"exit code {completed.returncode}",
    )


def scan_software_inventory(
    root: str | Path,
    *,
    runner: CommandRunner | None = None,
    match_cves: bool = True,
    include_osv: bool = False,
    osv_cache_dir: str | Path | None = None,
) -> VulnerabilityReport:
    command_runner = runner or _run_command
    root_path = Path(root)
    components = [
        _probe_command(name, kind, command, pattern, runner=command_runner)
        for name, kind, command, pattern in COMMAND_PROBES
    ]
    dependency_components, dependency_notes = discover_python_dependency_components(root_path)
    components.extend(dependency_components)

    sources = advisory_sources(include_osv=include_osv, osv_cache_dir=osv_cache_dir)
    findings = match_advisories(components, sources=sources) if match_cves else []
    notes = [
        f"Host platform: {platform.system()} {platform.release()}",
        "CVE matching always includes a small bundled offline advisory set.",
        "Confirm vendor backports before treating an older distro package as definitely vulnerable.",
    ]
    notes.extend(dependency_notes)
    found_count = sum(1 for component in components if component.status == "found")
    notes.append(f"Discovered {found_count} software component(s) from command probes and dependency manifests.")
    if match_cves:
        if include_osv:
            notes.append("OSV dependency advisory lookup was enabled for parsed Python dependency manifests.")
            if osv_cache_dir is not None:
                notes.append(f"OSV cache directory: {Path(osv_cache_dir).as_posix()}.")
        else:
            notes.append("OSV dependency advisory lookup was not enabled; use --osv to query OSV for parsed dependencies.")
        for source in sources:
            notes.extend(getattr(source, "notes", []))
        notes.append(f"Matched {len(findings)} advisory finding(s).")
    else:
        notes.append("CVE matching was disabled for this run.")
    return VulnerabilityReport(
        root=str(root_path),
        components=components,
        findings=findings,
        notes=notes,
        cve_matching=match_cves,
    )
