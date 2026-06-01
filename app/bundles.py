from __future__ import annotations

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from app.models import ReportBundle, ReportBundleItem


def _candidate_artifacts(report_path: Path, extra_artifacts: list[Path] | None = None) -> list[Path]:
    artifacts: list[Path] = []
    seen: set[Path] = set()

    def add(path: Path) -> None:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved in seen or not path.exists() or not path.is_file():
            return
        seen.add(resolved)
        artifacts.append(path)

    add(report_path)

    stem = report_path.stem
    directory = report_path.parent
    for suffix in (".json", ".md", ".markdown", ".html", ".htm"):
        sibling = directory / f"{stem}{suffix}"
        add(sibling)

    if "incident" in stem.lower():
        for name in ("incident-denylist.conf", "incident-fail2ban.conf", "incident-rate-limit.conf", "incident-maintenance.conf"):
            add(directory / name)

    for path in extra_artifacts or []:
        add(Path(path))

    return artifacts


def bundle_report_files(
    report_file: str | Path,
    *,
    output_path: str | Path | None = None,
    extra_artifacts: list[Path] | None = None,
) -> ReportBundle:
    report_path = Path(report_file)
    archive_path = Path(output_path) if output_path is not None else report_path.with_name(f"{report_path.stem}.bundle.zip")
    artifacts = _candidate_artifacts(report_path, extra_artifacts)
    manifest_name = f"{report_path.stem}.bundle-manifest.json"

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    items: list[ReportBundleItem] = []
    with ZipFile(archive_path, "w", compression=ZIP_DEFLATED) as archive:
        for artifact in artifacts:
            arcname = artifact.name if artifact.parent == report_path.parent else artifact.as_posix()
            archive.write(artifact, arcname=arcname)
            items.append(
                ReportBundleItem(
                    path=str(artifact),
                    arcname=arcname,
                    kind=artifact.suffix.lstrip(".") or "file",
                    size=artifact.stat().st_size if artifact.exists() else None,
                )
            )

        manifest = ReportBundle(
            output_path=str(archive_path),
            source_report=str(report_path),
            items=items,
            notes=[f"Bundled {len(items)} file(s) into {archive_path}"],
        )
        archive.writestr(manifest_name, manifest.model_dump_json(indent=2))

    return ReportBundle(
        output_path=str(archive_path),
        source_report=str(report_path),
        items=items,
        notes=[f"Bundled {len(items)} file(s) into {archive_path}"],
    )
