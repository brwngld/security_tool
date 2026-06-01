import zipfile
from pathlib import Path

from rich.console import Console

from app import main
from app.bundles import bundle_report_files


def test_bundle_report_files_packages_related_artifacts(workspace_temp_dir) -> None:
    report_path = workspace_temp_dir / "incident.json"
    report_path.write_text('{"kind":"incident"}', encoding="utf-8")
    (workspace_temp_dir / "incident.md").write_text("# report\n", encoding="utf-8")
    (workspace_temp_dir / "incident.html").write_text("<html></html>", encoding="utf-8")
    (workspace_temp_dir / "incident-denylist.conf").write_text("deny 10.0.0.1;\n", encoding="utf-8")

    bundle_path = workspace_temp_dir / "bundle.zip"
    bundle = bundle_report_files(report_path, output_path=bundle_path)

    assert Path(bundle.output_path).exists()
    assert len(bundle.items) >= 3

    with zipfile.ZipFile(bundle_path) as archive:
        names = set(archive.namelist())
        assert "bundle-manifest.json" in names
        assert "incident.json" in names
        assert "incident.md" in names
        assert "incident.html" in names
        assert "incident-denylist.conf" in names


def test_bundle_report_files_skips_missing_artifacts_and_deduplicates(workspace_temp_dir) -> None:
    report_path = workspace_temp_dir / "scan.json"
    report_path.write_text('{"kind":"scan"}', encoding="utf-8")
    duplicate_artifact = workspace_temp_dir / "duplicate.txt"
    duplicate_artifact.write_text("duplicate", encoding="utf-8")

    bundle = bundle_report_files(
        report_path,
        output_path=workspace_temp_dir / "bundle.zip",
        extra_artifacts=[duplicate_artifact, duplicate_artifact, workspace_temp_dir / "missing.txt"],
    )

    paths = [item.path for item in bundle.items]
    assert paths.count(str(duplicate_artifact)) == 1
    assert all("missing.txt" not in path for path in paths)


def test_bundle_command_renders_summary(monkeypatch, workspace_temp_dir) -> None:
    report_path = workspace_temp_dir / "scan.json"
    report_path.write_text('{"kind":"scan"}', encoding="utf-8")
    recorded_console = Console(record=True, width=120)
    monkeypatch.setattr(main, "console", recorded_console)

    main.bundle(report_path, artifact=[workspace_temp_dir / "incident-denylist.conf"], bundle_output=workspace_temp_dir / "outputs" / "bundle.zip")

    text = recorded_console.export_text()
    assert "Report Bundle" in text
    assert "bundle.zip" in text
