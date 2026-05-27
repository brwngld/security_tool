import os
import subprocess
import sys
from pathlib import Path

from app.models import ScanResult, Target
from app.output_paths import expand_optional_output_arguments, normalize_output_path
from app.reports.json_report import write_json_report


def test_normalize_output_path_treats_windows_root_paths_as_project_relative(workspace_temp_dir, monkeypatch) -> None:
    monkeypatch.chdir(workspace_temp_dir)

    normalized = normalize_output_path(r"\outputs\crawl-test.html", cwd=workspace_temp_dir)

    assert normalized is not None
    assert normalized.path == workspace_temp_dir / "outputs" / "crawl-test.html"
    assert normalized.note is not None
    assert "Interpreted '\\outputs\\crawl-test.html'" in normalized.note


def test_normalize_output_path_keeps_absolute_paths(monkeypatch, workspace_temp_dir) -> None:
    monkeypatch.chdir(workspace_temp_dir)

    absolute_path = Path("C:/reports/crawl-test.html")
    normalized = normalize_output_path(absolute_path, cwd=workspace_temp_dir)

    assert normalized is not None
    assert normalized.path == absolute_path
    assert normalized.note is None or "Interpreted" not in normalized.note


def test_expand_optional_output_arguments_inserts_default_output_path() -> None:
    rewritten, notes = expand_optional_output_arguments(["app.main", "crawl", "http://example.com", "--html-output"])

    assert rewritten[:3] == ["app.main", "crawl", "http://example.com"]
    assert rewritten[3] == "--html-output"
    default_path = Path(rewritten[4])
    assert default_path.parts[0] == "outputs"
    assert default_path.suffix == ".html"
    assert notes
    assert "Using default output path for --html-output" in notes[0]


def test_expand_optional_output_arguments_keeps_explicit_paths() -> None:
    rewritten, notes = expand_optional_output_arguments(
        ["app.main", "crawl", "http://example.com", "--html-output", "outputs/custom.html"]
    )

    assert rewritten == ["app.main", "crawl", "http://example.com", "--html-output", "outputs/custom.html"]
    assert notes == []


def test_report_command_accepts_bare_html_output_flag(workspace_temp_dir) -> None:
    report_input = workspace_temp_dir / "scan.json"
    result = ScanResult(
        target=Target(url="https://example.com", scheme="https", host="example.com"),
        findings=[],
        fix_plans=[],
    )
    write_json_report(result, report_input)

    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])

    completed = subprocess.run(
        [sys.executable, "-m", "app.main", "report", str(report_input), "--html-output"],
        cwd=workspace_temp_dir,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "Using default output path for --html-output:" in completed.stdout

    output_files = list((workspace_temp_dir / "outputs").glob("*.html"))
    assert output_files, completed.stdout
