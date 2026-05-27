import json

from app import main
from app.context import ApplicationContext
from app.config import AppConfig
from app.models import ScanResult, Target


def build_result() -> ScanResult:
    return ScanResult(
        target=Target(url="https://example.com", scheme="https", host="example.com"),
        context=ApplicationContext(root="C:/workspace", target=None),
        findings=[],
    )


def test_baseline_uses_host_name_when_no_label_is_set(monkeypatch, workspace_temp_dir) -> None:
    written_paths = []

    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig())
    monkeypatch.setattr(main, "scan_target", lambda url, timeout_seconds: build_result())
    monkeypatch.setattr(main, "render_policy", lambda policy: "policy")
    monkeypatch.setattr(main, "render_console", lambda result, include_fix_plans=False: "console")
    monkeypatch.setattr(main, "write_json_report", lambda result, path: written_paths.append(path) or path)

    monkeypatch.chdir(workspace_temp_dir)
    main.baseline("https://example.com")

    assert written_paths[0].name == "example.com.json"


def test_baseline_uses_friendly_label_when_one_is_set(monkeypatch, workspace_temp_dir) -> None:
    written_paths = []

    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig())
    monkeypatch.setattr(main, "scan_target", lambda url, timeout_seconds: build_result())
    monkeypatch.setattr(main, "render_policy", lambda policy: "policy")
    monkeypatch.setattr(main, "render_console", lambda result, include_fix_plans=False: "console")
    monkeypatch.setattr(main, "write_json_report", lambda result, path: written_paths.append(path) or path)

    monkeypatch.chdir(workspace_temp_dir)
    main.baseline("https://example.com", label="VPS West")

    assert written_paths[0].name == "vps-west.json"


def test_baseline_writes_metadata_next_to_the_saved_snapshot(monkeypatch, workspace_temp_dir) -> None:
    written_paths = []

    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig())
    monkeypatch.setattr(main, "scan_target", lambda url, timeout_seconds: build_result())
    monkeypatch.setattr(main, "render_policy", lambda policy: "policy")
    monkeypatch.setattr(main, "render_console", lambda result, include_fix_plans=False: "console")
    recorded_console = []
    monkeypatch.setattr(main, "console", type("Console", (), {"print": lambda self, message: recorded_console.append(str(message))})())

    def record_json_report(result, path):
        written_paths.append(path)
        path.write_text("{}", encoding="utf-8")
        return path

    monkeypatch.setattr(main, "write_json_report", record_json_report)

    monkeypatch.chdir(workspace_temp_dir)
    main.baseline("https://example.com", label="VPS West")

    baseline_path = written_paths[0]
    metadata_path = baseline_path.with_suffix(baseline_path.suffix + ".meta.json")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    assert metadata_path.exists()
    assert metadata["label"] == "VPS West"
    assert metadata["root"] == str(workspace_temp_dir)
    assert any("Wrote baseline metadata to" in line for line in recorded_console)
    assert any("Discovery:" in line for line in recorded_console)


def test_baseline_uses_cli_audit_log_path(monkeypatch, workspace_temp_dir) -> None:
    written_paths = []

    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig(audit_log_path="outputs/audit.log"))
    monkeypatch.setattr(main, "scan_target", lambda url, timeout_seconds: build_result())
    monkeypatch.setattr(main, "render_policy", lambda policy: "policy")
    monkeypatch.setattr(main, "render_console", lambda result, include_fix_plans=False: "console")
    monkeypatch.setattr(main, "write_json_report", lambda result, path: path)
    monkeypatch.setattr(main, "append_audit_event", lambda path, event: written_paths.append(path))

    monkeypatch.chdir(workspace_temp_dir)
    main.baseline("https://example.com", audit_log=workspace_temp_dir / "audit.log")

    assert written_paths[0] == workspace_temp_dir / "audit.log"
