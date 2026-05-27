from app.config import AppConfig, load_app_config


def test_load_app_config_reads_json_file(workspace_temp_dir) -> None:
    path = workspace_temp_dir / "policy.json"
    path.write_text('{"timeout_seconds": 2.5, "max_pages": 50, "audit_log_path": "logs/audit.log"}', encoding="utf-8")

    config = load_app_config(path)

    assert isinstance(config, AppConfig)
    assert config.timeout_seconds == 2.5
    assert config.max_pages == 50
    assert config.audit_log_path == "logs/audit.log"


def test_load_app_config_uses_defaults_when_no_file_is_given() -> None:
    config = load_app_config()

    assert config.allowed_fix_level == 0
    assert config.timeout_seconds == 10.0
    assert config.audit_log_path == "outputs/audit.log"
