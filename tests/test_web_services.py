import json

import pytest

pytest.importorskip("sqlalchemy")

from app.web.config import WebConfig, load_web_config, load_web_config_with_diagnostics, render_web_config_diagnostics
from app.web.db import Base, make_engine
from app.web.models import Job, User
from app.web.services import READ_ONLY_JOB_TYPES, bootstrap_admin, create_job, sanitize_params
from app.web.worker import JOB_HANDLERS


def test_sanitize_params_redacts_secret_like_values() -> None:
    params = sanitize_params({"target_url": "https://example.com", "password": "secret", "auth_env_ref": "APP_PASSWORD"})

    assert params["target_url"] == "https://example.com"
    assert params["password"] == "[redacted]"
    assert params["auth_env_ref"] == "APP_PASSWORD"


def test_bootstrap_admin_and_job_ownership(workspace_temp_dir) -> None:
    from sqlalchemy.orm import Session

    config = WebConfig(
        database_url=f"sqlite:///{workspace_temp_dir / 'web.db'}",
        secret_key="test-secret",
        output_dir=workspace_temp_dir / "outputs",
        host="127.0.0.1",
        port=8787,
        admin_email="admin@example.com",
        admin_password="temporary-password",
    )
    engine = make_engine(config)
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        admin = bootstrap_admin(session, config)
        assert admin is not None
        job = create_job(
            session,
            job_type="scan",
            created_by_user_id=admin.id,
            target_id=None,
            target_url="https://example.com",
            params={"target_url": "https://example.com", "password": "secret"},
        )
        admin_id = admin.id
        job_id = job.id
        session.commit()

    with Session(engine) as session:
        stored_user = session.get(User, admin_id)
        stored_job = session.get(Job, job_id)
        assert stored_user is not None
        assert stored_user.role == "admin"
        assert stored_job is not None
        assert stored_job.created_by_user_id == stored_user.id
        assert json.loads(stored_job.params_json)["password"] == "[redacted]"


def test_read_only_web_jobs_have_worker_handlers() -> None:
    assert READ_ONLY_JOB_TYPES == set(JOB_HANDLERS)


def test_create_job_rejects_disabled_response_actions(workspace_temp_dir) -> None:
    from sqlalchemy.orm import Session

    config = WebConfig(
        database_url=f"sqlite:///{workspace_temp_dir / 'web.db'}",
        secret_key="test-secret",
        output_dir=workspace_temp_dir / "outputs",
        host="127.0.0.1",
        port=8787,
        admin_email="admin@example.com",
        admin_password="temporary-password",
    )
    engine = make_engine(config)
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        with pytest.raises(ValueError, match="Unsupported read-only web job type"):
            create_job(
                session,
                job_type="fix",
                created_by_user_id=None,
                target_id=None,
                target_url=None,
                params={},
            )


def test_web_config_uses_dotenv_when_runtime_env_is_missing(workspace_temp_dir, monkeypatch) -> None:
    (workspace_temp_dir / ".env").write_text(
        "\n".join(
            [
                "PSHIELD_DATABASE_URL=sqlite:///from-dotenv.db",
                "PSHIELD_SECRET_KEY=dotenv-secret",
                "PSHIELD_OUTPUT_DIR=dotenv-output",
                "PSHIELD_WEB_HOST=0.0.0.0",
                "PSHIELD_WEB_PORT=9999",
                "PSHIELD_ADMIN_EMAIL=admin-dotenv@example.com",
                "PSHIELD_ADMIN_PASSWORD=dotenv-password",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(workspace_temp_dir)
    for key in (
        "PSHIELD_DATABASE_URL",
        "PSHIELD_SECRET_KEY",
        "PSHIELD_OUTPUT_DIR",
        "PSHIELD_WEB_HOST",
        "PSHIELD_WEB_PORT",
        "PSHIELD_ADMIN_EMAIL",
        "PSHIELD_ADMIN_PASSWORD",
    ):
        monkeypatch.delenv(key, raising=False)

    config = load_web_config()

    assert config.database_url == "sqlite:///from-dotenv.db"
    assert config.secret_key == "dotenv-secret"
    assert config.output_dir.name == "dotenv-output"
    assert config.host == "0.0.0.0"
    assert config.port == 9999
    assert config.admin_email == "admin-dotenv@example.com"
    assert config.admin_password == "dotenv-password"

    _config, diagnostics = load_web_config_with_diagnostics()
    lines = render_web_config_diagnostics(diagnostics)
    assert any(f"PSHIELD_DATABASE_URL: .env at {workspace_temp_dir / '.env'}" in line for line in lines)
    assert any(f"PSHIELD_ADMIN_PASSWORD: .env at {workspace_temp_dir / '.env'}" in line for line in lines)


def test_web_config_prefers_runtime_env_over_dotenv(workspace_temp_dir, monkeypatch) -> None:
    (workspace_temp_dir / ".env").write_text(
        "PSHIELD_WEB_PORT=9999\nPSHIELD_ADMIN_EMAIL=admin-dotenv@example.com\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(workspace_temp_dir)
    monkeypatch.setenv("PSHIELD_WEB_PORT", "8788")
    monkeypatch.setenv("PSHIELD_ADMIN_EMAIL", "admin-live@example.com")

    config = load_web_config()

    assert config.port == 8788
    assert config.admin_email == "admin-live@example.com"

    _config, diagnostics = load_web_config_with_diagnostics()
    lines = render_web_config_diagnostics(diagnostics)
    assert any("PSHIELD_WEB_PORT: live/process environment" in line for line in lines)
    assert any("PSHIELD_ADMIN_EMAIL: live/process environment" in line for line in lines)


def test_web_config_diagnostics_report_missing_values(workspace_temp_dir, monkeypatch) -> None:
    monkeypatch.chdir(workspace_temp_dir)
    for key in (
        "PSHIELD_SECRET_KEY",
        "PSHIELD_ADMIN_EMAIL",
        "PSHIELD_ADMIN_PASSWORD",
    ):
        monkeypatch.delenv(key, raising=False)

    config, diagnostics = load_web_config_with_diagnostics()
    lines = render_web_config_diagnostics(diagnostics)

    assert config.database_url.startswith("postgresql+psycopg://")
    assert any("PSHIELD_DATABASE_URL: built-in default" in line for line in lines)
    assert any("PSHIELD_SECRET_KEY: built-in default" in line for line in lines)
    assert any("PSHIELD_ADMIN_EMAIL: missing" in line for line in lines)
    assert any("PSHIELD_ADMIN_PASSWORD: missing" in line for line in lines)
    assert any("PSHIELD_DATABASE_URL was not found" in line for line in lines)
    assert any("PSHIELD_SECRET_KEY was not found" in line for line in lines)
