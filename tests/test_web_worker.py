from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.web.config import WebConfig
from app.web.db import Base, make_engine
from app.web.models import AuditEventRecord, Job, Report
from app.web.services import bootstrap_admin, create_job, record_report
from app.web.worker import run_job


def test_worker_run_job_records_success_report_and_audit(monkeypatch, workspace_temp_dir) -> None:
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

    def fake_handler(session, job, params, output_dir: Path):
        report_path = output_dir / "fake.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text("{}", encoding="utf-8")
        record_report(session, job_id=job.id, report_type="scan", json_path=report_path, summary={"fake": True})
        return {"fake": True}

    monkeypatch.setitem(__import__("app.web.worker", fromlist=["JOB_HANDLERS"]).JOB_HANDLERS, "scan", fake_handler)

    with Session(engine) as session:
        admin = bootstrap_admin(session, config)
        job = create_job(
            session,
            job_type="scan",
            created_by_user_id=admin.id if admin is not None else None,
            target_id=None,
            target_url="https://example.com",
            params={"target_url": "https://example.com"},
        )
        job.status = "running"
        session.flush()
        job_id = job.id
        run_job(session, job, config)
        session.commit()

    with Session(engine) as session:
        stored_job = session.get(Job, job_id)
        reports = session.scalars(select(Report).where(Report.job_id == job_id)).all()
        events = session.scalars(select(AuditEventRecord).where(AuditEventRecord.job_id == job_id)).all()

    assert stored_job is not None
    assert stored_job.status == "succeeded"
    assert len(reports) == 1
    assert len(events) == 1
    assert events[0].result == "succeeded"


def test_worker_crawl_handler_uses_engine_depth_keyword(monkeypatch, workspace_temp_dir) -> None:
    from app.models import ScanResult, Target
    from app.web.worker import handle_crawl

    captured = {}

    def fake_crawl_target(target_url: str, **kwargs):
        captured.update(kwargs)
        return ScanResult(
            target=Target(url=target_url, scheme="http", host="example.com"),
            findings=[],
            notes=[],
            scanned_urls=[target_url],
        )

    monkeypatch.setattr("app.web.worker.crawl_target", fake_crawl_target)

    config = WebConfig(
        database_url=f"sqlite:///{workspace_temp_dir / 'web.db'}",
        secret_key="test-secret",
        output_dir=workspace_temp_dir / "outputs",
        host="127.0.0.1",
        port=8787,
    )
    engine = make_engine(config)
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        job = Job(job_type="crawl", target_url="http://example.com", status="running", params_json="{}")
        session.add(job)
        session.flush()
        handle_crawl(session, job, {"max_pages": 10, "max_depth": 3}, workspace_temp_dir / "outputs")

    assert captured["max_crawl_depth"] == 3
    assert "max_depth" not in captured


def test_worker_scan_handler_passes_browser_auth_config(monkeypatch, workspace_temp_dir) -> None:
    from app.models import ScanResult, Target
    from app.web.worker import handle_scan

    captured = {}

    def fake_scan_target(target_url: str, **kwargs):
        captured.update(kwargs)
        return ScanResult(
            target=Target(url=target_url, scheme="http", host="example.com"),
            findings=[],
            notes=[],
            scanned_urls=[target_url],
        )

    monkeypatch.setattr("app.web.worker.scan_target", fake_scan_target)

    config = WebConfig(
        database_url=f"sqlite:///{workspace_temp_dir / 'web.db'}",
        secret_key="test-secret",
        output_dir=workspace_temp_dir / "outputs",
        host="127.0.0.1",
        port=8787,
    )
    engine = make_engine(config)
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        job = Job(job_type="scan", target_url="http://example.com", status="running", params_json="{}")
        session.add(job)
        session.flush()
        handle_scan(
            session,
            job,
            {
                "auth_method": "browser",
                "login_url": "/auth/login",
                "username": "bernard",
                "auth_env_ref": "PSHIELD_APP_PASSWORD",
                "auth_check_url": "/user/dashboard",
                "browser_username_selector": "#identifier",
                "browser_password_selector": "#password",
                "browser_submit_selector": "button[type='submit']",
                "browser_headless": True,
            },
            workspace_temp_dir / "outputs",
        )

    auth_config = captured["auth_config"]
    assert auth_config.auth_method == "browser"
    assert auth_config.login_url == "/auth/login"
    assert auth_config.password_env == "PSHIELD_APP_PASSWORD"
    assert auth_config.browser_username_selector == "#identifier"
