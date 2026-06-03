import re

from fastapi.testclient import TestClient

from app.web.models import Job
from app.web.services import record_report
from app.web.app import create_app
from app.web.config import WebConfig


def _web_config(workspace_temp_dir) -> WebConfig:
    return WebConfig(
        database_url=f"sqlite:///{workspace_temp_dir / 'web.db'}",
        secret_key="test-secret",
        output_dir=workspace_temp_dir / "outputs",
        host="127.0.0.1",
        port=8787,
        admin_email="admin@example.com",
        admin_password="temporary-password",
    )


def _csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def _login(client: TestClient) -> None:
    assert client.post(
        "/login",
        data={"email": "admin@example.com", "password": "temporary-password"},
        follow_redirects=False,
    ).status_code == 303


def test_web_app_redirects_unauthenticated_users_to_login(workspace_temp_dir) -> None:
    client = TestClient(create_app(_web_config(workspace_temp_dir)), follow_redirects=False)

    response = client.get("/")

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_web_app_login_target_and_job_flow(workspace_temp_dir) -> None:
    client = TestClient(create_app(_web_config(workspace_temp_dir)))

    _login(client)
    targets_form = client.get("/targets")

    target_response = client.post(
        "/targets",
        data={"name": "Example", "url": "https://example.com", "csrf_token": _csrf_token(targets_form.text)},
        follow_redirects=False,
    )
    assert target_response.status_code == 303

    new_job_form = client.get("/jobs/new")
    job_response = client.post(
        "/jobs",
        data={
            "job_type": "scan",
            "target_url": "https://example.com",
            "max_pages": "10",
            "max_depth": "1",
            "csrf_token": _csrf_token(new_job_form.text),
        },
        follow_redirects=False,
    )
    assert job_response.status_code == 303
    assert job_response.headers["location"].startswith("/jobs/")

    jobs_page = client.get("/jobs")
    assert jobs_page.status_code == 200
    assert "scan" in jobs_page.text


def test_new_job_page_lists_read_only_jobs_and_disabled_response_actions(workspace_temp_dir) -> None:
    client = TestClient(create_app(_web_config(workspace_temp_dir)))
    _login(client)

    response = client.get("/jobs/new")

    assert response.status_code == 200
    for label in [
        "Auth/session helpers",
        "Browser login for JS-heavy flows",
        "Safe fix helpers",
        "Watch snapshot",
        "Incident review",
        "Integrity drift",
        "Doctor readiness",
        "Server check",
        "Report drift",
        "Incident timeline",
        "Audit export",
    ]:
        assert label in response.text
    for label in ["Fix locally", "Live containment", "Kill process", "Disable account", "Quarantine file", "Firewall change"]:
        assert label in response.text
    assert "Disabled for v1" in response.text


def test_web_app_rejects_disabled_response_job_type(workspace_temp_dir) -> None:
    client = TestClient(create_app(_web_config(workspace_temp_dir)), follow_redirects=False)
    _login(client)

    form = client.get("/jobs/new")
    response = client.post(
        "/jobs",
        data={"job_type": "fix", "csrf_token": _csrf_token(form.text)},
    )

    assert response.status_code == 400


def test_admin_can_create_and_disable_user(workspace_temp_dir) -> None:
    client = TestClient(create_app(_web_config(workspace_temp_dir)))
    _login(client)

    users_form = client.get("/admin/users")
    create_response = client.post(
        "/admin/users",
        data={
            "email": "viewer@example.com",
            "password": "viewer-password",
            "role": "viewer",
            "csrf_token": _csrf_token(users_form.text),
        },
        follow_redirects=False,
    )
    assert create_response.status_code == 303

    users_page = client.get("/admin/users")
    assert "viewer@example.com" in users_page.text

    users_page = client.get("/admin/users")
    disable_response = client.post(
        "/admin/users/2/toggle",
        data={"csrf_token": _csrf_token(users_page.text)},
        follow_redirects=False,
    )
    assert disable_response.status_code == 303


def test_authenticated_post_requires_csrf_token(workspace_temp_dir) -> None:
    client = TestClient(create_app(_web_config(workspace_temp_dir)))
    _login(client)

    response = client.post(
        "/targets",
        data={"name": "Example", "url": "https://example.com"},
        follow_redirects=False,
    )

    assert response.status_code == 403


def test_report_preview_requires_auth_and_renders_text_report(workspace_temp_dir) -> None:
    config = _web_config(workspace_temp_dir)
    app = create_app(config)
    client = TestClient(app, follow_redirects=False)
    report_path = workspace_temp_dir / "report.json"
    report_path.write_text('{"ok": true}', encoding="utf-8")
    with app.state.session_factory() as session:
        job = Job(job_type="scan", target_url="https://example.com", status="succeeded", params_json="{}")
        session.add(job)
        session.flush()
        report = record_report(session, job_id=job.id, report_type="scan", json_path=report_path)
        report_id = report.id
        session.commit()

    assert client.get(f"/reports/{report_id}/preview/json").status_code == 303
    _login(client)
    response = client.get(f"/reports/{report_id}/preview/json")

    assert response.status_code == 200
    assert "{&#34;ok&#34;: true}" in response.text
