from email.message import EmailMessage

from app.models import IncidentFinding, IncidentReport
from app.notifications import (
    NotificationResult,
    send_email_notification,
    send_report_notifications,
    send_webhook_notification,
)


def test_send_webhook_notification_posts_payload(monkeypatch) -> None:
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b"ok"

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("app.notifications.urlopen", fake_urlopen)

    result = send_webhook_notification("https://example.com/webhook", "hello world", provider="discord", timeout=4.5)

    assert result.status == "sent"
    assert captured["timeout"] == 4.5
    assert captured["request"].full_url == "https://example.com/webhook"
    assert captured["request"].data == b'{"content": "hello world"}'


def test_send_email_notification_sends_message(monkeypatch) -> None:
    captured = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            captured["host"] = host
            captured["port"] = port
            captured["timeout"] = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def starttls(self):
            captured["starttls"] = True

        def login(self, username, password):
            captured["login"] = (username, password)

        def send_message(self, message: EmailMessage):
            captured["message"] = message

    monkeypatch.setattr("app.notifications.smtplib.SMTP", FakeSMTP)

    result = send_email_notification(
        smtp_host="smtp.example.com",
        smtp_port=587,
        sender="turan@example.com",
        recipients=["ops@example.com"],
        subject="Incident summary",
        body="Something happened",
        smtp_username="turan",
        smtp_password="secret",
    )

    assert result.status == "sent"
    assert captured["host"] == "smtp.example.com"
    assert captured["port"] == 587
    assert captured["starttls"] is True
    assert captured["login"] == ("turan", "secret")
    assert captured["message"]["Subject"] == "Incident summary"
    assert captured["message"]["From"] == "turan@example.com"
    assert "Something happened" in captured["message"].get_content()


def test_send_report_notifications_routes_targets(monkeypatch, workspace_temp_dir) -> None:
    report = IncidentReport(
        target="http://127.0.0.1:8000",
        source_files=[str(workspace_temp_dir / "access.log")],
        findings=[
            IncidentFinding(
                id="incident-1",
                source_file=str(workspace_temp_dir / "access.log"),
                log_family="nginx-access",
                title="Suspicious probing",
                category="scanner",
                severity="high",
                confidence="high",
                description="Probing activity.",
                evidence={},
                affected_ips=["10.0.0.1"],
                recommended_action="Block it.",
                count=3,
            )
        ],
        blocked_ips=["10.0.0.1"],
    )

    webhook_calls = []
    email_calls = []

    def fake_webhook(url, message, provider="webhook", timeout=10.0):
        webhook_calls.append((provider, url, message))
        return NotificationResult(channel=provider, target=url, status="sent", detail="ok")

    def fake_email(**kwargs):
        email_calls.append(kwargs)
        return NotificationResult(channel="email", target="ops@example.com", status="sent", detail="ok")

    monkeypatch.setattr("app.notifications.send_webhook_notification", fake_webhook)
    monkeypatch.setattr("app.notifications.send_email_notification", fake_email)
    monkeypatch.setattr("app.notifications.resolve_smtp_password", lambda *args, **kwargs: "secret")

    results = send_report_notifications(
        report,
        webhook_urls=["https://hooks.example/webhook"],
        slack_webhook_urls=["https://hooks.example/slack"],
        discord_webhook_urls=["https://hooks.example/discord"],
        email_recipients=["ops@example.com"],
        email_sender="turan@example.com",
        smtp_host="smtp.example.com",
        smtp_username="turan",
        root=workspace_temp_dir,
    )

    assert len(results) == 4
    assert [call[0] for call in webhook_calls] == ["webhook", "slack", "discord"]
    assert email_calls[0]["smtp_password"] == "secret"
    assert "Turan incident" in email_calls[0]["subject"]
    assert "Target: http://127.0.0.1:8000" in email_calls[0]["body"]
