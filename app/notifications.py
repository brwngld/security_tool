from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage
import json
import os
import smtplib
from pathlib import Path
from typing import Iterable
from urllib.error import URLError
from urllib.request import Request, urlopen

from app.environment import lookup_env_value
from app.models import IncidentReport, IntegrityReport, TimelineReport


@dataclass(frozen=True)
class NotificationResult:
    channel: str
    target: str
    status: str
    detail: str


def _shorten(text: str, limit: int = 200) -> str:
    cleaned = " ".join(text.split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: max(0, limit - 3)].rstrip() + "..."


def _incident_summary(report: IncidentReport) -> tuple[str, str]:
    subject = f"PsyberShield incident: {len(report.blocked_ips)} blocked, {len(report.findings)} findings"
    lines = [
        f"Target: {report.target or 'not resolved'}",
        f"Sources: {len(report.source_files)}",
        f"Findings: {len(report.findings)}",
        f"Blocked IPs: {', '.join(report.blocked_ips) if report.blocked_ips else '-'}",
    ]
    if report.findings:
        lines.append("Top findings:")
        for finding in report.findings[:3]:
            family = finding.log_family or "unknown"
            lines.append(f"- [{finding.severity}] {finding.title} ({family})")
    if report.notes:
        lines.append(f"Notes: {'; '.join(report.notes[:3])}")
    return subject, "\n".join(lines)


def _integrity_summary(report: IntegrityReport) -> tuple[str, str]:
    changed = len([item for item in report.files if item.status == "changed"])
    missing = len([item for item in report.files if item.status == "missing"])
    new = len([item for item in report.files if item.status == "new"])
    subject = f"PsyberShield integrity: {changed} changed, {missing} missing, {new} new"
    lines = [
        f"Root: {report.root}",
        f"Baseline: {report.baseline_path or 'not supplied'}",
        f"Files tracked: {len(report.files)}",
        f"Findings: {len(report.findings)}",
    ]
    if report.findings:
        lines.append("Top findings:")
        for finding in report.findings[:3]:
            lines.append(f"- [{finding.severity}] {finding.title} ({finding.kind})")
    if report.notes:
        lines.append(f"Notes: {'; '.join(report.notes[:3])}")
    return subject, "\n".join(lines)


def _timeline_summary(report: TimelineReport) -> tuple[str, str]:
    subject = f"PsyberShield timeline: {len(report.events)} event(s)"
    lines = [
        f"Incident report: {report.incident_report or '-'}",
        f"Audit log: {report.audit_log or '-'}",
        f"Events: {len(report.events)}",
    ]
    if report.events:
        lines.append("First events:")
        for event in report.events[:4]:
            lines.append(f"- {event.timestamp or '-'} [{event.kind}] {event.title}")
    if report.notes:
        lines.append(f"Notes: {'; '.join(report.notes[:3])}")
    return subject, "\n".join(lines)


def build_report_notification(report: IncidentReport | IntegrityReport | TimelineReport) -> tuple[str, str]:
    if isinstance(report, IncidentReport):
        return _incident_summary(report)
    if isinstance(report, IntegrityReport):
        return _integrity_summary(report)
    return _timeline_summary(report)


def _render_webhook_payload(message: str, provider: str) -> bytes:
    if provider == "discord":
        payload = {"content": message}
    else:
        payload = {"text": message}
    return json.dumps(payload, ensure_ascii=True).encode("utf-8")


def send_webhook_notification(
    url: str,
    message: str,
    *,
    provider: str = "webhook",
    timeout: float = 10.0,
) -> NotificationResult:
    payload = _render_webhook_payload(message, provider)
    request = Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "PsyberShield/notification"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - deliberate outbound notification hook
            response.read()
        return NotificationResult(channel=provider, target=url, status="sent", detail="Webhook delivered")
    except (URLError, OSError) as exc:
        reason = exc.reason if isinstance(exc, URLError) and hasattr(exc, "reason") else exc
        return NotificationResult(channel=provider, target=url, status="failed", detail=str(reason))


def send_email_notification(
    *,
    smtp_host: str,
    smtp_port: int,
    sender: str,
    recipients: Iterable[str],
    subject: str,
    body: str,
    smtp_username: str | None = None,
    smtp_password: str | None = None,
    use_starttls: bool = True,
    timeout: float = 10.0,
) -> NotificationResult:
    recipient_list = [recipient.strip() for recipient in recipients if recipient.strip()]
    if not recipient_list:
        return NotificationResult(channel="email", target=smtp_host, status="skipped", detail="No email recipients were supplied")

    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(recipient_list)
    message["Subject"] = subject
    message.set_content(body)

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=timeout) as client:
            if use_starttls:
                client.starttls()
            if smtp_username:
                client.login(smtp_username, smtp_password or "")
            client.send_message(message)
        return NotificationResult(channel="email", target=", ".join(recipient_list), status="sent", detail="Email delivered")
    except (OSError, smtplib.SMTPException) as exc:
        return NotificationResult(channel="email", target=", ".join(recipient_list), status="failed", detail=exc.__class__.__name__)


def resolve_smtp_password(password_env: str | None, root: Path | None = None, env_file: Path | None = None) -> str | None:
    key = password_env or "SMTP_PASSWORD"
    found = lookup_env_value(key, root, env_file)
    if found is not None:
        return found.value
    return os.environ.get(key)


def send_report_notifications(
    report: IncidentReport | IntegrityReport | TimelineReport,
    *,
    webhook_urls: Iterable[str] | None = None,
    slack_webhook_urls: Iterable[str] | None = None,
    discord_webhook_urls: Iterable[str] | None = None,
    email_recipients: Iterable[str] | None = None,
    email_sender: str | None = None,
    smtp_host: str | None = None,
    smtp_port: int = 587,
    smtp_username: str | None = None,
    smtp_password_env: str | None = None,
    root: Path | None = None,
    env_file: Path | None = None,
    timeout: float = 10.0,
    use_starttls: bool = True,
) -> list[NotificationResult]:
    subject, body = build_report_notification(report)
    results: list[NotificationResult] = []

    for url in webhook_urls or []:
        results.append(send_webhook_notification(url, body, provider="webhook", timeout=timeout))
    for url in slack_webhook_urls or []:
        results.append(send_webhook_notification(url, body, provider="slack", timeout=timeout))
    for url in discord_webhook_urls or []:
        results.append(send_webhook_notification(url, body, provider="discord", timeout=timeout))

    recipients = [recipient for recipient in (email_recipients or []) if recipient.strip()]
    if recipients:
        smtp_host_value = smtp_host or "localhost"
        sender_value = email_sender or "PsyberShield@localhost"
        smtp_password = resolve_smtp_password(smtp_password_env, root=root, env_file=env_file)
        results.append(
            send_email_notification(
                smtp_host=smtp_host_value,
                smtp_port=smtp_port,
                sender=sender_value,
                recipients=recipients,
                subject=subject,
                body=body,
                smtp_username=smtp_username,
                smtp_password=smtp_password,
                use_starttls=use_starttls,
                timeout=timeout,
            )
        )

    return results


def summarize_notification_results(results: list[NotificationResult]) -> str:
    if not results:
        return "No notification targets were supplied."
    sent = len([result for result in results if result.status == "sent"])
    failed = len([result for result in results if result.status == "failed"])
    skipped = len([result for result in results if result.status == "skipped"])
    return f"Notifications: {sent} sent, {failed} failed, {skipped} skipped"

