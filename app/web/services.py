from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.web.config import WebConfig
from app.web.models import AuditEventRecord, Job, Report, Target, User
from app.web.security import hash_password, verify_password

READ_ONLY_JOB_TYPES = {
    "scan",
    "crawl",
    "vuln_scan",
    "secrets",
    "baseline",
    "compare",
    "bundle",
    "doctor",
    "server_check",
    "incident",
    "integrity",
    "watch",
    "drift",
    "timeline",
    "audit",
}
WRITE_ONLY_SECRET_KEYS = {"password", "password_env", "browser_password", "smtp_password", "secret", "token"}


def bootstrap_admin(session: Session, config: WebConfig) -> User | None:
    if not config.admin_email or not config.admin_password:
        return None
    existing = session.scalar(select(User).where(User.email == config.admin_email.lower()))
    if existing is not None:
        return existing
    admin = User(
        email=config.admin_email.lower(),
        password_hash=hash_password(config.admin_password),
        role="admin",
        is_active=True,
    )
    session.add(admin)
    session.flush()
    return admin


def authenticate_user(session: Session, email: str, password: str) -> User | None:
    user = session.scalar(select(User).where(User.email == email.lower()))
    if user is None or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    user.last_login_at = datetime.now(UTC)
    session.flush()
    return user


def create_user(session: Session, *, email: str, password: str, role: str) -> User:
    user = User(email=email.lower(), password_hash=hash_password(password), role=role, is_active=True)
    session.add(user)
    session.flush()
    return user


def create_target(session: Session, *, name: str, url: str, created_by_user_id: int | None) -> Target:
    target = Target(name=name, url=url, created_by_user_id=created_by_user_id)
    session.add(target)
    session.flush()
    return target


def sanitize_params(params: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in params.items():
        normalized = key.lower()
        if any(secret_key in normalized for secret_key in WRITE_ONLY_SECRET_KEYS):
            clean[key] = "[redacted]" if value else value
        else:
            clean[key] = value
    return clean


def create_job(
    session: Session,
    *,
    job_type: str,
    created_by_user_id: int | None,
    target_id: int | None,
    target_url: str | None,
    params: dict[str, Any],
) -> Job:
    if job_type not in READ_ONLY_JOB_TYPES:
        raise ValueError(f"Unsupported read-only web job type: {job_type}")
    job = Job(
        job_type=job_type,
        created_by_user_id=created_by_user_id,
        target_id=target_id,
        target_url=target_url,
        params_json=json.dumps(sanitize_params(params), ensure_ascii=True),
    )
    session.add(job)
    session.flush()
    return job


def record_report(
    session: Session,
    *,
    job_id: int,
    report_type: str,
    json_path: Path | None = None,
    markdown_path: Path | None = None,
    html_path: Path | None = None,
    summary: dict[str, Any] | None = None,
) -> Report:
    report = Report(
        job_id=job_id,
        report_type=report_type,
        json_path=str(json_path) if json_path is not None else None,
        markdown_path=str(markdown_path) if markdown_path is not None else None,
        html_path=str(html_path) if html_path is not None else None,
        summary_json=json.dumps(summary or {}, ensure_ascii=True),
    )
    session.add(report)
    session.flush()
    return report


def record_audit_event(
    session: Session,
    *,
    user_id: int | None,
    job_id: int | None,
    action: str,
    target: str,
    result: str,
    details: dict[str, Any] | None = None,
) -> AuditEventRecord:
    event = AuditEventRecord(
        user_id=user_id,
        job_id=job_id,
        action=action,
        target=target,
        result=result,
        details_json=json.dumps(details or {}, ensure_ascii=True),
    )
    session.add(event)
    session.flush()
    return event
