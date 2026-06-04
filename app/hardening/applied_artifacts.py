from __future__ import annotations

from pathlib import Path

from app.hardening.backup import create_backup
from app.models import Finding, FixPlan


def applied_artifact_path(finding: Finding, output_dir: str | Path = "outputs/generated") -> Path:
    artifact_dir = Path(output_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return artifact_dir / f"{finding.id}.conf"


def _legacy_applied_artifact_path(finding: Finding) -> Path:
    return Path("outputs/applied") / f"{finding.id}.conf"


def create_applied_artifact_backup(finding: Finding, output_dir: str | Path = "outputs/generated") -> Path:
    artifact_path = applied_artifact_path(finding, output_dir)
    legacy_path = _legacy_applied_artifact_path(finding)
    if not artifact_path.exists() and legacy_path.exists():
        artifact_path = legacy_path
    backup_dir = artifact_path.parent.parent / "backups"
    return create_backup(artifact_path, backup_dir)


def build_applied_artifact_text(finding: Finding, plan: FixPlan) -> str:
    header_lines = [
        "# PsyberShield reversible hardening artifact",
        "",
        f"# Finding: {finding.title}",
        f"# Category: {finding.category}",
        f"# Target: {finding.target_url}",
        "",
        "# This file is local to the PsyberShield workspace.",
        "# It is safe to review, edit, or delete after the change is copied elsewhere.",
        "",
    ]

    category_blocks = {
        "headers": [
            "# Hide the banner and add the common security headers at the reverse proxy.",
            "# Keep this in the web server layer so the app does not need code changes.",
            'add_header X-Frame-Options "SAMEORIGIN" always;',
            'add_header X-Content-Type-Options "nosniff" always;',
            'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            'add_header Content-Security-Policy "default-src \'self\'" always;',
        ],
        "cookies": [
            "# Set Secure and HttpOnly where the cookie is issued.",
            "# Keep SameSite set to a strict or lax value that matches the app flow.",
            "# Example intent: Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax",
            "# If the app sets cookies in code, update the cookie builder instead of the proxy.",
        ],
        "server_info": [
            "# Hide the server banner in the web server config.",
            "# This keeps package and framework versions out of the response headers.",
            "server_tokens off;",
            '# Hide upstream app details too if the reverse proxy exposes X-Powered-By.',
        ],
        "exposed_files": [
            "# Block direct access to sensitive files at the web root.",
            "# This keeps .env, backups, and repository metadata off the public path.",
            r"location ~ /\.(env|git|sql|bak)$ {",
            "    deny all;",
            "}",
        ],
        "tls": [
            "# Force HTTPS at the edge and keep cleartext requests moving to the secure endpoint.",
            "if ($scheme = http) {",
            "    return 301 https://$host$request_uri;",
            "}",
            'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
        ],
    }

    body_lines = category_blocks.get(
        finding.category,
        [
            "# Keep this as a small reversible placeholder.",
            "# PsyberShield did not match a category-specific patch here, so this stays generic on purpose.",
            f"# Suggested next step: {plan.expected_impact}",
            f"# Rollback: {plan.rollback_command or 'Restore the previous version of this file.'}",
        ],
    )

    footer_lines = [
        "",
        f"# Suggested next step: {plan.expected_impact}",
        f"# Rollback: {plan.rollback_command or 'Restore the previous version of this file.'}",
    ]
    return "\n".join(header_lines + body_lines + footer_lines) + "\n"


def write_applied_artifact(
    finding: Finding,
    plan: FixPlan,
    output_dir: str | Path = "outputs/generated",
) -> Path:
    artifact_path = applied_artifact_path(finding, output_dir)
    artifact_path.write_text(build_applied_artifact_text(finding, plan), encoding="utf-8")
    return artifact_path

