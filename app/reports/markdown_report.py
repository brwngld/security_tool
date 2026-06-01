from __future__ import annotations

from pathlib import Path

from app.models import ScanResult


def _append_context_block(lines: list[str], result: ScanResult) -> None:
    if result.context is None:
        return

    discovery = result.context.discovery
    lines.extend(
        [
            "",
            "## Application Context",
            "",
            f"- Root: {result.context.root}",
            f"- Target: {result.context.target.value if result.context.target else 'not resolved'}",
            f"- Target source: {result.context.target.source if result.context.target else 'not resolved'}",
            f"- Discovered app: {discovery.app_name or '-'}",
            f"- Public URL: {discovery.public_url or '-'}",
            f"- Local URL: {discovery.local_url or '-'}",
            f"- Env file: {discovery.env_file or '-'}",
            f"- Env source: {discovery.env_source or '-'}",
            f"- Nginx config: {discovery.nginx_config or '-'}",
            f"- Systemd service: {discovery.systemd_service or '-'}",
        ]
    )
    if discovery.notes:
        lines.append(f"- Notes: {'; '.join(discovery.notes)}")


def _append_crawl_block(lines: list[str], result: ScanResult) -> None:
    if len(result.scanned_urls) <= 1:
        return

    lines.extend(["", "## Scanned URLs", ""])
    for index, url in enumerate(result.scanned_urls, start=1):
        lines.append(f"- {index}. {url}")
    if result.crawl_seed_sources:
        lines.append(f"- Seed sources: {', '.join(result.crawl_seed_sources)}")


def _append_findings_block(lines: list[str], result: ScanResult) -> None:
    if not result.findings:
        return

    lines.extend(["", "## Findings", ""])
    for finding in result.findings:
        lines.append(f"- [{finding.severity}] {finding.title}")
        lines.append(f"  - Category: {finding.category}")
        lines.append(f"  - Confidence: {finding.confidence}")
        lines.append(f"  - First move: {finding.expected_impact or '-'}")
        if getattr(finding, "affected_urls", []):
            lines.append("  - Affected URLs:")
            for index, url in enumerate(finding.affected_urls, start=1):
                lines.append(f"    - {index}. {url}")


def write_markdown_report(result: ScanResult, output_path: str | Path, include_fix_plans: bool = False) -> Path:
    path = Path(output_path)
    lines = [
        "# PsyberShield Report",
        "",
        f"Target: {result.target.url}",
        f"Findings: {len(result.findings)}",
    ]
    _append_context_block(lines, result)
    _append_crawl_block(lines, result)
    _append_findings_block(lines, result)
    if result.tls_summary:
        lines.extend(
            [
                "",
                "## TLS",
                "",
                f"Status: {result.tls_summary.get('status', 'unknown')}",
            ]
        )
        if result.tls_summary.get("expires_on"):
            lines.append(f"Expires on: {result.tls_summary['expires_on']}")
    if include_fix_plans and result.fix_plans:
        lines.extend(["", "## Proposed Fixes", ""])
        for plan in result.fix_plans:
            lines.append(f"- {plan.expected_impact}")
            if plan.rollback_command:
                lines.append(f"  - Rollback: {plan.rollback_command}")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
