from __future__ import annotations

from app.models import Finding
from app.http.normalizer import normalize_url


def exposed_file_candidates() -> list[str]:
    return [".env", ".git/HEAD", "backup.zip", "db.sql", "config.php.bak"]


def check_exposed_files(client, base_url: str) -> list[Finding]:
    # Try a short list of common file paths and report only the ones that answer back.
    findings: list[Finding] = []
    for candidate in exposed_file_candidates():
        url = normalize_url(base_url, candidate)
        response = client.get(url, headers={"User-Agent": "Turan/0.1.0"})
        if response.status_code != 200:
            continue

        findings.append(
            Finding(
                id=f"exposed-file-{candidate.replace('/', '-').replace('.', '-')}",
                target_url=url,
                title=f"Exposed file: {candidate}",
                description="A common sensitive file path is reachable.",
                severity="medium",
                category="exposed_files",
                evidence={
                    "path": candidate,
                    "status_code": response.status_code,
                    "content_type": response.headers.get("content-type", ""),
                    "url": url,
                },
                fix_level=0,
                risk_level="low",
                expected_impact="Report only; no system change required.",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            )
        )

    return findings
