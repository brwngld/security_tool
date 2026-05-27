from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Iterable

from app.context import resolve_application_context
from app.models import IncidentFinding, IncidentReport


_IP_RE = re.compile(r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b")
_REQUEST_RE = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<path>[^"]+?)\s+HTTP/[0-9.]+"')
_STATUS_RE = re.compile(r'"\s*(?P<status>\d{3})\s+')
_APACHE_CLIENT_RE = re.compile(r"\[client\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b", re.IGNORECASE)

_AUTH_LOG_MARKERS = {
    "failed password": "failed password",
    "invalid user": "invalid user",
    "authentication failure": "authentication failure",
    "pam_unix": "pam_unix",
    "sudo:": "sudo",
    "session opened for user": "session opened",
    "session closed for user": "session closed",
    "accepted publickey": "accepted publickey",
}

_APACHE_ERROR_MARKERS = {
    "client denied by server configuration": "client denied",
    "file does not exist": "missing file",
    "script not found or unable to stat": "missing script",
    "mod_security": "mod_security",
    "request exceeded the limit": "request limit",
    "ah0": "apache ah",
}

_LOG_FAMILY_NAMES = {
    "auth": "auth",
    "apache-access": "apache-access",
    "apache-error": "apache-error",
    "nginx-access": "nginx-access",
    "systemd": "systemd",
    "application": "application",
    "unknown": "unknown",
}

_SCANNER_MARKERS = {
    "sqlmap": "sqlmap",
    "nikto": "nikto",
    "nmap": "nmap",
    "masscan": "masscan",
    "zgrab": "zgrab",
    "curl": "curl",
    "wget": "wget",
    "python-requests": "python-requests",
    "libwww-perl": "libwww-perl",
    "go-http-client": "go-http-client",
}

_PROBE_MARKERS = {
    "/.env",
    "/.git",
    "/.git/config",
    "/wp-login.php",
    "/wp-admin",
    "/phpmyadmin",
    "/server-status",
    "/admin",
    "/backup",
    "/backup.zip",
    "/dump.sql",
    "/cgi-bin",
}

_ERROR_MARKERS = {
    "traceback",
    "exception",
    "stack trace",
    "permission denied",
    "unauthorized",
    "forbidden",
    "failed login",
    "invalid credentials",
    "csrf",
    "token mismatch",
    "database error",
    "sql error",
}

_INJECTION_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"union\s+select",
        r"or\s+1=1",
        r"and\s+1=1",
        r"\.\./",
        r"%2e%2e",
        r";\s*(?:curl|wget|id|cat|bash|sh)",
        r"\|\s*(?:curl|wget|id|cat|bash|sh)",
        r"\$\(",
        r"\{\{",
        r"<script",
        r"/etc/passwd",
    )
]


@dataclass
class _IpActivity:
    requests: int = 0
    scanner_hits: int = 0
    probe_hits: int = 0
    injection_hits: int = 0
    auth_hits: int = 0
    error_hits: int = 0
    status_401_403_hits: int = 0
    log_families: set[str] = field(default_factory=set)
    suspicious_paths: set[str] = field(default_factory=set)
    user_agents: set[str] = field(default_factory=set)
    source_files: set[str] = field(default_factory=set)

    def score(self) -> int:
        return (
            self.scanner_hits * 3
            + self.probe_hits * 2
            + self.injection_hits * 4
            + self.auth_hits * 3
            + self.error_hits
            + self.status_401_403_hits
        )


def _collect_log_files(sources: Iterable[Path]) -> list[Path]:
    collected: list[Path] = []
    seen: set[Path] = set()
    for source in sources:
        source_path = Path(source)
        if source_path.is_dir():
            for candidate in sorted(source_path.rglob("*")):
                if candidate.is_file() and candidate not in seen:
                    seen.add(candidate)
                    collected.append(candidate)
            continue
        if source_path.is_file() and source_path not in seen:
            seen.add(source_path)
            collected.append(source_path)
    return collected


def default_incident_sources(root: Path, context_target: str | None = None) -> list[Path]:
    candidates = [
        root / "logs" / "access.log",
        root / "logs" / "error.log",
        root / "logs" / "app.log",
        root / "logs" / "nginx" / "access.log",
        root / "logs" / "nginx" / "error.log",
        root / "logs" / "gunicorn.log",
        root / "logs" / "uwsgi.log",
        Path("/var/log/nginx/access.log"),
        Path("/var/log/nginx/error.log"),
        Path("/var/log/apache2/access.log"),
        Path("/var/log/apache2/error.log"),
        Path("/var/log/auth.log"),
        Path("/var/log/syslog"),
        Path("/var/log/messages"),
    ]
    if context_target is not None:
        candidates.insert(0, root / "logs")
    return _collect_log_files(candidates)


def _extract_request_path(line: str) -> str | None:
    match = _REQUEST_RE.search(line)
    if not match:
        return None
    raw_path = match.group("path").strip()
    return raw_path.split("?", 1)[0]


def _extract_status(line: str) -> int | None:
    match = _STATUS_RE.search(line)
    if not match:
        return None
    try:
        return int(match.group("status"))
    except ValueError:
        return None


def _extract_user_agent(line: str) -> str:
    parts = line.split('"')
    if len(parts) >= 6:
        return parts[5].strip()
    return ""


def _extract_client_ip(line: str) -> str | None:
    match = _IP_RE.search(line)
    if not match:
        match = _APACHE_CLIENT_RE.search(line)
        if match:
            return match.group("ip")
        return None
    return match.group("ip")


def _identify_log_family(source_file: Path, line: str) -> str:
    lower_line = line.lower()
    lower_name = source_file.name.lower()
    full_name = source_file.as_posix().lower()

    if any(marker in lower_line for marker in _AUTH_LOG_MARKERS):
        return _LOG_FAMILY_NAMES["auth"]
    if "sshd[" in lower_line or "sudo:" in lower_line or "pam_unix" in lower_line:
        return _LOG_FAMILY_NAMES["auth"]
    if "apache" in lower_name or "httpd" in lower_name or "apache" in full_name or "httpd" in full_name:
        if "[client" in lower_line or any(marker in lower_line for marker in _APACHE_ERROR_MARKERS):
            return _LOG_FAMILY_NAMES["apache-error"]
        return _LOG_FAMILY_NAMES["apache-access"]
    if "nginx" in lower_name or "nginx" in full_name:
        return _LOG_FAMILY_NAMES["nginx-access"]
    if "systemd" in lower_line or "journal" in lower_name or "systemd" in lower_name:
        return _LOG_FAMILY_NAMES["systemd"]
    if "gunicorn" in lower_name or "uwsgi" in lower_name or "app.log" in lower_name:
        return _LOG_FAMILY_NAMES["application"]
    if _REQUEST_RE.search(line):
        return _LOG_FAMILY_NAMES["nginx-access"]
    return _LOG_FAMILY_NAMES["unknown"]


def _matches_injection(line: str, path: str | None) -> bool:
    haystack = f"{line} {path or ''}".lower()
    return any(pattern.search(haystack) is not None for pattern in _INJECTION_PATTERNS)


def _classify_line(
    source_file: Path,
    line: str,
    request_path: str | None,
    status: int | None,
    user_agent: str,
) -> tuple[set[str], set[str], str]:
    markers: set[str] = set()
    reasons: set[str] = set()
    lower_line = line.lower()
    lower_path = (request_path or "").lower()
    lower_ua = user_agent.lower()
    family = _identify_log_family(source_file, line)

    scanner_hits = [name for marker, name in _SCANNER_MARKERS.items() if marker in lower_line or marker in lower_ua]
    if scanner_hits:
        markers.add("scanner")
        reasons.update(scanner_hits)

    probe_hits = [marker for marker in _PROBE_MARKERS if marker in lower_line or marker in lower_path]
    if probe_hits:
        markers.add("probe")
        reasons.update(probe_hits)

    if _matches_injection(line, request_path):
        markers.add("injection")
        reasons.add("injection-style payload")

    if status in {401, 403} and any(keyword in lower_path for keyword in ("login", "auth", "signin", "session", "token")):
        markers.add("auth")
        reasons.add(f"status {status}")

    if any(marker in lower_line for marker in _AUTH_LOG_MARKERS):
        markers.add("auth")
        reasons.update({reason for marker, reason in _AUTH_LOG_MARKERS.items() if marker in lower_line})
        if "failed password" in lower_line or "invalid user" in lower_line:
            markers.add("bruteforce")

    if any(marker in lower_line for marker in _APACHE_ERROR_MARKERS):
        markers.add("apache")
        markers.add("probe")
        markers.add("error")
        reasons.update({reason for marker, reason in _APACHE_ERROR_MARKERS.items() if marker in lower_line})

    if any(marker in lower_line for marker in _ERROR_MARKERS):
        markers.add("error")
        reasons.add("error signal")

    if status in {404, 429} and (probe_hits or scanner_hits):
        markers.add("probe")
        reasons.add(f"status {status}")

    return markers, reasons, family


def _build_incident_finding(
    finding_id: str,
    source_file: str,
    log_family: str,
    title: str,
    category: str,
    severity: str,
    confidence: str,
    description: str,
    evidence: dict[str, str | int | bool | None],
    affected_ips: list[str],
    recommended_action: str,
    block_action: str | None,
    count: int,
) -> IncidentFinding:
    return IncidentFinding(
        id=finding_id,
        source_file=source_file,
        log_family=log_family,
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        description=description,
        evidence=evidence,
        affected_ips=affected_ips,
        recommended_action=recommended_action,
        block_action=block_action,
        count=count,
    )


def analyze_incident_sources(
    sources: Iterable[Path],
    *,
    root: Path | None = None,
    url: str | None = None,
    block_threshold: int = 5,
    env_file: Path | None = None,
    nginx_config: Path | None = None,
) -> IncidentReport:
    root_path = Path.cwd() if root is None else Path(root)
    source_files = _collect_log_files(sources)
    context = resolve_application_context(url, root_path, env_file, nginx_config, require_target=False)
    if not source_files:
        return IncidentReport(
            context=context,
            target=str(context.target.value) if context.target is not None else url,
            source_files=[],
            notes=["No readable log files were found."],
        )

    activities: dict[str, _IpActivity] = defaultdict(_IpActivity)
    error_hits = 0
    total_lines = 0
    scan_notes: list[str] = []

    for source_file in source_files:
        try:
            text = source_file.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            scan_notes.append(f"Skipped {source_file}: {exc.__class__.__name__}")
            continue

        for line in text.splitlines():
            total_lines += 1
            ip = _extract_client_ip(line)
            request_path = _extract_request_path(line)
            status = _extract_status(line)
            user_agent = _extract_user_agent(line)
            markers, reasons, family = _classify_line(source_file, line, request_path, status, user_agent)

            if not markers:
                continue

            if ip is not None:
                activity = activities[ip]
                activity.requests += 1
                activity.source_files.add(str(source_file))
                activity.log_families.add(family)
                if request_path:
                    activity.suspicious_paths.add(request_path)
                if user_agent:
                    activity.user_agents.add(user_agent)
                if "scanner" in markers:
                    activity.scanner_hits += 1
                if "probe" in markers:
                    activity.probe_hits += 1
                if "injection" in markers:
                    activity.injection_hits += 1
                if "auth" in markers:
                    activity.auth_hits += 1
                if "error" in markers:
                    activity.error_hits += 1
                    error_hits += 1
                if status in {401, 403}:
                    activity.status_401_403_hits += 1
            else:
                error_hits += 1
                _ = reasons

    findings: list[IncidentFinding] = []
    suspect_ips: list[str] = []
    blocked_ips: list[str] = []

    for ip, activity in sorted(activities.items(), key=lambda item: item[1].score(), reverse=True):
        score = activity.score()
        if score == 0:
            continue

        suspect_ips.append(ip)
        sources_list = sorted(activity.source_files)
        evidence = {
            "requests": activity.requests,
            "scanner_hits": activity.scanner_hits,
            "probe_hits": activity.probe_hits,
            "injection_hits": activity.injection_hits,
            "auth_hits": activity.auth_hits,
            "error_hits": activity.error_hits,
            "score": score,
            "source_files": ", ".join(sources_list) if sources_list else None,
            "log_families": ", ".join(sorted(activity.log_families)) if activity.log_families else None,
        }
        if activity.user_agents:
            evidence["user_agents"] = ", ".join(sorted(activity.user_agents))
        if activity.suspicious_paths:
            evidence["paths"] = ", ".join(sorted(activity.suspicious_paths)[:4])

        if activity.scanner_hits or activity.probe_hits:
            severity = "high" if score >= block_threshold else "medium"
            findings.append(
                _build_incident_finding(
                    finding_id=f"incident-scan-{ip}",
                    source_file=sources_list[0] if sources_list else "-",
                    log_family=", ".join(sorted(activity.log_families)) if activity.log_families else "unknown",
                    title=f"Suspicious probing from {ip}",
                    category="scanner",
                    severity=severity,
                    confidence="high" if score >= block_threshold else "medium",
                    description="The log trail looks like automated probing or reconnaissance.",
                    evidence=evidence,
                    affected_ips=[ip],
                    recommended_action="Add the IP to the Nginx denylist and inspect the upstream logs.",
                    block_action=f"deny {ip};",
                    count=activity.requests,
                )
            )

        if activity.injection_hits:
            findings.append(
                _build_incident_finding(
                    finding_id=f"incident-injection-{ip}",
                    source_file=sources_list[0] if sources_list else "-",
                    log_family=", ".join(sorted(activity.log_families)) if activity.log_families else "unknown",
                    title=f"Injection-style payloads from {ip}",
                    category="injection",
                    severity="high",
                    confidence="high",
                    description="The logs contain payloads that look like SQL injection or command injection probes.",
                    evidence=evidence,
                    affected_ips=[ip],
                    recommended_action="Block the source IP, then inspect app input validation and WAF rules.",
                    block_action=f"deny {ip};",
                    count=activity.injection_hits,
                )
            )

        if activity.auth_hits:
            findings.append(
                _build_incident_finding(
                    finding_id=f"incident-auth-{ip}",
                    source_file=sources_list[0] if sources_list else "-",
                    log_family=", ".join(sorted(activity.log_families)) if activity.log_families else "unknown",
                    title=f"Repeated auth failures from {ip}",
                    category="auth",
                    severity="medium" if score < block_threshold else "high",
                    confidence="medium",
                    description="The logs show repeated authentication failures against a protected endpoint.",
                    evidence=evidence,
                    affected_ips=[ip],
                    recommended_action="Consider a temporary denylist entry and check for brute-force attempts.",
                    block_action=f"deny {ip};",
                    count=activity.auth_hits,
                )
            )

        if score >= block_threshold:
            blocked_ips.append(ip)

    if error_hits and not findings:
        findings.append(
            _build_incident_finding(
                finding_id="incident-error-burst",
                source_file=source_files[0].as_posix(),
                log_family="unknown",
                title="Application error burst",
                category="error",
                severity="medium",
                confidence="low",
                description="The logs contain repeated error signals even though no specific attacker IP was isolated.",
                evidence={"error_hits": error_hits, "source_files": ", ".join(str(path) for path in source_files[:3])},
                affected_ips=[],
                recommended_action="Review the error log around the time of the burst and tighten sensitive endpoints.",
                block_action=None,
                count=error_hits,
            )
        )

    notes = list(scan_notes)
    if blocked_ips:
        notes.append(f"Auto-block threshold reached for: {', '.join(blocked_ips)}")
    elif suspect_ips:
        notes.append("Suspicious traffic was detected, but it did not cross the auto-block threshold.")
    else:
        notes.append("No active attack indicators were found in the supplied logs.")

    return IncidentReport(
        context=context,
        target=str(context.target.value) if context.target is not None else url,
        source_files=[str(path) for path in source_files],
        total_lines=total_lines,
        findings=findings,
        suspect_ips=suspect_ips,
        blocked_ips=blocked_ips,
        notes=notes,
        containment_applied=False,
    )
