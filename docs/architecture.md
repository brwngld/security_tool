# PsyberShield Architecture

## Purpose

PsyberShield is a Python-based security visibility and response tool for small servers and web applications.
It supports HTTP/HTTPS scanning, passive crawling, detection of common website/server misconfigurations, WAF/firewall impact notes, incident log analysis for Apache/auth/systemd-style logs, file integrity monitoring, baseline drift detection, secret exposure checks, report bundling, report notifications, and safe defensive fixes where possible.

The preferred CLI command is `pshield`. `psybershield` and `turan` remain compatibility aliases during the transition.

For a command-by-command usage guide, see [docs/PsyberShield-user-guide.md](docs/PsyberShield-user-guide.md) and the matching PDF at [PsyberShield-user-guide.pdf](PsyberShield-user-guide.pdf).
For a short version history, see [docs/changelog.md](docs/changelog.md).

The core flow is:

1. Observe
2. Classify
3. Recommend
4. Apply only safe reversible fixes

Anything that changes the system must pass through one gate:

```python
if finding.fix_level > allowed_fix_level:
    return "approval_required"
```

That gate lives in one place only: the remediation executor.

## Safety Principles

- Report-only findings stay read-only.
- Safe fixes must be reversible.
- Every fix plan must include rollback metadata.
- Approval is required for anything outside the allowed fix level.
- Secrets must never be printed into reports or logs.
- The executor is the only module that can perform changes.
- All other modules produce findings, plans, or recommendations only.
- The first live-edit lane is `fix --local`, and it only touches a discovered server file after backup and validation.
- The incident-response lane is `incident`, and it only writes a denylist include after analysis and confirmation.

## Working Agreement

These rules govern how we build PsyberShield together:

1. Comments should be short working notes, not tutorial prose.
2. If a comment is needed, keep it close to the code and make it practical.
3. Use comments for the lines that need a nudge, not for everything.
4. Prefer code that reads clearly without a lot of explanation.
5. Function names should read naturally to a human.
6. If a function name is unclear, ask before creating it.
7. When asking about a function name, explain its purpose first so the naming choice is easy to review.
8. Every file we create should be actively used and connected to the rest of the app.
9. Do not create placeholder functions that live in isolation or force a file to exist without purpose.
10. Prefer small, related files that each earn their place in the project.

Comment style examples:

- Good: `# normalize input`
- Good: `# check v1 headers`
- Bad: `# We normalize the input first so the rest of the scan can trust one canonical URL.`
- Bad: `# We focus on a short list of headers that are easy to verify and easy to explain to users.`

See also: [docs/working-agreement.md](docs/working-agreement.md)

## Cleaned Project Tree

```text
PsyberShield/
|-- app/
|   |-- __init__.py
|   |-- main.py                 # CLI entry point
|   |-- config.py               # scan settings, defaults, environment handling
|   |-- artifacts.py            # load saved scan reports
|   |-- comparison.py           # compare two saved scan reports
|   |-- doctor.py               # local machine and environment checks
|   |-- incident.py             # suspicious activity analysis and containment planning
|   |-- scanner.py              # coordinates scan flow
|   |-- models.py               # Target, Finding, FixPlan, ScanResult, ComparisonResult
|   |-- policy.py               # fix levels, approval rules, redaction rules
|   |-- approvals.py            # admin approval flow for Level 2 actions
|   |-- audit.py                # append-only audit trail for scans and fixes
|   |-- redaction.py            # secret masking for logs and reports
|   |
|   |-- http/
|   |   |-- __init__.py
|   |   |-- client.py           # safe HTTP client with timeouts and limits
|   |   |-- crawler.py          # passive crawler, same-scope only
|   |   `-- normalizer.py       # URL cleaning, canonicalization, scope checks
|   |
|   |-- checks/
|   |   |-- __init__.py
|   |   |-- headers.py          # security headers
|   |   |-- cookies.py          # Secure, HttpOnly, SameSite
|   |   |-- tls.py              # HTTPS/cert summary
|   |   |-- exposed_files.py    # .env, .git, backup files, index exposure
|   |   |-- server_info.py      # server banners and version disclosure
|   |   `-- waf.py              # WAF/CDN detection note and scan-confidence hints
|   |
|   |-- hardening/
|   |   |-- __init__.py
|   |   |-- recommendations.py  # fix suggestions and remediation plans
|   |   |-- executor.py         # applies only approved, reversible fixes
|   |   |-- backup.py           # creates restore points before changes
|   |   |-- incident.py         # denylist containment for suspicious activity
|   |   `-- local_fixes.py      # first real local edit lane for a discovered server file
|   |   `-- nginx.py            # safe nginx snippet templates only
|   |
|   `-- reports/
|       |-- __init__.py
|       |-- console.py          # terminal output
|       |-- incident_report.py  # incident report export
|       |-- json_report.py      # JSON export
|       |-- markdown_report.py  # Markdown export
|       `-- html_report.py      # optional later
|
|-- tests/
|   |-- test_policy.py
|   |-- test_models.py
|   |-- test_executor_gate.py
|   `-- test_redaction.py
|-- pyproject.toml
|-- README.md
|-- .env.example
`-- docs/
    `-- architecture.md
```

## Data Models

Use Pydantic models for all structured scan and remediation data.

### Target

```python
from pydantic import BaseModel, Field, HttpUrl


class Target(BaseModel):
    url: HttpUrl
    scheme: str = Field(pattern=r"^https?$")
    host: str
    port: int | None = None
    scope_root: HttpUrl | None = None
```

### Finding

```python
from pydantic import BaseModel, Field


class Finding(BaseModel):
    id: str
    target_url: str
    title: str
    description: str
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    category: str
    evidence: dict[str, str | int | bool | None]
    fix_level: int = Field(ge=0, le=3)
    risk_level: str = Field(pattern=r"^(low|medium|high|critical)$")
    requires_approval: bool = False
    backup_path: str | None = None
    rollback_command: str | None = None
    expected_impact: str = ""
    references: list[str] = Field(default_factory=list)
```

### FixPlan

```python
from pydantic import BaseModel, Field


class FixPlan(BaseModel):
    finding_id: str
    fix_level: int = Field(ge=0, le=3)
    risk_level: str = Field(pattern=r"^(low|medium|high|critical)$")
    requires_approval: bool = False
    backup_path: str | None = None
    rollback_command: str | None = None
    expected_impact: str
    status: str = Field(default="proposed", pattern=r"^(proposed|approved|applied|blocked)$")
    approved_by: str | None = None
    approved_at: str | None = None
    applied_at: str | None = None
```

### Policy

```python
from pydantic import BaseModel, Field


class Policy(BaseModel):
    allowed_fix_level: int = Field(default=0, ge=0, le=3)
    require_backup_for_level_1: bool = True
    require_approval_for_level_2: bool = True
    block_level_3: bool = True
    redact_secrets_in_reports: bool = True
    redact_secrets_in_logs: bool = True
    audit_log_path: str = "outputs/audit.log"
    max_crawl_depth: int = Field(default=2, ge=0, le=10)
    max_pages: int = Field(default=100, ge=1, le=10_000)
    timeout_seconds: float = Field(default=10.0, gt=0)
```

### ScanResult

```python
from pydantic import BaseModel


class ScanResult(BaseModel):
    target: Target
    findings: list[Finding]
    fix_plans: list[FixPlan] = Field(default_factory=list)
    scanned_urls: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    waf_signals: list[str] = Field(default_factory=list)
    scan_confidence: float = 1.0
```

### ComparisonResult

```python
from pydantic import BaseModel, Field


class ComparisonFinding(BaseModel):
    finding_id: str
    title: str
    category: str
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    change: str = Field(pattern=r"^(fixed|new|unchanged)$")


class ComparisonResult(BaseModel):
    old_report: str
    new_report: str
    fixed_findings: list[ComparisonFinding] = Field(default_factory=list)
    new_findings: list[ComparisonFinding] = Field(default_factory=list)
    unchanged_findings: list[ComparisonFinding] = Field(default_factory=list)
    old_risk_score: int = 0
    new_risk_score: int = 0
    risk_trend: str = Field(pattern=r"^(improved|worsened|unchanged)$")
```

## Fix Levels

### Level 0: Report only

- Missing headers
- Open ports or service exposure observations
- Weak cookie flags
- Outdated packages

### Level 1: Safe auto-fix

- Create report files
- Tighten app-owned file permissions
- Add non-breaking comments or config suggestions
- Rotate scanner logs
- Create backups before changes

### Level 2: Approval required

- Change Nginx configs
- Restart services
- Modify firewall rules
- Change systemd files
- Update packages
- Edit app environment variables

### Level 3: Never auto-do

- Delete files
- Disable SSH
- Kill unknown processes
- Change database contents
- Expose secrets in reports

## Executor Gate

The remediation executor is the only module that can apply a fix.
It must enforce policy before any write, restart, or system change.

```python
from __future__ import annotations

from app.models import Finding, FixPlan, Policy


def execute_fix(finding: Finding, plan: FixPlan, policy: Policy) -> str:
    # Single gate.
    if finding.fix_level > policy.allowed_fix_level:
        return "approval_required"

    if plan.fix_level > policy.allowed_fix_level:
        return "approval_required"

    if plan.fix_level >= 2 and policy.require_approval_for_level_2:
        return "approval_required"

    if plan.fix_level >= 3 and policy.block_level_3:
        return "blocked"

    if policy.require_backup_for_level_1 and plan.fix_level >= 1 and not plan.backup_path:
        return "blocked"

    if not plan.rollback_command:
        return "blocked"

    if plan.expected_impact.strip() == "":
        return "blocked"

    # Safe, reversible changes only.
    return "applied"
```

## Approval Flow

Level 2 actions must be explicit:

1. A finding produces a FixPlan.
2. Policy marks the plan as requiring approval.
3. The approver reviews backup_path, rollback_command, and expected_impact.
4. The executor applies the change only after approval is recorded.
5. The audit log stores the decision and result.

## Audit Requirements

Every scan and fix action should write an audit event with:

- timestamp
- target
- action
- actor
- policy level
- approval status
- result
- rollback metadata

Audit records should be append-only.

Default path:

- `outputs/audit.log`

## Redaction Rules

Reports and logs must redact:

- tokens
- secrets
- passwords
- private keys
- session cookies
- authorization headers

Never emit raw secrets into HTML, Markdown, JSON, or console output.

## Recommended Build Order

1. `models.py`
2. `policy.py`
3. `redaction.py`
4. `http/client.py`
5. `http/normalizer.py`
6. `checks/headers.py`
7. `checks/cookies.py`
8. `checks/tls.py`
9. `hardening/recommendations.py`
10. `hardening/executor.py`
11. `reports/json_report.py`
12. `reports/markdown_report.py`
13. `tests/test_policy.py`
14. `tests/test_executor_gate.py`

## Notes for v1

- Keep crawling passive and same-scope only.
- Do not bundle active exploitation features.
- Do not auto-edit system files or services without approval.
- Prefer small, reversible changes that are easy to audit.

## CLI Shape

Use `scan` for one-page inspection and `crawl` for multi-page in-scope walking:

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com
.\venv\Scripts\python.exe -m app.main scan https://example.com --yes
.\venv\Scripts\python.exe -m app.main crawl https://example.com --max-pages 20 --max-depth 2
.\venv\Scripts\python.exe -m app.main crawl https://example.com --include /auth/ --exclude /logout
.\venv\Scripts\python.exe -m app.main crawl https://example.com --allow-offsite
.\venv\Scripts\python.exe -m app.main crawl https://example.com --seed-robots --seed-sitemap
.\venv\Scripts\python.exe -m app.main crawl https://example.com --yes
```

Authenticated crawl roadmap:

- Phase 1, implemented: HTTP login/session reuse, JSON or form payloads, custom field names, raw cookie reuse, and an optional protected-page check after login.
- Phase 2, implemented: saved session import/export with `--session-file` and `--save-session`.
- Phase 3, implemented: browser storage-state import/export with `--storage-state` and `--save-storage-state`.
- Phase 4, implemented: browser automation support for JS-heavy login flows when HTTP/session reuse is not enough. Install the optional browser extra with `pip install .[browser]`.

Example phase-1 commands:

```powershell
.\venv\Scripts\python.exe -m app.main crawl https://example.com --login-url /auth/login --auth-method json --username alice --password-env PsyberShield_PASSWORD --auth-check-url /account
.\venv\Scripts\python.exe -m app.main crawl https://example.com --cookie "session=abc123; csrf_token=..."
```

Example phase-2 command:

```powershell
.\venv\Scripts\python.exe -m app.main crawl https://example.com --session-file sessions\autoentrytrack.json --save-session --auth-check-url /account
```

Example phase-3 commands:

```powershell
.\venv\Scripts\python.exe -m app.main crawl https://example.com --storage-state browser\storage_state.json --save-storage-state --auth-check-url /account
```

Example phase-4 command:

```powershell
.\venv\Scripts\python.exe -m app.main crawl https://example.com --auth-method browser --browser-username-selector 'input[name="identifier"]' --browser-password-selector 'input[name="password"]' --username alice --password-env PsyberShield_PASSWORD --auth-check-url /account
```

Optional report exports:

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --json-output outputs\scan.json --markdown-output outputs\scan.md
```

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --html-output outputs\scan.html
```

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --html-output
```

If you pass one of the report output flags without a path, PsyberShield creates a timestamped file under `outputs/`.

When discovery resolves a local app target, the saved JSON, Markdown, and HTML reports include an `Application Context` section with the resolved target, env source, server hints, and discovery notes.
When crawl mode visits multiple pages, the saved JSON, Markdown, and HTML reports also include a `Scanned URLs` section with the in-scope pages PsyberShield visited, and repeated findings are grouped with an `Affected URLs` list instead of being repeated on every page.
If you pass a Windows-rooted output path like `\outputs\scan.html`, PsyberShield treats it as project-relative and prints the resolved path instead of silently writing to the drive root.

Cookie findings stay cautious about CSRF-style values: when the cookie name looks like a CSRF/XSRF token, PsyberShield lowers confidence and recommends reviewing the issuance location before making a flag change.

Saved report rendering:

```powershell
.\venv\Scripts\python.exe -m app.main report outputs\scan.json --html-output outputs\scan.html
```

`report` accepts `.json`, `.md`, and `.html` files.

```powershell
.\venv\Scripts\python.exe -m app.main report outputs\scan.md
.\venv\Scripts\python.exe -m app.main report outputs\scan.html
```

Audit history:

```powershell
.\venv\Scripts\python.exe -m app.main audit --last 25
.\venv\Scripts\python.exe -m app.main audit --event scan
.\venv\Scripts\python.exe -m app.main audit --target example.com
.\venv\Scripts\python.exe -m app.main audit --audit-log outputs\audit.log
.\venv\Scripts\python.exe -m app.main audit --json-output outputs\audit.json
```

Doctor:

```powershell
.\venv\Scripts\python.exe -m app.main doctor
```

`doctor` checks the local machine, config paths, open localhost ports, safe environment status, and any resolved app target without taking a target URL.

`doctor` can also read a specific env file:

```powershell
.\venv\Scripts\python.exe -m app.main doctor --env-file /path/to/autoentrytrack/.env
```

Server check:

```powershell
.\venv\Scripts\python.exe -m app.main server-check
```

`server-check` stays focused on server-facing paths, local service signals, and config checks, then scans the resolved local target when one is found.

`server-check` can also read a specific env file and a specific Nginx config:

```powershell
.\venv\Scripts\python.exe -m app.main server-check --env-file /path/to/autoentrytrack/.env --nginx-config /etc/nginx/nginx.conf
```

Incident response:

```powershell
.\venv\Scripts\python.exe -m app.main incident --logs /var/log/nginx/access.log --apply-blocks
```

`incident` analyzes suspicious activity in log files, groups repeated attacker signals, and can write denylist, fail2ban, rate-limit, or maintenance-mode containment presets when you explicitly opt into containment.

`timeline` turns a saved incident report and optional audit log into a chronological view of log-derived findings and containment actions.

Scan fallback:

```powershell
.\venv\Scripts\python.exe -m app.main scan
```

When `scan` runs without a URL, PsyberShield looks for `APP_URL`, then `TARGET_URL`, then `BASE_URL` in `.env` or the current environment. If those are missing, it checks the server layout first and prefers the app's own `.env` when Nginx or systemd point to an app root or an explicit `EnvironmentFile`. If discovery still can't resolve a target, PsyberShield falls back to the project `.env` only as the last local fallback.

When discovery finds a local target, PsyberShield prints a short `Discovery:` line first and then the fuller context block.

`scan` can also read a specific env file:

```powershell
.\venv\Scripts\python.exe -m app.main scan --env-file /path/to/autoentrytrack/.env
```

`.env` variables:

| Variable | Used by | Meaning |
| --- | --- | --- |
| `APP_URL` | `scan` | Default target URL when you skip the argument |
| `TARGET_URL` | `scan` | Backup target URL if `APP_URL` is missing |
| `BASE_URL` | `scan` | Final fallback target URL |
| `DEBUG` | `doctor`, `server-check` | Flags a noisy local debug setup |
| `SECRET_KEY` | `doctor`, `server-check` | Checked for presence and weak values only |
| `SERVER_NAME` | `doctor`, `server-check` | Reported as present or missing |
| `DATABASE_URL` | `doctor`, `server-check` | Reported as present or missing |
| `SMTP_PASSWORD` | `doctor`, `server-check` | Reported as present or missing |

Baseline snapshots:

```powershell
.\venv\Scripts\python.exe -m app.main baseline https://example.com --output baselines\example.json
```

Friendly baseline names:

```powershell
.\venv\Scripts\python.exe -m app.main baseline https://example.com --label vps-west
```

Each baseline snapshot writes a small companion metadata file next to it, like `baselines\vps-west.json.meta.json`, so the resolved target and discovery trail stay attached to the saved baseline.

Audit log override:

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --audit-log outputs\audit.log
.\venv\Scripts\python.exe -m app.main baseline https://example.com --audit-log outputs\audit.log
```

Compare runs:

```powershell
.\venv\Scripts\python.exe -m app.main compare outputs\old.json outputs\new.json
```

When the saved reports came from `crawl`, compare also shows crawl coverage deltas, including added and removed pages.
When crawl coverage changes, compare prints a short terminal note with the added and removed page counts.

Comparison reports:

```powershell
.\venv\Scripts\python.exe -m app.main compare old.json new.json --markdown-output compare.md
.\venv\Scripts\python.exe -m app.main compare old.json new.json --html-output compare.html
```

Local demo site:

```powershell
.\venv\Scripts\python.exe -m app.main demo-site --port 8000
.\venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8000
```

Timeout control:

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --timeout 5
```

Policy file:

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --policy policy.json
```

Start from [policy.example.json](policy.example.json) and edit the values you need.

Preview fixes:

```powershell
.\venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8000 --preview-fixes
```

Interactive fixes:

```powershell
.\venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8000 --interactive
```

Interactive mode shows a numbered fix list, asks whether you want to generate artifacts or apply fixes locally, and then lets you choose all fixes or a numbered subset.
If there are more than ten fixes, PsyberShield shows a paged list and lets you move with `n` and `p`.
For `fix-local`, PsyberShield shows the target file, backup path, validation command, and rollback state before the final apply confirmation.

Apply fixes:

```powershell
.\venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8000 --generate-fixes
```

Apply mode creates the backup first, then writes the local remediation note for each allowed safe fix.
`--apply-fixes` is kept as a legacy alias for `--generate-fixes` so older muscle memory still works.
Each remediation note keeps the backup path in the footer when PsyberShield creates one.
The generated fix artifact itself lands under `outputs/generated/` so it stays app-owned and easy to review.

Real local edit lane:

```powershell
.\venv\Scripts\python.exe -m app.main fix --local
```

`fix --local` is the first live-edit path. It discovers a supported server file, backs up the real file first, applies one small reversible edit, validates the config, and rolls back on failure.

