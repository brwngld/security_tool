# PsyberShield

PsyberShield is a Python-based security visibility and response tool for small servers and web applications.

## Status

Active CLI slice with scan, crawl, report, baseline, compare, drift, secrets, bundle, audit, doctor, server-check, incident, watch, vuln, fix, demo, and demo-site compatibility commands.

## Documentation

- Living user guide: [docs/turan-user-guide.md](docs/turan-user-guide.md)
- PDF version: [psybershield-user-guide.pdf](psybershield-user-guide.pdf)
- Combined manual: [psybershield-manual.pdf](psybershield-manual.pdf)
- Changelog: [docs/changelog.md](docs/changelog.md)
- Regenerate the PDF guide with `python generate_user_guide_pdf.py` and the combined manual with `python generate_psybershield_manual_pdf.py` after updating [docs/turan-user-guide.md](docs/turan-user-guide.md), [docs/architecture.md](docs/architecture.md), or [docs/changelog.md](docs/changelog.md)

## Desktop Build

Safest PyInstaller path:

1. Build the onedir launcher first with `pyinstaller pshield.spec`.
2. Test `dist\pshield\pshield.exe --help` and a simple `doctor` run.
3. Only switch to `--onefile` after the onedir build works reliably.

The launcher entry point is [build_pshield.py](build_pshield.py), which calls `app.main.cli_main()`.

## Commands

- `scan` scans a live target, or falls back to `APP_URL` / `TARGET_URL` / `BASE_URL` in `.env` or `--env-file`, then discovers a local app target when needed; supports browser-assisted login with `--auth-method browser`
- `crawl` starts from a target URL or discovered app target and follows in-scope links across multiple pages; supports browser-assisted login with `--auth-method browser`
- `report` re-renders or previews a saved scan report
- `audit` shows the append-only audit history
- `baseline` saves a scan snapshot for later comparison
- `compare` shows what changed between two saved scans, including crawl coverage deltas for crawl runs
- `drift` compares two saved reports and surfaces baseline drift across scan, integrity, incident, or doctor data
- `secrets` scans files for obvious secret exposure with redacted evidence
- `bundle` packages a report and related artifacts into a ZIP archive
- `doctor` checks the local machine and app environment
- `server-check` checks the server-facing config, discovers the app target, and scans it locally
- `incident` detects suspicious activity from logs and can generate or apply a denylist containment artifact
- `watch` monitors logs, file drift, and process activity in a snapshot or follow loop, writes JSON/Markdown/HTML reports under `outputs/` by default, and can compare file drift against a saved integrity baseline with `--baseline`
- `vuln scan` inventories local software versions, parses Python dependency manifests, matches bundled offline advisories, and can opt in to OSV dependency checks for exact versions with `--osv`
- `timeline` shows a chronological view of findings and containment activity from a saved incident report
- `fix` applies the first real local fix lane with `--local`
- `demo` starts the local test site
- `demo-site` remains as a compatibility alias

## Browser auth

PsyberShield supports browser-assisted authentication for JS-heavy login flows:

Browser auth requires either `--login-url` or `--storage-state` so PsyberShield knows how to establish the session before it scans.

```powershell
.\venv\Scripts\python.exe -m app.main crawl `
  https://example.com `
  --auth-method browser `
  --login-url /auth/login `
  --browser-username-selector 'input[name="identifier"]' `
  --browser-password-selector 'input[name="password"]' `
  --username alice `
  --password-env PsyberShield_PASSWORD `
  --auth-check-url /account
```

Storage-state reuse example:

```powershell
.\venv\Scripts\python.exe -m app.main crawl `
  https://example.com `
  --storage-state browser\storage_state.json `
  --auth-check-url /account
```

Install the optional browser extra with:

```powershell
pip install .[browser]
```

## Run

The preferred command is `pshield`. `psybershield` and `turan` remain compatibility aliases.

```powershell
pshield scan https://example.com
pshield scan https://example.com --yes
pshield watch --logs outputs\access.log --json-output
pshield watch --follow --interval 30 --tail-file outputs\access.log --html-output
pshield vuln scan --html-output
```

If you want PsyberShield to discover the app target on a VPS, you can leave the URL off:

```powershell
pshield scan
```

Browser-assisted login for JS-heavy auth flows:

```powershell
pshield scan https://example.com `
  --auth-method browser `
  --login-url /auth/login `
  --browser-username-selector 'input[name="identifier"]' `
  --browser-password-selector 'input[name="password"]' `
  --username alice `
  --password-env PsyberShield_PASSWORD `
  --auth-check-url /account
```

Check logs for active probing and, if needed, apply containment:

```powershell
pshield incident --logs outputs\access.log --apply-blocks
```

Capture fresh snapshots from live sources:

```powershell
pshield incident --live --tail-file outputs\access.log
pshield incident --live --event-log-name System --fail2ban-output outputs\incident-fail2ban.conf
```

You can also write a fail2ban-style snippet:

```powershell
pshield incident --logs outputs\access.log --fail2ban-output outputs\incident-fail2ban.conf
```

You can also generate rate-limit and maintenance-mode presets:

```powershell
pshield incident --logs outputs\access.log --rate-limit-output outputs\incident-rate-limit.conf --maintenance-output outputs\incident-maintenance.conf
```

You can compare two saved reports for drift:

```powershell
pshield drift baselines\scan.json outputs\scan.json --json-output outputs\drift.json
```

You can scan for obvious secret exposure:

```powershell
pshield secrets . --markdown-output outputs\secrets.md
```

If you omit all output flags, `secrets` now writes JSON, Markdown, and HTML reports under `outputs/` by default.

You can inventory local software versions and match them against bundled offline advisories:

```powershell
pshield vuln scan
pshield vuln scan --json-output outputs\vuln.json --html-output outputs\vuln.html
pshield vuln scan --inventory-only
pshield vuln scan --osv --osv-cache outputs\advisory-cache\osv
```

This checks common local commands such as Nginx, Apache, OpenSSL, Python, Node, npm, and PHP, then records the versions it can prove. It also parses Python dependencies from `requirements.txt` and `pyproject.toml`, including exact pins, version ranges, extras, environment markers, and direct references.

By default, CVE matching uses a small bundled offline ruleset only. Add `--osv` when you want PsyberShield to query OSV for parsed Python dependencies with exact versions, such as `flask==3.0.0`. Non-exact constraints such as `django>=5.0` stay in the inventory but are not treated as confirmed installed versions. OSV responses are cached under `outputs\advisory-cache\osv` unless you pass `--osv-cache`. Confirm distro backports and vendor advisories before treating system-package findings as final.

Containment planning is intentionally separated from live actions. PsyberShield now has recommendation, action, and result models for future containment workflows, but those models do not kill processes, disable accounts, quarantine files, or write firewall changes by themselves.

For automatic app-focused reporting, schedule the existing commands with cron, systemd timers, Windows Task Scheduler, or CI:

```powershell
pshield scan https://example.com --profile quick --html-output outputs\auto-scan.html --json-output outputs\auto-scan.json --yes
pshield crawl https://example.com --profile full --seed-robots --seed-sitemap --html-output outputs\auto-crawl.html --json-output outputs\auto-crawl.json --yes
pshield vuln scan --osv --html-output outputs\vuln-app.html --json-output outputs\vuln-app.json
```

This is best treated as app security visibility first. Deeper server/VPS automation and automatic containment should be enabled only after policy, rollback, and audit behavior are explicit.

## Private Web Dashboard

PsyberShield includes a private FastAPI dashboard for VPS-hosted, read-only app security workflows. It keeps source code on your server while users interact through HTML pages.

```powershell
pshield web --host 127.0.0.1 --port 8787
pshield worker
```

Set these before first launch:

```powershell
$env:PSHIELD_DATABASE_URL="postgresql+psycopg://psybershield:change-me@127.0.0.1:5432/psybershield"
$env:PSHIELD_SECRET_KEY="replace-with-a-long-random-secret"
$env:PSHIELD_OUTPUT_DIR="outputs/web"
$env:PSHIELD_ADMIN_EMAIL="admin@example.com"
$env:PSHIELD_ADMIN_PASSWORD="replace-with-a-temporary-admin-password"
```

V1 exposes read-only/reporting workflows only: targets, queued jobs, scan, crawl, vuln scan, secrets, baseline, compare, bundle, reports, audit history, and admin-created users. It does not expose local fixes, live containment, process killing, account disabling, file quarantine, or firewall changes.

The dashboard includes CSRF protection for authenticated POST routes, auto-refreshes queued/running job detail pages, and can preview JSON/Markdown/HTML reports before download. Example VPS service files live under `deploy/systemd/`, and a private Nginx reverse-proxy example lives under `deploy/nginx/`.

You can bundle a report and its related artifacts into a ZIP archive:

```powershell
pshield bundle outputs\incident.json --artifact outputs\incident-fail2ban.conf --bundle-output outputs\incident-bundle.zip
```

If you omit `--bundle-output`, PsyberShield names the archive after the source report, like `incident.bundle.zip`, and uses a matching manifest inside the ZIP.

You can send report summaries to webhooks or email after `incident`, `integrity`, or `timeline` runs:

```powershell
pshield incident --logs outputs\access.log --webhook-url https://hooks.example/webhook
pshield integrity . --baseline baselines\integrity.json --email-to security@example.com --email-from PsyberShield@example.com --smtp-host smtp.example.com --smtp-username PsyberShield --smtp-password-env SMTP_PASSWORD
pshield timeline outputs\incident.json --audit-log outputs\audit.log --slack-webhook-url https://hooks.slack.com/services/...
```

Monitor key files against a saved baseline:

```powershell
.\venv\Scripts\python.exe -m app.main integrity . --baseline baselines\integrity.json --json-output outputs\integrity.json
```

Create or refresh an integrity baseline:

```powershell
.\venv\Scripts\python.exe -m app.main integrity . --create-baseline baselines\integrity.json
.\venv\Scripts\python.exe -m app.main baseline https://example.com --output baselines\scan.json
```

Baseline workflow notes:

- create the first baseline after a known-good deployment
- refresh the baseline only after approved changes, then note what changed
- expect small drift from normal edits, version bumps, and content updates
- keep a team-owned baseline path and review it before using it in `watch`
- use `watch --baseline baselines\integrity.json` to compare live drift against that known-good snapshot

PsyberShield looks for `APP_URL`, then `TARGET_URL`, then `BASE_URL`.

If those are missing, PsyberShield checks the server layout first and prefers the app's own `.env` when Nginx or systemd point to an app root or an explicit `EnvironmentFile`.

If discovery still can't resolve a target, PsyberShield falls back to the project `.env` only as the last local fallback.

When that happens, PsyberShield prints a short `Discovery:` line first and then the fuller context block.

You can also point PsyberShield at a specific env file:

```powershell
.\venv\Scripts\python.exe -m app.main scan --env-file C:\path\to\autoentrytrack\.env
```

If you want PsyberShield to walk multiple in-scope pages instead of just one, use `crawl`:

```powershell
.\venv\Scripts\python.exe -m app.main crawl https://example.com --max-pages 20 --max-depth 2
.\venv\Scripts\python.exe -m app.main crawl https://example.com --include /auth/ --exclude /logout
.\venv\Scripts\python.exe -m app.main crawl https://example.com --allow-offsite
.\venv\Scripts\python.exe -m app.main crawl https://example.com --seed-robots --seed-sitemap
.\venv\Scripts\python.exe -m app.main crawl https://example.com --yes
```

## Authenticated crawl roadmap

Phase 1, implemented:
- HTTP login/session reuse for protected crawl and scan sessions
- JSON or form login payloads
- custom username/password field names
- raw cookie header reuse
- optional protected-page check after login

Example phase-1 commands:

```powershell
.\venv\Scripts\python.exe -m app.main crawl https://example.com --login-url /auth/login --auth-method json --username alice --password-env PsyberShield_PASSWORD --auth-check-url /account
.\venv\Scripts\python.exe -m app.main crawl https://example.com --cookie "session=abc123; csrf_token=..."
```

Phase 2, implemented:
- saved session import/export with `--session-file` and `--save-session`

Example phase-2 command:

```powershell
.\venv\Scripts\python.exe -m app.main crawl https://example.com --session-file sessions\autoentrytrack.json --save-session --auth-check-url /account
```

Phase 3, implemented:
- browser storage-state import/export with `--storage-state` and `--save-storage-state`

Phase 4, implemented:
- browser automation support for JS-heavy login flows when HTTP/session reuse is not enough
- install the optional browser extra with `pip install .[browser]`

Example phase-4 command:

```powershell
.\venv\Scripts\python.exe -m app.main crawl `
  https://example.com `
  --auth-method browser `
  --login-url /auth/login `
  --browser-username-selector 'input[name="identifier"]' `
  --browser-password-selector 'input[name="password"]' `
  --username alice `
  --password-env PsyberShield_PASSWORD `
  --auth-check-url /account
```

## Improvement Roadmap

The planned phases are complete. We are keeping the tool stable while doing final release prep and cleanup.

Phase 1: onboarding and packaging

- `pshield --help` clarity and examples
- `pshield demo` and `pshield doctor` first-run guidance
- packaged `.exe` build path and release notes

Phase 2: crawl and auth UX

- better page discovery explanations
- smarter auth/session handling
- clearer `why only these pages?` messaging
- polished sitemap and robots support

Phase 3: reports

- cleaner HTML report
- executive summary
- severity explanation
- `what to fix first`

Phase 4: doctor and server-check

- better VPS detection
- Nginx, systemd, and env checks
- clear `ready`, `warning`, and `danger` status

Phase 5: profiles

- `--profile quick` for a fast, shallow pass
- `--profile full` for a broader crawl with robots and sitemap hints
- `--profile safe-vps` for a balanced VPS-friendly pass

Example:

```powershell
.\venv\Scripts\python.exe -m app.main crawl https://example.com --profile safe-vps
.\venv\Scripts\python.exe -m app.main scan https://example.com --profile quick
```

Phase 6: fix confidence

- `report only`
- `generate artifact`
- `safe local fix`
- `needs manual approval`

Release prep:

- verify the packaged `.exe`
- refresh the user guide PDF if the docs change again
- run a final focused test pass before cutting a release

## Defensive Engine Roadmap

Phase 1: advisory abstraction

- add `AdvisorySource`
- add `AdvisoryQuery`
- add `LocalRulesSource`
- route the existing bundled offline CVE rules through the source abstraction
- keep `vuln scan` behavior compatible

Phase 2: OSV dependency advisories

- support Python dependency manifests first
- parse `requirements.txt`
- parse `pyproject.toml` where feasible
- add local cache and graceful offline handling
- label findings as confirmed, potential, or unknown

Phase 3: version and distro awareness

- normalize package names and versions
- separate upstream version matches from distro-patched package status
- report vendor backport uncertainty clearly

Phase 4: containment planning

- add `ContainmentRecommendation`
- add `ContainmentAction`
- add `ContainmentResult`
- make `watch` produce recommendations before any action execution exists

Phase 5: containment artifacts

- generate Windows Firewall, iptables/nftables, Nginx denylist, and fail2ban artifacts
- keep artifact generation separate from application

Phase 6: dry-run containment

- add `watch --contain --dry-run`
- audit the plan without changing the system

Phase 7: low-risk temporary blocking

- add explicit temporary IP containment behind policy approval
- audit every applied action
- include rollback guidance

Phase 8: high-risk actions

- consider process kill, account disablement, and file quarantine only behind strict policy
- require explicit flags, confidence thresholds, audit records, and rollback or restoration guidance

## `.env` variables

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
| `PsyberShield_PASSWORD` | `scan`, `crawl` | Secret value read by `--password-env` from the shell or the active `.env` / `--env-file` for browser auth or other password-based login flows |

## Local file overrides

```powershell
.\venv\Scripts\python.exe -m app.main doctor --env-file C:\path\to\autoentrytrack\.env
.\venv\Scripts\python.exe -m app.main server-check --env-file C:\path\to\autoentrytrack\.env --nginx-config /etc/nginx/nginx.conf
.\venv\Scripts\python.exe -m app.main incident --logs C:\path\to\logs --apply-blocks
```

## Export reports

PsyberShield writes three report formats:

- `--json-output` for machine-readable data
- `--markdown-output` for a quick human-readable report
- `--html-output` for the polished browser version
- If you pass one of those flags without a path, PsyberShield creates a timestamped file under `outputs/`

When PsyberShield discovers a local app target, the saved JSON, Markdown, and HTML reports include an `Application Context` section with the resolved target, env source, server hints, and discovery notes.
When you use `crawl`, the saved JSON, Markdown, and HTML reports also include a `Scanned URLs` section with the in-scope pages PsyberShield visited, and repeated findings are grouped with an `Affected URLs` list instead of being printed over and over.

Cookie warnings stay a little cautious too: CSRF-style cookies can show a lower confidence hint and a "review issuance location" recommendation instead of pretending they are always session cookies.

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --json-output outputs\scan.json --markdown-output outputs\scan.md
```

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --html-output outputs\scan.html
```

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --html-output
```

PsyberShield can write JSON, Markdown, and HTML reports in the same scan run if you pass the output paths you want.

If you pass a Windows-style rooted path like `\outputs\crawl-test.html`, PsyberShield treats it as project-relative, prints the resolved path, and writes the file under the current project folder instead of the drive root.

## Re-render a saved report

```powershell
.\venv\Scripts\python.exe -m app.main report outputs\scan.json --html-output outputs\scan.html
```

`report` accepts `.json`, `.md`, and `.html` files.

```powershell
.\venv\Scripts\python.exe -m app.main report outputs\scan.md
.\venv\Scripts\python.exe -m app.main report outputs\scan.html
```

## Save a baseline

```powershell
.\venv\Scripts\python.exe -m app.main baseline https://example.com --output baselines\example.json
```

You can give the baseline a friendlier name too:

```powershell
.\venv\Scripts\python.exe -m app.main baseline https://example.com --label vps-west
```

PsyberShield also writes a small companion metadata file next to each baseline snapshot, like `baselines\vps-west.json.meta.json`, so you can see the resolved target and discovery trail later.

You can point the audit log at a different file too:

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --audit-log outputs\audit.log
.\venv\Scripts\python.exe -m app.main baseline https://example.com --audit-log outputs\audit.log
```

## Compare two scans

```powershell
.\venv\Scripts\python.exe -m app.main compare outputs\old.json outputs\new.json
```

You can also write a Markdown or HTML diff report:

```powershell
.\venv\Scripts\python.exe -m app.main compare old.json new.json --markdown-output compare.md
.\venv\Scripts\python.exe -m app.main compare old.json new.json --html-output compare.html
```

When the saved reports come from `crawl`, `compare` also shows how many pages were added or removed between runs.
When crawl coverage changes, PsyberShield prints a short terminal note with the added and removed page counts.

## Audit history

```powershell
.\venv\Scripts\python.exe -m app.main audit --last 25
.\venv\Scripts\python.exe -m app.main audit --event scan
.\venv\Scripts\python.exe -m app.main audit --target example.com
.\venv\Scripts\python.exe -m app.main audit --audit-log outputs\audit.log
.\venv\Scripts\python.exe -m app.main audit --json-output outputs\audit.json
```

## Doctor

```powershell
.\venv\Scripts\python.exe -m app.main doctor
```

`doctor` checks the local machine, config paths, suspicious listeners and outbound connections, open localhost ports, safe environment status, a deployment profile hint, and any resolved app target without taking a target URL. The readiness score now includes a short breakdown of the checks that most influenced it, and the report also labels the overall state as `ready`, `warning`, or `danger`.

`doctor` also supports `--json-output`, `--markdown-output`, and `--html-output` for saved reports.

## Server check

```powershell
.\venv\Scripts\python.exe -m app.main server-check
```

`server-check` stays focused on server-facing paths, local service signals, and config checks, then scans the resolved local target when one is found. It also prints the deployment profile hint and the overall readiness state so you can tell at a glance whether the host looks ready, warning-level, or danger-level.

## Timeout

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --timeout 5
```

## Policy file

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com --policy policy.json
```

Copy [policy.example.json](policy.example.json) to `policy.json` and adjust the values for your environment.

## Preview fixes

```powershell
.\venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8000 --preview-fixes
```

## Interactive fixes

```powershell
.\venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8000 --interactive
```

PsyberShield shows a numbered list of suggested fixes, labels each one as report only, generate artifact, safe local fix, or needs manual approval, asks whether you want to generate artifacts or apply fixes locally, and then lets you choose all fixes or just the ones you want by number or range.
If there are more than ten fixes, PsyberShield shows a paged list and lets you move with `n` and `p`.
For `fix-local`, PsyberShield shows the target file, backup path, validation command, and rollback state before the final apply confirmation.

## Apply fixes

```powershell
.\venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8000 --generate-fixes
```

`--generate-fixes` creates a backup first, then writes local remediation notes for allowed safe changes. It does not change system services or config outside the approved gate.
`--apply-fixes` still works as a legacy alias for `--generate-fixes`, so older commands keep running while the wording stays honest.
Each remediation note includes the backup path when PsyberShield creates one.
The generated fix artifact itself is written as a small artifact under `outputs/generated/`.

PsyberShield also appends scan and fix events to `outputs/audit.log` by default.

## Real local fix

```powershell
.\venv\Scripts\python.exe -m app.main fix --local
```

`fix --local` is the first real live-edit lane. It discovers a supported server file, creates a backup of the real file first, applies one small reversible edit, validates the config, and rolls back if validation fails.

## Local Demo Site

Start the demo site in one terminal:

```powershell
.\venv\Scripts\python.exe -m app.main demo --port 8000
```

Then scan it from another terminal:

```powershell
.\venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8000
```

