# Turan

Turan is a Python-based web security scanner and hardening assistant.

## Status

Active CLI slice with scan, crawl, report, baseline, compare, audit, doctor, server-check, fix, and demo-site commands.

## Documentation

- Living user guide: [docs/turan-user-guide.md](docs/turan-user-guide.md)
- PDF version: [turan-user-guide.pdf](turan-user-guide.pdf)
- Changelog: [docs/changelog.md](docs/changelog.md)
- Regenerate the PDF guide with `python generate_user_guide_pdf.py` after updating [docs/turan-user-guide.md](docs/turan-user-guide.md)

## Commands

- `scan` scans a live target, or falls back to `APP_URL` / `TARGET_URL` / `BASE_URL` in `.env` or `--env-file`, then discovers a local app target when needed
- `crawl` starts from a target URL or discovered app target and follows in-scope links across multiple pages
- `report` re-renders or previews a saved scan report
- `audit` shows the append-only audit history
- `baseline` saves a scan snapshot for later comparison
- `compare` shows what changed between two saved scans, including crawl coverage deltas for crawl runs
- `doctor` checks the local machine and app environment
- `server-check` checks the server-facing config, discovers the app target, and scans it locally
- `fix` applies the first real local fix lane with `--local`
- `demo-site` starts the local test site

## Browser auth

Turan supports browser-assisted authentication for JS-heavy login flows:

```powershell
.\venv\Scripts\python.exe -m app.main crawl https://example.com --auth-method browser --browser-username-selector 'input[name="identifier"]' --browser-password-selector 'input[name="password"]' --username alice --password-env TURAN_PASSWORD --auth-check-url /account
```

Install the optional browser extra with:

```powershell
pip install .[browser]
```

## Run

```powershell
.\venv\Scripts\python.exe -m app.main scan https://example.com
.\venv\Scripts\python.exe -m app.main scan https://example.com --yes
```

If you want Turan to discover the app target on a VPS, you can leave the URL off:

```powershell
.\venv\Scripts\python.exe -m app.main scan
```

Turan looks for `APP_URL`, then `TARGET_URL`, then `BASE_URL`.

If those are missing, Turan checks the server layout first and prefers the app's own `.env` when Nginx or systemd point to an app root or an explicit `EnvironmentFile`.

If discovery still can't resolve a target, Turan falls back to the project `.env` only as the last local fallback.

When that happens, Turan prints a short `Discovery:` line first and then the fuller context block.

You can also point Turan at a specific env file:

```powershell
.\venv\Scripts\python.exe -m app.main scan --env-file C:\path\to\autoentrytrack\.env
```

If you want Turan to walk multiple in-scope pages instead of just one, use `crawl`:

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
.\venv\Scripts\python.exe -m app.main crawl https://example.com --login-url /auth/login --auth-method json --username alice --password-env TURAN_PASSWORD --auth-check-url /account
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
.\venv\Scripts\python.exe -m app.main crawl https://example.com --auth-method browser --browser-username-selector 'input[name="identifier"]' --browser-password-selector 'input[name="password"]' --username alice --password-env TURAN_PASSWORD --auth-check-url /account
```

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

## Local file overrides

```powershell
.\venv\Scripts\python.exe -m app.main doctor --env-file C:\path\to\autoentrytrack\.env
.\venv\Scripts\python.exe -m app.main server-check --env-file C:\path\to\autoentrytrack\.env --nginx-config /etc/nginx/nginx.conf
```

## Export reports

Turan writes three report formats:

- `--json-output` for machine-readable data
- `--markdown-output` for a quick human-readable report
- `--html-output` for the polished browser version
- If you pass one of those flags without a path, Turan creates a timestamped file under `outputs/`

When Turan discovers a local app target, the saved JSON, Markdown, and HTML reports include an `Application Context` section with the resolved target, env source, server hints, and discovery notes.
When you use `crawl`, the saved JSON, Markdown, and HTML reports also include a `Scanned URLs` section with the in-scope pages Turan visited, and repeated findings are grouped with an `Affected URLs` list instead of being printed over and over.

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

Turan can write JSON, Markdown, and HTML reports in the same scan run if you pass the output paths you want.

If you pass a Windows-style rooted path like `\outputs\crawl-test.html`, Turan treats it as project-relative, prints the resolved path, and writes the file under the current project folder instead of the drive root.

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

Turan also writes a small companion metadata file next to each baseline snapshot, like `baselines\vps-west.json.meta.json`, so you can see the resolved target and discovery trail later.

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

TODO:
- Add a short terminal note when `compare` includes crawl coverage deltas.

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

`doctor` checks the local machine, config paths, open localhost ports, safe environment status, and any resolved app target without taking a target URL.

## Server check

```powershell
.\venv\Scripts\python.exe -m app.main server-check
```

`server-check` stays focused on server-facing paths, local service signals, and config checks, then scans the resolved local target when one is found.

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

Turan shows a numbered list of suggested fixes, asks whether you want to generate artifacts or apply fixes locally, and then lets you choose all fixes or just the ones you want by number or range.
If there are more than ten fixes, Turan shows a paged list and lets you move with `n` and `p`.
For `fix-local`, Turan shows the target file, backup path, validation command, and rollback state before the final apply confirmation.

## Apply fixes

```powershell
.\venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8000 --generate-fixes
```

`--generate-fixes` creates a backup first, then writes local remediation notes for allowed safe changes. It does not change system services or config outside the approved gate.
`--apply-fixes` still works as a legacy alias for `--generate-fixes`, so older commands keep running while the wording stays honest.
Each remediation note includes the backup path when Turan creates one.
The generated fix artifact itself is written as a small artifact under `outputs/generated/`.

Turan also appends scan and fix events to `outputs/audit.log` by default.

## Real local fix

```powershell
.\venv\Scripts\python.exe -m app.main fix --local
```

`fix --local` is the first real live-edit lane. It discovers a supported server file, creates a backup of the real file first, applies one small reversible edit, validates the config, and rolls back if validation fails.

## Local Demo Site

Start the demo site in one terminal:

```powershell
.\venv\Scripts\python.exe -m app.main demo-site --port 8000
```

Then scan it from another terminal:

```powershell
.\venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8000
```
