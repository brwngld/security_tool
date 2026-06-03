# PsyberShield Changelog

This file tracks user-facing changes to PsyberShield over time.
It is intentionally short and practical so it can stay current as the app grows.

## Unreleased

- Added the living user guide in Markdown and PDF form.
- Added optional output flags that can auto-create files under `outputs/` when no path is supplied.
- Added output-path normalization for Windows-rooted relative paths like `\outputs\scan.html`.
- Added `crawl` scope controls, seed sources, and grouped repeated findings.
- Added generic authenticated scan and crawl support, including browser-assisted login flows.
- Added `fix --local` as the first real live-edit lane with backup, validation, and rollback.
- Added `doctor` and `server-check` discovery workflows for local and VPS environments, including a deployment profile hint and explicit `ready`, `warning`, and `danger` state labels.
- Added `--profile quick`, `--profile full`, and `--profile safe-vps` presets for scan and crawl defaults.
- Added fix confidence labels for suggested actions: report only, generate artifact, safe local fix, and needs manual approval.
- Added `incident` log analysis with Apache/auth/systemd patterns, optional Nginx denylist containment, and fail2ban-style output for suspicious activity.
- Added live log snapshot ingestion for `incident` from `journalctl`, Windows Event Log, and file tails.
- Added richer incident signatures for Apache, Nginx, Gunicorn, uWSGI, SSH, sudo, and auth middleware.
- Added `integrity` file monitoring with baseline comparison for config files, web roots, and startup scripts.
- Added process and port checks that flag suspicious listeners and outbound connections in `doctor` and `server-check`.
- Added `watch` as a hybrid monitoring command for log, file drift, and process activity with snapshot and follow modes.
- Added a readiness breakdown under the `doctor` readiness score so the score explains the main warnings.
- Added optional JSON, Markdown, and HTML saved reports for `doctor`.
- Added rate-limit and maintenance-mode containment presets alongside the Nginx denylist and fail2ban artifacts.
- Added `timeline` reports that order findings, containment actions, and audit events chronologically.
- Added report notification hooks for webhooks, Slack, Discord, and email across `incident`, `integrity`, and `timeline`.
- Added a short `compare` terminal note when crawl coverage changes between saved crawl reports.
- Added `drift` for baseline drift detection across saved reports.
- Added `secrets` for redacted secret exposure checks in logs and config files, with default saved report outputs when none are supplied.
- Added `vuln scan` for local software inventory with bundled offline advisory matching for a small initial CVE ruleset.
- Added an advisory source abstraction and routed the bundled local CVE rules through `LocalRulesSource`.
- Added `bundle` for packaging reports and related containment artifacts into ZIP archives.

## Notes

- When you add a new command, flag, or output format, update:
  - `README.md`
  - `docs/architecture.md`
  - `docs/turan-user-guide.md`
  - this changelog
- If the PDF guide changes, regenerate `psybershield-user-guide.pdf` with `python generate_user_guide_pdf.py`

## Release Checklist

Before you call a version ready, check:

1. The CLI help reflects the current commands and flags.
2. The README and architecture doc mention the new behavior.
3. The user guide is updated for any new user-facing flow.
4. The PDF guide is regenerated from `docs/turan-user-guide.md`.
5. The Desktop app copy is synced.
6. The full test suite passes in the Desktop app copy.
7. Any new output paths still land under `outputs/` unless the user explicitly provides a full path.

