# Turan Changelog

This file tracks user-facing changes to Turan over time.
It is intentionally short and practical so it can stay current as the app grows.

## Unreleased

- Added the living user guide in Markdown and PDF form.
- Added optional output flags that can auto-create files under `outputs/` when no path is supplied.
- Added output-path normalization for Windows-rooted relative paths like `\outputs\scan.html`.
- Added `crawl` scope controls, seed sources, and grouped repeated findings.
- Added generic authenticated scan and crawl support, including browser-assisted login flows.
- Added `fix --local` as the first real live-edit lane with backup, validation, and rollback.
- Added `doctor` and `server-check` discovery workflows for local and VPS environments.

## Notes

- When you add a new command, flag, or output format, update:
  - `README.md`
  - `docs/architecture.md`
  - `docs/turan-user-guide.md`
  - this changelog
- If the PDF guide changes, regenerate `turan-user-guide.pdf` with `python generate_user_guide_pdf.py`

## Release Checklist

Before you call a version ready, check:

1. The CLI help reflects the current commands and flags.
2. The README and architecture doc mention the new behavior.
3. The user guide is updated for any new user-facing flow.
4. The PDF guide is regenerated from `docs/turan-user-guide.md`.
5. The Desktop app copy is synced.
6. The full test suite passes in the Desktop app copy.
7. Any new output paths still land under `outputs/` unless the user explicitly provides a full path.
