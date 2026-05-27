# Remediation note for Missing security header: x-frame-options

- Finding: `missing-x-frame-options`
- Category: `headers`
- Severity: `low`
- Target: `http://127.0.0.1:8000/`
- Suggested next step: Add x-frame-options at the app edge or reverse proxy.
- Rollback: Restore the previous header config.
- Saved at: `2026-05-25T13:39:56.315199+00:00`

This file is local to the Turan workspace and can be removed safely after review.