# Remediation note for Exposed file: backup.zip

- Finding: `exposed-file-backup-zip`
- Category: `exposed_files`
- Severity: `medium`
- Target: `http://127.0.0.1:8000/backup.zip`
- Suggested next step: Block backup.zip from the web root.
- Rollback: Undo the web-root change if it caused the exposure.
- Saved at: `2026-05-25T13:39:56.324531+00:00`

This file is local to the Turan workspace and can be removed safely after review.