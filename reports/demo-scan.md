# Turan Report

Target: http://127.0.0.1:8000/
Findings: 7

## Proposed Fixes

- Add content-security-policy at the app edge or reverse proxy.
  - Rollback: Restore the previous header config.
- Add x-frame-options at the app edge or reverse proxy.
  - Rollback: Restore the previous header config.
- Add x-content-type-options at the app edge or reverse proxy.
  - Rollback: Restore the previous header config.
- Set Secure and HttpOnly on session cookies.
  - Rollback: Restore the previous cookie settings.
- Hide the server banner and framework version.
  - Rollback: Re-enable the banner only if you really need it.
- Block .env from the web root.
  - Rollback: Undo the web-root change if it caused the exposure.
- Block backup.zip from the web root.
  - Rollback: Undo the web-root change if it caused the exposure.