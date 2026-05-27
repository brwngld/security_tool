# Turan Report

Target: http://69.10.53.250/
Findings: 2

## Proposed Fixes

- Set Secure and HttpOnly on session cookies.
  - Rollback: Restore the previous cookie settings.
- Hide the server banner and framework version.
  - Rollback: Re-enable the banner only if you really need it.