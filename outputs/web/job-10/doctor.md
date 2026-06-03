# PsyberShield Doctor Report

Root: .
OS: Windows 10
Python: 3.14.0
Readiness state: danger
Readiness score: 69%

## Readiness Breakdown

- Readiness score is a weighted average across 14 check(s).
- Main drag from warnings: Process and port activity, DEBUG, SECRET_KEY, SERVER_NAME.
- Info checks: 3; unknown checks: 1.

## Application Context

- Root: .
- Target: http://69.10.53.250
- Target source: .env
- Discovered app: -
- Public URL: -
- Local URL: http://127.0.0.1:3000
- Env file: .env
- Env source: project .env
- Nginx config: -
- Systemd service: -
- Notes: scan target configured in .env; localhost ports listening: 3000

## Checks

- [ok] .env: found
- [ok] Scan target: present
- [info] Deployment profile: likely local development server
- [ok] Output folder: writable
- [ok] App config paths: found
- [info] Nginx config paths: not found
- [unknown] Nginx hardening: config not found
- [warn] Process and port activity: 74 suspicious listener(s); 26 outbound connection(s)
- [info] Open local ports: listening on localhost: 3000
- [warn] DEBUG: missing
- [warn] SECRET_KEY: missing
- [warn] SERVER_NAME: missing
- [warn] DATABASE_URL: missing
- [warn] SMTP_PASSWORD: missing