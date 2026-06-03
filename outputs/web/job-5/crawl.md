# PsyberShield Report

Target: http://69.10.53.250/
Findings: 1

## Executive Summary

- Detections: 1
- Notes: 5
- Scope: 6 scanned URL(s)
- High / Critical: 0
- Medium: 0
- Low: 1
- Info: 0
- TLS posture: unknown

## Scanned URLs

- 1. http://69.10.53.250/
- 2. http://69.10.53.250/auth/login
- 3. http://69.10.53.250/terms
- 4. http://69.10.53.250/auth/forgot-password
- 5. http://69.10.53.250/auth/reset-password
- 6. http://69.10.53.250/auth/register
- Seed sources: page links

## Notes

- Why these pages? PsyberShield starts at http://69.10.53.250/ and follows in-scope links until it reaches the crawl limits.
- Scope: same-host only, max depth 2, max pages 100.
- Discovery seeds: page links only.
- Seed URLs queued: none beyond the starting page.
- Crawled 6 page(s) within scope.

## Findings

- [low] Server information disclosure
  - Category: server_info
  - Confidence: high
  - First move: Report only; no system change required.
  - Affected URLs:
    - 1. http://69.10.53.250/
    - 2. http://69.10.53.250/auth/login
    - 3. http://69.10.53.250/terms
    - 4. http://69.10.53.250/auth/forgot-password
    - 5. http://69.10.53.250/auth/reset-password
    - 6. http://69.10.53.250/auth/register

## Severity Guide

- Critical: urgent, likely immediate risk
- High: important, should be handled first
- Medium: needs review and scheduling
- Low: useful hardening or hygiene item
- Info: context or supporting detail

## What to Fix First

1. [low] Server information disclosure
   - First move: Hide the banner in the web server config first.
   - Impact: Report only; no system change required.
   - Affected URLs: http://69.10.53.250/, http://69.10.53.250/auth/login, http://69.10.53.250/terms