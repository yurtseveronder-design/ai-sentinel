# Security policy

## Reporting a vulnerability
Please report suspected vulnerabilities privately through GitHub: **Security tab, "Report a vulnerability"** on this
repository. Do not open a public issue for them. Include what you found, how to reproduce it, and the version or commit.
You can expect an acknowledgement within a few days; this is a personal project, so there is no guaranteed response time.

## Scope
The gateway (`src/ai_sentinel/api`), the rule shield and the output scanner. Bypasses of detection (a phrasing that is
not blocked) are expected and documented in `docs/THREAT_MODEL.md`; they are welcome as regular issues or as
additions to the sentinel-eval datasets rather than as vulnerabilities.

## Supported versions
Only the latest commit on `main`.
