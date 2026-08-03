# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest (`main`) | Yes |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report them privately via [GitHub Security Advisories](https://github.com/dbnz-io/opencdr/security/advisories/new).

Include as much detail as possible:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You can expect an acknowledgement within **48 hours** and a status update within **7 days**.

## Scope

This policy covers vulnerabilities in:
- Detection and correlation logic (`src/domain/`)
- Incident response actions (`src/dredge/`)
- API handlers (`src/handlers/`)
- Bundled detection rules (`support_files/detection_rules/`)

Out of scope: vulnerabilities in third-party dependencies (report those upstream), AWS infrastructure misconfigurations in user deployments, or issues in forked/modified versions.
