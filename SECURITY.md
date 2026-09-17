# Security policy

Security is a primary design constraint for Index. This policy covers the application, release artifacts, container image, build workflows, and documentation in this repository.

## Supported versions

Before 1.0, only the latest published release and the current `main` branch receive security fixes. After a new release is published, older pre-1.0 releases are unsupported. Do not assume a commit on `main` has received release-level compatibility testing until it is tagged.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Current `main` | Development fixes |
| Older releases | No |

## Private reporting

Use [GitHub private vulnerability reporting](https://github.com/joanfabregat/index/security/advisories/new) for suspected vulnerabilities. Include the affected version or commit, deployment assumptions, reproduction steps, impact, and any suggested mitigation. Use placeholder credentials and synthetic files whenever possible.

Do not open a public issue, discussion, or pull request for an unpatched vulnerability. Never paste active passwords, session cookies, CSRF tokens, session-secret contents, private share data, signing material, or infrastructure credentials into a report. If a real credential was exposed, revoke or rotate it immediately and report only that rotation occurred.

If private reporting is unavailable, open a public issue containing no exploit details or secrets and ask the maintainer to establish a private channel.

## Response expectations

The maintainer aims to acknowledge a complete report within three business days, provide an initial severity/next-step assessment within seven business days, and send at least weekly updates while remediation is active. These are targets rather than a service-level agreement. Coordinated disclosure timing will be agreed with the reporter after a fix and release plan exist.

Security releases may invalidate sessions, restrict previously accepted configuration, or disable unsafe behavior. Advisories will credit reporters who request credit and will describe affected versions, mitigations, and upgrade instructions without exposing active credentials.

## Deployment boundary

Index assumes a trusted Linux host, trusted immutable configuration, correctly permissioned mounts, a private backend connection, and an HTTPS reverse proxy that preserves `Host`. The process is not a sandbox for malicious native filesystem content. Operators remain responsible for host access control, TLS, backups, malware scanning if required, proxy rate limits, and ensuring only one Index process writes a share.

The [threat model](docs/threat-model.md) and [filesystem security notes](docs/filesystem-security.md) define the intended boundary. Reports that demonstrate a violation of those documented invariants are in scope. Vulnerabilities in a supported direct dependency or pinned CI action that materially affect Index are also in scope.

Load testing that harms shared infrastructure, social engineering, denial of service against public services, and accessing data that is not yours are prohibited. Reproduce locally against synthetic data.
