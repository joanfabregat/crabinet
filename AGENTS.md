# Agent instructions

Crabinet is a public open-source project. Follow [CONTRIBUTING.md](CONTRIBUTING.md): run project Rust and JavaScript only in a locked-down container, never directly on the host, and keep the required checks green.

Keep deployment-specific details out of this repository. Hostnames, user names and email addresses, host paths, credentials, and operator tooling for a particular installation belong in that installation's own configuration, not in code, fixtures, scripts, or documentation here. Examples use `example.com`, `/srv/crabinet/...`, and the synthetic fixtures under `web/e2e/fixtures`.
