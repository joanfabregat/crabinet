# Dependency licensing

Index's own source and original assets are MIT licensed. Rust and frontend dependencies retain their own copyrights and licenses.

`deny.toml` permits only MIT, Apache-2.0 (including LLVM exception), BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, and Zlib for the locked Rust graph. CI runs `cargo deny check --all-features` on every merge. Pull requests also run GitHub dependency review and reject high-severity dependency findings and GPL/AGPL license families. The frontend lockfile is audited on every merge and release; its production dependency is Preact under MIT, while development packages are not shipped as runtime files.

Every release publishes SPDX JSON SBOMs for each binary archive and architecture-specific OCI image. Those SBOMs are the authoritative per-release inventory of package names, versions, source locations, and declared license identifiers. The release archive also includes Index's `LICENSE`.

No dependency in the currently locked distributable graph supplies a separate `NOTICE` file that must be copied verbatim into the release archive. Apache, MIT, BSD, ISC, Unicode, and Zlib terms and upstream copyright notices still apply to their respective components. A dependency update that introduces a package-specific notice, nonstandard license file, embedded asset, or attribution requirement must add that notice to release artifacts and update this document before merge; passing `cargo-deny` alone is not sufficient evidence for that case.

Release reviewers should compare the generated SBOM and dependency diff with this policy. Source distributions preserve dependency metadata through `Cargo.lock`, `web/package-lock.json`, and package manifests; binary recipients can use the published SBOM to retrieve the exact corresponding license text from each recorded upstream source.
