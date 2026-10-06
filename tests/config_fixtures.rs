#![expect(
    clippy::disallowed_methods,
    reason = "integration tests build synthetic fixtures in temporary directories"
)]

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
};

use crabinet::config::Config;

const HASH: &str = "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

fn quoted(path: &Path) -> String {
    format!("{:?}", path)
}

fn fragments(root: &Path, secret: &Path) -> (String, String, String) {
    let server = format!(
        r#"[server]
listen = "127.0.0.1:8080"
database_path = "database.sqlite3"
session_secret_file = {}
max_upload_size = "10 MiB"
max_preview_size = "1 MiB""#,
        quoted(secret)
    );
    let user = format!(
        r#"[[users]]
username = "alice"
password_hash = "{HASH}""#
    );
    let share = format!(
        r#"[[shares]]
id = "documents"
name = "Documents"
path = {}
[[shares.grants]]
user = "alice"
permission = "write""#,
        quoted(root)
    );
    (server, user, share)
}

/// Secrets must be owner-only, or every fixture would fail for that reason alone.
fn write_secret(path: &Path, contents: [u8; 32]) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn render(template: &str, temp: &Path) -> String {
    let root = temp.join("share");
    let child = root.join("child");
    let missing = temp.join("missing");
    let file = temp.join("plain-file");
    let link = temp.join("share-link");
    let secret = temp.join("session.key");
    fs::create_dir_all(&child).unwrap();
    fs::write(&file, b"not a directory").unwrap();
    write_secret(&secret, [9_u8; 32]);
    symlink(&root, &link).unwrap();
    let oidc_secret = temp.join("oidc.secret");
    fs::write(&oidc_secret, "example-client-secret").unwrap();
    fs::set_permissions(&oidc_secret, fs::Permissions::from_mode(0o600)).unwrap();
    // Generated for this run, so no private key is ever committed.
    let with_key = temp.join("ca-with-key.pem");
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let key = openssl::ec::EcKey::generate(&group).unwrap();
    fs::write(&with_key, key.private_key_to_pem().unwrap()).unwrap();
    let not_pem = temp.join("not-pem.pem");
    fs::write(&not_pem, b"not a certificate\n").unwrap();
    let (server, user, share) = fragments(&root, &secret);
    template
        .replace("{{OIDC_SECRET}}", oidc_secret.to_str().unwrap())
        .replace("{{CA_WITH_PRIVATE_KEY}}", with_key.to_str().unwrap())
        .replace("{{NOT_PEM}}", not_pem.to_str().unwrap())
        .replace("{{SERVER}}", &server)
        .replace("{{USER}}", &user)
        .replace("{{SHARE}}", &share)
        .replace("{{SECRET}}", secret.to_str().unwrap())
        .replace("{{ROOT}}", root.to_str().unwrap())
        .replace("{{CHILD}}", child.to_str().unwrap())
        .replace("{{MISSING}}", missing.to_str().unwrap())
        .replace("{{NON_DIRECTORY}}", file.to_str().unwrap())
        .replace("{{SYMLINK}}", link.to_str().unwrap())
}

#[test]
fn valid_fixture_loads() {
    let temp = tempfile::tempdir().unwrap();
    let rendered = render(include_str!("fixtures/config/valid.toml"), temp.path());
    let path = temp.path().join("config.toml");
    fs::write(&path, rendered).unwrap();
    Config::load(path).unwrap();
}

#[test]
fn annotated_example_loads_after_deployment_paths_are_prepared() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("share");
    fs::create_dir(&root).unwrap();
    fs::create_dir(temp.path().join("data")).unwrap();
    fs::create_dir(temp.path().join("secrets")).unwrap();
    write_secret(&temp.path().join("secrets/session.key"), [3_u8; 32]);
    let rendered = include_str!("../config.example.toml")
        .replace("/srv/crabinet/documents", root.to_str().unwrap());
    let path = temp.path().join("config.toml");
    fs::write(&path, rendered).unwrap();
    Config::load(path).unwrap();
}

#[test]
fn every_invalid_fixture_is_rejected() {
    let fixtures = [
        include_str!("fixtures/config/invalid/unknown-version.toml"),
        include_str!("fixtures/config/invalid/unknown-field.toml"),
        include_str!("fixtures/config/invalid/duplicate-user.toml"),
        include_str!("fixtures/config/invalid/duplicate-share.toml"),
        include_str!("fixtures/config/invalid/duplicate-grant.toml"),
        include_str!("fixtures/config/invalid/display-name.toml"),
        include_str!("fixtures/config/invalid/missing-display-name.toml"),
        include_str!("fixtures/config/invalid/dangling-grant.toml"),
        include_str!("fixtures/config/invalid/malformed-size.toml"),
        include_str!("fixtures/config/invalid/unsupported-hash.toml"),
        include_str!("fixtures/config/invalid/weak-hash.toml"),
        include_str!("fixtures/config/invalid/missing-root.toml"),
        include_str!("fixtures/config/invalid/non-directory-root.toml"),
        include_str!("fixtures/config/invalid/symlink-root.toml"),
        include_str!("fixtures/config/invalid/unsafe-root.toml"),
        include_str!("fixtures/config/invalid/overlapping-roots.toml"),
        include_str!("fixtures/config/invalid/connection-limit.toml"),
        include_str!("fixtures/config/invalid/header-read-timeout.toml"),
        include_str!("fixtures/config/invalid/trust-all-proxies.toml"),
        include_str!("fixtures/config/invalid/malformed-trusted-proxy.toml"),
        include_str!("fixtures/config/invalid/unknown-proxy-header.toml"),
        include_str!("fixtures/config/invalid/share-id-leading-dot.toml"),
        include_str!("fixtures/config/invalid/oidc-subject-without-email.toml"),
        include_str!("fixtures/config/invalid/folder-sizes-type.toml"),
        include_str!("fixtures/config/invalid/archive-compression-value.toml"),
        include_str!("fixtures/config/invalid/oidc-ca-file-relative.toml"),
        include_str!("fixtures/config/invalid/oidc-ca-file-missing.toml"),
        include_str!("fixtures/config/invalid/oidc-ca-file-private-key.toml"),
        include_str!("fixtures/config/invalid/oidc-ca-file-not-pem.toml"),
    ];
    for (index, template) in fixtures.into_iter().enumerate() {
        let temp = tempfile::tempdir().unwrap();
        let rendered = render(template, temp.path());
        let path = temp.path().join(format!("invalid-{index}.toml"));
        fs::write(&path, rendered).unwrap();
        assert!(
            Config::load(path).is_err(),
            "invalid fixture {index} loaded"
        );
    }
}

#[test]
fn invalid_oidc_ca_file_fixtures_fail_on_the_ca_file() {
    for (template, expected) in [
        (
            include_str!("fixtures/config/invalid/oidc-ca-file-relative.toml"),
            "must be an absolute path",
        ),
        (
            include_str!("fixtures/config/invalid/oidc-ca-file-missing.toml"),
            "is missing or unreadable",
        ),
        (
            include_str!("fixtures/config/invalid/oidc-ca-file-private-key.toml"),
            "contains a private key",
        ),
        (
            include_str!("fixtures/config/invalid/oidc-ca-file-not-pem.toml"),
            "at least one PEM CERTIFICATE block",
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        fs::write(&path, render(template, temp.path())).unwrap();
        let error = Config::load(path).unwrap_err().to_string();
        assert!(
            error.contains("auth.oidc.ca_file") && error.contains(expected),
            "{error}"
        );
    }
}
