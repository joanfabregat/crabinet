use std::{fs, os::unix::fs::symlink, path::Path};

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

fn render(template: &str, temp: &Path) -> String {
    let root = temp.join("share");
    let child = root.join("child");
    let missing = temp.join("missing");
    let file = temp.join("plain-file");
    let link = temp.join("share-link");
    let secret = temp.join("session.key");
    fs::create_dir_all(&child).unwrap();
    fs::write(&file, b"not a directory").unwrap();
    fs::write(&secret, [9_u8; 32]).unwrap();
    symlink(&root, &link).unwrap();
    let (server, user, share) = fragments(&root, &secret);
    template
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
    fs::write(temp.path().join("secrets/session.key"), [3_u8; 32]).unwrap();
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
