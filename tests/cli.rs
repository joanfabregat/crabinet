use std::{fs, net::TcpListener, process::Command};

const HASH: &str = "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

fn write_config(version: u32, listen: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("share");
    fs::create_dir(&root).unwrap();
    let secret = temp.path().join("session.key");
    fs::write(&secret, [5_u8; 32]).unwrap();
    let path = temp.path().join("config.toml");
    fs::write(
        &path,
        format!(
            r#"version = {version}
[server]
listen = {listen:?}
database_path = "database.sqlite3"
session_secret_file = {secret:?}
max_upload_size = "10 MiB"
max_preview_size = "1 MiB"
[[users]]
username = "alice"
password_hash = "{HASH}"
[[shares]]
id = "documents"
name = "Documents"
path = {root:?}
[[shares.grants]]
user = "alice"
permission = "read"
"#
        ),
    )
    .unwrap();
    (temp, path)
}

#[test]
fn check_config_accepts_global_config_after_subcommand() {
    let (_temp, path) = write_config(1, "127.0.0.1:8080");
    let output = Command::new(env!("CARGO_BIN_EXE_crabinet"))
        .args(["check-config", "--config"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"configuration is valid\n");
}

#[test]
fn command_line_config_takes_precedence_over_environment() {
    let (_temp, path) = write_config(1, "127.0.0.1:8080");
    let output = Command::new(env!("CARGO_BIN_EXE_crabinet"))
        .env("CRABINET_CONFIG", "/definitely/absent.toml")
        .args(["check-config", "--config"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn schema_command_does_not_require_a_configuration_file() {
    let output = Command::new(env!("CARGO_BIN_EXE_crabinet"))
        .env_remove("CRABINET_CONFIG")
        .arg("print-config-schema")
        .output()
        .unwrap();
    assert!(output.status.success());
    let schema: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(schema["title"], "RawConfig");
}

#[test]
fn invalid_config_is_rejected_before_the_listener_is_opened() {
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap().to_string();
    let (_temp, path) = write_config(2, &address);
    let output = Command::new(env!("CARGO_BIN_EXE_crabinet"))
        .arg("--config")
        .arg(path)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("startup configuration is invalid"),
        "{stderr}"
    );
    assert!(
        stderr.contains("unsupported configuration version"),
        "{stderr}"
    );
    assert!(!stderr.contains("address already in use"), "{stderr}");
}
