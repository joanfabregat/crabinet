use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use argon2::{Params, PasswordHash};
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const CONFIG_VERSION: u32 = 1;
const MIN_SESSION_SECRET_BYTES: usize = 32;
const MAX_SESSION_SECRET_BYTES: usize = 4096;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read configuration file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid TOML in configuration file{location}; consult `index print-config-schema`")]
    TomlSyntax { location: String },
    #[error(
        "configuration does not match the version 1 schema{location}; consult `index print-config-schema`"
    )]
    Schema { location: String },
    #[error("unsupported configuration version {0}; this binary supports only version 1")]
    UnsupportedVersion(u32),
    #[error("invalid configuration: {0}")]
    Validation(String),
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    /// Configuration format version. The only supported value is 1.
    #[schemars(range(min = 1, max = 1))]
    version: u32,
    server: RawServerConfig,
    #[serde(default)]
    #[schemars(length(min = 1))]
    users: Vec<RawUser>,
    #[serde(default)]
    shares: Vec<RawShare>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RawServerConfig {
    /// TCP socket address on which the HTTP server listens.
    listen: String,
    /// SQLite file. Relative paths are resolved from the configuration directory.
    database_path: PathBuf,
    /// File containing 32 to 4096 random bytes. Its contents are never printed.
    session_secret_file: PathBuf,
    /// Maximum request upload size, for example "100 MiB".
    max_upload_size: String,
    /// Maximum file size eligible for preview, for example "2 MiB".
    max_preview_size: String,
    /// Maximum simultaneous Argon2 password verifications.
    #[serde(default = "default_auth_max_concurrent")]
    #[schemars(range(min = 1, max = 16))]
    auth_max_concurrent: usize,
    /// Session idle timeout in seconds.
    #[serde(default = "default_session_idle_timeout_seconds")]
    #[schemars(range(min = 60, max = 86_400))]
    session_idle_timeout_seconds: u64,
    /// Session absolute lifetime in seconds.
    #[serde(default = "default_session_absolute_timeout_seconds")]
    #[schemars(range(min = 300, max = 2_592_000))]
    session_absolute_timeout_seconds: u64,
    /// Login attempts allowed per normalized username and source address each minute.
    #[serde(default = "default_login_attempts_per_minute")]
    #[schemars(range(min = 1, max = 1_000))]
    login_attempts_per_minute: u32,
    /// Maximum simultaneously active sessions retained for one user.
    #[serde(default = "default_max_sessions_per_user")]
    #[schemars(range(min = 1, max = 256))]
    max_sessions_per_user: usize,
    /// Maximum simultaneously active sessions retained across all users.
    #[serde(default = "default_max_sessions_total")]
    #[schemars(range(min = 1, max = 100_000))]
    max_sessions_total: usize,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RawUser {
    #[schemars(length(min = 1, max = 64))]
    username: String,
    /// An Argon2id PHC string produced by `index hash-password`.
    password_hash: String,
    /// Disabled users cannot log in and their existing sessions are rejected.
    #[serde(default)]
    disabled: bool,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RawShare {
    /// Stable identifier used in URLs and grants.
    #[schemars(length(min = 1, max = 64))]
    id: String,
    /// User-facing label. It may change without changing the share's identity or URLs.
    #[schemars(length(min = 1, max = 128))]
    name: String,
    /// Absolute directory path. The root itself must not be a symbolic link.
    path: PathBuf,
    /// If true, every grant on this share is effectively read-only.
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    grants: Vec<RawGrant>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RawGrant {
    #[schemars(length(min = 1, max = 64))]
    user: String,
    permission: Permission,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Read,
    Write,
}

pub struct Config {
    source: PathBuf,
    server: ServerConfig,
    users: Vec<User>,
    shares: Vec<Share>,
    session_secret: Vec<u8>,
}

impl fmt::Debug for Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Config")
            .field("source", &self.source)
            .field("server", &self.server)
            .field("users", &self.users)
            .field("shares", &self.shares)
            .field("session_secret", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    listen: SocketAddr,
    database_path: PathBuf,
    session_secret_file: PathBuf,
    max_upload_size: u64,
    max_preview_size: u64,
    auth_max_concurrent: usize,
    session_idle_timeout_seconds: u64,
    session_absolute_timeout_seconds: u64,
    login_attempts_per_minute: u32,
    max_sessions_per_user: usize,
    max_sessions_total: usize,
}

#[derive(Clone)]
pub struct User {
    username: String,
    password_hash: String,
    disabled: bool,
}

impl fmt::Debug for User {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("User")
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct Share {
    id: String,
    name: String,
    root: PathBuf,
    read_only: bool,
    grants: HashMap<String, Permission>,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let requested_path = path.as_ref();
        let source = fs::canonicalize(requested_path).map_err(|source| ConfigError::Read {
            path: requested_path.to_path_buf(),
            source,
        })?;
        let text = fs::read_to_string(&source).map_err(|source_error| ConfigError::Read {
            path: source.clone(),
            source: source_error,
        })?;
        let value =
            toml::from_str::<toml::Value>(&text).map_err(|error| ConfigError::TomlSyntax {
                location: safe_location(&text, error.span()),
            })?;
        let raw: RawConfig =
            value
                .try_into()
                .map_err(|error: toml::de::Error| ConfigError::Schema {
                    location: safe_location(&text, error.span()),
                })?;
        Self::validate(source, raw)
    }

    fn validate(source: PathBuf, raw: RawConfig) -> Result<Self, ConfigError> {
        if raw.version != CONFIG_VERSION {
            return Err(ConfigError::UnsupportedVersion(raw.version));
        }

        let base = source.parent().unwrap_or_else(|| Path::new("/"));
        let listen = raw.server.listen.parse::<SocketAddr>().map_err(|_| {
            ConfigError::Validation("server.listen must be an IP socket address".into())
        })?;
        let max_upload_size = parse_size(&raw.server.max_upload_size).map_err(|reason| {
            ConfigError::Validation(format!("server.max_upload_size {reason}"))
        })?;
        let max_preview_size = parse_size(&raw.server.max_preview_size).map_err(|reason| {
            ConfigError::Validation(format!("server.max_preview_size {reason}"))
        })?;
        if max_preview_size > max_upload_size {
            return Err(ConfigError::Validation(
                "server.max_preview_size must not exceed server.max_upload_size".into(),
            ));
        }
        if !(1..=16).contains(&raw.server.auth_max_concurrent) {
            return Err(ConfigError::Validation(
                "server.auth_max_concurrent must be between 1 and 16".into(),
            ));
        }
        if !(60..=86_400).contains(&raw.server.session_idle_timeout_seconds) {
            return Err(ConfigError::Validation(
                "server.session_idle_timeout_seconds must be between 60 and 86400".into(),
            ));
        }
        if !(300..=2_592_000).contains(&raw.server.session_absolute_timeout_seconds) {
            return Err(ConfigError::Validation(
                "server.session_absolute_timeout_seconds must be between 300 and 2592000".into(),
            ));
        }
        if raw.server.session_idle_timeout_seconds > raw.server.session_absolute_timeout_seconds {
            return Err(ConfigError::Validation(
                "server.session_idle_timeout_seconds must not exceed server.session_absolute_timeout_seconds".into(),
            ));
        }
        if !(1..=1_000).contains(&raw.server.login_attempts_per_minute) {
            return Err(ConfigError::Validation(
                "server.login_attempts_per_minute must be between 1 and 1000".into(),
            ));
        }
        if !(1..=256).contains(&raw.server.max_sessions_per_user) {
            return Err(ConfigError::Validation(
                "server.max_sessions_per_user must be between 1 and 256".into(),
            ));
        }
        if !(raw.server.max_sessions_per_user..=100_000).contains(&raw.server.max_sessions_total) {
            return Err(ConfigError::Validation(
                "server.max_sessions_total must be between max_sessions_per_user and 100000".into(),
            ));
        }

        let database_path = resolve_path(base, &raw.server.database_path);
        let database_path = validate_database_path(&database_path)?;
        let session_secret_file = resolve_path(base, &raw.server.session_secret_file);
        let (session_secret_file, session_secret) = read_session_secret(&session_secret_file)?;

        let mut usernames = HashSet::new();
        let mut users = Vec::with_capacity(raw.users.len());
        if raw.users.is_empty() {
            return Err(ConfigError::Validation(
                "at least one user must be configured".into(),
            ));
        }
        for user in raw.users {
            validate_identifier("username", &user.username)?;
            if !usernames.insert(user.username.clone()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate username {:?}",
                    user.username
                )));
            }
            validate_password_hash(&user.password_hash).map_err(|reason| {
                ConfigError::Validation(format!(
                    "password_hash for user {:?} {reason}",
                    user.username
                ))
            })?;
            users.push(User {
                username: user.username,
                password_hash: user.password_hash,
                disabled: user.disabled,
            });
        }

        let mut share_ids = HashSet::new();
        let mut shares = Vec::with_capacity(raw.shares.len());
        for share in raw.shares {
            validate_identifier("share id", &share.id)?;
            validate_display_name(&share.id, &share.name)?;
            if !share_ids.insert(share.id.clone()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate share id {:?}",
                    share.id
                )));
            }
            let root = validate_share_root(&share.id, &share.path)?;
            let mut grants = HashMap::new();
            for grant in share.grants {
                if !usernames.contains(&grant.user) {
                    return Err(ConfigError::Validation(format!(
                        "share {:?} grants access to unknown user {:?}",
                        share.id, grant.user
                    )));
                }
                if grants
                    .insert(grant.user.clone(), grant.permission)
                    .is_some()
                {
                    return Err(ConfigError::Validation(format!(
                        "share {:?} has duplicate grants for user {:?}",
                        share.id, grant.user
                    )));
                }
            }
            shares.push(Share {
                id: share.id,
                name: share.name,
                root,
                read_only: share.read_only,
                grants,
            });
        }
        reject_overlapping_roots(&shares)?;
        reject_sensitive_paths_inside_shares(
            &shares,
            &source,
            &database_path,
            &session_secret_file,
        )?;

        Ok(Self {
            source,
            server: ServerConfig {
                listen,
                database_path,
                session_secret_file,
                max_upload_size,
                max_preview_size,
                auth_max_concurrent: raw.server.auth_max_concurrent,
                session_idle_timeout_seconds: raw.server.session_idle_timeout_seconds,
                session_absolute_timeout_seconds: raw.server.session_absolute_timeout_seconds,
                login_attempts_per_minute: raw.server.login_attempts_per_minute,
                max_sessions_per_user: raw.server.max_sessions_per_user,
                max_sessions_total: raw.server.max_sessions_total,
            },
            users,
            shares,
            session_secret,
        })
    }

    pub fn source(&self) -> &Path {
        &self.source
    }

    pub fn server(&self) -> &ServerConfig {
        &self.server
    }

    pub fn users(&self) -> &[User] {
        &self.users
    }

    pub fn shares(&self) -> &[Share] {
        &self.shares
    }

    pub fn session_secret(&self) -> &[u8] {
        &self.session_secret
    }

    pub fn schema_json() -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&schema_for!(RawConfig))
    }
}

impl ServerConfig {
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub fn session_secret_file(&self) -> &Path {
        &self.session_secret_file
    }

    pub fn max_upload_size(&self) -> u64 {
        self.max_upload_size
    }

    pub fn max_preview_size(&self) -> u64 {
        self.max_preview_size
    }

    pub fn auth_max_concurrent(&self) -> usize {
        self.auth_max_concurrent
    }

    pub fn session_idle_timeout_seconds(&self) -> u64 {
        self.session_idle_timeout_seconds
    }

    pub fn session_absolute_timeout_seconds(&self) -> u64 {
        self.session_absolute_timeout_seconds
    }

    pub fn login_attempts_per_minute(&self) -> u32 {
        self.login_attempts_per_minute
    }

    pub fn max_sessions_per_user(&self) -> usize {
        self.max_sessions_per_user
    }

    pub fn max_sessions_total(&self) -> usize {
        self.max_sessions_total
    }
}

impl User {
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password_hash(&self) -> &str {
        &self.password_hash
    }

    pub fn disabled(&self) -> bool {
        self.disabled
    }
}

const fn default_auth_max_concurrent() -> usize {
    1
}

const fn default_session_idle_timeout_seconds() -> u64 {
    1_800
}

const fn default_session_absolute_timeout_seconds() -> u64 {
    43_200
}

const fn default_login_attempts_per_minute() -> u32 {
    5
}

const fn default_max_sessions_per_user() -> usize {
    16
}

const fn default_max_sessions_total() -> usize {
    4_096
}

impl Share {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    pub fn permission_for(&self, username: &str) -> Option<Permission> {
        self.grants.get(username).map(|permission| {
            if self.read_only {
                Permission::Read
            } else {
                *permission
            }
        })
    }
}

fn safe_location(source: &str, span: Option<std::ops::Range<usize>>) -> String {
    let Some(span) = span else {
        return String::new();
    };
    let offset = span.start.min(source.len());
    let prefix = &source[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix.len() + 1, |(_, tail)| tail.len() + 1);
    format!(" near line {line}, column {column}")
}

fn resolve_path(base: &Path, path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn validate_identifier(kind: &str, value: &str) -> Result<(), ConfigError> {
    let valid = (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid && value != "." && value != ".." {
        Ok(())
    } else {
        Err(ConfigError::Validation(format!(
            "{kind} must contain 1 to 64 ASCII letters, digits, dots, underscores, or hyphens"
        )))
    }
}

fn validate_display_name(id: &str, name: &str) -> Result<(), ConfigError> {
    let length = name.chars().count();
    if !(1..=128).contains(&length) || name.trim() != name || name.chars().any(char::is_control) {
        return Err(ConfigError::Validation(format!(
            "display name for share {id:?} must contain 1 to 128 characters, no control characters, and no leading or trailing whitespace"
        )));
    }
    Ok(())
}

fn validate_password_hash(hash: &str) -> Result<(), &'static str> {
    let parsed = PasswordHash::new(hash).map_err(|_| "is not a valid PHC string")?;
    if parsed.algorithm.as_str() != "argon2id" {
        return Err("uses an unsupported algorithm; only Argon2id is accepted");
    }
    if parsed.version.map(|version| version.to_string()).as_deref() != Some("19") {
        return Err("uses an unsupported Argon2 version; only version 19 is accepted");
    }
    if parsed.salt.is_none() || parsed.hash.is_none() {
        return Err("must include both a salt and a hash output");
    }
    Params::try_from(&parsed).map_err(|_| "contains unsupported Argon2 parameters")?;
    let Some(memory) = parsed.params.get_decimal("m") else {
        return Err("must include numeric m, t, and p parameters");
    };
    let Some(iterations) = parsed.params.get_decimal("t") else {
        return Err("must include numeric m, t, and p parameters");
    };
    let Some(parallelism) = parsed.params.get_decimal("p") else {
        return Err("must include numeric m, t, and p parameters");
    };
    if !(19_456..=262_144).contains(&memory)
        || !(2..=10).contains(&iterations)
        || !(1..=16).contains(&parallelism)
    {
        return Err("uses unsupported work factors (m: 19456..262144 KiB, t: 2..10, p: 1..16)");
    }
    Ok(())
}

pub fn parse_size(value: &str) -> Result<u64, &'static str> {
    let trimmed = value.trim();
    let split_at = trimmed
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (number, unit) = trimmed.split_at(split_at);
    if number.is_empty() || unit.starts_with(char::is_numeric) {
        return Err("must be a positive integer followed by B, KiB, MiB, or GiB");
    }
    let number = number
        .parse::<u64>()
        .map_err(|_| "must contain a valid integer")?;
    if number == 0 {
        return Err("must be greater than zero");
    }
    let multiplier = match unit.trim().to_ascii_lowercase().as_str() {
        "b" => 1,
        "kib" => 1024,
        "mib" => 1024 * 1024,
        "gib" => 1024 * 1024 * 1024,
        _ => return Err("must use one of the units B, KiB, MiB, or GiB"),
    };
    number
        .checked_mul(multiplier)
        .ok_or("is too large to represent")
}

fn reject_symlink_if_present(path: &Path, field: &str) -> Result<(), ConfigError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(ConfigError::Validation(format!(
            "{field} must not be a symbolic link"
        ))),
        Ok(_) | Err(_) => Ok(()),
    }
}

fn validate_database_path(path: &Path) -> Result<PathBuf, ConfigError> {
    reject_symlink_if_present(path, "server.database_path")?;
    let Some(parent) = path.parent() else {
        return Err(ConfigError::Validation(
            "server.database_path must have a parent directory".into(),
        ));
    };
    let parent = fs::canonicalize(parent).map_err(|_| {
        ConfigError::Validation(
            "parent directory of server.database_path is missing or unreadable".into(),
        )
    })?;
    if !parent.is_dir() {
        return Err(ConfigError::Validation(
            "parent of server.database_path is not a directory".into(),
        ));
    }
    let file_name = path.file_name().ok_or_else(|| {
        ConfigError::Validation("server.database_path must name a SQLite file".into())
    })?;
    let resolved = parent.join(file_name);
    if path.exists() {
        let metadata = fs::metadata(&resolved)
            .map_err(|_| ConfigError::Validation("server.database_path is unreadable".into()))?;
        if !metadata.is_file() {
            return Err(ConfigError::Validation(
                "server.database_path is not a regular file".into(),
            ));
        }
        fs::canonicalize(&resolved).map_err(|_| {
            ConfigError::Validation("server.database_path cannot be canonicalized".into())
        })
    } else {
        Ok(resolved)
    }
}

fn read_session_secret(path: &Path) -> Result<(PathBuf, Vec<u8>), ConfigError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        ConfigError::Validation("server.session_secret_file is missing or unreadable".into())
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ConfigError::Validation(
            "server.session_secret_file must be a regular file, not a symbolic link".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(ConfigError::Validation(
                "server.session_secret_file must not be writable by group or other users".into(),
            ));
        }
    }
    let secret = fs::read(path).map_err(|_| {
        ConfigError::Validation("server.session_secret_file is missing or unreadable".into())
    })?;
    if !(MIN_SESSION_SECRET_BYTES..=MAX_SESSION_SECRET_BYTES).contains(&secret.len()) {
        return Err(ConfigError::Validation(format!(
            "server.session_secret_file must contain {MIN_SESSION_SECRET_BYTES} to {MAX_SESSION_SECRET_BYTES} bytes"
        )));
    }
    let canonical = fs::canonicalize(path).map_err(|_| {
        ConfigError::Validation("server.session_secret_file cannot be canonicalized".into())
    })?;
    Ok((canonical, secret))
}

fn validate_share_root(id: &str, configured: &Path) -> Result<PathBuf, ConfigError> {
    if !configured.is_absolute() {
        return Err(ConfigError::Validation(format!(
            "root for share {id:?} must be an absolute path"
        )));
    }
    let metadata = fs::symlink_metadata(configured).map_err(|_| {
        ConfigError::Validation(format!(
            "root for share {id:?} is missing or cannot be inspected"
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(ConfigError::Validation(format!(
            "root for share {id:?} must not be a symbolic link"
        )));
    }
    if !metadata.is_dir() {
        return Err(ConfigError::Validation(format!(
            "root for share {id:?} is not a directory"
        )));
    }
    let canonical = fs::canonicalize(configured).map_err(|_| {
        ConfigError::Validation(format!("root for share {id:?} cannot be canonicalized"))
    })?;
    if canonical.parent().is_none() {
        return Err(ConfigError::Validation(format!(
            "root for share {id:?} cannot be the filesystem root"
        )));
    }
    Ok(canonical)
}

fn reject_overlapping_roots(shares: &[Share]) -> Result<(), ConfigError> {
    for (index, first) in shares.iter().enumerate() {
        for second in shares.iter().skip(index + 1) {
            if first.root.starts_with(&second.root) || second.root.starts_with(&first.root) {
                return Err(ConfigError::Validation(format!(
                    "share roots {:?} and {:?} overlap",
                    first.id, second.id
                )));
            }
        }
    }
    Ok(())
}

fn reject_sensitive_paths_inside_shares(
    shares: &[Share],
    config: &Path,
    database: &Path,
    secret: &Path,
) -> Result<(), ConfigError> {
    for share in shares {
        for (label, path) in [
            ("configuration file", config),
            ("database", database),
            ("session secret", secret),
        ] {
            if path.starts_with(&share.root) {
                return Err(ConfigError::Validation(format!(
                    "{label} must not be located inside share {:?}",
                    share.id
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use proptest::prelude::*;
    use tempfile::TempDir;

    use super::*;

    const HASH: &str =
        "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

    struct TestTree {
        _temp: TempDir,
        config: PathBuf,
        root: PathBuf,
    }

    impl TestTree {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("share");
            fs::create_dir(&root).unwrap();
            fs::write(temp.path().join("session.key"), [7; 32]).unwrap();
            let config = temp.path().join("config.toml");
            Self {
                _temp: temp,
                config,
                root,
            }
        }

        fn valid_text(&self) -> String {
            format!(
                r#"version = 1
[server]
listen = "127.0.0.1:8080"
database_path = "index.sqlite3"
session_secret_file = "session.key"
max_upload_size = "10 MiB"
max_preview_size = "1 MiB"

[[users]]
username = "alice"
password_hash = "{HASH}"

[[shares]]
id = "files"
name = "Files"
path = {:?}
read_only = false

[[shares.grants]]
user = "alice"
permission = "write"
"#,
                self.root
            )
        }

        fn load(&self, text: &str) -> Result<Config, ConfigError> {
            fs::write(&self.config, text).unwrap();
            Config::load(&self.config)
        }
    }

    #[test]
    fn loads_valid_config_and_applies_share_read_only() {
        let tree = TestTree::new();
        let text = tree
            .valid_text()
            .replace("read_only = false", "read_only = true");
        let config = tree.load(&text).unwrap();
        assert_eq!(config.server().max_upload_size(), 10 * 1024 * 1024);
        assert_eq!(config.server().auth_max_concurrent(), 1);
        assert_eq!(config.server().session_idle_timeout_seconds(), 1_800);
        assert_eq!(config.server().session_absolute_timeout_seconds(), 43_200);
        assert_eq!(config.server().login_attempts_per_minute(), 5);
        assert_eq!(config.server().max_sessions_per_user(), 16);
        assert_eq!(config.server().max_sessions_total(), 4_096);
        assert!(!config.users()[0].disabled());
        assert_eq!(config.shares()[0].id(), "files");
        assert_eq!(config.shares()[0].name(), "Files");
        assert_eq!(
            config.shares()[0].permission_for("alice"),
            Some(Permission::Read)
        );
        assert_eq!(config.shares()[0].permission_for("bob"), None);
        assert!(!format!("{config:?}").contains(HASH));
    }

    #[test]
    fn rejects_unknown_fields_without_leaking_hash() {
        let tree = TestTree::new();
        let text = tree
            .valid_text()
            .replace("password_hash =", "mystery = true\npassword_hash =");
        let error = tree.load(&text).unwrap_err().to_string();
        assert!(!error.contains(HASH));
        assert!(error.contains("schema"));
    }

    #[test]
    fn rejects_symlink_share_root() {
        let tree = TestTree::new();
        let link = tree._temp.path().join("link");
        symlink(&tree.root, &link).unwrap();
        let text = tree
            .valid_text()
            .replace(&format!("{:?}", tree.root), &format!("{link:?}"));
        assert!(
            tree.load(&text)
                .unwrap_err()
                .to_string()
                .contains("symbolic link")
        );
    }

    #[test]
    fn schema_is_json_and_mentions_version() {
        let schema = Config::schema_json().unwrap();
        let schema = serde_json::from_str::<serde_json::Value>(&schema).unwrap();
        assert_eq!(
            schema.pointer("/properties/version/minimum"),
            Some(&1.into())
        );
        assert_eq!(
            schema.pointer("/properties/version/maximum"),
            Some(&1.into())
        );
        let committed =
            serde_json::from_str::<serde_json::Value>(include_str!("../config.schema.json"))
                .unwrap();
        assert_eq!(
            schema, committed,
            "config.schema.json must match the CLI schema"
        );
    }

    #[test]
    fn secret_may_be_read_only_but_not_group_or_world_writable() {
        use std::os::unix::fs::PermissionsExt;

        let read_only = TestTree::new();
        let secret = read_only._temp.path().join("session.key");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(read_only.load(&read_only.valid_text()).is_ok());

        let writable = TestTree::new();
        let secret = writable._temp.path().join("session.key");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o664)).unwrap();
        assert!(
            writable
                .load(&writable.valid_text())
                .unwrap_err()
                .to_string()
                .contains("writable by group or other users")
        );
    }

    #[test]
    fn display_name_rejects_control_characters() {
        let tree = TestTree::new();
        let text = tree
            .valid_text()
            .replace("name = \"Files\"", "name = \"Files\\u0007\"");
        assert!(
            tree.load(&text)
                .unwrap_err()
                .to_string()
                .contains("no control characters")
        );
    }

    #[test]
    fn authentication_resource_limits_are_bounded() {
        let tree = TestTree::new();
        let invalid_concurrency = tree.valid_text().replace(
            "max_preview_size = \"1 MiB\"",
            "max_preview_size = \"1 MiB\"\nauth_max_concurrent = 0",
        );
        assert!(
            tree.load(&invalid_concurrency)
                .unwrap_err()
                .to_string()
                .contains("auth_max_concurrent")
        );

        let invalid_timeouts = tree.valid_text().replace(
            "max_preview_size = \"1 MiB\"",
            "max_preview_size = \"1 MiB\"\nsession_idle_timeout_seconds = 600\nsession_absolute_timeout_seconds = 300",
        );
        assert!(
            tree.load(&invalid_timeouts)
                .unwrap_err()
                .to_string()
                .contains("must not exceed")
        );

        let invalid_session_caps = tree.valid_text().replace(
            "max_preview_size = \"1 MiB\"",
            "max_preview_size = \"1 MiB\"\nmax_sessions_per_user = 20\nmax_sessions_total = 10",
        );
        assert!(
            tree.load(&invalid_session_caps)
                .unwrap_err()
                .to_string()
                .contains("max_sessions_total")
        );
    }

    proptest! {
        #[test]
        fn parsed_sizes_match_binary_units(value in 1_u64..1_000_000, unit in prop::sample::select(vec![("B", 1_u64), ("KiB", 1024), ("MiB", 1024 * 1024), ("GiB", 1024 * 1024 * 1024)])) {
            prop_assert_eq!(parse_size(&format!("{} {}", value, unit.0)), value.checked_mul(unit.1).ok_or("is too large to represent"));
        }

        #[test]
        fn malformed_sizes_are_rejected(value in "[^0-9][ -~]{0,20}") {
            prop_assert!(parse_size(&value).is_err());
        }

        #[test]
        fn duplicate_users_are_always_rejected(username in "[a-z][a-z0-9_-]{0,20}") {
            let tree = TestTree::new();
            let duplicate = format!("\n[[users]]\nusername = {username:?}\npassword_hash = {HASH:?}\n");
            let text = tree.valid_text().replace("username = \"alice\"", &format!("username = {username:?}")) + &duplicate;
            prop_assert!(tree.load(&text).unwrap_err().to_string().contains("duplicate username"));
        }

        #[test]
        fn dangling_grants_are_always_rejected(username in "[a-z][a-z0-9_-]{0,20}".prop_filter("must differ", |name| name != "alice")) {
            let tree = TestTree::new();
            let text = tree.valid_text().replace("user = \"alice\"", &format!("user = {username:?}"));
            prop_assert!(tree.load(&text).unwrap_err().to_string().contains("unknown user"));
        }
    }
}
