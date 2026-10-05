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

use crate::{client_address::IpNetwork, filesystem::ShareId};

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
    #[error("invalid TOML in configuration file{location}; consult `crabinet print-config-schema`")]
    TomlSyntax { location: String },
    #[error(
        "configuration does not match the version 1 schema{location}; consult `crabinet print-config-schema`"
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
    auth: RawAuthConfig,
    #[serde(default)]
    #[schemars(length(min = 1))]
    users: Vec<RawUser>,
    #[serde(default)]
    shares: Vec<RawShare>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RawAuthConfig {
    #[serde(default = "default_true")]
    password_enabled: bool,
    #[serde(default)]
    oidc_enabled: bool,
    oidc: Option<RawOidcConfig>,
    passkeys: Option<RawPasskeyConfig>,
    /// Show Gravatar images for users without an OIDC picture. Browsers then
    /// send a hash of the configured email address to gravatar.com.
    #[serde(default)]
    gravatar_enabled: bool,
}

impl Default for RawAuthConfig {
    fn default() -> Self {
        Self {
            password_enabled: true,
            oidc_enabled: false,
            oidc: None,
            passkeys: None,
            gravatar_enabled: false,
        }
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RawPasskeyConfig {
    /// Public HTTPS origin where browsers access Crabinet.
    origin: String,
}

const fn default_true() -> bool {
    true
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RawOidcConfig {
    issuer: String,
    client_id: String,
    client_secret_file: PathBuf,
    redirect_uri: String,
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
    /// Largest text, code, Markdown, HTML, or SVG file previewed whole, for example "2 MiB"; a larger one previews only its first 64 KiB and 1,000 lines. Streamed images, PDF, audio, and video are not bound by it.
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
    /// Password sign-in attempts allowed from one source address each minute,
    /// counted across all usernames and checked before any password hashing.
    /// IPv6 sources are grouped by /64.
    #[serde(default = "default_login_attempts_per_source_per_minute")]
    #[schemars(range(min = 1, max = 10_000))]
    login_attempts_per_source_per_minute: u32,
    /// Reverse proxy addresses or CIDR ranges, such as "192.0.2.10" or
    /// "2001:db8::/64", whose `trusted_proxy_header` names the client. Empty,
    /// the default, ignores forwarding headers and uses the TCP peer.
    #[serde(default)]
    #[schemars(length(max = 64))]
    trusted_proxies: Vec<String>,
    /// Forwarding header a trusted proxy sets to name the client.
    #[serde(default)]
    trusted_proxy_header: ForwardedHeader,
    /// Maximum simultaneously active sessions retained for one user.
    #[serde(default = "default_max_sessions_per_user")]
    #[schemars(range(min = 1, max = 256))]
    max_sessions_per_user: usize,
    /// Maximum simultaneously active sessions retained across all users.
    #[serde(default = "default_max_sessions_total")]
    #[schemars(range(min = 1, max = 100_000))]
    max_sessions_total: usize,
    /// Number of days before an item in Trash is eligible for permanent removal.
    #[serde(default = "default_trash_retention_days")]
    #[schemars(range(min = 1, max = 3650))]
    trash_retention_days: u16,
    /// Maximum simultaneously open client connections; new connections above it are closed.
    #[serde(default = "default_max_connections")]
    #[schemars(range(min = 1, max = 65_535))]
    max_connections: usize,
    /// Seconds to send a complete request head, also bounding keep-alive idle time.
    #[serde(default = "default_header_read_timeout_seconds")]
    #[schemars(range(min = 5, max = 3_600))]
    header_read_timeout_seconds: u64,
    /// Total memory, for example "256 MiB", that image thumbnail decodes may
    /// reserve at once, at most "4 GiB". Each decode reserves its estimated
    /// peak first; an image whose estimate exceeds the whole budget is not
    /// thumbnailed.
    #[serde(default = "default_max_image_decode_memory")]
    max_image_decode_memory: String,
    /// Directory for cached thumbnails, created with owner-only permissions.
    /// Relative paths are resolved from the configuration directory. Defaults
    /// to `thumbnails` next to `database_path`.
    #[serde(default)]
    thumbnail_cache_path: Option<PathBuf>,
    /// Maximum total size of cached thumbnails, for example "256 MiB", at most
    /// "64 GiB". The oldest entries are evicted beyond it; "0 B" disables the
    /// cache.
    #[serde(default = "default_max_thumbnail_cache_size")]
    max_thumbnail_cache_size: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RawUser {
    #[schemars(length(min = 1, max = 64))]
    username: String,
    /// An Argon2id PHC string produced by `crabinet hash-password`.
    password_hash: Option<String>,
    /// Email returned as a verified claim by the configured OIDC provider.
    email: Option<String>,
    /// Optional OIDC `sub` claim this user's ID token must carry in addition
    /// to the verified email. Requires `email`.
    #[schemars(length(min = 1, max = 255))]
    oidc_subject: Option<String>,
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

/// Header from which a trusted reverse proxy's client address is read.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ForwardedHeader {
    /// `X-Forwarded-For: client, proxy1, proxy2`.
    #[default]
    XForwardedFor,
    /// RFC 7239 `Forwarded: for=client, for=proxy1`.
    Forwarded,
}

pub struct Config {
    source: PathBuf,
    server: ServerConfig,
    auth: AuthConfig,
    users: Vec<User>,
    shares: Vec<Share>,
    session_secret: Vec<u8>,
}

#[derive(Clone)]
pub struct AuthConfig {
    password_enabled: bool,
    oidc: Option<OidcConfig>,
    passkeys_origin: Option<url::Url>,
    gravatar_enabled: bool,
}

#[derive(Clone)]
pub struct OidcConfig {
    issuer: String,
    client_id: String,
    client_secret: String,
    client_secret_file: PathBuf,
    redirect_uri: String,
}

impl fmt::Debug for OidcConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthConfig")
            .field("password_enabled", &self.password_enabled)
            .field("oidc", &self.oidc)
            .field("passkeys_origin", &self.passkeys_origin)
            .field("gravatar_enabled", &self.gravatar_enabled)
            .finish()
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Config")
            .field("source", &self.source)
            .field("server", &self.server)
            .field("auth", &self.auth)
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
    login_attempts_per_source_per_minute: u32,
    trusted_proxies: Vec<IpNetwork>,
    trusted_proxy_header: ForwardedHeader,
    max_sessions_per_user: usize,
    max_sessions_total: usize,
    trash_retention_days: u16,
    max_connections: usize,
    header_read_timeout_seconds: u64,
    max_image_decode_memory: u64,
    thumbnail_cache_path: Option<PathBuf>,
    max_thumbnail_cache_size: u64,
}

#[derive(Clone)]
pub struct User {
    username: String,
    password_hash: Option<String>,
    email: Option<String>,
    oidc_subject: Option<String>,
    disabled: bool,
}

impl fmt::Debug for User {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("User")
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .field("email", &self.email)
            .field("oidc_subject", &self.oidc_subject)
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
    #[expect(
        clippy::disallowed_methods,
        reason = "startup-only: inspects operator-trusted configuration paths before serving requests"
    )]
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let requested_path = path.as_ref();
        // nosemgrep: crabinet-ambient-filesystem-path
        let source = fs::canonicalize(requested_path).map_err(|source| ConfigError::Read {
            path: requested_path.to_path_buf(),
            source,
        })?;
        // nosemgrep: crabinet-ambient-filesystem-path
        let text = fs::read_to_string(&source).map_err(|source_error| ConfigError::Read {
            path: source.clone(),
            source: source_error,
        })?;
        warn_if_shared(&source);
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
        if !(1..=10_000).contains(&raw.server.login_attempts_per_source_per_minute) {
            return Err(ConfigError::Validation(
                "server.login_attempts_per_source_per_minute must be between 1 and 10000".into(),
            ));
        }
        let trusted_proxies = validate_trusted_proxies(&raw.server.trusted_proxies)?;
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
        if !(1..=3650).contains(&raw.server.trash_retention_days) {
            return Err(ConfigError::Validation(
                "server.trash_retention_days must be between 1 and 3650".into(),
            ));
        }
        if !(1..=65_535).contains(&raw.server.max_connections) {
            return Err(ConfigError::Validation(
                "server.max_connections must be between 1 and 65535".into(),
            ));
        }
        if !(5..=3_600).contains(&raw.server.header_read_timeout_seconds) {
            return Err(ConfigError::Validation(
                "server.header_read_timeout_seconds must be between 5 and 3600".into(),
            ));
        }

        let max_image_decode_memory =
            parse_size(&raw.server.max_image_decode_memory).map_err(|reason| {
                ConfigError::Validation(format!("server.max_image_decode_memory {reason}"))
            })?;
        if max_image_decode_memory > crate::thumbnail::HARD_MAX_DECODE_MEMORY {
            return Err(ConfigError::Validation(
                "server.max_image_decode_memory must not exceed 4 GiB".into(),
            ));
        }
        let max_thumbnail_cache_size = parse_size_or_zero(&raw.server.max_thumbnail_cache_size)
            .map_err(|reason| {
                ConfigError::Validation(format!("server.max_thumbnail_cache_size {reason}"))
            })?;
        if max_thumbnail_cache_size > crate::thumbnail::HARD_MAX_CACHE_BYTES {
            return Err(ConfigError::Validation(
                "server.max_thumbnail_cache_size must not exceed 64 GiB".into(),
            ));
        }

        let database_path = resolve_path(base, &raw.server.database_path);
        let database_path = validate_database_path(&database_path)?;
        let thumbnail_cache_path = if max_thumbnail_cache_size == 0 {
            None
        } else {
            let requested = match &raw.server.thumbnail_cache_path {
                Some(path) => resolve_path(base, path),
                None => database_path
                    .parent()
                    .unwrap_or_else(|| Path::new("/"))
                    .join("thumbnails"),
            };
            Some(validate_thumbnail_cache_path(&requested)?)
        };
        let session_secret_file = resolve_path(base, &raw.server.session_secret_file);
        let (session_secret_file, session_secret) = read_session_secret(&session_secret_file)?;

        if !raw.auth.password_enabled && !raw.auth.oidc_enabled {
            return Err(ConfigError::Validation(
                "both password and OIDC sign-in are disabled".into(),
            ));
        }
        if raw.auth.oidc_enabled != raw.auth.oidc.is_some() {
            return Err(ConfigError::Validation(
                "auth.oidc is required exactly when OIDC sign-in is enabled".into(),
            ));
        }
        let passkeys_origin = raw
            .auth
            .passkeys
            .map(|value| {
                let origin = validate_https_url(&value.origin, "auth.passkeys.origin")?;
                if origin.path() != "/" {
                    return Err(ConfigError::Validation(
                        "auth.passkeys.origin must have no path".into(),
                    ));
                }
                Ok(origin)
            })
            .transpose()?;
        let oidc = raw.auth.oidc.map(|value| {
            validate_https_url(&value.issuer, "auth.oidc.issuer")?;
            let redirect_uri = validate_https_url(&value.redirect_uri, "auth.oidc.redirect_uri")?;
            if redirect_uri.path() != "/api/v1/auth/oidc/callback" || redirect_uri.query().is_some() {
                return Err(ConfigError::Validation("auth.oidc.redirect_uri must use /api/v1/auth/oidc/callback without a query".into()));
            }
            if value.client_id.is_empty() || value.client_id.len() > 256 {
                return Err(ConfigError::Validation("auth.oidc.client_id must contain 1 to 256 bytes".into()));
            }
            let secret_path = resolve_path(base, &value.client_secret_file);
            let (client_secret_file, bytes) = read_secret_file(&secret_path, "auth.oidc.client_secret_file", 1, 4096)?;
            let client_secret = String::from_utf8(bytes).map_err(|_| ConfigError::Validation("auth.oidc.client_secret_file must contain UTF-8".into()))?;
            if client_secret.trim().is_empty() || client_secret.contains(['\n', '\r']) {
                return Err(ConfigError::Validation("auth.oidc.client_secret_file contains an invalid secret".into()));
            }
            Ok(OidcConfig { issuer: value.issuer, client_id: value.client_id, client_secret, client_secret_file, redirect_uri: redirect_uri.to_string() })
        }).transpose()?;

        let mut usernames = HashSet::new();
        let mut emails = HashSet::new();
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
            if let Some(hash) = &user.password_hash {
                validate_password_hash(hash).map_err(|reason| {
                    ConfigError::Validation(format!(
                        "password_hash for user {:?} {reason}",
                        user.username
                    ))
                })?;
            }
            let email = user
                .email
                .map(|email| {
                    let normalized = email.to_ascii_lowercase();
                    if email.trim() != email
                        || email.len() > 254
                        || !email.is_ascii()
                        || !email.contains('@')
                        || email.contains(char::is_whitespace)
                        || email.contains(['<', '>', ','])
                    {
                        return Err(ConfigError::Validation(format!(
                            "invalid email for user {:?}",
                            user.username
                        )));
                    }
                    if !emails.insert(normalized.clone()) {
                        return Err(ConfigError::Validation(format!(
                            "duplicate email for user {:?}",
                            user.username
                        )));
                    }
                    Ok(normalized)
                })
                .transpose()?;
            if let Some(subject) = &user.oidc_subject {
                validate_oidc_subject(&user.username, subject, email.is_some())?;
            }
            if !(user.disabled
                || raw.auth.password_enabled && user.password_hash.is_some()
                || oidc.is_some() && email.is_some())
            {
                return Err(ConfigError::Validation(format!(
                    "enabled user {:?} has no usable sign-in method",
                    user.username
                )));
            }
            users.push(User {
                username: user.username,
                password_hash: user.password_hash,
                email,
                oidc_subject: user.oidc_subject,
                disabled: user.disabled,
            });
        }
        if users.iter().any(|user| !user.disabled) {
            if raw.auth.password_enabled
                && !users
                    .iter()
                    .any(|user| !user.disabled && user.password_hash.is_some())
            {
                return Err(ConfigError::Validation(
                    "password sign-in is enabled but no enabled user has a password".into(),
                ));
            }
            if oidc.is_some()
                && !users
                    .iter()
                    .any(|user| !user.disabled && user.email.is_some())
            {
                return Err(ConfigError::Validation(
                    "OIDC sign-in is enabled but no enabled user has an email".into(),
                ));
            }
        }

        let mut share_ids = HashSet::new();
        let mut shares = Vec::with_capacity(raw.shares.len());
        for share in raw.shares {
            validate_share_id(&share.id)?;
            if RESERVED_SHARE_IDS
                .iter()
                .any(|reserved| share.id.eq_ignore_ascii_case(reserved))
            {
                return Err(ConfigError::Validation(format!(
                    "share id {:?} is reserved because it is a top-level URL of the app",
                    share.id
                )));
            }
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
            oidc.as_ref()
                .map(|value| value.client_secret_file.as_path()),
        )?;
        if let Some(cache) = &thumbnail_cache_path {
            for share in &shares {
                if cache.starts_with(&share.root) || share.root.starts_with(cache) {
                    return Err(ConfigError::Validation(format!(
                        "server.thumbnail_cache_path must not overlap share {:?}",
                        share.id
                    )));
                }
            }
            for (label, path) in [
                ("configuration file", source.as_path()),
                ("database", database_path.as_path()),
                ("session secret", session_secret_file.as_path()),
            ] {
                if path.starts_with(cache) {
                    return Err(ConfigError::Validation(format!(
                        "the {label} must not be located inside server.thumbnail_cache_path"
                    )));
                }
            }
        }

        Ok(Self {
            source,
            auth: AuthConfig {
                password_enabled: raw.auth.password_enabled,
                oidc,
                passkeys_origin,
                gravatar_enabled: raw.auth.gravatar_enabled,
            },
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
                login_attempts_per_source_per_minute: raw
                    .server
                    .login_attempts_per_source_per_minute,
                trusted_proxies,
                trusted_proxy_header: raw.server.trusted_proxy_header,
                max_sessions_per_user: raw.server.max_sessions_per_user,
                max_sessions_total: raw.server.max_sessions_total,
                trash_retention_days: raw.server.trash_retention_days,
                max_connections: raw.server.max_connections,
                header_read_timeout_seconds: raw.server.header_read_timeout_seconds,
                max_image_decode_memory,
                thumbnail_cache_path,
                max_thumbnail_cache_size,
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

    pub fn auth(&self) -> &AuthConfig {
        &self.auth
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

    pub fn login_attempts_per_source_per_minute(&self) -> u32 {
        self.login_attempts_per_source_per_minute
    }

    pub fn trusted_proxies(&self) -> &[IpNetwork] {
        &self.trusted_proxies
    }

    pub fn trusted_proxy_header(&self) -> ForwardedHeader {
        self.trusted_proxy_header
    }

    pub fn max_sessions_per_user(&self) -> usize {
        self.max_sessions_per_user
    }

    pub fn max_sessions_total(&self) -> usize {
        self.max_sessions_total
    }

    pub fn trash_retention_days(&self) -> u16 {
        self.trash_retention_days
    }

    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    pub fn header_read_timeout_seconds(&self) -> u64 {
        self.header_read_timeout_seconds
    }

    pub fn max_image_decode_memory(&self) -> u64 {
        self.max_image_decode_memory
    }

    /// The thumbnail cache directory, or `None` when the cache is disabled.
    pub fn thumbnail_cache_path(&self) -> Option<&Path> {
        self.thumbnail_cache_path.as_deref()
    }

    pub fn max_thumbnail_cache_size(&self) -> u64 {
        self.max_thumbnail_cache_size
    }
}

impl User {
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password_hash(&self) -> Option<&str> {
        self.password_hash.as_deref()
    }

    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// The OIDC `sub` claim this user's ID token must carry, if bound.
    pub fn oidc_subject(&self) -> Option<&str> {
        self.oidc_subject.as_deref()
    }

    pub fn disabled(&self) -> bool {
        self.disabled
    }
}

impl AuthConfig {
    pub fn password_enabled(&self) -> bool {
        self.password_enabled
    }
    pub fn oidc(&self) -> Option<&OidcConfig> {
        self.oidc.as_ref()
    }
    pub fn passkeys_origin(&self) -> Option<&url::Url> {
        self.passkeys_origin.as_ref()
    }
    pub fn gravatar_enabled(&self) -> bool {
        self.gravatar_enabled
    }
}

impl OidcConfig {
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            issuer: "https://id.example.com".into(),
            client_id: "crabinet".into(),
            client_secret: "test-secret".into(),
            client_secret_file: PathBuf::from("test-secret"),
            redirect_uri: "https://files.example.com/api/v1/auth/oidc/callback".into(),
        }
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

const fn default_login_attempts_per_source_per_minute() -> u32 {
    20
}

const MAX_TRUSTED_PROXIES: usize = 64;

/// Parses `server.trusted_proxies`. A network covering every address would let
/// any client choose its own rate-limit source, so prefix length 0 is refused.
fn validate_trusted_proxies(entries: &[String]) -> Result<Vec<IpNetwork>, ConfigError> {
    if entries.len() > MAX_TRUSTED_PROXIES {
        return Err(ConfigError::Validation(format!(
            "server.trusted_proxies must list at most {MAX_TRUSTED_PROXIES} entries"
        )));
    }
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let network = IpNetwork::parse(entry).map_err(|reason| {
                ConfigError::Validation(format!("server.trusted_proxies[{index}] {reason}"))
            })?;
            if network.prefix() == 0 {
                return Err(ConfigError::Validation(format!(
                    "server.trusted_proxies[{index}] ({network}) trusts every address, which would let any client choose its own address; list only the reverse proxy's addresses"
                )));
            }
            Ok(network)
        })
        .collect()
}

const fn default_max_sessions_per_user() -> usize {
    16
}

const fn default_max_sessions_total() -> usize {
    4_096
}

const fn default_trash_retention_days() -> u16 {
    30
}

const fn default_max_connections() -> usize {
    1_024
}

const fn default_header_read_timeout_seconds() -> u64 {
    300
}

fn default_max_image_decode_memory() -> String {
    "256 MiB".into()
}

fn default_max_thumbnail_cache_size() -> String {
    "256 MiB".into()
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

    pub fn writable(&self) -> bool {
        !self.read_only
            && self
                .grants
                .values()
                .any(|permission| *permission == Permission::Write)
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

/// Share ids form the first URL segment (`/<share>/<path>`), so they must not
/// shadow server routes, embedded assets, legacy routes, or Vite dev paths.
/// Keep in sync with `reservedShareIds` in `web/src/navigation.ts`.
const RESERVED_SHARE_IDS: &[&str] = &[
    "api",
    "assets",
    "browse",
    "crabinet.png",
    "favicon.ico",
    "google-g.png",
    "health",
    "index.html",
    "node_modules",
    "src",
    "trash",
];

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

/// Share IDs must satisfy the same grammar the runtime enforces, so a
/// configuration `check-config` accepts can never fail at startup.
fn validate_share_id(value: &str) -> Result<(), ConfigError> {
    ShareId::new(value.to_owned()).map(drop).map_err(|_| {
        ConfigError::Validation(
            "share id must contain 1 to 64 ASCII letters, digits, dots, underscores, or hyphens and start with a letter or digit".into(),
        )
    })
}

/// An OIDC subject is an opaque, case-sensitive provider identifier of at
/// most 255 ASCII characters (OpenID Connect Core 1.0, section 2).
fn validate_oidc_subject(
    username: &str,
    subject: &str,
    has_email: bool,
) -> Result<(), ConfigError> {
    if subject.is_empty()
        || subject.len() > 255
        || !subject.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ConfigError::Validation(format!(
            "oidc_subject for user {username:?} must contain 1 to 255 printable ASCII characters without spaces"
        )));
    }
    if !has_email {
        return Err(ConfigError::Validation(format!(
            "oidc_subject for user {username:?} requires an email binding"
        )));
    }
    Ok(())
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

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_config_text(text: &str) {
    if let Ok(value) = toml::from_str::<toml::Value>(text) {
        let _ = value.try_into::<RawConfig>();
    }
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_password_hash_policy(hash: &str) {
    let _ = validate_password_hash(hash);
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

/// Like [`parse_size`], but zero (for example "0 B") is accepted and means
/// "disabled".
pub fn parse_size_or_zero(value: &str) -> Result<u64, &'static str> {
    let trimmed = value.trim();
    let digits = trimmed
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(trimmed.len());
    if digits > 0 && trimmed[..digits].bytes().all(|byte| byte == b'0') {
        let unit = trimmed[digits..].trim().to_ascii_lowercase();
        return if matches!(unit.as_str(), "b" | "kib" | "mib" | "gib") {
            Ok(0)
        } else {
            Err("must use one of the units B, KiB, MiB, or GiB")
        };
    }
    parse_size(value)
}

/// The thumbnail cache directory may not exist yet, but its parent must, and
/// neither may be a symbolic link. Startup creates it with mode 0700 and
/// refuses an existing directory that group or other users can access.
#[expect(
    clippy::disallowed_methods,
    reason = "startup-only: inspects operator-trusted configuration paths before serving requests"
)]
fn validate_thumbnail_cache_path(path: &Path) -> Result<PathBuf, ConfigError> {
    reject_symlink_if_present(path, "server.thumbnail_cache_path")?;
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(ConfigError::Validation(
            "server.thumbnail_cache_path must name a directory below an existing parent".into(),
        ));
    };
    // nosemgrep: crabinet-ambient-filesystem-path
    let parent = fs::canonicalize(parent).map_err(|_| {
        ConfigError::Validation(
            "parent directory of server.thumbnail_cache_path is missing or unreadable".into(),
        )
    })?;
    if !parent.is_dir() {
        return Err(ConfigError::Validation(
            "parent of server.thumbnail_cache_path is not a directory".into(),
        ));
    }
    let resolved = parent.join(name);
    // nosemgrep: crabinet-ambient-filesystem-path
    match fs::symlink_metadata(&resolved) {
        Ok(metadata) if !metadata.is_dir() => Err(ConfigError::Validation(
            "server.thumbnail_cache_path is not a directory".into(),
        )),
        _ => Ok(resolved),
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "startup-only: inspects operator-trusted configuration paths before serving requests"
)]
fn reject_symlink_if_present(path: &Path, field: &str) -> Result<(), ConfigError> {
    // nosemgrep: crabinet-ambient-filesystem-path
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(ConfigError::Validation(format!(
            "{field} must not be a symbolic link"
        ))),
        Ok(_) | Err(_) => Ok(()),
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "startup-only: inspects operator-trusted configuration paths before serving requests"
)]
fn validate_database_path(path: &Path) -> Result<PathBuf, ConfigError> {
    reject_symlink_if_present(path, "server.database_path")?;
    let Some(parent) = path.parent() else {
        return Err(ConfigError::Validation(
            "server.database_path must have a parent directory".into(),
        ));
    };
    // nosemgrep: crabinet-ambient-filesystem-path
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
    // nosemgrep: crabinet-ambient-filesystem-path
    if path.exists() {
        // nosemgrep: crabinet-ambient-filesystem-path
        let metadata = fs::metadata(&resolved)
            .map_err(|_| ConfigError::Validation("server.database_path is unreadable".into()))?;
        if !metadata.is_file() {
            return Err(ConfigError::Validation(
                "server.database_path is not a regular file".into(),
            ));
        }
        // nosemgrep: crabinet-ambient-filesystem-path
        fs::canonicalize(&resolved).map_err(|_| {
            ConfigError::Validation("server.database_path cannot be canonicalized".into())
        })
    } else {
        Ok(resolved)
    }
}

/// The configuration holds password hashes, so access by group or other
/// users is reported. It is a warning rather than an error because a
/// group-readable configuration was previously accepted silently.
#[cfg(unix)]
#[expect(
    clippy::disallowed_methods,
    reason = "startup-only: inspects the operator-trusted configuration file before serving requests"
)]
fn warn_if_shared(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    // nosemgrep: crabinet-ambient-filesystem-path
    if fs::metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o077 != 0) {
        let name = path
            .file_name()
            .map_or_else(|| "the file".into(), |name| name.to_string_lossy());
        tracing::warn!(
            "the configuration file is accessible by group or other users and contains password hashes; run `chmod 600 {name}` as its owner"
        );
    }
}

#[cfg(not(unix))]
fn warn_if_shared(_path: &Path) {}

fn read_session_secret(path: &Path) -> Result<(PathBuf, Vec<u8>), ConfigError> {
    read_secret_file(
        path,
        "server.session_secret_file",
        MIN_SESSION_SECRET_BYTES,
        MAX_SESSION_SECRET_BYTES,
    )
}

#[expect(
    clippy::disallowed_methods,
    reason = "startup-only: inspects operator-trusted configuration paths before serving requests"
)]
fn read_secret_file(
    path: &Path,
    field: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(PathBuf, Vec<u8>), ConfigError> {
    // nosemgrep: crabinet-ambient-filesystem-path
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ConfigError::Validation(format!("{field} is missing or unreadable")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ConfigError::Validation(format!(
            "{field} must be a regular file, not a symbolic link"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o077 != 0 {
            let name = path
                .file_name()
                .map_or_else(|| "the file".into(), |name| name.to_string_lossy());
            return Err(ConfigError::Validation(format!(
                "{field} must not be readable or writable by group or other users; run `chmod 600 {name}` as its owner"
            )));
        }
    }
    // nosemgrep: crabinet-ambient-filesystem-path
    let secret = fs::read(path)
        .map_err(|_| ConfigError::Validation(format!("{field} is missing or unreadable")))?;
    if !(minimum..=maximum).contains(&secret.len()) {
        return Err(ConfigError::Validation(format!(
            "{field} must contain {minimum} to {maximum} bytes"
        )));
    }
    // nosemgrep: crabinet-ambient-filesystem-path
    let canonical = fs::canonicalize(path)
        .map_err(|_| ConfigError::Validation(format!("{field} cannot be canonicalized")))?;
    Ok((canonical, secret))
}

fn validate_https_url(value: &str, field: &str) -> Result<url::Url, ConfigError> {
    let parsed = url::Url::parse(value)
        .map_err(|_| ConfigError::Validation(format!("{field} must be an HTTPS URL")))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || parsed.query().is_some()
    {
        return Err(ConfigError::Validation(format!(
            "{field} must be an HTTPS URL without credentials, query, or fragment"
        )));
    }
    Ok(parsed)
}

#[expect(
    clippy::disallowed_methods,
    reason = "startup-only: inspects operator-trusted configuration paths before serving requests"
)]
fn validate_share_root(id: &str, configured: &Path) -> Result<PathBuf, ConfigError> {
    if !configured.is_absolute() {
        return Err(ConfigError::Validation(format!(
            "root for share {id:?} must be an absolute path"
        )));
    }
    // nosemgrep: crabinet-ambient-filesystem-path
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
    // nosemgrep: crabinet-ambient-filesystem-path
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
    oidc_secret: Option<&Path>,
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
        if oidc_secret.is_some_and(|path| path.starts_with(&share.root)) {
            return Err(ConfigError::Validation(format!(
                "OIDC client secret must not be located inside share {:?}",
                share.id
            )));
        }
    }
    Ok(())
}

/// Writes a test secret with the owner-only mode startup requires.
#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "test-only: writes a synthetic secret in a temporary directory"
)]
pub(crate) fn write_private_file(path: &Path, contents: impl AsRef<[u8]>) {
    use std::os::unix::fs::PermissionsExt;

    // nosemgrep: crabinet-ambient-filesystem-path
    fs::write(path, contents).expect("write private test file");
    // nosemgrep: crabinet-ambient-filesystem-path
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("restrict test file");
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "unit tests build synthetic fixtures in temporary directories"
)]
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
            write_private_file(&temp.path().join("session.key"), [7; 32]);
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
database_path = "crabinet.sqlite3"
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
        assert_eq!(config.server().login_attempts_per_source_per_minute(), 20);
        assert!(config.server().trusted_proxies().is_empty());
        assert_eq!(
            config.server().trusted_proxy_header(),
            ForwardedHeader::XForwardedFor
        );
        assert_eq!(config.server().max_sessions_per_user(), 16);
        assert_eq!(config.server().max_sessions_total(), 4_096);
        assert_eq!(config.server().trash_retention_days(), 30);
        assert_eq!(config.server().max_connections(), 1_024);
        assert_eq!(config.server().header_read_timeout_seconds(), 300);
        assert!(!config.users()[0].disabled());
        assert_eq!(config.shares()[0].id(), "files");
        assert_eq!(config.shares()[0].name(), "Files");
        assert!(!config.shares()[0].writable());
        assert_eq!(
            config.shares()[0].permission_for("alice"),
            Some(Permission::Read)
        );
        assert_eq!(config.shares()[0].permission_for("bob"), None);
        assert!(!format!("{config:?}").contains(HASH));
    }

    #[test]
    fn trash_retention_is_configurable_and_bounded() {
        let tree = TestTree::new();
        let text = tree.valid_text().replace(
            "max_preview_size = \"1 MiB\"",
            "max_preview_size = \"1 MiB\"\ntrash_retention_days = 45",
        );
        assert_eq!(
            tree.load(&text).unwrap().server().trash_retention_days(),
            45
        );
        let invalid = text.replace("trash_retention_days = 45", "trash_retention_days = 0");
        assert!(tree.load(&invalid).is_err());
    }

    #[test]
    fn thumbnail_settings_have_defaults_and_bounds() {
        let tree = TestTree::new();
        let base = tree.config.parent().unwrap().canonicalize().unwrap();
        let config = tree.load(&tree.valid_text()).unwrap();
        assert_eq!(config.server().max_image_decode_memory(), 256 * 1024 * 1024);
        assert_eq!(
            config.server().max_thumbnail_cache_size(),
            256 * 1024 * 1024
        );
        assert_eq!(
            config.server().thumbnail_cache_path(),
            Some(base.join("thumbnails").as_path())
        );

        let with = |settings: &str| {
            tree.valid_text().replace(
                "max_preview_size = \"1 MiB\"",
                &format!("max_preview_size = \"1 MiB\"\n{settings}"),
            )
        };
        let custom = tree
            .load(&with(
                "max_image_decode_memory = \"64 MiB\"\nthumbnail_cache_path = \"cache/thumbs\"\nmax_thumbnail_cache_size = \"1 GiB\"",
            ))
            .err();
        assert!(custom.is_some(), "the parent of the cache path must exist");
        fs::create_dir(base.join("cache")).unwrap();
        let custom = tree
            .load(&with(
                "max_image_decode_memory = \"64 MiB\"\nthumbnail_cache_path = \"cache/thumbs\"\nmax_thumbnail_cache_size = \"1 GiB\"",
            ))
            .unwrap();
        assert_eq!(custom.server().max_image_decode_memory(), 64 * 1024 * 1024);
        assert_eq!(
            custom.server().thumbnail_cache_path(),
            Some(base.join("cache/thumbs").as_path())
        );
        let disabled = tree
            .load(&with("max_thumbnail_cache_size = \"0 B\""))
            .unwrap();
        assert_eq!(disabled.server().max_thumbnail_cache_size(), 0);
        assert_eq!(disabled.server().thumbnail_cache_path(), None);

        for invalid in [
            "max_image_decode_memory = \"0 B\"",
            "max_image_decode_memory = \"5 GiB\"",
            "max_image_decode_memory = \"lots\"",
            "max_thumbnail_cache_size = \"65 GiB\"",
            "max_thumbnail_cache_size = \"0 parsecs\"",
            "thumbnail_cache_path = \"share/thumbnails\"",
            "thumbnail_cache_path = \".\"",
            "thumbnail_cache_path = \"config.toml\"",
        ] {
            assert!(tree.load(&with(invalid)).is_err(), "{invalid}");
        }
        symlink(base.join("cache"), base.join("linked")).unwrap();
        assert!(
            tree.load(&with("thumbnail_cache_path = \"linked\""))
                .is_err()
        );
    }

    #[test]
    fn connection_limit_is_configurable_and_bounded() {
        let tree = TestTree::new();
        let text = tree.valid_text().replace(
            "max_preview_size = \"1 MiB\"",
            "max_preview_size = \"1 MiB\"\nmax_connections = 64",
        );
        assert_eq!(tree.load(&text).unwrap().server().max_connections(), 64);
        for invalid in ["max_connections = 0", "max_connections = 65536"] {
            let invalid = text.replace("max_connections = 64", invalid);
            assert!(tree.load(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn header_read_timeout_is_configurable_and_bounded() {
        let tree = TestTree::new();
        let text = tree.valid_text().replace(
            "max_preview_size = \"1 MiB\"",
            "max_preview_size = \"1 MiB\"\nheader_read_timeout_seconds = 30",
        );
        assert_eq!(
            tree.load(&text)
                .unwrap()
                .server()
                .header_read_timeout_seconds(),
            30
        );
        for valid in [5, 3_600] {
            let valid = text.replace(
                "header_read_timeout_seconds = 30",
                &format!("header_read_timeout_seconds = {valid}"),
            );
            assert!(tree.load(&valid).is_ok(), "{valid}");
        }
        for invalid in [0, 4, 3_601] {
            let invalid = text.replace(
                "header_read_timeout_seconds = 30",
                &format!("header_read_timeout_seconds = {invalid}"),
            );
            assert!(tree.load(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn rejects_impossible_authentication_settings() {
        let tree = TestTree::new();
        let both_disabled = tree.valid_text().replace(
            "[server]",
            "[auth]\npassword_enabled = false\noidc_enabled = false\n[server]",
        );
        assert!(
            tree.load(&both_disabled)
                .unwrap_err()
                .to_string()
                .contains("both password and OIDC")
        );

        let missing_oidc = tree.valid_text().replace(
            "[server]",
            "[auth]\npassword_enabled = false\noidc_enabled = true\n[server]",
        );
        assert!(
            tree.load(&missing_oidc)
                .unwrap_err()
                .to_string()
                .contains("auth.oidc is required")
        );
    }

    #[test]
    fn passkeys_require_an_exact_https_origin_and_a_recovery_method() {
        let tree = TestTree::new();
        let with_origin = |origin: &str| {
            tree.valid_text().replace(
                "[server]",
                &format!("[auth.passkeys]\norigin = {origin:?}\n[server]"),
            )
        };
        let config = tree
            .load(&with_origin("https://files.example.com:8443"))
            .unwrap();
        assert_eq!(
            config.auth().passkeys_origin().unwrap().as_str(),
            "https://files.example.com:8443/"
        );
        for origin in [
            "http://files.example.com",
            "https://files.example.com/path",
            "https://files.example.com?x=1",
        ] {
            assert!(
                tree.load(&with_origin(origin)).is_err(),
                "accepted {origin}"
            );
        }
        let disabled = with_origin("https://files.example.com").replace(
            "[auth.passkeys]",
            "[auth]\npassword_enabled = false\noidc_enabled = false\n[auth.passkeys]",
        );
        assert!(
            tree.load(&disabled)
                .unwrap_err()
                .to_string()
                .contains("both password and OIDC")
        );
    }

    #[test]
    fn oidc_only_accepts_email_user_without_password() {
        let tree = TestTree::new();
        let secret = tree.root.parent().unwrap().join("oidc.secret");
        write_private_file(&secret, "example-client-secret");
        let settings = format!(
            "[auth]\npassword_enabled = false\noidc_enabled = true\n[auth.oidc]\nissuer = \"https://id.example.com\"\nclient_id = \"crabinet\"\nclient_secret_file = {:?}\nredirect_uri = \"https://files.example.com/api/v1/auth/oidc/callback\"\n",
            secret
        );
        let text = tree
            .valid_text()
            .replace("[server]", &format!("{settings}[server]"))
            .replace(
                &format!("password_hash = \"{HASH}\""),
                "email = \"alice@example.com\"",
            );
        let config = tree.load(&text).unwrap();
        assert!(!config.auth().password_enabled());
        assert!(config.auth().oidc().is_some());
        assert_eq!(config.users()[0].email(), Some("alice@example.com"));
        assert_eq!(config.users()[0].password_hash(), None);
    }

    #[test]
    fn duplicate_email_bindings_are_rejected_case_insensitively() {
        let tree = TestTree::new();
        let extra = format!(
            "[[users]]\nusername = \"bob\"\nemail = \"ALICE@example.com\"\npassword_hash = \"{HASH}\"\n\n"
        );
        let text = tree
            .valid_text()
            .replace(
                &format!("password_hash = \"{HASH}\""),
                &format!("password_hash = \"{HASH}\"\nemail = \"alice@example.com\""),
            )
            .replace("[[shares]]", &format!("{extra}[[shares]]"));
        assert!(
            tree.load(&text)
                .unwrap_err()
                .to_string()
                .contains("duplicate email")
        );
    }

    #[test]
    fn share_ids_that_shadow_top_level_urls_are_rejected() {
        let tree = TestTree::new();
        for reserved in ["api", "Assets", "trash", "src", "crabinet.png"] {
            let text = tree
                .valid_text()
                .replace("id = \"files\"", &format!("id = {reserved:?}"));
            let error = tree.load(&text).unwrap_err().to_string();
            assert!(error.contains("is reserved"), "{reserved}: {error}");
        }
        assert!(
            tree.load(
                &tree
                    .valid_text()
                    .replace("id = \"files\"", "id = \"api-docs\"")
            )
            .is_ok()
        );
    }

    #[test]
    fn a_share_is_writable_only_with_an_effective_write_grant() {
        let tree = TestTree::new();
        let writable = tree.load(&tree.valid_text()).expect("writable config");
        assert!(writable.shares()[0].writable());

        let without_write = tree
            .load(
                &tree
                    .valid_text()
                    .replace("permission = \"write\"", "permission = \"read\""),
            )
            .expect("read-only grant config");
        assert!(!without_write.shares()[0].writable());
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
    fn secrets_must_be_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        for mode in [0o600, 0o400] {
            let tree = TestTree::new();
            let secret = tree._temp.path().join("session.key");
            fs::set_permissions(&secret, fs::Permissions::from_mode(mode)).unwrap();
            assert!(tree.load(&tree.valid_text()).is_ok(), "{mode:o}");
        }
        for mode in [0o444, 0o640, 0o604, 0o620, 0o602, 0o664, 0o610] {
            let tree = TestTree::new();
            let secret = tree._temp.path().join("session.key");
            fs::set_permissions(&secret, fs::Permissions::from_mode(mode)).unwrap();
            let error = tree.load(&tree.valid_text()).unwrap_err().to_string();
            assert!(
                error.contains("server.session_secret_file must not be readable or writable by group or other users")
                    && error.contains("`chmod 600 session.key`"),
                "{mode:o}: {error}"
            );
            assert!(
                !error.contains(&*tree._temp.path().to_string_lossy()),
                "{error}"
            );
        }
    }

    #[test]
    fn oidc_client_secret_must_be_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let tree = TestTree::new();
        let secret = tree.root.parent().unwrap().join("oidc.secret");
        write_private_file(&secret, "example-client-secret");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap();
        let settings = format!(
            "[auth]\noidc_enabled = true\n[auth.oidc]\nissuer = \"https://id.example.com\"\nclient_id = \"crabinet\"\nclient_secret_file = {secret:?}\nredirect_uri = \"https://files.example.com/api/v1/auth/oidc/callback\"\n"
        );
        let text = tree
            .valid_text()
            .replace("[[users]]", &format!("{settings}\n[[users]]"))
            .replace(
                &format!("password_hash = \"{HASH}\""),
                &format!("password_hash = \"{HASH}\"\nemail = \"alice@example.com\""),
            );
        let error = tree.load(&text).unwrap_err().to_string();
        assert!(
            error.contains("auth.oidc.client_secret_file must not be readable")
                && error.contains("`chmod 600 oidc.secret`"),
            "{error}"
        );
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(tree.load(&text).is_ok());
    }

    #[test]
    fn group_readable_configuration_is_loaded_with_a_warning() {
        use std::os::unix::fs::PermissionsExt;

        let tree = TestTree::new();
        fs::write(&tree.config, tree.valid_text()).unwrap();
        fs::set_permissions(&tree.config, fs::Permissions::from_mode(0o640)).unwrap();
        let logs = crate::audit::capture::start();
        assert!(Config::load(&tree.config).is_ok());
        let warning = logs.take();
        assert!(
            warning.contains("contains password hashes")
                && warning.contains("chmod 600 config.toml"),
            "{warning}"
        );

        fs::set_permissions(&tree.config, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Config::load(&tree.config).is_ok());
        assert_eq!(logs.take(), "");
    }

    #[test]
    fn oidc_subject_is_bounded_and_requires_an_email() {
        let tree = TestTree::new();
        let with = |line: &str| {
            tree.valid_text().replace(
                &format!("password_hash = \"{HASH}\""),
                &format!("password_hash = \"{HASH}\"\n{line}"),
            )
        };
        let bound = tree
            .load(&with(
                "email = \"alice@example.com\"\noidc_subject = \"110169484474386276334\"",
            ))
            .unwrap();
        assert_eq!(
            bound.users()[0].oidc_subject(),
            Some("110169484474386276334")
        );
        assert_eq!(
            tree.load(&tree.valid_text()).unwrap().users()[0].oidc_subject(),
            None
        );

        let long = "s".repeat(256);
        for subject in [
            "",
            " padded",
            "has space",
            "line\\nbreak",
            "é",
            long.as_str(),
        ] {
            let error = tree
                .load(&with(&format!(
                    "email = \"alice@example.com\"\noidc_subject = \"{subject}\""
                )))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("must contain 1 to 255 printable ASCII"),
                "{error}"
            );
        }
        assert!(
            tree.load(&with("oidc_subject = \"110169484474386276334\""))
                .unwrap_err()
                .to_string()
                .contains("requires an email binding")
        );
    }

    #[test]
    fn share_ids_follow_the_runtime_grammar() {
        let tree = TestTree::new();
        for id in [".hidden", "-dash", "_under"] {
            let text = tree
                .valid_text()
                .replace("id = \"files\"", &format!("id = \"{id}\""));
            let error = tree.load(&text).unwrap_err().to_string();
            assert!(
                error.contains("start with a letter or digit"),
                "{id}: {error}"
            );
        }
        let text = tree
            .valid_text()
            .replace("id = \"files\"", "id = \"9.files-a_b\"");
        assert!(tree.load(&text).is_ok());
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
    fn trusted_proxies_and_source_limit_are_validated() {
        let tree = TestTree::new();
        let with = |settings: &str| {
            tree.valid_text().replace(
                "max_preview_size = \"1 MiB\"",
                &format!("max_preview_size = \"1 MiB\"\n{settings}"),
            )
        };

        let config = tree
            .load(&with(
                "trusted_proxies = [\"192.0.2.10\", \"198.51.100.0/24\", \"2001:db8::/64\", \"::1\"]\ntrusted_proxy_header = \"forwarded\"\nlogin_attempts_per_source_per_minute = 50",
            ))
            .unwrap();
        let server = config.server();
        assert_eq!(server.login_attempts_per_source_per_minute(), 50);
        assert_eq!(server.trusted_proxy_header(), ForwardedHeader::Forwarded);
        let networks: Vec<String> = server
            .trusted_proxies()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            networks,
            [
                "192.0.2.10/32",
                "198.51.100.0/24",
                "2001:db8::/64",
                "::1/128"
            ]
        );
        assert_eq!(
            tree.load(&with("trusted_proxy_header = \"x-forwarded-for\""))
                .unwrap()
                .server()
                .trusted_proxy_header(),
            ForwardedHeader::XForwardedFor
        );

        for everything in ["0.0.0.0/0", "::/0"] {
            let error = tree
                .load(&with(&format!("trusted_proxies = [\"{everything}\"]")))
                .unwrap_err()
                .to_string();
            assert!(error.contains("trusts every address"), "{error}");
        }
        for invalid in [
            "proxy.example.com",
            "192.0.2.0/33",
            "192.0.2.1/24",
            "::ffff:192.0.2.0/120",
        ] {
            let error = tree
                .load(&with(&format!("trusted_proxies = [\"{invalid}\"]")))
                .unwrap_err()
                .to_string();
            assert!(error.contains("server.trusted_proxies[0]"), "{error}");
        }
        let too_many = (0..65)
            .map(|index| format!("\"192.0.2.{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            tree.load(&with(&format!("trusted_proxies = [{too_many}]")))
                .unwrap_err()
                .to_string()
                .contains("at most 64")
        );
        assert!(
            tree.load(&with("trusted_proxy_header = \"x-real-ip\""))
                .is_err()
        );
        for limit in ["0", "10001"] {
            assert!(
                tree.load(&with(&format!(
                    "login_attempts_per_source_per_minute = {limit}"
                )))
                .unwrap_err()
                .to_string()
                .contains("login_attempts_per_source_per_minute")
            );
        }
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
