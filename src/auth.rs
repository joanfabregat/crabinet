//! Local password authentication, opaque server-side sessions, and request protection.

mod passkeys;

use std::{
    collections::HashMap,
    fs::OpenOptions,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use argon2::{
    Argon2, PasswordHash,
    password_hash::{PasswordHasher, PasswordVerifier},
};
use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, FromRequestParts, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use getrandom::fill as random_fill;
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::{
    app::AppState,
    browse::{AuthenticatedIdentity, BrowseState, run_blocking},
    client_address::TrustedProxies,
    config::{Config, Permission},
    error::AppError,
    filesystem::{AccessLevel, EntryKind, ShareGrant, ShareId, VirtualPath},
    mutations::CsrfVerified,
};

type HmacSha256 = Hmac<Sha256>;

const SESSION_COOKIE: &str = "__Host-crabinet_session";
const TOKEN_BYTES: usize = 32;
const SESSION_SCHEMA_VERSION: i64 = 5;
const RATE_LIMIT_WINDOW_SECONDS: i64 = 60;
const MAX_RATE_LIMIT_KEYS: usize = 4_096;
const MAX_USERNAME_BYTES: usize = 64;
const MAX_PASSWORD_BYTES: usize = 4_096;
const VERIFIER_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
const DUMMY_PASSWORD_HASH: &str =
    "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

#[derive(Debug, thiserror::Error)]
pub enum AuthInitError {
    #[error("cannot create the session database")]
    CreateDatabase(#[from] std::io::Error),
    #[error("cannot initialize the session database")]
    Database(#[from] rusqlite::Error),
    #[error("cannot initialize passkeys: {0}")]
    Passkeys(String),
}

#[derive(Debug, thiserror::Error)]
enum AuthError {
    #[error("session database operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("session database worker failed")]
    Worker,
    #[error("secure random generation failed")]
    Random,
}

impl From<AuthError> for AppError {
    fn from(error: AuthError) -> Self {
        tracing::error!(error = %error, "authentication operation failed");
        AppError::Internal
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPrincipal {
    username: Arc<str>,
}

impl AuthenticatedPrincipal {
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }
}

impl<S> FromRequestParts<S> for AuthenticatedPrincipal
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(AppError::Unauthorized)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveShare {
    pub id: String,
    pub name: String,
    pub access: &'static str,
}

#[derive(Clone)]
pub struct AuthService {
    inner: Arc<AuthInner>,
}

struct AuthInner {
    users: HashMap<String, UserRecord>,
    password_enabled: bool,
    passkeys: Option<passkeys::PasskeyState>,
    shares: Vec<ShareRecord>,
    store: SessionStore,
    token_key: Vec<u8>,
    verifier_slots: Arc<Semaphore>,
    dummy_password_hash: String,
    gravatar_enabled: bool,
    idle_timeout_seconds: i64,
    absolute_timeout_seconds: i64,
    max_sessions_per_user: usize,
    max_sessions_total: usize,
    rate_limit: Mutex<RateLimiter<RateLimitKey>>,
    source_rate_limit: Mutex<RateLimiter<Option<IpAddr>>>,
    trusted_proxies: TrustedProxies,
    clock: Arc<dyn Clock>,
}

#[derive(Clone)]
struct UserRecord {
    password_hash: Option<String>,
    email: Option<String>,
    disabled: bool,
}

#[derive(Clone)]
struct ShareRecord {
    id: String,
    name: String,
    grants: HashMap<String, Permission>,
    read_only: bool,
}

#[derive(Clone)]
struct SessionStore {
    connection: Arc<Mutex<Connection>>,
}

#[derive(Clone, Debug)]
struct StoredSession {
    username: String,
    picture_url: Option<String>,
    created_at: i64,
    last_seen_at: i64,
    expires_at: i64,
}

struct SessionRotation {
    old_key: Option<Vec<u8>>,
    new_key: Vec<u8>,
    username: String,
    picture_url: Option<String>,
    now: i64,
    expires_at: i64,
    idle_cutoff: i64,
    max_sessions_per_user: usize,
    max_sessions_total: usize,
}

#[derive(Clone)]
struct AuthenticatedSession {
    principal: AuthenticatedPrincipal,
    session_token: [u8; TOKEN_BYTES],
    created_at: i64,
    picture_url: Option<String>,
}

trait Clock: Send + Sync {
    fn now(&self) -> i64;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs().min(i64::MAX as u64) as i64)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RateLimitKey {
    account: [u8; 32],
    source: Option<IpAddr>,
}

#[derive(Clone, Copy)]
struct AttemptWindow {
    started_at: i64,
    attempts: u32,
    last_seen_at: i64,
}

struct RateLimiter<K> {
    entries: HashMap<K, AttemptWindow>,
    attempts_per_window: u32,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

/// The TCP peer of the connection, before any trusted-proxy resolution.
struct PeerAddress(Option<IpAddr>);

impl<S> FromRequestParts<S> for PeerAddress
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|address| address.0.ip()),
        ))
    }
}

/// Groups peers the way address allocation does: a client normally controls
/// a whole IPv6 /64, so each /64 is one limiter source.
fn rate_limit_source(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) => address,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(std::net::Ipv6Addr::from(
                u128::from(v6) & !((1_u128 << 64) - 1),
            )),
        },
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponse {
    user: SessionUser,
    shares: Vec<EffectiveShare>,
    default_folder: Option<DefaultFolder>,
    preferences: DisplayPreferences,
    csrf_token: String,
    /// The running server release, shown to signed-in users only.
    version: &'static str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DefaultFolder {
    share_id: String,
    path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreferencesUpdate {
    default_folder: Option<DefaultFolder>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreferencesResponse {
    default_folder: Option<DefaultFolder>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum ThemePreference {
    #[default]
    System,
    Light,
    Dark,
}

impl ThemePreference {
    fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }

    fn from_column(value: &str) -> Option<Self> {
        match value {
            "system" => Some(Self::System),
            "light" => Some(Self::Light),
            "dark" => Some(Self::Dark),
            _ => None,
        }
    }
}

/// Per-account display settings that follow the user across devices.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct DisplayPreferences {
    show_hidden_files: bool,
    theme: ThemePreference,
}

impl Default for DisplayPreferences {
    fn default() -> Self {
        Self {
            show_hidden_files: false,
            theme: ThemePreference::System,
        }
    }
}

/// A partial update: absent fields keep their saved value, `null` is rejected.
#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DisplayPreferencesUpdate {
    #[serde(default, deserialize_with = "present_value")]
    show_hidden_files: Option<bool>,
    #[serde(default, deserialize_with = "present_value")]
    theme: Option<ThemePreference>,
}

fn present_value<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionUser {
    id: String,
    username: String,
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    picture_url: Option<String>,
}

struct NewSession {
    cookie_token: String,
    csrf_token: String,
    username: String,
    picture_url: Option<String>,
}

impl AuthService {
    pub(crate) fn password_enabled(&self) -> bool {
        self.inner.password_enabled
    }

    pub(crate) fn passkey_enabled(&self) -> bool {
        self.inner.passkeys.is_some()
    }

    pub(crate) fn absolute_timeout_seconds(&self) -> i64 {
        self.inner.absolute_timeout_seconds
    }
    pub fn from_config(config: &Config) -> Result<Self, AuthInitError> {
        let users = config
            .users()
            .iter()
            .map(|user| {
                (
                    user.username().to_owned(),
                    UserRecord {
                        password_hash: user.password_hash().map(str::to_owned),
                        email: user.email().map(str::to_owned),
                        disabled: user.disabled(),
                    },
                )
            })
            .collect();
        let shares = config
            .shares()
            .iter()
            .map(|share| ShareRecord {
                id: share.id().to_owned(),
                name: share.name().to_owned(),
                grants: config
                    .users()
                    .iter()
                    .filter_map(|user| {
                        share
                            .permission_for(user.username())
                            .map(|permission| (user.username().to_owned(), permission))
                    })
                    .collect(),
                read_only: share.read_only(),
            })
            .collect();
        let server = config.server();
        let store = SessionStore::open(server.database_path())?;
        store.prune_unknown_users(config.users().iter().map(|user| user.username()))?;
        let mut auth = Self::new(
            users,
            config.auth().password_enabled(),
            shares,
            store,
            config.session_secret().to_vec(),
            server.auth_max_concurrent(),
            server.session_idle_timeout_seconds() as i64,
            server.session_absolute_timeout_seconds() as i64,
            server.login_attempts_per_minute(),
            server.login_attempts_per_source_per_minute(),
            server.max_sessions_per_user(),
            server.max_sessions_total(),
            Arc::new(SystemClock),
        );
        let inner = Arc::get_mut(&mut auth.inner).expect("new auth service has one owner");
        inner.gravatar_enabled = config.auth().gravatar_enabled();
        inner.trusted_proxies = TrustedProxies::new(
            server.trusted_proxies().to_vec(),
            server.trusted_proxy_header(),
        );
        inner.dummy_password_hash = dummy_password_hash(
            config
                .users()
                .iter()
                .filter_map(|user| user.password_hash()),
        );
        if let Some(origin) = config.auth().passkeys_origin() {
            inner.passkeys = Some(passkeys::PasskeyState::new(origin)?);
        }
        Ok(auth)
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        users: HashMap<String, UserRecord>,
        password_enabled: bool,
        shares: Vec<ShareRecord>,
        store: SessionStore,
        token_key: Vec<u8>,
        verifier_slots: usize,
        idle_timeout_seconds: i64,
        absolute_timeout_seconds: i64,
        login_attempts_per_minute: u32,
        login_attempts_per_source_per_minute: u32,
        max_sessions_per_user: usize,
        max_sessions_total: usize,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            inner: Arc::new(AuthInner {
                users,
                password_enabled,
                passkeys: None,
                shares,
                store,
                token_key,
                verifier_slots: Arc::new(Semaphore::new(verifier_slots)),
                dummy_password_hash: DUMMY_PASSWORD_HASH.to_owned(),
                gravatar_enabled: false,
                idle_timeout_seconds,
                absolute_timeout_seconds,
                max_sessions_per_user,
                max_sessions_total,
                rate_limit: Mutex::new(RateLimiter {
                    entries: HashMap::new(),
                    attempts_per_window: login_attempts_per_minute,
                }),
                source_rate_limit: Mutex::new(RateLimiter {
                    entries: HashMap::new(),
                    attempts_per_window: login_attempts_per_source_per_minute,
                }),
                trusted_proxies: TrustedProxies::default(),
                clock,
            }),
        }
    }

    /// The limiter source of a sign-in request: the client address resolved
    /// through the configured trusted proxies, grouped by
    /// [`rate_limit_source`]. `None` when the transport peer is unknown.
    fn sign_in_source(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Option<IpAddr> {
        peer.map(|peer| rate_limit_source(self.inner.trusted_proxies.client_address(peer, headers)))
    }

    /// Counts one sign-in attempt against its source's per-minute budget.
    /// Password logins and passkey sign-in starts share this one budget per
    /// source, so neither can be used to bypass the other's limit.
    fn allow_sign_in_source(&self, source: Option<IpAddr>) -> Result<(), AppError> {
        if self
            .inner
            .source_rate_limit
            .lock()
            .map_err(|_| AppError::Internal)?
            .allow(source, self.inner.clock.now())
        {
            Ok(())
        } else {
            Err(AppError::TooManyRequests)
        }
    }

    async fn login(
        &self,
        username: &str,
        password: &str,
        source: Option<IpAddr>,
        old_cookie: Option<&str>,
    ) -> Result<NewSession, AppError> {
        let candidate = if is_plausible_username(username) {
            self.inner.users.get_key_value(username)
        } else if username.len() <= 254 && username.is_ascii() && username.contains('@') {
            self.inner.users.iter().find(|(_, user)| {
                user.email
                    .as_deref()
                    .is_some_and(|email| email.eq_ignore_ascii_case(username))
            })
        } else {
            None
        };
        let account = candidate.map_or(username, |(name, _)| name.as_str());
        // Oversized passwords are rejected before they can create limiter
        // entries, so they cannot be used to churn the bounded limiter map.
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(AppError::AuthenticationFailed);
        }
        // The per-source cap is counted across all usernames and costs no
        // Argon2 work, so one source cycling usernames is refused here instead
        // of queueing for the shared verifier ahead of everyone else.
        self.allow_sign_in_source(source)?;
        // The permit is taken before the per-account limiter is consulted, so
        // new (account, source) keys can only be created at the bounded
        // verification rate. It is moved into the blocking task below:
        // cancelling the request cannot release it while a detached Argon2
        // computation is still running.
        let permit = tokio::time::timeout(
            VERIFIER_WAIT,
            Arc::clone(&self.inner.verifier_slots).acquire_owned(),
        )
        .await
        .map_err(|_| AppError::Busy)?
        .map_err(|_| AppError::Internal)?;
        let now = self.inner.clock.now();
        let rate_key = RateLimitKey {
            account: normalized_identifier_digest(account),
            source,
        };
        if !self
            .inner
            .rate_limit
            .lock()
            .map_err(|_| AppError::Internal)?
            .allow(rate_key.clone(), now)
        {
            return Err(AppError::TooManyRequests);
        }

        let usable = self.inner.password_enabled
            && candidate.is_some_and(|(_, user)| !user.disabled && user.password_hash.is_some());
        let hash = if usable {
            candidate
                .expect("checked above")
                .1
                .password_hash
                .clone()
                .expect("checked above")
        } else {
            self.inner.dummy_password_hash.clone()
        };
        let password = password.as_bytes().to_vec();
        let valid = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            verify_password(&hash, &password)
        })
        .await
        .map_err(|_| AppError::Internal)?;
        if !usable || !valid {
            return Err(AppError::AuthenticationFailed);
        }

        let session = self
            .issue_session(
                account,
                None,
                old_cookie.and_then(|token| self.session_key(token)),
            )
            .await?;
        self.inner
            .rate_limit
            .lock()
            .map_err(|_| AppError::Internal)?
            .clear(&rate_key);
        Ok(session)
    }

    pub(crate) async fn login_oidc(
        &self,
        email: &str,
        picture_url: Option<&str>,
        old_session_key: Option<Vec<u8>>,
    ) -> Result<(String, String, String), AppError> {
        let email = email.to_ascii_lowercase();
        let Some((username, _)) = self
            .inner
            .users
            .iter()
            .find(|(_, user)| !user.disabled && user.email.as_deref() == Some(email.as_str()))
        else {
            return Err(AppError::AuthenticationFailed);
        };
        let session = self
            .issue_session(username, picture_url, old_session_key)
            .await?;
        Ok((session.username, session.cookie_token, session.csrf_token))
    }

    async fn issue_session(
        &self,
        username: &str,
        picture_url: Option<&str>,
        old_key: Option<Vec<u8>>,
    ) -> Result<NewSession, AppError> {
        let now = self.inner.clock.now();
        let mut session_token = [0_u8; TOKEN_BYTES];
        random_fill(&mut session_token).map_err(|_| AuthError::Random)?;
        let cookie_token = encode_hex(&session_token);
        let csrf_token_text = encode_hex(&self.digest(b"csrf-token\0", &session_token));
        let session_key = self.digest(b"session\0", &session_token);
        let expires_at = now.saturating_add(self.inner.absolute_timeout_seconds);
        self.inner
            .store
            .rotate(SessionRotation {
                old_key,
                new_key: session_key,
                username: username.to_owned(),
                picture_url: picture_url.map(str::to_owned),
                now,
                expires_at,
                idle_cutoff: now.saturating_sub(self.inner.idle_timeout_seconds),
                max_sessions_per_user: self.inner.max_sessions_per_user,
                max_sessions_total: self.inner.max_sessions_total,
            })
            .await?;
        Ok(NewSession {
            cookie_token,
            csrf_token: csrf_token_text,
            username: username.to_owned(),
            picture_url: picture_url.map(str::to_owned),
        })
    }

    async fn authenticate(&self, headers: &HeaderMap) -> Result<AuthenticatedSession, AppError> {
        let (key, raw_token, session, now) = self.validate_session(headers).await?;
        self.inner.store.touch(key, now).await?;
        Ok(AuthenticatedSession {
            principal: AuthenticatedPrincipal {
                username: Arc::from(session.username),
            },
            session_token: raw_token,
            created_at: session.created_at,
            picture_url: session.picture_url,
        })
    }

    /// Reports whether the presented session is still valid without
    /// extending it. Long-lived responses, such as directory event streams,
    /// use it to end once their session is signed out, expired, or revoked.
    pub(crate) async fn session_is_active(&self, headers: &HeaderMap) -> bool {
        self.validate_session(headers).await.is_ok()
    }

    /// Looks up the presented session and deletes it if it has expired or its
    /// user is no longer active.
    async fn validate_session(
        &self,
        headers: &HeaderMap,
    ) -> Result<(Vec<u8>, [u8; TOKEN_BYTES], StoredSession, i64), AppError> {
        let cookie = session_cookie(headers).ok_or(AppError::Unauthorized)?;
        let raw_token = decode_token(cookie).ok_or(AppError::Unauthorized)?;
        let key = self.digest(b"session\0", &raw_token);
        let now = self.inner.clock.now();
        let Some(session) = self.inner.store.lookup(key.clone()).await? else {
            return Err(AppError::Unauthorized);
        };
        let expired = now >= session.expires_at
            || now.saturating_sub(session.last_seen_at) >= self.inner.idle_timeout_seconds
            || now < session.created_at;
        let user_is_active = self
            .inner
            .users
            .get(&session.username)
            .is_some_and(|user| !user.disabled);
        if expired || !user_is_active {
            self.inner.store.delete(key).await?;
            return Err(AppError::Unauthorized);
        }
        Ok((key, raw_token, session, now))
    }

    async fn logout(&self, headers: &HeaderMap) -> Result<(), AppError> {
        let cookie = session_cookie(headers).ok_or(AppError::Unauthorized)?;
        let key = self.session_key(cookie).ok_or(AppError::Unauthorized)?;
        self.inner.store.delete(key).await?;
        Ok(())
    }

    fn verify_csrf(&self, session: &AuthenticatedSession, headers: &HeaderMap) -> bool {
        let Some(token) = headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .and_then(decode_token)
        else {
            return false;
        };
        let mut mac = HmacSha256::new_from_slice(&self.inner.token_key)
            .expect("HMAC accepts keys of every length");
        mac.update(b"csrf-token\0");
        mac.update(&session.session_token);
        mac.verify_slice(&token).is_ok()
    }

    #[must_use]
    pub fn effective_shares(&self, username: &str) -> Vec<EffectiveShare> {
        self.inner
            .shares
            .iter()
            .filter_map(|share| {
                share.grants.get(username).map(|permission| EffectiveShare {
                    id: share.id.clone(),
                    name: share.name.clone(),
                    access: if share.read_only || *permission == Permission::Read {
                        "read"
                    } else {
                        "read-write"
                    },
                })
            })
            .collect()
    }

    fn browse_identity(&self, username: &str) -> AuthenticatedIdentity {
        let grants = self
            .inner
            .shares
            .iter()
            .filter_map(|share| {
                let permission = share.grants.get(username)?;
                let share_id = ShareId::new(share.id.clone())
                    .expect("configuration validation guarantees a valid share identifier");
                let access = if share.read_only || *permission == Permission::Read {
                    AccessLevel::ReadOnly
                } else {
                    AccessLevel::ReadWrite
                };
                Some(ShareGrant { share_id, access })
            })
            .collect();
        AuthenticatedIdentity::new(username, grants)
    }

    fn digest(&self, domain: &[u8], token: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.inner.token_key)
            .expect("HMAC accepts keys of every length");
        mac.update(domain);
        mac.update(token);
        mac.finalize().into_bytes().to_vec()
    }

    pub(crate) fn session_key(&self, encoded: &str) -> Option<Vec<u8>> {
        decode_token(encoded).map(|token| self.digest(b"session\0", &token))
    }

    async fn session_response(
        &self,
        browse: &BrowseState,
        username: &str,
        csrf_token: String,
        picture_url: Option<String>,
    ) -> Result<SessionResponse, AppError> {
        let default_folder = self.inner.store.default_folder(username).await?;
        let default_folder = match default_folder {
            Some(folder) if self.valid_default_folder(browse, username, &folder).await? => {
                Some(folder)
            }
            _ => None,
        };
        let preferences = self.inner.store.display_preferences(username).await?;
        let picture_url = picture_url.or_else(|| {
            self.inner
                .users
                .get(username)
                .filter(|_| self.inner.gravatar_enabled)
                .and_then(|user| user.email.as_deref())
                .map(gravatar_picture_url)
        });
        Ok(SessionResponse {
            user: SessionUser {
                id: username.to_owned(),
                username: username.to_owned(),
                display_name: username.to_owned(),
                picture_url,
            },
            shares: self.effective_shares(username),
            default_folder,
            preferences,
            csrf_token,
            version: env!("CARGO_PKG_VERSION"),
        })
    }

    /// Checks that a saved default folder is still an authorized directory.
    /// The directory lookup runs on the blocking pool: this is on every
    /// session read and sign-in, and a slow filesystem must not stall the
    /// async workers that serve them.
    async fn valid_default_folder(
        &self,
        browse: &BrowseState,
        username: &str,
        folder: &DefaultFolder,
    ) -> Result<bool, AppError> {
        let Ok(share_id) = ShareId::new(folder.share_id.clone()) else {
            return Ok(false);
        };
        let path = if folder.path.is_empty() {
            VirtualPath::root()
        } else if let Ok(path) = VirtualPath::parse(&folder.path) {
            path
        } else {
            return Ok(false);
        };
        let identity = self.browse_identity(username);
        let Ok(authorized) = browse.authorize_owned(&identity, &share_id) else {
            return Ok(false);
        };
        if path.is_root() {
            return Ok(true);
        }
        run_blocking(move || {
            authorized
                .view()
                .metadata(&path)
                .is_ok_and(|metadata| metadata.kind == EntryKind::Directory)
        })
        .await
    }
}

fn read_display_preferences(
    connection: &Connection,
    username: &str,
) -> Result<DisplayPreferences, rusqlite::Error> {
    let saved = connection
        .query_row(
            "SELECT show_hidden_files, theme FROM user_preferences WHERE username = ?1",
            params![username],
            |row| {
                let theme: String = row.get(1)?;
                Ok(DisplayPreferences {
                    show_hidden_files: row.get(0)?,
                    theme: ThemePreference::from_column(&theme).unwrap_or_default(),
                })
            },
        )
        .optional()?;
    Ok(saved.unwrap_or_default())
}

/// Drops a row that no longer differs from the defaults of a new account.
fn delete_default_preferences(
    connection: &Connection,
    username: &str,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "DELETE FROM user_preferences
         WHERE username = ?1 AND default_share_id = '' AND show_hidden_files = 0
           AND theme = 'system'",
        params![username],
    )?;
    Ok(())
}

#[expect(
    clippy::disallowed_methods,
    reason = "startup-only: creates the operator-configured session database before serving requests"
)]
fn create_database_if_missing(path: &std::path::Path) -> Result<(), std::io::Error> {
    // nosemgrep: crabinet-ambient-filesystem-path
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    match options.open(path) {
        Ok(file) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};

                if file.metadata()?.mode() & 0o777 != 0o600 {
                    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

impl SessionStore {
    fn open(path: &std::path::Path) -> Result<Self, AuthInitError> {
        create_database_if_missing(path)?;
        let connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > SESSION_SCHEMA_VERSION {
            return Err(AuthInitError::Database(rusqlite::Error::InvalidQuery));
        }
        if version == 0 {
            connection.execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE IF NOT EXISTS sessions (
                   session_key BLOB PRIMARY KEY NOT NULL CHECK(length(session_key) = 32),
                   username TEXT NOT NULL,
                   created_at INTEGER NOT NULL,
                   last_seen_at INTEGER NOT NULL,
                   expires_at INTEGER NOT NULL
                 ) WITHOUT ROWID;
                 CREATE INDEX IF NOT EXISTS sessions_expiration ON sessions(expires_at);
                 PRAGMA user_version = 1;
                 COMMIT;",
            )?;
        }
        if version < 2 {
            connection.execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE user_preferences (
                   username TEXT PRIMARY KEY NOT NULL,
                   default_share_id TEXT NOT NULL,
                   default_path TEXT NOT NULL
                 ) WITHOUT ROWID;
                 PRAGMA user_version = 2;
                 COMMIT;",
            )?;
        }
        if version < 3 {
            connection.execute_batch(
                "BEGIN IMMEDIATE;
                 ALTER TABLE sessions ADD COLUMN picture_url TEXT;
                 PRAGMA user_version = 3;
                 COMMIT;",
            )?;
        }
        if version < 4 {
            connection.execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE passkey_users (
                   username TEXT PRIMARY KEY NOT NULL,
                   user_handle BLOB NOT NULL UNIQUE CHECK(length(user_handle) = 16)
                 ) WITHOUT ROWID;
                 CREATE TABLE passkeys (
                   id TEXT PRIMARY KEY NOT NULL,
                   username TEXT NOT NULL,
                   credential_id BLOB NOT NULL UNIQUE,
                   name TEXT NOT NULL,
                   credential_json TEXT NOT NULL,
                   created_at INTEGER NOT NULL,
                   last_used_at INTEGER
                 ) WITHOUT ROWID;
                 CREATE INDEX passkeys_user ON passkeys(username);
                 PRAGMA user_version = 4;
                 COMMIT;",
            )?;
        }
        if version < 5 {
            // Rows now also exist for users without a start folder; such rows
            // store an empty `default_share_id`, which is never a valid share.
            connection.execute_batch(
                "BEGIN IMMEDIATE;
                 ALTER TABLE user_preferences
                   ADD COLUMN show_hidden_files INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE user_preferences
                   ADD COLUMN theme TEXT NOT NULL DEFAULT 'system'
                   CHECK (theme IN ('system', 'light', 'dark'));
                 PRAGMA user_version = 5;
                 COMMIT;",
            )?;
        }
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Deletes sessions, preferences and passkeys of usernames that are no
    /// longer configured, so a later user given a removed name inherits none.
    fn prune_unknown_users<'a>(
        &self,
        usernames: impl Iterator<Item = &'a str>,
    ) -> Result<(), AuthInitError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| AuthInitError::Database(rusqlite::Error::InvalidQuery))?;
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE TEMP TABLE configured_users (username TEXT PRIMARY KEY NOT NULL);",
        )?;
        for username in usernames {
            transaction.execute(
                "INSERT OR IGNORE INTO configured_users (username) VALUES (?1)",
                params![username],
            )?;
        }
        transaction.execute_batch(
            "DELETE FROM sessions WHERE username NOT IN (SELECT username FROM configured_users);
             DELETE FROM user_preferences
               WHERE username NOT IN (SELECT username FROM configured_users);
             DELETE FROM passkeys WHERE username NOT IN (SELECT username FROM configured_users);
             DELETE FROM passkey_users
               WHERE username NOT IN (SELECT username FROM configured_users);
             DROP TABLE configured_users;",
        )?;
        transaction.commit()?;
        Ok(())
    }

    async fn default_folder(&self, username: &str) -> Result<Option<DefaultFolder>, AuthError> {
        let username = username.to_owned();
        self.with_connection(move |connection| {
            connection
                .query_row(
                    "SELECT default_share_id, default_path FROM user_preferences
                     WHERE username = ?1 AND default_share_id <> ''",
                    params![username],
                    |row| {
                        Ok(DefaultFolder {
                            share_id: row.get(0)?,
                            path: row.get(1)?,
                        })
                    },
                )
                .optional()
        })
        .await
    }

    async fn set_default_folder(
        &self,
        username: &str,
        folder: Option<DefaultFolder>,
    ) -> Result<(), AuthError> {
        let username = username.to_owned();
        self.with_connection(move |connection| {
            if let Some(folder) = folder {
                connection.execute(
                    "INSERT INTO user_preferences (username, default_share_id, default_path)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(username) DO UPDATE SET
                       default_share_id = excluded.default_share_id,
                       default_path = excluded.default_path",
                    params![username, folder.share_id, folder.path],
                )?;
            } else {
                // Clearing the start folder keeps the account's other settings.
                let transaction = connection.transaction()?;
                transaction.execute(
                    "UPDATE user_preferences SET default_share_id = '', default_path = ''
                     WHERE username = ?1",
                    params![username],
                )?;
                delete_default_preferences(&transaction, &username)?;
                transaction.commit()?;
            }
            Ok(())
        })
        .await
    }

    async fn display_preferences(&self, username: &str) -> Result<DisplayPreferences, AuthError> {
        let username = username.to_owned();
        self.with_connection(move |connection| read_display_preferences(connection, &username))
            .await
    }

    /// Applies a partial update without touching the start folder or any
    /// field the update leaves out, and returns the saved settings.
    async fn update_display_preferences(
        &self,
        username: &str,
        update: DisplayPreferencesUpdate,
    ) -> Result<DisplayPreferences, AuthError> {
        let username = username.to_owned();
        self.with_connection(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT INTO user_preferences
                   (username, default_share_id, default_path, show_hidden_files, theme)
                 VALUES (?1, '', '', COALESCE(?2, 1), COALESCE(?3, 'system'))
                 ON CONFLICT(username) DO UPDATE SET
                   show_hidden_files = COALESCE(?2, show_hidden_files),
                   theme = COALESCE(?3, theme)",
                params![
                    username,
                    update.show_hidden_files,
                    update.theme.map(ThemePreference::as_str)
                ],
            )?;
            let saved = read_display_preferences(&transaction, &username)?;
            delete_default_preferences(&transaction, &username)?;
            transaction.commit()?;
            Ok(saved)
        })
        .await
    }

    async fn with_connection<T, F>(&self, operation: F) -> Result<T, AuthError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, rusqlite::Error> + Send + 'static,
    {
        let connection = Arc::clone(&self.connection);
        tokio::task::spawn_blocking(move || {
            let mut connection = connection
                .lock()
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            operation(&mut connection)
        })
        .await
        .map_err(|_| AuthError::Worker)?
        .map_err(AuthError::Database)
    }

    async fn rotate(&self, rotation: SessionRotation) -> Result<(), AuthError> {
        self.with_connection(move |connection| {
            let SessionRotation {
                old_key,
                new_key,
                username,
                picture_url,
                now,
                expires_at,
                idle_cutoff,
                max_sessions_per_user,
                max_sessions_total,
            } = rotation;
            let transaction = connection.transaction()?;
            if let Some(old_key) = old_key {
                transaction.execute(
                    "DELETE FROM sessions WHERE session_key = ?1",
                    params![old_key],
                )?;
            }
            transaction.execute(
                "DELETE FROM sessions WHERE expires_at <= ?1 OR last_seen_at <= ?2",
                params![now, idle_cutoff],
            )?;
            transaction.execute(
                "DELETE FROM sessions
                 WHERE session_key IN (
                   SELECT session_key FROM sessions
                   WHERE username = ?1
                   ORDER BY last_seen_at DESC, created_at DESC, hex(session_key) DESC
                   LIMIT -1 OFFSET ?2
                 )",
                params![username, max_sessions_per_user.saturating_sub(1) as i64],
            )?;
            transaction.execute(
                "DELETE FROM sessions
                 WHERE session_key IN (
                   SELECT session_key FROM sessions
                   ORDER BY last_seen_at DESC, created_at DESC, hex(session_key) DESC
                   LIMIT -1 OFFSET ?1
                 )",
                params![max_sessions_total.saturating_sub(1) as i64],
            )?;
            transaction.execute(
                "INSERT INTO sessions
                 (session_key, username, created_at, last_seen_at, expires_at, picture_url)
                 VALUES (?1, ?2, ?3, ?3, ?4, ?5)",
                params![new_key, username, now, expires_at, picture_url],
            )?;
            transaction.commit()
        })
        .await
    }

    async fn lookup(&self, key: Vec<u8>) -> Result<Option<StoredSession>, AuthError> {
        self.with_connection(move |connection| {
            connection
                .query_row(
                    "SELECT username, created_at, last_seen_at, expires_at, picture_url
                     FROM sessions WHERE session_key = ?1",
                    params![key],
                    |row| {
                        Ok(StoredSession {
                            username: row.get(0)?,
                            created_at: row.get(1)?,
                            last_seen_at: row.get(2)?,
                            expires_at: row.get(3)?,
                            picture_url: row.get(4)?,
                        })
                    },
                )
                .optional()
        })
        .await
    }

    async fn touch(&self, key: Vec<u8>, now: i64) -> Result<(), AuthError> {
        self.with_connection(move |connection| {
            connection.execute(
                "UPDATE sessions SET last_seen_at = ?2 WHERE session_key = ?1",
                params![key, now],
            )?;
            Ok(())
        })
        .await
    }

    async fn delete(&self, key: Vec<u8>) -> Result<(), AuthError> {
        self.with_connection(move |connection| {
            connection.execute("DELETE FROM sessions WHERE session_key = ?1", params![key])?;
            Ok(())
        })
        .await
    }
}

impl<K: Clone + Eq + Hash> RateLimiter<K> {
    fn allow(&mut self, key: K, now: i64) -> bool {
        self.entries.retain(|_, window| {
            now.saturating_sub(window.last_seen_at) < RATE_LIMIT_WINDOW_SECONDS
        });
        if self.entries.len() >= MAX_RATE_LIMIT_KEYS && !self.entries.contains_key(&key) {
            // Never evict an exhausted window: that would let a blocked caller
            // reset its own limit by flooding the map with fresh keys.
            let limit = self.attempts_per_window;
            let Some(oldest) = self
                .entries
                .iter()
                .filter(|(_, window)| window.attempts < limit)
                .min_by_key(|(_, window)| window.last_seen_at)
                .map(|(key, _)| key.clone())
            else {
                return false;
            };
            self.entries.remove(&oldest);
        }
        let window = self.entries.entry(key).or_insert(AttemptWindow {
            started_at: now,
            attempts: 0,
            last_seen_at: now,
        });
        if now.saturating_sub(window.started_at) >= RATE_LIMIT_WINDOW_SECONDS
            || now < window.started_at
        {
            *window = AttemptWindow {
                started_at: now,
                attempts: 0,
                last_seen_at: now,
            };
        }
        window.last_seen_at = now;
        if window.attempts >= self.attempts_per_window {
            return false;
        }
        window.attempts = window.attempts.saturating_add(1);
        true
    }

    fn clear(&mut self, key: &K) {
        self.entries.remove(key);
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/session", get(current_session))
        .route("/preferences", put(update_preferences))
        .route("/preferences/display", put(update_display_preferences))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .merge(passkeys::router())
}

/// Authenticates a request and inserts [`AuthenticatedPrincipal`] for protected APIs.
pub async fn require_authentication(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let auth = state.auth().ok_or(AppError::Internal)?;
    let session = auth.authenticate(request.headers()).await?;
    let identity = auth.browse_identity(session.principal.username());
    request.extensions_mut().insert(session.principal);
    request.extensions_mut().insert(identity);
    Ok(next.run(request).await)
}

/// Authenticates and enforces CSRF plus same-origin headers before a state change.
pub async fn require_state_change(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    validate_same_origin(request.headers())?;
    let auth = state.auth().ok_or(AppError::Internal)?;
    let session = auth.authenticate(request.headers()).await?;
    if !auth.verify_csrf(&session, request.headers()) {
        return Err(AppError::Forbidden);
    }
    let identity = auth.browse_identity(session.principal.username());
    request.extensions_mut().insert(session.principal);
    request.extensions_mut().insert(identity);
    request.extensions_mut().insert(CsrfVerified(()));
    Ok(next.run(request).await)
}

async fn current_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let auth = state.auth().ok_or(AppError::Internal)?;
    let session = auth.authenticate(&headers).await?;
    Ok(session_json(
        StatusCode::OK,
        auth.session_response(
            state.browse(),
            session.principal.username(),
            encode_hex(&auth.digest(b"csrf-token\0", &session.session_token)),
            session.picture_url,
        )
        .await?,
        None,
    ))
}

async fn update_preferences(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<PreferencesUpdate>, JsonRejection>,
) -> Result<Response, AppError> {
    validate_same_origin(&headers)?;
    let auth = state.auth().ok_or(AppError::Internal)?;
    let session = auth.authenticate(&headers).await?;
    if !auth.verify_csrf(&session, &headers) {
        return Err(AppError::Forbidden);
    }
    let Json(payload) = payload.map_err(|_| AppError::InvalidRequest)?;
    if let Some(folder) = payload.default_folder.as_ref()
        && !auth
            .valid_default_folder(state.browse(), session.principal.username(), folder)
            .await?
    {
        return Err(AppError::NotFound);
    }
    auth.inner
        .store
        .set_default_folder(session.principal.username(), payload.default_folder.clone())
        .await?;
    let mut response = Json(PreferencesResponse {
        default_folder: payload.default_folder,
    })
    .into_response();
    no_store(response.headers_mut());
    Ok(response)
}

async fn update_display_preferences(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<DisplayPreferencesUpdate>, JsonRejection>,
) -> Result<Response, AppError> {
    validate_same_origin(&headers)?;
    let auth = state.auth().ok_or(AppError::Internal)?;
    let session = auth.authenticate(&headers).await?;
    if !auth.verify_csrf(&session, &headers) {
        return Err(AppError::Forbidden);
    }
    let Json(payload) = payload.map_err(|_| AppError::InvalidRequest)?;
    let saved = auth
        .inner
        .store
        .update_display_preferences(session.principal.username(), payload)
        .await?;
    let mut response = Json(saved).into_response();
    no_store(response.headers_mut());
    Ok(response)
}

async fn login(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    payload: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    validate_same_origin(&headers)?;
    let Json(payload) = payload.map_err(|_| AppError::AuthenticationFailed)?;
    let auth = state.auth().ok_or(AppError::Internal)?;
    let source = auth.sign_in_source(peer, &headers);
    let session = auth
        .login(
            &payload.username,
            &payload.password,
            source,
            session_cookie(&headers),
        )
        .await?;
    Ok(session_json(
        StatusCode::OK,
        auth.session_response(
            state.browse(),
            &session.username,
            session.csrf_token,
            session.picture_url,
        )
        .await?,
        Some(session_cookie_header(
            &session.cookie_token,
            auth.inner.absolute_timeout_seconds,
        )),
    ))
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, AppError> {
    validate_same_origin(&headers)?;
    let auth = state.auth().ok_or(AppError::Internal)?;
    let session = auth.authenticate(&headers).await?;
    if !auth.verify_csrf(&session, &headers) {
        return Err(AppError::Forbidden);
    }
    auth.logout(&headers).await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, clear_session_cookie());
    no_store(response.headers_mut());
    Ok(response)
}

fn session_json(
    status: StatusCode,
    body: SessionResponse,
    set_cookie: Option<HeaderValue>,
) -> Response {
    let mut response = (status, Json(body)).into_response();
    if let Some(cookie) = set_cookie {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    no_store(response.headers_mut());
    response
}

fn no_store(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

pub(crate) fn session_cookie_header(token: &str, max_age: i64) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Strict"
    ))
    .expect("hex token and integer form a valid cookie")
}

fn clear_session_cookie() -> HeaderValue {
    HeaderValue::from_static(
        "__Host-crabinet_session=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Strict",
    )
}

pub(crate) fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    cookie_value(headers, SESSION_COOKIE)
}

/// Returns the single value of cookie `name`, or `None` when it is absent or
/// duplicated. Malformed or non-UTF-8 pairs set by unrelated applications on
/// the same site are skipped instead of hiding every other cookie.
pub(crate) fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut found = None;
    for header_value in headers.get_all(header::COOKIE) {
        for pair in header_value.as_bytes().split(|byte| *byte == b';') {
            let Ok(pair) = std::str::from_utf8(pair) else {
                continue;
            };
            let Some((key, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if key == name {
                if found.is_some() {
                    return None;
                }
                found = Some(value);
            }
        }
    }
    found
}

fn validate_same_origin(headers: &HeaderMap) -> Result<(), AppError> {
    if let Some(site) = headers.get("sec-fetch-site")
        && site.as_bytes() != b"same-origin"
    {
        return Err(AppError::Forbidden);
    }
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Forbidden)?;
    let source = headers
        .get(header::ORIGIN)
        .or_else(|| headers.get(header::REFERER))
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Forbidden)?;
    let uri = source
        .parse::<axum::http::Uri>()
        .map_err(|_| AppError::Forbidden)?;
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.authority().map(|authority| authority.as_str()) != Some(host)
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// Returns the hash verified for unknown or unusable accounts. It uses the most
/// expensive configured Argon2 cost, so a failed lookup takes as long as a real
/// verification and response timing does not reveal which accounts exist.
fn dummy_password_hash<'a>(hashes: impl Iterator<Item = &'a str>) -> String {
    let strongest = hashes
        .filter_map(|hash| {
            let parsed = PasswordHash::new(hash).ok()?;
            Some((
                parsed.params.get_decimal("m")?,
                parsed.params.get_decimal("t")?,
                parsed.params.get_decimal("p")?,
            ))
        })
        .max();
    let Some((memory, iterations, parallelism)) = strongest else {
        return DUMMY_PASSWORD_HASH.to_owned();
    };
    if (memory, iterations, parallelism)
        == (
            crate::password::PASSWORD_MEMORY_KIB,
            crate::password::PASSWORD_ITERATIONS,
            crate::password::PASSWORD_PARALLELISM,
        )
    {
        return DUMMY_PASSWORD_HASH.to_owned();
    }
    let mut password = [0_u8; TOKEN_BYTES];
    if random_fill(&mut password).is_err() {
        return DUMMY_PASSWORD_HASH.to_owned();
    }
    argon2::Params::new(memory, iterations, parallelism, None)
        .ok()
        .and_then(|params| {
            Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                .hash_password(&password)
                .ok()
        })
        .map_or_else(|| DUMMY_PASSWORD_HASH.to_owned(), |hash| hash.to_string())
}

fn verify_password(hash: &str, password: &[u8]) -> bool {
    PasswordHash::new(hash)
        .ok()
        .is_some_and(|parsed| Argon2::default().verify_password(password, &parsed).is_ok())
}

fn normalized_identifier_digest(username: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    for byte in username.trim().bytes() {
        digest.update([byte.to_ascii_lowercase()]);
    }
    digest.finalize().into()
}

fn gravatar_picture_url(email: &str) -> String {
    format!(
        "https://www.gravatar.com/avatar/{}?s=64&d=identicon",
        encode_hex(&normalized_identifier_digest(email))
    )
}

fn is_plausible_username(username: &str) -> bool {
    (1..=MAX_USERNAME_BYTES).contains(&username.len())
        && username != "."
        && username != ".."
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(crate) fn decode_token(value: &str) -> Option<[u8; TOKEN_BYTES]> {
    if value.len() != TOKEN_BYTES * 2 {
        return None;
    }
    let mut decoded = [0_u8; TOKEN_BYTES];
    for (target, pair) in decoded.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        *target = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Some(decoded)
}

fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "unit tests build synthetic fixtures in temporary directories"
)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicI64, Ordering},
    };

    use argon2::{Algorithm, Params, Version, password_hash::PasswordHasher};
    use axum::{Router, body::to_bytes, http::Request};
    use tempfile::TempDir;
    use tower::ServiceExt;

    use super::*;
    use crate::{
        app::{AppState, router as app_router},
        browse::{BrowseLimits, BrowseState, ConfiguredShare},
        filesystem::{GlobalPolicy, ShareFs},
        mutations::{MutationLimits, MutationState},
    };

    struct TestClock(AtomicI64);

    impl TestClock {
        fn new(now: i64) -> Self {
            Self(AtomicI64::new(now))
        }

        fn set(&self, now: i64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    struct TestAuth {
        _directory: TempDir,
        service: AuthService,
        clock: Arc<TestClock>,
    }

    fn test_auth(concurrency: usize, attempts: u32) -> TestAuth {
        test_auth_with_source_limit(concurrency, attempts, 1_000)
    }

    fn test_auth_with_source_limit(
        concurrency: usize,
        attempts: u32,
        attempts_per_source: u32,
    ) -> TestAuth {
        let directory = tempfile::tempdir().unwrap();
        let store = SessionStore::open(&directory.path().join("sessions.sqlite3")).unwrap();
        let password_hash = test_hash("a very long unicode password 🙂");
        let disabled_hash = test_hash("disabled password");
        let bob_hash = test_hash("bob password");
        let users = HashMap::from([
            (
                "Alice".to_owned(),
                UserRecord {
                    password_hash: Some(password_hash),
                    email: None,
                    disabled: false,
                },
            ),
            (
                "disabled".to_owned(),
                UserRecord {
                    password_hash: Some(disabled_hash),
                    email: None,
                    disabled: true,
                },
            ),
            (
                "Bob".to_owned(),
                UserRecord {
                    password_hash: Some(bob_hash),
                    email: None,
                    disabled: false,
                },
            ),
        ]);
        let shares = vec![
            ShareRecord {
                id: "documents".to_owned(),
                name: "Documents".to_owned(),
                grants: HashMap::from([
                    ("Alice".to_owned(), Permission::Write),
                    ("disabled".to_owned(), Permission::Read),
                ]),
                read_only: false,
            },
            ShareRecord {
                id: "private".to_owned(),
                name: "Private".to_owned(),
                grants: HashMap::from([("Bob".to_owned(), Permission::Write)]),
                read_only: false,
            },
        ];
        let clock = Arc::new(TestClock::new(1_000_000));
        let service = AuthService::new(
            users,
            true,
            shares,
            store,
            vec![0x5a; 32],
            concurrency,
            120,
            600,
            attempts,
            attempts_per_source,
            2,
            3,
            clock.clone(),
        );
        TestAuth {
            _directory: directory,
            service,
            clock,
        }
    }

    fn test_hash(password: &str) -> String {
        let parameters = Params::new(8, 1, 1, None).unwrap();
        Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters)
            .hash_password(password.as_bytes())
            .unwrap()
            .to_string()
    }

    fn post(path: &str, body: impl Into<Body>) -> Request<Body> {
        Request::post(path)
            .header(header::HOST, "files.example.test")
            .header(header::ORIGIN, "https://files.example.test")
            .header("sec-fetch-site", "same-origin")
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.into())
            .unwrap()
    }

    fn cookie_pair(response: &Response) -> String {
        response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    async fn login_response(service: &AuthService) -> Response {
        app_router(AppState::with_auth(true, service.clone()))
            .oneshot(post(
                "/api/v1/auth/login",
                r#"{"username":"Alice","password":"a very long unicode password 🙂"}"#,
            ))
            .await
            .unwrap()
    }

    fn protected_app(
        service: AuthService,
        documents: &std::path::Path,
        private: &std::path::Path,
    ) -> Router {
        let shares = [
            ("documents", "Documents", documents),
            ("private", "Private", private),
        ]
        .into_iter()
        .map(|(id, name, root)| {
            let id = ShareId::new(id).expect("share id");
            let filesystem = ShareFs::open(id, root).expect("share filesystem");
            ConfiguredShare::new(name, filesystem).expect("configured share")
        })
        .collect();
        let browse = BrowseState::new(
            shares,
            BrowseLimits::default(),
            GlobalPolicy::default(),
            [0x5a; 32],
        )
        .expect("browse state");
        let mutations = MutationState::new(MutationLimits::default()).expect("mutation state");
        app_router(
            AppState::with_auth(true, service)
                .with_browse(browse)
                .with_mutations(mutations),
        )
    }

    async fn login_as(app: &Router, username: &str, password: &str) -> (String, String) {
        let payload = serde_json::json!({"username": username, "password": password});
        let response = app
            .clone()
            .oneshot(post("/api/v1/auth/login", payload.to_string()))
            .await
            .expect("login response");
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = cookie_pair(&response);
        let body = to_bytes(response.into_body(), 16_384)
            .await
            .expect("login body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("login JSON");
        let csrf = json["csrfToken"].as_str().expect("CSRF token").to_owned();
        (cookie, csrf)
    }

    fn mutation_request(path: &str, cookie: &str, csrf: Option<&str>) -> Request<Body> {
        let mut request = Request::post("/api/v1/shares/documents/files")
            .header(header::HOST, "files.example.test")
            .header(header::ORIGIN, "https://files.example.test")
            .header("sec-fetch-site", "same-origin")
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(csrf) = csrf {
            request = request.header("x-csrf-token", csrf);
        }
        request
            .body(Body::from(serde_json::json!({"path": path}).to_string()))
            .expect("mutation request")
    }

    #[tokio::test]
    async fn real_auth_middleware_enforces_user_and_share_isolation() {
        let auth = test_auth(1, 20);
        let documents = TempDir::new().expect("documents root");
        let private = TempDir::new().expect("private root");
        fs::write(documents.path().join("alice.txt"), b"alice").expect("Alice fixture");
        fs::write(private.path().join("bob.txt"), b"bob").expect("Bob fixture");
        let app = protected_app(auth.service, documents.path(), private.path());

        let anonymous = app
            .clone()
            .oneshot(Request::get("/api/v1/shares").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

        let (alice_cookie, _) = login_as(&app, "Alice", "a very long unicode password 🙂").await;
        let (bob_cookie, _) = login_as(&app, "Bob", "bob password").await;
        for (cookie, allowed, denied, marker) in [
            (&alice_cookie, "documents", "private", "alice.txt"),
            (&bob_cookie, "private", "documents", "bob.txt"),
        ] {
            let allowed = app
                .clone()
                .oneshot(
                    Request::get(format!("/api/v1/shares/{allowed}/directory"))
                        .header(header::COOKIE, cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(allowed.status(), StatusCode::OK);
            let body = to_bytes(allowed.into_body(), 16_384).await.unwrap();
            assert!(String::from_utf8_lossy(&body).contains(marker));

            let denied = app
                .clone()
                .oneshot(
                    Request::get(format!("/api/v1/shares/{denied}/directory"))
                        .header(header::COOKIE, cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(denied.status(), StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn real_state_change_middleware_wires_csrf_and_effective_access() {
        let auth = test_auth(1, 20);
        let documents = TempDir::new().expect("documents root");
        let private = TempDir::new().expect("private root");
        let app = protected_app(auth.service, documents.path(), private.path());
        let (cookie, csrf) = login_as(&app, "Alice", "a very long unicode password 🙂").await;

        for (path, presented_csrf) in [("missing.txt", None), ("wrong.txt", Some("00"))] {
            let response = app
                .clone()
                .oneshot(mutation_request(path, &cookie, presented_csrf))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(!documents.path().join(path).exists());
        }

        let response = app
            .clone()
            .oneshot(mutation_request("created.txt", &cookie, Some(&csrf)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(documents.path().join("created.txt").is_file());

        let mut read_only_auth = test_auth(1, 20);
        Arc::get_mut(&mut read_only_auth.service.inner)
            .expect("unshared auth service")
            .shares
            .iter_mut()
            .find(|share| share.id == "documents")
            .expect("documents share")
            .read_only = true;
        let read_only_documents = TempDir::new().expect("read-only documents root");
        let read_only_private = TempDir::new().expect("read-only private root");
        let read_only_app = protected_app(
            read_only_auth.service,
            read_only_documents.path(),
            read_only_private.path(),
        );
        let (cookie, csrf) =
            login_as(&read_only_app, "Alice", "a very long unicode password 🙂").await;
        let response = read_only_app
            .oneshot(mutation_request("blocked.txt", &cookie, Some(&csrf)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!read_only_documents.path().join("blocked.txt").exists());
    }

    #[tokio::test]
    async fn event_streams_end_soon_after_their_session_is_signed_out() {
        let auth = test_auth(1, 20);
        let documents = TempDir::new().expect("documents root");
        let private = TempDir::new().expect("private root");
        let app = protected_app(auth.service, documents.path(), private.path());
        let (cookie, csrf) = login_as(&app, "Alice", "a very long unicode password 🙂").await;
        let events = || {
            Request::get("/api/v1/shares/documents/events")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap()
        };

        // While the session is valid, the stream stays open past several
        // session checks.
        let open = app.clone().oneshot(events()).await.unwrap();
        assert_eq!(open.status(), StatusCode::OK);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                to_bytes(open.into_body(), 16_384)
            )
            .await
            .is_err()
        );

        let stream = app.clone().oneshot(events()).await.unwrap();
        assert_eq!(stream.status(), StatusCode::OK);
        let logout = app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/logout")
                    .header(header::HOST, "files.example.test")
                    .header(header::ORIGIN, "https://files.example.test")
                    .header("sec-fetch-site", "same-origin")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::NO_CONTENT);
        // The stream ends at its next session check, long before its
        // 60-second lifetime.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            to_bytes(stream.into_body(), 16_384),
        )
        .await
        .expect("signed-out stream ends")
        .expect("stream body");
    }

    #[tokio::test]
    async fn login_session_logout_and_replay_are_protected() {
        let auth = test_auth(1, 5);
        let login = login_response(&auth.service).await;
        assert_eq!(login.status(), StatusCode::OK);
        let set_cookie = login
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("Secure"));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Strict"));
        assert!(set_cookie.contains("Path=/"));
        assert!(set_cookie.contains("Max-Age=600"));
        assert_eq!(login.headers()[header::CACHE_CONTROL], "no-store");
        let cookie = cookie_pair(&login);
        let login_body = to_bytes(login.into_body(), 16_384).await.unwrap();
        let login_json: serde_json::Value = serde_json::from_slice(&login_body).unwrap();
        let csrf = login_json["csrfToken"].as_str().unwrap().to_owned();
        assert_eq!(login_json["user"]["username"], "Alice");
        assert_eq!(login_json["shares"][0]["access"], "read-write");

        let session = app_router(AppState::with_auth(true, auth.service.clone()))
            .oneshot(
                Request::get("/api/v1/session")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(session.status(), StatusCode::OK);
        assert!(session.headers().get(header::SET_COOKIE).is_none());
        let session_body = to_bytes(session.into_body(), 16_384).await.unwrap();
        let session_json: serde_json::Value = serde_json::from_slice(&session_body).unwrap();
        assert_eq!(session_json["csrfToken"], csrf);
        assert_eq!(session_json["version"], env!("CARGO_PKG_VERSION"));

        let rejected_logout = app_router(AppState::with_auth(true, auth.service.clone()))
            .oneshot(post("/api/v1/auth/logout", ""))
            .await
            .unwrap();
        assert_eq!(rejected_logout.status(), StatusCode::UNAUTHORIZED);

        let logout = app_router(AppState::with_auth(true, auth.service.clone()))
            .oneshot(
                Request::post("/api/v1/auth/logout")
                    .header(header::HOST, "files.example.test")
                    .header(header::ORIGIN, "https://files.example.test")
                    .header("sec-fetch-site", "same-origin")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::NO_CONTENT);
        assert!(
            logout.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );

        let replay = app_router(AppState::with_auth(true, auth.service.clone()))
            .oneshot(
                Request::get("/api/v1/session")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn successful_login_rotates_a_presented_session() {
        let auth = test_auth(1, 5);
        let first = login_response(&auth.service).await;
        let old_cookie = cookie_pair(&first);
        let second = app_router(AppState::with_auth(true, auth.service.clone()))
            .oneshot(post(
                "/api/v1/auth/login",
                r#"{"username":"Alice","password":"a very long unicode password 🙂"}"#,
            ))
            .await
            .unwrap();
        let new_cookie = cookie_pair(&second);
        assert_ne!(old_cookie, new_cookie);

        // Rotation is tied to a presented cookie; repeat with the old cookie supplied.
        let rotated = app_router(AppState::with_auth(true, auth.service.clone()))
            .oneshot(
                Request::post("/api/v1/auth/login")
                    .header(header::HOST, "files.example.test")
                    .header(header::ORIGIN, "https://files.example.test")
                    .header("sec-fetch-site", "same-origin")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &old_cookie)
                    .body(Body::from(
                        r#"{"username":"Alice","password":"a very long unicode password 🙂"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rotated.status(), StatusCode::OK);
        let old_replay = app_router(AppState::with_auth(true, auth.service.clone()))
            .oneshot(
                Request::get("/api/v1/session")
                    .header(header::COOKIE, old_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(old_replay.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn default_folder_is_per_user_validated_and_csrf_protected() {
        let auth = test_auth(1, 5);
        let documents = tempfile::tempdir().unwrap();
        let private = tempfile::tempdir().unwrap();
        std::fs::create_dir(documents.path().join("nested")).unwrap();
        std::fs::write(documents.path().join("file.txt"), b"file").unwrap();
        let app = protected_app(auth.service, documents.path(), private.path());
        let (alice_cookie, alice_csrf) =
            login_as(&app, "Alice", "a very long unicode password 🙂").await;

        let put = |cookie: &str, csrf: Option<&str>, body: &str| {
            let mut request = Request::put("/api/v1/preferences")
                .header(header::HOST, "files.example.test")
                .header(header::ORIGIN, "https://files.example.test")
                .header("sec-fetch-site", "same-origin")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie);
            if let Some(csrf) = csrf {
                request = request.header("x-csrf-token", csrf);
            }
            request.body(Body::from(body.to_owned())).unwrap()
        };

        let selected = r#"{"defaultFolder":{"shareId":"documents","path":"nested"}}"#;
        let forbidden = app
            .clone()
            .oneshot(put(&alice_cookie, None, selected))
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        for invalid in [
            r#"{"defaultFolder":{"shareId":"private","path":""}}"#,
            r#"{"defaultFolder":{"shareId":"documents","path":"file.txt"}}"#,
            r#"{"defaultFolder":{"shareId":"documents","path":"missing"}}"#,
            r#"{"defaultFolder":{"shareId":"documents","path":"../nested"}}"#,
        ] {
            let response = app
                .clone()
                .oneshot(put(&alice_cookie, Some(&alice_csrf), invalid))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        let saved = app
            .clone()
            .oneshot(put(&alice_cookie, Some(&alice_csrf), selected))
            .await
            .unwrap();
        assert_eq!(saved.status(), StatusCode::OK);
        assert_eq!(saved.headers()[header::CACHE_CONTROL], "no-store");

        let alice_session = app
            .clone()
            .oneshot(
                Request::get("/api/v1/session")
                    .header(header::COOKIE, &alice_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(alice_session.into_body(), 16_384).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["defaultFolder"]["shareId"], "documents");
        assert_eq!(body["defaultFolder"]["path"], "nested");

        let (bob_cookie, _) = login_as(&app, "Bob", "bob password").await;
        let bob_session = app
            .clone()
            .oneshot(
                Request::get("/api/v1/session")
                    .header(header::COOKIE, bob_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(bob_session.into_body(), 16_384).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body["defaultFolder"].is_null());

        let reset = app
            .oneshot(put(
                &alice_cookie,
                Some(&alice_csrf),
                r#"{"defaultFolder":null}"#,
            ))
            .await
            .unwrap();
        assert_eq!(reset.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn display_preferences_are_validated_csrf_protected_and_in_the_session() {
        let auth = test_auth(1, 5);
        let documents = tempfile::tempdir().unwrap();
        let private = tempfile::tempdir().unwrap();
        let app = protected_app(auth.service, documents.path(), private.path());
        let (alice_cookie, alice_csrf) =
            login_as(&app, "Alice", "a very long unicode password 🙂").await;

        let put = |path: &str, csrf: Option<&str>, body: &str| {
            let mut request = Request::put(path)
                .header(header::HOST, "files.example.test")
                .header(header::ORIGIN, "https://files.example.test")
                .header("sec-fetch-site", "same-origin")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &alice_cookie);
            if let Some(csrf) = csrf {
                request = request.header("x-csrf-token", csrf);
            }
            request.body(Body::from(body.to_owned())).unwrap()
        };
        let session_body = |cookie: String| {
            let app = app.clone();
            async move {
                let response = app
                    .oneshot(
                        Request::get("/api/v1/session")
                            .header(header::COOKIE, cookie)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let body = to_bytes(response.into_body(), 16_384).await.unwrap();
                serde_json::from_slice::<serde_json::Value>(&body).unwrap()
            }
        };
        let path = "/api/v1/preferences/display";

        assert_eq!(
            session_body(alice_cookie.clone()).await["preferences"],
            serde_json::json!({"showHiddenFiles": false, "theme": "system"})
        );

        let forbidden = app
            .clone()
            .oneshot(put(path, None, r#"{"theme":"dark"}"#))
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        for invalid in [
            r#"{"theme":"sepia"}"#,
            r#"{"theme":"Dark"}"#,
            r#"{"theme":null}"#,
            r#"{"showHiddenFiles":"false"}"#,
            r#"{"showHiddenFiles":null}"#,
            r#"{"theme":"dark","defaultFolder":null}"#,
            r#"{"fontSize":12}"#,
            "not json",
        ] {
            let response = app
                .clone()
                .oneshot(put(path, Some(&alice_csrf), invalid))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{invalid}");
            let body = to_bytes(response.into_body(), 16_384).await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["error"]["code"], "invalid_request", "{invalid}");
        }
        assert_eq!(
            session_body(alice_cookie.clone()).await["preferences"],
            serde_json::json!({"showHiddenFiles": false, "theme": "system"})
        );

        let folder = app
            .clone()
            .oneshot(put(
                "/api/v1/preferences",
                Some(&alice_csrf),
                r#"{"defaultFolder":{"shareId":"documents","path":""}}"#,
            ))
            .await
            .unwrap();
        assert_eq!(folder.status(), StatusCode::OK);

        let saved = app
            .clone()
            .oneshot(put(path, Some(&alice_csrf), r#"{"theme":"dark"}"#))
            .await
            .unwrap();
        assert_eq!(saved.status(), StatusCode::OK);
        assert_eq!(saved.headers()[header::CACHE_CONTROL], "no-store");
        let body = to_bytes(saved.into_body(), 16_384).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"showHiddenFiles": false, "theme": "dark"})
        );

        let saved = app
            .clone()
            .oneshot(put(path, Some(&alice_csrf), r#"{"showHiddenFiles":true}"#))
            .await
            .unwrap();
        let body = to_bytes(saved.into_body(), 16_384).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"showHiddenFiles": true, "theme": "dark"})
        );

        let session = session_body(alice_cookie.clone()).await;
        assert_eq!(
            session["preferences"],
            serde_json::json!({"showHiddenFiles": true, "theme": "dark"})
        );
        assert_eq!(session["defaultFolder"]["shareId"], "documents");

        let (bob_cookie, _) = login_as(&app, "Bob", "bob password").await;
        assert_eq!(
            session_body(bob_cookie).await["preferences"],
            serde_json::json!({"showHiddenFiles": false, "theme": "system"})
        );
    }

    #[tokio::test]
    async fn display_preferences_and_start_folder_update_independently() {
        let auth = test_auth(1, 5);
        let store = &auth.service.inner.store;
        let folder = DefaultFolder {
            share_id: "documents".to_owned(),
            path: "nested".to_owned(),
        };
        let row_count = || {
            store
                .connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM user_preferences WHERE username = 'Alice'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
        };

        store
            .set_default_folder("Alice", Some(folder.clone()))
            .await
            .unwrap();
        let saved = store
            .update_display_preferences(
                "Alice",
                DisplayPreferencesUpdate {
                    theme: Some(ThemePreference::Light),
                    ..DisplayPreferencesUpdate::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            saved,
            DisplayPreferences {
                show_hidden_files: false,
                theme: ThemePreference::Light,
            }
        );
        assert_eq!(store.default_folder("Alice").await.unwrap(), Some(folder));

        store
            .update_display_preferences(
                "Alice",
                DisplayPreferencesUpdate {
                    show_hidden_files: Some(true),
                    ..DisplayPreferencesUpdate::default()
                },
            )
            .await
            .unwrap();
        let other = DefaultFolder {
            share_id: "documents".to_owned(),
            path: String::new(),
        };
        store
            .set_default_folder("Alice", Some(other.clone()))
            .await
            .unwrap();
        assert_eq!(store.default_folder("Alice").await.unwrap(), Some(other));
        assert_eq!(
            store.display_preferences("Alice").await.unwrap(),
            DisplayPreferences {
                show_hidden_files: true,
                theme: ThemePreference::Light,
            }
        );

        store.set_default_folder("Alice", None).await.unwrap();
        assert_eq!(store.default_folder("Alice").await.unwrap(), None);
        assert_eq!(
            store.display_preferences("Alice").await.unwrap(),
            DisplayPreferences {
                show_hidden_files: true,
                theme: ThemePreference::Light,
            }
        );
        assert_eq!(row_count(), 1);

        let reset = store
            .update_display_preferences(
                "Alice",
                DisplayPreferencesUpdate {
                    show_hidden_files: Some(false),
                    theme: Some(ThemePreference::System),
                },
            )
            .await
            .unwrap();
        assert_eq!(reset, DisplayPreferences::default());
        assert_eq!(row_count(), 0);
        assert_eq!(
            store.display_preferences("Bob").await.unwrap(),
            DisplayPreferences::default()
        );
    }

    #[tokio::test]
    async fn version_four_database_gains_display_defaults_and_keeps_start_folders() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sessions.sqlite3");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE sessions (
                   session_key BLOB PRIMARY KEY NOT NULL CHECK(length(session_key) = 32),
                   username TEXT NOT NULL,
                   created_at INTEGER NOT NULL,
                   last_seen_at INTEGER NOT NULL,
                   expires_at INTEGER NOT NULL,
                   picture_url TEXT
                 ) WITHOUT ROWID;
                 CREATE INDEX sessions_expiration ON sessions(expires_at);
                 CREATE TABLE user_preferences (
                   username TEXT PRIMARY KEY NOT NULL,
                   default_share_id TEXT NOT NULL,
                   default_path TEXT NOT NULL
                 ) WITHOUT ROWID;
                 CREATE TABLE passkey_users (
                   username TEXT PRIMARY KEY NOT NULL,
                   user_handle BLOB NOT NULL UNIQUE CHECK(length(user_handle) = 16)
                 ) WITHOUT ROWID;
                 CREATE TABLE passkeys (
                   id TEXT PRIMARY KEY NOT NULL,
                   username TEXT NOT NULL,
                   credential_id BLOB NOT NULL UNIQUE,
                   name TEXT NOT NULL,
                   credential_json TEXT NOT NULL,
                   created_at INTEGER NOT NULL,
                   last_used_at INTEGER
                 ) WITHOUT ROWID;
                 CREATE INDEX passkeys_user ON passkeys(username);
                 INSERT INTO user_preferences VALUES
                   ('Alice', 'documents', 'nested'), ('Bob', 'private', '');
                 PRAGMA user_version = 4;",
            )
            .unwrap();
        drop(connection);

        let store = SessionStore::open(&path).unwrap();
        {
            let connection = store.connection.lock().unwrap();
            let version: i64 = connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(version, 5);
            let rejected = connection.execute(
                "UPDATE user_preferences SET theme = 'sepia' WHERE username = 'Alice'",
                [],
            );
            assert!(rejected.is_err());
        }
        assert_eq!(
            store.default_folder("Alice").await.unwrap(),
            Some(DefaultFolder {
                share_id: "documents".to_owned(),
                path: "nested".to_owned(),
            })
        );
        assert_eq!(
            store.default_folder("Bob").await.unwrap(),
            Some(DefaultFolder {
                share_id: "private".to_owned(),
                path: String::new(),
            })
        );
        for username in ["Alice", "Bob", "Carol"] {
            assert_eq!(
                store.display_preferences(username).await.unwrap(),
                DisplayPreferences::default()
            );
        }
        drop(store);

        // Reopening a current database is a no-op.
        let store = SessionStore::open(&path).unwrap();
        assert!(store.default_folder("Alice").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn version_one_session_database_migrates_without_losing_sessions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sessions.sqlite3");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE sessions (
                   session_key BLOB PRIMARY KEY NOT NULL,
                   username TEXT NOT NULL,
                   created_at INTEGER NOT NULL,
                   last_seen_at INTEGER NOT NULL,
                   expires_at INTEGER NOT NULL
                 ) WITHOUT ROWID;
                 INSERT INTO sessions VALUES (zeroblob(32), 'Alice', 1, 1, 100);
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        drop(connection);

        let store = SessionStore::open(&path).unwrap();
        let connection = store.connection.lock().unwrap();
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let sessions: i64 = connection
            .query_row("SELECT count(*) FROM sessions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SESSION_SCHEMA_VERSION);
        assert_eq!(sessions, 1);
        let picture: Option<String> = connection
            .query_row("SELECT picture_url FROM sessions", [], |row| row.get(0))
            .unwrap();
        assert!(picture.is_none());
    }

    #[tokio::test]
    async fn passkey_registration_requires_session_and_csrf_and_returns_browser_options() {
        let mut test = test_auth(1, 5);
        Arc::get_mut(&mut test.service.inner).unwrap().passkeys = Some(
            passkeys::PasskeyState::new(&url::Url::parse("https://files.example.test").unwrap())
                .unwrap(),
        );
        let app = app_router(AppState::with_auth(true, test.service.clone()));
        let login = login_response(&test.service).await;
        let cookie = cookie_pair(&login);
        let json: serde_json::Value =
            serde_json::from_slice(&to_bytes(login.into_body(), 16_384).await.unwrap()).unwrap();
        let csrf = json["csrfToken"].as_str().unwrap();
        let path = "/api/v1/auth/passkeys/register/start";
        let body = r#"{"name":"My laptop"}"#;
        assert_eq!(
            app.clone()
                .oneshot(post(path, body))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let without_csrf = Request::post(path)
            .header(header::HOST, "files.example.test")
            .header(header::ORIGIN, "https://files.example.test")
            .header("sec-fetch-site", "same-origin")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &cookie)
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(without_csrf).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let response = app
            .oneshot(
                Request::post(path)
                    .header(header::HOST, "files.example.test")
                    .header(header::ORIGIN, "https://files.example.test")
                    .header("sec-fetch-site", "same-origin")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", csrf)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let challenge: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65_536).await.unwrap()).unwrap();
        assert!(challenge["flowId"].as_str().is_some());
        assert!(
            challenge["options"]["publicKey"]["challenge"]
                .as_str()
                .is_some()
        );
        assert_eq!(
            challenge["options"]["publicKey"]["authenticatorSelection"]["residentKey"],
            "required"
        );
        assert_eq!(
            challenge["options"]["publicKey"]["authenticatorSelection"]["requireResidentKey"],
            true
        );
    }

    #[tokio::test]
    async fn passkey_login_can_start_without_an_account_name() {
        let mut test = test_auth(1, 5);
        Arc::get_mut(&mut test.service.inner).unwrap().passkeys = Some(
            passkeys::PasskeyState::new(&url::Url::parse("https://files.example.test").unwrap())
                .unwrap(),
        );
        let app = app_router(AppState::with_auth(true, test.service));
        let response = app
            .oneshot(
                Request::post("/api/v1/auth/passkeys/login/start")
                    .header(header::HOST, "files.example.test")
                    .header(header::ORIGIN, "https://files.example.test")
                    .header("sec-fetch-site", "same-origin")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let challenge: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65_536).await.unwrap()).unwrap();
        assert!(challenge["flowId"].as_str().is_some());
        assert!(
            challenge["options"]["publicKey"]["allowCredentials"]
                .as_array()
                .is_none_or(Vec::is_empty)
        );
    }

    #[tokio::test]
    async fn oidc_email_mapping_issues_only_enabled_local_user_sessions() {
        let mut test = test_auth(1, 5);
        let inner = Arc::get_mut(&mut test.service.inner).unwrap();
        inner.users.get_mut("Alice").unwrap().email = Some("alice@example.com".into());
        inner.users.get_mut("disabled").unwrap().email = Some("disabled@example.com".into());
        inner.password_enabled = false;
        assert!(matches!(
            test.service
                .login("Alice", "a very long unicode password 🙂", None, None)
                .await,
            Err(AppError::AuthenticationFailed)
        ));
        assert!(matches!(
            test.service
                .login_oidc("unknown@example.com", None, None)
                .await,
            Err(AppError::AuthenticationFailed)
        ));
        assert!(matches!(
            test.service
                .login_oidc("disabled@example.com", None, None)
                .await,
            Err(AppError::AuthenticationFailed)
        ));
        let (username, cookie, _) = test
            .service
            .login_oidc(
                "ALICE@example.com",
                Some("https://lh3.googleusercontent.com/a/test-avatar"),
                None,
            )
            .await
            .unwrap();
        assert_eq!(username, "Alice");
        let session = test
            .service
            .authenticate(&headers_with_cookie(&format!("{SESSION_COOKIE}={cookie}")))
            .await
            .unwrap();
        assert_eq!(session.principal.username(), "Alice");
        assert_eq!(
            session.picture_url.as_deref(),
            Some("https://lh3.googleusercontent.com/a/test-avatar")
        );
    }

    #[tokio::test]
    async fn password_login_does_not_inherit_google_picture() {
        let mut test = test_auth(1, 5);
        Arc::get_mut(&mut test.service.inner)
            .unwrap()
            .users
            .get_mut("Alice")
            .unwrap()
            .email = Some("alice@example.com".into());
        let (_, google_cookie, _) = test
            .service
            .login_oidc(
                "alice@example.com",
                Some("https://lh3.googleusercontent.com/a/avatar"),
                None,
            )
            .await
            .unwrap();
        let password_session = test
            .service
            .login(
                "Alice",
                "a very long unicode password 🙂",
                None,
                Some(&google_cookie),
            )
            .await
            .unwrap();
        assert!(password_session.picture_url.is_none());
        let session = test
            .service
            .authenticate(&headers_with_cookie(&format!(
                "{SESSION_COOKIE}={}",
                password_session.cookie_token
            )))
            .await
            .unwrap();
        assert!(session.picture_url.is_none());
    }

    #[tokio::test]
    async fn session_response_uses_gravatar_when_no_google_picture_is_present() {
        let mut test = test_auth(1, 5);
        Arc::get_mut(&mut test.service.inner)
            .unwrap()
            .users
            .get_mut("Alice")
            .unwrap()
            .email = Some("Alice@Example.com".into());
        let state = AppState::new(true);
        let disabled = test
            .service
            .session_response(state.browse(), "Alice", "csrf".into(), None)
            .await
            .unwrap();
        assert!(disabled.user.picture_url.is_none());
        Arc::get_mut(&mut test.service.inner)
            .unwrap()
            .gravatar_enabled = true;
        let fallback = test
            .service
            .session_response(state.browse(), "Alice", "csrf".into(), None)
            .await
            .unwrap();
        assert_eq!(
            fallback.user.picture_url.as_deref(),
            Some(
                "https://www.gravatar.com/avatar/ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976?s=64&d=identicon"
            )
        );
        let google = test
            .service
            .session_response(
                state.browse(),
                "Alice",
                "csrf".into(),
                Some("https://lh3.googleusercontent.com/a/avatar".into()),
            )
            .await
            .unwrap();
        assert_eq!(
            google.user.picture_url.as_deref(),
            Some("https://lh3.googleusercontent.com/a/avatar")
        );
    }

    #[tokio::test]
    async fn password_login_accepts_username_or_configured_email() {
        let mut test = test_auth(1, 5);
        let inner = Arc::get_mut(&mut test.service.inner).unwrap();
        inner.users.get_mut("Alice").unwrap().email = Some("alice@example.com".into());
        let by_email = test
            .service
            .login(
                "ALICE@example.com",
                "a very long unicode password 🙂",
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(by_email.username, "Alice");
        assert!(matches!(
            test.service
                .login("alice@example.com", "wrong password", None, None)
                .await,
            Err(AppError::AuthenticationFailed)
        ));
        let by_username = test
            .service
            .login("Alice", "a very long unicode password 🙂", None, None)
            .await
            .unwrap();
        assert_eq!(by_username.username, "Alice");
    }

    #[tokio::test]
    async fn database_stores_only_a_keyed_session_digest() {
        let auth = test_auth(1, 5);
        let session = auth
            .service
            .login("Alice", "a very long unicode password 🙂", None, None)
            .await
            .unwrap();
        let raw = decode_token(&session.cookie_token).unwrap();
        let stored: Vec<u8> = auth
            .service
            .inner
            .store
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT session_key FROM sessions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(stored.len(), 32);
        assert_ne!(stored, raw);
    }

    #[cfg(unix)]
    #[test]
    fn newly_created_database_is_owner_only_and_existing_mode_is_preserved() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let created_path = directory.path().join("created.sqlite3");
        SessionStore::open(&created_path).unwrap();
        assert_eq!(
            std::fs::metadata(&created_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let existing_path = directory.path().join("existing.sqlite3");
        std::fs::write(&existing_path, []).unwrap();
        std::fs::set_permissions(&existing_path, std::fs::Permissions::from_mode(0o640)).unwrap();
        SessionStore::open(&existing_path).unwrap();
        assert_eq!(
            std::fs::metadata(&existing_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
    }

    #[tokio::test]
    async fn persistent_session_counts_are_bounded_without_an_old_cookie() {
        let auth = test_auth(1, 20);
        let mut alice_sessions = Vec::new();
        for offset in 0..3 {
            auth.clock.set(1_000_000 + offset);
            alice_sessions.push(
                auth.service
                    .login("Alice", "a very long unicode password 🙂", None, None)
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(session_count(&auth.service, Some("Alice")), 2);
        assert!(matches!(
            auth.service
                .authenticate(&headers_with_cookie(&format!(
                    "{SESSION_COOKIE}={}",
                    alice_sessions[0].cookie_token
                )))
                .await,
            Err(AppError::Unauthorized)
        ));

        for offset in 3..5 {
            auth.clock.set(1_000_000 + offset);
            auth.service
                .login("Bob", "bob password", None, None)
                .await
                .unwrap();
        }
        assert_eq!(session_count(&auth.service, None), 3);
        assert_eq!(session_count(&auth.service, Some("Alice")), 1);
        assert_eq!(session_count(&auth.service, Some("Bob")), 2);
    }

    #[tokio::test]
    async fn newest_session_survives_caps_when_all_timestamps_tie() {
        let auth = test_auth(1, 20);
        for (username, password) in [
            ("Alice", "a very long unicode password 🙂"),
            ("Bob", "bob password"),
            ("Alice", "a very long unicode password 🙂"),
            ("Bob", "bob password"),
            ("Alice", "a very long unicode password 🙂"),
            ("Bob", "bob password"),
        ] {
            let issued = auth
                .service
                .login(username, password, None, None)
                .await
                .unwrap();
            let authenticated = auth
                .service
                .authenticate(&headers_with_cookie(&format!(
                    "{SESSION_COOKIE}={}",
                    issued.cookie_token
                )))
                .await
                .unwrap();
            assert_eq!(authenticated.principal.username(), username);
            assert!(session_count(&auth.service, Some(username)) <= 2);
            assert!(session_count(&auth.service, None) <= 3);
        }
    }

    #[tokio::test]
    async fn idle_and_absolute_expiration_delete_sessions() {
        let auth = test_auth(1, 5);
        let first = login_response(&auth.service).await;
        let idle_cookie = cookie_pair(&first);
        auth.clock.set(1_000_120);
        let expired = auth
            .service
            .authenticate(&headers_with_cookie(&idle_cookie))
            .await;
        assert!(matches!(expired, Err(AppError::Unauthorized)));
        assert!(matches!(
            auth.service
                .authenticate(&headers_with_cookie(&idle_cookie))
                .await,
            Err(AppError::Unauthorized)
        ));

        auth.clock.set(2_000_000);
        let second = login_response(&auth.service).await;
        let absolute_cookie = cookie_pair(&second);
        // Keep touching before each idle boundary, then pass the absolute lifetime.
        for offset in [100, 200, 300, 400, 500, 590] {
            auth.clock.set(2_000_000 + offset);
            auth.service
                .authenticate(&headers_with_cookie(&absolute_cookie))
                .await
                .unwrap();
        }
        auth.clock.set(2_000_600);
        assert!(matches!(
            auth.service
                .authenticate(&headers_with_cookie(&absolute_cookie))
                .await,
            Err(AppError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn removed_and_disabled_users_immediately_lose_persisted_sessions() {
        let auth = test_auth(1, 5);
        let removed_session = auth
            .service
            .login("Alice", "a very long unicode password 🙂", None, None)
            .await
            .unwrap();
        let disabled_session = auth
            .service
            .login("Alice", "a very long unicode password 🙂", None, None)
            .await
            .unwrap();
        let removed = AuthService::new(
            HashMap::new(),
            true,
            Vec::new(),
            auth.service.inner.store.clone(),
            vec![0x5a; 32],
            1,
            120,
            600,
            5,
            20,
            2,
            3,
            auth.clock.clone(),
        );
        assert!(matches!(
            removed
                .authenticate(&headers_with_cookie(&format!(
                    "{SESSION_COOKIE}={}",
                    removed_session.cookie_token
                )))
                .await,
            Err(AppError::Unauthorized)
        ));

        let disabled = AuthService::new(
            HashMap::from([(
                "Alice".to_owned(),
                UserRecord {
                    password_hash: Some(test_hash("a very long unicode password 🙂")),
                    email: None,
                    disabled: true,
                },
            )]),
            true,
            Vec::new(),
            auth.service.inner.store.clone(),
            vec![0x5a; 32],
            1,
            120,
            600,
            5,
            20,
            2,
            3,
            auth.clock.clone(),
        );
        assert!(matches!(
            disabled
                .authenticate(&headers_with_cookie(&format!(
                    "{SESSION_COOKIE}={}",
                    disabled_session.cookie_token
                )))
                .await,
            Err(AppError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn wrong_unknown_and_disabled_users_have_identical_public_errors() {
        let auth = test_auth(1, 20);
        let app = app_router(AppState::with_auth(true, auth.service));
        let mut bodies = Vec::new();
        for body in [
            r#"{"username":"Alice","password":"wrong"}"#,
            r#"{"username":"missing","password":"wrong"}"#,
            r#"{"username":"disabled","password":"wrong"}"#,
        ] {
            let response = app
                .clone()
                .oneshot(post("/api/v1/auth/login", body))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            bodies.push(to_bytes(response.into_body(), 4096).await.unwrap());
        }
        assert_eq!(bodies[0], bodies[1]);
        assert_eq!(bodies[1], bodies[2]);
    }

    #[tokio::test]
    async fn malformed_and_extreme_login_fields_use_the_generic_failure() {
        let auth = test_auth(1, 20);
        let app = app_router(AppState::with_auth(true, auth.service.clone()));
        let baseline = app
            .clone()
            .oneshot(post(
                "/api/v1/auth/login",
                r#"{"username":"Alice","password":"wrong"}"#,
            ))
            .await
            .unwrap();
        let baseline_body = to_bytes(baseline.into_body(), 4_096).await.unwrap();
        let oversized_password = "x".repeat(MAX_PASSWORD_BYTES + 1);
        let cases = [
            serde_json::json!({"username": "a".repeat(MAX_USERNAME_BYTES + 1), "password": "wrong"}).to_string(),
            serde_json::json!({"username": "🙂", "password": "wrong"}).to_string(),
            serde_json::json!({"username": "Alice", "password": oversized_password}).to_string(),
            r#"{"username":"Alice"}"#.to_owned(),
            r#"{"username":"Alice","password":42}"#.to_owned(),
            r#"{"username":"Alice""#.to_owned(),
        ];
        for body in cases {
            let response = app
                .clone()
                .oneshot(post("/api/v1/auth/login", body))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                to_bytes(response.into_body(), 4_096).await.unwrap(),
                baseline_body
            );
        }

        let permit = auth.service.inner.verifier_slots.acquire().await.unwrap();
        let service = auth.service.clone();
        let oversized = tokio::spawn(async move {
            service
                .login("Alice", &"x".repeat(MAX_PASSWORD_BYTES + 1), None, None)
                .await
        });
        for _ in 0..100 {
            if oversized.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(oversized.is_finished());
        assert!(matches!(
            oversized.await.unwrap(),
            Err(AppError::AuthenticationFailed)
        ));
        drop(permit);
    }

    #[tokio::test]
    async fn origin_fetch_metadata_and_csrf_are_all_enforced() {
        let auth = test_auth(1, 5);
        let login = login_response(&auth.service).await;
        let cookie = cookie_pair(&login);
        let body = to_bytes(login.into_body(), 16_384).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let csrf = json["csrfToken"].as_str().unwrap();

        for request in [
            Request::post("/api/v1/auth/logout")
                .header(header::HOST, "files.example.test")
                .header(header::ORIGIN, "https://evil.example.test")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", csrf)
                .body(Body::empty())
                .unwrap(),
            Request::post("/api/v1/auth/logout")
                .header(header::HOST, "files.example.test")
                .header(header::ORIGIN, "https://files.example.test")
                .header("sec-fetch-site", "cross-site")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", csrf)
                .body(Body::empty())
                .unwrap(),
            Request::post("/api/v1/auth/logout")
                .header(header::HOST, "files.example.test")
                .header(header::ORIGIN, "https://files.example.test")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", "00")
                .body(Body::empty())
                .unwrap(),
        ] {
            let response = app_router(AppState::with_auth(true, auth.service.clone()))
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn rate_limit_normalizes_identifier_and_bounds_state() {
        let auth = test_auth(1, 1);
        let first = auth.service.login(" missing ", "wrong", None, None).await;
        assert!(matches!(first, Err(AppError::AuthenticationFailed)));
        let second = auth.service.login("MISSING", "wrong", None, None).await;
        assert!(matches!(second, Err(AppError::TooManyRequests)));

        let mut limiter = RateLimiter {
            entries: HashMap::new(),
            attempts_per_window: 1,
        };
        for index in 0..(MAX_RATE_LIMIT_KEYS + 100) {
            limiter.allow(
                RateLimitKey {
                    account: normalized_identifier_digest(&format!("user-{index}")),
                    source: None,
                },
                100,
            );
        }
        assert_eq!(limiter.entries.len(), MAX_RATE_LIMIT_KEYS);
    }

    #[test]
    fn rate_limit_identity_has_fixed_memory_for_long_unicode_input() {
        let long = format!("  {}  ", "🙂".repeat(250_000));
        let key = RateLimitKey {
            account: normalized_identifier_digest(&long),
            source: None,
        };
        assert_eq!(std::mem::size_of_val(&key.account), 32);
        assert_eq!(
            normalized_identifier_digest("  MISSING  "),
            normalized_identifier_digest("missing")
        );
        drop(long);
        let mut limiter = RateLimiter {
            entries: HashMap::new(),
            attempts_per_window: 1,
        };
        assert!(limiter.allow(key, 100));
        assert_eq!(limiter.entries.len(), 1);
    }

    #[tokio::test]
    async fn verifier_semaphore_blocks_excess_concurrency() {
        let auth = test_auth(1, 10);
        let permit = auth.service.inner.verifier_slots.acquire().await.unwrap();
        let service = auth.service.clone();
        let pending = tokio::spawn(async move {
            service
                .login("Alice", "a very long unicode password 🙂", None, None)
                .await
        });
        tokio::task::yield_now().await;
        assert!(!pending.is_finished());
        drop(permit);
        assert!(pending.await.unwrap().is_ok());
    }

    #[test]
    fn exhausted_limiter_windows_survive_key_flooding() {
        let key = |name: &str| RateLimitKey {
            account: normalized_identifier_digest(name),
            source: None,
        };
        let mut limiter = RateLimiter {
            entries: HashMap::new(),
            attempts_per_window: 2,
        };
        assert!(limiter.allow(key("victim"), 100));
        assert!(limiter.allow(key("victim"), 100));
        assert!(!limiter.allow(key("victim"), 100));
        for index in 0..(MAX_RATE_LIMIT_KEYS + 100) {
            limiter.allow(key(&format!("flood-{index}")), 101);
        }
        assert_eq!(limiter.entries.len(), MAX_RATE_LIMIT_KEYS);
        assert!(!limiter.allow(key("victim"), 102));

        let mut full = RateLimiter {
            entries: HashMap::new(),
            attempts_per_window: 1,
        };
        for index in 0..MAX_RATE_LIMIT_KEYS {
            assert!(full.allow(key(&format!("blocked-{index}")), 100));
        }
        assert!(!full.allow(key("newcomer"), 100));
    }

    #[test]
    fn limiter_sources_group_ipv6_prefixes() {
        let first: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let second: IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(rate_limit_source(first), rate_limit_source(second));
        assert_ne!(rate_limit_source(first), rate_limit_source(other));
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(
            rate_limit_source(mapped),
            "192.0.2.7".parse::<IpAddr>().unwrap()
        );
        let v4: IpAddr = "192.0.2.8".parse().unwrap();
        assert_eq!(rate_limit_source(v4), v4);
    }

    const ALICE_PASSWORD: &str = "a very long unicode password 🙂";

    fn trust_test_proxy(auth: &mut TestAuth) {
        let inner = Arc::get_mut(&mut auth.service.inner).expect("unshared test service");
        inner.trusted_proxies = TrustedProxies::new(
            vec![crate::client_address::IpNetwork::parse("192.0.2.0/28").unwrap()],
            crate::config::ForwardedHeader::XForwardedFor,
        );
    }

    /// A login relayed by the reverse proxy at 192.0.2.10, which appends the
    /// client's address to whatever `X-Forwarded-For` the client sent.
    fn proxied_login(username: &str, password: &str, client: &str) -> Request<Body> {
        let payload = serde_json::json!({"username": username, "password": password});
        let mut request = post("/api/v1/auth/login", payload.to_string());
        request.headers_mut().insert(
            "x-forwarded-for",
            HeaderValue::from_str(&format!("203.0.113.250, {client}")).unwrap(),
        );
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 10], 4711))));
        request
    }

    async fn error_code(response: Response) -> String {
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        value["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    #[tokio::test]
    async fn username_flood_from_one_source_is_refused_before_the_verifier() {
        let mut auth = test_auth_with_source_limit(1, 5, 3);
        trust_test_proxy(&mut auth);
        let app = app_router(AppState::with_auth(true, auth.service.clone()));
        for index in 0..3 {
            let response = app
                .clone()
                .oneshot(proxied_login(
                    &format!("random-{index}"),
                    "wrong",
                    "198.51.100.7",
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        // With the only verifier slot held, a request that waited for it
        // would stall for VERIFIER_WAIT and then fail as busy. The flood is
        // refused at once instead, so it never queues for the verifier.
        let held = Arc::clone(&auth.service.inner.verifier_slots)
            .acquire_owned()
            .await
            .unwrap();
        for index in 3..60 {
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                app.clone().oneshot(proxied_login(
                    &format!("random-{index}"),
                    "wrong",
                    "198.51.100.7",
                )),
            )
            .await
            .expect("refused without waiting for the verifier")
            .unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(error_code(response).await, "rate_limited");
        }
        // Refused attempts create no per-account limiter keys.
        assert_eq!(
            auth.service.inner.rate_limit.lock().unwrap().entries.len(),
            3
        );
        assert_eq!(
            auth.service
                .inner
                .source_rate_limit
                .lock()
                .unwrap()
                .entries
                .len(),
            1
        );
        drop(held);

        let response = app
            .clone()
            .oneshot(proxied_login("Alice", ALICE_PASSWORD, "203.0.113.9"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn account_lockout_does_not_spread_to_other_clients_behind_a_trusted_proxy() {
        let mut auth = test_auth_with_source_limit(1, 2, 1_000);
        trust_test_proxy(&mut auth);
        let app = app_router(AppState::with_auth(true, auth.service.clone()));
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(proxied_login("Alice", "wrong", "198.51.100.7"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let locked = app
            .clone()
            .oneshot(proxied_login("Alice", ALICE_PASSWORD, "198.51.100.7"))
            .await
            .unwrap();
        assert_eq!(locked.status(), StatusCode::TOO_MANY_REQUESTS);
        // The attacker cannot leave its bucket by prepending another address.
        let mut spoofed = proxied_login("Alice", ALICE_PASSWORD, "198.51.100.7");
        spoofed.headers_mut().insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.9, 198.51.100.7"),
        );
        assert_eq!(
            app.clone().oneshot(spoofed).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );

        let response = app
            .clone()
            .oneshot(proxied_login("Alice", ALICE_PASSWORD, "203.0.113.9"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Without the trusted-proxy setting the header is ignored, so every
        // client shares the proxy's address and the lockout spreads.
        let untrusted = test_auth_with_source_limit(1, 2, 1_000);
        let app = app_router(AppState::with_auth(true, untrusted.service.clone()));
        for _ in 0..2 {
            app.clone()
                .oneshot(proxied_login("Alice", "wrong", "198.51.100.7"))
                .await
                .unwrap();
        }
        let response = app
            .clone()
            .oneshot(proxied_login("Alice", ALICE_PASSWORD, "203.0.113.9"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    /// A passkey sign-in start relayed by the trusted proxy at 192.0.2.10.
    fn proxied_passkey_start(client: &str) -> Request<Body> {
        let mut request = post("/api/v1/auth/passkeys/login/start", "{}");
        request.headers_mut().insert(
            "x-forwarded-for",
            HeaderValue::from_str(&format!("203.0.113.250, {client}")).unwrap(),
        );
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 10], 4711))));
        request
    }

    async fn flow_id(response: Response) -> String {
        let body = to_bytes(response.into_body(), 65_536).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        value["flowId"].as_str().expect("flow ID").to_owned()
    }

    #[tokio::test]
    async fn passkey_sign_in_starts_share_the_per_source_budget() {
        let mut auth = test_auth_with_source_limit(1, 5, 3);
        trust_test_proxy(&mut auth);
        Arc::get_mut(&mut auth.service.inner)
            .expect("unshared test service")
            .passkeys = Some(
            passkeys::PasskeyState::new(&url::Url::parse("https://files.example.test").unwrap())
                .unwrap(),
        );
        let app = app_router(AppState::with_auth(true, auth.service.clone()));

        // A genuine user behind the proxy starts a ceremony.
        let genuine = app
            .clone()
            .oneshot(proxied_passkey_start("203.0.113.9"))
            .await
            .unwrap();
        assert_eq!(genuine.status(), StatusCode::OK);
        let genuine = flow_id(genuine).await;

        // Another client spends its budget, then is refused without storing
        // further ceremonies.
        for _ in 0..3 {
            let response = app
                .clone()
                .oneshot(proxied_passkey_start("198.51.100.7"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        for _ in 0..50 {
            let response = app
                .clone()
                .oneshot(proxied_passkey_start("198.51.100.7"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(error_code(response).await, "rate_limited");
        }
        let passkeys = auth.service.inner.passkeys.as_ref().expect("passkeys");
        let pending = passkeys.pending_logins();
        assert_eq!(pending.len(), 4);
        assert!(pending.contains(&genuine));

        // The budget is shared with password sign-in from the same source.
        let response = app
            .clone()
            .oneshot(proxied_login("Alice", ALICE_PASSWORD, "198.51.100.7"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        // A different client behind the same trusted proxy is unaffected.
        let other = app
            .clone()
            .oneshot(proxied_passkey_start("203.0.113.20"))
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::OK);
    }

    #[test]
    fn dummy_hash_matches_the_strongest_configured_cost() {
        assert_eq!(dummy_password_hash(std::iter::empty()), DUMMY_PASSWORD_HASH);
        assert_eq!(
            dummy_password_hash([DUMMY_PASSWORD_HASH].into_iter()),
            DUMMY_PASSWORD_HASH
        );
        let cheap = test_hash("cheap");
        let stronger = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(16, 2, 1, None).unwrap(),
        )
        .hash_password(b"stronger")
        .unwrap()
        .to_string();
        let dummy = dummy_password_hash([cheap.as_str(), stronger.as_str()].into_iter());
        let parsed = PasswordHash::new(&dummy).unwrap();
        assert_eq!(parsed.params.get_decimal("m"), Some(16));
        assert_eq!(parsed.params.get_decimal("t"), Some(2));
        assert!(!verify_password(&dummy, b"stronger"));
    }

    #[tokio::test]
    async fn startup_prunes_state_of_removed_users() {
        let auth = test_auth(1, 20);
        auth.service
            .login("Alice", "a very long unicode password 🙂", None, None)
            .await
            .unwrap();
        let store = &auth.service.inner.store;
        store
            .with_connection(|connection| {
                connection.execute_batch(
                    "INSERT INTO sessions (session_key, username, created_at, last_seen_at, expires_at)
                       VALUES (zeroblob(32), 'Ghost', 1, 1, 9999999999);
                     INSERT INTO user_preferences (username, default_share_id, default_path)
                       VALUES ('Ghost', 'documents', ''), ('Alice', 'documents', '');
                     INSERT INTO passkey_users (username, user_handle)
                       VALUES ('Ghost', zeroblob(16));
                     INSERT INTO passkeys (id, username, credential_id, name, credential_json, created_at)
                       VALUES ('ghost-key', 'Ghost', x'02', 'Old', '{}', 1);",
                )
            })
            .await
            .unwrap();
        store
            .prune_unknown_users(["Alice", "Bob"].into_iter())
            .unwrap();
        for table in ["sessions", "user_preferences", "passkey_users", "passkeys"] {
            let ghosts: i64 = store
                .connection
                .lock()
                .unwrap()
                .query_row(
                    &format!("SELECT count(*) FROM {table} WHERE username = 'Ghost'"),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(ghosts, 0, "{table}");
        }
        assert_eq!(session_count(&auth.service, Some("Alice")), 1);
        assert!(store.default_folder("Alice").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn passkey_registration_requires_a_recent_sign_in() {
        let mut auth = test_auth(1, 20);
        {
            let inner = Arc::get_mut(&mut auth.service.inner).unwrap();
            inner.idle_timeout_seconds = 3_600;
            inner.absolute_timeout_seconds = 7_200;
            inner.passkeys = Some(
                passkeys::PasskeyState::new(
                    &url::Url::parse("https://files.example.test").unwrap(),
                )
                .unwrap(),
            );
        }
        let app = app_router(AppState::with_auth(true, auth.service.clone()));
        let (cookie, csrf) = login_as(&app, "Alice", "a very long unicode password 🙂").await;
        let start = || {
            Request::post("/api/v1/auth/passkeys/register/start")
                .header(header::HOST, "files.example.test")
                .header(header::ORIGIN, "https://files.example.test")
                .header("sec-fetch-site", "same-origin")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"name":"Laptop"}"#))
                .unwrap()
        };
        let fresh = app.clone().oneshot(start()).await.unwrap();
        assert_eq!(fresh.status(), StatusCode::OK);
        auth.clock.set(1_000_000 + 601);
        let stale = app.clone().oneshot(start()).await.unwrap();
        assert_eq!(stale.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(stale.into_body(), 4_096).await.unwrap();
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("reauthentication_required")
        );
    }

    #[test]
    fn cookie_parser_skips_foreign_malformed_pairs() {
        let token = "0".repeat(64);
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_bytes(b"theme=\xff\xfe; flag").unwrap(),
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_str(&format!("other=1; {SESSION_COOKIE}={token}")).unwrap(),
        );
        assert_eq!(session_cookie(&headers), Some(token.as_str()));
        let mut unprefixed = HeaderMap::new();
        unprefixed.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("crabinet_session={token}")).unwrap(),
        );
        assert_eq!(session_cookie(&unprefixed), None);
    }

    #[test]
    fn cookie_parser_and_token_decoder_reject_ambiguity() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!(
                "{SESSION_COOKIE}={}; {SESSION_COOKIE}={}",
                "0".repeat(64),
                "1".repeat(64)
            ))
            .unwrap(),
        );
        assert_eq!(session_cookie(&headers), None);
        assert!(decode_token(&"f".repeat(64)).is_some());
        assert!(decode_token(&"F".repeat(64)).is_none());
        assert!(decode_token(&"0".repeat(63)).is_none());
    }

    #[test]
    fn long_unicode_passwords_are_not_truncated() {
        let password = "correct-🙂".repeat(300);
        assert!(password.len() <= MAX_PASSWORD_BYTES);
        let mut different_suffix = password.clone();
        different_suffix.push('x');
        let hash = test_hash(&password);
        assert!(verify_password(&hash, password.as_bytes()));
        assert!(!verify_password(&hash, different_suffix.as_bytes()));
    }

    #[test]
    fn same_origin_accepts_referer_fallback() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("files.example.test"));
        headers.insert(
            header::REFERER,
            HeaderValue::from_static("https://files.example.test/browse/docs"),
        );
        assert!(validate_same_origin(&headers).is_ok());
    }

    /// Reproducible release-profile smoke benchmark for deployment sizing.
    #[test]
    #[ignore = "run explicitly in the release container when sizing authentication"]
    fn benchmark_default_argon2_verification_profile() {
        let iterations = 3_u32;
        let started = std::time::Instant::now();
        for _ in 0..iterations {
            assert!(!verify_password(DUMMY_PASSWORD_HASH, b"benchmark-password"));
        }
        let elapsed = started.elapsed();
        eprintln!(
            "argon2id m=65536,t=3,p=1: {iterations} verifications in {elapsed:?}, mean {:?}",
            elapsed / iterations
        );
    }

    fn headers_with_cookie(cookie: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
        headers
    }

    fn session_count(service: &AuthService, username: Option<&str>) -> i64 {
        let connection = service.inner.store.connection.lock().unwrap();
        match username {
            Some(username) => connection
                .query_row(
                    "SELECT count(*) FROM sessions WHERE username = ?1",
                    params![username],
                    |row| row.get(0),
                )
                .unwrap(),
            None => connection
                .query_row("SELECT count(*) FROM sessions", [], |row| row.get(0))
                .unwrap(),
        }
    }
}
