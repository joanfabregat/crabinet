//! Local password authentication, opaque server-side sessions, and request protection.

use std::{
    collections::HashMap,
    fs::OpenOptions,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use argon2::{Argon2, PasswordHash, password_hash::PasswordVerifier};
use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, FromRequestParts, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use getrandom::fill as random_fill;
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::{
    app::AppState,
    browse::AuthenticatedIdentity,
    config::{Config, Permission},
    error::AppError,
    filesystem::{AccessLevel, ShareGrant, ShareId},
};

type HmacSha256 = Hmac<Sha256>;

const SESSION_COOKIE: &str = "index_session";
const TOKEN_BYTES: usize = 32;
const SESSION_SCHEMA_VERSION: i64 = 1;
const RATE_LIMIT_WINDOW_SECONDS: i64 = 60;
const MAX_RATE_LIMIT_KEYS: usize = 4_096;
const MAX_USERNAME_BYTES: usize = 64;
const MAX_PASSWORD_BYTES: usize = 4_096;
const DUMMY_PASSWORD_HASH: &str =
    "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

#[derive(Debug, thiserror::Error)]
pub enum AuthInitError {
    #[error("cannot create the session database")]
    CreateDatabase(#[from] std::io::Error),
    #[error("cannot initialize the session database")]
    Database(#[from] rusqlite::Error),
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
    shares: Vec<ShareRecord>,
    store: SessionStore,
    token_key: Vec<u8>,
    verifier_slots: Semaphore,
    idle_timeout_seconds: i64,
    absolute_timeout_seconds: i64,
    max_sessions_per_user: usize,
    max_sessions_total: usize,
    rate_limit: Mutex<RateLimiter>,
    clock: Arc<dyn Clock>,
}

#[derive(Clone)]
struct UserRecord {
    password_hash: String,
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
    created_at: i64,
    last_seen_at: i64,
    expires_at: i64,
}

struct SessionRotation {
    old_key: Option<Vec<u8>>,
    new_key: Vec<u8>,
    username: String,
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

struct RateLimiter {
    entries: HashMap<RateLimitKey, AttemptWindow>,
    attempts_per_window: u32,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponse {
    user: SessionUser,
    shares: Vec<EffectiveShare>,
    csrf_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionUser {
    id: String,
    username: String,
    display_name: String,
}

struct NewSession {
    cookie_token: String,
    csrf_token: String,
    username: String,
}

impl AuthService {
    pub fn from_config(config: &Config) -> Result<Self, AuthInitError> {
        let users = config
            .users()
            .iter()
            .map(|user| {
                (
                    user.username().to_owned(),
                    UserRecord {
                        password_hash: user.password_hash().to_owned(),
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
        Ok(Self::new(
            users,
            shares,
            SessionStore::open(server.database_path())?,
            config.session_secret().to_vec(),
            server.auth_max_concurrent(),
            server.session_idle_timeout_seconds() as i64,
            server.session_absolute_timeout_seconds() as i64,
            server.login_attempts_per_minute(),
            server.max_sessions_per_user(),
            server.max_sessions_total(),
            Arc::new(SystemClock),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        users: HashMap<String, UserRecord>,
        shares: Vec<ShareRecord>,
        store: SessionStore,
        token_key: Vec<u8>,
        verifier_slots: usize,
        idle_timeout_seconds: i64,
        absolute_timeout_seconds: i64,
        login_attempts_per_minute: u32,
        max_sessions_per_user: usize,
        max_sessions_total: usize,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            inner: Arc::new(AuthInner {
                users,
                shares,
                store,
                token_key,
                verifier_slots: Semaphore::new(verifier_slots),
                idle_timeout_seconds,
                absolute_timeout_seconds,
                max_sessions_per_user,
                max_sessions_total,
                rate_limit: Mutex::new(RateLimiter {
                    entries: HashMap::new(),
                    attempts_per_window: login_attempts_per_minute,
                }),
                clock,
            }),
        }
    }

    async fn login(
        &self,
        username: &str,
        password: &str,
        source: Option<IpAddr>,
        old_cookie: Option<&str>,
    ) -> Result<NewSession, AppError> {
        let now = self.inner.clock.now();
        let rate_key = RateLimitKey {
            account: normalized_identifier_digest(username),
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

        if password.len() > MAX_PASSWORD_BYTES {
            return Err(AppError::AuthenticationFailed);
        }
        let candidate = if is_plausible_username(username) {
            self.inner.users.get(username)
        } else {
            None
        };
        let usable = candidate.is_some_and(|user| !user.disabled);
        let hash = if usable {
            candidate.expect("checked above").password_hash.clone()
        } else {
            DUMMY_PASSWORD_HASH.to_owned()
        };
        let password = password.as_bytes().to_vec();
        let permit = self
            .inner
            .verifier_slots
            .acquire()
            .await
            .map_err(|_| AppError::Internal)?;
        let valid = tokio::task::spawn_blocking(move || verify_password(&hash, &password))
            .await
            .map_err(|_| AppError::Internal)?;
        drop(permit);
        if !usable || !valid {
            return Err(AppError::AuthenticationFailed);
        }

        let mut session_token = [0_u8; TOKEN_BYTES];
        random_fill(&mut session_token).map_err(|_| AuthError::Random)?;
        let cookie_token = encode_hex(&session_token);
        let csrf_token_text = encode_hex(&self.digest(b"csrf-token\0", &session_token));
        let session_key = self.digest(b"session\0", &session_token);
        let old_key = old_cookie.and_then(|token| self.session_key(token));
        let expires_at = now.saturating_add(self.inner.absolute_timeout_seconds);
        self.inner
            .store
            .rotate(SessionRotation {
                old_key,
                new_key: session_key,
                username: username.to_owned(),
                now,
                expires_at,
                idle_cutoff: now.saturating_sub(self.inner.idle_timeout_seconds),
                max_sessions_per_user: self.inner.max_sessions_per_user,
                max_sessions_total: self.inner.max_sessions_total,
            })
            .await?;
        self.inner
            .rate_limit
            .lock()
            .map_err(|_| AppError::Internal)?
            .clear(&rate_key);

        Ok(NewSession {
            cookie_token,
            csrf_token: csrf_token_text,
            username: username.to_owned(),
        })
    }

    async fn authenticate(&self, headers: &HeaderMap) -> Result<AuthenticatedSession, AppError> {
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
        self.inner.store.touch(key, now).await?;
        Ok(AuthenticatedSession {
            principal: AuthenticatedPrincipal {
                username: Arc::from(session.username),
            },
            session_token: raw_token,
        })
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

    fn session_key(&self, encoded: &str) -> Option<Vec<u8>> {
        decode_token(encoded).map(|token| self.digest(b"session\0", &token))
    }

    fn session_response(&self, username: &str, csrf_token: String) -> SessionResponse {
        SessionResponse {
            user: SessionUser {
                id: username.to_owned(),
                username: username.to_owned(),
                display_name: username.to_owned(),
            },
            shares: self.effective_shares(username),
            csrf_token,
        }
    }
}

fn create_database_if_missing(path: &std::path::Path) -> Result<(), std::io::Error> {
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
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
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
                 (session_key, username, created_at, last_seen_at, expires_at)
                 VALUES (?1, ?2, ?3, ?3, ?4)",
                params![new_key, username, now, expires_at],
            )?;
            transaction.commit()
        })
        .await
    }

    async fn lookup(&self, key: Vec<u8>) -> Result<Option<StoredSession>, AuthError> {
        self.with_connection(move |connection| {
            connection
                .query_row(
                    "SELECT username, created_at, last_seen_at, expires_at
                     FROM sessions WHERE session_key = ?1",
                    params![key],
                    |row| {
                        Ok(StoredSession {
                            username: row.get(0)?,
                            created_at: row.get(1)?,
                            last_seen_at: row.get(2)?,
                            expires_at: row.get(3)?,
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

impl RateLimiter {
    fn allow(&mut self, key: RateLimitKey, now: i64) -> bool {
        self.entries.retain(|_, window| {
            now.saturating_sub(window.last_seen_at) < RATE_LIMIT_WINDOW_SECONDS
        });
        if self.entries.len() >= MAX_RATE_LIMIT_KEYS
            && !self.entries.contains_key(&key)
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, window)| window.last_seen_at)
                .map(|(key, _)| key.clone())
        {
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

    fn clear(&mut self, key: &RateLimitKey) {
        self.entries.remove(key);
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/session", get(current_session))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
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
            session.principal.username(),
            encode_hex(&auth.digest(b"csrf-token\0", &session.session_token)),
        ),
        None,
    ))
}

async fn login(
    State(state): State<AppState>,
    PeerAddress(source): PeerAddress,
    headers: HeaderMap,
    payload: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    validate_same_origin(&headers)?;
    let Json(payload) = payload.map_err(|_| AppError::AuthenticationFailed)?;
    let auth = state.auth().ok_or(AppError::Internal)?;
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
        auth.session_response(&session.username, session.csrf_token),
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

fn session_cookie_header(token: &str, max_age: i64) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Strict"
    ))
    .expect("hex token and integer form a valid cookie")
}

fn clear_session_cookie() -> HeaderValue {
    HeaderValue::from_static(
        "index_session=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Strict",
    )
}

fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    let mut found = None;
    for header_value in headers.get_all(header::COOKIE) {
        let Ok(cookies) = header_value.to_str() else {
            return None;
        };
        for cookie in cookies.split(';') {
            let Some((name, value)) = cookie.trim().split_once('=') else {
                continue;
            };
            if name == SESSION_COOKIE {
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

fn is_plausible_username(username: &str) -> bool {
    (1..=MAX_USERNAME_BYTES).contains(&username.len())
        && username != "."
        && username != ".."
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_token(value: &str) -> Option<[u8; TOKEN_BYTES]> {
    if value.len() != TOKEN_BYTES * 2 {
        return None;
    }
    let mut decoded = [0_u8; TOKEN_BYTES];
    for (target, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
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
mod tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use argon2::{Algorithm, Params, Version, password_hash::PasswordHasher};
    use axum::{body::to_bytes, http::Request};
    use tempfile::TempDir;
    use tower::ServiceExt;

    use super::*;
    use crate::app::{AppState, router as app_router};

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
        let directory = tempfile::tempdir().unwrap();
        let store = SessionStore::open(&directory.path().join("sessions.sqlite3")).unwrap();
        let password_hash = test_hash("a very long unicode password 🙂");
        let disabled_hash = test_hash("disabled password");
        let bob_hash = test_hash("bob password");
        let users = HashMap::from([
            (
                "Alice".to_owned(),
                UserRecord {
                    password_hash,
                    disabled: false,
                },
            ),
            (
                "disabled".to_owned(),
                UserRecord {
                    password_hash: disabled_hash,
                    disabled: true,
                },
            ),
            (
                "Bob".to_owned(),
                UserRecord {
                    password_hash: bob_hash,
                    disabled: false,
                },
            ),
        ]);
        let shares = vec![ShareRecord {
            id: "documents".to_owned(),
            name: "Documents".to_owned(),
            grants: HashMap::from([
                ("Alice".to_owned(), Permission::Write),
                ("disabled".to_owned(), Permission::Read),
            ]),
            read_only: false,
        }];
        let clock = Arc::new(TestClock::new(1_000_000));
        let service = AuthService::new(
            users,
            shares,
            store,
            vec![0x5a; 32],
            concurrency,
            120,
            600,
            attempts,
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
            Vec::new(),
            auth.service.inner.store.clone(),
            vec![0x5a; 32],
            1,
            120,
            600,
            5,
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
                    password_hash: test_hash("a very long unicode password 🙂"),
                    disabled: true,
                },
            )]),
            Vec::new(),
            auth.service.inner.store.clone(),
            vec![0x5a; 32],
            1,
            120,
            600,
            5,
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
    fn cookie_parser_and_token_decoder_reject_ambiguity() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static(
                "index_session=0000000000000000000000000000000000000000000000000000000000000000; index_session=1111111111111111111111111111111111111111111111111111111111111111",
            ),
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
