//! WebAuthn passkeys bound to configuration-defined users.

use super::*;
use crate::extract::ApiPath;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use axum::{extract::DefaultBodyLimit, routing::patch};
use webauthn_rs::prelude::{
    AuthenticationResult, DiscoverableAuthentication, DiscoverableKey, Passkey,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, Uuid, Webauthn,
    WebauthnBuilder,
};
use webauthn_rs_proto::ResidentKeyRequirement;

const REGISTRATION_LIFETIME: Duration = Duration::from_secs(300);
const LOGIN_LIFETIME: Duration = Duration::from_secs(120);
/// Unauthenticated login ceremonies share this bound. When it is reached the
/// oldest ceremony is dropped rather than refusing new ones, so filling the map
/// cannot lock every user out of passkey sign-in.
const MAX_PENDING_LOGINS: usize = 4_096;
const MAX_PENDING_REGISTRATIONS_PER_USER: usize = 4;
/// Adding a passkey creates a long-lived credential, so it requires a session
/// that was signed in recently rather than any still-valid session.
const REGISTRATION_MAX_SESSION_AGE_SECONDS: i64 = 600;
const MAX_PASSKEYS_PER_USER: i64 = 20;
const MAX_PASSKEY_NAME_BYTES: usize = 80;

pub(super) struct PasskeyState {
    webauthn: Webauthn,
    registrations: Mutex<HashMap<String, Pending<Registration>>>,
    logins: Mutex<HashMap<String, Pending<DiscoverableAuthentication>>>,
}

struct Pending<T> {
    expires: Instant,
    state: T,
}

struct Registration {
    username: String,
    session_key: Vec<u8>,
    name: String,
    state: PasskeyRegistration,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Challenge<T: Serialize> {
    flow_id: String,
    options: T,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartRegistration {
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FinishRegistration {
    flow_id: String,
    credential: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartLogin {
    /// Accepted from older clients and ignored; see [`start_login`].
    #[serde(default, rename = "username")]
    _username: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FinishLogin {
    flow_id: String,
    credential: PublicKeyCredential,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenamePasskey {
    name: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PasskeySummary {
    id: String,
    name: String,
    created_at: i64,
    last_used_at: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyList {
    passkeys: Vec<PasskeySummary>,
}

impl PasskeyState {
    pub(super) fn new(origin: &url::Url) -> Result<Self, AuthInitError> {
        let rp_id = origin
            .host_str()
            .ok_or_else(|| AuthInitError::Passkeys("origin has no host".into()))?;
        let webauthn = WebauthnBuilder::new(rp_id, origin)
            .and_then(|builder| builder.rp_name("Crabinet").build())
            .map_err(|error| AuthInitError::Passkeys(error.to_string()))?;
        Ok(Self {
            webauthn,
            registrations: Mutex::new(HashMap::new()),
            logins: Mutex::new(HashMap::new()),
        })
    }

    fn insert_registration(&self, registration: Registration) -> Result<String, AppError> {
        let mut pending = self.registrations.lock().map_err(|_| AppError::Internal)?;
        let now = Instant::now();
        pending.retain(|_, flow| flow.expires > now);
        // Registrations are authenticated and bounded per configured user;
        // a user's own oldest ceremony gives way to a new one.
        let mine = || {
            pending
                .iter()
                .filter(|(_, flow)| flow.state.username == registration.username)
        };
        if mine().count() >= MAX_PENDING_REGISTRATIONS_PER_USER
            && let Some(oldest) = mine()
                .min_by_key(|(_, flow)| flow.expires)
                .map(|(id, _)| id.clone())
        {
            pending.remove(&oldest);
        }
        let id = flow_id()?;
        pending.insert(
            id.clone(),
            Pending {
                expires: now + REGISTRATION_LIFETIME,
                state: registration,
            },
        );
        Ok(id)
    }

    fn insert_login(&self, login: DiscoverableAuthentication) -> Result<String, AppError> {
        let mut pending = self.logins.lock().map_err(|_| AppError::Internal)?;
        let now = Instant::now();
        pending.retain(|_, flow| flow.expires > now);
        if pending.len() >= MAX_PENDING_LOGINS
            && let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, flow)| flow.expires)
                .map(|(id, _)| id.clone())
        {
            pending.remove(&oldest);
        }
        let id = flow_id()?;
        pending.insert(
            id.clone(),
            Pending {
                expires: now + LOGIN_LIFETIME,
                state: login,
            },
        );
        Ok(id)
    }

    fn take_registration(&self, id: &str) -> Result<Registration, AppError> {
        take(&self.registrations, id)
    }

    fn take_login(&self, id: &str) -> Result<DiscoverableAuthentication, AppError> {
        take(&self.logins, id)
    }

    #[cfg(test)]
    pub(super) fn pending_logins(&self) -> Vec<String> {
        self.logins.lock().unwrap().keys().cloned().collect()
    }
}

fn flow_id() -> Result<String, AppError> {
    let mut random = [0_u8; TOKEN_BYTES];
    random_fill(&mut random).map_err(|_| AppError::Internal)?;
    Ok(encode_hex(&random))
}

fn take<T>(flows: &Mutex<HashMap<String, Pending<T>>>, id: &str) -> Result<T, AppError> {
    if id.len() != TOKEN_BYTES * 2 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::AuthenticationFailed);
    }
    let pending = flows
        .lock()
        .map_err(|_| AppError::Internal)?
        .remove(id)
        .ok_or(AppError::AuthenticationFailed)?;
    if pending.expires <= Instant::now() {
        return Err(AppError::AuthenticationFailed);
    }
    Ok(pending.state)
}

fn enabled(auth: &AuthService) -> Result<&PasskeyState, AppError> {
    auth.inner.passkeys.as_ref().ok_or(AppError::NotFound)
}

fn validated_name(value: &str) -> Result<String, AppError> {
    let name = value.trim();
    if name.is_empty() || name.len() > MAX_PASSKEY_NAME_BYTES || name.chars().any(char::is_control)
    {
        return Err(AppError::InvalidRequest);
    }
    Ok(name.to_owned())
}

async fn authorized_session(
    auth: &AuthService,
    headers: &HeaderMap,
) -> Result<AuthenticatedSession, AppError> {
    validate_same_origin(headers)?;
    let session = auth.authenticate(headers).await?;
    if !auth.verify_csrf(&session, headers) {
        return Err(AppError::Forbidden);
    }
    Ok(session)
}

fn no_store_json<T: Serialize>(value: T) -> Response {
    let mut response = Json(value).into_response();
    no_store(response.headers_mut());
    response
}

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/passkeys", get(list_passkeys))
        .route("/auth/passkeys/register/start", post(start_registration))
        .route("/auth/passkeys/register/finish", post(finish_registration))
        .route("/auth/passkeys/login/start", post(start_login))
        .route("/auth/passkeys/login/finish", post(finish_login))
        .route(
            "/auth/passkeys/{id}",
            patch(rename_passkey).delete(remove_passkey),
        )
        .layer(DefaultBodyLimit::max(128 * 1024))
}

async fn list_passkeys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let auth = state.auth().ok_or(AppError::Internal)?;
    enabled(auth)?;
    let session = auth.authenticate(&headers).await?;
    Ok(no_store_json(PasskeyList {
        passkeys: auth
            .inner
            .store
            .passkey_list(session.principal.username())
            .await?,
    }))
}

async fn start_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<StartRegistration>, JsonRejection>,
) -> Result<Response, AppError> {
    let auth = state.auth().ok_or(AppError::Internal)?;
    let passkeys = enabled(auth)?;
    let session = authorized_session(auth, &headers).await?;
    if auth.inner.clock.now().saturating_sub(session.created_at)
        > REGISTRATION_MAX_SESSION_AGE_SECONDS
    {
        return Err(AppError::ReauthenticationRequired);
    }
    let Json(payload) = payload.map_err(|_| AppError::InvalidRequest)?;
    let name = validated_name(&payload.name)?;
    let username = session.principal.username().to_owned();
    let existing = auth.inner.store.passkeys_for(&username).await?;
    if existing.len() as i64 >= MAX_PASSKEYS_PER_USER {
        return Err(AppError::TooLarge);
    }
    let user_handle = auth.inner.store.passkey_user_handle(&username).await?;
    let exclude = existing.iter().map(|key| key.cred_id().clone()).collect();
    let (mut options, registration) = passkeys
        .webauthn
        .start_passkey_registration(
            Uuid::from_bytes(user_handle),
            &username,
            &username,
            Some(exclude),
        )
        .map_err(|_| AppError::Internal)?;
    if let Some(selection) = options.public_key.authenticator_selection.as_mut() {
        selection.resident_key = Some(ResidentKeyRequirement::Required);
        selection.require_resident_key = true;
    } else {
        return Err(AppError::Internal);
    }
    let session_key = auth.digest(b"session\0", &session.session_token);
    let flow_id = passkeys.insert_registration(Registration {
        username,
        session_key,
        name,
        state: registration,
    })?;
    Ok(no_store_json(Challenge { flow_id, options }))
}

async fn finish_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<FinishRegistration>, JsonRejection>,
) -> Result<Response, AppError> {
    let auth = state.auth().ok_or(AppError::Internal)?;
    let passkeys = enabled(auth)?;
    let session = authorized_session(auth, &headers).await?;
    let Json(payload) = payload.map_err(|_| AppError::InvalidRequest)?;
    let Registration {
        username,
        session_key,
        name,
        state: registration,
    } = passkeys.take_registration(&payload.flow_id)?;
    if username != session.principal.username()
        || session_key != auth.digest(b"session\0", &session.session_token)
    {
        return Err(AppError::AuthenticationFailed);
    }
    let credential = passkeys
        .webauthn
        .finish_passkey_registration(&payload.credential, &registration)
        .map_err(|_| AppError::AuthenticationFailed)?;
    let summary = auth
        .inner
        .store
        .add_passkey(&username, name, credential, auth.inner.clock.now())
        .await?;
    tracing::info!(
        audit = true,
        subject = %username,
        operation = "passkey_register",
        passkey = %summary.id,
        outcome = "success"
    );
    Ok(no_store_json(summary))
}

/// Starts a discoverable ceremony. A supplied username is accepted for client
/// compatibility but deliberately ignored: every enrolled passkey is
/// discoverable, and answering per account would reveal which accounts exist
/// and expose their credential IDs.
async fn start_login(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    payload: Result<Json<StartLogin>, JsonRejection>,
) -> Result<Response, AppError> {
    validate_same_origin(&headers)?;
    let auth = state.auth().ok_or(AppError::Internal)?;
    let passkeys = enabled(auth)?;
    let Json(_payload) = payload.map_err(|_| AppError::AuthenticationFailed)?;
    // Counted against the same per-source budget as password sign-in before
    // a ceremony is stored, so one source cannot flood the bounded pending
    // map and evict other users' in-progress ceremonies.
    auth.allow_sign_in_source(auth.sign_in_source(peer, &headers))
        .map_err(|error| {
            let rejection = LoginRejection::from_source_limit(error);
            audit::sign_in_rejected(
                "passkey_login",
                rejection.reason,
                None,
                None,
                auth.client_address(peer, &headers),
            );
            rejection.error
        })?;
    let (options, authentication) = passkeys
        .webauthn
        .start_discoverable_authentication()
        .map_err(|_| AppError::Internal)?;
    let flow_id = passkeys.insert_login(authentication)?;
    Ok(no_store_json(Challenge { flow_id, options }))
}

async fn finish_login(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    payload: Result<Json<FinishLogin>, JsonRejection>,
) -> Result<Response, AppError> {
    let auth = state.auth().ok_or(AppError::Internal)?;
    let client = auth.client_address(peer, &headers);
    let session = match verify_login(auth, &headers, payload).await {
        Ok(session) => {
            audit::sign_in_succeeded("passkey_login", &session.username, client);
            session
        }
        Err(rejection) => {
            audit::sign_in_rejected(
                "passkey_login",
                rejection.reason,
                rejection.subject.as_deref(),
                None,
                client,
            );
            return Err(rejection.error);
        }
    };
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

/// Completes a discoverable ceremony and issues a session, or names the
/// stable audit reason it was refused for.
async fn verify_login(
    auth: &AuthService,
    headers: &HeaderMap,
    payload: Result<Json<FinishLogin>, JsonRejection>,
) -> Result<NewSession, LoginRejection> {
    let failed = |reason| LoginRejection::new(AppError::AuthenticationFailed, reason);
    validate_same_origin(headers).map_err(|error| LoginRejection::new(error, "cross_origin"))?;
    let passkeys =
        enabled(auth).map_err(|error| LoginRejection::new(error, "method_unavailable"))?;
    let Json(payload) = payload.map_err(|_| failed("malformed_request"))?;
    let authentication = passkeys
        .take_login(&payload.flow_id)
        .map_err(|error| LoginRejection::new(error, "invalid_challenge"))?;
    let (handle, credential_id) = passkeys
        .webauthn
        .identify_discoverable_authentication(&payload.credential)
        .map_err(|_| failed("invalid_credential"))?;
    let (username, credential) = auth
        .inner
        .store
        .passkey_for_discoverable_login(handle.as_bytes(), credential_id)
        .await?
        .ok_or_else(|| failed("unknown_credential"))?;
    let refuse = |reason| {
        let mut rejection = failed(reason);
        rejection.subject = Some(username.clone());
        rejection
    };
    if auth
        .inner
        .users
        .get(&username)
        .is_none_or(|user| user.disabled)
    {
        return Err(refuse("disabled"));
    }
    let result = passkeys
        .webauthn
        .finish_discoverable_authentication(
            &payload.credential,
            authentication,
            &[DiscoverableKey::from(&credential)],
        )
        .map_err(|_| refuse("invalid_credential"))?;
    if !auth
        .inner
        .store
        .update_passkey_after_login(&username, result, auth.inner.clock.now())
        .await?
    {
        return Err(refuse("unknown_credential"));
    }
    Ok(auth
        .issue_session(
            &username,
            None,
            session_cookie(headers).and_then(|cookie| auth.session_key(cookie)),
        )
        .await?)
}

async fn rename_passkey(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<String>,
    headers: HeaderMap,
    payload: Result<Json<RenamePasskey>, JsonRejection>,
) -> Result<Response, AppError> {
    let auth = state.auth().ok_or(AppError::Internal)?;
    enabled(auth)?;
    let session = authorized_session(auth, &headers).await?;
    let Json(payload) = payload.map_err(|_| AppError::InvalidRequest)?;
    let name = validated_name(&payload.name)?;
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::NotFound);
    }
    let summary = auth
        .inner
        .store
        .rename_passkey(session.principal.username(), &id, name)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(no_store_json(summary))
}

async fn remove_passkey(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let auth = state.auth().ok_or(AppError::Internal)?;
    enabled(auth)?;
    let session = authorized_session(auth, &headers).await?;
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::NotFound);
    }
    if !auth
        .inner
        .store
        .remove_passkey(session.principal.username(), &id)
        .await?
    {
        return Err(AppError::NotFound);
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    no_store(response.headers_mut());
    Ok(response)
}

impl SessionStore {
    async fn passkey_user_handle(&self, username: &str) -> Result<[u8; 16], AuthError> {
        let username = username.to_owned();
        let mut candidate = [0_u8; 16];
        random_fill(&mut candidate).map_err(|_| AuthError::Random)?;
        let value = self
            .with_connection(move |connection| {
                connection.execute(
                    "INSERT OR IGNORE INTO passkey_users(username, user_handle) VALUES (?1, ?2)",
                    params![username, candidate.as_slice()],
                )?;
                connection.query_row(
                    "SELECT user_handle FROM passkey_users WHERE username = ?1",
                    params![username],
                    |row| row.get::<_, Vec<u8>>(0),
                )
            })
            .await?;
        value
            .try_into()
            .map_err(|_| AuthError::Database(rusqlite::Error::InvalidQuery))
    }

    async fn passkey_list(&self, username: &str) -> Result<Vec<PasskeySummary>, AuthError> {
        let username = username.to_owned();
        self.with_connection(move |connection| {
            let mut query = connection.prepare("SELECT id, name, created_at, last_used_at FROM passkeys WHERE username = ?1 ORDER BY created_at DESC, id DESC")?;
            query.query_map(params![username], |row| Ok(PasskeySummary {
                id: row.get(0)?, name: row.get(1)?, created_at: row.get(2)?, last_used_at: row.get(3)?,
            }))?.collect()
        }).await
    }

    async fn passkeys_for(&self, username: &str) -> Result<Vec<Passkey>, AuthError> {
        let username = username.to_owned();
        self.with_connection(move |connection| {
            let mut query =
                connection.prepare("SELECT credential_json FROM passkeys WHERE username = ?1")?;
            query
                .query_map(params![username], |row| {
                    let json: String = row.get(0)?;
                    serde_json::from_str(&json).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })
                })?
                .collect()
        })
        .await
    }

    async fn passkey_for_discoverable_login(
        &self,
        user_handle: &[u8],
        credential_id: &[u8],
    ) -> Result<Option<(String, Passkey)>, AuthError> {
        let user_handle = user_handle.to_vec();
        let credential_id = credential_id.to_vec();
        self.with_connection(move |connection| {
            let row: Option<(String, String)> = connection.query_row(
                "SELECT p.username, p.credential_json FROM passkeys p JOIN passkey_users u ON u.username = p.username WHERE u.user_handle = ?1 AND p.credential_id = ?2",
                params![user_handle, credential_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional()?;
            row.map(|(username, json)| {
                serde_json::from_str(&json)
                    .map(|credential| (username, credential))
                    .map_err(|error| rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    ))
            }).transpose()
        }).await
    }

    async fn add_passkey(
        &self,
        username: &str,
        name: String,
        credential: Passkey,
        now: i64,
    ) -> Result<PasskeySummary, AppError> {
        let username = username.to_owned();
        let id = random_id(16)?;
        let credential_id = credential.cred_id().to_vec();
        let json = serde_json::to_string(&credential).map_err(|_| AppError::Internal)?;
        let summary = PasskeySummary {
            id: id.clone(),
            name: name.clone(),
            created_at: now,
            last_used_at: None,
        };
        let saved = self.with_connection(move |connection| {
            let transaction = connection.transaction()?;
            let count: i64 = transaction.query_row("SELECT count(*) FROM passkeys WHERE username = ?1", params![username], |row| row.get(0))?;
            if count >= MAX_PASSKEYS_PER_USER { return Ok(false); }
            let rows = transaction.execute("INSERT OR IGNORE INTO passkeys(id, username, credential_id, name, credential_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![id, username, credential_id, name, json, now])?;
            transaction.commit()?;
            Ok(rows == 1)
        }).await?;
        if !saved {
            return Err(AppError::Conflict);
        }
        Ok(summary)
    }

    async fn rename_passkey(
        &self,
        username: &str,
        id: &str,
        name: String,
    ) -> Result<Option<PasskeySummary>, AuthError> {
        let username = username.to_owned();
        let id = id.to_owned();
        self.with_connection(move |connection| {
            connection.execute("UPDATE passkeys SET name = ?3 WHERE id = ?1 AND username = ?2", params![id, username, name])?;
            connection.query_row("SELECT id, name, created_at, last_used_at FROM passkeys WHERE id = ?1 AND username = ?2", params![id, username], |row| Ok(PasskeySummary { id: row.get(0)?, name: row.get(1)?, created_at: row.get(2)?, last_used_at: row.get(3)? })).optional()
        }).await
    }

    async fn remove_passkey(&self, username: &str, id: &str) -> Result<bool, AuthError> {
        let username = username.to_owned();
        let id = id.to_owned();
        self.with_connection(move |connection| {
            Ok(connection.execute(
                "DELETE FROM passkeys WHERE id = ?1 AND username = ?2",
                params![id, username],
            )? == 1)
        })
        .await
    }

    async fn update_passkey_after_login(
        &self,
        username: &str,
        result: AuthenticationResult,
        now: i64,
    ) -> Result<bool, AuthError> {
        let username = username.to_owned();
        let credential_id = result.cred_id().to_vec();
        self.with_connection(move |connection| {
            let row: Option<String> = connection.query_row("SELECT credential_json FROM passkeys WHERE credential_id = ?1 AND username = ?2", params![credential_id, username], |row| row.get(0)).optional()?;
            let Some(json) = row else { return Ok(false); };
            let mut credential: Passkey = serde_json::from_str(&json).map_err(|error| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error)))?;
            if credential.update_credential(&result).is_none() { return Ok(false); }
            let updated = serde_json::to_string(&credential).map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            Ok(connection.execute("UPDATE passkeys SET credential_json = ?3, last_used_at = ?4 WHERE credential_id = ?1 AND username = ?2", params![credential_id, username, updated, now])? == 1)
        }).await
    }
}

fn random_id(bytes: usize) -> Result<String, AppError> {
    let mut random = vec![0_u8; bytes];
    random_fill(&mut random).map_err(|_| AppError::Internal)?;
    Ok(encode_hex(&random))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> PasskeyState {
        PasskeyState::new(&url::Url::parse("https://files.example.test").unwrap()).unwrap()
    }

    #[test]
    fn login_ceremonies_drop_the_oldest_instead_of_refusing() {
        let passkeys = state();
        let mut last = String::new();
        for _ in 0..=MAX_PENDING_LOGINS {
            let (_, login) = passkeys
                .webauthn
                .start_discoverable_authentication()
                .unwrap();
            last = passkeys.insert_login(login).unwrap();
        }
        assert_eq!(passkeys.logins.lock().unwrap().len(), MAX_PENDING_LOGINS);
        assert!(passkeys.take_login(&last).is_ok());
        assert!(matches!(
            passkeys.take_login(&last),
            Err(AppError::AuthenticationFailed)
        ));
    }

    #[test]
    fn registrations_are_bounded_per_user_and_separate_from_logins() {
        let passkeys = state();
        let registration = |username: &str| {
            let (_, state) = passkeys
                .webauthn
                .start_passkey_registration(Uuid::from_bytes([1; 16]), username, username, None)
                .unwrap();
            Registration {
                username: username.to_owned(),
                session_key: vec![0; 32],
                name: "Key".into(),
                state,
            }
        };
        let bob = passkeys.insert_registration(registration("Bob")).unwrap();
        let alice: Vec<_> = (0..=MAX_PENDING_REGISTRATIONS_PER_USER)
            .map(|_| passkeys.insert_registration(registration("Alice")).unwrap())
            .collect();
        assert_eq!(
            passkeys.registrations.lock().unwrap().len(),
            MAX_PENDING_REGISTRATIONS_PER_USER + 1
        );
        assert!(passkeys.take_login(&bob).is_err());
        assert!(passkeys.take_registration(&bob).is_ok());
        let kept = alice
            .iter()
            .filter(|id| passkeys.take_registration(id).is_ok())
            .count();
        assert_eq!(kept, MAX_PENDING_REGISTRATIONS_PER_USER);
    }

    #[tokio::test]
    async fn passkey_records_are_scoped_to_their_owner_and_can_be_renamed_or_removed() {
        let directory = tempfile::tempdir().unwrap();
        let store = SessionStore::open(&directory.path().join("sessions.sqlite3")).unwrap();
        let alice_handle = store.passkey_user_handle("Alice").await.unwrap();
        assert_eq!(
            alice_handle,
            store.passkey_user_handle("Alice").await.unwrap()
        );
        assert_ne!(
            alice_handle,
            store.passkey_user_handle("Bob").await.unwrap()
        );
        let id = "0123456789abcdef0123456789abcdef";
        store.with_connection(move |connection| {
            connection.execute("INSERT INTO passkeys (id, username, credential_id, name, credential_json, created_at) VALUES (?1, 'Alice', x'01', 'Laptop', '{}', 100)", params![id])?;
            Ok(())
        }).await.unwrap();
        assert!(store.passkey_list("Bob").await.unwrap().is_empty());
        assert!(
            store
                .rename_passkey("Bob", id, "Stolen".into())
                .await
                .unwrap()
                .is_none()
        );
        assert!(!store.remove_passkey("Bob", id).await.unwrap());
        let renamed = store
            .rename_passkey("Alice", id, "My laptop".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(renamed.name, "My laptop");
        assert_eq!(store.passkey_list("Alice").await.unwrap().len(), 1);
        assert!(store.remove_passkey("Alice", id).await.unwrap());
        assert!(store.passkey_list("Alice").await.unwrap().is_empty());
    }
}
