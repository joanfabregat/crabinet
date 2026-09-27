//! WebAuthn passkeys bound to configuration-defined users.

use super::*;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use axum::{
    extract::{DefaultBodyLimit, Path},
    routing::patch,
};
use webauthn_rs::prelude::{
    AuthenticationResult, DiscoverableAuthentication, DiscoverableKey, Passkey,
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    Uuid, Webauthn, WebauthnBuilder,
};
use webauthn_rs_proto::ResidentKeyRequirement;

const CHALLENGE_LIFETIME: Duration = Duration::from_secs(300);
const MAX_PENDING: usize = 1_024;
const MAX_PASSKEYS_PER_USER: i64 = 20;
const MAX_PASSKEY_NAME_BYTES: usize = 80;

pub(super) struct PasskeyState {
    webauthn: Webauthn,
    pending: Mutex<HashMap<String, Pending>>,
}

struct Pending {
    expires: Instant,
    kind: PendingKind,
}

enum PendingKind {
    Registration {
        username: String,
        session_key: Vec<u8>,
        name: String,
        state: PasskeyRegistration,
    },
    Login {
        username: String,
        state: PasskeyAuthentication,
    },
    DiscoverableLogin {
        state: DiscoverableAuthentication,
    },
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
    #[serde(default)]
    username: Option<String>,
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
            pending: Mutex::new(HashMap::new()),
        })
    }

    fn insert(&self, kind: PendingKind) -> Result<String, AppError> {
        let mut pending = self.pending.lock().map_err(|_| AppError::Internal)?;
        let now = Instant::now();
        pending.retain(|_, flow| flow.expires > now);
        if pending.len() >= MAX_PENDING {
            return Err(AppError::Busy);
        }
        let mut random = [0_u8; TOKEN_BYTES];
        random_fill(&mut random).map_err(|_| AppError::Internal)?;
        let id = encode_hex(&random);
        pending.insert(
            id.clone(),
            Pending {
                expires: now + CHALLENGE_LIFETIME,
                kind,
            },
        );
        Ok(id)
    }

    fn take(&self, id: &str) -> Result<PendingKind, AppError> {
        if id.len() != TOKEN_BYTES * 2 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(AppError::AuthenticationFailed);
        }
        let pending = self
            .pending
            .lock()
            .map_err(|_| AppError::Internal)?
            .remove(id)
            .ok_or(AppError::AuthenticationFailed)?;
        if pending.expires <= Instant::now() {
            return Err(AppError::AuthenticationFailed);
        }
        Ok(pending.kind)
    }
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
    let flow_id = passkeys.insert(PendingKind::Registration {
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
    let PendingKind::Registration {
        username,
        session_key,
        name,
        state: registration,
    } = passkeys.take(&payload.flow_id)?
    else {
        return Err(AppError::AuthenticationFailed);
    };
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
    Ok(no_store_json(summary))
}

async fn start_login(
    State(state): State<AppState>,
    PeerAddress(source): PeerAddress,
    headers: HeaderMap,
    payload: Result<Json<StartLogin>, JsonRejection>,
) -> Result<Response, AppError> {
    validate_same_origin(&headers)?;
    let auth = state.auth().ok_or(AppError::Internal)?;
    let passkeys = enabled(auth)?;
    let Json(payload) = payload.map_err(|_| AppError::AuthenticationFailed)?;
    let input = payload.username.as_deref().unwrap_or("").trim();
    if input.is_empty() {
        let rate_key = RateLimitKey {
            account: normalized_identifier_digest("passkey-discoverable"),
            source,
        };
        if !auth
            .inner
            .rate_limit
            .lock()
            .map_err(|_| AppError::Internal)?
            .allow(rate_key, auth.inner.clock.now())
        {
            return Err(AppError::TooManyRequests);
        }
        let (options, authentication) = passkeys
            .webauthn
            .start_discoverable_authentication()
            .map_err(|_| AppError::Internal)?;
        let flow_id = passkeys.insert(PendingKind::DiscoverableLogin {
            state: authentication,
        })?;
        return Ok(no_store_json(Challenge { flow_id, options }));
    }
    let user = if is_plausible_username(input) {
        auth.inner.users.get_key_value(input)
    } else if input.len() <= 254 && input.is_ascii() && input.contains('@') {
        auth.inner.users.iter().find(|(_, user)| {
            user.email
                .as_deref()
                .is_some_and(|email| email.eq_ignore_ascii_case(input))
        })
    } else {
        None
    };
    let account = user.map_or(input, |(name, _)| name.as_str());
    let rate_key = RateLimitKey {
        account: normalized_identifier_digest(account),
        source,
    };
    if !auth
        .inner
        .rate_limit
        .lock()
        .map_err(|_| AppError::Internal)?
        .allow(rate_key, auth.inner.clock.now())
    {
        return Err(AppError::TooManyRequests);
    }
    let (username, _) = user
        .filter(|(_, user)| !user.disabled)
        .ok_or(AppError::AuthenticationFailed)?;
    let credentials = auth.inner.store.passkeys_for(username).await?;
    if credentials.is_empty() {
        return Err(AppError::AuthenticationFailed);
    }
    let (options, authentication) = passkeys
        .webauthn
        .start_passkey_authentication(&credentials)
        .map_err(|_| AppError::AuthenticationFailed)?;
    let flow_id = passkeys.insert(PendingKind::Login {
        username: username.to_owned(),
        state: authentication,
    })?;
    Ok(no_store_json(Challenge { flow_id, options }))
}

async fn finish_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<FinishLogin>, JsonRejection>,
) -> Result<Response, AppError> {
    validate_same_origin(&headers)?;
    let auth = state.auth().ok_or(AppError::Internal)?;
    let passkeys = enabled(auth)?;
    let Json(payload) = payload.map_err(|_| AppError::AuthenticationFailed)?;
    let pending = passkeys.take(&payload.flow_id)?;
    let (username, result) = match pending {
        PendingKind::Login { username, state } => {
            if auth
                .inner
                .users
                .get(&username)
                .is_none_or(|user| user.disabled)
            {
                return Err(AppError::AuthenticationFailed);
            }
            let result = passkeys
                .webauthn
                .finish_passkey_authentication(&payload.credential, &state)
                .map_err(|_| AppError::AuthenticationFailed)?;
            (username, result)
        }
        PendingKind::DiscoverableLogin { state } => {
            let (handle, credential_id) = passkeys
                .webauthn
                .identify_discoverable_authentication(&payload.credential)
                .map_err(|_| AppError::AuthenticationFailed)?;
            let (username, credential) = auth
                .inner
                .store
                .passkey_for_discoverable_login(handle.as_bytes(), credential_id)
                .await?
                .ok_or(AppError::AuthenticationFailed)?;
            if auth
                .inner
                .users
                .get(&username)
                .is_none_or(|user| user.disabled)
            {
                return Err(AppError::AuthenticationFailed);
            }
            let result = passkeys
                .webauthn
                .finish_discoverable_authentication(
                    &payload.credential,
                    state,
                    &[DiscoverableKey::from(&credential)],
                )
                .map_err(|_| AppError::AuthenticationFailed)?;
            (username, result)
        }
        PendingKind::Registration { .. } => return Err(AppError::AuthenticationFailed),
    };
    if !auth
        .inner
        .store
        .update_passkey_after_login(&username, result, auth.inner.clock.now())
        .await?
    {
        return Err(AppError::AuthenticationFailed);
    }
    let session = auth
        .issue_session(
            &username,
            None,
            session_cookie(&headers).and_then(|cookie| auth.session_key(cookie)),
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

async fn rename_passkey(
    State(state): State<AppState>,
    Path(id): Path<String>,
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
    Path(id): Path<String>,
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
