//! Server-side OpenID Connect sign-in. Provider tokens never reach the frontend.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    app::AppState,
    audit,
    auth::{
        LoginRejection, PeerAddress, cookie_value, decode_token, encode_hex, session_cookie,
        session_cookie_header,
    },
    config::OidcConfig,
    error::AppError,
    extract::ApiQuery,
};

const TRANSACTION_SECONDS: u64 = 300;
const TRANSACTION_COOKIE: &str = "__Host-crabinet_oidc_state";
/// Bounds the replay-protection set of consumed states. Transactions live in
/// the browser, so nothing unauthenticated callers do can refuse new sign-ins.
const MAX_CONSUMED_STATES: usize = 4_096;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct OidcService {
    inner: Arc<OidcInner>,
}

struct OidcInner {
    config: OidcConfig,
    http: reqwest::Client,
    metadata: ProviderMetadata,
    keys: Mutex<JwkSet>,
    transaction_key: Vec<u8>,
    consumed: Mutex<HashMap<String, u64>>,
}

#[derive(Clone, Deserialize)]
struct ProviderMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    userinfo_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

/// One sign-in attempt. Its state, expiry and the previous session key travel
/// in an HMAC-protected cookie; the nonce and PKCE verifier are derived from
/// the state with the server key, so no per-attempt server memory is needed.
struct Transaction {
    nonce: String,
    verifier: String,
    previous_session_key: Option<Vec<u8>>,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// A refused callback: the public error, its audit reason, and whether the
/// browser is shown the unrecognized-account page rather than an error.
struct CallbackFailure {
    rejection: LoginRejection,
    identifier: Option<String>,
    unrecognized: bool,
}

impl CallbackFailure {
    const fn new(error: AppError, reason: &'static str) -> Self {
        Self {
            rejection: LoginRejection::new(error, reason),
            identifier: None,
            unrecognized: false,
        }
    }

    const fn refused(reason: &'static str) -> Self {
        Self::new(AppError::AuthenticationFailed, reason)
    }

    const fn unrecognized(reason: &'static str) -> Self {
        let mut failure = Self::refused(reason);
        failure.unrecognized = true;
        failure
    }
}
#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
    access_token: Option<String>,
}

#[derive(Deserialize)]
struct UserInfo {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: serde_json::Value,
    azp: Option<String>,
    nonce: String,
    iat: Option<u64>,
    email: Option<String>,
    email_verified: Option<bool>,
    picture: Option<String>,
}

impl Claims {
    fn verified_email(&self) -> Option<&str> {
        if self.email_verified == Some(true) {
            self.email.as_deref()
        } else {
            None
        }
    }
}

fn google_picture_url(picture: Option<&str>) -> Option<&str> {
    let picture = picture.filter(|value| value.len() <= 2_048)?;
    let url = Url::parse(picture).ok()?;
    (url.scheme() == "https"
        && url.host_str() == Some("lh3.googleusercontent.com")
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none())
    .then_some(picture)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Methods {
    password_enabled: bool,
    oidc_enabled: bool,
    passkey_enabled: bool,
}

impl OidcService {
    /// `transaction_key` authenticates sign-in transaction cookies; derive it
    /// from the session secret with a domain separate from other uses.
    pub async fn discover(config: OidcConfig, transaction_key: Vec<u8>) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .no_proxy()
            .build()
            .map_err(|_| "cannot initialize OIDC HTTP client")?;
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            config.issuer().trim_end_matches('/')
        );
        let metadata: ProviderMetadata = fetch_json(&http, &discovery_url, 64 * 1024).await?;
        if metadata.issuer != config.issuer() {
            return Err("OIDC discovery issuer does not match configuration".into());
        }
        for endpoint in [
            &metadata.authorization_endpoint,
            &metadata.token_endpoint,
            &metadata.jwks_uri,
        ] {
            safe_https_url(endpoint)?;
        }
        if let Some(endpoint) = &metadata.userinfo_endpoint {
            safe_https_url(endpoint)?;
        }
        if let Some(endpoint) = &metadata.end_session_endpoint {
            safe_https_url(endpoint)?;
        }
        if metadata
            .token_endpoint_auth_methods_supported
            .as_ref()
            .is_some_and(|methods| !methods.iter().any(|method| method == "client_secret_basic"))
        {
            return Err("OIDC provider does not support client_secret_basic".into());
        }
        let keys = fetch_json(&http, &metadata.jwks_uri, 256 * 1024).await?;
        Ok(Self {
            inner: Arc::new(OidcInner {
                config,
                http,
                metadata,
                keys: Mutex::new(keys),
                transaction_key,
                consumed: Mutex::new(HashMap::new()),
            }),
        })
    }

    fn transaction_mac(&self) -> HmacSha256 {
        HmacSha256::new_from_slice(&self.inner.transaction_key)
            .expect("HMAC accepts keys of every length")
    }

    fn derive(&self, domain: &[u8], state: &str) -> String {
        let mut mac = self.transaction_mac();
        mac.update(domain);
        mac.update(state.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    fn cookie_mac(&self, state: &str, expires_at: u64, previous: &str) -> HmacSha256 {
        let mut mac = self.transaction_mac();
        mac.update(b"oidc-transaction\0");
        mac.update(state.as_bytes());
        mac.update(b"\0");
        mac.update(expires_at.to_string().as_bytes());
        mac.update(b"\0");
        mac.update(previous.as_bytes());
        mac
    }

    fn begin(&self, previous_session_key: Option<&[u8]>) -> Result<Response, AppError> {
        let state = random_token()?;
        let nonce = self.derive(b"oidc-nonce\0", &state);
        let verifier = self.derive(b"oidc-verifier\0", &state);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let expires_at = unix_time()? + TRANSACTION_SECONDS;
        let previous = previous_session_key.map(encode_hex).unwrap_or_default();
        let tag = URL_SAFE_NO_PAD.encode(
            self.cookie_mac(&state, expires_at, &previous)
                .finalize()
                .into_bytes(),
        );
        let mut url = Url::parse(&self.inner.metadata.authorization_endpoint)
            .map_err(|_| AppError::Internal)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", self.inner.config.client_id())
            .append_pair("redirect_uri", self.inner.config.redirect_uri())
            .append_pair("scope", "openid profile email")
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        let mut response = Redirect::temporary(url.as_str()).into_response();
        response.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&format!(
            "{TRANSACTION_COOKIE}={state}.{expires_at}.{previous}.{tag}; Max-Age={TRANSACTION_SECONDS}; Path=/; Secure; HttpOnly; SameSite=Lax"
        )).map_err(|_| AppError::Internal)?);
        no_store(&mut response);
        Ok(response)
    }

    /// Completes a callback and writes the audit event for its outcome. An
    /// identity that cannot be mapped to an enabled user is redirected to the
    /// unrecognized-account page; a broken or forged transaction is refused.
    async fn finish(
        &self,
        headers: &HeaderMap,
        callback: CallbackQuery,
        auth: &crate::auth::AuthService,
        client: Option<IpAddr>,
    ) -> Result<Response, AppError> {
        match self.complete(headers, callback, auth).await {
            Ok((username, cookie_token)) => {
                audit::sign_in_succeeded("oidc_login", &username, client);
                let mut response = Redirect::to("/").into_response();
                response.headers_mut().append(
                    header::SET_COOKIE,
                    session_cookie_header(&cookie_token, auth.absolute_timeout_seconds()),
                );
                response
                    .headers_mut()
                    .append(header::SET_COOKIE, clear_transaction_cookie());
                no_store(&mut response);
                Ok(response)
            }
            Err(failure) => {
                audit::sign_in_rejected(
                    "oidc_login",
                    failure.rejection.reason,
                    failure.rejection.subject.as_deref(),
                    failure.identifier.as_deref(),
                    client,
                );
                match failure.rejection.error {
                    AppError::AuthenticationFailed if failure.unrecognized => {
                        Ok(redirect_unknown())
                    }
                    error => Err(error),
                }
            }
        }
    }

    async fn complete(
        &self,
        headers: &HeaderMap,
        callback: CallbackQuery,
        auth: &crate::auth::AuthService,
    ) -> Result<(String, String), CallbackFailure> {
        let refused = |reason| CallbackFailure::refused(reason);
        let state = callback
            .state
            .ok_or_else(|| refused("invalid_transaction"))?;
        let transaction = self
            .consume(headers, &state)
            .map_err(|error| CallbackFailure::new(error, "invalid_transaction"))?;
        if callback.error.is_some() {
            return Err(refused("provider_error"));
        }
        let code = callback.code.ok_or_else(|| refused("missing_code"))?;
        if code.is_empty() || code.len() > 4096 {
            return Err(refused("missing_code"));
        }
        let response = self
            .inner
            .http
            .post(&self.inner.metadata.token_endpoint)
            .basic_auth(
                self.inner.config.client_id(),
                Some(self.inner.config.client_secret()),
            )
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", self.inner.config.redirect_uri()),
                ("code_verifier", transaction.verifier.as_str()),
            ])
            .send()
            .await
            .map_err(|_| refused("token_exchange_failed"))?;
        let token: TokenResponse = response_json(response, 64 * 1024)
            .await
            .map_err(|_| refused("token_exchange_failed"))?;
        let claims = self
            .verify(&token.id_token, &transaction.nonce)
            .await
            .map_err(|error| CallbackFailure::new(error, "invalid_id_token"))?;
        let email = if claims.email_verified == Some(false) {
            return Err(CallbackFailure::unrecognized("unverified_email"));
        } else if let Some(email) = claims.verified_email() {
            email.to_owned()
        } else if let (Some(endpoint), Some(access_token)) = (
            &self.inner.metadata.userinfo_endpoint,
            token.access_token.as_deref(),
        ) {
            let response = self
                .inner
                .http
                .get(endpoint)
                .bearer_auth(access_token)
                .send()
                .await
                .map_err(|_| refused("userinfo_failed"))?;
            let info: UserInfo = response_json(response, 64 * 1024)
                .await
                .map_err(|_| refused("userinfo_failed"))?;
            if info.sub != claims.sub {
                return Err(CallbackFailure::unrecognized("userinfo_subject_mismatch"));
            }
            match (info.email_verified, info.email) {
                (Some(true), Some(email)) => email,
                _ => return Err(CallbackFailure::unrecognized("unverified_email")),
            }
        } else {
            return Err(CallbackFailure::unrecognized("unverified_email"));
        };
        let (username, cookie_token, _) = auth
            .login_oidc(
                &email,
                &claims.sub,
                google_picture_url(claims.picture.as_deref()),
                transaction.previous_session_key,
            )
            .await
            .map_err(|rejection| CallbackFailure {
                identifier: rejection
                    .subject
                    .is_none()
                    .then(|| auth.identifier_digest(&email)),
                unrecognized: true,
                rejection,
            })?;
        Ok((username, cookie_token))
    }

    fn consume(&self, headers: &HeaderMap, state: &str) -> Result<Transaction, AppError> {
        let value =
            cookie_value(headers, TRANSACTION_COOKIE).ok_or(AppError::AuthenticationFailed)?;
        let mut parts = value.split('.');
        let (Some(cookie_state), Some(expires_at), Some(previous), Some(tag), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(AppError::AuthenticationFailed);
        };
        if state.len() > 128 || cookie_state != state {
            return Err(AppError::AuthenticationFailed);
        }
        let expires_at: u64 = expires_at
            .parse()
            .map_err(|_| AppError::AuthenticationFailed)?;
        let tag = URL_SAFE_NO_PAD
            .decode(tag)
            .map_err(|_| AppError::AuthenticationFailed)?;
        self.cookie_mac(state, expires_at, previous)
            .verify_slice(&tag)
            .map_err(|_| AppError::AuthenticationFailed)?;
        let now = unix_time()?;
        if expires_at <= now {
            return Err(AppError::AuthenticationFailed);
        }
        let previous_session_key = if previous.is_empty() {
            None
        } else {
            Some(
                decode_token(previous)
                    .ok_or(AppError::AuthenticationFailed)?
                    .to_vec(),
            )
        };
        {
            let mut consumed = self.inner.consumed.lock().map_err(|_| AppError::Internal)?;
            consumed.retain(|_, expiry| *expiry > now);
            if consumed.contains_key(state) {
                return Err(AppError::AuthenticationFailed);
            }
            if consumed.len() >= MAX_CONSUMED_STATES
                && let Some(oldest) = consumed
                    .iter()
                    .min_by_key(|(_, expiry)| **expiry)
                    .map(|(state, _)| state.clone())
            {
                consumed.remove(&oldest);
            }
            consumed.insert(state.to_owned(), expires_at);
        }
        Ok(Transaction {
            nonce: self.derive(b"oidc-nonce\0", state),
            verifier: self.derive(b"oidc-verifier\0", state),
            previous_session_key,
        })
    }

    async fn verify(&self, token: &str, nonce: &str) -> Result<Claims, AppError> {
        if token.len() > 16 * 1024 {
            return Err(AppError::AuthenticationFailed);
        }
        let header = decode_header(token).map_err(|_| AppError::AuthenticationFailed)?;
        if !matches!(header.alg, Algorithm::RS256 | Algorithm::ES256) {
            return Err(AppError::AuthenticationFailed);
        }
        let kid = header.kid.ok_or(AppError::AuthenticationFailed)?;
        let mut key = self
            .inner
            .keys
            .lock()
            .map_err(|_| AppError::Internal)?
            .find(&kid)
            .cloned();
        if key.is_none() {
            let fresh: JwkSet =
                fetch_json(&self.inner.http, &self.inner.metadata.jwks_uri, 256 * 1024)
                    .await
                    .map_err(|_| AppError::AuthenticationFailed)?;
            key = fresh.find(&kid).cloned();
            *self.inner.keys.lock().map_err(|_| AppError::Internal)? = fresh;
        }
        let key = key.ok_or(AppError::AuthenticationFailed)?;
        if let Some(algorithm) = &key.common.key_algorithm
            && format!("{algorithm:?}") != format!("{:?}", header.alg)
        {
            return Err(AppError::AuthenticationFailed);
        }
        let decoding_key =
            DecodingKey::from_jwk(&key).map_err(|_| AppError::AuthenticationFailed)?;
        let mut validation = Validation::new(header.alg);
        validation.leeway = 30;
        validation.set_issuer(&[self.inner.config.issuer()]);
        validation.set_audience(&[self.inner.config.client_id()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let claims = decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|_| AppError::AuthenticationFailed)?
            .claims;
        let audience_count = match &claims.aud {
            serde_json::Value::Array(items) => items.len(),
            serde_json::Value::String(_) => 1,
            _ => 0,
        };
        if claims.iss != self.inner.config.issuer()
            || claims.sub.is_empty()
            || claims.nonce != nonce
            || audience_count == 0
            || claims
                .azp
                .as_ref()
                .is_some_and(|azp| azp != self.inner.config.client_id())
            || audience_count > 1 && claims.azp.as_deref() != Some(self.inner.config.client_id())
            || claims
                .iat
                .is_some_and(|iat| iat > unix_time().unwrap_or(0) + 60)
        {
            return Err(AppError::AuthenticationFailed);
        }
        Ok(claims)
    }

    fn disconnect(&self) -> Response {
        let target = self
            .inner
            .metadata
            .end_session_endpoint
            .as_ref()
            .and_then(|url| {
                let mut url = Url::parse(url).ok()?;
                url.query_pairs_mut()
                    .append_pair("client_id", self.inner.config.client_id());
                Some(url)
            });
        let mut response = if let Some(url) = target {
            Redirect::temporary(url.as_str()).into_response()
        } else {
            Redirect::to("/?oidc_error=provider_logout_unavailable").into_response()
        };
        response
            .headers_mut()
            .append(header::SET_COOKIE, clear_transaction_cookie());
        no_store(&mut response);
        response
    }
}

fn safe_https_url(value: &str) -> Result<(), String> {
    let url = Url::parse(value).map_err(|_| "OIDC provider returned an invalid endpoint")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("OIDC provider returned an unsafe endpoint".into());
    }
    Ok(())
}

async fn fetch_json<T: DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
    limit: usize,
) -> Result<T, String> {
    let response = http
        .get(url)
        .send()
        .await
        .map_err(|_| "OIDC provider request failed")?;
    response_json(response, limit).await
}

async fn response_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<T, String> {
    if !response.status().is_success() {
        return Err("OIDC provider returned an error".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "OIDC provider response failed")?
    {
        if body.len() + chunk.len() > limit {
            return Err("OIDC provider response is too large".into());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| "OIDC provider returned invalid JSON".into())
}

fn random_token() -> Result<String, AppError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| AppError::Internal)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn unix_time() -> Result<u64, AppError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::Internal)?
        .as_secs())
}

fn clear_transaction_cookie() -> HeaderValue {
    HeaderValue::from_static(
        "__Host-crabinet_oidc_state=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax",
    )
}

fn redirect_unknown() -> Response {
    let mut response = Redirect::to("/?oidc_error=unrecognized").into_response();
    response
        .headers_mut()
        .append(header::SET_COOKIE, clear_transaction_cookie());
    no_store(&mut response);
    response
}

fn no_store(response: &mut Response) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/methods", get(methods))
        .route("/auth/oidc/start", get(start))
        .route("/auth/oidc/callback", get(callback))
        .route("/auth/oidc/disconnect", get(disconnect))
}

async fn methods(State(state): State<AppState>) -> Json<Methods> {
    Json(Methods {
        password_enabled: state.auth().is_some_and(|auth| auth.password_enabled()),
        oidc_enabled: state.oidc().is_some(),
        passkey_enabled: state.auth().is_some_and(|auth| auth.passkey_enabled()),
    })
}

async fn start(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, AppError> {
    let oidc = state.oidc().ok_or(AppError::NotFound)?;
    let previous_session_key = state
        .auth()
        .and_then(|auth| session_cookie(&headers).and_then(|cookie| auth.session_key(cookie)));
    oidc.begin(previous_session_key.as_deref())
}

async fn callback(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    ApiQuery(query): ApiQuery<CallbackQuery>,
) -> Result<Response, AppError> {
    let oidc = state.oidc().ok_or(AppError::NotFound)?;
    let auth = state.auth().ok_or(AppError::Internal)?;
    let client = auth.client_address(peer, &headers);
    oidc.finish(&headers, query, auth, client).await
}

async fn disconnect(State(state): State<AppState>) -> Result<Response, AppError> {
    Ok(state.oidc().ok_or(AppError::NotFound)?.disconnect())
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "unit tests build synthetic fixtures in temporary directories"
)]
mod tests {
    use super::*;
    use crate::{auth::AuthService, config::Config};
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
    };
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    fn service_and_key() -> (OidcService, Vec<u8>) {
        let rng = SystemRandom::new();
        let private = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, private.as_ref()).unwrap();
        let public = pair.public_key().as_ref();
        assert_eq!(public.len(), 65);
        let keys: JwkSet = serde_json::from_value(json!({"keys": [{
            "kty": "EC", "crv": "P-256", "kid": "test", "alg": "ES256", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(&public[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&public[33..65])
        }]}))
        .unwrap();
        let config = OidcConfig::for_test();
        let metadata = ProviderMetadata {
            issuer: config.issuer().into(),
            authorization_endpoint: "https://id.example.com/authorize".into(),
            token_endpoint: "https://id.example.com/token".into(),
            jwks_uri: "https://id.example.com/jwks".into(),
            userinfo_endpoint: None,
            end_session_endpoint: None,
            token_endpoint_auth_methods_supported: None,
        };
        (
            OidcService {
                inner: Arc::new(OidcInner {
                    config,
                    http: reqwest::Client::builder().no_proxy().build().unwrap(),
                    metadata,
                    keys: Mutex::new(keys),
                    transaction_key: vec![3_u8; 32],
                    consumed: Mutex::new(HashMap::new()),
                }),
            },
            private.as_ref().to_vec(),
        )
    }

    fn token(
        private: &[u8],
        issuer: &str,
        audience: &str,
        nonce: &str,
        expiry: u64,
        verified: bool,
    ) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("test".into());
        encode(
            &header,
            &json!({
                "iss": issuer, "sub": "stable-subject", "aud": audience,
                "exp": expiry, "iat": unix_time().unwrap(), "nonce": nonce,
                "email": "Alice@Example.com", "email_verified": verified,
                "picture": "https://lh3.googleusercontent.com/a/test-avatar",
            }),
            &EncodingKey::from_ec_der(private),
        )
        .unwrap()
    }

    #[test]
    fn accepts_only_google_avatar_urls() {
        assert_eq!(
            google_picture_url(Some("https://lh3.googleusercontent.com/a/avatar")),
            Some("https://lh3.googleusercontent.com/a/avatar")
        );
        for url in [
            "http://lh3.googleusercontent.com/a/avatar",
            "https://lh3.googleusercontent.com.evil.example/a/avatar",
            "https://evil.example/a/avatar",
            "https://user@lh3.googleusercontent.com/a/avatar",
        ] {
            assert_eq!(google_picture_url(Some(url)), None);
        }
    }

    #[tokio::test]
    async fn accepts_only_signed_current_id_tokens_for_the_configured_client_and_nonce() {
        let (service, private) = service_and_key();
        let later = unix_time().unwrap() + 300;
        let valid = token(
            &private,
            "https://id.example.com",
            "crabinet",
            "nonce",
            later,
            true,
        );
        assert_eq!(
            service
                .verify(&valid, "nonce")
                .await
                .unwrap()
                .verified_email(),
            Some("Alice@Example.com")
        );
        assert!(service.verify(&valid, "other").await.is_err());
        for invalid in [
            token(
                &private,
                "https://other.example.com",
                "crabinet",
                "nonce",
                later,
                true,
            ),
            token(
                &private,
                "https://id.example.com",
                "other",
                "nonce",
                later,
                true,
            ),
            token(
                &private,
                "https://id.example.com",
                "crabinet",
                "nonce",
                unix_time().unwrap() - 100,
                true,
            ),
        ] {
            assert!(service.verify(&invalid, "nonce").await.is_err());
        }
        let unverified = token(
            &private,
            "https://id.example.com",
            "crabinet",
            "nonce",
            later,
            false,
        );
        assert!(
            service
                .verify(&unverified, "nonce")
                .await
                .unwrap()
                .verified_email()
                .is_none()
        );
    }

    #[test]
    fn duplicate_transaction_cookie_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("__Host-crabinet_oidc_state=a; __Host-crabinet_oidc_state=b"),
        );
        assert_eq!(cookie_value(&headers, TRANSACTION_COOKIE), None);
    }

    #[test]
    fn state_requires_the_starting_browser_and_is_single_use() {
        let (service, _) = service_and_key();
        let response = service.begin(None).unwrap();
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        let state = Url::parse(location)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let raw_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(raw_cookie.split(';').next().unwrap()).unwrap(),
        );
        assert!(matches!(
            service.consume(&HeaderMap::new(), &state),
            Err(AppError::AuthenticationFailed)
        ));
        assert!(service.consume(&headers, &state).is_ok());
        assert!(matches!(
            service.consume(&headers, &state),
            Err(AppError::AuthenticationFailed)
        ));
    }

    #[test]
    fn transaction_cookie_is_authenticated_and_carries_no_server_state() {
        let (service, _) = service_and_key();
        let previous = [9_u8; 32];
        let response = service.begin(Some(&previous)).unwrap();
        let location = response.headers().get(header::LOCATION).unwrap();
        let location = Url::parse(location.to_str().unwrap()).unwrap();
        let query = |name: &str| {
            location
                .query_pairs()
                .find(|(key, _)| key == name)
                .unwrap()
                .1
                .into_owned()
        };
        let state = query("state");
        let raw_cookie = response.headers().get(header::SET_COOKIE).unwrap();
        let raw_cookie = raw_cookie.to_str().unwrap();
        assert!(raw_cookie.starts_with("__Host-crabinet_oidc_state="));
        assert!(raw_cookie.contains("; Path=/;"));
        let pair = raw_cookie.split(';').next().unwrap().to_owned();
        let with_cookie = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, HeaderValue::from_str(value).unwrap());
            headers
        };

        for tampered in [
            pair.replacen(&encode_hex(&previous), &encode_hex(&[8_u8; 32]), 1),
            pair.replacen(&state, &random_token().unwrap(), 1),
            format!(
                "{}{}",
                &pair[..pair.len() - 1],
                if pair.ends_with('A') { "B" } else { "A" }
            ),
        ] {
            assert!(matches!(
                service.consume(&with_cookie(&tampered), &state),
                Err(AppError::AuthenticationFailed)
            ));
        }
        let transaction = service.consume(&with_cookie(&pair), &state).unwrap();
        assert_eq!(
            transaction.previous_session_key.as_deref(),
            Some(&previous[..])
        );
        assert_eq!(transaction.nonce, query("nonce"));
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(transaction.verifier.as_bytes())),
            query("code_challenge")
        );
    }

    fn local_auth() -> (TempDir, AuthService) {
        let directory = tempfile::tempdir().unwrap();
        crate::config::write_private_file(&directory.path().join("session.key"), [7_u8; 32]);
        crate::config::write_private_file(&directory.path().join("oidc.secret"), "example-secret");
        fs::write(
            directory.path().join("config.toml"),
            r#"version = 1
[server]
listen = "127.0.0.1:8080"
database_path = "sessions.sqlite3"
session_secret_file = "session.key"
max_upload_size = "1 MiB"
max_preview_size = "1 MiB"
[auth]
password_enabled = false
oidc_enabled = true
[auth.oidc]
issuer = "https://id.example.com"
client_id = "crabinet"
client_secret_file = "oidc.secret"
redirect_uri = "https://files.example.com/api/v1/auth/oidc/callback"
[[users]]
username = "alice"
email = "alice@example.com"
"#,
        )
        .unwrap();
        let config = Config::load(directory.path().join("config.toml")).unwrap();
        let auth = AuthService::from_config(&config).unwrap();
        (directory, auth)
    }

    #[tokio::test]
    async fn callback_exchanges_code_maps_email_and_rejects_replay() {
        let (_directory, auth) = local_auth();
        let logs = crate::audit::capture::start();
        let (mut service, private) = service_and_key();
        let begin = service.begin(None).unwrap();
        let location = Url::parse(
            begin
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        assert!(
            location
                .query_pairs()
                .any(|(key, value)| { key == "scope" && value == "openid profile email" })
        );
        let state = location
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let nonce = location
            .query_pairs()
            .find(|(key, _)| key == "nonce")
            .unwrap()
            .1
            .into_owned();
        let raw_cookie = begin
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(raw_cookie.split(';').next().unwrap()).unwrap(),
        );

        let signed = token(
            &private,
            "https://id.example.com",
            "crabinet",
            &nonce,
            unix_time().unwrap() + 300,
            true,
        );
        let signed_token = signed.clone();
        let state_value = state.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let provider = axum::Router::new().route(
            "/token",
            axum::routing::post(move |body: String| {
                let signed = signed.clone();
                async move {
                    assert!(body.contains("grant_type=authorization_code"));
                    assert!(body.contains("code_verifier="));
                    Json(json!({"id_token": signed}))
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, provider).await.unwrap() });
        Arc::get_mut(&mut service.inner)
            .unwrap()
            .metadata
            .token_endpoint = format!("http://{address}/token");

        let callback = CallbackQuery {
            code: Some("sample-code".into()),
            state: Some(state.clone()),
            error: None,
        };
        let client = Some(std::net::IpAddr::from([198, 51, 100, 7]));
        let response = service
            .finish(&headers, callback, &auth, client)
            .await
            .unwrap();
        let success = logs.take();
        for needle in ["oidc_login", "success", "alice", "198.51.100.7"] {
            assert!(success.contains(needle), "missing {needle}: {success}");
        }
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/");
        assert!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|cookie| cookie
                    .to_str()
                    .unwrap()
                    .starts_with("__Host-crabinet_session="))
        );
        let replay = CallbackQuery {
            code: Some("sample-code".into()),
            state: Some(state),
            error: None,
        };
        assert!(matches!(
            service.finish(&headers, replay, &auth, None).await,
            Err(AppError::AuthenticationFailed)
        ));
        let replayed = logs.take();
        assert!(
            replayed.contains("oidc_login") && replayed.contains("invalid_transaction"),
            "{replayed}"
        );
        let session_cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|cookie| {
                cookie
                    .to_str()
                    .unwrap()
                    .strip_prefix("__Host-crabinet_session=")
                    .map(|value| value.split(';').next().unwrap().to_owned())
            })
            .unwrap();
        let captured = format!("{success}{replayed}");
        for secret in [
            "sample-code",
            signed_token.as_str(),
            state_value.as_str(),
            session_cookie.as_str(),
            "example-secret",
        ] {
            assert!(
                !captured.contains(secret),
                "log contains a secret: {captured}"
            );
        }
        server.abort();
    }
}
