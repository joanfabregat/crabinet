//! Server-side OpenID Connect sign-in. Provider tokens never reach the frontend.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{app::AppState, config::OidcConfig, error::AppError};

const TRANSACTION_SECONDS: u64 = 300;
const TRANSACTION_COOKIE: &str = "crabinet_oidc_state";

#[derive(Clone)]
pub struct OidcService {
    inner: Arc<OidcInner>,
}

struct OidcInner {
    config: OidcConfig,
    http: reqwest::Client,
    metadata: ProviderMetadata,
    keys: Mutex<JwkSet>,
    pending: Mutex<HashMap<String, Pending>>,
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

struct Pending {
    nonce: String,
    verifier: String,
    previous_cookie: Option<String>,
    expires_at: u64,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Methods {
    password_enabled: bool,
    oidc_enabled: bool,
}

impl OidcService {
    pub async fn discover(config: OidcConfig) -> Result<Self, String> {
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
                pending: Mutex::new(HashMap::new()),
            }),
        })
    }

    fn begin(&self, headers: &HeaderMap) -> Result<Response, AppError> {
        let state = random_token()?;
        let nonce = random_token()?;
        let verifier = random_token()?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let now = unix_time()?;
        {
            let mut pending = self.inner.pending.lock().map_err(|_| AppError::Internal)?;
            pending.retain(|_, item| item.expires_at > now);
            if pending.len() >= 1024 {
                return Err(AppError::Busy);
            }
            pending.insert(
                state.clone(),
                Pending {
                    nonce: nonce.clone(),
                    verifier,
                    previous_cookie: crate::auth::session_cookie(headers).map(str::to_owned),
                    expires_at: now + TRANSACTION_SECONDS,
                },
            );
        }
        let mut url = Url::parse(&self.inner.metadata.authorization_endpoint)
            .map_err(|_| AppError::Internal)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", self.inner.config.client_id())
            .append_pair("redirect_uri", self.inner.config.redirect_uri())
            .append_pair("scope", "openid email")
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        let mut response = Redirect::temporary(url.as_str()).into_response();
        response.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&format!(
            "{TRANSACTION_COOKIE}={state}; Max-Age={TRANSACTION_SECONDS}; Path=/api/v1/auth/oidc; Secure; HttpOnly; SameSite=Lax"
        )).map_err(|_| AppError::Internal)?);
        no_store(&mut response);
        Ok(response)
    }

    async fn finish(
        &self,
        headers: &HeaderMap,
        callback: CallbackQuery,
        auth: &crate::auth::AuthService,
    ) -> Result<Response, AppError> {
        let state = callback.state.ok_or(AppError::AuthenticationFailed)?;
        let transaction = self.consume(headers, &state)?;
        if callback.error.is_some() {
            return Err(AppError::AuthenticationFailed);
        }
        let code = callback.code.ok_or(AppError::AuthenticationFailed)?;
        if code.is_empty() || code.len() > 4096 {
            return Err(AppError::AuthenticationFailed);
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
            .map_err(|_| AppError::AuthenticationFailed)?;
        let token: TokenResponse = response_json(response, 64 * 1024)
            .await
            .map_err(|_| AppError::AuthenticationFailed)?;
        let claims = self.verify(&token.id_token, &transaction.nonce).await?;
        let email = if claims.email_verified == Some(false) {
            None
        } else if let Some(email) = claims.verified_email() {
            Some(email.to_owned())
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
                .map_err(|_| AppError::AuthenticationFailed)?;
            let info: UserInfo = response_json(response, 64 * 1024)
                .await
                .map_err(|_| AppError::AuthenticationFailed)?;
            if info.sub != claims.sub || info.email_verified != Some(true) {
                None
            } else {
                info.email
            }
        } else {
            None
        };
        let Some(email) = email else {
            return Ok(redirect_unknown());
        };
        match auth
            .login_oidc(&email, transaction.previous_cookie.as_deref())
            .await
        {
            Ok((_, cookie_token, _)) => {
                let mut response = Redirect::to("/").into_response();
                response.headers_mut().append(header::SET_COOKIE, HeaderValue::from_str(&format!(
                    "crabinet_session={cookie_token}; Path=/; Max-Age={}; Secure; HttpOnly; SameSite=Strict",
                    auth.absolute_timeout_seconds()
                )).map_err(|_| AppError::Internal)?);
                response
                    .headers_mut()
                    .append(header::SET_COOKIE, clear_transaction_cookie());
                no_store(&mut response);
                Ok(response)
            }
            Err(AppError::AuthenticationFailed) => Ok(redirect_unknown()),
            Err(error) => Err(error),
        }
    }

    fn consume(&self, headers: &HeaderMap, state: &str) -> Result<Pending, AppError> {
        if state.len() > 128 || cookie(headers, TRANSACTION_COOKIE) != Some(state) {
            return Err(AppError::AuthenticationFailed);
        }
        let transaction = self
            .inner
            .pending
            .lock()
            .map_err(|_| AppError::Internal)?
            .remove(state)
            .ok_or(AppError::AuthenticationFailed)?;
        if transaction.expires_at <= unix_time()? {
            return Err(AppError::AuthenticationFailed);
        }
        Ok(transaction)
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

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE) {
        for part in header.to_str().ok()?.split(';') {
            let (key, value) = part.trim().split_once('=')?;
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

fn clear_transaction_cookie() -> HeaderValue {
    HeaderValue::from_static(
        "crabinet_oidc_state=; Max-Age=0; Path=/api/v1/auth/oidc; Secure; HttpOnly; SameSite=Lax",
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
    })
}

async fn start(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, AppError> {
    state.oidc().ok_or(AppError::NotFound)?.begin(&headers)
}

async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    state
        .oidc()
        .ok_or(AppError::NotFound)?
        .finish(&headers, query, state.auth().ok_or(AppError::Internal)?)
        .await
}

async fn disconnect(State(state): State<AppState>) -> Result<Response, AppError> {
    Ok(state.oidc().ok_or(AppError::NotFound)?.disconnect())
}

#[cfg(test)]
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
                    pending: Mutex::new(HashMap::new()),
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
            }),
            &EncodingKey::from_ec_der(private),
        )
        .unwrap()
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
            HeaderValue::from_static("crabinet_oidc_state=a; crabinet_oidc_state=b"),
        );
        assert_eq!(cookie(&headers, TRANSACTION_COOKIE), None);
    }

    #[test]
    fn state_requires_the_starting_browser_and_is_single_use() {
        let (service, _) = service_and_key();
        let response = service.begin(&HeaderMap::new()).unwrap();
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

    fn local_auth() -> (TempDir, AuthService) {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("session.key"), [7_u8; 32]).unwrap();
        fs::write(directory.path().join("oidc.secret"), "example-secret").unwrap();
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
        let (mut service, private) = service_and_key();
        let begin = service.begin(&HeaderMap::new()).unwrap();
        let location = Url::parse(
            begin
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
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
        let response = service.finish(&headers, callback, &auth).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/");
        assert!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|cookie| cookie.to_str().unwrap().starts_with("crabinet_session="))
        );
        let replay = CallbackQuery {
            code: Some("sample-code".into()),
            state: Some(state),
            error: None,
        };
        assert!(matches!(
            service.finish(&headers, replay, &auth).await,
            Err(AppError::AuthenticationFailed)
        ));
        server.abort();
    }
}
