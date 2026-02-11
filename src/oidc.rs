//! OIDC authentication — login, callback, logout handlers.

use crate::config::OidcConfig;
use crate::db::{self, Db};
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{AppendHeaders, IntoResponse, Redirect, Response},
    Extension,
};
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    AuthType, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// The concrete CoreClient type after from_provider_metadata + set_redirect_uri.
/// from_provider_metadata sets auth/token/userinfo to EndpointSet when present in metadata.
type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// Pending OIDC flow entry: PKCE verifier, nonce, and creation timestamp.
type PendingFlows =
    Arc<Mutex<std::collections::HashMap<String, (PkceCodeVerifier, Nonce, Instant)>>>;

/// Shared OIDC state initialized once at startup.
#[derive(Clone)]
pub struct OidcState {
    pub client: OidcClient,
    pub http_client: openidconnect::reqwest::Client,
    pub config: OidcConfig,
    /// Auth session TTL in seconds.
    pub session_ttl_secs: u64,
    /// Pending OIDC flows: state -> (pkce_verifier, nonce, created_at)
    pub pending: PendingFlows,
}

/// Initialize OIDC client by discovering provider metadata.
pub async fn init_oidc(config: &OidcConfig, session_ttl_secs: u64) -> Result<OidcState, String> {
    let http_client = openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let issuer_url = IssuerUrl::new(config.issuer_url.clone())
        .map_err(|e| format!("Invalid issuer URL: {}", e))?;

    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .map_err(|e| format!("OIDC discovery failed: {}", e))?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(config.client_secret.clone())),
    )
    .set_auth_type(AuthType::RequestBody)
    .set_redirect_uri(
        RedirectUrl::new(config.redirect_uri.clone())
            .map_err(|e| format!("Invalid redirect URI: {}", e))?,
    );

    Ok(OidcState {
        client,
        http_client,
        config: config.clone(),
        session_ttl_secs,
        pending: Arc::new(Mutex::new(std::collections::HashMap::new())),
    })
}

#[derive(Deserialize)]
pub struct LoginParams {
    pub next: Option<String>,
}

/// GET /auth/login — redirect user to OIDC provider.
pub async fn login(State(oidc): State<OidcState>, Query(params): Query<LoginParams>) -> Response {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut auth_request = oidc
        .client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge);

    // Request any extra scopes configured (e.g. "groups")
    for scope in &oidc.config.extra_scopes {
        auth_request = auth_request.add_scope(Scope::new(scope.clone()));
    }

    let (auth_url, csrf_token, nonce) = auth_request.url();

    // Store PKCE verifier + nonce keyed by CSRF state, and evict stale entries
    let state_key = csrf_token.secret().clone();
    let mut pending = oidc.pending.lock().await;
    let cutoff = Instant::now() - std::time::Duration::from_secs(600);
    pending.retain(|_, (_, _, created)| *created > cutoff);
    pending.insert(state_key.clone(), (pkce_verifier, nonce, Instant::now()));
    drop(pending);

    // Set state in a cookie so we can verify on callback, then redirect
    let state_cookie = format!(
        "rustguac_oidc_state={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600",
        state_key
    );

    let mut cookies = vec![(header::SET_COOKIE, state_cookie)];

    // Store post-login redirect URL in a cookie if provided and safe
    if let Some(ref next) = params.next {
        if next.starts_with('/') && !next.contains("://") {
            let next_cookie = format!(
                "rustguac_next={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600",
                next
            );
            cookies.push((header::SET_COOKIE, next_cookie));
        }
    }

    (
        AppendHeaders(cookies),
        Redirect::temporary(auth_url.as_str()),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// GET /auth/callback — exchange code for tokens, create session.
pub async fn callback(
    State(oidc): State<OidcState>,
    Extension(database): Extension<Db>,
    headers: axum::http::HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Response {
    // Handle SSO error responses (e.g. user denied consent, timeout)
    if let Some(ref err) = params.error {
        let desc = params
            .error_description
            .as_deref()
            .unwrap_or("unknown error");
        tracing::warn!("OIDC callback error from provider: {} — {}", err, desc);
        return axum::response::Redirect::to("/?sso_error=1").into_response();
    }

    let code = match params.code {
        Some(c) => c,
        None => {
            tracing::warn!("OIDC callback missing 'code' parameter");
            return axum::response::Redirect::to("/?sso_error=1").into_response();
        }
    };

    let state = match params.state {
        Some(s) => s,
        None => {
            tracing::warn!("OIDC callback missing 'state' parameter");
            return axum::response::Redirect::to("/?sso_error=1").into_response();
        }
    };

    // Retrieve and remove the pending PKCE verifier
    let pending_entry = oidc.pending.lock().await.remove(&state);
    let (pkce_verifier, nonce, _created) = match pending_entry {
        Some(entry) => entry,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"error": "invalid or expired OIDC state"})),
            )
                .into_response();
        }
    };

    // Exchange authorization code for tokens
    let code_request = match oidc.client.exchange_code(AuthorizationCode::new(code)) {
        Ok(req) => req,
        Err(e) => {
            tracing::error!("OIDC token endpoint not configured: {:?}", e);
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": "OIDC token endpoint not available"})),
            )
                .into_response();
        }
    };

    let token_response = match code_request
        .set_pkce_verifier(pkce_verifier)
        .request_async(&oidc.http_client)
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("OIDC token exchange failed: {:?}", e);
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": "OIDC token exchange failed"})),
            )
                .into_response();
        }
    };

    // Extract and verify ID token
    use openidconnect::core::{CoreIdToken, CoreIdTokenClaims};
    let id_token: &CoreIdToken = match token_response.id_token() {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": "no ID token in OIDC response"})),
            )
                .into_response();
        }
    };

    let claims: &CoreIdTokenClaims = match id_token.claims(&oidc.client.id_token_verifier(), &nonce)
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("OIDC ID token verification failed: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": "ID token verification failed"})),
            )
                .into_response();
        }
    };

    // Extract user info from claims
    let subject = claims.subject().to_string();
    let email: String = claims
        .email()
        .map(|e| e.to_string())
        .unwrap_or_else(|| subject.clone());
    let name: String = claims
        .name()
        .and_then(|n| n.get(None).map(|v| v.to_string()))
        .unwrap_or_default();

    // Extract group memberships from ID token JWT payload
    let groups = extract_groups_from_jwt(&id_token.to_string(), &oidc.config.groups_claim);
    if !groups.is_empty() {
        tracing::info!(email = %email, groups = ?groups, "OIDC groups extracted");
    }

    // Resolve role from group-to-role mappings (highest matching wins).
    // Returns Some(role) only if a mapping matched; None means keep existing role.
    let db_for_role = database.clone();
    let groups_for_role = groups.clone();
    let mapped_role = match tokio::task::spawn_blocking(move || {
        db::resolve_role_from_groups(&db_for_role, &groups_for_role)
    })
    .await
    {
        Ok(Ok(role)) => role,
        _ => None,
    };

    // Upsert user in DB (sets default_role only on first login INSERT, not on subsequent updates)
    let default_role = oidc.config.default_role.clone();
    let db_clone = database.clone();
    let email_clone = email.clone();
    let name_clone = name.clone();
    let subject_clone = subject.clone();

    let user = match tokio::task::spawn_blocking(move || {
        db::upsert_user(
            &db_clone,
            &email_clone,
            &name_clone,
            Some(&subject_clone),
            &default_role,
            &groups,
        )
    })
    .await
    {
        Ok(Ok(user)) => user,
        Ok(Err(e)) => {
            tracing::error!("Failed to upsert user: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "failed to create user"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Spawn blocking failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "internal error"})),
            )
                .into_response();
        }
    };

    // If a group mapping matched, update the user's role to the mapped value
    let effective_role = if let Some(ref role) = mapped_role {
        let db_clone = database.clone();
        let email_clone = email.clone();
        let role_clone = role.clone();
        let _ = tokio::task::spawn_blocking(move || {
            db::set_user_role(&db_clone, &email_clone, &role_clone)
        })
        .await;
        tracing::info!(email = %email, role = %role, "Role set from group mapping");
        role.clone()
    } else {
        user.role.clone()
    };

    if user.disabled {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "account is disabled"})),
        )
            .into_response();
    }

    // Create auth session
    let user_id = user.id;
    let ttl_secs = oidc.session_ttl_secs;
    let db_clone = database.clone();
    let session_token = match tokio::task::spawn_blocking(move || {
        db::create_auth_session(&db_clone, user_id, ttl_secs)
    })
    .await
    {
        Ok(Ok(token)) => token,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "failed to create session"})),
            )
                .into_response();
        }
    };

    tracing::info!(email = %email, role = %effective_role, "OIDC login successful");

    // Check for post-login redirect cookie
    let redirect_to = extract_cookie_from_headers(&headers, "rustguac_next")
        .filter(|n| n.starts_with('/') && !n.contains("://"))
        .unwrap_or_else(|| "/addressbook.html".to_string());

    // Set session cookie and redirect; clear OIDC state and next cookies
    let session_cookie = format!(
        "rustguac_session={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        session_token, ttl_secs
    );
    let clear_state_cookie =
        "rustguac_oidc_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0".to_string();
    let clear_next_cookie = "rustguac_next=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0".to_string();

    (
        AppendHeaders([
            (header::SET_COOKIE, session_cookie),
            (header::SET_COOKIE, clear_state_cookie),
            (header::SET_COOKIE, clear_next_cookie),
        ]),
        Redirect::temporary(&redirect_to),
    )
        .into_response()
}

/// GET /auth/logout — clear session cookie and redirect to login.
pub async fn logout(
    Extension(database): Extension<Db>,
    request: axum::extract::Request,
) -> Response {
    // Try to delete the session from DB
    if let Some(token) = extract_cookie_value(&request, "rustguac_session") {
        let db_clone = database.clone();
        let _ =
            tokio::task::spawn_blocking(move || db::delete_auth_session(&db_clone, &token)).await;
    }

    let clear_cookie = "rustguac_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0".to_string();

    (
        [(header::SET_COOKIE, clear_cookie)],
        Redirect::temporary("/"),
    )
        .into_response()
}

/// Extract group memberships from a JWT string by decoding the payload.
/// Accepts the raw JWT string to avoid openidconnect's complex generics.
fn extract_groups_from_jwt(token_str: &str, groups_claim: &str) -> Vec<String> {
    use base64::Engine;
    let parts: Vec<&str> = token_str.split('.').collect();
    let payload = match parts.get(1) {
        Some(p) => p,
        None => return Vec::new(),
    };

    let bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    let claims: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    match claims.get(groups_claim) {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        // Some OIDC providers send a plain string instead of an array when user is in one group
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// Extract a cookie value from request headers.
fn extract_cookie_value(request: &axum::extract::Request, name: &str) -> Option<String> {
    extract_cookie_from_headers(request.headers(), name)
}

/// Extract a cookie value from a HeaderMap.
fn extract_cookie_from_headers(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                let c = c.trim();
                if let Some(val) = c.strip_prefix(name) {
                    val.strip_prefix('=').map(|v| v.to_string())
                } else {
                    None
                }
            })
        })
}
