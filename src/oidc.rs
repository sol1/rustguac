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
use tokio::sync::{Mutex, RwLock};

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

/// Lazily-discovered OIDC client. `None` until provider metadata is fetched
/// successfully; populated on first use (or by best-effort startup discovery)
/// and re-attempted on the next use after a discovery failure.
type LazyClient = Arc<RwLock<Option<Discovered>>>;

/// What discovery produced: the client, plus the key ids in the provider's
/// signing key set, kept only to explain an ID token signature failure.
#[derive(Clone)]
struct Discovered {
    client: OidcClient,
    key_ids: Arc<Vec<String>>,
}

/// Shared OIDC state. The HTTP client and config are fixed at startup; the
/// provider-derived `client` is discovered lazily so that an unreachable
/// provider at boot does not permanently disable SSO (it is retried on first
/// login once the provider becomes available).
#[derive(Clone)]
pub struct OidcState {
    client: LazyClient,
    pub http_client: openidconnect::reqwest::Client,
    pub config: OidcConfig,
    /// Auth session TTL in seconds.
    pub session_ttl_secs: u64,
    /// Pending OIDC flows: state -> (pkce_verifier, nonce, created_at)
    pub pending: PendingFlows,
    /// Set while a background discovery started by `warm_in_background` runs,
    /// so polling the unauthenticated status endpoint cannot pile them up.
    discovering: Arc<std::sync::atomic::AtomicBool>,
}

impl OidcState {
    /// Return a ready OIDC client, discovering provider metadata on first use
    /// (and re-attempting after a prior failure). The result is cached so
    /// steady-state logins pay no discovery cost. Concurrent callers during a
    /// cold start share a single discovery via the write lock.
    pub async fn client(&self) -> Result<OidcClient, String> {
        self.discovered().await.map(|d| d.client)
    }

    /// Key ids in the provider's signing key set as last discovered.
    pub async fn provider_key_ids(&self) -> Arc<Vec<String>> {
        match self.client.read().await.as_ref() {
            Some(d) => d.key_ids.clone(),
            None => Arc::new(Vec::new()),
        }
    }

    async fn discovered(&self) -> Result<Discovered, String> {
        if let Some(d) = self.client.read().await.clone() {
            return Ok(d);
        }
        // Cold (or previously-failed) cache: take the write lock and discover.
        let mut guard = self.client.write().await;
        // Another task may have populated the cache while we waited.
        if let Some(d) = guard.clone() {
            return Ok(d);
        }
        let d = discover_client(&self.config, &self.http_client).await?;
        *guard = Some(d.clone());
        tracing::info!(
            keys = d.key_ids.len(),
            "OIDC provider metadata discovered for {}",
            self.config.issuer_url
        );
        Ok(d)
    }

    /// Start a discovery in the background if none is cached and none is
    /// already running. Called from the unauthenticated status endpoint, so
    /// it must stay at one outbound attempt at a time however often that
    /// endpoint is hit while the provider is down.
    pub fn warm_in_background(&self) {
        use std::sync::atomic::Ordering;
        if self
            .discovering
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let state = self.clone();
        tokio::spawn(async move {
            let _ = state.discovered().await;
            state.discovering.store(false, Ordering::Release);
        });
    }

    /// Whether provider metadata has already been discovered and cached.
    /// Cheap (read lock, no network) — used by the status endpoint to report
    /// availability without blocking on a discovery round-trip.
    pub async fn is_ready(&self) -> bool {
        self.client.read().await.is_some()
    }
}

/// Discover provider metadata and build the OIDC client. Network-dependent —
/// this is what fails when the provider (e.g. Authelia) is unreachable.
async fn discover_client(
    config: &OidcConfig,
    http_client: &openidconnect::reqwest::Client,
) -> Result<Discovered, String> {
    let issuer_url = IssuerUrl::new(config.issuer_url.clone())
        .map_err(|e| format!("Invalid issuer URL: {}", e))?;

    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, http_client)
        .await
        .map_err(|e| friendly_discovery_error(&format!("{:?}", e)))?;

    // client_secret is validated at config-load time when [oidc] is
    // configured (Config::load), so reaching this point with None
    // means we were called with a partially-constructed config; treat
    // that as a programming error rather than a user-facing one.
    let key_ids: Vec<String> = provider_metadata
        .jwks()
        .keys()
        .iter()
        .filter_map(|k| openidconnect::JsonWebKey::key_id(k).map(|id| id.to_string()))
        .collect();
    let client_secret = config
        .client_secret
        .clone()
        .ok_or_else(|| "OIDC client_secret missing at startup".to_string())?;
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(client_secret)),
    )
    .set_auth_type(AuthType::RequestBody)
    .set_redirect_uri(
        RedirectUrl::new(config.redirect_uri.clone())
            .map_err(|e| format!("Invalid redirect URI: {}", e))?,
    );
    Ok(Discovered {
        client,
        key_ids: Arc::new(key_ids),
    })
}

/// Initialize OIDC state. Builds the HTTP client (fatal config errors here —
/// e.g. a bad CA cert — disable SSO), then makes a best-effort attempt to
/// discover provider metadata. Discovery failure is non-fatal: SSO stays
/// enabled and discovery is retried on the first login.
pub async fn init_oidc(config: &OidcConfig, session_ttl_secs: u64) -> Result<OidcState, String> {
    let mut builder = openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        // Bound discovery/token requests so a hung or unreachable provider can't
        // stall the lazy-discovery path (login, callback, or background warm).
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10));

    if config.tls_skip_verify {
        tracing::warn!(
            "OIDC TLS certificate verification is DISABLED (tls_skip_verify = true). \
             This exposes client_secret and tokens to MITM attacks — do NOT use in production."
        );
        builder = builder.danger_accept_invalid_certs(true);
    }

    if let Some(ref ca_path) = config.ca_cert {
        let pem = std::fs::read(ca_path)
            .map_err(|e| format!("Failed to read OIDC CA cert {}: {}", ca_path, e))?;
        let cert = reqwest::tls::Certificate::from_pem(&pem)
            .map_err(|e| format!("Failed to parse OIDC CA cert {}: {}", ca_path, e))?;
        builder = builder.add_root_certificate(cert);
        tracing::info!("OIDC TLS: added custom CA certificate from {}", ca_path);
    }

    let http_client = builder
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let state = OidcState {
        client: Arc::new(RwLock::new(None)),
        http_client,
        config: config.clone(),
        session_ttl_secs,
        pending: Arc::new(Mutex::new(std::collections::HashMap::new())),
        discovering: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };

    // Best-effort eager discovery so the first login is fast and startup logs
    // reflect provider reachability. A failure here is non-fatal: SSO remains
    // enabled and discovery is retried on the next login (e.g. once the
    // provider finishes starting).
    if let Err(e) = state.client().await {
        tracing::warn!(
            "OIDC provider not reachable at startup ({}); SSO stays enabled \
             and discovery will be retried on the first login",
            e
        );
    }

    Ok(state)
}

#[derive(Deserialize)]
pub struct LoginParams {
    pub next: Option<String>,
}

/// GET /auth/login — redirect user to OIDC provider.
pub async fn login(State(oidc): State<OidcState>, Query(params): Query<LoginParams>) -> Response {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Resolve the client lazily — this is the point where a provider that was
    // unreachable at startup gets re-discovered.
    let client = match oidc.client().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("OIDC discovery failed on login: {}", e);
            return Redirect::temporary("/?sso_error=1").into_response();
        }
    };

    let mut auth_request = client
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
    if let Some(next) = params.next.as_deref().and_then(safe_next) {
        let next_cookie = format!(
            "rustguac_next={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600",
            next
        );
        cookies.push((header::SET_COOKIE, next_cookie));
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

    // Verify the state cookie matches the state query parameter (binds flow to browser)
    let state_cookie = extract_cookie_from_headers(&headers, "rustguac_oidc_state");
    if state_cookie.as_deref() != Some(&state) {
        // Distinguish "cookie absent" from "cookie present but different" and
        // surface request context — this is the usual point of failure when the
        // browser doesn't send the state cookie back on the callback (e.g. the
        // proxy→rustguac leg running HTTPS dropping cookies, a SameSite
        // interaction, or login host != redirect_uri host).
        let present_cookies = cookie_names(&headers);
        tracing::warn!(
            cookie_present = state_cookie.is_some(),
            cookies_seen = ?present_cookies,
            host = ?header_str(&headers, "host"),
            forwarded_host = ?header_str(&headers, "x-forwarded-host"),
            forwarded_proto = ?header_str(&headers, "x-forwarded-proto"),
            "OIDC callback state cookie mismatch ({})",
            if state_cookie.is_some() { "present but different" } else { "absent" }
        );
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "OIDC state cookie mismatch"})),
        )
            .into_response();
    }

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

    // Resolve the client lazily (same retry path as login).
    let client = match oidc.client().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("OIDC discovery failed on callback: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": "OIDC provider not available"})),
            )
                .into_response();
        }
    };

    // Exchange authorization code for tokens
    let code_request = match client.exchange_code(AuthorizationCode::new(code)) {
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

    let claims: &CoreIdTokenClaims = match id_token.claims(&client.id_token_verifier(), &nonce) {
        Ok(c) => c,
        Err(e) => {
            // The library's message ("Signature verification failed") hides
            // the cause in its source chain, so log the whole chain plus the
            // token's key id and algorithm (header fields, not secrets).
            let (alg, kid) = jwt_header_alg_kid(&id_token.to_string());
            let provider_key_ids = oidc.provider_key_ids().await;
            let kid_known = kid
                .as_deref()
                .map(|k| provider_key_ids.iter().any(|known| known == k));
            tracing::error!(
                error = %error_chain(&e),
                token_alg = alg.as_deref().unwrap_or("?"),
                token_kid = kid.as_deref().unwrap_or("?"),
                kid_in_provider_keys = ?kid_known,
                provider_keys = ?provider_key_ids,
                "OIDC ID token verification failed"
            );
            if kid_known == Some(false) {
                tracing::error!(
                    "The ID token is signed with a key the provider did not publish when rustguac \
                     started. If the provider has rotated its keys since, restart rustguac. On \
                     Microsoft Entra ID, an app with claims mapping or a custom signing \
                     certificate signs with an app-specific key that is only listed under the \
                     ?appid=<client-id> key set."
                );
            }
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
        let db_for_seen = database.clone();
        let groups_for_seen = groups.clone();
        let _ = tokio::task::spawn_blocking(move || {
            if let Err(e) = db::upsert_seen_groups(&db_for_seen, &groups_for_seen) {
                tracing::warn!(error = %e, "failed to persist seen OIDC groups");
            }
        })
        .await;
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

    // Upsert user in DB (sets default_role only on first login INSERT, not on subsequent updates).
    // With auto_create_users = false, only already-provisioned users get through.
    let default_role = oidc.config.default_role.clone();
    let auto_create = oidc.config.auto_create_users;
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
            auto_create,
        )
    })
    .await
    {
        Ok(Ok(Some(user))) => user,
        Ok(Ok(None)) => {
            tracing::warn!(email = %email, "OIDC login rejected: no account and auto_create_users is disabled");
            return Redirect::to("/?sso_error=no_account").into_response();
        }
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
        tracing::warn!(email = %email, "OIDC login rejected: account is disabled");
        return Redirect::to("/?sso_error=disabled").into_response();
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
        .and_then(|n| safe_next(&n).map(str::to_string))
        .unwrap_or_else(|| "/addressbook.html".to_string());

    // Set session cookie and redirect; clear OIDC state and next cookies
    let session_cookie = format!(
        "rustguac_session={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        session_token, ttl_secs
    );
    let clear_state_cookie =
        "rustguac_oidc_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0".to_string();
    let clear_next_cookie =
        "rustguac_next=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0".to_string();

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

    let clear_cookie =
        "rustguac_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0".to_string();

    (
        [(header::SET_COOKIE, clear_cookie)],
        Redirect::temporary("/"),
    )
        .into_response()
}

/// Extract group memberships from a JWT string by decoding the payload.
/// Accepts the raw JWT string to avoid openidconnect's complex generics.
/// Max OIDC groups kept per login. Caps `seen_groups` bloat + `oidc_groups`
/// column size if an IdP returns an absurdly large group list (misconfig or
/// compromise). Realistic AD deployments sit well under this.
const MAX_OIDC_GROUPS: usize = 64;
/// Max characters per group name. Longer names are truncated on the byte
/// boundary preserving UTF-8 (we drop trailing partial code points).
const MAX_OIDC_GROUP_LEN: usize = 256;

fn truncate_group_name(s: &str) -> String {
    if s.len() <= MAX_OIDC_GROUP_LEN {
        return s.to_string();
    }
    let mut end = MAX_OIDC_GROUP_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// An error and its sources, joined with ": ".
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        out.push_str(": ");
        out.push_str(&s.to_string());
        source = s.source();
    }
    out
}

/// `alg` and `kid` from a JWT's (unverified) header, for diagnostics only.
fn jwt_header_alg_kid(token_str: &str) -> (Option<String>, Option<String>) {
    use base64::Engine;
    let header = token_str
        .split('.')
        .next()
        .and_then(|h| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(h)
                .ok()
        })
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    let field = |name: &str| {
        header
            .as_ref()
            .and_then(|h| h.get(name))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };
    (field("alg"), field("kid"))
}

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

    let mut groups: Vec<String> = match claims.get(groups_claim) {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(truncate_group_name))
            .collect(),
        // Some OIDC providers send a plain string instead of an array when user is in one group
        Some(serde_json::Value::String(s)) => vec![truncate_group_name(s)],
        _ => Vec::new(),
    };

    if groups.len() > MAX_OIDC_GROUPS {
        tracing::warn!(
            total = groups.len(),
            kept = MAX_OIDC_GROUPS,
            "OIDC groups claim exceeds cap — truncating"
        );
        groups.truncate(MAX_OIDC_GROUPS);
    }
    groups
}

/// Collect the names of cookies present in the request (values omitted, so we
/// never log secrets). Used for diagnosing missing-cookie failures.
fn cookie_names(headers: &axum::http::HeaderMap) -> Vec<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(|cookies| {
            cookies
                .split(';')
                .filter_map(|c| c.trim().split('=').next().map(|n| n.trim().to_string()))
                .filter(|n| !n.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Read a request header as a string for diagnostic logging.
fn header_str(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Extract a cookie value from request headers.
fn extract_cookie_value(request: &axum::extract::Request, name: &str) -> Option<String> {
    extract_cookie_from_headers(request.headers(), name)
}

/// Extract a cookie value from a HeaderMap.
/// Accept a post-login `next` only if it is a same-origin path.
///
/// Browsers are lenient about Location: they treat `\` as `/` and drop
/// tabs and newlines, so `/\evil.com` and a `/<TAB>/evil.com` that arrives
/// percent-decoded from the query both become `//evil.com`, another site,
/// after a check for a leading `//` has passed them. Requiring visible ASCII
/// with no backslash closes those, and also keeps the value safe to place in
/// the `rustguac_next` cookie and the Location header unescaped (no `;`,
/// `,`, quotes or spaces). Legitimate targets are already percent-encoded.
fn safe_next(next: &str) -> Option<&str> {
    let bytes = next.as_bytes();
    if next.len() > 2048 || bytes.first() != Some(&b'/') || bytes.get(1) == Some(&b'/') {
        return None;
    }
    if !bytes
        .iter()
        .all(|&b| (0x21..=0x7e).contains(&b) && !matches!(b, b'\\' | b';' | b',' | b'"'))
    {
        return None;
    }
    // An encoded slash or backslash straight after the first `/`.
    let lower = next.to_ascii_lowercase();
    if lower.starts_with("/%2f") || lower.starts_with("/%5c") {
        return None;
    }
    Some(next)
}

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

/// Reshape the openidconnect crate's discovery error into something an
/// operator can act on without grepping Debug output.
///
/// The specific case we handle is the issuer-URI mismatch that OIDC
/// Discovery's spec demands (the `issuer` claim in the discovery document
/// must byte-for-byte match the URL the client used to fetch it). This
/// fires for any OIDC provider where the operator has a trailing slash
/// wrong or copy-pasted the authorisation URL instead of the issuer URL:
/// Keycloak, Authentik, Azure AD / Entra ID, Okta, Auth0, JumpCloud,
/// Google, and so on. The original library error gives the two URIs but
/// phrases "expected" from the validator's perspective, which is
/// exactly backwards for what the operator needs to do. We flip it
/// around and name the fix explicitly.
///
/// Every other discovery failure (network, TLS, JSON parse, wrong path)
/// falls through to the raw Debug string so we don't swallow useful
/// diagnostics.
fn friendly_discovery_error(raw: &str) -> String {
    let (got, expected) = match parse_issuer_mismatch(raw) {
        Some(pair) => pair,
        None => return format!("OIDC discovery failed: {raw}"),
    };

    // `got` is what the provider actually advertises in its discovery
    // document; `expected` is what the library was told by the config.
    // The operator always needs to change `expected` to match `got`.
    let headline;
    let fix;
    if got.trim_end_matches('/') == expected.trim_end_matches('/') {
        // Slash-only mismatch — the overwhelmingly common case.
        if expected.ends_with('/') && !got.ends_with('/') {
            headline = "issuer_url has an extra trailing slash";
            fix = "remove the trailing slash from issuer_url".to_string();
        } else {
            headline = "issuer_url is missing a trailing slash";
            fix = "add a trailing slash to issuer_url".to_string();
        }
    } else {
        // Genuinely different URLs (different host, different path, wrong
        // URL copied from the provider console). Operator needs to see
        // both sides and swap in the right one.
        headline = "issuer_url does not match the provider's advertised value";
        fix = format!("set issuer_url = \"{got}\" in your [oidc] config");
    }

    format!(
        "OIDC discovery failed: {headline}.\n  \
         config:   \"{expected}\"\n  \
         provider: \"{got}\"\n  \
         Fix: {fix}."
    )
}

/// Extract (got, expected) from the openidconnect crate's issuer-mismatch
/// validation error. The error is Debug-formatted into the enclosing code
/// path and reliably contains:
///     unexpected issuer URI `GOT` (expected `EXPECTED`)
/// Returns None for any other shape so the caller falls through to the raw
/// error text.
fn parse_issuer_mismatch(raw: &str) -> Option<(String, String)> {
    let tag = "unexpected issuer URI `";
    let start = raw.find(tag)? + tag.len();
    let after = &raw[start..];
    let got_end = after.find('`')?;
    let got = after[..got_end].to_string();

    let rest = &after[got_end + 1..];
    let expected_tag = "(expected `";
    let expected_start = rest.find(expected_tag)? + expected_tag.len();
    let expected_rest = &rest[expected_start..];
    let expected_end = expected_rest.find('`')?;
    let expected = expected_rest[..expected_end].to_string();

    Some((got, expected))
}

#[cfg(test)]
mod tests {
    #[test]
    fn jwt_header_fields_are_read() {
        // {"alg":"RS256","kid":"abc123","typ":"JWT"}
        let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYzEyMyIsInR5cCI6IkpXVCJ9.e30.sig";
        assert_eq!(
            super::jwt_header_alg_kid(token),
            (Some("RS256".into()), Some("abc123".into()))
        );
        assert_eq!(super::jwt_header_alg_kid("garbage"), (None, None));
    }

    #[test]
    fn error_chain_includes_sources() {
        #[derive(Debug)]
        struct Inner;
        impl std::fmt::Display for Inner {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "No matching key found")
            }
        }
        impl std::error::Error for Inner {}
        #[derive(Debug)]
        struct Outer(Inner);
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "Signature verification failed")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        assert_eq!(
            super::error_chain(&Outer(Inner)),
            "Signature verification failed: No matching key found"
        );
    }

    #[test]
    fn safe_next_allows_same_origin_paths() {
        for ok in [
            "/connections.html",
            "/client/550e8400-e29b-41d4-a716-446655440000?token=abc",
            "/api/connect?scope=shared&folder=My%20Folder&entry=a%2Fb",
        ] {
            assert_eq!(super::safe_next(ok), Some(ok), "{ok}");
        }
    }

    /// M2: each of these is read by browsers as a different origin.
    #[test]
    fn safe_next_rejects_open_redirects() {
        for bad in [
            "//evil.com",
            "/\\evil.com",
            "/\t/evil.com",
            "/\n/evil.com",
            "/ /evil.com",
            "/%2F/evil.com",
            "/%5cevil.com",
            "https://evil.com",
            "evil.com",
            "",
            "/a;Domain=evil.com",
            "/caf\u{e9}",
        ] {
            assert_eq!(super::safe_next(bad), None, "{bad:?}");
        }
    }

    use super::*;
    use base64::Engine;

    fn make_jwt(payload: &serde_json::Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(payload).unwrap());
        format!("{}.{}.sig", header, payload)
    }

    #[test]
    fn groups_missing_claim_returns_empty() {
        let jwt = make_jwt(&serde_json::json!({"sub": "alice"}));
        assert!(extract_groups_from_jwt(&jwt, "groups").is_empty());
    }

    #[test]
    fn groups_malformed_jwt_returns_empty() {
        assert!(extract_groups_from_jwt("not-a-jwt", "groups").is_empty());
        assert!(extract_groups_from_jwt("onlyone", "groups").is_empty());
        assert!(extract_groups_from_jwt("a.b", "groups").is_empty());
        assert!(extract_groups_from_jwt("a.!notbase64!.c", "groups").is_empty());
    }

    #[test]
    fn groups_array_passed_through() {
        let jwt = make_jwt(&serde_json::json!({"groups": ["admins", "ops"]}));
        let got = extract_groups_from_jwt(&jwt, "groups");
        assert_eq!(got, vec!["admins".to_string(), "ops".to_string()]);
    }

    #[test]
    fn groups_single_string_wrapped() {
        let jwt = make_jwt(&serde_json::json!({"groups": "admins"}));
        assert_eq!(extract_groups_from_jwt(&jwt, "groups"), vec!["admins"]);
    }

    #[test]
    fn groups_non_string_values_filtered() {
        let jwt = make_jwt(&serde_json::json!({"groups": ["ok", 42, null, {"nested": "x"}]}));
        assert_eq!(extract_groups_from_jwt(&jwt, "groups"), vec!["ok"]);
    }

    #[test]
    fn groups_array_over_cap_truncated() {
        let many: Vec<String> = (0..MAX_OIDC_GROUPS + 50).map(|i| format!("g{i}")).collect();
        let jwt = make_jwt(&serde_json::json!({"groups": many}));
        let got = extract_groups_from_jwt(&jwt, "groups");
        assert_eq!(got.len(), MAX_OIDC_GROUPS);
        assert_eq!(got[0], "g0");
    }

    #[test]
    fn groups_long_names_truncated_on_utf8_boundary() {
        // Build a name with a multi-byte char straddling the 256-byte limit.
        // '€' is 3 bytes. Pad with ASCII up to position 254 then add two '€' —
        // naive byte-truncate at 256 would split the second '€'.
        let mut name = "a".repeat(254);
        name.push('€'); // bytes 254..257
        name.push('€'); // bytes 257..260
        let jwt = make_jwt(&serde_json::json!({"groups": [name.clone()]}));
        let got = extract_groups_from_jwt(&jwt, "groups");
        assert_eq!(got.len(), 1);
        // Truncation must end on a valid UTF-8 boundary ≤ 256 bytes.
        assert!(got[0].len() <= MAX_OIDC_GROUP_LEN);
        assert!(std::str::from_utf8(got[0].as_bytes()).is_ok());
        // And must not exceed the original.
        assert!(name.starts_with(&got[0]));
    }

    #[test]
    fn groups_short_names_pass_through_unchanged() {
        let jwt = make_jwt(&serde_json::json!({"groups": ["alpha", "beta"]}));
        assert_eq!(
            extract_groups_from_jwt(&jwt, "groups"),
            vec!["alpha", "beta"]
        );
    }

    #[test]
    fn groups_custom_claim_name_respected() {
        let jwt = make_jwt(&serde_json::json!({"roles": ["r1", "r2"], "groups": ["g1"]}));
        assert_eq!(extract_groups_from_jwt(&jwt, "roles"), vec!["r1", "r2"]);
        assert_eq!(extract_groups_from_jwt(&jwt, "groups"), vec!["g1"]);
    }

    // ── Discovery error wrapping ────────────────────────────────────────

    #[test]
    fn parse_issuer_mismatch_extracts_both_uris() {
        let raw = "Validation(\"unexpected issuer URI `https://oauth.jumpcloud.com` (expected `https://oauth.jumpcloud.com/`)\")";
        let (got, expected) = parse_issuer_mismatch(raw).expect("should parse");
        assert_eq!(got, "https://oauth.jumpcloud.com");
        assert_eq!(expected, "https://oauth.jumpcloud.com/");
    }

    #[test]
    fn parse_issuer_mismatch_handles_opposite_slash_direction() {
        // JumpCloud's other endpoint: the mirror-image of the JumpCloud bug.
        let raw = "Validation(\"unexpected issuer URI `https://oauth.id.jumpcloud.com/` (expected `https://oauth.id.jumpcloud.com`)\")";
        let (got, expected) = parse_issuer_mismatch(raw).expect("should parse");
        assert_eq!(got, "https://oauth.id.jumpcloud.com/");
        assert_eq!(expected, "https://oauth.id.jumpcloud.com");
    }

    #[test]
    fn parse_issuer_mismatch_returns_none_for_unrelated_errors() {
        assert!(parse_issuer_mismatch("Request(reqwest::Error { ... })").is_none());
        assert!(parse_issuer_mismatch("random string").is_none());
        assert!(parse_issuer_mismatch("").is_none());
    }

    #[test]
    fn friendly_discovery_error_extra_slash_in_config() {
        // Config has trailing slash, provider advertises without.
        let raw = "Validation(\"unexpected issuer URI `https://oauth.jumpcloud.com` (expected `https://oauth.jumpcloud.com/`)\")";
        let msg = friendly_discovery_error(raw);
        assert!(msg.contains("issuer_url has an extra trailing slash"));
        assert!(msg.contains("config:   \"https://oauth.jumpcloud.com/\""));
        assert!(msg.contains("provider: \"https://oauth.jumpcloud.com\""));
        assert!(msg.contains("Fix: remove the trailing slash from issuer_url"));
    }

    #[test]
    fn friendly_discovery_error_missing_slash_in_config() {
        // Provider advertises with trailing slash, config doesn't have one.
        let raw = "Validation(\"unexpected issuer URI `https://auth.example.com/realms/corp/` (expected `https://auth.example.com/realms/corp`)\")";
        let msg = friendly_discovery_error(raw);
        assert!(msg.contains("issuer_url is missing a trailing slash"));
        assert!(msg.contains("config:   \"https://auth.example.com/realms/corp\""));
        assert!(msg.contains("provider: \"https://auth.example.com/realms/corp/\""));
        assert!(msg.contains("Fix: add a trailing slash to issuer_url"));
    }

    #[test]
    fn friendly_discovery_error_different_urls_entirely() {
        // Azure-AD-style: the v2.0 authority URL vs the actual issuer.
        // Works for any provider where the operator copy-pasted a wrong URL.
        let raw = "Validation(\"unexpected issuer URI `https://sts.windows.net/tenant-id/` (expected `https://login.microsoftonline.com/tenant-id/v2.0`)\")";
        let msg = friendly_discovery_error(raw);
        assert!(msg.contains("issuer_url does not match the provider's advertised value"));
        assert!(msg.contains("config:   \"https://login.microsoftonline.com/tenant-id/v2.0\""));
        assert!(msg.contains("provider: \"https://sts.windows.net/tenant-id/\""));
        assert!(msg.contains("Fix: set issuer_url = \"https://sts.windows.net/tenant-id/\""));
    }

    #[test]
    fn friendly_discovery_error_passes_through_other_errors() {
        let raw = "Request(NetworkError(connect_timeout))";
        let msg = friendly_discovery_error(raw);
        assert_eq!(
            msg,
            "OIDC discovery failed: Request(NetworkError(connect_timeout))"
        );
    }
}
