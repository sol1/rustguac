//! Authentication middleware — supports API key, OIDC session cookie, and
//! single-use WebSocket tickets.

use crate::db::{self, AuthError, Db};
use axum::{
    extract::{ConnectInfo, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use ipnetwork::IpNetwork;
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Single-use WebSocket ticket. Created via POST /api/ws-ticket, consumed on
/// WebSocket connect. Prevents API keys from appearing in WebSocket URLs.
struct WsTicket {
    identity: AuthIdentity,
    created: Instant,
}

/// Thread-safe store of pending WebSocket tickets.
#[derive(Clone)]
pub struct WsTicketStore(Arc<Mutex<HashMap<String, WsTicket>>>);

const WS_TICKET_TTL_SECS: u64 = 30;

impl WsTicketStore {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    /// Create a ticket for the given identity. Returns the ticket string.
    pub fn create(&self, identity: AuthIdentity) -> String {
        let ticket = format!("wst_{}", uuid::Uuid::new_v4().as_simple());
        let mut store = self.0.lock().unwrap();

        // Prune expired tickets while we have the lock
        let cutoff = Instant::now() - std::time::Duration::from_secs(WS_TICKET_TTL_SECS);
        store.retain(|_, t| t.created > cutoff);

        store.insert(
            ticket.clone(),
            WsTicket {
                identity,
                created: Instant::now(),
            },
        );
        ticket
    }

    /// Consume a ticket, returning the identity if valid and not expired.
    /// Single-use: the ticket is removed on consumption.
    pub fn consume(&self, ticket: &str) -> Option<AuthIdentity> {
        let mut store = self.0.lock().unwrap();
        let entry = store.remove(ticket)?;
        if entry.created.elapsed().as_secs() <= WS_TICKET_TTL_SECS {
            Some(entry.identity)
        } else {
            None
        }
    }
}

/// Shared extension carrying the trusted proxy CIDRs from config.
#[derive(Clone)]
pub struct TrustedProxies(pub Vec<String>);

/// Identity of the authenticated caller.
#[derive(Clone, Debug)]
pub enum AuthIdentity {
    /// API key admin — always full admin access.
    ApiKey(String),
    /// OIDC user with email, role, and group memberships.
    User {
        email: String,
        /// The role shown for the user: their recorded role, or for an API
        /// token the lower of that and the token's cap.
        role: String,
        groups: Vec<String>,
        /// The roles in effect (#294): every role their groups map to, or
        /// their directly assigned role when no mapping matches.
        roles: Vec<String>,
        /// The union of those roles' permissions, cut down to the token's
        /// cap for an API token.
        perms: crate::perms::PermSet,
    },
}

impl AuthIdentity {
    pub fn display_name(&self) -> &str {
        match self {
            AuthIdentity::ApiKey(name) => name,
            AuthIdentity::User { email, .. } => email,
        }
    }

    pub fn role(&self) -> &str {
        match self {
            AuthIdentity::ApiKey(_) => "admin",
            AuthIdentity::User { role, .. } => role,
        }
    }

    /// Return OIDC group memberships. Empty for API key identities.
    /// The identity as folder access sees it: login email and groups.
    pub fn folder_subject(&self) -> crate::vault::FolderSubject<'_> {
        match self {
            AuthIdentity::ApiKey(_) => crate::vault::FolderSubject {
                email: None,
                groups: &[],
            },
            AuthIdentity::User { email, groups, .. } => crate::vault::FolderSubject {
                email: Some(email),
                groups,
            },
        }
    }

    pub fn groups(&self) -> &[String] {
        match self {
            AuthIdentity::ApiKey(_) => &[],
            AuthIdentity::User { groups, .. } => groups,
        }
    }

    /// Everything this identity may do. Admin API keys hold every
    /// permission; a user holds what their role grants (#294).
    pub fn permissions(&self) -> crate::perms::PermSet {
        match self {
            AuthIdentity::ApiKey(_) => crate::perms::PermSet::all(),
            AuthIdentity::User { perms, .. } => *perms,
        }
    }

    /// Whether this identity holds `perm`.
    pub fn has_perm(&self, perm: crate::perms::Perm) -> bool {
        self.permissions().contains(perm)
    }
}

/// Map role names to numeric levels for comparison.
pub fn role_level(role: &str) -> u8 {
    match role {
        "admin" => 4,
        "poweruser" => 3,
        "operator" => 2,
        "viewer" => 1,
        _ => 0,
    }
}

/// The identity of an authenticated user: their roles and permissions as the
/// database has them now, cut down to `cap` (a token's `max_role`). A
/// database error grants nothing.
pub fn user_identity(db: &Db, user: db::User, cap: Option<&str>) -> AuthIdentity {
    let access = crate::roles::user_access(db, &user).unwrap_or_else(|e| {
        tracing::error!(error = %e, email = %user.email, "could not resolve the user's roles");
        crate::roles::UserAccess {
            direct_role: user.role.clone(),
            direct_role_in_effect: true,
            group_roles: Vec::new(),
            roles: Vec::new(),
            permissions: crate::perms::PermSet::EMPTY,
        }
    });
    let mut perms = access.permissions;
    let role = match cap {
        Some(cap) => {
            perms = perms.intersection(
                crate::roles::role_perms(db, cap).unwrap_or(crate::perms::PermSet::EMPTY),
            );
            compute_effective_role(&user.role, &Some(cap.to_string()))
        }
        None => user.role.clone(),
    };
    AuthIdentity::User {
        groups: user.groups_vec(),
        email: user.email,
        role,
        roles: access.roles,
        perms,
    }
}

/// Compute the effective role for a user API token.
/// Returns the lower of the user's current role and the token's max_role cap.
pub fn compute_effective_role(user_role: &str, max_role: &Option<String>) -> String {
    match max_role {
        Some(max) if role_level(max) < role_level(user_role) => max.clone(),
        _ => user_role.to_string(),
    }
}

/// Extract the real client IP, honouring X-Forwarded-For when the socket
/// address belongs to a trusted proxy CIDR.
pub fn client_ip(headers: &HeaderMap, socket_addr: IpAddr, trusted_proxies: &[String]) -> IpAddr {
    client_ip_from(
        headers,
        socket_addr,
        &parse_trusted_proxies(trusted_proxies),
    )
}

/// Parse `trusted_proxies` CIDRs, dropping entries that do not parse
/// (startup warns about those).
pub fn parse_trusted_proxies(trusted_proxies: &[String]) -> Vec<IpNetwork> {
    trusted_proxies
        .iter()
        .filter_map(|s| s.parse::<IpNetwork>().ok())
        .collect()
}

/// Resolve the client address behind a chain of trusted proxies.
///
/// X-Forwarded-For is walked from the RIGHT. Each proxy appends the address
/// it received the request from, so the right-hand entries are the only ones
/// written by infrastructure we trust; anything to their left came from the
/// client and may be forged. The client is the first entry, reading
/// leftwards, that is not itself a trusted proxy. Taking the leftmost entry
/// instead would let anyone choose their own address (and so walk through an
/// IP allowlist) behind any proxy that appends to an incoming header, which
/// includes nginx's `$proxy_add_x_forwarded_for` and Apache's mod_proxy.
///
/// Every X-Forwarded-For header line is read, in order, since some proxies
/// add a new line rather than appending to the existing one. Entries are
/// split on raw bytes so a non-UTF-8 value smuggled in on the left cannot
/// hide the valid address a proxy appended after it.
pub fn client_ip_from(headers: &HeaderMap, socket_addr: IpAddr, trusted: &[IpNetwork]) -> IpAddr {
    let is_trusted = |ip: IpAddr| trusted.iter().any(|net| net.contains(ip));
    if !is_trusted(socket_addr) {
        return socket_addr;
    }
    let hops: Vec<&[u8]> = headers
        .get_all("x-forwarded-for")
        .iter()
        .flat_map(|v| v.as_bytes().split(|&b| b == b','))
        .collect();
    let mut client = socket_addr;
    for hop in hops.iter().rev() {
        // A malformed entry ends the walk: nothing to its left can be
        // attributed to a trusted proxy.
        let Some(ip) = parse_forwarded_ip(hop) else {
            break;
        };
        client = ip;
        if !is_trusted(ip) {
            break;
        }
    }
    client
}

/// Rate-limit key: the client address as resolved by [`client_ip_from`].
///
/// Replaces tower_governor's `SmartIpKeyExtractor`, which believes
/// X-Forwarded-For (and Forwarded / X-Real-IP) from ANY peer. With that,
/// a client sending a different forged address per request got a fresh
/// bucket every time, so no limiter, including the always-on OIDC one,
/// ever engaged. Forwarded headers are only honoured from `trusted_proxies`
/// here, exactly as for IP allowlists and audit logs.
#[derive(Clone)]
pub struct ClientIpKeyExtractor {
    trusted: Arc<Vec<IpNetwork>>,
}

impl ClientIpKeyExtractor {
    pub fn new(trusted_proxies: &[String]) -> Self {
        Self {
            trusted: Arc::new(parse_trusted_proxies(trusted_proxies)),
        }
    }
}

impl tower_governor::key_extractor::KeyExtractor for ClientIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(
        &self,
        req: &axum::http::Request<T>,
    ) -> Result<Self::Key, tower_governor::GovernorError> {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
            .ok_or(tower_governor::GovernorError::UnableToExtractKey)?;
        Ok(client_ip_from(req.headers(), peer, &self.trusted))
    }
}

/// Parse one X-Forwarded-For entry: a bare address, or one with a port
/// (`203.0.113.5:4711`, `[2001:db8::1]:4711`) as some proxies write it.
fn parse_forwarded_ip(raw: &[u8]) -> Option<IpAddr> {
    let s = std::str::from_utf8(raw).ok()?.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some(sa.ip());
    }
    s.strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .and_then(|r| r.parse::<IpAddr>().ok())
}

/// Every `name=value` pair in the request's cookies. HTTP/2 lets a client
/// split cookies over several `Cookie` headers (RFC 9113 8.2.3), and some
/// proxies pass them on unmerged, so all of them are read, not just the
/// first (#328).
pub fn cookie_pairs(headers: &axum::http::HeaderMap) -> impl Iterator<Item = (&str, &str)> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|cookies| cookies.split(';'))
        .filter_map(|c| {
            let (name, value) = c.trim().split_once('=')?;
            Some((name.trim(), value))
        })
}

/// The value of the cookie `name`, from any of the request's Cookie headers.
pub fn cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    cookie_pairs(headers)
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.to_string())
}

/// Extract session cookie value from the Cookie header.
fn extract_cookie(request: &Request, name: &str) -> Option<String> {
    cookie_value(request.headers(), name)
}

/// Axum middleware that validates either API key or session cookie.
/// On success, inserts `AuthIdentity` into request extensions.
pub async fn require_auth(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let db = request.extensions().get::<Db>().cloned();
    let db = match db {
        Some(db) => db,
        None => {
            return next.run(request).await;
        }
    };

    let trusted = request.extensions().get::<TrustedProxies>().cloned();
    let proxies = trusted.map(|t| t.0).unwrap_or_default();
    let ip = client_ip(request.headers(), addr.ip(), &proxies);
    let path = request.uri().path().to_string();

    // Path 1: API key from Authorization: Bearer <key> or X-API-Key: <key>
    let api_key = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| {
            request
                .headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
        })
        .map(|k| k.to_string());

    if let Some(key) = api_key {
        let validate_ip = Some(ip);
        let db_clone = db.clone();
        let key_clone = key.clone();
        let result = tokio::task::spawn_blocking(move || {
            db::validate_api_key(&db_clone, &key_clone, validate_ip)
        })
        .await
        .unwrap_or(Err(AuthError::InvalidKey));

        match result {
            Ok(admin) => {
                tracing::debug!(admin = %admin.name, "API key authenticated");
                let mut request = request;
                request
                    .extensions_mut()
                    .insert(AuthIdentity::ApiKey(admin.name));
                return next.run(request).await;
            }
            Err(AuthError::InvalidKey) => {
                // Not found in admins table — try user API tokens
                let db_clone = db.clone();
                let token_result = tokio::task::spawn_blocking(move || {
                    db::validate_user_token(&db_clone, &key).map(|(user, token_meta)| {
                        let id = user_identity(&db_clone, user, token_meta.max_role.as_deref());
                        (id, token_meta)
                    })
                })
                .await
                .unwrap_or(Err(AuthError::InvalidKey));

                match token_result {
                    Ok((identity, token_meta)) => {
                        tracing::debug!(email = %identity.display_name(), role = %identity.role(), token = %token_meta.name, "User token authenticated");
                        let mut request = request;
                        request.extensions_mut().insert(identity);
                        return next.run(request).await;
                    }
                    Err(_) => {
                        tracing::warn!(client_ip = %ip, "Authentication failed: invalid API key/token");
                        return (
                            StatusCode::UNAUTHORIZED,
                            axum::Json(json!({"error": "invalid API key or token"})),
                        )
                            .into_response();
                    }
                }
            }
            Err(e) => {
                tracing::warn!(client_ip = %ip, reason = %e, "Authentication failed");
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        }
    }

    // Path 2: Session cookie
    let session_token = extract_cookie(&request, "rustguac_session");
    if let Some(token) = session_token {
        let db_clone = db.clone();
        let result = tokio::task::spawn_blocking(move || {
            db::validate_auth_session(&db_clone, &token)
                .map(|user| user_identity(&db_clone, user, None))
        })
        .await
        .unwrap_or(Err(AuthError::InvalidSession));

        return match result {
            Ok(identity) => {
                tracing::debug!(email = %identity.display_name(), role = %identity.role(), "Session cookie authenticated");
                let mut request = request;
                request.extensions_mut().insert(identity);
                next.run(request).await
            }
            Err(_) => {
                tracing::warn!(client_ip = %ip, "Authentication failed: invalid session cookie");
                (
                    StatusCode::UNAUTHORIZED,
                    axum::Json(json!({"error": "invalid or expired session"})),
                )
                    .into_response()
            }
        };
    }

    // Neither API key nor cookie
    tracing::warn!(client_ip = %ip, path = %path, "Authentication failed: no credentials");
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({"error": "authentication required — use API key or sign in via SSO"})),
    )
        .into_response()
}

/// Optional auth middleware — identical to `require_auth` but passes through
/// silently when no credentials are present (no 401). Inserts `AuthIdentity`
/// into extensions on success.
/// Also checks for `key` query parameter as a fallback for API-key auth
/// (used by WebSocket connections from API-key users).
pub async fn optional_auth(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let db = request.extensions().get::<Db>().cloned();
    let db = match db {
        Some(db) => db,
        None => {
            return next.run(request).await;
        }
    };

    let trusted = request.extensions().get::<TrustedProxies>().cloned();
    let proxies = trusted.map(|t| t.0).unwrap_or_default();
    let ip = client_ip(request.headers(), addr.ip(), &proxies);

    // Path 1: API key from Authorization header
    let api_key = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| {
            request
                .headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
        })
        .map(|k| k.to_string());

    // Path 1b: Single-use WebSocket ticket from ?ticket= query parameter.
    // Tickets are created via POST /api/ws-ticket and consumed here.
    // This prevents API keys from appearing in WebSocket URLs.
    if let Some(ticket_store) = request.extensions().get::<WsTicketStore>().cloned() {
        let ticket_val = request.uri().query().and_then(|q| {
            q.split('&').find_map(|pair| {
                let (k, v) = pair.split_once('=')?;
                if k == "ticket" {
                    Some(v.split('?').next().unwrap_or(v).to_string())
                } else {
                    None
                }
            })
        });
        if let Some(ticket) = ticket_val {
            if let Some(identity) = ticket_store.consume(&ticket) {
                tracing::debug!("Optional auth: WebSocket ticket consumed");
                let mut request = request;
                request.extensions_mut().insert(identity);
                return next.run(request).await;
            }
            // Invalid/expired ticket — fall through to other auth methods
        }
    }

    // Path 1c: API key from ?key= query parameter (legacy fallback).
    // Guacamole.WebSocketTunnel appends "?" + connect_data to the URL, so
    // the raw query string may be "key=XXXX?GUAC_WIDTH=1024&...". Truncate
    // the value at the first '?' to strip the Guacamole suffix.
    let api_key = api_key.or_else(|| {
        request.uri().query().and_then(|q| {
            q.split('&').find_map(|pair| {
                let (k, v) = pair.split_once('=')?;
                if k == "key" {
                    Some(v.split('?').next().unwrap_or(v).to_string())
                } else {
                    None
                }
            })
        })
    });

    if let Some(key) = api_key {
        let validate_ip = Some(ip);
        let db_clone = db.clone();
        let key_clone = key.clone();
        let result = tokio::task::spawn_blocking(move || {
            db::validate_api_key(&db_clone, &key_clone, validate_ip)
        })
        .await
        .unwrap_or(Err(AuthError::InvalidKey));

        match result {
            Ok(admin) => {
                tracing::debug!(admin = %admin.name, "Optional auth: API key authenticated");
                let mut request = request;
                request
                    .extensions_mut()
                    .insert(AuthIdentity::ApiKey(admin.name));
                return next.run(request).await;
            }
            Err(AuthError::InvalidKey) => {
                // Not found in admins table — try user API tokens
                let db_clone = db.clone();
                let token_result = tokio::task::spawn_blocking(move || {
                    db::validate_user_token(&db_clone, &key).map(|(user, token_meta)| {
                        let id = user_identity(&db_clone, user, token_meta.max_role.as_deref());
                        (id, token_meta)
                    })
                })
                .await
                .unwrap_or(Err(AuthError::InvalidKey));

                match token_result {
                    Ok((identity, token_meta)) => {
                        tracing::debug!(email = %identity.display_name(), role = %identity.role(), token = %token_meta.name, "Optional auth: user token authenticated");
                        let mut request = request;
                        request.extensions_mut().insert(identity);
                        return next.run(request).await;
                    }
                    Err(_) => {
                        tracing::warn!(client_ip = %ip, "Authentication failed: invalid API key/token (optional auth)");
                        return next.run(request).await;
                    }
                }
            }
            Err(_) => {
                tracing::warn!(client_ip = %ip, "Authentication failed: API key disabled/expired (optional auth)");
                return next.run(request).await;
            }
        }
    }

    // Path 2: Session cookie
    let session_token = extract_cookie(&request, "rustguac_session");
    if let Some(token) = session_token {
        let db_clone = db.clone();
        let result = tokio::task::spawn_blocking(move || {
            db::validate_auth_session(&db_clone, &token)
                .map(|user| user_identity(&db_clone, user, None))
        })
        .await
        .unwrap_or(Err(AuthError::InvalidSession));

        return match result {
            Ok(identity) => {
                tracing::debug!(email = %identity.display_name(), role = %identity.role(), "Optional auth: session cookie authenticated");
                let mut request = request;
                request.extensions_mut().insert(identity);
                next.run(request).await
            }
            Err(_) => {
                tracing::warn!(client_ip = %ip, "Authentication failed: invalid session cookie (optional auth)");
                next.run(request).await
            }
        };
    }

    // No credentials — pass through without identity
    next.run(request).await
}

#[cfg(test)]
mod tests {
    #[test]
    fn cookies_are_read_from_every_cookie_header() {
        // #328: an HTTP/2 client or a proxy can split cookies over several
        // Cookie headers; the one we want may be in any of them.
        let mut h = axum::http::HeaderMap::new();
        h.append(
            axum::http::header::COOKIE,
            "theme=dark; a=1".parse().unwrap(),
        );
        h.append(
            axum::http::header::COOKIE,
            "rustguac_oidc_state=abc; rustguac_session=xyz"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            super::cookie_value(&h, "rustguac_oidc_state").as_deref(),
            Some("abc")
        );
        assert_eq!(
            super::cookie_value(&h, "rustguac_session").as_deref(),
            Some("xyz")
        );
        assert_eq!(super::cookie_value(&h, "a").as_deref(), Some("1"));
        // A name that is a prefix of another is not confused with it.
        assert_eq!(super::cookie_value(&h, "rustguac"), None);
        assert_eq!(super::cookie_value(&h, "missing"), None);
        let names: Vec<_> = super::cookie_pairs(&h).map(|(n, _)| n).collect();
        assert_eq!(
            names,
            ["theme", "a", "rustguac_oidc_state", "rustguac_session"]
        );
    }

    use super::*;

    #[test]
    fn test_role_level_hierarchy() {
        assert_eq!(role_level("admin"), 4);
        assert_eq!(role_level("poweruser"), 3);
        assert_eq!(role_level("operator"), 2);
        assert_eq!(role_level("viewer"), 1);
        assert_eq!(role_level("unknown"), 0);
        assert_eq!(role_level(""), 0);
    }

    #[test]
    fn test_role_level_ordering() {
        assert!(role_level("admin") > role_level("poweruser"));
        assert!(role_level("poweruser") > role_level("operator"));
        assert!(role_level("operator") > role_level("viewer"));
        assert!(role_level("viewer") > role_level("garbage"));
    }

    #[test]
    fn test_compute_effective_role_no_cap() {
        assert_eq!(compute_effective_role("admin", &None), "admin");
        assert_eq!(compute_effective_role("viewer", &None), "viewer");
    }

    #[test]
    fn test_compute_effective_role_capped() {
        let cap = Some("operator".into());
        assert_eq!(compute_effective_role("admin", &cap), "operator");
        assert_eq!(compute_effective_role("poweruser", &cap), "operator");
    }

    #[test]
    fn test_compute_effective_role_cap_higher_than_user() {
        let cap = Some("admin".into());
        assert_eq!(compute_effective_role("viewer", &cap), "viewer");
        assert_eq!(compute_effective_role("operator", &cap), "operator");
    }

    #[test]
    fn test_compute_effective_role_same_level() {
        let cap = Some("operator".into());
        assert_eq!(compute_effective_role("operator", &cap), "operator");
    }

    #[test]
    fn test_client_ip_no_proxies() {
        let headers = HeaderMap::new();
        let ip = client_ip(&headers, "10.0.0.1".parse().unwrap(), &[]);
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn test_client_ip_xff_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.50, 10.0.0.1".parse().unwrap());
        let proxies = vec!["10.0.0.0/8".into()];
        let ip = client_ip(&headers, "10.0.0.1".parse().unwrap(), &proxies);
        assert_eq!(ip.to_string(), "203.0.113.50");
    }

    #[test]
    fn test_client_ip_xff_untrusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.50".parse().unwrap());
        let proxies = vec!["10.0.0.0/8".into()];
        // Socket is NOT in trusted range
        let ip = client_ip(&headers, "192.168.1.1".parse().unwrap(), &proxies);
        assert_eq!(ip.to_string(), "192.168.1.1");
    }

    fn xff(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for v in values {
            headers.append("x-forwarded-for", v.parse().unwrap());
        }
        headers
    }

    /// H2: behind a proxy that appends (nginx `$proxy_add_x_forwarded_for`),
    /// a client-supplied left entry must not be believed.
    #[test]
    fn test_client_ip_ignores_forged_left_entry() {
        let proxies = vec!["10.0.0.0/8".into()];
        // Client 198.51.100.7 sent "X-Forwarded-For: 192.168.1.10"; nginx
        // appended the real peer.
        let headers = xff(&["192.168.1.10, 198.51.100.7"]);
        let ip = client_ip(&headers, "10.0.0.1".parse().unwrap(), &proxies);
        assert_eq!(ip.to_string(), "198.51.100.7");
    }

    #[test]
    fn test_client_ip_walks_through_proxy_chain() {
        let proxies = vec!["10.0.0.0/8".into()];
        let headers = xff(&["1.1.1.1, 203.0.113.50, 10.0.0.9, 10.0.0.8"]);
        let ip = client_ip(&headers, "10.0.0.1".parse().unwrap(), &proxies);
        assert_eq!(ip.to_string(), "203.0.113.50");
    }

    #[test]
    fn test_client_ip_reads_every_header_line() {
        // A proxy that adds its own line rather than appending.
        let proxies = vec!["10.0.0.0/8".into()];
        let headers = xff(&["192.168.1.10", "198.51.100.7"]);
        let ip = client_ip(&headers, "10.0.0.1".parse().unwrap(), &proxies);
        assert_eq!(ip.to_string(), "198.51.100.7");
    }

    #[test]
    fn test_client_ip_non_utf8_left_entry_does_not_hide_peer() {
        let proxies = vec!["10.0.0.0/8".into()];
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            axum::http::HeaderValue::from_bytes(b"\xff\xfe, 198.51.100.7").unwrap(),
        );
        let ip = client_ip(&headers, "10.0.0.1".parse().unwrap(), &proxies);
        assert_eq!(ip.to_string(), "198.51.100.7");
    }

    #[test]
    fn test_client_ip_entry_with_port() {
        let proxies = vec!["10.0.0.0/8".into()];
        let ip = client_ip(
            &xff(&["198.51.100.7:4711"]),
            "10.0.0.1".parse().unwrap(),
            &proxies,
        );
        assert_eq!(ip.to_string(), "198.51.100.7");
        let ip = client_ip(
            &xff(&["[2001:db8::1]:4711"]),
            "10.0.0.1".parse().unwrap(),
            &proxies,
        );
        assert_eq!(ip.to_string(), "2001:db8::1");
    }

    #[test]
    fn test_client_ip_all_hops_trusted_returns_leftmost() {
        let proxies = vec!["10.0.0.0/8".into()];
        let ip = client_ip(
            &xff(&["10.1.2.3, 10.0.0.9"]),
            "10.0.0.1".parse().unwrap(),
            &proxies,
        );
        assert_eq!(ip.to_string(), "10.1.2.3");
    }

    #[test]
    fn test_client_ip_xff_invalid_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        let proxies = vec!["10.0.0.0/8".into()];
        let ip = client_ip(&headers, "10.0.0.1".parse().unwrap(), &proxies);
        // Falls back to socket addr when XFF can't be parsed
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn identities_hold_their_roles_permissions() {
        use crate::perms::Perm;
        let admin = AuthIdentity::ApiKey("admin".into());
        assert!(admin.has_perm(Perm::DocsView));
        assert!(admin.has_perm(Perm::AdminRoles));

        let viewer = AuthIdentity::User {
            email: "test@test.com".into(),
            role: "viewer".into(),
            groups: vec![],
            roles: vec!["viewer".to_string()],
            perms: crate::perms::role_perms("viewer"),
        };
        assert!(viewer.has_perm(Perm::DocsView));
        assert!(!viewer.has_perm(Perm::ConnectionsConnect));
        assert!(!viewer.has_perm(Perm::AdminRoles));

        let unknown = AuthIdentity::User {
            email: "test@test.com".into(),
            role: "someday-custom".into(),
            groups: vec![],
            roles: vec!["someday-custom".to_string()],
            perms: crate::perms::role_perms("someday-custom"),
        };
        assert_eq!(unknown.permissions(), crate::perms::PermSet::EMPTY);
    }
}
