//! Authentication middleware — supports API key and OIDC session cookie.

use crate::db::{self, AuthError, Db};
use axum::{
    extract::{ConnectInfo, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use ipnetwork::IpNetwork;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};

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
        role: String,
        groups: Vec<String>,
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
    pub fn groups(&self) -> &[String] {
        match self {
            AuthIdentity::ApiKey(_) => &[],
            AuthIdentity::User { groups, .. } => groups,
        }
    }

    /// Check if identity has at least the given role level.
    /// admin > poweruser > operator > viewer
    pub fn has_role(&self, min_role: &str) -> bool {
        role_level(self.role()) >= role_level(min_role)
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
    if !trusted_proxies.is_empty() {
        let networks: Vec<IpNetwork> = trusted_proxies
            .iter()
            .filter_map(|s| s.parse::<IpNetwork>().ok())
            .collect();

        if networks.iter().any(|net| net.contains(socket_addr)) {
            if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
                // First IP in X-Forwarded-For is the original client
                if let Some(first) = xff.split(',').next() {
                    if let Ok(ip) = first.trim().parse::<IpAddr>() {
                        return ip;
                    }
                }
            }
        }
    }
    socket_addr
}

/// Extract session cookie value from the Cookie header.
fn extract_cookie(request: &Request, name: &str) -> Option<String> {
    request
        .headers()
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
                let token_result =
                    tokio::task::spawn_blocking(move || db::validate_user_token(&db_clone, &key))
                        .await
                        .unwrap_or(Err(AuthError::InvalidKey));

                match token_result {
                    Ok((user, token_meta)) => {
                        let effective_role =
                            compute_effective_role(&user.role, &token_meta.max_role);
                        tracing::debug!(email = %user.email, role = %effective_role, token = %token_meta.name, "User token authenticated");
                        let groups = user.groups_vec();
                        let mut request = request;
                        request.extensions_mut().insert(AuthIdentity::User {
                            email: user.email,
                            role: effective_role,
                            groups,
                        });
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
        let result =
            tokio::task::spawn_blocking(move || db::validate_auth_session(&db_clone, &token))
                .await
                .unwrap_or(Err(AuthError::InvalidSession));

        return match result {
            Ok(user) => {
                tracing::debug!(email = %user.email, role = %user.role, "Session cookie authenticated");
                let groups = user.groups_vec();
                let mut request = request;
                request.extensions_mut().insert(AuthIdentity::User {
                    email: user.email,
                    role: user.role,
                    groups,
                });
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

    // Path 1b: API key from ?key= query parameter (fallback for WebSocket).
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
                let token_result =
                    tokio::task::spawn_blocking(move || db::validate_user_token(&db_clone, &key))
                        .await
                        .unwrap_or(Err(AuthError::InvalidKey));

                match token_result {
                    Ok((user, token_meta)) => {
                        let effective_role =
                            compute_effective_role(&user.role, &token_meta.max_role);
                        tracing::debug!(email = %user.email, role = %effective_role, token = %token_meta.name, "Optional auth: user token authenticated");
                        let groups = user.groups_vec();
                        let mut request = request;
                        request.extensions_mut().insert(AuthIdentity::User {
                            email: user.email,
                            role: effective_role,
                            groups,
                        });
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
        let result =
            tokio::task::spawn_blocking(move || db::validate_auth_session(&db_clone, &token))
                .await
                .unwrap_or(Err(AuthError::InvalidSession));

        return match result {
            Ok(user) => {
                tracing::debug!(email = %user.email, role = %user.role, "Optional auth: session cookie authenticated");
                let groups = user.groups_vec();
                let mut request = request;
                request.extensions_mut().insert(AuthIdentity::User {
                    email: user.email,
                    role: user.role,
                    groups,
                });
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
    fn test_has_role() {
        let admin = AuthIdentity::ApiKey("admin".into());
        assert!(admin.has_role("viewer"));
        assert!(admin.has_role("admin"));

        let viewer = AuthIdentity::User {
            email: "test@test.com".into(),
            role: "viewer".into(),
            groups: vec![],
        };
        assert!(viewer.has_role("viewer"));
        assert!(!viewer.has_role("operator"));
        assert!(!viewer.has_role("admin"));
    }
}
