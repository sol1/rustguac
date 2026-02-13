//! REST API routes.

use crate::auth::{client_ip, role_level, AuthIdentity, TrustedProxies};
use crate::db::{self, Db};
use crate::session::{CreateSessionRequest, SessionManager, SessionType};
use crate::vault::{AddressBookEntry, FolderConfig, VaultClient, VaultError};
use axum::{
    body::Body,
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

pub type AppState = Arc<SessionManager>;

/// POST /api/sessions — Create a new session. Requires operator+.
pub async fn create_session(
    State(manager): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Json(req): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    let identity = identity.map(|Extension(id)| id);
    let admin_name = identity
        .as_ref()
        .map(|id| id.display_name().to_string())
        .unwrap_or_else(|| "unknown".into());

    // Require poweruser+ role for ad-hoc session creation
    if let Some(ref id) = identity {
        if !id.has_role("poweruser") {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "insufficient permissions — poweruser role required for ad-hoc sessions"})),
            )
                .into_response();
        }
    }

    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let client_ip = client_ip(&headers, addr.ip(), &proxies);

    let target = match req.session_type {
        crate::session::SessionType::Ssh => {
            format!(
                "{}:{}",
                req.hostname.as_deref().unwrap_or("?"),
                req.port.unwrap_or(22)
            )
        }
        crate::session::SessionType::Rdp => {
            format!(
                "{}:{}",
                req.hostname.as_deref().unwrap_or("?"),
                req.port.unwrap_or(3389)
            )
        }
        crate::session::SessionType::Vnc => {
            format!(
                "{}:{}",
                req.hostname.as_deref().unwrap_or("?"),
                req.port.unwrap_or(5900)
            )
        }
        crate::session::SessionType::Web => req.url.as_deref().unwrap_or("?").to_string(),
    };

    tracing::info!(
        admin = %admin_name,
        client_ip = %client_ip,
        session_type = ?req.session_type,
        target = %target,
        "Session creation requested"
    );

    match manager.create_session(req, admin_name.clone()).await {
        Ok(info) => {
            tracing::info!(
                admin = %admin_name,
                client_ip = %client_ip,
                session_id = %info.session_id,
                session_type = ?info.session_type,
                target = %target,
                "Session created successfully"
            );
            (StatusCode::CREATED, Json(json!(info))).into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            tracing::error!(
                admin = %admin_name,
                client_ip = %client_ip,
                target = %target,
                error = %msg,
                "Session creation failed"
            );
            let status = match &e {
                crate::session::SessionError::ValidationError(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::BAD_GATEWAY,
            };
            (status, Json(json!({ "error": msg }))).into_response()
        }
    }
}

/// GET /api/sessions — List all sessions. All authenticated roles.
pub async fn list_sessions(State(manager): State<AppState>) -> impl IntoResponse {
    let sessions = manager.list_sessions().await;
    Json(json!(sessions))
}

/// GET /api/sessions/:id — Get session info. All authenticated roles.
pub async fn get_session(
    State(manager): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match manager.get_session(id).await {
        Some(info) => (StatusCode::OK, Json(json!(info))).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "session not found" })),
        )
            .into_response(),
    }
}

/// DELETE /api/sessions/:id — Terminate a session.
/// Admins can delete any session. Operators can only delete their own sessions.
pub async fn delete_session(
    State(manager): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let ip = client_ip(&headers, addr.ip(), &proxies);

    let id_inner = match identity {
        Some(Extension(ref id_inner)) => id_inner,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "authentication required"})),
            )
                .into_response();
        }
    };

    if !id_inner.has_role("operator") {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "insufficient permissions — operator role required"})),
        )
            .into_response();
    }

    // Operators can only delete their own sessions; admins can delete any
    if !id_inner.has_role("admin") {
        if let Some(creator) = manager.get_session_creator(id).await {
            if creator != id_inner.display_name() {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "you can only delete your own sessions"})),
                )
                    .into_response();
            }
        }
    }

    if manager.delete_session(id).await {
        tracing::info!(
            session_id = %id,
            identity = %id_inner.display_name(),
            client_ip = %ip,
            "Session deleted"
        );
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "session not found" })),
        )
            .into_response()
    }
}

/// GET /api/health — Health check.
pub async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// GET /api/auth/status — Returns whether OIDC is enabled. No auth required.
pub async fn auth_status(
    Extension(oidc_enabled): Extension<OidcEnabled>,
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
) -> impl IntoResponse {
    let mut resp = json!({ "oidc_enabled": oidc_enabled.0, "site_title": site_title.0 });
    if let Some(ref t) = theme.0 {
        if let Ok(v) = serde_json::to_value(t) {
            resp["theme"] = v;
        }
    }
    Json(resp)
}

/// Site title from config, shared via Extension.
#[derive(Clone)]
pub struct SiteTitle(pub String);

/// Theme configuration from config, shared via Extension.
#[derive(Clone)]
pub struct ThemeData(pub Option<crate::config::ThemeConfig>);

/// Marker for whether OIDC is configured.
#[derive(Clone)]
pub struct OidcEnabled(pub bool);

/// Marker for whether Vault is configured (has [vault] in config).
/// Distinct from VaultState which tracks whether it's currently connected.
#[derive(Clone)]
pub struct VaultConfigured(pub bool);

/// GET /api/recordings — List all recording files. All authenticated roles.
pub async fn list_recordings(State(manager): State<AppState>) -> impl IntoResponse {
    let recording_path = manager.recording_path().to_path_buf();

    match tokio::task::spawn_blocking(move || {
        let mut recordings = Vec::new();
        let entries = match std::fs::read_dir(&recording_path) {
            Ok(e) => e,
            Err(_) => return recordings,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("guac") {
                continue;
            }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            let meta = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let modified = meta
                .modified()
                .ok()
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Utc> = t.into();
                    dt.to_rfc3339()
                })
                .unwrap_or_default();
            recordings.push(json!({
                "name": name,
                "size_bytes": meta.len(),
                "modified": modified,
            }));
        }
        recordings.sort_by(|a, b| {
            let ma = a["modified"].as_str().unwrap_or("");
            let mb = b["modified"].as_str().unwrap_or("");
            mb.cmp(ma)
        });
        recordings
    })
    .await
    {
        Ok(recordings) => Json(json!(recordings)).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to list recordings"})),
        )
            .into_response(),
    }
}

/// GET /api/recordings/{name} — Serve a .guac recording file.
pub async fn serve_recording(
    State(manager): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if !is_safe_recording_name(&name, manager.recording_path()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid recording name"})),
        )
            .into_response();
    }

    let path = manager.recording_path().join(&name);

    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "recording not found"})),
            )
                .into_response();
        }
    };

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    axum::response::Response::builder()
        .header("content-type", "application/octet-stream")
        .header(
            "content-disposition",
            format!("inline; filename=\"{}\"", name),
        )
        .body(body)
        .unwrap()
        .into_response()
}

/// DELETE /api/recordings/{name} — Delete a recording file. Requires admin.
pub async fn delete_recording(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if let Some(Extension(ref id)) = identity {
        if !id.has_role("admin") {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "insufficient permissions — admin role required"})),
            )
                .into_response();
        }
    }

    if !is_safe_recording_name(&name, manager.recording_path()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid recording name"})),
        )
            .into_response();
    }

    let path = manager.recording_path().join(&name);

    match tokio::fs::remove_file(&path).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "recording not found"})),
        )
            .into_response(),
    }
}

/// Validate a recording filename: must end in .guac, no path separators,
/// and the resolved path must stay within the recording directory.
fn is_safe_recording_name(name: &str, recording_dir: &std::path::Path) -> bool {
    if !name.ends_with(".guac") || name.contains('/') || name.contains('\\') || name.contains("..")
    {
        return false;
    }
    // Belt-and-suspenders: verify canonical path is within recording dir
    let full = recording_dir.join(name);
    match (full.canonicalize(), recording_dir.canonicalize()) {
        (Ok(resolved), Ok(base)) => resolved.starts_with(&base),
        _ => true, // file may not exist yet; string checks above are sufficient
    }
}

// ── User management endpoints (admin only) ──

/// GET /api/users — List all OIDC users. Admin only.
pub async fn list_users(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> impl IntoResponse {
    if let Some(Extension(ref id)) = identity {
        if !id.has_role("admin") {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response();
        }
    }

    let db_clone = database.clone();
    match tokio::task::spawn_blocking(move || db::list_users(&db_clone)).await {
        Ok(Ok(users)) => Json(json!(users)).into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to list users"})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct SetRoleRequest {
    pub role: String,
}

/// PUT /api/users/{email}/role — Set user role. Admin only.
pub async fn set_user_role(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(email): Path<String>,
    Json(req): Json<SetRoleRequest>,
) -> impl IntoResponse {
    if let Some(Extension(ref id)) = identity {
        if !id.has_role("admin") {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response();
        }
    }

    if !["admin", "poweruser", "operator", "viewer"].contains(&req.role.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "role must be admin, poweruser, operator, or viewer"})),
        )
            .into_response();
    }

    let db_clone = database.clone();
    let role = req.role.clone();
    match tokio::task::spawn_blocking(move || db::set_user_role(&db_clone, &email, &role)).await {
        Ok(Ok(true)) => Json(json!({"ok": true})).into_response(),
        Ok(Ok(false)) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "user not found"})),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to set role"})),
        )
            .into_response(),
    }
}

/// DELETE /api/users/{email} — Delete user. Admin only.
pub async fn delete_user(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(email): Path<String>,
) -> impl IntoResponse {
    if let Some(Extension(ref id)) = identity {
        if !id.has_role("admin") {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response();
        }
    }

    let db_clone = database.clone();
    match tokio::task::spawn_blocking(move || db::delete_user(&db_clone, &email)).await {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "user not found"})),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to delete user"})),
        )
            .into_response(),
    }
}

/// DELETE /api/users/{email}/sessions — Force-logout a user by deleting all their sessions. Admin only.
pub async fn delete_user_sessions(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(email): Path<String>,
) -> impl IntoResponse {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response();
    }

    let db_clone = database.clone();
    let email_clone = email.clone();
    let user =
        match tokio::task::spawn_blocking(move || db::get_user_by_email(&db_clone, &email_clone))
            .await
        {
            Ok(Ok(user)) => user,
            _ => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "user not found"})),
                )
                    .into_response()
            }
        };

    let db_clone = database.clone();
    let user_id = user.id;
    match tokio::task::spawn_blocking(move || db::delete_user_sessions(&db_clone, user_id)).await {
        Ok(Ok(count)) => {
            tracing::info!(email = %email, sessions_revoked = count, "Admin force-logout user");
            Json(json!({"ok": true, "sessions_revoked": count})).into_response()
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to delete sessions"})),
        )
            .into_response(),
    }
}

/// GET /api/me — Return current user identity and role.
pub async fn me(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Extension(vault_configured): Extension<VaultConfigured>,
) -> impl IntoResponse {
    match identity {
        Some(Extension(id)) => {
            let vault_available = vault.read().await.is_some();
            Json(json!({
                "name": id.display_name(),
                "role": id.role(),
                "groups": id.groups(),
                "vault_enabled": vault_available,
                "vault_configured": vault_configured.0,
            }))
            .into_response()
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "not authenticated"})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct BannerQuery {
    pub token: String,
}

/// GET /api/sessions/:id/banner?token=... — Get session banner (unauthenticated, requires share token).
pub async fn get_session_banner(
    State(manager): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<BannerQuery>,
) -> impl IntoResponse {
    if !manager.validate_share_token(id, &query.token).await {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "invalid share token"})),
        )
            .into_response();
    }

    match manager.get_session(id).await {
        Some(info) => Json(json!({ "banner": info.banner })).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "session not found"})),
        )
            .into_response(),
    }
}

// ── User disable/enable endpoints (admin only) ──

/// POST /api/users/{email}/disable — Disable a user. Admin only.
pub async fn disable_user(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(email): Path<String>,
) -> impl IntoResponse {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response();
    }

    let db_clone = database.clone();
    match tokio::task::spawn_blocking(move || db::disable_user(&db_clone, &email)).await {
        Ok(Ok(true)) => Json(json!({"ok": true})).into_response(),
        Ok(Ok(false)) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "user not found"})),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to disable user"})),
        )
            .into_response(),
    }
}

/// POST /api/users/{email}/enable — Enable a user. Admin only.
pub async fn enable_user(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(email): Path<String>,
) -> impl IntoResponse {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response();
    }

    let db_clone = database.clone();
    match tokio::task::spawn_blocking(move || db::enable_user(&db_clone, &email)).await {
        Ok(Ok(true)) => Json(json!({"ok": true})).into_response(),
        Ok(Ok(false)) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "user not found"})),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to enable user"})),
        )
            .into_response(),
    }
}

// ── Group-to-role mapping endpoints (admin only) ──

#[derive(Deserialize)]
pub struct CreateGroupMappingRequest {
    pub group: String,
    pub role: String,
}

/// GET /api/admin/group-mappings — List all group-to-role mappings. Admin only.
pub async fn list_group_mappings(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> impl IntoResponse {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response();
    }

    let db_clone = database.clone();
    match tokio::task::spawn_blocking(move || db::list_group_mappings(&db_clone)).await {
        Ok(Ok(mappings)) => Json(json!(mappings)).into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to list mappings"})),
        )
            .into_response(),
    }
}

/// POST /api/admin/group-mappings — Create a group-to-role mapping. Admin only.
pub async fn create_group_mapping(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Json(req): Json<CreateGroupMappingRequest>,
) -> impl IntoResponse {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response();
    }

    if !["admin", "poweruser", "operator", "viewer"].contains(&req.role.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "role must be admin, poweruser, operator, or viewer"})),
        )
            .into_response();
    }

    let db_clone = database.clone();
    match tokio::task::spawn_blocking(move || {
        db::create_group_mapping(&db_clone, &req.group, &req.role)
    })
    .await
    {
        Ok(Ok(mapping)) => (StatusCode::CREATED, Json(json!(mapping))).into_response(),
        Ok(Err(e)) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE") {
                (
                    StatusCode::CONFLICT,
                    Json(json!({"error": "mapping for this group already exists"})),
                )
                    .into_response()
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": msg})),
                )
                    .into_response()
            }
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to create mapping"})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpdateGroupMappingRequest {
    pub group: String,
    pub role: String,
}

/// PUT /api/admin/group-mappings/{id} — Update a group-to-role mapping. Admin only.
pub async fn update_group_mapping(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateGroupMappingRequest>,
) -> impl IntoResponse {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response();
    }

    if !["admin", "poweruser", "operator", "viewer"].contains(&req.role.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "role must be admin, poweruser, operator, or viewer"})),
        )
            .into_response();
    }

    let db_clone = database.clone();
    match tokio::task::spawn_blocking(move || {
        db::update_group_mapping(&db_clone, id, &req.group, &req.role)
    })
    .await
    {
        Ok(Ok(true)) => Json(json!({"ok": true})).into_response(),
        Ok(Ok(false)) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "mapping not found"})),
        )
            .into_response(),
        Ok(Err(e)) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE") {
                (
                    StatusCode::CONFLICT,
                    Json(json!({"error": "mapping for this group already exists"})),
                )
                    .into_response()
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": msg})),
                )
                    .into_response()
            }
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to update mapping"})),
        )
            .into_response(),
    }
}

/// DELETE /api/admin/group-mappings/{id} — Delete a group-to-role mapping. Admin only.
pub async fn delete_group_mapping(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response();
    }

    let db_clone = database.clone();
    match tokio::task::spawn_blocking(move || db::delete_group_mapping(&db_clone, id)).await {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "mapping not found"})),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to delete mapping"})),
        )
            .into_response(),
    }
}

// ── Address Book endpoints (Vault-backed) ──

pub type VaultState = Arc<tokio::sync::RwLock<Option<Arc<VaultClient>>>>;

// ── Docs endpoint ──

include!(concat!(env!("OUT_DIR"), "/docs-rendered.rs"));

/// GET /api/docs — Return rendered documentation sections. No auth required.
pub async fn get_docs() -> impl IntoResponse {
    let sections: Vec<serde_json::Value> = DOCS
        .iter()
        .map(|(slug, title, html)| json!({ "slug": slug, "title": title, "html": html }))
        .collect();
    Json(json!(sections))
}

/// Helper: require Vault to be available, or return an appropriate error.
async fn require_vault(vault: &VaultState) -> Result<Arc<VaultClient>, Response> {
    let guard = vault.read().await;
    guard.clone().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Vault is not available — address book is temporarily offline"})),
        )
            .into_response()
    })
}

/// Helper: check if the identity has group access to a folder.
async fn check_folder_access(
    vault: &VaultClient,
    scope: &str,
    folder: &str,
    identity: &AuthIdentity,
) -> Result<(), Response> {
    // Admins bypass group checks
    if identity.has_role("admin") {
        return Ok(());
    }

    let config = vault
        .get_folder_config(scope, folder)
        .await
        .map_err(|e| match e {
            VaultError::NotFound => (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "folder not found"})),
            )
                .into_response(),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
        })?;

    let user_groups = identity.groups();
    if config
        .allowed_groups
        .iter()
        .any(|g| user_groups.iter().any(|ug| ug == g))
    {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "no access to this folder"})),
        )
            .into_response())
    }
}

/// GET /api/addressbook/folders — List folders visible to the current user.
pub async fn ab_list_folders(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
) -> impl IntoResponse {
    let vault = match require_vault(&vault).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id,
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "operator role required"})),
            )
                .into_response()
        }
    };

    let folders = match vault.list_folders().await {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    // Filter by group access (admins see all)
    let mut visible = Vec::new();
    for folder in folders {
        if id.has_role("admin") {
            visible.push(folder);
            continue;
        }
        if let Ok(config) = vault.get_folder_config(&folder.scope, &folder.name).await {
            let user_groups = id.groups();
            if config
                .allowed_groups
                .iter()
                .any(|g| user_groups.iter().any(|ug| ug == g))
            {
                visible.push(folder);
            }
        }
    }

    Json(json!(visible)).into_response()
}

/// GET /api/addressbook/folders/:scope/:folder/entries — List entries in a folder.
pub async fn ab_list_entries(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
) -> impl IntoResponse {
    let vault = match require_vault(&vault).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id,
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "operator role required"})),
            )
                .into_response()
        }
    };

    if let Err(resp) = check_folder_access(&vault, &scope, &folder, id).await {
        return resp;
    }

    let entry_names = match vault.list_entries(&scope, &folder).await {
        Ok(e) => e,
        Err(VaultError::NotFound) => Vec::new(),
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    // Fetch each entry and strip credentials
    let mut entries = Vec::new();
    for name in &entry_names {
        if let Ok(entry) = vault.get_entry(&scope, &folder, name).await {
            entries.push(crate::vault::EntryInfo::from((name.as_str(), &entry)));
        }
    }

    Json(json!(entries)).into_response()
}

#[derive(Deserialize)]
pub struct ConnectRequest {
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub dpi: Option<u32>,
    #[serde(default)]
    pub banner: Option<String>,
    /// Override or supply credentials at connect time (never stored).
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
}

/// POST /api/addressbook/folders/:scope/:folder/entries/:entry/connect — Create session from entry.
#[allow(clippy::too_many_arguments)]
pub async fn ab_connect_entry(
    State(manager): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder, entry)): Path<(String, String, String)>,
    Json(req): Json<ConnectRequest>,
) -> impl IntoResponse {
    let vault = match require_vault(&vault).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id.clone(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "operator role required"})),
            )
                .into_response()
        }
    };

    if let Err(resp) = check_folder_access(&vault, &scope, &folder, &id).await {
        return resp;
    }

    // Read full entry (with credentials) from Vault
    let ab_entry = match vault.get_entry(&scope, &folder, &entry).await {
        Ok(e) => e,
        Err(VaultError::NotFound) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "entry not found"})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    // Map address book entry type to SessionType
    let session_type = match ab_entry.session_type.as_str() {
        "ssh" => SessionType::Ssh,
        "rdp" => SessionType::Rdp,
        "vnc" => SessionType::Vnc,
        "web" => SessionType::Web,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("unknown session type: {}", other)})),
            )
                .into_response()
        }
    };

    // Build CreateSessionRequest from the Vault entry + connect request display params.
    // ConnectRequest credentials override address book values (for prompted credentials).
    let ab_entry_key = format!("{}/{}/{}", scope, folder, entry);
    let create_req = CreateSessionRequest {
        session_type,
        hostname: ab_entry.hostname,
        port: ab_entry.port,
        username: req.username.or(ab_entry.username),
        password: req.password.or(ab_entry.password),
        private_key: ab_entry.private_key,
        generate_keypair: None,
        url: ab_entry.url,
        domain: req.domain.or(ab_entry.domain),
        security: ab_entry.security,
        ignore_cert: ab_entry.ignore_cert,
        auth_pkg: ab_entry.auth_pkg,
        kdc_url: ab_entry.kdc_url,
        kerberos_cache: None,
        color_depth: ab_entry.color_depth,
        jump_hosts: ab_entry.jump_hosts,
        jump_host: None,
        jump_port: None,
        jump_username: None,
        jump_password: None,
        jump_private_key: None,
        width: req.width,
        height: req.height,
        dpi: req.dpi,
        banner: req.banner.or(ab_entry.display_name),
        enable_drive: ab_entry.enable_drive,
        remote_app: ab_entry.remote_app,
        remote_app_dir: ab_entry.remote_app_dir,
        remote_app_args: ab_entry.remote_app_args,
        enable_recording: ab_entry.enable_recording,
        address_book_entry: Some(ab_entry_key),
        max_recordings: ab_entry.max_recordings,
    };

    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let client_ip_addr = client_ip(&headers, addr.ip(), &proxies);
    let admin_name = id.display_name().to_string();

    tracing::info!(
        user = %admin_name,
        client_ip = %client_ip_addr,
        folder = %folder,
        entry = %entry,
        scope = %scope,
        "Address book connect requested"
    );

    match manager.create_session(create_req, admin_name.clone()).await {
        Ok(info) => {
            tracing::info!(
                user = %admin_name,
                session_id = %info.session_id,
                "Address book session created"
            );
            (StatusCode::CREATED, Json(json!(info))).into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            tracing::error!(user = %admin_name, error = %msg, "Address book session creation failed");
            let status = match &e {
                crate::session::SessionError::ValidationError(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::BAD_GATEWAY,
            };
            (status, Json(json!({"error": msg}))).into_response()
        }
    }
}

// ── Admin-only address book management ──

#[derive(Deserialize)]
pub struct CreateFolderRequest {
    pub name: String,
    pub allowed_groups: Vec<String>,
    #[serde(default)]
    pub description: String,
    /// "shared" or "instance" (default: "shared")
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_scope() -> String {
    "shared".into()
}

/// POST /api/addressbook/folders — Create a new folder. Admin only.
pub async fn ab_create_folder(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Json(req): Json<CreateFolderRequest>,
) -> impl IntoResponse {
    let vault = match require_vault(&vault).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response();
    }

    let config = FolderConfig {
        allowed_groups: req.allowed_groups,
        description: req.description,
    };

    match vault
        .put_folder_config(&req.scope, &req.name, &config)
        .await
    {
        Ok(()) => (StatusCode::CREATED, Json(json!({"ok": true}))).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpdateFolderRequest {
    pub allowed_groups: Vec<String>,
    #[serde(default)]
    pub description: String,
}

/// PUT /api/addressbook/folders/:scope/:folder — Update folder config. Admin only.
pub async fn ab_update_folder(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
    Json(req): Json<UpdateFolderRequest>,
) -> impl IntoResponse {
    let vault = match require_vault(&vault).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response();
    }

    let config = FolderConfig {
        allowed_groups: req.allowed_groups,
        description: req.description,
    };

    match vault.put_folder_config(&scope, &folder, &config).await {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// DELETE /api/addressbook/folders/:scope/:folder — Delete folder and all entries. Admin only.
pub async fn ab_delete_folder(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
) -> impl IntoResponse {
    let vault = match require_vault(&vault).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response();
    }

    match vault.delete_folder(&scope, &folder).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct CreateEntryRequest {
    pub name: String,
    #[serde(flatten)]
    pub entry: AddressBookEntry,
}

/// POST /api/addressbook/folders/:scope/:folder/entries — Create/update an entry. Admin only.
pub async fn ab_create_entry(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
    Json(req): Json<CreateEntryRequest>,
) -> impl IntoResponse {
    let vault = match require_vault(&vault).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response();
    }

    match vault
        .put_entry(&scope, &folder, &req.name, &req.entry)
        .await
    {
        Ok(()) => (StatusCode::CREATED, Json(json!({"ok": true}))).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// PUT /api/addressbook/folders/:scope/:folder/entries/:entry — Update an entry. Admin only.
/// Performs a read-modify-write: reads the existing entry from Vault first, then merges
/// incoming fields on top. This preserves credentials (password, private_key) that the
/// frontend deliberately omits from edit forms.
pub async fn ab_update_entry(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder, entry)): Path<(String, String, String)>,
    Json(data): Json<AddressBookEntry>,
) -> impl IntoResponse {
    let vault = match require_vault(&vault).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response();
    }

    // Read existing entry to preserve credentials the frontend never sends back
    let merged = match vault.get_entry(&scope, &folder, &entry).await {
        Ok(existing) => {
            // Per-hop credential merge: for each hop in the new data, if credentials
            // are None and the same-index hop exists in the old data, preserve them.
            let merged_jump_hosts = if let Some(ref new_hops) = data.jump_hosts {
                let old_hops = existing.jump_hosts.as_deref().unwrap_or(&[]);
                let merged: Vec<_> = new_hops
                    .iter()
                    .enumerate()
                    .map(|(i, hop)| {
                        let old = old_hops.get(i);
                        crate::tunnel::JumpHost {
                            hostname: hop.hostname.clone(),
                            port: hop.port,
                            username: hop.username.clone(),
                            password: hop
                                .password
                                .clone()
                                .or_else(|| old.and_then(|o| o.password.clone())),
                            private_key: hop
                                .private_key
                                .clone()
                                .or_else(|| old.and_then(|o| o.private_key.clone())),
                        }
                    })
                    .collect();
                Some(merged)
            } else {
                data.jump_hosts.clone()
            };

            AddressBookEntry {
                password: data.password.or(existing.password),
                private_key: data.private_key.or(existing.private_key),
                jump_hosts: merged_jump_hosts,
                // Clear legacy flat fields — they've been migrated
                jump_password: None,
                jump_private_key: None,
                ..data
            }
        }
        Err(_) => data, // New entry or Vault error — just write what we have
    };

    match vault.put_entry(&scope, &folder, &entry, &merged).await {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// DELETE /api/addressbook/folders/:scope/:folder/entries/:entry — Delete an entry. Admin only.
pub async fn ab_delete_entry(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder, entry)): Path<(String, String, String)>,
) -> impl IntoResponse {
    let vault = match require_vault(&vault).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response();
    }

    match vault.delete_entry(&scope, &folder, &entry).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(VaultError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "entry not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ── User API Tokens ──

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    pub max_role: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Deserialize)]
pub struct AdminCreateTokenRequest {
    pub email: String,
    pub name: String,
    pub max_role: Option<String>,
    pub expires_at: Option<String>,
}

/// POST /api/me/tokens — Create a personal API token. Requires poweruser+.
pub async fn create_my_token(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    trusted: Option<Extension<TrustedProxies>>,
    Json(req): Json<CreateTokenRequest>,
) -> impl IntoResponse {
    let id = match identity {
        Some(Extension(ref id)) => id.clone(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "authentication required"})),
            )
                .into_response()
        }
    };

    // Only poweruser+ can self-create tokens
    if !id.has_role("poweruser") {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "poweruser role or higher required to create tokens"})),
        )
            .into_response();
    }

    // Must be an OIDC user (not an API key admin)
    let email = match &id {
        AuthIdentity::User { email, .. } => email.clone(),
        AuthIdentity::ApiKey(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "API key admins cannot create user tokens — use the admin endpoint"})),
            )
                .into_response()
        }
    };

    // Validate max_role if provided
    if let Some(ref max_role) = req.max_role {
        if !["admin", "poweruser", "operator", "viewer"].contains(&max_role.as_str()) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "max_role must be admin, poweruser, operator, or viewer"})),
            )
                .into_response();
        }
        if role_level(max_role) > role_level(id.role()) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "max_role cannot exceed your current role"})),
            )
                .into_response();
        }
    }

    if req.name.is_empty() || req.name.len() > 100 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "token name must be 1-100 characters"})),
        )
            .into_response();
    }

    let db_clone = database.clone();
    let email_clone = email.clone();
    let user =
        match tokio::task::spawn_blocking(move || db::get_user_by_email(&db_clone, &email_clone))
            .await
        {
            Ok(Ok(u)) => u,
            _ => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "failed to look up user"})),
                )
                    .into_response()
            }
        };

    let db_clone = database.clone();
    let name = req.name.clone();
    let max_role = req.max_role.clone();
    let expires_at = req.expires_at.clone();
    let result = tokio::task::spawn_blocking(move || {
        db::create_user_token(
            &db_clone,
            user.id,
            &name,
            max_role.as_deref(),
            expires_at.as_deref(),
        )
    })
    .await;

    match result {
        Ok(Ok((token_id, plaintext))) => {
            let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
            let ip = client_ip(&headers, addr.ip(), &proxies);
            let details = serde_json::to_string(&json!({
                "max_role": req.max_role,
                "expires_at": req.expires_at,
            }))
            .ok();
            let db_clone = database.clone();
            let email_clone = email.clone();
            let name_clone = req.name.clone();
            let _ = tokio::task::spawn_blocking(move || {
                db::log_token_event(
                    &db_clone,
                    Some(token_id),
                    Some(&name_clone),
                    &email_clone,
                    "created",
                    Some(&ip.to_string()),
                    details.as_deref(),
                )
            })
            .await;

            Json(json!({
                "id": token_id,
                "name": req.name,
                "token": plaintext,
                "max_role": req.max_role,
                "expires_at": req.expires_at,
            }))
            .into_response()
        }
        Ok(Err(e)) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE constraint") {
                (
                    StatusCode::CONFLICT,
                    Json(json!({"error": format!("token name '{}' already exists", req.name)})),
                )
                    .into_response()
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "failed to create token"})),
                )
                    .into_response()
            }
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to create token"})),
        )
            .into_response(),
    }
}

/// GET /api/me/tokens — List own tokens.
pub async fn list_my_tokens(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> impl IntoResponse {
    let email = match identity {
        Some(Extension(AuthIdentity::User { ref email, .. })) => email.clone(),
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "OIDC authentication required"})),
            )
                .into_response()
        }
    };

    let db_clone = database.clone();
    let user =
        match tokio::task::spawn_blocking(move || db::get_user_by_email(&db_clone, &email)).await {
            Ok(Ok(u)) => u,
            _ => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "failed to look up user"})),
                )
                    .into_response()
            }
        };

    let db_clone = database.clone();
    match tokio::task::spawn_blocking(move || db::list_user_tokens(&db_clone, user.id)).await {
        Ok(Ok(tokens)) => Json(json!(tokens)).into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to list tokens"})),
        )
            .into_response(),
    }
}

/// DELETE /api/me/tokens/{id} — Revoke own token. Requires poweruser+.
pub async fn revoke_my_token(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    trusted: Option<Extension<TrustedProxies>>,
    Path(token_id): Path<i64>,
) -> impl IntoResponse {
    let (email, role) = match identity {
        Some(Extension(AuthIdentity::User {
            ref email,
            ref role,
            ..
        })) => (email.clone(), role.clone()),
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "OIDC authentication required"})),
            )
                .into_response()
        }
    };

    if role_level(&role) < role_level("poweruser") {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "poweruser role or higher required to manage tokens"})),
        )
            .into_response();
    }

    let db_clone = database.clone();
    let email_clone = email.clone();
    let user =
        match tokio::task::spawn_blocking(move || db::get_user_by_email(&db_clone, &email_clone))
            .await
        {
            Ok(Ok(u)) => u,
            _ => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "failed to look up user"})),
                )
                    .into_response()
            }
        };

    let db_clone = database.clone();
    let user_id = user.id;
    match tokio::task::spawn_blocking(move || db::revoke_user_token(&db_clone, user_id, token_id))
        .await
    {
        Ok(Ok(true)) => {
            let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
            let ip = client_ip(&headers, addr.ip(), &proxies);
            let db_clone = database.clone();
            let _ = tokio::task::spawn_blocking(move || {
                db::log_token_event(
                    &db_clone,
                    Some(token_id),
                    None,
                    &email,
                    "revoked",
                    Some(&ip.to_string()),
                    Some("self-service revocation"),
                )
            })
            .await;
            Json(json!({"ok": true})).into_response()
        }
        Ok(Ok(false)) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "token not found or not yours"})),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to revoke token"})),
        )
            .into_response(),
    }
}

/// POST /api/admin/user-tokens — Admin creates a token for any user.
pub async fn admin_create_user_token(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    trusted: Option<Extension<TrustedProxies>>,
    Json(req): Json<AdminCreateTokenRequest>,
) -> impl IntoResponse {
    let admin_name = match identity {
        Some(Extension(ref id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response()
        }
    };

    if req.name.is_empty() || req.name.len() > 100 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "token name must be 1-100 characters"})),
        )
            .into_response();
    }

    if let Some(ref max_role) = req.max_role {
        if !["admin", "poweruser", "operator", "viewer"].contains(&max_role.as_str()) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "max_role must be admin, poweruser, operator, or viewer"})),
            )
                .into_response();
        }
    }

    let db_clone = database.clone();
    let target_email = req.email.clone();
    let user =
        match tokio::task::spawn_blocking(move || db::get_user_by_email(&db_clone, &target_email))
            .await
        {
            Ok(Ok(u)) => u,
            Ok(Err(_)) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "user not found"})),
                )
                    .into_response()
            }
            _ => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "database error"})),
                )
                    .into_response()
            }
        };

    if let Some(ref max_role) = req.max_role {
        if role_level(max_role) > role_level(&user.role) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("max_role '{}' exceeds user's role '{}'", max_role, user.role)})),
            )
                .into_response();
        }
    }

    let db_clone = database.clone();
    let name = req.name.clone();
    let max_role = req.max_role.clone();
    let expires_at = req.expires_at.clone();
    let user_id = user.id;
    let result = tokio::task::spawn_blocking(move || {
        db::create_user_token(
            &db_clone,
            user_id,
            &name,
            max_role.as_deref(),
            expires_at.as_deref(),
        )
    })
    .await;

    match result {
        Ok(Ok((token_id, plaintext))) => {
            let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
            let ip = client_ip(&headers, addr.ip(), &proxies);
            let details = serde_json::to_string(&json!({
                "created_by": admin_name,
                "for_user": req.email,
                "max_role": req.max_role,
                "expires_at": req.expires_at,
            }))
            .ok();
            let db_clone = database.clone();
            let email_clone = req.email.clone();
            let name_clone = req.name.clone();
            let _ = tokio::task::spawn_blocking(move || {
                db::log_token_event(
                    &db_clone,
                    Some(token_id),
                    Some(&name_clone),
                    &email_clone,
                    "created",
                    Some(&ip.to_string()),
                    details.as_deref(),
                )
            })
            .await;

            Json(json!({
                "id": token_id,
                "name": req.name,
                "email": req.email,
                "token": plaintext,
                "max_role": req.max_role,
                "expires_at": req.expires_at,
            }))
            .into_response()
        }
        Ok(Err(e)) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE constraint") {
                (
                    StatusCode::CONFLICT,
                    Json(json!({"error": format!("token name '{}' already exists for this user", req.name)})),
                )
                    .into_response()
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "failed to create token"})),
                )
                    .into_response()
            }
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to create token"})),
        )
            .into_response(),
    }
}

/// GET /api/admin/user-tokens — List all user tokens. Admin only.
pub async fn admin_list_user_tokens(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> impl IntoResponse {
    if let Some(Extension(ref id)) = identity {
        if !id.has_role("admin") {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response();
        }
    }

    let db_clone = database.clone();
    match tokio::task::spawn_blocking(move || db::list_all_user_tokens(&db_clone)).await {
        Ok(Ok(tokens)) => {
            let entries: Vec<_> = tokens
                .into_iter()
                .map(|(t, email)| {
                    json!({
                        "id": t.id,
                        "user_id": t.user_id,
                        "email": email,
                        "name": t.name,
                        "max_role": t.max_role,
                        "expires_at": t.expires_at,
                        "disabled": t.disabled,
                        "created_at": t.created_at,
                        "last_used_at": t.last_used_at,
                    })
                })
                .collect();
            Json(json!(entries)).into_response()
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to list tokens"})),
        )
            .into_response(),
    }
}

/// DELETE /api/admin/user-tokens/{id} — Admin revoke any token.
pub async fn admin_revoke_user_token(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    trusted: Option<Extension<TrustedProxies>>,
    Path(token_id): Path<i64>,
) -> impl IntoResponse {
    let admin_name = match identity {
        Some(Extension(ref id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response()
        }
    };

    let db_clone = database.clone();
    match tokio::task::spawn_blocking(move || db::admin_revoke_user_token(&db_clone, token_id))
        .await
    {
        Ok(Ok(true)) => {
            let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
            let ip = client_ip(&headers, addr.ip(), &proxies);
            let db_clone = database.clone();
            let _ = tokio::task::spawn_blocking(move || {
                db::log_token_event(
                    &db_clone,
                    Some(token_id),
                    None,
                    &admin_name,
                    "admin_revoked",
                    Some(&ip.to_string()),
                    None,
                )
            })
            .await;
            Json(json!({"ok": true})).into_response()
        }
        Ok(Ok(false)) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "token not found"})),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to revoke token"})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct AuditLogQuery {
    pub limit: Option<u32>,
    pub email: Option<String>,
}

/// GET /api/admin/token-audit — View token audit log. Admin only.
pub async fn admin_token_audit(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Query(query): Query<AuditLogQuery>,
) -> impl IntoResponse {
    if let Some(Extension(ref id)) = identity {
        if !id.has_role("admin") {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response();
        }
    }

    let limit = query.limit.unwrap_or(200).min(1000);
    let email = query.email.clone();
    let db_clone = database.clone();
    match tokio::task::spawn_blocking(move || {
        db::list_token_audit_log(&db_clone, limit, email.as_deref())
    })
    .await
    {
        Ok(Ok(entries)) => Json(json!(entries)).into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to list audit log"})),
        )
            .into_response(),
    }
}

// ── Quick Connect (external integrations) ──

#[derive(Deserialize)]
pub struct QuickConnectQuery {
    /// "ssh", "rdp", "vnc", "web"
    pub protocol: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub url: Option<String>,
    // Display
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub dpi: Option<u32>,
    // Address book mode
    pub scope: Option<String>,
    pub folder: Option<String>,
    pub entry: Option<String>,
}

/// GET /api/connect — Quick-connect endpoint for external integrations.
/// Creates a session and 302-redirects to the client page.
/// If not authenticated, redirects to /auth/login?next=<original-url>.
#[allow(clippy::too_many_arguments)]
pub async fn quick_connect(
    State(manager): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(vault): Extension<VaultState>,
    Extension(oidc_enabled): Extension<OidcEnabled>,
    request: axum::extract::Request,
) -> Response {
    // Reconstruct query string from the request URI
    let query_string = request.uri().query().unwrap_or("");

    let query: QuickConnectQuery = match serde_urlencoded::from_str(query_string) {
        Ok(q) => q,
        Err(e) => {
            return quick_connect_error(
                StatusCode::BAD_REQUEST,
                &format!("Invalid query parameters: {}", e),
            );
        }
    };

    let id = match identity {
        Some(Extension(ref id)) => id.clone(),
        None => {
            // Not authenticated — redirect to login with next= param
            if oidc_enabled.0 {
                let next = format!("/api/connect?{}", query_string);
                let encoded = urlencoding::encode(&next);
                return Redirect::temporary(&format!("/auth/login?next={}", encoded))
                    .into_response();
            }
            return quick_connect_error(
                StatusCode::UNAUTHORIZED,
                "Authentication required. Sign in via SSO or provide an API key.",
            );
        }
    };

    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let client_ip = client_ip(&headers, addr.ip(), &proxies);
    let admin_name = id.display_name().to_string();

    // Address book mode: scope + folder + entry all provided
    if let (Some(scope), Some(folder), Some(entry)) = (
        query.scope.as_ref(),
        query.folder.as_ref(),
        query.entry.as_ref(),
    ) {
        if !id.has_role("operator") {
            return quick_connect_error(
                StatusCode::FORBIDDEN,
                "Operator role or higher required for address book connections.",
            );
        }

        let vault = match require_vault(&vault).await {
            Ok(v) => v,
            Err(_) => {
                return quick_connect_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Address book is temporarily unavailable (Vault offline).",
                );
            }
        };

        if check_folder_access(&vault, scope, folder, &id)
            .await
            .is_err()
        {
            return quick_connect_error(StatusCode::FORBIDDEN, "No access to this folder.");
        }

        let ab_entry = match vault.get_entry(scope, folder, entry).await {
            Ok(e) => e,
            Err(VaultError::NotFound) => {
                return quick_connect_error(
                    StatusCode::NOT_FOUND,
                    &format!("Entry '{}' not found in {}/{}.", entry, scope, folder),
                );
            }
            Err(e) => {
                return quick_connect_error(
                    StatusCode::BAD_GATEWAY,
                    &format!("Failed to read address book entry: {}", e),
                );
            }
        };

        // Check if we need to prompt for credentials before connecting
        let needs_prompt = ab_entry.session_type != "web"
            && (ab_entry.prompt_credentials == Some(true)
                || (ab_entry.password.as_ref().is_none_or(|p| p.is_empty())
                    && ab_entry.private_key.as_ref().is_none_or(|k| k.is_empty())));

        if needs_prompt {
            return quick_connect_credential_form(
                scope,
                folder,
                entry,
                &ab_entry.session_type,
                ab_entry.username.as_deref(),
                ab_entry.domain.as_deref(),
                ab_entry.display_name.as_deref(),
            );
        }

        let session_type = match ab_entry.session_type.as_str() {
            "ssh" => SessionType::Ssh,
            "rdp" => SessionType::Rdp,
            "vnc" => SessionType::Vnc,
            "web" => SessionType::Web,
            other => {
                return quick_connect_error(
                    StatusCode::BAD_REQUEST,
                    &format!("Unknown session type: {}", other),
                );
            }
        };

        let ab_entry_key = format!("{}/{}/{}", scope, folder, entry);
        let create_req = CreateSessionRequest {
            session_type,
            hostname: ab_entry.hostname,
            port: ab_entry.port,
            username: ab_entry.username,
            password: ab_entry.password,
            private_key: ab_entry.private_key,
            generate_keypair: None,
            url: ab_entry.url,
            domain: ab_entry.domain,
            security: ab_entry.security,
            ignore_cert: ab_entry.ignore_cert,
            auth_pkg: ab_entry.auth_pkg,
            kdc_url: ab_entry.kdc_url,
            kerberos_cache: None,
            color_depth: ab_entry.color_depth,
            jump_hosts: ab_entry.jump_hosts,
            jump_host: None,
            jump_port: None,
            jump_username: None,
            jump_password: None,
            jump_private_key: None,
            width: query.width,
            height: query.height,
            dpi: query.dpi,
            banner: ab_entry.display_name,
            enable_drive: ab_entry.enable_drive,
            remote_app: ab_entry.remote_app,
            remote_app_dir: ab_entry.remote_app_dir,
            remote_app_args: ab_entry.remote_app_args,
            enable_recording: ab_entry.enable_recording,
            address_book_entry: Some(ab_entry_key),
            max_recordings: ab_entry.max_recordings,
        };

        tracing::info!(
            user = %admin_name,
            client_ip = %client_ip,
            scope = %scope,
            folder = %folder,
            entry = %entry,
            "Quick connect (address book)"
        );

        return match manager.create_session(create_req, admin_name).await {
            Ok(info) => {
                Redirect::temporary(&format!("/client/{}", info.session_id)).into_response()
            }
            Err(e) => quick_connect_error(StatusCode::BAD_GATEWAY, &e.to_string()),
        };
    }

    // Ad-hoc mode: requires poweruser+
    if !id.has_role("poweruser") {
        return quick_connect_error(
            StatusCode::FORBIDDEN,
            "Poweruser role or higher required for ad-hoc connections.",
        );
    }

    let session_type = match query.protocol.as_deref() {
        Some("rdp") => SessionType::Rdp,
        Some("vnc") => SessionType::Vnc,
        Some("web") => SessionType::Web,
        Some("ssh") | None => SessionType::Ssh,
        Some(other) => {
            return quick_connect_error(
                StatusCode::BAD_REQUEST,
                &format!("Unknown protocol '{}'. Use ssh, rdp, vnc, or web.", other),
            );
        }
    };

    tracing::info!(
        user = %admin_name,
        client_ip = %client_ip,
        protocol = query.protocol.as_deref().unwrap_or("ssh"),
        hostname = query.hostname.as_deref().unwrap_or("?"),
        "Quick connect (ad-hoc)"
    );

    let create_req = CreateSessionRequest {
        session_type,
        hostname: query.hostname,
        port: query.port,
        username: query.username,
        password: None,
        private_key: None,
        generate_keypair: None,
        url: query.url,
        domain: None,
        security: None,
        ignore_cert: None,
        auth_pkg: None,
        kdc_url: None,
        kerberos_cache: None,
        color_depth: None,
        jump_hosts: None,
        jump_host: None,
        jump_port: None,
        jump_username: None,
        jump_password: None,
        jump_private_key: None,
        width: query.width,
        height: query.height,
        dpi: query.dpi,
        banner: None,
        enable_drive: None,
        remote_app: None,
        remote_app_dir: None,
        remote_app_args: None,
        enable_recording: None,
        address_book_entry: None,
        max_recordings: None,
    };

    match manager.create_session(create_req, admin_name).await {
        Ok(info) => Redirect::temporary(&format!("/client/{}", info.session_id)).into_response(),
        Err(e) => quick_connect_error(StatusCode::BAD_GATEWAY, &e.to_string()),
    }
}

/// Return an inline HTML credential form for quick-connect when prompting is needed.
fn quick_connect_credential_form(
    scope: &str,
    folder: &str,
    entry: &str,
    session_type: &str,
    username: Option<&str>,
    domain: Option<&str>,
    display_name: Option<&str>,
) -> Response {
    let title = display_name.unwrap_or(entry);
    let user_val = html_escape(username.unwrap_or(""));
    let domain_val = html_escape(domain.unwrap_or(""));
    let domain_display = if session_type == "rdp" {
        "block"
    } else {
        "none"
    };
    let html = format!(
        r##"<!DOCTYPE html>
<html><head><title>Connect — {title}</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:system-ui,sans-serif;background:#1a1a2e;color:#e0e0e0;margin:0;
  display:flex;justify-content:center;align-items:center;min-height:100vh}}
.card{{background:#16213e;border-radius:12px;padding:32px;width:100%;max-width:400px;
  box-shadow:0 4px 24px rgba(0,0,0,.4)}}
h2{{margin:0 0 4px;color:#fff;font-size:1.3em}}
.sub{{color:#8899aa;font-size:.85em;margin-bottom:20px}}
label{{display:block;color:#aab;font-size:.85em;margin-bottom:4px;margin-top:14px}}
input{{width:100%;padding:10px 12px;border:1px solid #2a3a5e;border-radius:6px;
  background:#0f1629;color:#e0e0e0;font-size:1em}}
input:focus{{outline:none;border-color:#4a6fa5}}
.domain-row{{display:{domain_display}}}
button{{width:100%;margin-top:20px;padding:12px;border:none;border-radius:6px;
  background:#4a6fa5;color:#fff;font-size:1em;cursor:pointer;font-weight:600}}
button:hover{{background:#5a8fbf}}
button:disabled{{opacity:.6;cursor:wait}}
.error{{color:#f66;font-size:.85em;margin-top:12px;display:none}}
</style></head>
<body>
<div class="card">
<h2>{title}</h2>
<div class="sub">{session_type_upper} connection</div>
<form id="cred-form" autocomplete="on"
  data-scope="{scope}" data-folder="{folder}" data-entry="{entry}">
<label for="username">Username</label>
<input id="username" name="username" type="text" value="{user_val}" autocomplete="username" autofocus>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password">
<div class="domain-row">
<label for="domain">Domain</label>
<input id="domain" name="domain" type="text" value="{domain_val}">
</div>
<button type="submit" id="btn">Connect</button>
<div class="error" id="err"></div>
</form>
</div>
<script>
document.getElementById('cred-form').addEventListener('submit', async function(e) {{
  e.preventDefault();
  const form = e.target;
  const btn = document.getElementById('btn');
  const err = document.getElementById('err');
  btn.disabled = true;
  btn.textContent = 'Connecting…';
  err.style.display = 'none';
  const apiPath = '/api/addressbook/folders/'
    + encodeURIComponent(form.dataset.scope) + '/'
    + encodeURIComponent(form.dataset.folder) + '/entries/'
    + encodeURIComponent(form.dataset.entry) + '/connect';
  const body = {{
    username: document.getElementById('username').value || undefined,
    password: document.getElementById('password').value || undefined,
    domain: document.getElementById('domain').value || undefined,
    width: window.innerWidth,
    height: window.innerHeight,
    dpi: Math.round(window.devicePixelRatio * 96) || 96,
  }};
  try {{
    const headers = {{'Content-Type': 'application/json'}};
    const apiKey = sessionStorage.getItem('api_key');
    if (apiKey) headers['X-API-Key'] = apiKey;
    const resp = await fetch(apiPath, {{
      method: 'POST',
      headers: headers,
      credentials: 'same-origin',
      body: JSON.stringify(body),
    }});
    if (resp.ok) {{
      const data = await resp.json();
      window.location.href = '/client/' + data.session_id;
    }} else {{
      const data = await resp.json().catch(() => ({{}}));
      throw new Error(data.error || ('HTTP ' + resp.status));
    }}
  }} catch (ex) {{
    err.textContent = ex.message;
    err.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Connect';
  }}
}});
</script>
</body></html>"##,
        title = html_escape(title),
        session_type_upper = session_type.to_uppercase(),
        domain_display = domain_display,
        scope = html_escape(scope),
        folder = html_escape(folder),
        entry = html_escape(entry),
        user_val = user_val,
        domain_val = domain_val,
    );
    (StatusCode::OK, axum::response::Html(html)).into_response()
}

/// Return an HTML error page for quick-connect failures (browser redirect flow).
fn quick_connect_error(status: StatusCode, message: &str) -> Response {
    let html = format!(
        r#"<!DOCTYPE html>
<html><head><title>Connection Error</title>
<style>body{{font-family:system-ui,sans-serif;max-width:600px;margin:80px auto;padding:0 20px}}
h1{{color:#c00}}a{{color:#06c}}</style></head>
<body><h1>Connection Error</h1><p>{}</p>
<p><a href="/">Return to home page</a></p></body></html>"#,
        html_escape(message)
    );
    (status, axum::response::Html(html)).into_response()
}

/// Minimal HTML escaping for error messages.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
