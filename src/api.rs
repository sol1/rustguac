//! REST API routes.

use crate::auth::{self, client_ip, role_level, AuthIdentity, TrustedProxies};
use crate::db::{self, Db};
use crate::session::{CreateSessionRequest, SessionManager, SessionType};
use crate::vault::{AddressBookEntry, DefaultsSource, FolderConfig, VaultClient, VaultError};
use axum::{
    body::Body,
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
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
    Json(mut req): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    let identity = identity.map(|Extension(id)| id);
    // Ad-hoc targets from anyone below admin get every network fence, none
    // of the fields only a saved entry may set, and the site's recording,
    // drive and VDI limits.
    let is_admin = identity.as_ref().is_some_and(|id| id.has_role("admin"));
    crate::session::apply_adhoc_policy(&mut req, is_admin, manager.config());
    let caller_name = identity
        .as_ref()
        .map(|id| id.display_name().to_string())
        .unwrap_or_else(|| "unknown".into());

    // Require poweruser+ role for ad-hoc session creation
    if let Some(ref id) = identity {
        if !can_connect_adhoc(id) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "insufficient permissions — poweruser role required for ad-hoc sessions"})),
            )
                .into_response();
        }
    }

    // `owner` creates the session on someone else's behalf: they, not the
    // caller, are its creator and the only identity that may connect to it
    // first. Admin-only, since it hands that user a logged-in session.
    let admin_name = match req.owner.as_deref() {
        None => caller_name.clone(),
        Some(owner) => {
            if !identity.as_ref().is_some_and(|id| id.has_role("admin")) {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "admin role required to create a session for another owner"})),
                )
                    .into_response();
            }
            match validate_session_owner(owner) {
                Ok(o) => o,
                Err(msg) => {
                    return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg })))
                        .into_response();
                }
            }
        }
    };

    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let client_ip = client_ip(&headers, addr.ip(), &proxies);

    let target = session_target(&req);

    tracing::info!(
        admin = %admin_name,
        caller = %caller_name,
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

/// A short description of what a session request connects to, for the log.
fn session_target(req: &CreateSessionRequest) -> String {
    match req.session_type {
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
        crate::session::SessionType::Spice => {
            format!(
                "{}:{}",
                req.hostname.as_deref().unwrap_or("?"),
                req.port.unwrap_or(5900)
            )
        }
        crate::session::SessionType::Proxmox => {
            format!(
                "{}/{}",
                req.proxmox_node.as_deref().unwrap_or("?"),
                req.proxmox_vmid
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".into())
            )
        }
        crate::session::SessionType::Web => req.url.as_deref().unwrap_or("?").to_string(),
        crate::session::SessionType::Vdi => {
            req.container_image.as_deref().unwrap_or("?").to_string()
        }
    }
}

/// Normalise and check the `owner` of a session created on someone's
/// behalf. It is compared against the connecting user's email, so it must
/// look like an identity rather than arbitrary text.
fn validate_session_owner(owner: &str) -> Result<String, &'static str> {
    let owner = owner.trim();
    if owner.is_empty() {
        return Err("owner must not be empty");
    }
    if owner.len() > 320 {
        return Err("owner is too long");
    }
    if owner.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("owner must not contain whitespace or control characters");
    }
    Ok(owner.to_string())
}

/// Strip share_url from session info unless the caller is the session creator or an admin.
fn redact_share_url(
    mut info: crate::session::SessionInfo,
    identity: &Option<Extension<AuthIdentity>>,
) -> crate::session::SessionInfo {
    let is_owner_or_admin = match identity {
        Some(Extension(id)) => id.has_role("admin") || id.display_name() == info.created_by,
        None => false,
    };
    if !is_owner_or_admin {
        info.share_url = None;
        info.share_url_readonly = None;
    }
    info
}

#[derive(Deserialize, Default)]
pub struct ListSessionsQuery {
    /// When `true`, admins receive all active sessions instead of only
    /// their own. Ignored for non-admins. Used by the Sessions
    /// management page; the Address Book keeps the owner-only default.
    #[serde(default)]
    pub all: bool,
}

/// GET /api/sessions — List active sessions.
/// Default behaviour (GitHub #102): callers see only sessions they
/// created. The Sessions management page passes `?all=true` to let
/// admins see everyone.
pub async fn list_sessions(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
    axum::extract::Query(q): axum::extract::Query<ListSessionsQuery>,
) -> impl IntoResponse {
    let is_admin = identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false);
    let owner = identity
        .as_ref()
        .map(|Extension(id)| id.display_name().to_string());
    let show_all = q.all && is_admin;

    let sessions: Vec<_> = manager
        .list_sessions()
        .await
        .into_iter()
        .filter(|s| show_all || owner.as_deref().map(|o| s.created_by == o).unwrap_or(false))
        .map(|s| redact_share_url(s, &identity))
        .collect();
    Json(json!(sessions))
}

/// GET /api/sessions/:id — Get session info.
/// Non-admins can only inspect their own sessions (GitHub #102).
pub async fn get_session(
    State(manager): State<AppState>,
    Path(id): Path<Uuid>,
    identity: Option<Extension<AuthIdentity>>,
) -> impl IntoResponse {
    match manager.get_session(id).await {
        Some(info) => {
            let is_admin = identity
                .as_ref()
                .map(|Extension(id)| id.has_role("admin"))
                .unwrap_or(false);
            let is_owner = identity
                .as_ref()
                .map(|Extension(id)| info.created_by == id.display_name())
                .unwrap_or(false);
            if !is_admin && !is_owner {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "session not found" })),
                )
                    .into_response();
            }
            let info = redact_share_url(info, &identity);
            (StatusCode::OK, Json(json!(info))).into_response()
        }
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

/// PUT /api/sessions/:id/thumbnail — Upload a session thumbnail (JPEG).
/// Called by the client periodically to update the session preview.
/// Only the session owner (or an admin) can upload.
pub async fn put_session_thumbnail(
    State(manager): State<AppState>,
    Path(id): Path<Uuid>,
    identity: Option<Extension<AuthIdentity>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Validate: session must exist
    let Some(info) = manager.get_session(id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Authorise: owner or admin only (privacy — GitHub #102)
    let is_admin = identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false);
    let is_owner = identity
        .as_ref()
        .map(|Extension(id)| info.created_by == id.display_name())
        .unwrap_or(false);
    if !is_admin && !is_owner {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Reject oversized thumbnails (100KB max)
    if body.len() > 100_000 {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    // Validate JPEG magic bytes
    if !is_jpeg_magic(&body) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let dir = manager.thumbnails_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!("Failed to create thumbnails dir: {}", e);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let path = manager.thumbnail_path(id);
    match tokio::fs::write(&path, &body).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::warn!(session_id = %id, "Failed to write thumbnail: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// GET /api/sessions/:id/thumbnail — Serve a session thumbnail (JPEG).
/// Only the session owner (or an admin) can read. Returns 404 for
/// non-owners so we don't leak session existence.
pub async fn get_session_thumbnail(
    State(manager): State<AppState>,
    Path(id): Path<Uuid>,
    identity: Option<Extension<AuthIdentity>>,
) -> impl IntoResponse {
    let Some(info) = manager.get_session(id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let is_admin = identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false);
    let is_owner = identity
        .as_ref()
        .map(|Extension(id)| info.created_by == id.display_name())
        .unwrap_or(false);
    if !is_admin && !is_owner {
        return StatusCode::NOT_FOUND.into_response();
    }

    let path = manager.thumbnail_path(id);
    match tokio::fs::read(&path).await {
        Ok(data) => (
            StatusCode::OK,
            [
                (axum::http::header::CONTENT_TYPE, "image/jpeg"),
                (axum::http::header::CACHE_CONTROL, "no-cache"),
            ],
            data,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Optional body for `POST /api/sessions/:id/shadow`.
#[derive(Deserialize, Default)]
pub struct ShadowRequest {
    /// Join as a view-only viewer. Default false (keyboard and mouse
    /// control), which is what shadow has always granted.
    #[serde(default)]
    pub read_only: bool,
}

/// POST /api/sessions/:id/shadow — Mint a short-lived viewer token
/// that lets the caller join another user's active session without that
/// user's cooperation. Admin-only. The raw token is returned once and a
/// `token_audit_log` entry is written. Tokens expire after 10 minutes.
#[allow(clippy::too_many_arguments)]
pub async fn shadow_session(
    State(manager): State<AppState>,
    Extension(database): Extension<Db>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Path(id): Path<Uuid>,
    body: Option<Json<ShadowRequest>>,
) -> impl IntoResponse {
    let read_only = body.map(|Json(b)| b.read_only).unwrap_or(false);
    let id_inner = match identity {
        Some(Extension(ref id)) if id.has_role("admin") => id.clone(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response();
        }
    };

    let info = match manager.get_session(id).await {
        Some(i) => i,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "session not found"})),
            )
                .into_response();
        }
    };

    let admin_email = id_inner.display_name().to_string();
    let (raw, expires_at) = match manager.mint_shadow_token(id, &admin_email, read_only).await {
        Ok(t) => t,
        Err(crate::session::SessionError::NotActive) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "session hasn't started yet; its owner must connect before it can be shadowed"})),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "session not found"})),
            )
                .into_response();
        }
    };

    // Audit: record that an admin shadowed a session.
    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let ip = client_ip(&headers, addr.ip(), &proxies).to_string();
    let details = format!(
        "session_id={}, owner={}, read_only={}, expires_at={}",
        id,
        info.created_by,
        read_only,
        expires_at.to_rfc3339()
    );
    let db_clone = database.clone();
    let admin_for_audit = admin_email.clone();
    let _ = tokio::task::spawn_blocking(move || {
        if let Err(e) = db::log_token_event(
            &db_clone,
            None,
            None,
            &admin_for_audit,
            "shadow_session",
            Some(&ip),
            Some(&details),
        ) {
            tracing::warn!(error = %e, "failed to write shadow audit log");
        }
    })
    .await;

    tracing::info!(
        admin = %admin_email,
        session_id = %id,
        owner = %info.created_by,
        "Admin minted shadow token"
    );

    let url = format!("/client/{}?token={}", id, raw);
    Json(json!({
        "url": url,
        "expires_at": expires_at.to_rfc3339(),
        "ttl_seconds": 600,
        "read_only": read_only,
    }))
    .into_response()
}

/// GET /api/vdi/containers — List running VDI containers for the current user.
/// Returns containers with metadata for the "Active Desktops" UI.
pub async fn list_vdi_containers(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
) -> impl IntoResponse {
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

    let Some(vdi) = manager.vdi_driver() else {
        return Json(json!([])).into_response();
    };

    let mut containers = match vdi.list_managed_containers_detail().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to list VDI containers: {}", e);
            return Json(json!([])).into_response();
        }
    };

    // Filter to current user's containers
    let current_user = id
        .display_name()
        .split('@')
        .next()
        .unwrap_or("")
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>();

    containers.retain(|c| c.username == current_user);

    // Populate thumbnail URLs and active session status
    for c in &mut containers {
        let vdi_thumb = manager.vdi_thumbnail_path(&c.container_name);
        if vdi_thumb.exists() {
            c.thumbnail_url = Some(format!(
                "/api/vdi/containers/{}/thumbnail",
                c.container_name
            ));
        }
        c.has_active_session = manager.has_active_vdi_session(&c.container_id).await;
    }

    Json(json!(containers)).into_response()
}

/// GET /api/vdi/containers/:name/thumbnail — Serve a VDI container's thumbnail.
/// Owner-or-admin only: a caller may only read the thumbnail of a container
/// derived from their own username (admins may read any). Returns 404 for
/// non-owners so container existence is not leaked.
pub async fn get_vdi_container_thumbnail(
    State(manager): State<AppState>,
    Path(name): Path<String>,
    identity: Option<Extension<AuthIdentity>>,
) -> impl IntoResponse {
    // Prevent path traversal: container names are alphanumeric + hyphens only
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Ownership: container names are `rustguac-vdi-{username}` or
    // `rustguac-vdi-{username}-{entry}`, where {username} is derived from the
    // caller's identity exactly as in list_vdi_containers. A caller may only
    // read their own container's thumbnail; admins may read any.
    let Some(Extension(id)) = identity else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let current_user = id
        .display_name()
        .split('@')
        .next()
        .unwrap_or("")
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>();
    let owns = !current_user.is_empty()
        && (name == format!("rustguac-vdi-{}", current_user)
            || name.starts_with(&format!("rustguac-vdi-{}-", current_user)));
    if !id.has_role("admin") && !owns {
        return StatusCode::NOT_FOUND.into_response();
    }

    let path = manager.vdi_thumbnail_path(&name);
    match tokio::fs::read(&path).await {
        Ok(data) => (
            StatusCode::OK,
            [
                (axum::http::header::CONTENT_TYPE, "image/jpeg"),
                (axum::http::header::CACHE_CONTROL, "no-cache"),
            ],
            data,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// GET /api/login-scripts — List available login scripts. Requires operator+.
pub async fn list_login_scripts(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
) -> impl IntoResponse {
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

    let scripts_dir = std::path::Path::new(&manager.config().login_scripts_dir);
    let mut scripts: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(scripts_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    // Only list script files, skip hidden/config files
                    if !name.starts_with('.')
                        && (name.ends_with(".js") || name.ends_with(".sh") || name.ends_with(".py"))
                        && !name.starts_with("package")
                    {
                        scripts.push(name.to_string());
                    }
                }
            }
        }
    }
    scripts.sort();
    Json(json!({ "scripts": scripts })).into_response()
}

/// GET /api/health — Health check.
pub async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// POST /api/ws-ticket — Create a single-use WebSocket ticket.
/// Returns a short-lived ticket that can be used in place of an API key
/// in the WebSocket URL query parameter, preventing key exposure in logs.
pub async fn create_ws_ticket(
    Extension(ticket_store): Extension<auth::WsTicketStore>,
    identity: Option<Extension<AuthIdentity>>,
) -> impl IntoResponse {
    let identity = match identity {
        Some(Extension(id)) => id,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized"})),
            )
        }
    };
    let ticket = ticket_store.create(identity);
    (StatusCode::OK, Json(json!({"ticket": ticket})))
}

/// GET /api/system/status — System info for admin panel. Admin only.
pub async fn system_status(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Extension(vault_configured): Extension<VaultConfigured>,
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

    let version = env!("CARGO_PKG_VERSION");

    // Recording disk usage
    let rec_path = manager.recording_path().to_path_buf();
    let (rec_disk_pct, rec_count, rec_size_mb) = tokio::task::spawn_blocking(move || {
        let pct = crate::recording::disk_usage_percent(&rec_path).unwrap_or(0.0);
        let mut count = 0u32;
        let mut total_bytes = 0u64;
        if let Ok(entries) = std::fs::read_dir(&rec_path) {
            for entry in entries.flatten() {
                if entry.path().extension().and_then(|e| e.to_str()) == Some("guac") {
                    count += 1;
                    total_bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
                }
            }
        }
        (pct, count, total_bytes as f64 / 1024.0 / 1024.0)
    })
    .await
    .unwrap_or((0.0, 0, 0.0));

    // Active sessions
    let sessions = manager.list_sessions().await;
    let active_sessions = sessions
        .iter()
        .filter(|s| s.status == crate::session::SessionStatus::Active)
        .count();
    let pending_sessions = sessions
        .iter()
        .filter(|s| s.status == crate::session::SessionStatus::Pending)
        .count();

    // Vault status
    let vault_ok = if vault_configured.0 {
        manager.config().vault.is_some()
    } else {
        false
    };

    // User count
    let user_count = {
        let conn = database.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get::<_, i64>(0))
            .unwrap_or(0)
    };

    // Session history total
    let history_total = {
        let conn = database.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM session_history", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or(0)
    };

    // OIDC configured
    let oidc_configured = manager.config().oidc.is_some();

    // Drive configured
    let drive_configured = manager.config().drive.is_some();

    // TLS
    let tls_configured = manager.config().tls.is_some();

    Json(json!({
        "version": version,
        "sessions": {
            "active": active_sessions,
            "pending": pending_sessions,
            "total_current": sessions.len(),
        },
        "recordings": {
            "count": rec_count,
            "size_mb": (rec_size_mb * 10.0).round() / 10.0,
            "disk_usage_pct": (rec_disk_pct * 10.0).round() / 10.0,
        },
        "vault": {
            "configured": vault_configured.0,
            "connected": vault_ok,
        },
        "users": {
            "count": user_count,
        },
        "history": {
            "total_sessions": history_total,
        },
        "features": {
            "oidc": oidc_configured,
            "drive": drive_configured,
            "tls": tls_configured,
        },
    }))
    .into_response()
}

/// GET /api/auth/status — Returns whether OIDC is enabled. No auth required.
pub async fn auth_status(
    Extension(oidc_enabled): Extension<OidcEnabled>,
    Extension(oidc): Extension<OidcHandle>,
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    Extension(drive_configured): Extension<DriveConfigured>,
) -> impl IntoResponse {
    // Live provider availability: true once metadata has been discovered and
    // cached. If OIDC is enabled but not yet ready (provider was down at
    // startup and nobody has logged in since), kick off a background discovery
    // so the cache warms and a subsequent poll flips availability — no user
    // click required for recovery.
    let oidc_available = match oidc.0 {
        Some(state) => {
            let ready = state.is_ready().await;
            if !ready {
                state.warm_in_background();
            }
            ready
        }
        None => false,
    };

    let mut resp = json!({
        "oidc_enabled": oidc_enabled.0,
        "oidc_available": oidc_available,
        "site_title": site_title.0,
        "drive_configured": drive_configured.configured,
        // Lets the entry editor hide file transfer from ad-hoc users below
        // admin when it is off site-wide: their request couldn't turn it on.
        "drive_enabled": drive_configured.enabled,
    });
    resp["theme"] = json!({
        "admin_preset": theme.admin_preset,
        "admin_colors": theme.admin_colors,
        "presets": theme.presets,
    });
    if let Some(ref url) = theme.logo_url {
        resp["theme"]["logo_url"] = json!(url);
    }
    Json(resp)
}

/// Site title from config, shared via Extension.
#[derive(Clone)]
pub struct SiteTitle(pub String);

/// Resolved theme data shared via Extension.
#[derive(Clone)]
pub struct ThemeData {
    /// Admin-configured preset name (e.g. "dark").
    pub admin_preset: String,
    /// Fully-resolved admin theme colors (preset + overrides).
    pub admin_colors: crate::config::ThemeColors,
    /// Optional custom logo URL.
    pub logo_url: Option<String>,
    /// All built-in preset palettes for client-side switching.
    pub presets: std::collections::HashMap<String, crate::config::ThemeColors>,
}

/// Marker for whether OIDC is configured.
#[derive(Clone)]
pub struct OidcEnabled(pub bool);

/// Handle to the live OIDC state (`None` when OIDC is not configured). Lets the
/// status endpoint report current provider *availability* (metadata discovered)
/// distinct from whether OIDC is merely configured.
#[derive(Clone)]
pub struct OidcHandle(pub Option<crate::oidc::OidcState>);

/// Marker for whether Vault is configured (has [vault] in config).
/// Distinct from VaultState which tracks whether it's currently connected.
#[derive(Clone)]
pub struct VaultConfigured(pub bool);

/// Whether `[drive]` is configured, and whether it is enabled site-wide.
#[derive(Clone)]
pub struct DriveConfigured {
    pub configured: bool,
    pub enabled: bool,
}

/// Default scope ("local" | "shared") for a new per-user credential variable
/// (from `[user_credentials_default_scope]`). Only meaningful when more than
/// one Vault backend is configured.
#[derive(Clone)]
pub struct CredentialDefaultScope(pub String);

/// GET /api/recordings — List all recording files. Requires poweruser+ role.
pub async fn list_recordings(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
    mp4: Option<Extension<Arc<crate::recording_mp4::Mp4Converter>>>,
) -> impl IntoResponse {
    match &identity {
        Some(Extension(id)) if id.has_role("poweruser") => {}
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "requires poweruser or admin role"})),
            )
                .into_response();
        }
    }
    let recording_path = manager.recording_path().to_path_buf();
    // Each recording's MP4 state (#241), when conversion is available here;
    // the field is left out otherwise, which is how the page knows.
    let mp4 = mp4.map(|Extension(c)| c).filter(|c| c.enabled());

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
            let mut rec = json!({
                "name": name,
                "size_bytes": meta.len(),
                "modified": modified,
            });
            // Read sidecar .meta file for extra context
            if let Some(sidecar) = crate::recording::read_meta(&path) {
                if let Some(ref e) = sidecar.address_book_entry {
                    rec["address_book_entry"] = json!(e);
                }
                rec["created_at"] = json!(sidecar.created_at);
                if let Some(ref u) = sidecar.user {
                    rec["user"] = json!(u);
                }
                if let Some(ref f) = sidecar.folder {
                    rec["folder"] = json!(f);
                }
                if let Some(ref d) = sidecar.entry_display_name {
                    rec["entry_display_name"] = json!(d);
                }
                if let Some(ref t) = sidecar.session_type {
                    rec["session_type"] = json!(t);
                }
                if let Some(ref p) = sidecar.protocol {
                    rec["protocol"] = json!(p);
                }
            }
            if let Some(ref conv) = mp4 {
                rec["mp4"] = mp4_state_json(&conv.state(&name))["state"].clone();
            }
            recordings.push(rec);
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

/// GET /api/typescripts - List SSH typescript recordings (#159). Requires
/// poweruser+ role.
///
/// **List only by design.** Unlike `.guac` recordings, the typescript
/// content is never served or downloadable through the web UI: a
/// typescript captures the full terminal output (which can include
/// passwords typed at prompts or secrets printed to screen). A poweruser
/// can see *that* a session was recorded (connection, time, size) for
/// accountability, but retrieving the actual log requires direct access
/// to the rustguac host or storage. There is deliberately no serve or
/// delete endpoint, so there is also no name parameter and no
/// path-traversal surface.
pub async fn list_typescripts(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
) -> impl IntoResponse {
    match &identity {
        Some(Extension(id)) if id.has_role("poweruser") => {}
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "requires poweruser or admin role"})),
            )
                .into_response();
        }
    }

    let ts_path = match manager
        .config()
        .recording
        .as_ref()
        .and_then(|r| r.typescript_path.clone())
    {
        Some(p) => p,
        // Typescript recording not configured: empty list, not an error.
        None => return Json(json!({"path": null, "items": []})).into_response(),
    };
    // Host path shown in the UI so operators know where the files live.
    let ts_path_str = ts_path.display().to_string();

    match tokio::task::spawn_blocking(move || {
        let mut items = Vec::new();
        let entries = match std::fs::read_dir(&ts_path) {
            Ok(e) => e,
            Err(_) => return items,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            // Each session writes "NAME" + "NAME.timing"; list only the
            // data file so one row == one session.
            if name.ends_with(".timing") {
                continue;
            }
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
            items.push(json!({
                "name": name,
                "size_bytes": meta.len(),
                "modified": modified,
            }));
        }
        items.sort_by(|a, b| {
            let ma = a["modified"].as_str().unwrap_or("");
            let mb = b["modified"].as_str().unwrap_or("");
            mb.cmp(ma)
        });
        items
    })
    .await
    {
        Ok(items) => Json(json!({"path": ts_path_str, "items": items})).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to list typescripts"})),
        )
            .into_response(),
    }
}

// ── Report endpoints ──

#[derive(Deserialize)]
pub struct ReportQuery {
    pub user: Option<String>,
    pub entry: Option<String>,
    #[serde(rename = "type")]
    pub session_type: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    /// The caller's `Date.getTimezoneOffset()`: minutes to add to local time to
    /// reach UTC. Makes a zoneless `from`/`to` mean a *local* day, matching the
    /// local times the Reports page displays. Absent (the scripted case) means
    /// UTC, so existing callers are unaffected.
    pub tz_offset: Option<i32>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Normalize a report date filter into the shape `session_history` stores
/// ("YYYY-MM-DD HH:MM:SS", UTC), so the string comparison in SQL means what the
/// caller intended. Returns `Err` with the offending value if it can't be read.
///
/// A bare "YYYY-MM-DD" is a whole day: its first second for the lower bound,
/// its last for the upper, so `to=2026-09-04` includes the 4th rather than
/// excluding it (the DB values sort after a bare date, so they used to fall
/// outside). Zoneless values are shifted by `tz_offset_mins`; a value carrying
/// its own zone is converted from that and ignores the offset.
fn normalize_report_bound(
    value: &str,
    tz_offset_mins: i32,
    end_of_day: bool,
) -> Result<String, String> {
    const STORED: &str = "%Y-%m-%d %H:%M:%S";
    let v = value.trim();
    if v.is_empty() {
        return Err(value.to_string());
    }

    // Zoned: RFC 3339 / ISO 8601 with Z or an explicit offset.
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(v) {
        return Ok(dt.with_timezone(&chrono::Utc).format(STORED).to_string());
    }

    let local: chrono::NaiveDateTime =
        if let Ok(d) = chrono::NaiveDate::parse_from_str(v, "%Y-%m-%d") {
            let time = if end_of_day {
                chrono::NaiveTime::from_hms_opt(23, 59, 59)
            } else {
                chrono::NaiveTime::from_hms_opt(0, 0, 0)
            };
            d.and_time(time.expect("literal time is valid"))
        } else if let Some(dt) = ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M"]
            .iter()
            .find_map(|f| chrono::NaiveDateTime::parse_from_str(v, f).ok())
        {
            dt
        } else {
            return Err(value.to_string());
        };

    // A local wall clock plus its offset-to-UTC is the UTC instant.
    let utc = local + chrono::Duration::minutes(tz_offset_mins as i64);
    Ok(utc.format(STORED).to_string())
}

/// Read `from`/`to` off a report query as stored-format UTC bounds, or name the
/// parameter that could not be parsed.
fn report_bounds(q: &ReportQuery) -> Result<(Option<String>, Option<String>), String> {
    // Beyond any real zone (UTC-12..UTC+14), so a junk value can't shift a
    // filter into a different year.
    let tz = q.tz_offset.unwrap_or(0).clamp(-840, 840);
    let from = match q.from.as_deref() {
        Some(v) => Some(normalize_report_bound(v, tz, false).map_err(|v| format!("from={}", v))?),
        None => None,
    };
    let to = match q.to.as_deref() {
        Some(v) => Some(normalize_report_bound(v, tz, true).map_err(|v| format!("to={}", v))?),
        None => None,
    };
    Ok((from, to))
}

/// GET /api/reports/sessions — Paginated session history with filters. Poweruser+ only.
pub async fn report_sessions(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Query(q): Query<ReportQuery>,
) -> impl IntoResponse {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("poweruser"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "poweruser role required"})),
        )
            .into_response();
    }
    let limit = q.limit.unwrap_or(100).min(1000);
    let offset = q.offset.unwrap_or(0);
    let (from, to) = match report_bounds(&q) {
        Ok(b) => b,
        Err(bad) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("unparseable date filter: {}", bad)})),
            )
                .into_response();
        }
    };
    match db::query_session_history(
        &database,
        q.user.as_deref(),
        q.entry.as_deref(),
        q.session_type.as_deref(),
        from.as_deref(),
        to.as_deref(),
        limit,
        offset,
    ) {
        Ok((rows, total)) => {
            Json(json!({"sessions": rows, "total": total, "limit": limit, "offset": offset}))
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// GET /api/reports/sessions/csv — Export session history as CSV. Poweruser+ only.
pub async fn report_sessions_csv(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Query(q): Query<ReportQuery>,
) -> impl IntoResponse {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("poweruser"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "poweruser role required"})),
        )
            .into_response();
    }
    let (from, to) = match report_bounds(&q) {
        Ok(b) => b,
        Err(bad) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("unparseable date filter: {}", bad)})),
            )
                .into_response();
        }
    };
    match db::query_session_history(
        &database,
        q.user.as_deref(),
        q.entry.as_deref(),
        q.session_type.as_deref(),
        from.as_deref(),
        to.as_deref(),
        100_000,
        0,
    ) {
        Ok((rows, _total)) => {
            let mut csv = String::from("Session ID,Type,Hostname,Username,User,Entry,Folder,Started (UTC),Ended (UTC),Duration (secs),Status,Recording\n");
            for row in &rows {
                let fields = [
                    row["session_id"].as_str().unwrap_or(""),
                    row["session_type"].as_str().unwrap_or(""),
                    row["hostname"].as_str().unwrap_or(""),
                    row["username"].as_str().unwrap_or(""),
                    row["created_by"].as_str().unwrap_or(""),
                    row["entry_display_name"]
                        .as_str()
                        .or_else(|| row["address_book_entry"].as_str())
                        .unwrap_or(""),
                    row["address_book_folder"].as_str().unwrap_or(""),
                ];
                for (i, f) in fields.iter().enumerate() {
                    if i > 0 {
                        csv.push(',');
                    }
                    csv_escape_into(&mut csv, f);
                }
                // Timestamps, marked as UTC. The DB stores them zoneless, which
                // a spreadsheet reads as local time and silently shifts.
                for key in ["started_at", "ended_at"] {
                    csv.push(',');
                    csv_escape_into(&mut csv, &mark_utc(row[key].as_str().unwrap_or("")));
                }
                // duration_secs (numeric)
                csv.push(',');
                if let Some(d) = row["duration_secs"].as_i64() {
                    csv.push_str(&d.to_string());
                }
                // status
                csv.push(',');
                csv_escape_into(&mut csv, row["status"].as_str().unwrap_or(""));
                // recording
                csv.push(',');
                csv_escape_into(&mut csv, row["recording_file"].as_str().unwrap_or(""));
                csv.push('\n');
            }
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/csv; charset=utf-8")
                .header(
                    "Content-Disposition",
                    "attachment; filename=\"session-history.csv\"",
                )
                .body(Body::from(csv))
                .unwrap()
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// Escape a field for CSV output: wrap in double quotes if it contains commas, quotes, or newlines.
/// Tag a zoneless SQLite timestamp ("YYYY-MM-DD HH:MM:SS", always UTC via
/// `datetime('now')`) as RFC 3339 UTC. Values that already carry a zone, and
/// anything that doesn't match the expected shape, pass through unchanged.
fn mark_utc(ts: &str) -> String {
    let bytes = ts.as_bytes();
    if bytes.len() == 19 && bytes[10] == b' ' {
        format!("{}T{}Z", &ts[..10], &ts[11..])
    } else {
        ts.to_string()
    }
}

fn csv_escape_into(buf: &mut String, field: &str) {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        buf.push('"');
        for ch in field.chars() {
            if ch == '"' {
                buf.push('"');
            }
            buf.push(ch);
        }
        buf.push('"');
    } else {
        buf.push_str(field);
    }
}

/// GET /api/reports/top-connections — Most-used connections. Poweruser+ only.
pub async fn report_top_connections(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Query(q): Query<ReportQuery>,
) -> impl IntoResponse {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("poweruser"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "poweruser role required"})),
        )
            .into_response();
    }
    let limit = q.limit.unwrap_or(20).min(100);
    match db::top_connections(&database, limit) {
        Ok(rows) => Json(json!(rows)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// GET /api/reports/top-users — Most active users. Poweruser+ only.
pub async fn report_top_users(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Query(q): Query<ReportQuery>,
) -> impl IntoResponse {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("poweruser"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "poweruser role required"})),
        )
            .into_response();
    }
    let limit = q.limit.unwrap_or(20).min(100);
    match db::top_users(&database, limit) {
        Ok(rows) => Json(json!(rows)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// GET /api/reports/summary — Dashboard statistics. Poweruser+ only.
pub async fn report_summary(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> impl IntoResponse {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("poweruser"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "poweruser role required"})),
        )
            .into_response();
    }
    match db::session_summary(&database) {
        Ok(summary) => Json(summary).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// GET /api/recordings/{name} — Serve a .guac recording file. Requires poweruser+ role.
pub async fn serve_recording(
    State(manager): State<AppState>,
    Path(name): Path<String>,
    identity: Option<Extension<AuthIdentity>>,
) -> impl IntoResponse {
    match &identity {
        Some(Extension(id)) if id.has_role("poweruser") => {}
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "requires poweruser or admin role"})),
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

/// The check every recording read makes (download, MP4): poweruser or
/// admin, and a plain `.guac` name inside the recording directory.
#[allow(clippy::result_large_err)]
fn check_recording_read(
    identity: &Option<Extension<AuthIdentity>>,
    name: &str,
    recording_dir: &std::path::Path,
) -> Result<(), Response> {
    match identity {
        Some(Extension(id)) if id.has_role("poweruser") => {}
        _ => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({"error": "requires poweruser or admin role"})),
            )
                .into_response())
        }
    }
    if !is_safe_recording_name(name, recording_dir) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid recording name"})),
        )
            .into_response());
    }
    Ok(())
}

fn mp4_state_json(state: &crate::recording_mp4::Mp4State) -> serde_json::Value {
    use crate::recording_mp4::Mp4State;
    match state {
        Mp4State::Unavailable => json!({"state": "unavailable"}),
        Mp4State::None => json!({"state": "none"}),
        Mp4State::Running => json!({"state": "running"}),
        Mp4State::Ready { size_bytes } => json!({"state": "ready", "size_bytes": size_bytes}),
        Mp4State::Failed(why) => json!({"state": "failed", "error": why}),
    }
}

/// POST /api/recordings/{name}/mp4: Start converting a recording to MP4
/// (#241). Same access as downloading the recording. 202 while it converts,
/// 200 when a converted copy is already there, 409 while the recording's
/// session is still live, 503 when conversion is not available here.
pub async fn start_recording_mp4(
    State(manager): State<AppState>,
    Extension(mp4): Extension<Arc<crate::recording_mp4::Mp4Converter>>,
    identity: Option<Extension<AuthIdentity>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    use crate::recording_mp4::StartOutcome;
    if let Err(resp) = check_recording_read(&identity, &name, manager.recording_path()) {
        return resp;
    }
    let who = identity
        .as_ref()
        .map(|Extension(id)| id.display_name().to_string())
        .unwrap_or_default();
    let live = manager
        .active_recording_paths()
        .await
        .contains(&manager.recording_path().join(&name));
    match mp4.start(&name, live, &who) {
        StartOutcome::Started | StartOutcome::AlreadyRunning => {
            (StatusCode::ACCEPTED, Json(json!({"state": "running"}))).into_response()
        }
        StartOutcome::AlreadyReady { size_bytes } => {
            Json(json!({"state": "ready", "size_bytes": size_bytes})).into_response()
        }
        StartOutcome::Live => (
            StatusCode::CONFLICT,
            Json(json!({"error": "this session is still being recorded; try again once it has ended"})),
        )
            .into_response(),
        StartOutcome::NotFound => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "recording not found"})),
        )
            .into_response(),
        StartOutcome::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "MP4 conversion is not available on this server"})),
        )
            .into_response(),
    }
}

/// GET /api/recordings/{name}/mp4/status: Where a recording's MP4 stands:
/// `none`, `running`, `ready` (with `size_bytes`), `failed` (with `error`)
/// or `unavailable`.
pub async fn recording_mp4_status(
    State(manager): State<AppState>,
    Extension(mp4): Extension<Arc<crate::recording_mp4::Mp4Converter>>,
    identity: Option<Extension<AuthIdentity>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = check_recording_read(&identity, &name, manager.recording_path()) {
        return resp;
    }
    Json(mp4_state_json(&mp4.state(&name))).into_response()
}

/// GET /api/recordings/{name}/mp4: Download the converted MP4, once ready.
pub async fn serve_recording_mp4(
    State(manager): State<AppState>,
    Extension(mp4): Extension<Arc<crate::recording_mp4::Mp4Converter>>,
    identity: Option<Extension<AuthIdentity>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    use crate::recording_mp4::Mp4State;
    if let Err(resp) = check_recording_read(&identity, &name, manager.recording_path()) {
        return resp;
    }
    let not_yet = || {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no MP4 yet; start one with POST"})),
        )
            .into_response()
    };
    if !matches!(mp4.state(&name), Mp4State::Ready { .. }) {
        return not_yet();
    }
    let file = match tokio::fs::File::open(mp4.mp4_path(&name)).await {
        Ok(f) => f,
        Err(_) => return not_yet(),
    };
    let stem = name.strip_suffix(".guac").unwrap_or(&name);
    axum::response::Response::builder()
        .header("content-type", "video/mp4")
        .header(
            "content-disposition",
            format!("attachment; filename=\"{}.mp4\"", stem),
        )
        .body(Body::from_stream(ReaderStream::new(file)))
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
    if name.is_empty()
        || name == ".guac"
        || !name.ends_with(".guac")
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name.contains('\0')
    {
        return false;
    }
    // Belt-and-suspenders: verify canonical path is within recording dir
    let full = recording_dir.join(name);
    match (full.canonicalize(), recording_dir.canonicalize()) {
        (Ok(resolved), Ok(base)) => resolved.starts_with(&base),
        _ => false,
    }
}

/// JPEG magic-byte check. Uploaded thumbnails must begin with `FF D8 FF`
/// (SOI + APPn marker). Rejects truncated bodies so the caller can return
/// a clean 400 without touching disk.
fn is_jpeg_magic(body: &[u8]) -> bool {
    body.len() >= 3 && body[0] == 0xFF && body[1] == 0xD8 && body[2] == 0xFF
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
pub struct CreateUserRequest {
    pub email: String,
    #[serde(default)]
    pub name: String,
    pub role: String,
}

/// POST /api/users — Pre-provision a user for OIDC login (needed when
/// `auto_create_users = false`). Admin only.
pub async fn create_user(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Json(req): Json<CreateUserRequest>,
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

    let email = req.email.trim().to_string();
    let name = req.name.trim().to_string();
    if let Err(msg) = db::check_user_email(&email).and_then(|_| db::check_user_name(&name)) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response();
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
    let admin = identity
        .as_ref()
        .map(|Extension(id)| id.display_name().to_string())
        .unwrap_or_default();
    let (log_email, log_role) = (email.clone(), role.clone());
    match tokio::task::spawn_blocking(move || db::create_user(&db_clone, &email, &name, &role))
        .await
    {
        Ok(Ok(user)) => {
            tracing::info!(admin = %admin, email = %log_email, role = %log_role, "user added");
            (StatusCode::CREATED, Json(json!(user))).into_response()
        }
        Ok(Err(db::CreateUserError::Exists)) => (
            StatusCode::CONFLICT,
            Json(json!({"error": "a user with that email already exists (emails match ignoring case)"})),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to create user"})),
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
            let vault_available = vault.any_connected().await;
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
    if !manager
        .validate_share_token(id, &query.token)
        .await
        .is_valid()
    {
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

/// GET /api/auth/known-groups — List known OIDC groups (union of role
/// mappings + groups ever seen in a user's login claims). Admin only;
/// used by the folder modal to populate the allowed_groups picker.
pub async fn list_known_groups(
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
    match tokio::task::spawn_blocking(move || db::list_known_groups(&db_clone)).await {
        Ok(Ok(groups)) => Json(json!({ "groups": groups })).into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to list groups"})),
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

/// One Vault backend connection cell — `None` until connected / while down.
pub type VaultCell = Arc<tokio::sync::RwLock<Option<Arc<VaultClient>>>>;

/// The set of Vault backends rustguac talks to.
///
/// In the single-Vault default, `shared` and `local` both alias `default`, so
/// behaviour is identical to a single `VaultClient`. A multi-Vault split (see
/// `[vault_shared]` / `[vault_local]`) routes the `shared` and `instance`
/// address-book scopes to dedicated backends, each with its own connection and
/// retry lifecycle, so one backend being down cannot take the others with it.
pub struct VaultBackends {
    /// `[vault]`: fallback for any scope without a dedicated backend, and home
    /// of unscoped secrets (the LUKS key; user credential variables for now).
    pub default: VaultCell,
    /// Serves the `shared` scope. Aliases `default` unless `[vault_shared]` is
    /// configured.
    pub shared: VaultCell,
    /// Serves the `instance` (local) scope. Aliases `default` unless
    /// `[vault_local]` is configured.
    pub local: VaultCell,
}

impl VaultBackends {
    /// The backend cell serving a given address-book scope (`"shared"` or
    /// `"instance"`). Anything else falls back to the shared backend.
    pub fn cell_for_scope(&self, scope: &str) -> &VaultCell {
        match scope {
            "instance" => &self.local,
            _ => &self.shared,
        }
    }

    /// Resolve the connected client for `scope`, or `Unavailable` if that
    /// backend is down / not yet connected.
    async fn scoped(&self, scope: &str) -> Result<Arc<VaultClient>, VaultError> {
        self.cell_for_scope(scope)
            .read()
            .await
            .clone()
            .ok_or(VaultError::Unavailable)
    }

    /// True if at least one configured backend is currently connected.
    pub async fn any_connected(&self) -> bool {
        self.default.read().await.is_some()
            || self.shared.read().await.is_some()
            || self.local.read().await.is_some()
    }

    // ── Scope-routed address-book operations (dispatch to the scope's backend) ──

    pub async fn list_subfolders(
        &self,
        scope: &str,
        parent: &str,
    ) -> Result<Vec<crate::vault::FolderInfo>, VaultError> {
        self.scoped(scope)
            .await?
            .list_subfolders(scope, parent)
            .await
    }

    pub async fn list_entries(&self, scope: &str, folder: &str) -> Result<Vec<String>, VaultError> {
        self.scoped(scope).await?.list_entries(scope, folder).await
    }

    pub async fn get_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<AddressBookEntry, VaultError> {
        self.scoped(scope)
            .await?
            .get_entry(scope, folder, entry)
            .await
    }

    pub async fn put_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
    ) -> Result<(), VaultError> {
        self.scoped(scope)
            .await?
            .put_entry(scope, folder, entry, data)
            .await
    }

    pub async fn put_entry_if_absent(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
    ) -> Result<bool, VaultError> {
        self.scoped(scope)
            .await?
            .put_entry_if_absent(scope, folder, entry, data)
            .await
    }

    pub async fn delete_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<(), VaultError> {
        self.scoped(scope)
            .await?
            .delete_entry(scope, folder, entry)
            .await
    }

    pub async fn get_folder_config(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<FolderConfig, VaultError> {
        self.scoped(scope)
            .await?
            .get_folder_config(scope, folder)
            .await
    }

    pub async fn put_folder_config(
        &self,
        scope: &str,
        folder: &str,
        config: &FolderConfig,
    ) -> Result<(), VaultError> {
        self.scoped(scope)
            .await?
            .put_folder_config(scope, folder, config)
            .await
    }

    pub async fn get_folder_defaults(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<crate::vault::FolderDefaults, VaultError> {
        self.scoped(scope)
            .await?
            .get_folder_defaults(scope, folder)
            .await
    }

    pub async fn put_folder_defaults(
        &self,
        scope: &str,
        folder: &str,
        defaults: &crate::vault::FolderDefaults,
    ) -> Result<(), VaultError> {
        self.scoped(scope)
            .await?
            .put_folder_defaults(scope, folder, defaults)
            .await
    }

    pub async fn delete_folder_defaults(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<(), VaultError> {
        self.scoped(scope)
            .await?
            .delete_folder_defaults(scope, folder)
            .await
    }

    pub async fn effective_folder_defaults(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<Option<crate::vault::FolderDefaults>, VaultError> {
        self.scoped(scope)
            .await?
            .effective_folder_defaults(scope, folder)
            .await
    }

    pub async fn delete_folder(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<(usize, usize), VaultError> {
        self.scoped(scope).await?.delete_folder(scope, folder).await
    }

    pub async fn resolve_folder_access(
        &self,
        scope: &str,
        folder: &str,
        who: crate::vault::FolderSubject<'_>,
    ) -> Result<bool, VaultError> {
        self.scoped(scope)
            .await?
            .resolve_folder_access(scope, folder, who)
            .await
    }

    // ── Per-user credential variables ──
    //
    // Credentials live in the "local" backend (cell_for_scope("instance")) or
    // the "shared" backend (cell_for_scope("shared")) — location is the scope.
    // In single-Vault those cells alias the default, so there is one physical
    // store and the shared/local distinction collapses (see `creds_split`),
    // preserving the quick-start behaviour exactly.

    /// Whether the shared and local credential backends are physically
    /// distinct. False in single-Vault (one store); the per-credential
    /// shared/local choice is only meaningful when this is true.
    pub fn creds_split(&self) -> bool {
        !Arc::ptr_eq(&self.shared, &self.local)
    }

    async fn cred_client(&self, shared: bool) -> Result<Arc<VaultClient>, VaultError> {
        let cell = if shared { &self.shared } else { &self.local };
        cell.read().await.clone().ok_or(VaultError::Unavailable)
    }

    pub async fn get_user_credentials_scoped(
        &self,
        email: &str,
        shared: bool,
    ) -> Result<std::collections::HashMap<String, String>, VaultError> {
        self.cred_client(shared)
            .await?
            .get_user_credentials(email)
            .await
    }

    pub async fn put_user_credentials_scoped(
        &self,
        email: &str,
        shared: bool,
        creds: &std::collections::HashMap<String, String>,
    ) -> Result<(), VaultError> {
        self.cred_client(shared)
            .await?
            .put_user_credentials(email, creds)
            .await
    }

    /// Merged view (local wins on a name collision) for connect-time
    /// resolution. Tolerant of a down backend — it contributes nothing, so a
    /// credential on the reachable backend still resolves. Single read in
    /// single-Vault.
    pub async fn get_user_credentials(
        &self,
        email: &str,
    ) -> Result<std::collections::HashMap<String, String>, VaultError> {
        let local = self
            .get_user_credentials_scoped(email, false)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "reading local credentials failed");
                std::collections::HashMap::new()
            });
        if !self.creds_split() {
            return Ok(local);
        }
        let mut merged = self
            .get_user_credentials_scoped(email, true)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "reading shared credentials failed");
                std::collections::HashMap::new()
            });
        merged.extend(local); // local wins
        Ok(merged)
    }

    // ── Fan-out across scopes ──

    /// List top-level folders across every scope, routing each to its backend.
    /// Returns `(folders, unavailable_scopes)`: a scope whose dedicated backend
    /// is down (or errors) is reported in `unavailable_scopes` rather than
    /// failing the whole call, so the UI can grey it while other scopes stay
    /// live. Only when NO backend is connected at all is `Unavailable` returned
    /// (full outage → 503). In a single-Vault deployment every scope aliases
    /// the one backend, so `unavailable_scopes` is empty whenever it is up.
    pub async fn list_all_folders(
        &self,
    ) -> Result<(Vec<crate::vault::FolderInfo>, Vec<String>), VaultError> {
        let mut folders = Vec::new();
        let mut unavailable = Vec::new();
        let mut any = false;
        for scope in ["shared", "instance"] {
            match self.cell_for_scope(scope).read().await.clone() {
                Some(client) => {
                    any = true;
                    match client.list_folders_in_scope(scope).await {
                        Ok(fs) => folders.extend(fs),
                        Err(VaultError::NotFound) => {}
                        Err(e) => {
                            tracing::warn!(scope, error = %e, "listing folders for scope failed");
                            unavailable.push(scope.to_string());
                        }
                    }
                }
                None => unavailable.push(scope.to_string()),
            }
        }
        if !any {
            return Err(VaultError::Unavailable);
        }
        Ok((folders, unavailable))
    }
}

/// The defaults walk over the multi-backend router: each read goes to the
/// backend that serves the scope, like every other folder read here.
impl DefaultsSource for VaultBackends {
    async fn folder_defaults(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<Option<crate::vault::FolderDefaults>, VaultError> {
        self.scoped(scope)
            .await?
            .folder_defaults(scope, folder)
            .await
    }

    async fn takes_parent_defaults(&self, scope: &str, folder: &str) -> Result<bool, VaultError> {
        self.scoped(scope)
            .await?
            .takes_parent_defaults(scope, folder)
            .await
    }
}

pub type VaultState = Arc<VaultBackends>;

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

/// Who is asking, for the entry and protocol access rules (#296): `None`
/// for an admin, who may use every protocol.
fn entry_viewer(id: &AuthIdentity) -> Option<crate::vault::FolderSubject<'_>> {
    if id.has_role("admin") {
        None
    } else {
        Some(id.folder_subject())
    }
}

/// Helper: check if the identity has group access to a folder, honouring
/// `inherit_from_parent` on the folder's config (a subfolder may inherit
/// access from any ancestor whose `allowed_groups` matches the caller's
/// OIDC groups). Admin role bypasses all checks.
// The Err variant is an axum `Response` on purpose (callers `?` it straight
// into a handler result), so its size is inherent, not a mistake.
#[allow(clippy::result_large_err)]
async fn check_folder_access(
    vault: &VaultBackends,
    scope: &str,
    folder: &str,
    identity: &AuthIdentity,
) -> Result<(), Response> {
    if identity.has_role("admin") {
        return Ok(());
    }

    let who = identity.folder_subject();
    match vault.resolve_folder_access(scope, folder, who).await {
        Ok(true) => Ok(()),
        Ok(false) => Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "no access to this folder"})),
        )
            .into_response()),
        Err(VaultError::NotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "folder not found"})),
        )
            .into_response()),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response()),
    }
}

/// Returns true if the user can access this folder directly, or can access
/// any descendant of it. Used to decide folder visibility: a folder the user
/// cannot enter is still shown if it is on the path to something they can
/// reach, so deeper grants are never orphaned out of the tree.
///
/// Recursion is boxed (async). The walk short-circuits on the first
/// accessible folder and is bounded by the actual subtree, which is small in
/// practice; folders the user CAN access return immediately without
/// descending.
fn folder_or_descendant_accessible<'a>(
    vault: &'a VaultBackends,
    scope: &'a str,
    path: &'a str,
    who: crate::vault::FolderSubject<'a>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
    Box::pin(async move {
        if vault
            .resolve_folder_access(scope, path, who)
            .await
            .unwrap_or(false)
        {
            return true;
        }
        // Not directly accessible — keep it only if some descendant is.
        if let Ok(subs) = vault.list_subfolders(scope, path).await {
            for sub in subs {
                let child = sub.path.unwrap_or(sub.name);
                if folder_or_descendant_accessible(vault, scope, &child, who).await {
                    return true;
                }
            }
        }
        false
    })
}

/// GET /api/addressbook/folders — List folders visible to the current user.
pub async fn ab_list_folders(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
) -> impl IntoResponse {
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

    let folders = match vault.list_all_folders().await {
        Ok((f, _)) => f,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    // Filter by access (admins see all). A top-level folder is shown if the
    // user can open it OR it is on the path to a subfolder they can: access
    // granted only to `users/jsmith` must still be reachable from the tree.
    // The folder's own entries stay refused by the per-folder check.
    let who = id.folder_subject();
    let mut visible = Vec::new();
    for folder in folders {
        if id.has_role("admin")
            || folder_or_descendant_accessible(&vault, &folder.scope, &folder.name, who).await
        {
            visible.push(folder);
        }
    }

    Json(json!(visible)).into_response()
}

/// GET /api/addressbook/folders/:scope/:folder/subfolders — List subfolders at a path.
pub async fn ab_list_subfolders(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
) -> impl IntoResponse {
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

    // Listing children only needs the folder to be on the user's path, not
    // openable: that is how a grant on a deeper folder is reached. The
    // children are filtered the same way below, so nothing off the path is
    // named, and the folder's own entries are still refused elsewhere.
    if !id.has_role("admin")
        && !folder_or_descendant_accessible(&vault, &scope, &folder, id.folder_subject()).await
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "no access to this folder"})),
        )
            .into_response();
    }

    match vault.list_subfolders(&scope, &folder).await {
        Ok(subfolders) => {
            // Hide subfolders the user cannot reach. A folder is shown if the
            // user can access it directly or can access any descendant of it
            // (so deeper grants aren't orphaned out of the tree). Admins see
            // everything. Fixes #147: previously every subfolder of an
            // accessible parent was returned, so users saw folders they could
            // only click into and get "no access".
            if id.has_role("admin") {
                return Json(json!(subfolders)).into_response();
            }
            let who = id.folder_subject();
            let mut visible = Vec::with_capacity(subfolders.len());
            for sf in subfolders {
                let path = sf.path.clone().unwrap_or_else(|| sf.name.clone());
                if folder_or_descendant_accessible(&vault, &scope, &path, who).await {
                    visible.push(sf);
                }
            }
            Json(json!(visible)).into_response()
        }
        Err(crate::vault::VaultError::NotFound) => Json(json!([])).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ── Folder default credentials ──

/// Which default credentials a folder lends, without the secrets.
fn folder_defaults_summary(d: &crate::vault::FolderDefaults) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for (session_type, c) in d {
        out.insert(
            session_type.clone(),
            json!({
                "username": c.username,
                "domain": c.domain,
                "has_password": c.password.as_deref().is_some_and(|p| !p.is_empty()),
                "has_private_key": c.private_key.as_deref().is_some_and(|k| !k.is_empty()),
            }),
        );
    }
    serde_json::Value::Object(out)
}

/// GET /api/addressbook/folders/:scope/:folder/defaults — admin only. The
/// folder's own `.defaults` (not what it inherits), secrets stripped.
pub async fn ab_get_folder_defaults(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
) -> impl IntoResponse {
    if !matches!(identity, Some(Extension(ref id)) if id.has_role("admin")) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response();
    }
    match vault.get_folder_defaults(&scope, &folder).await {
        Ok(d) => Json(json!({ "defaults": folder_defaults_summary(&d) })).into_response(),
        Err(VaultError::NotFound) => Json(json!({ "defaults": {} })).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// One session type's part of a `PUT .../defaults` body. An omitted field
/// keeps what is stored, an empty string clears it; the same rule as entry
/// PUTs use for their secrets.
#[derive(Deserialize, Default)]
pub struct DefaultCredentialsPatch {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
}

/// PUT /api/addressbook/folders/:scope/:folder/defaults — admin only.
///
/// Body: `{ "<session type>": { username?, password?, private_key?, domain? } | null, ... }`.
/// Types not mentioned keep what is stored; `null` removes a type. Within a
/// type an omitted secret keeps the stored one and `""` clears it. A type
/// left with nothing in it is dropped; a folder left with no types loses its
/// `.defaults` key.
#[allow(clippy::too_many_arguments)]
pub async fn ab_put_folder_defaults(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
    Json(patch): Json<std::collections::BTreeMap<String, Option<DefaultCredentialsPatch>>>,
) -> impl IntoResponse {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response()
        }
    };

    for session_type in patch.keys() {
        let ok = !session_type.is_empty()
            && session_type.len() <= 32
            && session_type
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
        if !ok {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid session type key {:?}", session_type)})),
            )
                .into_response();
        }
    }

    // Only on a folder that exists: writing <path>/.defaults on its own would
    // make a folder with no .config, which nobody but an admin can see.
    match vault.get_folder_config(&scope, &folder).await {
        Ok(_) => {}
        Err(VaultError::NotFound) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "folder not found"})),
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
    }

    let mut current = match vault.get_folder_defaults(&scope, &folder).await {
        Ok(d) => d,
        Err(VaultError::NotFound) => crate::vault::FolderDefaults::new(),
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    fn non_empty(v: String) -> Option<String> {
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    }

    for (session_type, part) in patch {
        match part {
            None => {
                current.remove(&session_type);
            }
            Some(p) => {
                let c = current.entry(session_type).or_default();
                if let Some(u) = p.username {
                    c.username = non_empty(u);
                }
                if let Some(d) = p.domain {
                    c.domain = non_empty(d);
                }
                if let Some(pw) = p.password {
                    c.password = non_empty(pw);
                }
                if let Some(k) = p.private_key {
                    c.private_key = non_empty(k);
                }
            }
        }
    }
    current.retain(|_, c| c.username.is_some() || c.domain.is_some() || c.has_secret());

    match vault.put_folder_defaults(&scope, &folder, &current).await {
        Ok(()) => {
            let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
            let details = json!({ "types": current.keys().collect::<Vec<_>>() }).to_string();
            log_ab_event(
                &database,
                &admin_email,
                "update_folder_defaults",
                &scope,
                &folder,
                None,
                &ip,
                Some(&details),
            )
            .await;
            Json(json!({ "ok": true, "defaults": folder_defaults_summary(&current) }))
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// DELETE /api/addressbook/folders/:scope/:folder/defaults — admin only.
pub async fn ab_delete_folder_defaults(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
) -> impl IntoResponse {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response()
        }
    };
    match vault.delete_folder_defaults(&scope, &folder).await {
        Ok(()) => {
            let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
            log_ab_event(
                &database,
                &admin_email,
                "delete_folder_defaults",
                &scope,
                &folder,
                None,
                &ip,
                None,
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// Lend an entry without credentials of its own the folder defaults for its
/// session type: the nearest folder on the path wins per type, and the walk
/// stops at a folder with `inherit_from_parent: false` (see
/// `crate::vault::resolve_effective_defaults`). This is the one place the
/// Connections connect endpoint and `/api/connect` quick links resolve
/// defaults, so an entry behaves the same from either. An entry with its own
/// secret, or set to prompt, is returned untouched; a Vault error leaves it
/// as it was, and the caller then prompts as it did before defaults existed.
async fn lend_folder_defaults<S: DefaultsSource>(
    src: &S,
    scope: &str,
    folder: &str,
    entry: &str,
    mut ab_entry: AddressBookEntry,
) -> AddressBookEntry {
    if !crate::vault::entry_takes_folder_defaults(&ab_entry) {
        return ab_entry;
    }
    match crate::vault::resolve_effective_defaults(src, scope, folder).await {
        Ok(Some(d)) => {
            if crate::vault::apply_folder_defaults(&mut ab_entry, &d) {
                tracing::debug!(
                    scope,
                    folder,
                    entry,
                    "entry using folder default credentials"
                );
            }
        }
        Ok(None) => {}
        Err(err) => tracing::warn!("Failed to read folder defaults from Vault: {}", err),
    }
    ab_entry
}

// ── Address book change log ──
//
// The Connections page keeps itself current by polling
// `GET /api/addressbook/version?since=N` every few seconds. The answer comes
// from this in-memory log and names the folders that changed since the
// version the page last saw, so a page re-reads only what it shows: the
// open folder when its entries changed, the folder list when a folder came
// or went. The search index is never rebuilt on a poll; the page marks it
// stale and walks the book again only when the box is next used. Per
// change, an open tab therefore costs Vault at most one folder's entries
// plus one folder-list listing, however many tabs are open; a poll costs
// nothing.
//
// Changes are attributed from the request path (`ab_changes_for_request`).
// Routes whose folders only the body knows (create folder, move, copy, bulk)
// report them through an `AbChanged` response extension; should one not,
// the change is logged as `all` and the page refreshes what it shows.
//
// Per-user credential variables (`/api/me/credentials`) are not address-book
// changes and never touch this log: the tab that saved them reloads its own
// credential status, and no other tab needs to know.
//
// The log is per process. A second rustguac on the same Vault, or a direct
// Vault write, is not seen; those take a page reload, as they always did.

/// What changed, as the Connections page needs to know it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AbChange {
    /// "shared" or "instance"; "*" for `All`.
    pub scope: String,
    /// Folder path, `a/b` for a subfolder; empty for `All`.
    pub folder: String,
    pub kind: AbChangeKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AbChangeKind {
    /// Entries in the folder were created, updated, deleted, moved or copied.
    Entries,
    /// The folder itself: created, deleted, or its config changed.
    Tree,
    /// Could not be attributed: the page refreshes everything it shows.
    All,
}

impl AbChange {
    pub fn entries(scope: &str, folder: &str) -> Self {
        AbChange {
            scope: scope.to_string(),
            folder: folder.to_string(),
            kind: AbChangeKind::Entries,
        }
    }
    pub fn tree(scope: &str, folder: &str) -> Self {
        AbChange {
            scope: scope.to_string(),
            folder: folder.to_string(),
            kind: AbChangeKind::Tree,
        }
    }
    pub fn all() -> Self {
        AbChange {
            scope: "*".to_string(),
            folder: String::new(),
            kind: AbChangeKind::All,
        }
    }
    /// A folder changed somewhere, without saying which: what a caller who
    /// may not see every folder is told about folder-level changes, so a
    /// poll never names a folder they cannot access.
    pub fn tree_anywhere() -> Self {
        AbChange {
            scope: "*".to_string(),
            folder: String::new(),
            kind: AbChangeKind::Tree,
        }
    }
}

/// Response extension a handler sets to name the folders it changed when
/// the request path alone does not say (the target of a move, the folder a
/// POST created, every folder a bulk request touched).
#[derive(Clone, Debug)]
pub struct AbChanged(pub Vec<AbChange>);

/// Attach the folders a handler changed to its response, for `ab_change_track`.
fn with_ab_changes(mut response: Response, changes: Vec<AbChange>) -> Response {
    response.extensions_mut().insert(AbChanged(changes));
    response
}

/// How many individual changes the log keeps. A page that has not polled
/// for longer than it takes to make this many changes gets `changes: null`
/// and refreshes what it shows, so the bound on reads holds either way.
const AB_CHANGE_LOG_LEN: usize = 512;

/// The change log: a version counter and the recent changes behind it.
#[derive(Clone)]
pub struct AddressBookChanges {
    inner: Arc<std::sync::Mutex<AbChangeLog>>,
    /// Identifies this process's log. The version counter starts again at
    /// 0 on a restart, so a page that saw version 5 before the restart and
    /// polls once the new process has also reached 5 or more would be
    /// answered from a different log; a new epoch tells it to refresh what
    /// it shows instead.
    epoch: u64,
}

impl Default for AddressBookChanges {
    fn default() -> Self {
        AddressBookChanges {
            inner: Default::default(),
            epoch: new_ab_epoch(),
        }
    }
}

/// A fresh log id: random, so two processes never share one, and below
/// 2^53 so the page's JavaScript compares it exactly.
fn new_ab_epoch() -> u64 {
    use rand::RngExt;
    (rand::rng().random::<u64>() >> 11).max(1)
}

#[derive(Default)]
struct AbChangeLog {
    version: u64,
    changed_at_ms: u64,
    /// `(version, change)`, oldest first. One `record` call may push several
    /// changes under the same version.
    recent: std::collections::VecDeque<(u64, AbChange)>,
    /// Lowest version every change of which is still in `recent`. Eviction
    /// moves it past the version it evicted from, so a partially evicted
    /// version is never reported as complete.
    oldest_complete: u64,
}

/// Answer to `since`.
pub struct AbChangesSince {
    pub version: u64,
    pub changed_at_ms: u64,
    /// `None` when the log no longer reaches back to `since`.
    pub changes: Option<Vec<AbChange>>,
}

impl AddressBookChanges {
    /// This process's log id, sent with every version answer.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Log a change set under one new version; returns that version.
    pub fn record(&self, changes: Vec<AbChange>) -> u64 {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut log = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        log.version += 1;
        log.changed_at_ms = now_ms;
        let version = log.version;
        if log.recent.is_empty() {
            log.oldest_complete = version;
        }
        for change in changes {
            if log.recent.len() >= AB_CHANGE_LOG_LEN {
                if let Some((evicted, _)) = log.recent.pop_front() {
                    log.oldest_complete = log.oldest_complete.max(evicted + 1);
                }
            }
            log.recent.push_back((version, change));
        }
        version
    }

    /// Current version and timestamp (unix ms, 0 before the first change).
    pub fn snapshot(&self) -> (u64, u64) {
        let log = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (log.version, log.changed_at_ms)
    }

    /// Everything logged after version `since`, deduplicated, or `None` if
    /// the log has already dropped part of that range. `All` swallows the
    /// rest: the page refreshes what it shows once.
    pub fn since(&self, since: u64) -> AbChangesSince {
        let log = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let (version, changed_at_ms) = (log.version, log.changed_at_ms);
        if since == version {
            return AbChangesSince {
                version,
                changed_at_ms,
                changes: Some(Vec::new()),
            };
        }
        // Everything in (since, version] must still be in the log. A page
        // ahead of the log saw a previous process: it refreshes too. With an
        // empty log the only reachable case is `since == version`, above.
        if since > version || log.recent.is_empty() || since + 1 < log.oldest_complete {
            return AbChangesSince {
                version,
                changed_at_ms,
                changes: None,
            };
        }
        let mut out: Vec<AbChange> = Vec::new();
        for (v, change) in log.recent.iter() {
            if *v <= since {
                continue;
            }
            if change.kind == AbChangeKind::All {
                return AbChangesSince {
                    version,
                    changed_at_ms,
                    changes: Some(vec![AbChange::all()]),
                };
            }
            if !out.contains(change) {
                out.push(change.clone());
            }
        }
        AbChangesSince {
            version,
            changed_at_ms,
            changes: Some(out),
        }
    }
}

/// The address-book changes a request implies, from its method and path.
///
/// `None`: not an address-book change (reads, connects, and everything
/// outside `/api/addressbook`, `/api/me/credentials` included). Otherwise
/// the changes the path names and whether that is all of them; when it is
/// not, the handler reports the rest (`AbChanged`) or the change is logged
/// as `All`. Folder segments arrive percent-encoded (`a%2Fb`) and are
/// decoded here, as the routes would.
pub fn ab_changes_for_request(
    method: &axum::http::Method,
    path: &str,
) -> Option<(Vec<AbChange>, bool)> {
    use axum::http::Method;
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return None;
    }
    let rest = path.strip_prefix("/api/addressbook")?;
    let segs: Vec<String> = rest
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| {
            urlencoding::decode(s)
                .map(|c| c.into_owned())
                .unwrap_or_else(|_| s.to_string())
        })
        .collect();
    let seg = |i: usize| segs.get(i).map(String::as_str);
    match (seg(0), seg(1), seg(2), seg(3), seg(4), seg(5)) {
        // POST /folders: the folder is in the body.
        (Some("folders"), None, ..) => Some((Vec::new(), false)),
        // POST /bulk: the folders are in the body.
        (Some("bulk"), None, ..) => Some((Vec::new(), false)),
        // PUT|DELETE /folders/{scope}/{folder}
        (Some("folders"), Some(scope), Some(folder), None, ..) => {
            Some((vec![AbChange::tree(scope, folder)], true))
        }
        // POST /folders/{scope}/{folder}/entries
        (Some("folders"), Some(scope), Some(folder), Some("entries"), None, _) => {
            Some((vec![AbChange::entries(scope, folder)], true))
        }
        // PUT|DELETE /folders/{scope}/{folder}/entries/{entry}
        (Some("folders"), Some(scope), Some(folder), Some("entries"), Some(_), None) => {
            Some((vec![AbChange::entries(scope, folder)], true))
        }
        // POST .../entries/{entry}/connect starts a session, changes nothing.
        (Some("folders"), Some(_), Some(_), Some("entries"), Some(_), Some("connect")) => None,
        // POST /adhoc/connect starts an ad-hoc session from the editor; it
        // changes nothing in the address book either.
        (Some("adhoc"), Some("connect"), None, ..) => None,
        // POST .../entries/{entry}/move|copy: the target is in the body.
        (Some("folders"), Some(scope), Some(folder), Some("entries"), Some(_), Some(_)) => {
            Some((vec![AbChange::entries(scope, folder)], false))
        }
        // PUT|DELETE /folders/{scope}/{folder}/defaults: the folder's default
        // credentials also decide what every subfolder that shares its
        // audience lends, so nothing narrower than everything is right. The
        // handler reports nothing, which is logged as All.
        (Some("folders"), Some(_), Some(_), Some("defaults"), None, _) => Some((Vec::new(), false)),
        // Anything else that writes under the prefix: refresh everything
        // rather than miss it.
        _ => Some((Vec::new(), false)),
    }
}

/// Middleware: log the address-book changes of every successful mutating
/// request. It runs outside `require_auth`, so it also sees requests that
/// were refused; those fail and are not logged. A failed request is logged
/// only when its handler reported what it changed anyway (`AbChanged`), as
/// a move that copied the entry but could not remove the original does.
pub async fn ab_change_track(
    changes: Option<Extension<AddressBookChanges>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let implied = ab_changes_for_request(request.method(), request.uri().path());
    let response = next.run(request).await;
    if let Some((mut found, mut complete)) = implied {
        let reported = response.extensions().get::<AbChanged>();
        if response.status().is_success() {
            if let Some(AbChanged(reported)) = reported {
                found.extend(reported.iter().cloned());
                complete = true;
            }
            if !complete {
                found.push(AbChange::all());
            }
            if let Some(Extension(log)) = changes {
                log.record(found);
            }
        } else if let (Some(AbChanged(reported)), Some(Extension(log))) = (reported, changes) {
            if !reported.is_empty() {
                log.record(reported.clone());
            }
        }
    }
    response
}

#[derive(Deserialize, Default)]
pub struct AbVersionQuery {
    pub since: Option<u64>,
}

/// Most change rows a non-admin's poll checks one by one. Past this (a big
/// bulk change) the rows are replaced by one path-less tree marker and the
/// page refreshes what it shows, so a burst costs each tab a bounded number
/// of folder-config reads.
const AB_VERSION_MAX_CHECKED_ROWS: usize = 32;

/// The changes a caller who is not an admin may be told about. An entries
/// row is kept only for a folder the caller can open directly (the
/// `check_folder_access` rule); folder-level rows never name the folder,
/// since a folder that was created, deleted or had its access changed may
/// be one the caller cannot see. `can_access` is only consulted when there
/// are rows to answer, so an empty poll still costs no Vault read.
async fn ab_changes_visible_to<F, Fut>(changes: Vec<AbChange>, can_access: F) -> Vec<AbChange>
where
    F: Fn(String, String) -> Fut,
    Fut: std::future::Future<Output = Result<bool, VaultError>>,
{
    if changes.iter().any(|c| c.kind == AbChangeKind::All) {
        return vec![AbChange::all()];
    }
    if changes.len() > AB_VERSION_MAX_CHECKED_ROWS {
        return vec![AbChange::tree_anywhere()];
    }
    let mut out = Vec::new();
    let mut tree = false;
    for c in changes {
        match c.kind {
            AbChangeKind::Tree => tree = true,
            AbChangeKind::Entries => match can_access(c.scope.clone(), c.folder.clone()).await {
                Ok(true) => out.push(c),
                // No access, or the folder has gone: nothing to say.
                Ok(false) | Err(VaultError::NotFound) => {}
                // Can't tell: have the page refresh rather than miss it,
                // without naming the folder.
                Err(_) => tree = true,
            },
            AbChangeKind::All => unreachable!("handled above"),
        }
    }
    if tree {
        out.push(AbChange::tree_anywhere());
    }
    out
}

/// GET /api/addressbook/version?since=N — the change log since version N,
/// answered from memory. Requires operator. `epoch` identifies this
/// process's log: a page that sees it change refreshes what it shows.
pub async fn ab_version(
    identity: Option<Extension<AuthIdentity>>,
    changes: Option<Extension<AddressBookChanges>>,
    vault: Option<Extension<VaultState>>,
    Query(q): Query<AbVersionQuery>,
) -> impl IntoResponse {
    let id = match identity {
        Some(Extension(id)) if id.has_role("operator") => id,
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "operator role required"})),
            )
                .into_response();
        }
    };
    let Some(Extension(log)) = changes else {
        return Json(json!({ "version": 0, "changed_at": 0, "epoch": 0, "changes": null }))
            .into_response();
    };
    let answer = match q.since {
        Some(since) => log.since(since),
        None => {
            let (version, changed_at_ms) = log.snapshot();
            AbChangesSince {
                version,
                changed_at_ms,
                changes: None,
            }
        }
    };
    let changes = match answer.changes {
        Some(rows) if !rows.is_empty() && !id.has_role("admin") => {
            let who = id.folder_subject();
            Some(match vault {
                Some(Extension(vault)) => {
                    ab_changes_visible_to(rows, |scope, folder| {
                        let vault = vault.clone();
                        async move { vault.resolve_folder_access(&scope, &folder, who).await }
                    })
                    .await
                }
                // No Vault to check against: say only that something changed.
                None => vec![AbChange::tree_anywhere()],
            })
        }
        other => other,
    };
    Json(json!({
        "version": answer.version,
        "changed_at": answer.changed_at_ms,
        "epoch": log.epoch(),
        "changes": changes,
    }))
    .into_response()
}

/// GET /api/addressbook — Batch endpoint returning all visible folders with entries.
/// Replaces the N+1 pattern of listing folders then entries per folder.
pub async fn ab_list_all(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
) -> impl IntoResponse {
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

    let (folders, unavailable_scopes) = match vault.list_all_folders().await {
        Ok(fu) => fu,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    let mut result = Vec::new();
    let who = id.folder_subject();
    for folder in folders {
        // Access check (admins see all); inherits via resolver walk-up. A
        // folder the user cannot open is still listed, without its entries,
        // when it leads to a subfolder they can: that is how the tree reaches
        // a grant made only on `users/jsmith`.
        if !id.has_role("admin")
            && !vault
                .resolve_folder_access(&folder.scope, &folder.name, who)
                .await
                .unwrap_or(false)
        {
            if folder_or_descendant_accessible(&vault, &folder.scope, &folder.name, who).await {
                result.push(json!({
                    "name": folder.name,
                    "scope": folder.scope,
                    "path": folder.path,
                    "has_children": folder.has_children,
                    "description": folder.description,
                    "display_name": folder.display_name,
                    "path_only": true,
                    "entries": [],
                }));
            }
            continue;
        }

        // Fetch folder config for the response
        let config = vault
            .get_folder_config(&folder.scope, &folder.name)
            .await
            .ok();

        // Fetch entries (stripped of credentials)
        let entry_names = vault
            .list_entries(&folder.scope, &folder.name)
            .await
            .unwrap_or_default();
        let defaults = vault
            .effective_folder_defaults(&folder.scope, &folder.name)
            .await
            .ok()
            .flatten();
        let mut entries = Vec::new();
        for name in &entry_names {
            if let Ok(entry) = vault.get_entry(&folder.scope, &folder.name, name).await {
                // Only the protocols the caller may use; none hides the entry.
                let Some(info) = crate::vault::EntryInfo::for_viewer(
                    name,
                    &entry,
                    defaults.as_ref(),
                    entry_viewer(id),
                ) else {
                    continue;
                };
                entries.push(info);
            }
        }

        result.push(json!({
            "name": folder.name,
            "scope": folder.scope,
            "path": folder.path,
            "has_children": folder.has_children,
            "description": folder.description,
            "display_name": folder.display_name,
            "allowed_groups": config.as_ref().map(|c| &c.allowed_groups),
            // allowed_users is deliberately not listed: operators see this,
            // and a user who can open a folder should not learn who else can.
            // Admins read it from GET .../config.
            "entries": entries,
        }));
    }

    // `unavailable_scopes` lists scopes whose dedicated backend is down (empty
    // in a healthy single-Vault deploy). The UI greys those scopes rather than
    // silently hiding them.
    Json(json!({"folders": result, "unavailable_scopes": unavailable_scopes})).into_response()
}

/// GET /api/addressbook/search-index — Flat list of every entry the user has access to,
/// across all folders and subfolders. Powers the Connections page quick-search.
///
/// Walks the full tree (top-level via list_folders, then list_subfolders per node) and
/// emits one row per entry as `{scope, folder_path, entry: EntryInfo}`. Subfolder
/// traversal is unconditional because a child may grant access independently of a
/// denied parent (resolve_folder_access semantics); ACL is enforced per folder before
/// its entries are emitted.
pub async fn ab_search_index(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
) -> impl IntoResponse {
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

    let who = id.folder_subject();
    let is_admin = id.has_role("admin");

    let top = match vault.list_all_folders().await {
        Ok((f, _)) => f,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    let mut queue: Vec<(String, String)> = top
        .into_iter()
        .map(|f| (f.scope, f.path.unwrap_or(f.name)))
        .collect();
    let mut emitted = Vec::new();

    while let Some((scope, path)) = queue.pop() {
        if let Ok(subs) = vault.list_subfolders(&scope, &path).await {
            for s in subs {
                let child_path = s.path.unwrap_or_else(|| s.name.clone());
                queue.push((scope.clone(), child_path));
            }
        }

        let allowed = is_admin
            || vault
                .resolve_folder_access(&scope, &path, who)
                .await
                .unwrap_or(false);
        if !allowed {
            continue;
        }

        let names = match vault.list_entries(&scope, &path).await {
            Ok(n) => n,
            Err(_) => continue,
        };
        let defaults = vault
            .effective_folder_defaults(&scope, &path)
            .await
            .ok()
            .flatten();
        // The folder's human title (e.g. the NetBox tenant name), so the
        // search results can show it over the folder key like the folder view.
        let folder_display = vault
            .get_folder_config(&scope, &path)
            .await
            .ok()
            .map(|c| c.display_name)
            .filter(|s| !s.is_empty());
        for name in &names {
            if let Ok(entry) = vault.get_entry(&scope, &path, name).await {
                // Only the protocols the caller may use; none hides the entry.
                let Some(info) = crate::vault::EntryInfo::for_viewer(
                    name,
                    &entry,
                    defaults.as_ref(),
                    entry_viewer(id),
                ) else {
                    continue;
                };
                emitted.push(json!({
                    "scope": scope,
                    "folder_path": path,
                    "folder_display_name": folder_display,
                    "entry": info,
                }));
            }
        }
    }

    Json(json!({"entries": emitted})).into_response()
}

/// GET /api/addressbook/folders/:scope/:folder/entries — List entries in a folder.
pub async fn ab_list_entries(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
) -> impl IntoResponse {
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
    let defaults = vault
        .effective_folder_defaults(&scope, &folder)
        .await
        .ok()
        .flatten();
    let mut entries = Vec::new();
    for name in &entry_names {
        if let Ok(entry) = vault.get_entry(&scope, &folder, name).await {
            // Only the protocols the caller may use; none hides the entry.
            let Some(info) = crate::vault::EntryInfo::for_viewer(
                name,
                &entry,
                defaults.as_ref(),
                entry_viewer(id),
            ) else {
                continue;
            };
            entries.push(info);
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
    /// The screen's size in CSS pixels. An entry that opens fullscreen on
    /// connect is created at this size instead of the window's, so nothing
    /// has to be resized once the fullscreen transition lands.
    #[serde(default)]
    pub screen_width: Option<u32>,
    #[serde(default)]
    pub screen_height: Option<u32>,
    #[serde(default)]
    pub dpi: Option<u32>,
    /// The browser user's keyboard layout (a guacd `server-layout` name),
    /// for an RDP or VDI entry with no layout of its own.
    #[serde(default)]
    pub keyboard_layout: Option<String>,
    #[serde(default)]
    pub banner: Option<String>,
    /// Override or supply credentials at connect time (never stored).
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    /// Which of the entry's protocols to connect with, by name (#296).
    /// Default: the primary, or the first one the caller may use.
    #[serde(default)]
    pub protocol: Option<String>,
}

/// POST /api/ssh/probe-host-key — Probe an SSH server to retrieve its host key.
pub async fn ssh_probe_host_key(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
    axum::Json(body): axum::Json<ProbeHostKeyRequest>,
) -> impl IntoResponse {
    // Used while filling in an entry or an ad-hoc connection.
    match &identity {
        Some(Extension(id)) if id.has_role("admin") || can_connect_adhoc(id) => {}
        _ => {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({"error": "requires poweruser or admin role"})),
            )
                .into_response();
        }
    }

    let port = body.port.unwrap_or(22);
    // The probe is a raw TCP + SSH key exchange to a caller-chosen host. For
    // a poweruser it is fenced like an SSH session and dialled at the checked
    // address; unchecked it is a port scanner and banner grabber for anything
    // rustguac can reach (guacd, Vault, metadata services). Admins probe
    // freely, since they configure jump hosts outside the allowlists.
    let is_admin = matches!(&identity, Some(Extension(id)) if id.has_role("admin"));
    let dial = if is_admin {
        body.hostname.clone()
    } else {
        match crate::session::allowed_address(
            &body.hostname,
            port,
            &manager.config().ssh_allowed_networks,
        )
        .await
        {
            Ok(ip) => crate::session::dial_host(ip),
            Err(e) => {
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        }
    };
    match crate::tunnel::probe_host_key(&dial, port).await {
        Ok(host_key) => {
            let fingerprint = crate::tunnel::fingerprint_openssh_key(&host_key)
                .unwrap_or_else(|_| "unknown".into());
            let algorithm = host_key
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_string();
            (
                StatusCode::OK,
                axum::Json(serde_json::json!({
                    "host_key": host_key,
                    "fingerprint": fingerprint,
                    "algorithm": algorithm,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            axum::Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct ProbeHostKeyRequest {
    pub hostname: String,
    pub port: Option<u16>,
}

/// The size a new session is created at.
///
/// A bitmap (RDP/VNC) entry that opens fullscreen on connect is created at
/// the screen's size, which is the size it will have once fullscreen lands.
/// Until the client's fullscreen gesture fires it scales that picture to fit
/// the window, so the desktop is painted once at its final size and the
/// fullscreen transition brings no resize, no decoder rebuild and no second
/// repaint (#257). Everything else keeps the window's size: a terminal
/// reflows to fullscreen instantly.
///
/// Both sizes are CSS pixels, which is what the client's post-connect size
/// send uses today, so creation and that send agree. When #238 lands
/// (native/HiDPI resolution, `display_scale`), that send becomes the
/// device-pixel size, and the mod-16 rounding below must then be applied to
/// the final size after the devicePixelRatio multiply, not to the CSS size.
pub fn initial_session_size(
    session_type: &str,
    fullscreen_on_connect: bool,
    window: (Option<u32>, Option<u32>),
    screen: (Option<u32>, Option<u32>),
) -> (Option<u32>, Option<u32>) {
    let bitmap = matches!(session_type, "rdp" | "vnc");
    let (w, h) = match (bitmap && fullscreen_on_connect, screen) {
        (true, (Some(w), Some(h))) if w > 0 && h > 0 => (Some(w), Some(h)),
        _ => window,
    };
    // RDP's display channel rounds every requested size down to a multiple
    // of 16 (patches/007, which prevents the H.264 green band), so the
    // client's first post-connect size send always lands on that grid.
    // Create the session there already, fullscreen or windowed, so the two
    // match: guacd coalesces them and there is no resize, the H.264 decoder
    // is not rebuilt and the picture never flashes on connect (#257). VNC
    // has no such rounding, so it keeps the exact size.
    //
    // #238 (not merged at the time of writing): once the session is created
    // at the device-pixel size, round that size, i.e. apply round_down_mod16
    // after multiplying by devicePixelRatio, since rounding the CSS size and
    // then scaling it would leave the grid again.
    if session_type == "rdp" {
        (w.map(round_down_mod16), h.map(round_down_mod16))
    } else {
        (w, h)
    }
}

/// Round a dimension down to a multiple of 16, with a 16px floor so a tiny
/// screen never rounds to zero. Mirrors guacd's RDP display-channel rounding.
fn round_down_mod16(v: u32) -> u32 {
    let r = v - (v % 16);
    if r < 16 {
        16
    } else {
        r
    }
}

/// The session type an entry's `type` names, or `None` for an unknown one.
fn entry_session_type(entry_type: &str) -> Option<SessionType> {
    Some(match entry_type {
        "ssh" => SessionType::Ssh,
        "rdp" => SessionType::Rdp,
        "vnc" => SessionType::Vnc,
        "spice" => SessionType::Spice,
        "proxmox" => SessionType::Proxmox,
        "web" => SessionType::Web,
        "vdi" => SessionType::Vdi,
        _ => return None,
    })
}

/// How the browser that asked will draw the session: never part of an entry.
pub struct EntryDisplay {
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub dpi: Option<u32>,
    /// The browser user's own keyboard layout, used for an RDP or VDI entry
    /// that leaves its layout at the server default.
    pub keyboard_layout: Option<String>,
}

/// A keyboard layout the browser asked for, if guacd knows it. Anything
/// else is dropped rather than refused: it is a preference, and an unknown
/// one should not stop the connection.
pub fn browser_keyboard_layout(layout: Option<&str>) -> Option<String> {
    layout
        .map(str::trim)
        .filter(|l| crate::guacd::RDP_KEYBOARD_LAYOUTS.contains(l))
        .map(str::to_string)
}

/// The saved entry a session comes from, for its recording and reports.
pub struct EntryRef {
    /// `scope/folder/entry`.
    pub key: String,
    pub folder: String,
}

/// The session request a connection entry describes. The one conversion
/// used by the Connections connect endpoint, `/api/connect` links and
/// ad-hoc connections, so an option added to entries works in all three.
///
/// `attribution` names the saved entry the session belongs to; an ad-hoc
/// connection has none, and its entry's display name is then not used
/// either. The request is returned unfenced and unfiltered: an ad-hoc
/// caller's request still has to go through
/// `crate::session::apply_adhoc_policy`.
pub fn session_request_from_entry(
    entry: AddressBookEntry,
    display: EntryDisplay,
    attribution: Option<EntryRef>,
) -> Result<CreateSessionRequest, String> {
    let session_type = entry_session_type(&entry.session_type)
        .ok_or_else(|| format!("unknown session type: {}", entry.session_type))?;
    let (address_book_entry, address_book_folder, entry_display_name) = match attribution {
        Some(r) => (Some(r.key), Some(r.folder), entry.display_name),
        None => (None, None, None),
    };
    Ok(CreateSessionRequest {
        session_type,
        hostname: entry.hostname,
        port: entry.port,
        username: entry.username,
        password: entry.password,
        private_key: entry.private_key,
        generate_keypair: None,
        url: entry.url,
        domain: entry.domain,
        security: entry.security,
        server_layout: entry
            .server_layout
            .filter(|l| !l.trim().is_empty())
            .or(display.keyboard_layout),
        ignore_cert: entry.ignore_cert,
        auth_pkg: entry.auth_pkg,
        kdc_url: entry.kdc_url,
        kerberos_cache: None,
        color_depth: entry.color_depth,
        jump_hosts: entry.jump_hosts,
        jump_host: None,
        jump_port: None,
        jump_username: None,
        jump_password: None,
        jump_private_key: None,
        width: display.width,
        height: display.height,
        dpi: display.dpi,
        banner: entry.banner,
        enable_drive: entry.enable_drive,
        remote_app: entry.remote_app,
        remote_app_dir: entry.remote_app_dir,
        remote_app_args: entry.remote_app_args,
        enable_recording: entry.enable_recording,
        record_typescript: entry.record_typescript,
        address_book_entry,
        address_book_folder,
        address_book_protocol: None,
        entry_display_name,
        max_recordings: entry.max_recordings,
        login_script: entry.login_script,
        autofill: entry.autofill,
        allowed_domains: entry.allowed_domains,
        vnc_resize: entry.vnc_resize,
        vnc_network: entry.vnc_network,
        disable_copy: entry.disable_copy,
        disable_paste: entry.disable_paste,
        enable_gfx: entry.enable_gfx,
        enable_desktop_composition: entry.enable_desktop_composition,
        enable_wallpaper: entry.enable_wallpaper,
        enable_theming: entry.enable_theming,
        enable_full_window_drag: entry.enable_full_window_drag,
        force_lossless: entry.force_lossless,
        enable_h264: entry.enable_h264,
        container_image: entry.container_image,
        container_cpu_limit: entry.container_cpu_limit,
        container_memory_limit: entry.container_memory_limit,
        container_env: entry.container_env,
        container_idle_timeout_mins: entry.container_idle_timeout_mins,
        container_username: entry.container_username,
        container_password: entry.container_password,
        allow_sharing: entry.allow_sharing,
        fullscreen_on_connect: entry.fullscreen_on_connect,
        autohide_side_tabs: entry.autohide_side_tabs,
        spice_tls: entry.spice_tls,
        spice_tls_port: entry.spice_tls_port,
        spice_ca_cert: entry.spice_ca_cert,
        spice_cert_subject: entry.spice_cert_subject,
        spice_proxy: entry.spice_proxy,
        proxmox_url: entry.proxmox_url,
        proxmox_node: entry.proxmox_node,
        proxmox_vmid: entry.proxmox_vmid,
        proxmox_token_id: entry.proxmox_token_id,
        proxmox_token_secret: entry.proxmox_token_secret,
        proxmox_verify_tls: entry.proxmox_verify_tls,
        max_monitors: entry.max_monitors,
        owner: None,
        fence_all_targets: false,
        ssh_font_size: entry.ssh_font_size,
        wol_send_packet: entry.wol_send_packet,
        wol_mac_addr: entry.wol_mac_addr,
        wol_broadcast_addr: entry.wol_broadcast_addr,
        wol_udp_port: entry.wol_udp_port,
        wol_wait_time: entry.wol_wait_time,
    })
}

/// The session request for connecting a saved entry from the Connections
/// page: the entry, with the credentials and banner the user was prompted
/// for (never stored) in place of its own, at the size the page asked for.
fn entry_connect_request(
    mut ab_entry: AddressBookEntry,
    req: ConnectRequest,
    entry_key: &str,
    folder: &str,
) -> Result<CreateSessionRequest, String> {
    ab_entry.username = req.username.or(ab_entry.username);
    ab_entry.password = req.password.or(ab_entry.password);
    ab_entry.domain = req.domain.or(ab_entry.domain);
    ab_entry.banner = req.banner.or(ab_entry.banner);
    let (width, height) = initial_session_size(
        &ab_entry.session_type,
        ab_entry.fullscreen_on_connect.unwrap_or(false),
        (req.width, req.height),
        (req.screen_width, req.screen_height),
    );
    let display = EntryDisplay {
        width,
        height,
        dpi: req.dpi,
        keyboard_layout: browser_keyboard_layout(req.keyboard_layout.as_deref()),
    };
    let attribution = EntryRef {
        key: entry_key.to_string(),
        folder: folder.to_string(),
    };
    session_request_from_entry(ab_entry, display, Some(attribution))
}

/// Whether `id` may open ad-hoc connections: sessions to a target of their
/// own choosing rather than a saved entry. The one place that decides it.
pub fn can_connect_adhoc(id: &AuthIdentity) -> bool {
    id.has_role("poweruser")
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

    // The protocol to connect with, resolved to a plain single-type entry.
    // One the caller may not use is reported as missing, like one that does
    // not exist, so it does not show.
    let Some((protocol_name, ab_entry)) =
        ab_entry.pick_protocol(req.protocol.as_deref(), entry_viewer(&id))
    else {
        let msg = if req
            .protocol
            .as_deref()
            .is_some_and(|p| !p.trim().is_empty())
        {
            "protocol not found"
        } else {
            "entry not found"
        };
        return (StatusCode::NOT_FOUND, Json(json!({"error": msg}))).into_response();
    };

    let ab_entry = lend_folder_defaults(vault.as_ref(), &scope, &folder, &entry, ab_entry).await;

    // Resolve credential variable references ($domain_user, $domain_password, etc.)
    let ab_entry = if !crate::vault::entry_credential_variables(&ab_entry).is_empty() {
        let user_email = match &id {
            AuthIdentity::User { email, .. } => Some(email.clone()),
            _ => None,
        };
        if let Some(email) = user_email {
            match vault.get_user_credentials(&email).await {
                Ok(user_creds) => {
                    match crate::vault::resolve_credential_variables(&ab_entry, &user_creds) {
                        Ok(resolved) => resolved,
                        Err(missing) => {
                            return (
                                StatusCode::PRECONDITION_FAILED,
                                Json(json!({
                                    "error": "missing credential variables",
                                    "missing_variables": missing,
                                })),
                            )
                                .into_response()
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to read user credentials from Vault: {}", e);
                    ab_entry // Fall through with unresolved variables
                }
            }
        } else {
            ab_entry // API key users — no variable resolution
        }
    } else {
        ab_entry
    };

    let ab_entry_key = format!("{}/{}/{}", scope, folder, entry);
    let create_req = match entry_connect_request(ab_entry, req, &ab_entry_key, &folder) {
        Ok(mut r) => {
            r.address_book_protocol = Some(protocol_name.clone());
            r
        }
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response()
        }
    };

    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let client_ip_addr = client_ip(&headers, addr.ip(), &proxies);
    let admin_name = id.display_name().to_string();

    tracing::info!(
        user = %admin_name,
        client_ip = %client_ip_addr,
        folder = %folder,
        entry = %entry,
        protocol = %protocol_name,
        scope = %scope,
        "Address book connect requested"
    );

    // Reuse a Pending session this user already opened for this entry rather
    // than spawning a duplicate (e.g. a repeat Connect click). Matched on the
    // fully built request above, credentials included: a retry with a
    // different password, key or domain (a mistyped prompt) must not get
    // the old Pending session, which still holds the old credentials. The
    // fingerprint is a hash, compared only, never logged.
    if let Some(existing) = manager
        .find_reusable_session(&admin_name, &ab_entry_key, &create_req.reuse_fingerprint())
        .await
    {
        tracing::info!(
            user = %admin_name,
            session_id = %existing.session_id,
            "Reusing existing address book session"
        );
        return (StatusCode::CREATED, Json(json!(existing))).into_response();
    }

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

/// Where an ad-hoc connection's credential variables are read from: the
/// caller's own My Credentials and nothing else. A trait so the resolution
/// is testable without a Vault.
#[allow(async_fn_in_trait)]
pub trait UserCredentialSource {
    async fn user_credentials(
        &self,
        email: &str,
    ) -> Result<std::collections::HashMap<String, String>, VaultError>;
}

impl UserCredentialSource for VaultBackends {
    async fn user_credentials(
        &self,
        email: &str,
    ) -> Result<std::collections::HashMap<String, String>, VaultError> {
        self.get_user_credentials(email).await
    }
}

/// Fill in the `$variable` references of an ad-hoc connection from the
/// caller's own credential variables, as a saved entry's are at connect.
/// `creds` is `None` when no Vault is configured: then nothing is resolved.
///
/// Unlike a saved entry, nothing else is filled in. An ad-hoc connection
/// belongs to no folder, so folder default credentials never apply.
async fn resolve_adhoc_entry<S: UserCredentialSource>(
    mut entry: AddressBookEntry,
    id: &AuthIdentity,
    creds: Option<&S>,
) -> Result<AddressBookEntry, AdhocEntryError> {
    entry.normalize_jump_hosts();
    if crate::vault::entry_credential_variables(&entry).is_empty() {
        return Ok(entry);
    }
    let AuthIdentity::User { email, .. } = id else {
        return Err(AdhocEntryError::ApiKeyVariables);
    };
    let Some(creds) = creds else {
        return Ok(entry);
    };
    let user_creds = creds.user_credentials(email).await.unwrap_or_else(|e| {
        tracing::warn!("Failed to read user credentials from Vault: {}", e);
        std::collections::HashMap::new()
    });
    crate::vault::resolve_credential_variables(&entry, &user_creds)
        .map_err(AdhocEntryError::MissingVariables)
}

/// Why an ad-hoc connection's credential variables could not be resolved.
#[derive(Debug, PartialEq)]
enum AdhocEntryError {
    /// The caller is an API key, which has no credential variables.
    ApiKeyVariables,
    /// The caller has no variable of these names.
    MissingVariables(Vec<String>),
}

impl IntoResponse for AdhocEntryError {
    fn into_response(self) -> Response {
        match self {
            Self::ApiKeyVariables => (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "credential variables belong to a signed-in user; an API key has none"
                })),
            )
                .into_response(),
            Self::MissingVariables(missing) => (
                StatusCode::PRECONDITION_FAILED,
                Json(json!({
                    "error": "missing credential variables",
                    "missing_variables": missing,
                })),
            )
                .into_response(),
        }
    }
}

/// The session request for an ad-hoc connection, under the ad-hoc policy.
fn adhoc_session_request(
    entry: AddressBookEntry,
    req: &AdhocConnectRequest,
    is_admin: bool,
    config: &crate::config::Config,
) -> Result<CreateSessionRequest, String> {
    // One host, one protocol: there is no primary to pick from a list.
    if entry.protocols.is_some() {
        return Err("an ad-hoc connection is one protocol: set type, not protocols".into());
    }
    let (width, height) = initial_session_size(
        &entry.session_type,
        entry.fullscreen_on_connect.unwrap_or(false),
        (req.width, req.height),
        (req.screen_width, req.screen_height),
    );
    let display = EntryDisplay {
        width,
        height,
        dpi: req.dpi,
        keyboard_layout: browser_keyboard_layout(req.keyboard_layout.as_deref()),
    };
    let mut create_req = session_request_from_entry(entry, display, None)?;
    create_req.generate_keypair = req.generate_keypair.filter(|&g| g);
    crate::session::apply_adhoc_policy(&mut create_req, is_admin, config);
    Ok(create_req)
}

/// Body of `POST /api/addressbook/adhoc/connect`.
#[derive(Deserialize)]
pub struct AdhocConnectRequest {
    /// The connection, in the form a saved entry takes. Its name, folder
    /// and the like are not used.
    pub entry: AddressBookEntry,
    /// SSH: generate an ephemeral keypair (ad-hoc only; shown in a banner).
    #[serde(default)]
    pub generate_keypair: Option<bool>,
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub screen_width: Option<u32>,
    #[serde(default)]
    pub screen_height: Option<u32>,
    #[serde(default)]
    pub dpi: Option<u32>,
    #[serde(default)]
    pub keyboard_layout: Option<String>,
}

/// POST /api/addressbook/adhoc/connect — Connect to a host that is not a
/// saved entry, described with every option an entry has. Poweruser+.
/// Credential variables resolve from the caller's own; folder defaults
/// never apply. Non-admins get the ad-hoc policy (`apply_adhoc_policy`).
#[allow(clippy::too_many_arguments)]
pub async fn ab_adhoc_connect(
    State(manager): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(vault): Extension<VaultState>,
    Extension(vault_configured): Extension<VaultConfigured>,
    Json(mut req): Json<AdhocConnectRequest>,
) -> Response {
    let id = match identity {
        Some(Extension(id)) if can_connect_adhoc(&id) => id,
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "insufficient permissions — poweruser role required for ad-hoc connections"})),
            )
                .into_response()
        }
    };

    let creds = vault_configured.0.then_some(vault.as_ref());
    let entry = match resolve_adhoc_entry(std::mem::take(&mut req.entry), &id, creds).await {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let create_req =
        match adhoc_session_request(entry, &req, id.has_role("admin"), manager.config()) {
            Ok(r) => r,
            Err(msg) => {
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response()
            }
        };

    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let client_ip_addr = client_ip(&headers, addr.ip(), &proxies);
    let user = id.display_name().to_string();
    let target = session_target(&create_req);
    tracing::info!(
        user = %user,
        client_ip = %client_ip_addr,
        session_type = ?create_req.session_type,
        target = %target,
        "Ad-hoc connect requested"
    );

    match manager.create_session(create_req, user.clone()).await {
        Ok(info) => {
            tracing::info!(user = %user, session_id = %info.session_id, "Ad-hoc session created");
            (StatusCode::CREATED, Json(json!(info))).into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            tracing::error!(user = %user, target = %target, error = %msg, "Ad-hoc session creation failed");
            let status = match &e {
                crate::session::SessionError::ValidationError(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::BAD_GATEWAY,
            };
            (status, Json(json!({ "error": msg }))).into_response()
        }
    }
}

// ── Admin-only address book management ──

#[derive(Deserialize)]
pub struct CreateFolderRequest {
    pub name: String,
    pub allowed_groups: Vec<String>,
    /// Login emails granted access in addition to `allowed_groups`.
    #[serde(default)]
    pub allowed_users: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub display_name: String,
    /// "shared" or "instance" (default: "shared")
    #[serde(default = "default_scope")]
    pub scope: String,
    #[serde(default)]
    pub inherit_from_parent: bool,
}

fn default_scope() -> String {
    "shared".into()
}

/// Most users one folder may list in `allowed_users`.
const MAX_ALLOWED_USERS: usize = 500;

/// Tidy a folder's `allowed_users`: trim, drop blanks and case-insensitive
/// repeats, and refuse anything that cannot be a login identity. Usually an
/// email, but not required to contain `@`: rustguac falls back to the OIDC
/// subject when a provider sends no email claim.
fn normalize_allowed_users(users: Vec<String>) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for raw in users {
        let u = raw.trim();
        if u.is_empty() {
            continue;
        }
        if u.len() > 320 || u.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(format!("not a valid user identity: {u:?}"));
        }
        if !out.iter().any(|o| o.eq_ignore_ascii_case(u)) {
            out.push(u.to_string());
        }
    }
    if out.len() > MAX_ALLOWED_USERS {
        return Err(format!("at most {MAX_ALLOWED_USERS} users per folder"));
    }
    Ok(out)
}

/// Resolve the caller's client IP (honouring trusted proxies) into a string
/// for audit logging. Returns the empty string if the identity is anonymous.
fn audit_client_ip(
    headers: &axum::http::HeaderMap,
    addr: &SocketAddr,
    trusted: Option<&Extension<TrustedProxies>>,
) -> String {
    let proxies = trusted.map(|Extension(t)| t.0.as_slice()).unwrap_or(&[]);
    client_ip(headers, addr.ip(), proxies).to_string()
}

/// Persist a connections audit row asynchronously via spawn_blocking.
/// Errors are swallowed: an audit write must never cause a user request to
/// fail. Details must be headline-only (counts, field-name lists, booleans);
/// never entry field values (see feedback_audit_log_scope.md).
#[allow(clippy::too_many_arguments)]
async fn log_ab_event(
    database: &Db,
    email: &str,
    action: &str,
    scope: &str,
    folder_path: &str,
    entry_name: Option<&str>,
    ip: &str,
    details: Option<&str>,
) {
    let database = database.clone();
    let email = email.to_string();
    let action = action.to_string();
    let scope = scope.to_string();
    let folder_path = folder_path.to_string();
    let entry_name = entry_name.map(str::to_string);
    let ip = ip.to_string();
    let details = details.map(str::to_string);
    let _ = tokio::task::spawn_blocking(move || {
        let _ = db::log_addressbook_event(
            &database,
            &email,
            &action,
            &scope,
            &folder_path,
            entry_name.as_deref(),
            Some(&ip),
            details.as_deref(),
        );
    })
    .await;
}

/// POST /api/addressbook/folders — Create a new folder. Admin only.
#[allow(clippy::too_many_arguments)]
pub async fn ab_create_folder(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Json(req): Json<CreateFolderRequest>,
) -> impl IntoResponse {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response()
        }
    };

    let allowed_users = match normalize_allowed_users(req.allowed_users) {
        Ok(u) => u,
        Err(msg) => return ab_error(StatusCode::BAD_REQUEST, msg),
    };
    let allowed_count = req.allowed_groups.len();
    let users_count = allowed_users.len();
    let inherit = req.inherit_from_parent;
    let config = FolderConfig {
        allowed_groups: req.allowed_groups,
        allowed_users,
        description: req.description,
        display_name: req.display_name.trim().to_string(),
        inherit_from_parent: req.inherit_from_parent,
    };

    match vault
        .put_folder_config(&req.scope, &req.name, &config)
        .await
    {
        Ok(()) => {
            let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
            let details = json!({
                "allowed_groups_count": allowed_count,
                "allowed_users_count": users_count,
                "inherit_from_parent": inherit,
            })
            .to_string();
            log_ab_event(
                &database,
                &admin_email,
                "create_folder",
                &req.scope,
                &req.name,
                None,
                &ip,
                Some(&details),
            )
            .await;
            with_ab_changes(
                (StatusCode::CREATED, Json(json!({"ok": true}))).into_response(),
                vec![AbChange::tree(&req.scope, &req.name)],
            )
        }
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
    /// Login emails granted access. Omitted means "leave as is", so a client
    /// that predates this field cannot wipe the list by saving the folder.
    #[serde(default)]
    pub allowed_users: Option<Vec<String>>,
    #[serde(default)]
    pub description: String,
    /// Title shown over the folder key. Omitted means "leave as is", like
    /// `allowed_users`, so a client or script that predates the field cannot
    /// wipe it by saving the folder; `""` clears it.
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub inherit_from_parent: bool,
}

/// PUT /api/addressbook/folders/:scope/:folder — Update folder config. Admin only.
#[allow(clippy::too_many_arguments)]
pub async fn ab_update_folder(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
    Json(req): Json<UpdateFolderRequest>,
) -> impl IntoResponse {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response()
        }
    };

    // Fields the request may leave out keep their stored values, so the
    // stored config is read once when any of them is missing.
    let existing = if req.allowed_users.is_none() || req.display_name.is_none() {
        match vault.get_folder_config(&scope, &folder).await {
            Ok(existing) => Some(existing),
            Err(VaultError::NotFound) => None,
            Err(e) => return ab_error(StatusCode::BAD_GATEWAY, e.to_string()),
        }
    } else {
        None
    };
    let allowed_users = match req.allowed_users {
        Some(users) => match normalize_allowed_users(users) {
            Ok(u) => u,
            Err(msg) => return ab_error(StatusCode::BAD_REQUEST, msg),
        },
        None => existing
            .as_ref()
            .map(|c| c.allowed_users.clone())
            .unwrap_or_default(),
    };
    let display_name = match req.display_name {
        Some(d) => d.trim().to_string(),
        None => existing.map(|c| c.display_name).unwrap_or_default(),
    };
    let allowed_count = req.allowed_groups.len();
    let users_count = allowed_users.len();
    let inherit = req.inherit_from_parent;
    let config = FolderConfig {
        allowed_groups: req.allowed_groups,
        allowed_users,
        description: req.description,
        display_name,
        inherit_from_parent: req.inherit_from_parent,
    };

    match vault.put_folder_config(&scope, &folder, &config).await {
        Ok(()) => {
            let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
            let details = json!({
                "allowed_groups_count": allowed_count,
                "allowed_users_count": users_count,
                "inherit_from_parent": inherit,
            })
            .to_string();
            log_ab_event(
                &database,
                &admin_email,
                "update_folder",
                &scope,
                &folder,
                None,
                &ip,
                Some(&details),
            )
            .await;
            Json(json!({"ok": true})).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// GET /api/addressbook/folders/:scope/:folder/config — Read the stored
/// FolderConfig (allowed_groups, description). Admin only — used by the
/// folder modal to prefill the allowed-groups picker on edit.
pub async fn ab_get_folder_config(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
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

    match vault.get_folder_config(&scope, &folder).await {
        Ok(cfg) => Json(json!({
            "allowed_groups": cfg.allowed_groups,
            "allowed_users": cfg.allowed_users,
            "description": cfg.description,
            "display_name": cfg.display_name,
            "inherit_from_parent": cfg.inherit_from_parent,
        }))
        .into_response(),
        Err(crate::vault::VaultError::NotFound) => Json(json!({
            "allowed_groups": Vec::<String>::new(),
            "allowed_users": Vec::<String>::new(),
            "description": "",
            "inherit_from_parent": false,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// DELETE /api/addressbook/folders/:scope/:folder — Delete folder and all entries. Admin only.
pub async fn ab_delete_folder(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
) -> impl IntoResponse {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response()
        }
    };

    match vault.delete_folder(&scope, &folder).await {
        Ok((subfolders, entries)) => {
            let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
            let details = json!({
                "subfolders_deleted": subfolders,
                "entries_deleted": entries,
            })
            .to_string();
            log_ab_event(
                &database,
                &admin_email,
                "delete_folder",
                &scope,
                &folder,
                None,
                &ip,
                Some(&details),
            )
            .await;
            Json(json!({
                "ok": true,
                "subfolders_deleted": subfolders,
                "entries_deleted": entries,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// Check an entry body from the API and tidy it for storage: either form
/// (a top-level `type`, or `protocols`), access rules tidied like a
/// folder's, written in the old flat form when that loses nothing.
fn prepare_entry_body(mut e: AddressBookEntry) -> Result<AddressBookEntry, String> {
    e.check_shape().map_err(|e| e.to_string())?;
    fn tidy(
        groups: &mut Option<Vec<String>>,
        users: &mut Option<Vec<String>>,
    ) -> Result<(), String> {
        if let Some(g) = groups.as_mut() {
            let mut out: Vec<String> = Vec::new();
            for x in g.drain(..) {
                let x = x.trim().to_string();
                if !x.is_empty() && !out.contains(&x) {
                    out.push(x);
                }
            }
            *g = out;
        }
        if let Some(u) = users.take() {
            *users = Some(normalize_allowed_users(u)?);
        }
        Ok(())
    }
    tidy(&mut e.allowed_groups, &mut e.allowed_users)?;
    // An empty host rule means no rule: store it as absent.
    if e.allowed_groups.as_ref().is_some_and(Vec::is_empty)
        && e.allowed_users.as_ref().is_none_or(Vec::is_empty)
    {
        e.allowed_groups = None;
    }
    if e.allowed_users.as_ref().is_some_and(Vec::is_empty) && e.allowed_groups.is_none() {
        e.allowed_users = None;
    }
    // A flat body with an access rule goes to the list form, which older
    // instances cannot read: in the flat form they would read the entry and
    // ignore the rule, showing it to the whole folder.
    if !e.has_protocol_list() && (e.allowed_groups.is_some() || e.allowed_users.is_some()) {
        let (mut host, protocols) = e.split();
        host.protocols = Some(protocols);
        e = host;
    }
    if let Some(protocols) = e.protocols.as_mut() {
        for p in protocols.iter_mut() {
            tidy(&mut p.allowed_groups, &mut p.allowed_users)?;
            if p.name.as_deref() == Some(p.session_type.as_str()) {
                p.name = None;
            }
        }
    }
    Ok(e.compact())
}

/// Audit details of an entry write: headline only, the protocol types.
/// `moved_from` is `Some` for an update (`Some(None)`: not moved).
fn entry_audit_details(e: &AddressBookEntry, moved_from: Option<Option<&MovedFrom>>) -> String {
    let types = e.protocol_types();
    let mut d = json!({ "type": types.first().cloned().unwrap_or_default() });
    if types.len() > 1 {
        d["protocols"] = json!(types);
    }
    if let Some(from) = moved_from {
        d["moved_from"] = json!(from);
    }
    d.to_string()
}

#[derive(Deserialize)]
pub struct CreateEntryRequest {
    pub name: String,
    #[serde(flatten)]
    pub entry: AddressBookEntry,
}

/// POST /api/addressbook/folders/:scope/:folder/entries — Create/update an entry. Admin only.
#[allow(clippy::too_many_arguments)]
pub async fn ab_create_entry(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
    Json(req): Json<CreateEntryRequest>,
) -> impl IntoResponse {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response()
        }
    };

    let entry = match prepare_entry_body(req.entry) {
        Ok(e) => e,
        Err(msg) => return ab_error(StatusCode::BAD_REQUEST, msg),
    };
    let details = entry_audit_details(&entry, None);
    match vault.put_entry(&scope, &folder, &req.name, &entry).await {
        Ok(()) => {
            let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
            log_ab_event(
                &database,
                &admin_email,
                "create_entry",
                &scope,
                &folder,
                Some(&req.name),
                &ip,
                Some(&details),
            )
            .await;
            (StatusCode::CREATED, Json(json!({"ok": true}))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// Query string of `PUT .../entries/:entry`.
#[derive(Deserialize, Default)]
pub struct EntryPutQuery {
    /// `?move=true`: before the update, find the entry whose `external_id`
    /// matches the body's anywhere in the scope and move it here, secrets
    /// included, so a synced device that changes folder or name is moved
    /// rather than duplicated. Needs `external_id` in the body; the name is
    /// never used to match across folders.
    #[serde(rename = "move", default)]
    pub move_: bool,
}

/// The entry storage the update and move paths work on. A trait, like
/// `FolderSource`, so the locate / move / merge sequence of
/// `PUT ...?move=true` is unit-testable without a live Vault.
#[allow(async_fn_in_trait)]
trait EntryStore {
    /// Every folder path in `scope`, top level and below.
    async fn folder_paths(&self, scope: &str) -> Result<Vec<String>, VaultError>;
    /// Entry names in one folder, subfolders excluded.
    async fn entry_names(&self, scope: &str, folder: &str) -> Result<Vec<String>, VaultError>;
    /// The full entry, secrets included.
    async fn get_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<AddressBookEntry, VaultError>;
    async fn put_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
    ) -> Result<(), VaultError>;
    /// Write only if nothing is stored there; `Ok(false)` when something is.
    async fn put_entry_if_absent(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
    ) -> Result<bool, VaultError>;
    async fn delete_entry(&self, scope: &str, folder: &str, entry: &str) -> Result<(), VaultError>;
}

impl EntryStore for VaultBackends {
    async fn folder_paths(&self, scope: &str) -> Result<Vec<String>, VaultError> {
        let client = self.scoped(scope).await?;
        let mut queue: Vec<String> = client
            .list_folders_in_scope(scope)
            .await?
            .into_iter()
            .map(|f| f.path.unwrap_or(f.name))
            .collect();
        let mut out = Vec::new();
        while let Some(path) = queue.pop() {
            match client.list_subfolders(scope, &path).await {
                Ok(subs) => {
                    for s in subs {
                        queue.push(s.path.unwrap_or_else(|| format!("{path}/{}", s.name)));
                    }
                }
                // Emptied since it was listed.
                Err(VaultError::NotFound) => {}
                Err(e) => return Err(e),
            }
            out.push(path);
        }
        Ok(out)
    }

    async fn entry_names(&self, scope: &str, folder: &str) -> Result<Vec<String>, VaultError> {
        // The KV listing also returns subfolders, as `name/`.
        match VaultBackends::list_entries(self, scope, folder).await {
            Ok(names) => Ok(names.into_iter().filter(|n| !n.ends_with('/')).collect()),
            Err(VaultError::NotFound) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    async fn get_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<AddressBookEntry, VaultError> {
        VaultBackends::get_entry(self, scope, folder, entry).await
    }

    async fn put_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
    ) -> Result<(), VaultError> {
        VaultBackends::put_entry(self, scope, folder, entry, data).await
    }

    async fn put_entry_if_absent(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
    ) -> Result<bool, VaultError> {
        VaultBackends::put_entry_if_absent(self, scope, folder, entry, data).await
    }

    async fn delete_entry(&self, scope: &str, folder: &str, entry: &str) -> Result<(), VaultError> {
        VaultBackends::delete_entry(self, scope, folder, entry).await
    }
}

/// An update merged onto the stored entry: anything the request carries
/// wins, and every secret it omits is kept, because neither the edit form
/// (which never receives secrets) nor a sync source such as the NetBox
/// webhook (which has none) can send them back. Jump host credentials are
/// kept per hop by index; `external_id` is kept the same way so an edit
/// from the form does not cut a synced entry loose from its source.
///
/// Both sides are taken as a host and its protocols (#296), so an old flat
/// body and an old flat stored entry each count as one protocol. The host's
/// secrets are kept as above, and each protocol's are kept from the stored
/// protocol of the same name, or of the name in its `renamed_from` when it
/// is being renamed; when both sides have exactly one protocol the
/// two are paired whatever their names, so an old flat body that changes
/// an entry's type keeps its secrets as it always did. The request's list
/// of protocols is the entry's list. The result is written in the old flat
/// form whenever that loses nothing (`AddressBookEntry::compact`).
fn merge_entry_update(data: AddressBookEntry, existing: AddressBookEntry) -> AddressBookEntry {
    let (data_host, mut data_protocols) = data.split();
    let (existing_host, existing_protocols) = existing.split();
    let mut host = merge_host_update(data_host, existing_host);
    let pair_singles = data_protocols.len() == 1 && existing_protocols.len() == 1;
    for p in &mut data_protocols {
        let was = match p.renamed_from.take().filter(|n| !n.is_empty()) {
            Some(n) => n,
            None => p.name().to_string(),
        };
        let old = existing_protocols
            .iter()
            .find(|o| o.name() == was)
            .or(if pair_singles {
                existing_protocols.first()
            } else {
                None
            });
        if let Some(old) = old {
            crate::entry_protocols::keep_secrets(&mut p.settings, &old.settings);
        }
    }
    host.protocols = Some(data_protocols);
    host.session_type = String::new();
    host.compact()
}

/// `merge_entry_update` for the host's own fields.
fn merge_host_update(data: AddressBookEntry, existing: AddressBookEntry) -> AddressBookEntry {
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
                    host_key: hop
                        .host_key
                        .clone()
                        .or_else(|| old.and_then(|o| o.host_key.clone())),
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
        container_password: data.container_password.or(existing.container_password),
        proxmox_token_secret: data.proxmox_token_secret.or(existing.proxmox_token_secret),
        external_id: data.external_id.or(existing.external_id),
        jump_hosts: merged_jump_hosts,
        // Clear legacy flat fields — they've been migrated
        jump_password: None,
        jump_private_key: None,
        ..data
    }
}

/// Where `PUT ...?move=true` found the entry before bringing it to the
/// requested folder and name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct MovedFrom {
    folder: String,
    name: String,
}

/// Why an upsert did not complete.
#[derive(Debug)]
enum UpsertError {
    /// Nothing was changed.
    Rejected(StatusCode, String),
    /// The entry was copied to the requested folder but the original could
    /// not be removed, so it now exists in both; the update was not applied.
    MoveIncomplete { from: MovedFrom, error: VaultError },
    /// The write of the update failed, after the move if there was one.
    UpdateFailed {
        moved_from: Option<MovedFrom>,
        error: VaultError,
    },
}

/// `?move=true`: find the entry stored under `external_id` in `scope` and
/// bring it to `folder`/`entry`, with everything stored in it, before the
/// update is applied. Returns where it came from, or `None` when nothing
/// had to move (it is already there, or there is no such entry yet).
///
/// Matching is on `external_id` only. Entries elsewhere in the scope that
/// merely share the name are not the same device (two tenants can each
/// have a `fw01`) and are never touched.
async fn relocate_by_external_id<S: EntryStore>(
    store: &S,
    scope: &str,
    folder: &str,
    entry: &str,
    external_id: &str,
) -> Result<Option<MovedFrom>, UpsertError> {
    let reject = |e: VaultError| {
        let (status, msg) = ab_vault_error(e);
        UpsertError::Rejected(status, msg)
    };

    // Already here: the steady state of a sync, and the only case that
    // needs no scan.
    let adopting = match store.get_entry(scope, folder, entry).await {
        Ok(existing) => match existing.external_id.as_deref() {
            Some(other) if other != external_id => {
                return Err(UpsertError::Rejected(
                    StatusCode::CONFLICT,
                    format!("{folder}/{entry} belongs to another device (external_id {other})"),
                ))
            }
            Some(_) => return Ok(None),
            // An entry made by hand before syncing began: it is updated in
            // place and adopts the id, but only once the scan below shows no
            // other entry already carries it, or the id would end up on two.
            None => true,
        },
        Err(VaultError::NotFound) => false,
        Err(e) => return Err(reject(e)),
    };

    let mut found = Vec::new();
    for other_folder in store.folder_paths(scope).await.map_err(reject)? {
        for name in store
            .entry_names(scope, &other_folder)
            .await
            .map_err(reject)?
        {
            if other_folder == folder && name == entry {
                continue;
            }
            let stored = match store.get_entry(scope, &other_folder, &name).await {
                Ok(e) => e,
                Err(VaultError::NotFound) => continue, // deleted since it was listed
                Err(e) => return Err(reject(e)),
            };
            if stored.external_id.as_deref() == Some(external_id) {
                found.push(MovedFrom {
                    folder: other_folder.clone(),
                    name,
                });
            }
        }
    }

    if adopting && !found.is_empty() {
        let where_ = found
            .iter()
            .map(|f| format!("{}/{}", f.folder, f.name))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(UpsertError::Rejected(
            StatusCode::CONFLICT,
            format!(
                "{folder}/{entry} is an entry without an external_id, and external_id {external_id} \
                 is already stored on {where_}; nothing was changed"
            ),
        ));
    }

    match found.len() {
        0 => Ok(None),
        1 => {
            let from = found.remove(0);
            match move_stored_entry(store, scope, &from.folder, &from.name, scope, folder, entry)
                .await
            {
                Ok(_) => Ok(Some(from)),
                Err(MoveError::Copy(status, msg)) => Err(UpsertError::Rejected(status, msg)),
                Err(MoveError::Incomplete(error)) => {
                    Err(UpsertError::MoveIncomplete { from, error })
                }
            }
        }
        n => {
            let where_ = found
                .iter()
                .map(|f| format!("{}/{}", f.folder, f.name))
                .collect::<Vec<_>>()
                .join(", ");
            Err(UpsertError::Rejected(
                StatusCode::CONFLICT,
                format!("external_id {external_id} is stored on {n} entries ({where_}); nothing was changed"),
            ))
        }
    }
}

/// What a completed upsert wrote, and where the entry came from if
/// `?move=true` moved it.
#[derive(Debug)]
struct UpsertOutcome {
    moved_from: Option<MovedFrom>,
    entry: AddressBookEntry,
}

/// `PUT .../entries/:entry` without the HTTP: locate (and move) by
/// `external_id` when asked, then read-modify-write so the request's fields
/// land on top of everything stored, secrets included.
async fn upsert_entry<S: EntryStore>(
    store: &S,
    scope: &str,
    folder: &str,
    entry: &str,
    data: AddressBookEntry,
    move_: bool,
) -> Result<UpsertOutcome, UpsertError> {
    let moved_from = if move_ {
        let Some(external_id) = data.external_id.as_deref().filter(|id| !id.is_empty()) else {
            return Err(UpsertError::Rejected(
                StatusCode::BAD_REQUEST,
                "move=true needs external_id in the body: the entry is matched on it, not on its name"
                    .into(),
            ));
        };
        relocate_by_external_id(store, scope, folder, entry, external_id).await?
    } else {
        None
    };

    let merged = match store.get_entry(scope, folder, entry).await {
        Ok(existing) => merge_entry_update(data, existing),
        Err(VaultError::NotFound) => data,
        // Writing the request as-is here would replace a stored entry with
        // one that has no secrets, so a failed read is an error, not a create.
        Err(error) => return Err(UpsertError::UpdateFailed { moved_from, error }),
    };

    match store.put_entry(scope, folder, entry, &merged).await {
        Ok(()) => Ok(UpsertOutcome {
            moved_from,
            entry: merged,
        }),
        Err(error) => Err(UpsertError::UpdateFailed { moved_from, error }),
    }
}

/// PUT /api/addressbook/folders/:scope/:folder/entries/:entry — Update an entry,
/// creating it if there is none. Admin only.
///
/// Read-modify-write: the stored entry is read first and the request's
/// fields are merged on top, so credentials the request omits are kept (see
/// `merge_entry_update`). With `?move=true` the entry is first located by
/// `external_id` anywhere in the scope and moved here, credentials included,
/// by the same path as `POST .../move` (see `relocate_by_external_id`).
#[allow(clippy::too_many_arguments)]
pub async fn ab_update_entry(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder, entry)): Path<(String, String, String)>,
    Query(query): Query<EntryPutQuery>,
    Json(data): Json<AddressBookEntry>,
) -> impl IntoResponse {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response()
        }
    };
    let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
    let data = match prepare_entry_body(data) {
        Ok(e) => e,
        Err(msg) => return ab_error(StatusCode::BAD_REQUEST, msg),
    };
    let external_id = data.external_id.clone();

    let result = upsert_entry(vault.as_ref(), &scope, &folder, &entry, data, query.move_).await;

    // A move that happened is recorded whatever came after it, as the move
    // endpoint records it, so the audit log says where the entry went.
    let (moved_from, incomplete) = match &result {
        Ok(outcome) => (outcome.moved_from.as_ref(), false),
        Err(UpsertError::UpdateFailed { moved_from, .. }) => (moved_from.as_ref(), false),
        Err(UpsertError::MoveIncomplete { from, .. }) => (Some(from), true),
        Err(UpsertError::Rejected(..)) => (None, false),
    };
    if let Some(from) = moved_from {
        let details = json!({
            "to_scope": scope,
            "to_folder": folder,
            "to_name": entry,
            "external_id": external_id,
        })
        .to_string();
        log_ab_event(
            &database,
            &admin_email,
            if incomplete {
                "move_entry_incomplete"
            } else {
                "move_entry"
            },
            &scope,
            &from.folder,
            Some(&from.name),
            &ip,
            Some(&details),
        )
        .await;
    }
    // The live refresh hears about the target folder from the request path;
    // a move also changed the folder the entry came from, and did so even
    // when what came after it failed.
    let moved_changes = moved_from
        .map(|from| upsert_move_changes(&scope, &from.folder, &folder))
        .unwrap_or_default();

    let response = match result {
        Ok(outcome) => {
            let details = entry_audit_details(&outcome.entry, Some(outcome.moved_from.as_ref()));
            log_ab_event(
                &database,
                &admin_email,
                "update_entry",
                &scope,
                &folder,
                Some(&entry),
                &ip,
                Some(&details),
            )
            .await;
            match outcome.moved_from {
                Some(from) => Json(json!({"ok": true, "moved_from": from})).into_response(),
                None => Json(json!({"ok": true})).into_response(),
            }
        }
        Err(UpsertError::Rejected(status, msg)) => ab_error(status, msg),
        Err(UpsertError::MoveIncomplete { error, .. }) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": format!(
                    "entry was copied to the target folder but the original could not be removed: {error}"
                ),
                "copied": true,
            })),
        )
            .into_response(),
        Err(UpsertError::UpdateFailed { error, .. }) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    };
    if moved_changes.is_empty() {
        response
    } else {
        with_ab_changes(response, moved_changes)
    }
}

/// The folders a `PUT ...?move=true` that moved an entry changed: the one
/// it came from and the one it went to (both in the request's scope).
fn upsert_move_changes(scope: &str, from_folder: &str, to_folder: &str) -> Vec<AbChange> {
    let mut changes = vec![AbChange::entries(scope, from_folder)];
    if from_folder != to_folder {
        changes.push(AbChange::entries(scope, to_folder));
    }
    changes
}

/// Body for `POST .../entries/{entry}/move` and `.../copy`.
#[derive(Deserialize)]
pub struct MoveEntryRequest {
    pub target_scope: String,
    pub target_folder: String,
    /// Copy only: the name of the new entry. Defaults to the source name.
    #[serde(default)]
    pub new_name: Option<String>,
}

fn ab_error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

/// Copy an entry as stored in Vault, secrets included, to a target that
/// must not already exist. Returns what was copied.
///
/// The browser cannot do this itself: it never receives an entry's secrets
/// (password, private key, jump host credentials, tokens, or a `$variable`
/// reference held in the password field), so a copy built from the edit
/// form silently dropped all of them (#232).
///
/// Every endpoint that uses this is admin-only, like every other change to
/// connection entries. If editing is ever delegated per folder (#231), they
/// must require edit rights on the source AND the target: copying moves
/// working credentials, so rights on the target alone would let an editor
/// pull them out of a folder they cannot reach into one they can, and
/// connect with them there.
async fn copy_stored_entry<S: EntryStore>(
    store: &S,
    scope: &str,
    folder: &str,
    entry: &str,
    target_scope: &str,
    target_folder: &str,
    target_name: &str,
) -> Result<AddressBookEntry, (StatusCode, String)> {
    let full = store
        .get_entry(scope, folder, entry)
        .await
        .map_err(ab_vault_error)?;
    // Vault refuses the write if anything already exists at the target, so
    // an entry is never overwritten even by a concurrent writer.
    match store
        .put_entry_if_absent(target_scope, target_folder, target_name, &full)
        .await
    {
        Ok(true) => Ok(full),
        Ok(false) => Err((
            StatusCode::CONFLICT,
            "an entry with that name already exists in the target folder".into(),
        )),
        Err(e) => Err(ab_vault_error(e)),
    }
}

/// Why a move did not complete.
#[derive(Debug)]
enum MoveError {
    /// Nothing was changed: the copy to the target was refused.
    Copy(StatusCode, String),
    /// The copy is in place but the original could not be removed, so the
    /// entry now exists in both folders.
    Incomplete(VaultError),
}

/// Move an entry with everything stored in it: the full entry is copied to
/// the target and only then is the original removed, so a failure leaves it
/// in both folders rather than in neither. This is the server-side move
/// behind `POST .../move`; `PUT ...?move=true` goes through it too.
#[allow(clippy::too_many_arguments)]
async fn move_stored_entry<S: EntryStore>(
    store: &S,
    scope: &str,
    folder: &str,
    entry: &str,
    target_scope: &str,
    target_folder: &str,
    target_name: &str,
) -> Result<AddressBookEntry, MoveError> {
    let full = copy_stored_entry(
        store,
        scope,
        folder,
        entry,
        target_scope,
        target_folder,
        target_name,
    )
    .await
    .map_err(|(status, msg)| MoveError::Copy(status, msg))?;
    store
        .delete_entry(scope, folder, entry)
        .await
        .map_err(MoveError::Incomplete)?;
    Ok(full)
}

/// Status for a Vault error on the move/copy path: a rejected name or
/// scope is the caller's mistake, not the backend's.
fn ab_vault_error(e: VaultError) -> (StatusCode, String) {
    match e {
        VaultError::NotFound => (StatusCode::NOT_FOUND, "entry not found".into()),
        VaultError::BadName(msg) => (StatusCode::BAD_REQUEST, msg),
        other => (StatusCode::BAD_GATEWAY, other.to_string()),
    }
}

fn require_ab_admin(
    identity: &Option<Extension<AuthIdentity>>,
) -> Result<String, (StatusCode, String)> {
    match identity {
        Some(Extension(id)) if id.has_role("admin") => Ok(id.display_name().to_string()),
        _ => Err((StatusCode::FORBIDDEN, "admin role required".into())),
    }
}

/// POST /api/addressbook/folders/:scope/:folder/entries/:entry/move
///
/// Moves an entry with everything stored in it: the full entry is copied to
/// the target and only then is the original removed. An existing entry of
/// the same name in the target is never overwritten.
#[allow(clippy::too_many_arguments)]
pub async fn ab_move_entry(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder, entry)): Path<(String, String, String)>,
    Json(req): Json<MoveEntryRequest>,
) -> impl IntoResponse {
    let admin_email = match require_ab_admin(&identity) {
        Ok(e) => e,
        Err((status, msg)) => return ab_error(status, msg),
    };
    if req.target_scope == scope && req.target_folder == folder {
        return ab_error(StatusCode::BAD_REQUEST, "entry is already in that folder");
    }

    let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
    let details = json!({
        "to_scope": req.target_scope,
        "to_folder": req.target_folder,
    })
    .to_string();

    match move_stored_entry(
        vault.as_ref(),
        &scope,
        &folder,
        &entry,
        &req.target_scope,
        &req.target_folder,
        &entry,
    )
    .await
    {
        Ok(_) => {}
        Err(MoveError::Copy(status, msg)) => return ab_error(status, msg),
        // The copy is in place, so the entry is in both folders rather than
        // in neither. Say so instead of reporting a plain error the caller
        // might answer by retrying.
        Err(MoveError::Incomplete(e)) => {
            log_ab_event(
                &database,
                &admin_email,
                "move_entry_incomplete",
                &scope,
                &folder,
                Some(&entry),
                &ip,
                Some(&details),
            )
            .await;
            // The target folder did change: tell the live refresh, though
            // the request failed.
            return with_ab_changes(
                (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "error": format!(
                            "entry was copied to the target folder but the original could not be removed: {e}"
                        ),
                        "copied": true,
                    })),
                )
                    .into_response(),
                vec![
                    AbChange::entries(&scope, &folder),
                    AbChange::entries(&req.target_scope, &req.target_folder),
                ],
            );
        }
    }

    log_ab_event(
        &database,
        &admin_email,
        "move_entry",
        &scope,
        &folder,
        Some(&entry),
        &ip,
        Some(&details),
    )
    .await;
    with_ab_changes(
        (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        vec![
            AbChange::entries(&scope, &folder),
            AbChange::entries(&req.target_scope, &req.target_folder),
        ],
    )
}

/// Most entries one bulk request may name.
const BULK_MAX_ITEMS: usize = 1000;
/// Entries processed at once within a bulk request.
const BULK_CONCURRENCY: usize = 8;
/// Highest suffix tried when renaming around a clash (`name-2` .. `name-N`).
const BULK_MAX_RENAME: u32 = 99;

#[derive(Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct BulkItem {
    pub scope: String,
    pub folder: String,
    pub name: String,
}

#[derive(Deserialize, Clone)]
pub struct BulkTarget {
    pub scope: String,
    pub folder: String,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum BulkAction {
    Move,
    Copy,
    Delete,
}

/// What to do when the target already has an entry of the same name.
#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Default, Debug)]
#[serde(rename_all = "lowercase")]
pub enum OnConflict {
    /// Leave that entry where it is and report it as skipped.
    #[default]
    Skip,
    /// Use the first free `name-2`, `name-3`, ... instead.
    Rename,
}

#[derive(Deserialize)]
pub struct BulkRequest {
    pub action: BulkAction,
    pub items: Vec<BulkItem>,
    #[serde(default)]
    pub target: Option<BulkTarget>,
    #[serde(default)]
    pub on_conflict: OnConflict,
}

/// Names to try for an entry copied around a clash: the name itself, then
/// `name-2` .. `name-99`, trimming the base so every candidate stays within
/// Vault's 64-character name limit.
fn rename_candidates(name: &str, rename: bool) -> Vec<String> {
    let mut out = vec![name.to_string()];
    if rename {
        for n in 2..=BULK_MAX_RENAME {
            let suffix = format!("-{n}");
            let keep = 64usize.saturating_sub(suffix.len()).min(name.len());
            // Names are validated ASCII, so a byte cut is a char boundary.
            out.push(format!("{}{}", &name[..keep], suffix));
        }
    }
    out
}

/// Copy a stored entry, secrets included, into the target folder under the
/// first free name allowed by `on_conflict`. Returns the name used, or
/// `None` when the name was taken and the policy is to skip.
async fn copy_entry_into(
    vault: &VaultState,
    item: &BulkItem,
    target: &BulkTarget,
    on_conflict: OnConflict,
) -> Result<Option<String>, (StatusCode, String)> {
    let full = vault
        .get_entry(&item.scope, &item.folder, &item.name)
        .await
        .map_err(ab_vault_error)?;
    for candidate in rename_candidates(&item.name, on_conflict == OnConflict::Rename) {
        // Vault refuses the write if anything exists there, so a clash is
        // detected atomically and nothing is ever overwritten.
        match vault
            .put_entry_if_absent(&target.scope, &target.folder, &candidate, &full)
            .await
        {
            Ok(true) => return Ok(Some(candidate)),
            Ok(false) => continue,
            Err(e) => return Err(ab_vault_error(e)),
        }
    }
    if on_conflict == OnConflict::Rename {
        Err((
            StatusCode::CONFLICT,
            "no free name found for the copy".into(),
        ))
    } else {
        Ok(None)
    }
}

/// One entry of a bulk request, handled on its own so a failure never
/// affects the others. Audits what it did.
async fn bulk_one(
    vault: &VaultState,
    database: &Db,
    admin_email: &str,
    ip: &str,
    req: &BulkRequest,
    item: &BulkItem,
) -> serde_json::Value {
    let mut result = json!({
        "scope": item.scope,
        "folder": item.folder,
        "name": item.name,
    });
    let set = |r: &mut serde_json::Value, k: &str, v: serde_json::Value| {
        r[k] = v;
    };

    if req.action == BulkAction::Delete {
        // Vault reports success for deleting a path that does not exist, so
        // look first: otherwise a missing entry would be reported (and
        // audited) as deleted.
        if let Err(e) = vault.get_entry(&item.scope, &item.folder, &item.name).await {
            let (_, msg) = ab_vault_error(e);
            set(&mut result, "status", json!("failed"));
            set(&mut result, "error", json!(msg));
            return result;
        }
        match vault
            .delete_entry(&item.scope, &item.folder, &item.name)
            .await
        {
            Ok(()) => {
                log_ab_event(
                    database,
                    admin_email,
                    "delete_entry",
                    &item.scope,
                    &item.folder,
                    Some(&item.name),
                    ip,
                    Some(r#"{"bulk":true}"#),
                )
                .await;
                set(&mut result, "status", json!("deleted"));
            }
            Err(e) => {
                let (_, msg) = ab_vault_error(e);
                set(&mut result, "status", json!("failed"));
                set(&mut result, "error", json!(msg));
            }
        }
        return result;
    }

    // Move and copy both have a target (checked by the caller).
    let target = req.target.as_ref().expect("target checked");
    if req.action == BulkAction::Move && item.scope == target.scope && item.folder == target.folder
    {
        set(&mut result, "status", json!("skipped"));
        set(&mut result, "error", json!("already in that folder"));
        return result;
    }

    let used = match copy_entry_into(vault, item, target, req.on_conflict).await {
        Ok(Some(name)) => name,
        Ok(None) => {
            set(&mut result, "status", json!("skipped"));
            set(
                &mut result,
                "error",
                json!("an entry with that name already exists in the target folder"),
            );
            return result;
        }
        Err((_, msg)) => {
            set(&mut result, "status", json!("failed"));
            set(&mut result, "error", json!(msg));
            return result;
        }
    };
    if used != item.name {
        set(&mut result, "new_name", json!(used));
    }
    let details = json!({
        "bulk": true,
        "to_scope": target.scope,
        "to_folder": target.folder,
        "to_name": used,
    })
    .to_string();

    if req.action == BulkAction::Copy {
        log_ab_event(
            database,
            admin_email,
            "copy_entry",
            &item.scope,
            &item.folder,
            Some(&item.name),
            ip,
            Some(&details),
        )
        .await;
        set(&mut result, "status", json!("copied"));
        return result;
    }

    // Move: the copy is in place, so a failed removal leaves the entry in
    // both folders, never in neither. Report that distinctly.
    match vault
        .delete_entry(&item.scope, &item.folder, &item.name)
        .await
    {
        Ok(()) => {
            log_ab_event(
                database,
                admin_email,
                "move_entry",
                &item.scope,
                &item.folder,
                Some(&item.name),
                ip,
                Some(&details),
            )
            .await;
            set(&mut result, "status", json!("moved"));
        }
        Err(e) => {
            log_ab_event(
                database,
                admin_email,
                "move_entry_incomplete",
                &item.scope,
                &item.folder,
                Some(&item.name),
                ip,
                Some(&details),
            )
            .await;
            set(&mut result, "status", json!("copied_not_removed"));
            set(
                &mut result,
                "error",
                json!(format!(
                    "copied, but the original could not be removed: {}",
                    ab_vault_error(e).1
                )),
            );
        }
    }
    result
}

/// POST /api/addressbook/bulk
///
/// Move, copy or delete many entries in one request. Each entry is handled
/// on its own, through the same stored-entry copy as the single-entry
/// endpoints (credentials included, never overwriting), and the response
/// reports what happened to each. Admin only. See `copy_stored_entry` for
/// the rule any future per-folder delegation must follow.
pub async fn ab_bulk(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Json(req): Json<BulkRequest>,
) -> impl IntoResponse {
    use futures_util::StreamExt;

    let admin_email = match require_ab_admin(&identity) {
        Ok(e) => e,
        Err((status, msg)) => return ab_error(status, msg),
    };
    if req.items.is_empty() {
        return ab_error(StatusCode::BAD_REQUEST, "no entries given");
    }
    if req.items.len() > BULK_MAX_ITEMS {
        return ab_error(
            StatusCode::BAD_REQUEST,
            format!("at most {BULK_MAX_ITEMS} entries per request"),
        );
    }
    if req.action != BulkAction::Delete && req.target.is_none() {
        return ab_error(StatusCode::BAD_REQUEST, "move and copy need a target");
    }

    // The same entry named twice would race itself (a move whose source is
    // gone by the second pass), so act on each once.
    let mut seen = std::collections::HashSet::new();
    let items: Vec<BulkItem> = req
        .items
        .iter()
        .filter(|i| seen.insert((*i).clone()))
        .cloned()
        .collect();

    let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
    // Each future owns what it uses: borrowing into a buffered stream does
    // not satisfy the handler's Send bound.
    let req = Arc::new(req);
    let results: Vec<serde_json::Value> = futures_util::stream::iter(items)
        .map(|item| {
            let (vault, database, admin_email, ip, req) = (
                vault.clone(),
                database.clone(),
                admin_email.clone(),
                ip.clone(),
                req.clone(),
            );
            async move { bulk_one(&vault, &database, &admin_email, &ip, &req, &item).await }
        })
        .buffered(BULK_CONCURRENCY)
        .collect()
        .await;

    let mut summary = std::collections::BTreeMap::<String, usize>::new();
    for r in &results {
        if let Some(s) = r["status"].as_str() {
            *summary.entry(s.to_string()).or_default() += 1;
        }
    }
    // Every source folder and the target, for the change log; which of them
    // actually changed is not worth a per-item account.
    let mut touched: Vec<AbChange> = Vec::new();
    for item in &req.items {
        let c = AbChange::entries(&item.scope, &item.folder);
        if !touched.contains(&c) {
            touched.push(c);
        }
    }
    if let Some(t) = &req.target {
        let c = AbChange::entries(&t.scope, &t.folder);
        if !touched.contains(&c) {
            touched.push(c);
        }
    }
    with_ab_changes(
        (
            StatusCode::OK,
            Json(json!({ "results": results, "summary": summary })),
        )
            .into_response(),
        touched,
    )
}

/// GET /api/addressbook/folder-paths
///
/// Every folder in both scopes, for the bulk move/copy picker. Admin only,
/// as it is only used to choose where entries go. The tree view loads
/// subfolders lazily, so it cannot supply this itself.
pub async fn ab_folder_paths(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
) -> impl IntoResponse {
    if let Err((status, msg)) = require_ab_admin(&identity) {
        return ab_error(status, msg);
    }
    let (top, unavailable) = match vault.list_all_folders().await {
        Ok(t) => t,
        Err(e) => return ab_error(StatusCode::BAD_GATEWAY, e.to_string()),
    };
    let mut queue: Vec<(String, String)> = top
        .into_iter()
        .map(|f| (f.scope, f.path.unwrap_or(f.name)))
        .collect();
    let mut folders = Vec::new();
    while let Some((scope, path)) = queue.pop() {
        if let Ok(subs) = vault.list_subfolders(&scope, &path).await {
            for s in subs {
                queue.push((scope.clone(), s.path.unwrap_or_else(|| s.name.clone())));
            }
        }
        folders.push(json!({ "scope": scope, "path": path }));
    }
    folders.sort_by(|a, b| {
        (a["scope"].as_str(), a["path"].as_str()).cmp(&(b["scope"].as_str(), b["path"].as_str()))
    });
    Json(json!({ "folders": folders, "unavailable": unavailable })).into_response()
}

/// POST /api/addressbook/folders/:scope/:folder/entries/:entry/copy
///
/// Copies an entry with everything stored in it, under `new_name` in the
/// target folder. Used by Clone, which then applies the form's edits with
/// an ordinary update (which keeps stored secrets it is not given).
#[allow(clippy::too_many_arguments)]
pub async fn ab_copy_entry(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder, entry)): Path<(String, String, String)>,
    Json(req): Json<MoveEntryRequest>,
) -> impl IntoResponse {
    let admin_email = match require_ab_admin(&identity) {
        Ok(e) => e,
        Err((status, msg)) => return ab_error(status, msg),
    };
    let new_name = req.new_name.clone().unwrap_or_else(|| entry.clone());
    if req.target_scope == scope && req.target_folder == folder && new_name == entry {
        return ab_error(StatusCode::BAD_REQUEST, "copy needs a new name or folder");
    }
    if let Err((status, msg)) = copy_stored_entry(
        vault.as_ref(),
        &scope,
        &folder,
        &entry,
        &req.target_scope,
        &req.target_folder,
        &new_name,
    )
    .await
    {
        return ab_error(status, msg);
    }
    let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
    let details = json!({
        "to_scope": req.target_scope,
        "to_folder": req.target_folder,
        "to_name": new_name,
    })
    .to_string();
    log_ab_event(
        &database,
        &admin_email,
        "copy_entry",
        &scope,
        &folder,
        Some(&entry),
        &ip,
        Some(&details),
    )
    .await;
    with_ab_changes(
        (StatusCode::CREATED, Json(json!({"ok": true}))).into_response(),
        vec![
            AbChange::entries(&scope, &folder),
            AbChange::entries(&req.target_scope, &req.target_folder),
        ],
    )
}

/// DELETE /api/addressbook/folders/:scope/:folder/entries/:entry — Delete an entry. Admin only.
pub async fn ab_delete_entry(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder, entry)): Path<(String, String, String)>,
) -> impl IntoResponse {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response()
        }
    };

    // Vault reports success for deleting a path that does not exist, so
    // look first rather than answer (and audit) a delete of nothing.
    match vault.get_entry(&scope, &folder, &entry).await {
        Ok(_) => {}
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
    }

    match vault.delete_entry(&scope, &folder, &entry).await {
        Ok(()) => {
            let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
            log_ab_event(
                &database,
                &admin_email,
                "delete_entry",
                &scope,
                &folder,
                Some(&entry),
                &ip,
                None,
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
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

// ── User credential variables ──

/// Mask a credential value for the UI: never echo a stored secret back.
fn mask_credential(name: &str, value: &str, scope: &str) -> serde_json::Value {
    let display = if value.is_empty() {
        String::new()
    } else if name.ends_with("_password") || name.ends_with("_key") {
        "••••••••".to_string()
    } else {
        value.to_string()
    };
    json!({ "set": !value.is_empty(), "display": display, "scope": scope })
}

/// Compute the (local, shared) credential maps to persist from a save batch,
/// preserving untouched keys and honouring "leave blank = keep".
///
/// - `existing_local` / `existing_shared`: current stored maps. Single-Vault
///   passes the one store as `existing_local` with an empty `existing_shared`.
/// - `incoming`: name -> value for the keys being saved (blank value = keep the
///   existing value, moving it to the target scope if that changed).
/// - `scopes`: name -> "shared"|"local" target for touched keys.
/// - `default_scope`: fallback when a touched key has no explicit scope.
/// - `split`: false in single-Vault — everything lands in the returned local
///   map (the caller writes it once) and the shared map stays empty.
fn partition_credential_writes(
    mut existing_local: std::collections::HashMap<String, String>,
    mut existing_shared: std::collections::HashMap<String, String>,
    incoming: &std::collections::HashMap<String, String>,
    scopes: &std::collections::HashMap<String, String>,
    default_scope: &str,
    split: bool,
) -> (
    std::collections::HashMap<String, String>,
    std::collections::HashMap<String, String>,
) {
    for (name, val) in incoming {
        // Resolve the value: keep the existing one when left blank.
        let value = if !val.is_empty() {
            val.clone()
        } else {
            existing_local
                .get(name)
                .or_else(|| existing_shared.get(name))
                .cloned()
                .unwrap_or_default()
        };
        // Blank with no existing value: nothing to store.
        if value.is_empty() {
            existing_local.remove(name);
            existing_shared.remove(name);
            continue;
        }
        let to_shared = split
            && scopes
                .get(name)
                .map(String::as_str)
                .unwrap_or(default_scope)
                == "shared";
        if to_shared {
            existing_shared.insert(name.clone(), value);
            existing_local.remove(name);
        } else {
            existing_local.insert(name.clone(), value);
            existing_shared.remove(name);
        }
    }
    (existing_local, existing_shared)
}

/// GET /api/me/credentials — List own credential variables (names and masked
/// values). Also reports whether the shared/local scope choice is available
/// (`creds_split`) and the default scope for new variables, so the UI can show
/// or hide the per-credential toggle.
pub async fn get_my_credentials(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Extension(default_scope): Extension<CredentialDefaultScope>,
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

    let split = vault.creds_split();
    let local = match vault.get_user_credentials_scoped(&email, false).await {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("Failed to read credentials: {}", e)})),
            )
                .into_response()
        }
    };
    // Shared backend errors are tolerated (its creds just don't show); a
    // central-Vault blip shouldn't block editing local credentials.
    let shared = if split {
        vault
            .get_user_credentials_scoped(&email, true)
            .await
            .unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };

    // Build masked entries; local wins on a name collision, and `scope`
    // reflects where each value currently lives.
    let mut masked = serde_json::Map::new();
    for (k, v) in &shared {
        masked.insert(k.clone(), mask_credential(k, v, "shared"));
    }
    for (k, v) in &local {
        masked.insert(k.clone(), mask_credential(k, v, "local"));
    }

    Json(json!({
        "credentials": masked,
        "creds_split": split,
        "default_scope": default_scope.0,
    }))
    .into_response()
}

/// PUT /api/me/credentials — Save credential variables. Operator+ required.
///
/// Body: `{ "credentials": { name: value }, "scopes": { name: "shared"|"local" } }`.
/// A blank value keeps the existing value (moving it to the target scope if
/// `scopes` changed it); untouched keys are preserved. When only one Vault
/// backend is configured the scope is ignored and everything is written to the
/// single store, so the quick-start path is unchanged.
pub async fn put_my_credentials(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Extension(default_scope): Extension<CredentialDefaultScope>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let email = match identity {
        Some(Extension(AuthIdentity::User {
            ref email,
            ref role,
            ..
        })) if role_level(role) >= role_level("operator") => email.clone(),
        Some(Extension(AuthIdentity::User { .. })) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "operator role required"})),
            )
                .into_response()
        }
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "OIDC authentication required"})),
            )
                .into_response()
        }
    };

    // Expect { "credentials": { "corp_user": "alice", ... } }
    let creds_obj = match body.get("credentials").and_then(|v| v.as_object()) {
        Some(obj) => obj,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "missing or invalid 'credentials' object"})),
            )
                .into_response()
        }
    };

    // Validate variable names: [a-z0-9_-]+
    let mut incoming = std::collections::HashMap::new();
    for (k, v) in creds_obj {
        if !k
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid variable name '{}': use lowercase alphanumeric, underscores and hyphens", k)})),
            )
                .into_response();
        }
        incoming.insert(k.clone(), v.as_str().unwrap_or("").to_string());
    }

    // Optional per-key target scope: { "scopes": { name: "shared"|"local" } }.
    let mut scopes = std::collections::HashMap::new();
    if let Some(obj) = body.get("scopes").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                if s == "shared" || s == "local" {
                    scopes.insert(k.clone(), s.to_string());
                }
            }
        }
    }

    let split = vault.creds_split();

    // Read existing maps. Abort on a hard read error rather than risk writing a
    // partial set (which would drop untouched keys).
    let existing_local = match vault.get_user_credentials_scoped(&email, false).await {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("Failed to read existing credentials: {}", e)})),
            )
                .into_response()
        }
    };
    let existing_shared = if split {
        match vault.get_user_credentials_scoped(&email, true).await {
            Ok(m) => m,
            Err(e) => return (
                StatusCode::BAD_GATEWAY,
                Json(
                    json!({"error": format!("Failed to read existing shared credentials: {}", e)}),
                ),
            )
                .into_response(),
        }
    } else {
        std::collections::HashMap::new()
    };

    let (new_local, new_shared) = partition_credential_writes(
        existing_local,
        existing_shared,
        &incoming,
        &scopes,
        &default_scope.0,
        split,
    );

    // Write the local store first (in single-Vault this is the only store).
    if let Err(e) = vault
        .put_user_credentials_scoped(&email, false, &new_local)
        .await
    {
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": format!("Failed to save credentials: {}", e)})),
        )
            .into_response();
    }
    if split {
        if let Err(e) = vault
            .put_user_credentials_scoped(&email, true, &new_shared)
            .await
        {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("Failed to save shared credentials: {}", e)})),
            )
                .into_response();
        }
    }

    let count = new_local.len() + new_shared.len();
    tracing::info!(user = %email, count, "User credentials updated");
    Json(json!({"ok": true, "count": count})).into_response()
}

/// Abstraction over the folder tree + per-folder access, used to gather
/// credential variables. Kept as a trait so the traversal below is unit-
/// testable without a live Vault.
#[allow(async_fn_in_trait)]
trait FolderSource {
    /// Whether the user may directly access (enter) this folder.
    async fn accessible(&self, scope: &str, path: &str) -> bool;
    /// Full paths of this folder's immediate subfolders.
    async fn subfolders(&self, scope: &str, path: &str) -> Vec<String>;
    /// Credential-variable names referenced by entries in this folder.
    async fn folder_var_names(&self, scope: &str, path: &str) -> Vec<String>;
}

/// Walk the folder tree from `roots`, collecting credential-variable names and
/// their reference counts. Descends into every subfolder so a grant on a deep
/// folder nested under an inaccessible ancestor is still reached (mirroring the
/// connections tree, which shows a folder when a descendant is accessible), but
/// only collects variables from folders the user can directly access.
///
/// This replaced an earlier walk that short-circuited the whole subtree on a
/// directly-inaccessible ancestor, hiding credential variables from any entry
/// nested under it (an operator granted access at a subfolder level saw "No
/// credential variables" in My Credentials even though they could connect the
/// entry).
async fn gather_credential_variables<S: FolderSource>(
    src: &S,
    roots: Vec<(String, String)>,
) -> std::collections::HashMap<String, u32> {
    let mut all_vars: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut stack = roots;
    while let Some((scope, path)) = stack.pop() {
        if src.accessible(&scope, &path).await {
            for var in src.folder_var_names(&scope, &path).await {
                *all_vars.entry(var).or_insert(0) += 1;
            }
        }
        // Always descend: a deeper folder may be directly granted even when
        // this one is not.
        for sub in src.subfolders(&scope, &path).await {
            stack.push((scope.clone(), sub));
        }
    }
    all_vars
}

/// Real [`FolderSource`] backed by Vault and the caller's identity.
struct VaultFolderSource<'a> {
    vault: &'a VaultBackends,
    id: &'a AuthIdentity,
}

impl FolderSource for VaultFolderSource<'_> {
    async fn accessible(&self, scope: &str, path: &str) -> bool {
        check_folder_access(self.vault, scope, path, self.id)
            .await
            .is_ok()
    }

    async fn subfolders(&self, scope: &str, path: &str) -> Vec<String> {
        match self.vault.list_subfolders(scope, path).await {
            Ok(subs) => subs
                .into_iter()
                .map(|sub| sub.path.unwrap_or_else(|| format!("{}/{}", path, sub.name)))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    async fn folder_var_names(&self, scope: &str, path: &str) -> Vec<String> {
        let mut out = Vec::new();
        let entries = self
            .vault
            .list_entries(scope, path)
            .await
            .unwrap_or_default();
        for entry_name in &entries {
            if let Ok(entry) = self.vault.get_entry(scope, path, entry_name).await {
                // Every protocol the caller may use (#296), each resolved
                // against the host it inherits from.
                for (_, eff) in entry.visible_protocols(entry_viewer(self.id)) {
                    for var in crate::vault::entry_credential_variables(&eff) {
                        if !out.contains(&var) {
                            out.push(var);
                        }
                    }
                }
            }
        }
        out
    }
}

/// GET /api/credential-variables — List all unique credential variables across address book entries.
/// Returns grouped by domain prefix, with entry counts.
pub async fn list_credential_variables(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
) -> impl IntoResponse {
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

    // Scan all accessible folders and entries for variable references,
    // recursing into subfolders so vars inside nested trees surface too.
    let folders = match vault.list_all_folders().await {
        Ok((f, _)) => f,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("Failed to list folders: {}", e)})),
            )
                .into_response()
        }
    };

    let roots: Vec<(String, String)> = folders.into_iter().map(|f| (f.scope, f.name)).collect();
    let all_vars = gather_credential_variables(
        &VaultFolderSource {
            vault: &vault,
            id: &id,
        },
        roots,
    )
    .await;

    // Group by domain prefix (everything before the last _user/_password/_domain/_key suffix)
    let mut domains: std::collections::HashMap<String, Vec<serde_json::Value>> =
        std::collections::HashMap::new();
    for (var, count) in &all_vars {
        let domain = var
            .rsplit_once('_')
            .map(|(prefix, _suffix)| prefix.to_string())
            .unwrap_or_else(|| var.clone());
        domains
            .entry(domain)
            .or_default()
            .push(json!({"name": var, "entry_count": count}));
    }

    Json(json!({ "variables": all_vars, "domains": domains })).into_response()
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

/// GET /api/admin/addressbook-audit — View connections audit log. Admin only.
pub async fn admin_addressbook_audit(
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
        db::list_addressbook_audit_log(&db_clone, limit, email.as_deref())
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

        if !vault.any_connected().await {
            return quick_connect_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Address book is temporarily unavailable (Vault offline).",
            );
        }

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

        // In entry mode `protocol` picks one of the entry's protocols by
        // name (or type); without it the primary is used, as links made
        // before multi-protocol entries expect.
        let requested = query.protocol.as_deref().filter(|p| !p.trim().is_empty());
        let Some((protocol_name, ab_entry)) = ab_entry.pick_protocol(requested, entry_viewer(&id))
        else {
            return quick_connect_error(
                StatusCode::NOT_FOUND,
                &match requested {
                    Some(p) => format!("Entry '{}' has no protocol '{}'.", entry, p),
                    None => format!("Entry '{}' not found in {}/{}.", entry, scope, folder),
                },
            );
        };

        // Same folder defaults as the Connections connect endpoint, so an
        // entry that works from the page works from a link too.
        let ab_entry = lend_folder_defaults(vault.as_ref(), scope, folder, entry, ab_entry).await;

        // Resolve credential variable references
        let ab_entry = if !crate::vault::entry_credential_variables(&ab_entry).is_empty() {
            let user_email = match &id {
                AuthIdentity::User { email, .. } => Some(email.clone()),
                _ => None,
            };
            if let Some(email) = user_email {
                match vault.get_user_credentials(&email).await {
                    Ok(user_creds) => {
                        match crate::vault::resolve_credential_variables(&ab_entry, &user_creds) {
                            Ok(resolved) => resolved,
                            Err(missing) => {
                                return quick_connect_error(
                                    StatusCode::PRECONDITION_FAILED,
                                    &format!(
                                        "Missing credential variables: {}. Set them in My Credentials.",
                                        missing.join(", ")
                                    ),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to read user credentials from Vault: {}", e);
                        ab_entry
                    }
                }
            } else {
                ab_entry
            }
        } else {
            ab_entry
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
                &protocol_name,
                &ab_entry.session_type,
                ab_entry.username.as_deref(),
                ab_entry.domain.as_deref(),
                ab_entry.display_name.as_deref(),
            );
        }

        // Links open the four protocols a browser tab can carry on its own.
        if !matches!(
            ab_entry.session_type.as_str(),
            "ssh" | "rdp" | "vnc" | "web"
        ) {
            return quick_connect_error(
                StatusCode::BAD_REQUEST,
                &format!("Unknown session type: {}", ab_entry.session_type),
            );
        }

        let create_req = match quick_connect_entry_request(ab_entry, &query, scope, folder, entry) {
            Ok(mut r) => {
                r.address_book_protocol = Some(protocol_name.clone());
                r
            }
            Err(msg) => return quick_connect_error(StatusCode::BAD_REQUEST, &msg),
        };

        tracing::info!(
            user = %admin_name,
            client_ip = %client_ip,
            scope = %scope,
            folder = %folder,
            entry = %entry,
            protocol = %protocol_name,
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
    if !can_connect_adhoc(&id) {
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

    let mut create_req = CreateSessionRequest {
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
        server_layout: None,
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
        record_typescript: None,
        address_book_entry: None,
        address_book_folder: None,
        address_book_protocol: None,
        entry_display_name: None,
        max_recordings: None,
        login_script: None,
        autofill: None,
        allowed_domains: None,
        vnc_resize: None,
        vnc_network: None,
        disable_copy: None,
        disable_paste: None,
        enable_gfx: None,
        enable_desktop_composition: None,
        enable_wallpaper: None,
        enable_theming: None,
        enable_full_window_drag: None,
        force_lossless: None,
        enable_h264: None,
        container_image: None,
        container_cpu_limit: None,
        container_memory_limit: None,
        container_env: None,
        container_idle_timeout_mins: None,
        container_username: None,
        container_password: None,
        allow_sharing: None,
        fullscreen_on_connect: None,
        autohide_side_tabs: None,
        spice_tls: None,
        spice_tls_port: None,
        spice_ca_cert: None,
        spice_cert_subject: None,
        spice_proxy: None,
        proxmox_url: None,
        proxmox_node: None,
        proxmox_vmid: None,
        proxmox_token_id: None,
        proxmox_token_secret: None,
        proxmox_verify_tls: None,
        max_monitors: None,
        owner: None,
        fence_all_targets: false,
        ssh_font_size: None,
        wol_send_packet: None,
        wol_mac_addr: None,
        wol_broadcast_addr: None,
        wol_udp_port: None,
        wol_wait_time: None,
    };
    crate::session::apply_adhoc_policy(&mut create_req, id.has_role("admin"), manager.config());

    match manager.create_session(create_req, admin_name).await {
        Ok(info) => Redirect::temporary(&format!("/client/{}", info.session_id)).into_response(),
        Err(e) => quick_connect_error(StatusCode::BAD_GATEWAY, &e.to_string()),
    }
}

/// The session request for an entry opened from a `/api/connect` link, at
/// the size the link asks for.
fn quick_connect_entry_request(
    ab_entry: AddressBookEntry,
    query: &QuickConnectQuery,
    scope: &str,
    folder: &str,
    entry: &str,
) -> Result<CreateSessionRequest, String> {
    let display = EntryDisplay {
        width: query.width,
        height: query.height,
        dpi: query.dpi,
        keyboard_layout: None,
    };
    let attribution = EntryRef {
        key: format!("{}/{}/{}", scope, folder, entry),
        folder: folder.to_string(),
    };
    session_request_from_entry(ab_entry, display, Some(attribution))
}

/// Return an inline HTML credential form for quick-connect when prompting is needed.
#[allow(clippy::too_many_arguments)]
fn quick_connect_credential_form(
    scope: &str,
    folder: &str,
    entry: &str,
    protocol: &str,
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
  data-scope="{scope}" data-folder="{folder}" data-entry="{entry}" data-protocol="{protocol}">
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
    protocol: form.dataset.protocol || undefined,
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
        protocol = html_escape(protocol),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionInfo;

    // ── The entry-to-request conversion, against the code it replaced ──

    /// `ab_connect_entry`'s inline conversion before it moved into
    /// `session_request_from_entry`, verbatim.
    #[allow(clippy::let_and_return)] // kept verbatim
    fn legacy_ab_connect_request(
        ab_entry: AddressBookEntry,
        session_type: SessionType,
        req: ConnectRequest,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> CreateSessionRequest {
        let ab_entry_key = format!("{}/{}/{}", scope, folder, entry);
        let (initial_width, initial_height) = initial_session_size(
            &ab_entry.session_type,
            ab_entry.fullscreen_on_connect.unwrap_or(false),
            (req.width, req.height),
            (req.screen_width, req.screen_height),
        );
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
            server_layout: ab_entry.server_layout,
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
            width: initial_width,
            height: initial_height,
            dpi: req.dpi,
            banner: req.banner.or(ab_entry.banner),
            enable_drive: ab_entry.enable_drive,
            remote_app: ab_entry.remote_app,
            remote_app_dir: ab_entry.remote_app_dir,
            remote_app_args: ab_entry.remote_app_args,
            enable_recording: ab_entry.enable_recording,
            record_typescript: ab_entry.record_typescript,
            address_book_entry: Some(ab_entry_key.clone()),
            address_book_folder: Some(folder.to_string()),
            address_book_protocol: None,
            entry_display_name: ab_entry.display_name.clone(),
            max_recordings: ab_entry.max_recordings,
            login_script: ab_entry.login_script,
            autofill: ab_entry.autofill,
            allowed_domains: ab_entry.allowed_domains,
            vnc_resize: ab_entry.vnc_resize,
            vnc_network: ab_entry.vnc_network.clone(),
            disable_copy: ab_entry.disable_copy,
            disable_paste: ab_entry.disable_paste,
            enable_gfx: ab_entry.enable_gfx,
            enable_desktop_composition: ab_entry.enable_desktop_composition,
            enable_wallpaper: ab_entry.enable_wallpaper,
            enable_theming: ab_entry.enable_theming,
            enable_full_window_drag: ab_entry.enable_full_window_drag,
            force_lossless: ab_entry.force_lossless,
            enable_h264: ab_entry.enable_h264,
            container_image: ab_entry.container_image,
            container_cpu_limit: ab_entry.container_cpu_limit,
            container_memory_limit: ab_entry.container_memory_limit,
            container_env: ab_entry.container_env,
            container_idle_timeout_mins: ab_entry.container_idle_timeout_mins,
            container_username: ab_entry.container_username,
            container_password: ab_entry.container_password,
            allow_sharing: ab_entry.allow_sharing,
            fullscreen_on_connect: ab_entry.fullscreen_on_connect,
            autohide_side_tabs: ab_entry.autohide_side_tabs,
            spice_tls: ab_entry.spice_tls,
            spice_tls_port: ab_entry.spice_tls_port,
            spice_ca_cert: ab_entry.spice_ca_cert,
            spice_cert_subject: ab_entry.spice_cert_subject,
            spice_proxy: ab_entry.spice_proxy,
            proxmox_url: ab_entry.proxmox_url,
            proxmox_node: ab_entry.proxmox_node,
            proxmox_vmid: ab_entry.proxmox_vmid,
            proxmox_token_id: ab_entry.proxmox_token_id,
            proxmox_token_secret: ab_entry.proxmox_token_secret,
            proxmox_verify_tls: ab_entry.proxmox_verify_tls,
            max_monitors: ab_entry.max_monitors,
            owner: None,
            fence_all_targets: false,
            ssh_font_size: ab_entry.ssh_font_size,
            wol_send_packet: ab_entry.wol_send_packet,
            wol_mac_addr: ab_entry.wol_mac_addr,
            wol_broadcast_addr: ab_entry.wol_broadcast_addr,
            wol_udp_port: ab_entry.wol_udp_port,
            wol_wait_time: ab_entry.wol_wait_time,
        };
        create_req
    }

    /// `quick_connect`'s inline conversion (entry mode), verbatim.
    #[allow(clippy::let_and_return)] // kept verbatim
    fn legacy_quick_connect_request(
        ab_entry: AddressBookEntry,
        session_type: SessionType,
        query: QuickConnectQuery,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> CreateSessionRequest {
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
            server_layout: ab_entry.server_layout,
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
            banner: ab_entry.banner,
            enable_drive: ab_entry.enable_drive,
            remote_app: ab_entry.remote_app,
            remote_app_dir: ab_entry.remote_app_dir,
            remote_app_args: ab_entry.remote_app_args,
            enable_recording: ab_entry.enable_recording,
            record_typescript: ab_entry.record_typescript,
            address_book_entry: Some(ab_entry_key),
            address_book_folder: Some(folder.to_string()),
            address_book_protocol: None,
            entry_display_name: ab_entry.display_name.clone(),
            max_recordings: ab_entry.max_recordings,
            login_script: ab_entry.login_script,
            autofill: ab_entry.autofill,
            allowed_domains: ab_entry.allowed_domains,
            vnc_resize: ab_entry.vnc_resize,
            vnc_network: ab_entry.vnc_network.clone(),
            disable_copy: ab_entry.disable_copy,
            disable_paste: ab_entry.disable_paste,
            enable_gfx: ab_entry.enable_gfx,
            enable_desktop_composition: ab_entry.enable_desktop_composition,
            enable_wallpaper: ab_entry.enable_wallpaper,
            enable_theming: ab_entry.enable_theming,
            enable_full_window_drag: ab_entry.enable_full_window_drag,
            force_lossless: ab_entry.force_lossless,
            enable_h264: ab_entry.enable_h264,
            container_image: ab_entry.container_image,
            container_cpu_limit: ab_entry.container_cpu_limit,
            container_memory_limit: ab_entry.container_memory_limit,
            container_env: ab_entry.container_env,
            container_idle_timeout_mins: ab_entry.container_idle_timeout_mins,
            container_username: ab_entry.container_username,
            container_password: ab_entry.container_password,
            allow_sharing: ab_entry.allow_sharing,
            fullscreen_on_connect: ab_entry.fullscreen_on_connect,
            autohide_side_tabs: ab_entry.autohide_side_tabs,
            spice_tls: ab_entry.spice_tls,
            spice_tls_port: ab_entry.spice_tls_port,
            spice_ca_cert: ab_entry.spice_ca_cert,
            spice_cert_subject: ab_entry.spice_cert_subject,
            spice_proxy: ab_entry.spice_proxy,
            proxmox_url: None,
            proxmox_node: None,
            proxmox_vmid: None,
            proxmox_token_id: None,
            proxmox_token_secret: None,
            proxmox_verify_tls: None,
            max_monitors: None,
            owner: None,
            fence_all_targets: false,
            ssh_font_size: ab_entry.ssh_font_size,
            wol_send_packet: ab_entry.wol_send_packet,
            wol_mac_addr: ab_entry.wol_mac_addr,
            wol_broadcast_addr: ab_entry.wol_broadcast_addr,
            wol_udp_port: ab_entry.wol_udp_port,
            wol_wait_time: ab_entry.wol_wait_time,
        };
        create_req
    }

    /// An entry with every field the conversion reads set to something
    /// distinct, so a field dropped or swapped shows up.
    fn full_entry(session_type: &str) -> AddressBookEntry {
        // In parts: one json! literal this size exceeds the macro recursion limit.
        let mut body = serde_json::Map::new();
        for part in [
            json!({
            "type": session_type,
            "hostname": "host.example.test", "port": 2222,
            "username": "alice", "password": "pw", "private_key": "KEY",
            "url": "https://app.example.test", "domain": "CORP",
            "security": "nla", "server_layout": "en-gb-qwerty", "ignore_cert": true,
            "display_name": "Host One", "enable_drive": true, "auth_pkg": "kerberos",
            "kdc_url": "https://kdc.example.test", "prompt_credentials": false,
            "color_depth": 16
            }),
            json!({
            "jump_hosts": [{"hostname": "bastion", "port": 22, "username": "j",
                            "password": "jp", "private_key": null, "host_key": null}],
            "remote_app": "||notepad", "remote_app_dir": "C:\\", "remote_app_args": "-x",
            "enable_recording": false, "max_recordings": 3, "record_typescript": true,
            "login_script": "login.sh", "autofill": "[]",
            "allowed_domains": ["example.test"], "disable_copy": true, "disable_paste": true,
            "banner": "be careful", "enable_gfx": true, "enable_desktop_composition": true,
            "enable_wallpaper": true, "enable_theming": true, "enable_full_window_drag": true
            }),
            json!({
            "force_lossless": true, "enable_h264": false,
            "container_image": "desktop:1", "container_cpu_limit": 3.0,
            "container_memory_limit": 2048, "container_env": {"A": "1"},
            "container_idle_timeout_mins": 5, "container_username": "svc",
            "container_password": "svcpw", "allow_sharing": true,
            "auto_open_if_singleton": true, "fullscreen_on_connect": true,
            "autohide_side_tabs": true, "spice_tls": true, "spice_tls_port": 5901,
            "spice_ca_cert": "CA", "spice_cert_subject": "CN=x"
            }),
            json!({
            "spice_proxy": "http://proxy:3128", "proxmox_url": "https://pve:8006",
            "proxmox_node": "pve1", "proxmox_vmid": 101, "proxmox_token_id": "u@pam!t",
            "proxmox_token_secret": "secret", "proxmox_verify_tls": true,
            "max_monitors": 2, "ssh_font_size": 14, "wol_send_packet": true,
            "wol_mac_addr": "00:11:22:33:44:55", "wol_broadcast_addr": "192.0.2.255",
            "wol_udp_port": 9, "wol_wait_time": 30, "external_id": "netbox:device:1"
            }),
        ] {
            body.extend(part.as_object().unwrap().clone());
        }
        serde_json::from_value(serde_json::Value::Object(body)).unwrap()
    }

    fn as_json(req: &CreateSessionRequest) -> serde_json::Value {
        let mut v = serde_json::to_value(req).unwrap();
        v["fence_all_targets"] = json!(req.fence_all_targets);
        v
    }

    #[test]
    fn entry_connect_request_matches_the_inline_conversion() {
        for session_type in ["ssh", "rdp", "vnc", "spice", "proxmox", "web", "vdi"] {
            for prompt in [
                json!({ "width": 1700, "height": 900, "screen_width": 1920,
                        "screen_height": 1080, "dpi": 144 }),
                json!({ "width": 800, "height": 600, "username": "bob",
                        "password": "typed", "domain": "OTHER", "banner": "hi" }),
            ] {
                let req = || serde_json::from_value::<ConnectRequest>(prompt.clone()).unwrap();
                let new = entry_connect_request(
                    full_entry(session_type),
                    req(),
                    "shared/ops/host-1",
                    "ops",
                )
                .unwrap();
                let old = legacy_ab_connect_request(
                    full_entry(session_type),
                    entry_session_type(session_type).unwrap(),
                    req(),
                    "shared",
                    "ops",
                    "host-1",
                );
                assert_eq!(as_json(&new), as_json(&old), "{session_type} {prompt}");
                assert_eq!(new.reuse_fingerprint(), old.reuse_fingerprint());
            }
        }
    }

    #[test]
    fn quick_connect_request_matches_the_inline_conversion() {
        let query = || -> QuickConnectQuery {
            serde_urlencoded::from_str("width=1280&height=720&dpi=96").unwrap()
        };
        for session_type in ["ssh", "rdp", "vnc", "web"] {
            let new = quick_connect_entry_request(
                full_entry(session_type),
                &query(),
                "shared",
                "ops",
                "host-1",
            )
            .unwrap();
            let old = legacy_quick_connect_request(
                full_entry(session_type),
                entry_session_type(session_type).unwrap(),
                query(),
                "shared",
                "ops",
                "host-1",
            );
            let (mut new, mut old) = (as_json(&new), as_json(&old));
            // The one difference: links dropped the entry's Proxmox fields
            // and monitor count. Proxmox fields mean nothing to these four
            // types; the monitor count now reaches an RDP session from a
            // link as it does from the page.
            assert_eq!(new["max_monitors"], json!(2));
            for k in [
                "proxmox_url",
                "proxmox_node",
                "proxmox_vmid",
                "proxmox_token_id",
                "proxmox_token_secret",
                "proxmox_verify_tls",
                "max_monitors",
            ] {
                assert_eq!(old[k], serde_json::Value::Null, "{k}");
                new.as_object_mut().unwrap().remove(k);
                old.as_object_mut().unwrap().remove(k);
            }
            assert_eq!(new, old, "{session_type}");
        }
    }

    #[test]
    fn the_browser_keyboard_layout_fills_in_only_for_entries_without_one() {
        let display = |layout: Option<&str>| EntryDisplay {
            width: None,
            height: None,
            dpi: None,
            keyboard_layout: browser_keyboard_layout(layout),
        };
        let rdp = |layout: Option<&str>| AddressBookEntry {
            session_type: "rdp".into(),
            hostname: Some("desktop".into()),
            server_layout: layout.map(str::to_string),
            ..Default::default()
        };

        // No layout on the entry: the browser's is used.
        let req =
            session_request_from_entry(rdp(None), display(Some("de-ch-qwertz")), None).unwrap();
        assert_eq!(req.server_layout.as_deref(), Some("de-ch-qwertz"));
        let req =
            session_request_from_entry(rdp(Some("")), display(Some("de-ch-qwertz")), None).unwrap();
        assert_eq!(
            req.server_layout.as_deref(),
            Some("de-ch-qwertz"),
            "blank means server default"
        );

        // The entry's own layout wins.
        let req = session_request_from_entry(
            rdp(Some("en-gb-qwerty")),
            display(Some("de-ch-qwertz")),
            None,
        )
        .unwrap();
        assert_eq!(req.server_layout.as_deref(), Some("en-gb-qwerty"));

        // VDI entries have no layout field, so they always take the browser's.
        let vdi = AddressBookEntry {
            session_type: "vdi".into(),
            ..Default::default()
        };
        let req = session_request_from_entry(vdi, display(Some("fr-ch-qwertz")), None).unwrap();
        assert_eq!(req.server_layout.as_deref(), Some("fr-ch-qwertz"));

        // Nothing asked for: guacd's default, as before.
        let req = session_request_from_entry(rdp(None), display(None), None).unwrap();
        assert_eq!(req.server_layout, None);
    }

    #[test]
    fn unknown_browser_keyboard_layouts_are_dropped() {
        assert_eq!(
            browser_keyboard_layout(Some("de-ch-qwertz")).as_deref(),
            Some("de-ch-qwertz")
        );
        assert_eq!(
            browser_keyboard_layout(Some(" failsafe ")).as_deref(),
            Some("failsafe")
        );
        assert_eq!(browser_keyboard_layout(Some("klingon")), None);
        assert_eq!(
            browser_keyboard_layout(Some("de-ch-qwertz\nhostname")),
            None
        );
        assert_eq!(browser_keyboard_layout(Some("")), None);
        assert_eq!(browser_keyboard_layout(None), None);
    }

    #[test]
    fn an_adhoc_request_names_no_entry() {
        let display = EntryDisplay {
            width: Some(1024),
            height: Some(768),
            dpi: Some(96),
            keyboard_layout: None,
        };
        let req = session_request_from_entry(full_entry("ssh"), display, None).unwrap();
        assert_eq!(req.address_book_entry, None);
        assert_eq!(req.address_book_folder, None);
        assert_eq!(req.entry_display_name, None);
        assert_eq!(req.hostname.as_deref(), Some("host.example.test"));
        assert!(session_request_from_entry(
            AddressBookEntry {
                session_type: "telnet".into(),
                ..Default::default()
            },
            EntryDisplay {
                width: None,
                height: None,
                dpi: None,
                keyboard_layout: None,
            },
            None,
        )
        .is_err());
    }

    #[test]
    fn saved_entries_keep_their_admin_settings() {
        // A saved entry's fixed VDI account, recording opt-out, drive and
        // resources reach the session; only ad-hoc requests are filtered.
        let req = entry_connect_request(
            full_entry("vdi"),
            serde_json::from_value(json!({})).unwrap(),
            "shared/ops/host-1",
            "ops",
        )
        .unwrap();
        assert!(!req.fence_all_targets);
        assert_eq!(req.container_username.as_deref(), Some("svc"));
        assert_eq!(req.enable_recording, Some(false));
        assert_eq!(req.enable_drive, Some(true));
        assert_eq!(req.container_cpu_limit, Some(3.0));
        assert_eq!(req.max_recordings, Some(3));
    }

    // ── Ad-hoc connections ──

    /// Credentials and folder defaults behind one fake, counting what is
    /// read. Folder defaults are set for every type, so an ad-hoc entry
    /// would pick them up if anything lent them.
    struct FakeVault {
        creds: std::collections::HashMap<String, String>,
        cred_reads: std::sync::Mutex<Vec<String>>,
        defaults_reads: std::sync::atomic::AtomicUsize,
    }

    impl FakeVault {
        fn with(creds: &[(&str, &str)]) -> Self {
            Self {
                creds: creds
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                cred_reads: Default::default(),
                defaults_reads: Default::default(),
            }
        }
    }

    impl UserCredentialSource for FakeVault {
        async fn user_credentials(
            &self,
            email: &str,
        ) -> Result<std::collections::HashMap<String, String>, VaultError> {
            self.cred_reads.lock().unwrap().push(email.to_string());
            Ok(self.creds.clone())
        }
    }

    impl DefaultsSource for FakeVault {
        async fn folder_defaults(
            &self,
            _scope: &str,
            _folder: &str,
        ) -> Result<Option<crate::vault::FolderDefaults>, VaultError> {
            self.defaults_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Some(
                serde_json::from_value(json!({
                    "ssh": { "username": "folder-user", "password": "folder-pw" }
                }))
                .unwrap(),
            ))
        }
        async fn takes_parent_defaults(&self, _s: &str, _f: &str) -> Result<bool, VaultError> {
            self.defaults_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(true)
        }
    }

    fn user(email: &str, role: &str) -> AuthIdentity {
        AuthIdentity::User {
            email: email.into(),
            role: role.into(),
            groups: vec![],
        }
    }

    fn adhoc_entry(body: serde_json::Value) -> AddressBookEntry {
        serde_json::from_value(body).unwrap()
    }

    #[tokio::test]
    async fn adhoc_resolves_only_the_callers_own_variables() {
        let vault = FakeVault::with(&[("my_ssh_key", "-----KEY-----"), ("me", "alice")]);
        let entry = adhoc_entry(json!({
            "type": "ssh", "hostname": "10.0.0.1",
            "username": "$me", "private_key": "$my_ssh_key",
        }));
        let caller = user("Alice@example.com", "poweruser");
        let out = resolve_adhoc_entry(entry, &caller, Some(&vault))
            .await
            .unwrap();
        assert_eq!(out.username.as_deref(), Some("alice"));
        assert_eq!(out.private_key.as_deref(), Some("-----KEY-----"));
        assert_eq!(*vault.cred_reads.lock().unwrap(), vec!["Alice@example.com"]);
    }

    #[tokio::test]
    async fn adhoc_missing_variables_are_named() {
        let vault = FakeVault::with(&[("me", "alice")]);
        let entry = adhoc_entry(json!({
            "type": "ssh", "hostname": "10.0.0.1", "username": "$me", "password": "$nope",
        }));
        let err = resolve_adhoc_entry(entry, &user("a@example.com", "poweruser"), Some(&vault))
            .await
            .unwrap_err();
        assert_eq!(err, AdhocEntryError::MissingVariables(vec!["nope".into()]));
        assert_eq!(
            err.into_response().status(),
            StatusCode::PRECONDITION_FAILED
        );
    }

    #[tokio::test]
    async fn adhoc_variables_need_a_signed_in_user() {
        let vault = FakeVault::with(&[("me", "alice")]);
        let entry = adhoc_entry(json!({ "type": "ssh", "hostname": "h", "username": "$me" }));
        let err = resolve_adhoc_entry(entry, &AuthIdentity::ApiKey("ci".into()), Some(&vault))
            .await
            .unwrap_err();
        assert_eq!(err, AdhocEntryError::ApiKeyVariables);
        assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
        assert!(vault.cred_reads.lock().unwrap().is_empty());
        // Without variables an API key connects as before.
        let plain = adhoc_entry(json!({ "type": "ssh", "hostname": "h", "username": "root" }));
        let ci = AuthIdentity::ApiKey("ci".into());
        assert!(resolve_adhoc_entry(plain, &ci, Some(&vault)).await.is_ok());
    }

    #[tokio::test]
    async fn adhoc_without_vault_leaves_references_alone() {
        let entry = adhoc_entry(json!({ "type": "ssh", "hostname": "h", "username": "$me" }));
        let out =
            resolve_adhoc_entry::<FakeVault>(entry, &user("a@example.com", "poweruser"), None)
                .await
                .unwrap();
        assert_eq!(out.username.as_deref(), Some("$me"));
    }

    #[tokio::test]
    async fn adhoc_never_takes_folder_defaults() {
        // A bare SSH entry is exactly what folder defaults fill in on a saved
        // entry; an ad-hoc one has no folder, so it stays bare.
        let vault = FakeVault::with(&[]);
        let caller = user("a@example.com", "poweruser");
        let out = resolve_adhoc_entry(
            adhoc_entry(json!({ "type": "ssh", "hostname": "10.0.0.1" })),
            &caller,
            Some(&vault),
        )
        .await
        .unwrap();
        assert_eq!(out.username, None);
        assert_eq!(out.password, None);
        assert_eq!(
            vault
                .defaults_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no folder defaults may be read for an ad-hoc connection"
        );
    }

    #[tokio::test]
    async fn adhoc_legacy_jump_host_fields_become_a_chain() {
        let entry = adhoc_entry(json!({
            "type": "ssh", "hostname": "h", "jump_host": "bastion", "jump_username": "j",
        }));
        let out =
            resolve_adhoc_entry::<FakeVault>(entry, &user("a@example.com", "poweruser"), None)
                .await
                .unwrap();
        let hops = out.jump_hosts.unwrap();
        assert_eq!((hops[0].hostname.as_str(), hops[0].port), ("bastion", 22));
        assert_eq!(out.jump_host, None);
    }

    fn adhoc_test_manager() -> SessionManager {
        let config = crate::config::Config {
            recording_path: std::env::temp_dir()
                .join(format!("rustguac-adhoc-test-{}", Uuid::new_v4())),
            xvnc_path: "/bin/true".into(),
            chromium_path: "/bin/true".into(),
            login_scripts_dir: "/tmp".into(),
            ..Default::default()
        };
        SessionManager::new(config, None)
    }

    fn adhoc_body(extra: serde_json::Value) -> AdhocConnectRequest {
        let mut body = json!({ "width": 1280, "height": 720 });
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(body).unwrap()
    }

    /// What a poweruser's ad-hoc connection would make of `entry`, through
    /// to `create_session` on a manager with the default (localhost-only)
    /// allowlists.
    async fn poweruser_adhoc(entry: serde_json::Value) -> Result<SessionInfo, String> {
        let mgr = adhoc_test_manager();
        let mut body = adhoc_body(json!({ "entry": entry }));
        let entry = std::mem::take(&mut body.entry);
        let req = adhoc_session_request(entry, &body, false, mgr.config())?;
        assert!(req.fence_all_targets);
        mgr.create_session(req, "pu@example.com".into())
            .await
            .map_err(|e| e.to_string())
    }

    #[tokio::test]
    async fn adhoc_fences_spice_proxmox_and_jump_hosts() {
        let spice = poweruser_adhoc(json!({ "type": "spice", "hostname": "192.0.2.30" })).await;
        assert!(
            spice
                .as_ref()
                .unwrap_err()
                .contains("not in the allowed network list"),
            "{:?}",
            spice.err()
        );
        let pve = poweruser_adhoc(json!({
            "type": "proxmox", "proxmox_url": "https://192.0.2.20:8006", "proxmox_vmid": 100,
        }))
        .await;
        assert!(
            pve.as_ref().unwrap_err().contains("Proxmox API"),
            "{:?}",
            pve.err()
        );
        let jump = poweruser_adhoc(json!({
            "type": "ssh", "hostname": "127.0.0.1",
            "jump_hosts": [{ "hostname": "192.0.2.10", "port": 22, "username": "j" }],
        }))
        .await;
        assert!(
            jump.as_ref().unwrap_err().contains("jump host"),
            "{:?}",
            jump.err()
        );
    }

    #[test]
    fn adhoc_refuses_a_protocols_list() {
        let mgr = adhoc_test_manager();
        let body = adhoc_body(json!({ "entry": { "type": "ssh" } }));
        let multi: AddressBookEntry = serde_json::from_value(json!({
            "hostname": "h", "protocols": [{"type": "ssh"}, {"type": "rdp"}]
        }))
        .unwrap();
        let err = adhoc_session_request(multi, &body, true, mgr.config()).unwrap_err();
        assert!(err.contains("one protocol"), "{err}");
    }

    #[test]
    fn adhoc_drops_wake_on_lan_and_entry_only_settings() {
        let mgr = adhoc_test_manager();
        let body = adhoc_body(json!({ "entry": { "type": "vdi" } }));
        let req = adhoc_session_request(full_entry("ssh"), &body, false, mgr.config()).unwrap();
        assert!(req.fence_all_targets);
        assert_eq!(req.wol_send_packet, None);
        assert_eq!(req.wol_mac_addr, None);
        assert_eq!(req.container_username, None);
        assert_eq!(req.max_recordings, None);
        assert_eq!(req.record_typescript, None);
        assert_eq!(req.allow_sharing, None);
        // Recording is on site-wide by default: the entry's opt-out is ignored.
        assert_eq!(req.enable_recording, None);
        // No [drive] section: the drive stays off.
        assert_eq!(req.enable_drive, None);
        // What an ad-hoc caller may choose is kept.
        assert_eq!(req.login_script.as_deref(), Some("login.sh"));
        assert_eq!(req.ssh_font_size, Some(14));
        assert_eq!(req.disable_copy, Some(true));
    }

    #[test]
    fn adhoc_from_an_admin_is_used_as_sent() {
        let mgr = adhoc_test_manager();
        let body = adhoc_body(json!({ "entry": { "type": "ssh" }, "generate_keypair": true }));
        let req = adhoc_session_request(full_entry("ssh"), &body, true, mgr.config()).unwrap();
        assert!(!req.fence_all_targets);
        assert_eq!(req.wol_send_packet, Some(true));
        assert_eq!(req.enable_recording, Some(false));
        assert_eq!(req.generate_keypair, Some(true));
        assert_eq!(req.address_book_entry, None);
    }

    #[test]
    fn folder_update_leaves_an_omitted_display_name_alone() {
        // A client or script that predates display names saves a folder
        // without the field: that must not wipe the stored title. An empty
        // string is how a title is cleared on purpose.
        let old: UpdateFolderRequest =
            serde_json::from_str(r#"{"allowed_groups":["ops"],"description":"x"}"#).unwrap();
        assert_eq!(old.display_name, None);
        assert_eq!(old.allowed_users, None);
        let cleared: UpdateFolderRequest =
            serde_json::from_str(r#"{"allowed_groups":[],"display_name":""}"#).unwrap();
        assert_eq!(cleared.display_name.as_deref(), Some(""));
    }

    #[test]
    fn address_book_change_attribution() {
        use axum::http::Method;
        let f = ab_changes_for_request;
        // entries: create, update, delete; the folder segment is decoded
        assert_eq!(
            f(&Method::POST, "/api/addressbook/folders/shared/x/entries"),
            Some((vec![AbChange::entries("shared", "x")], true))
        );
        assert_eq!(
            f(
                &Method::PUT,
                "/api/addressbook/folders/shared/a%2Fb/entries/y"
            ),
            Some((vec![AbChange::entries("shared", "a/b")], true))
        );
        assert_eq!(
            f(
                &Method::DELETE,
                "/api/addressbook/folders/instance/x/entries/y"
            ),
            Some((vec![AbChange::entries("instance", "x")], true))
        );
        // the folder itself
        assert_eq!(
            f(&Method::PUT, "/api/addressbook/folders/shared/a%2Fb"),
            Some((vec![AbChange::tree("shared", "a/b")], true))
        );
        assert_eq!(
            f(&Method::DELETE, "/api/addressbook/folders/shared/x"),
            Some((vec![AbChange::tree("shared", "x")], true))
        );
        // connecting changes nothing, from an entry or ad hoc; an ad-hoc
        // connect marked as a change made every open tab reload
        assert_eq!(
            f(
                &Method::POST,
                "/api/addressbook/folders/shared/x/entries/y/connect"
            ),
            None
        );
        assert_eq!(f(&Method::POST, "/api/addressbook/adhoc/connect"), None);
        // folder defaults reach subfolders too: everything is refreshed
        assert_eq!(
            f(
                &Method::PUT,
                "/api/addressbook/folders/shared/a%2Fb/defaults"
            ),
            Some((vec![], false))
        );
        assert_eq!(
            f(
                &Method::DELETE,
                "/api/addressbook/folders/shared/x/defaults"
            ),
            Some((vec![], false))
        );
        // the body knows the rest: the handler reports it
        assert_eq!(
            f(&Method::POST, "/api/addressbook/folders"),
            Some((vec![], false))
        );
        assert_eq!(
            f(&Method::POST, "/api/addressbook/bulk"),
            Some((vec![], false))
        );
        assert_eq!(
            f(
                &Method::POST,
                "/api/addressbook/folders/shared/x/entries/y/move"
            ),
            Some((vec![AbChange::entries("shared", "x")], false))
        );
        assert_eq!(
            f(
                &Method::POST,
                "/api/addressbook/folders/shared/x/entries/y/copy"
            ),
            Some((vec![AbChange::entries("shared", "x")], false))
        );
        // reads and connects are not changes
        assert_eq!(f(&Method::GET, "/api/addressbook"), None);
        assert_eq!(f(&Method::GET, "/api/addressbook/version"), None);
        assert_eq!(f(&Method::GET, "/api/addressbook/search-index"), None);
        assert_eq!(
            f(
                &Method::POST,
                "/api/addressbook/folders/shared/x/entries/y/connect"
            ),
            None
        );
        assert_eq!(f(&Method::POST, "/api/sessions"), None);
        // a user's own credential variables are not an address-book change:
        // saving them must not touch every other tab
        assert_eq!(f(&Method::PUT, "/api/me/credentials"), None);
        assert_eq!(f(&Method::GET, "/api/me/credentials"), None);
    }

    #[test]
    fn address_book_change_log_since() {
        let log = AddressBookChanges::default();
        assert_eq!(log.snapshot(), (0, 0));
        let s = log.since(0);
        assert_eq!((s.version, s.changes), (0, Some(vec![])));

        assert_eq!(log.record(vec![AbChange::entries("shared", "a")]), 1);
        assert_eq!(log.record(vec![AbChange::entries("shared", "a")]), 2);
        assert_eq!(
            log.record(vec![
                AbChange::tree("shared", "b"),
                AbChange::entries("instance", "c"),
            ]),
            3
        );
        let (v, t) = log.snapshot();
        assert_eq!(v, 3);
        assert!(t > 1_600_000_000_000);

        // everything since 0, repeats collapsed, order kept
        let s = log.since(0);
        assert_eq!(
            s.changes,
            Some(vec![
                AbChange::entries("shared", "a"),
                AbChange::tree("shared", "b"),
                AbChange::entries("instance", "c"),
            ])
        );
        // only what came after the version the page saw
        assert_eq!(
            log.since(2).changes,
            Some(vec![
                AbChange::tree("shared", "b"),
                AbChange::entries("instance", "c"),
            ])
        );
        assert_eq!(log.since(3).changes, Some(vec![]));
        // a page ahead of the log saw a previous process: told to refresh,
        // not that nothing moved, or it would wait for the count to catch up
        assert_eq!(log.since(99).changes, None);

        // an unattributed change swallows the rest
        log.record(vec![AbChange::all()]);
        assert_eq!(log.since(0).changes, Some(vec![AbChange::all()]));
        assert_eq!(log.since(3).changes, Some(vec![AbChange::all()]));
        assert_eq!(
            log.since(4).changes,
            Some(vec![]),
            "the swallow applies only to what the page has not seen"
        );
    }

    #[test]
    fn address_book_change_log_forgets_the_oldest() {
        let log = AddressBookChanges::default();
        // Two changes per version: the ring then holds LEN/2 versions.
        for i in 0..(AB_CHANGE_LOG_LEN as u64) {
            log.record(vec![
                AbChange::entries("shared", &format!("f{i}")),
                AbChange::tree("shared", &format!("f{i}")),
            ]);
        }
        let version = log.snapshot().0;
        assert_eq!(version, AB_CHANGE_LOG_LEN as u64);
        let oldest_kept = version - (AB_CHANGE_LOG_LEN as u64 / 2) + 1;
        // Reachable: every version after `since` is still whole in the log.
        assert!(log.since(oldest_kept - 1).changes.is_some());
        assert_eq!(
            log.since(oldest_kept - 1).changes.unwrap().len(),
            AB_CHANGE_LOG_LEN
        );
        // One further back and part of the range is gone: say so, rather
        // than hand the page a partial list it would trust.
        assert!(log.since(oldest_kept - 2).changes.is_none());
        assert!(log.since(0).changes.is_none());
        // Still exact at the newest end.
        assert_eq!(log.since(version - 1).changes.unwrap().len(), 2);
    }

    /// The middleware, on a router: what reaches the log for each kind of
    /// request, and that a user's credential variables never do.
    #[tokio::test]
    async fn address_book_change_track_middleware() {
        use axum::body::Body;
        use axum::http::{Method, Request};
        use axum::routing::{post, put};
        use axum::Router;
        use tower::ServiceExt;

        let log = AddressBookChanges::default();
        let app = Router::new()
            .route("/api/me/credentials", put(|| async { "ok" }))
            .route(
                "/api/addressbook/folders/{scope}/{folder}/entries/{entry}",
                put(|| async { "ok" }),
            )
            .route(
                "/api/addressbook/folders/{scope}/{folder}/entries",
                post(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "vault down") }),
            )
            .route(
                "/api/addressbook/folders",
                post(|| async {
                    with_ab_changes(
                        (StatusCode::CREATED, "ok").into_response(),
                        vec![AbChange::tree("instance", "new/sub")],
                    )
                }),
            )
            .route("/api/addressbook/bulk", post(|| async { "ok" }))
            .layer(axum::middleware::from_fn(ab_change_track))
            .layer(Extension(log.clone()));

        let send = |method: Method, uri: &str| {
            let app = app.clone();
            let req = Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap();
            async move { app.oneshot(req).await.unwrap().status() }
        };

        // A user saving their own credential variables: nothing logged.
        assert!(send(Method::PUT, "/api/me/credentials").await.is_success());
        assert_eq!(log.snapshot().0, 0);

        // An entry write: logged against its (decoded) folder.
        assert!(send(
            Method::PUT,
            "/api/addressbook/folders/shared/a%2Fb/entries/host1"
        )
        .await
        .is_success());
        assert_eq!(log.snapshot().0, 1);
        assert_eq!(
            log.since(0).changes,
            Some(vec![AbChange::entries("shared", "a/b")])
        );

        // A failed write changes nothing, so it is not logged.
        assert_eq!(
            send(Method::POST, "/api/addressbook/folders/shared/x/entries").await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(log.snapshot().0, 1);

        // A handler that reports its folders: logged precisely, not as `all`.
        assert!(send(Method::POST, "/api/addressbook/folders")
            .await
            .is_success());
        assert_eq!(
            log.since(1).changes,
            Some(vec![AbChange::tree("instance", "new/sub")])
        );

        // A body-dependent route whose handler reports nothing: `all`, so
        // the page refreshes rather than misses it.
        assert!(send(Method::POST, "/api/addressbook/bulk")
            .await
            .is_success());
        assert_eq!(log.since(2).changes, Some(vec![AbChange::all()]));
        assert_eq!(log.snapshot().0, 3);
    }

    #[tokio::test]
    async fn a_failed_move_that_changed_folders_is_still_logged() {
        // A move that copied the entry but could not remove the original
        // answers 502, yet both folders changed: the handler reports them
        // and the log records exactly those, not the request's own path.
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::put;
        use axum::Router;
        use tower::ServiceExt;

        let log = AddressBookChanges::default();
        let app = Router::new()
            .route(
                "/api/addressbook/folders/{scope}/{folder}/entries/{entry}",
                put(|| async {
                    with_ab_changes(
                        (StatusCode::BAD_GATEWAY, "copied").into_response(),
                        upsert_move_changes("shared", "tenant-a", "tenant-b"),
                    )
                }),
            )
            .layer(axum::middleware::from_fn(ab_change_track))
            .layer(Extension(log.clone()));
        let req = Request::builder()
            .method("PUT")
            .uri("/api/addressbook/folders/shared/tenant-b/entries/fw01?move=true")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(req).await.unwrap().status(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            log.since(0).changes,
            Some(vec![
                AbChange::entries("shared", "tenant-a"),
                AbChange::entries("shared", "tenant-b"),
            ])
        );
    }

    #[test]
    fn upsert_move_changes_names_both_folders_once() {
        assert_eq!(
            upsert_move_changes("shared", "a", "b"),
            vec![
                AbChange::entries("shared", "a"),
                AbChange::entries("shared", "b")
            ]
        );
        // A rename within the folder changed one folder.
        assert_eq!(
            upsert_move_changes("shared", "a", "a"),
            vec![AbChange::entries("shared", "a")]
        );
    }

    #[test]
    fn address_book_change_log_epochs_differ_and_fit_javascript() {
        // The page compares epochs as JavaScript numbers, so they must be
        // exact below 2^53, and two processes must not share one.
        let a = AddressBookChanges::default();
        let b = AddressBookChanges::default();
        assert_ne!(a.epoch(), b.epoch());
        for e in [a.epoch(), b.epoch()] {
            assert!(e > 0 && e < (1u64 << 53), "{e}");
        }
        // A clone is the same log.
        assert_eq!(a.clone().epoch(), a.epoch());
    }

    #[tokio::test]
    async fn version_rows_never_name_a_folder_the_caller_cannot_open() {
        // An operator granted only teamA polls while an admin works in
        // secretco and creates a folder there. The answer may say that
        // teamA's entries changed and that the tree changed somewhere, and
        // nothing else: no secretco path, not even in a tree row.
        let can_open = |scope: String, folder: String| async move {
            Ok::<_, VaultError>(scope == "shared" && folder == "teamA")
        };
        let rows = vec![
            AbChange::entries("shared", "teamA"),
            AbChange::entries("shared", "customers/secretco"),
            AbChange::tree("shared", "customers/secretco/new"),
            AbChange::tree("shared", "teamA"),
        ];
        let out = ab_changes_visible_to(rows, can_open).await;
        assert_eq!(
            out,
            vec![
                AbChange::entries("shared", "teamA"),
                AbChange::tree_anywhere()
            ]
        );
        let text = serde_json::to_string(&out).unwrap();
        assert!(!text.contains("secretco"), "{text}");

        // Only a change the caller can't see: just "the tree changed" if a
        // folder moved, otherwise nothing at all.
        let out = ab_changes_visible_to(
            vec![AbChange::entries("shared", "customers/secretco")],
            can_open,
        )
        .await;
        assert!(out.is_empty(), "{out:?}");

        // A folder that has gone, or an access check that fails, never
        // names the folder; a failure still makes the page refresh.
        let out = ab_changes_visible_to(
            vec![
                AbChange::entries("shared", "gone"),
                AbChange::entries("shared", "flaky"),
            ],
            |_scope: String, folder: String| async move {
                if folder == "gone" {
                    Err(VaultError::NotFound)
                } else {
                    Err(VaultError::Parse("vault down".into()))
                }
            },
        )
        .await;
        assert_eq!(out, vec![AbChange::tree_anywhere()]);

        // `all` names nothing and passes through as is.
        let out = ab_changes_visible_to(
            vec![AbChange::entries("shared", "teamA"), AbChange::all()],
            can_open,
        )
        .await;
        assert_eq!(out, vec![AbChange::all()]);

        // A burst is not checked row by row: one path-less marker, and no
        // access check at all.
        let checks = std::sync::atomic::AtomicUsize::new(0);
        let many: Vec<AbChange> = (0..=AB_VERSION_MAX_CHECKED_ROWS)
            .map(|i| AbChange::entries("shared", &format!("f{i}")))
            .collect();
        let out = ab_changes_visible_to(many, |_s: String, _f: String| {
            checks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            async { Ok::<_, VaultError>(true) }
        })
        .await;
        assert_eq!(out, vec![AbChange::tree_anywhere()]);
        assert_eq!(checks.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
    use std::path::Path;

    #[test]
    fn entry_put_query_parses_the_move_flag() {
        // `PUT .../entries/:entry?move=true` is what the NetBox upsert sends;
        // the flag must default to off and accept only an explicit true.
        let q: EntryPutQuery = serde_urlencoded::from_str("move=true").unwrap();
        assert!(q.move_);
        let q: EntryPutQuery = serde_urlencoded::from_str("move=false").unwrap();
        assert!(!q.move_);
        let q: EntryPutQuery = serde_urlencoded::from_str("").unwrap();
        assert!(!q.move_, "move defaults to off");
        assert!(
            serde_urlencoded::from_str::<EntryPutQuery>("move=yes").is_err(),
            "a non-boolean value is rejected rather than treated as true"
        );
    }

    // ── `PUT .../entries/:entry?move=true`: the entry is matched on its
    // stored external_id, never on its name across folders; a match
    // elsewhere is moved whole by the server-side move and only then
    // updated, so no secret the payload lacks is ever lost. ──

    /// In-memory stand-in for the Vault entry store, keyed by folder + name.
    #[derive(Default)]
    struct FakeStore {
        entries: std::sync::Mutex<std::collections::BTreeMap<(String, String), AddressBookEntry>>,
        /// Make every delete fail, for the incomplete-move path.
        fail_delete: bool,
    }

    impl FakeStore {
        fn with(entries: &[(&str, &str, AddressBookEntry)]) -> Self {
            let store = FakeStore::default();
            for (folder, name, e) in entries {
                store
                    .entries
                    .lock()
                    .unwrap()
                    .insert((folder.to_string(), name.to_string()), e.clone());
            }
            store
        }
        fn stored(&self, folder: &str, name: &str) -> Option<AddressBookEntry> {
            self.entries
                .lock()
                .unwrap()
                .get(&(folder.to_string(), name.to_string()))
                .cloned()
        }
        /// Every `folder/name` held, sorted.
        fn keys(&self) -> Vec<String> {
            self.entries
                .lock()
                .unwrap()
                .keys()
                .map(|(f, n)| format!("{f}/{n}"))
                .collect()
        }
    }

    impl EntryStore for FakeStore {
        async fn folder_paths(&self, _scope: &str) -> Result<Vec<String>, VaultError> {
            let mut folders: Vec<String> = self
                .entries
                .lock()
                .unwrap()
                .keys()
                .map(|(f, _)| f.clone())
                .collect();
            folders.dedup();
            Ok(folders)
        }
        async fn entry_names(&self, _scope: &str, folder: &str) -> Result<Vec<String>, VaultError> {
            Ok(self
                .entries
                .lock()
                .unwrap()
                .keys()
                .filter(|(f, _)| f == folder)
                .map(|(_, n)| n.clone())
                .collect())
        }
        async fn get_entry(
            &self,
            _scope: &str,
            folder: &str,
            entry: &str,
        ) -> Result<AddressBookEntry, VaultError> {
            self.stored(folder, entry).ok_or(VaultError::NotFound)
        }
        async fn put_entry(
            &self,
            _scope: &str,
            folder: &str,
            entry: &str,
            data: &AddressBookEntry,
        ) -> Result<(), VaultError> {
            self.entries
                .lock()
                .unwrap()
                .insert((folder.to_string(), entry.to_string()), data.clone());
            Ok(())
        }
        async fn put_entry_if_absent(
            &self,
            _scope: &str,
            folder: &str,
            entry: &str,
            data: &AddressBookEntry,
        ) -> Result<bool, VaultError> {
            let mut entries = self.entries.lock().unwrap();
            let key = (folder.to_string(), entry.to_string());
            if entries.contains_key(&key) {
                return Ok(false);
            }
            entries.insert(key, data.clone());
            Ok(true)
        }
        async fn delete_entry(
            &self,
            _scope: &str,
            folder: &str,
            entry: &str,
        ) -> Result<(), VaultError> {
            if self.fail_delete {
                return Err(VaultError::Parse("delete refused".into()));
            }
            self.entries
                .lock()
                .unwrap()
                .remove(&(folder.to_string(), entry.to_string()))
                .map(|_| ())
                .ok_or(VaultError::NotFound)
        }
    }

    /// An entry from JSON, as the webhook or the edit form sends it.
    fn entry(v: serde_json::Value) -> AddressBookEntry {
        serde_json::from_value(v).unwrap()
    }

    /// Device 1 as stored, with every kind of credential someone adds by
    /// hand: a password holding a `$variable` reference, a private key and
    /// a jump host password.
    fn fw01_stored() -> AddressBookEntry {
        entry(json!({
            "type": "ssh", "hostname": "10.0.0.1", "port": 22, "username": "admin",
            "password": "$tenant_a_password", "private_key": "-----BEGIN KEY-----",
            "jump_hosts": [{"hostname": "bastion", "port": 22, "username": "jump", "password": "jump-pw"}],
            "external_id": "netbox:device:1"
        }))
    }

    /// What the NetBox webhook sends for device 1: no secrets at all.
    fn fw01_webhook(hostname: &str) -> AddressBookEntry {
        entry(json!({
            "type": "ssh", "hostname": hostname, "port": 22, "username": "admin",
            "jump_hosts": [{"hostname": "bastion", "port": 22, "username": "jump"}],
            "external_id": "netbox:device:1"
        }))
    }

    fn from(folder: &str, name: &str) -> MovedFrom {
        MovedFrom {
            folder: folder.into(),
            name: name.into(),
        }
    }

    fn rejected(err: UpsertError) -> (StatusCode, String) {
        match err {
            UpsertError::Rejected(status, msg) => (status, msg),
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn move_upsert_leaves_a_same_named_entry_in_another_folder_alone() {
        // Names are not unique across folders: tenant A and tenant B each
        // have a fw01. A's webhook must never touch B's, credentials and all.
        let store = FakeStore::with(&[
            ("tenant-a", "fw01", fw01_stored()),
            (
                "tenant-b",
                "fw01",
                entry(
                    json!({"type": "ssh", "hostname": "10.0.1.1", "password": "b-secret",
                             "external_id": "netbox:device:2"}),
                ),
            ),
        ]);
        let out = upsert_entry(
            &store,
            "shared",
            "tenant-a",
            "fw01",
            fw01_webhook("10.0.0.9"),
            true,
        )
        .await
        .unwrap();
        assert_eq!(out.moved_from, None);
        assert_eq!(store.keys(), ["tenant-a/fw01", "tenant-b/fw01"]);
        let b = store.stored("tenant-b", "fw01").unwrap();
        assert_eq!(b.password.as_deref(), Some("b-secret"));
        assert_eq!(b.hostname.as_deref(), Some("10.0.1.1"));
        let a = store.stored("tenant-a", "fw01").unwrap();
        assert_eq!(a.hostname.as_deref(), Some("10.0.0.9"));

        // A third tenant's own fw01 is created there; the other two are as
        // they were.
        let out = upsert_entry(
            &store,
            "shared",
            "tenant-c",
            "fw01",
            entry(json!({"type": "ssh", "hostname": "10.0.2.1", "external_id": "netbox:device:3"})),
            true,
        )
        .await
        .unwrap();
        assert_eq!(out.moved_from, None);
        assert_eq!(
            store.keys(),
            ["tenant-a/fw01", "tenant-b/fw01", "tenant-c/fw01"]
        );
        assert_eq!(
            store
                .stored("tenant-a", "fw01")
                .unwrap()
                .password
                .as_deref(),
            Some("$tenant_a_password")
        );
        assert_eq!(
            store
                .stored("tenant-b", "fw01")
                .unwrap()
                .password
                .as_deref(),
            Some("b-secret")
        );
    }

    #[tokio::test]
    async fn move_upsert_moves_the_matched_entry_with_its_credentials() {
        // The device changed tenant, so the webhook now writes to tenant B's
        // (nested) folder, and it carries no secrets. The stored entry is
        // moved whole first (#232: the $variable reference, the key and the
        // jump host password come along), and the update lands on top.
        let store = FakeStore::with(&[("tenant-a", "fw01", fw01_stored())]);
        let out = upsert_entry(
            &store,
            "shared",
            "tenants/tenant-b",
            "fw01",
            fw01_webhook("10.0.1.9"),
            true,
        )
        .await
        .unwrap();
        assert_eq!(out.moved_from, Some(from("tenant-a", "fw01")));
        assert_eq!(
            store.keys(),
            ["tenants/tenant-b/fw01"],
            "the original is gone and nothing else appeared"
        );
        let moved = store.stored("tenants/tenant-b", "fw01").unwrap();
        assert_eq!(
            moved.hostname.as_deref(),
            Some("10.0.1.9"),
            "update applied"
        );
        assert_eq!(moved.password.as_deref(), Some("$tenant_a_password"));
        assert_eq!(moved.private_key.as_deref(), Some("-----BEGIN KEY-----"));
        assert_eq!(
            moved.jump_hosts.as_ref().unwrap()[0].password.as_deref(),
            Some("jump-pw")
        );
        assert_eq!(moved.external_id.as_deref(), Some("netbox:device:1"));
    }

    #[tokio::test]
    async fn move_upsert_follows_a_rename_within_the_folder() {
        // Same tenant, new device name: matched on the id, so it is a move
        // (with its secrets), not a second entry beside an orphan.
        let store = FakeStore::with(&[("tenant-a", "fw01", fw01_stored())]);
        let out = upsert_entry(
            &store,
            "shared",
            "tenant-a",
            "fw01-core",
            fw01_webhook("10.0.0.1"),
            true,
        )
        .await
        .unwrap();
        assert_eq!(out.moved_from, Some(from("tenant-a", "fw01")));
        assert_eq!(store.keys(), ["tenant-a/fw01-core"]);
        assert_eq!(
            store
                .stored("tenant-a", "fw01-core")
                .unwrap()
                .password
                .as_deref(),
            Some("$tenant_a_password")
        );
    }

    #[tokio::test]
    async fn upsert_without_secrets_keeps_the_stored_ones() {
        // The steady state: the device is where the webhook says. A payload
        // without secrets keeps every stored one, and a form edit that also
        // omits external_id keeps that.
        let store = FakeStore::with(&[("tenant-a", "fw01", fw01_stored())]);
        let out = upsert_entry(
            &store,
            "shared",
            "tenant-a",
            "fw01",
            fw01_webhook("10.0.0.2"),
            true,
        )
        .await
        .unwrap();
        assert_eq!(out.moved_from, None, "already there: nothing to move");
        let e = store.stored("tenant-a", "fw01").unwrap();
        assert_eq!(e.hostname.as_deref(), Some("10.0.0.2"));
        assert_eq!(e.password.as_deref(), Some("$tenant_a_password"));
        assert_eq!(e.private_key.as_deref(), Some("-----BEGIN KEY-----"));
        assert_eq!(
            e.jump_hosts.as_ref().unwrap()[0].password.as_deref(),
            Some("jump-pw")
        );

        // The edit form: no secrets, no external_id, no move flag.
        let form = entry(
            json!({"type": "ssh", "hostname": "10.0.0.3", "port": 2222, "username": "admin"}),
        );
        upsert_entry(&store, "shared", "tenant-a", "fw01", form, false)
            .await
            .unwrap();
        let e = store.stored("tenant-a", "fw01").unwrap();
        assert_eq!(e.port, Some(2222));
        assert_eq!(e.password.as_deref(), Some("$tenant_a_password"));
        assert_eq!(
            e.external_id.as_deref(),
            Some("netbox:device:1"),
            "a form edit does not cut the entry loose from its source"
        );
    }

    #[tokio::test]
    async fn move_upsert_adopts_a_hand_made_entry_of_that_name() {
        // Made by hand before syncing began: same folder and name, no id.
        // Updated in place, password kept, and it takes the id.
        let store = FakeStore::with(&[(
            "tenant-a",
            "fw01",
            entry(json!({"type": "ssh", "hostname": "10.0.0.1", "password": "typed-in"})),
        )]);
        let out = upsert_entry(
            &store,
            "shared",
            "tenant-a",
            "fw01",
            fw01_webhook("10.0.0.1"),
            true,
        )
        .await
        .unwrap();
        assert_eq!(out.moved_from, None);
        let e = store.stored("tenant-a", "fw01").unwrap();
        assert_eq!(e.password.as_deref(), Some("typed-in"));
        assert_eq!(e.external_id.as_deref(), Some("netbox:device:1"));
    }

    #[tokio::test]
    async fn move_upsert_does_not_adopt_when_the_id_is_already_elsewhere() {
        // Device 1 moves to tenant B, where someone had made an fw01 by
        // hand. Adopting it would leave device 1's id on two entries and
        // every later sync of the device refused as ambiguous, so it is
        // refused now with both entries as they were.
        let store = FakeStore::with(&[
            ("tenant-a", "fw01", fw01_stored()),
            (
                "tenant-b",
                "fw01",
                entry(json!({"type": "ssh", "hostname": "10.0.1.1", "password": "typed-in"})),
            ),
        ]);
        let (status, msg) = rejected(
            upsert_entry(
                &store,
                "shared",
                "tenant-b",
                "fw01",
                fw01_webhook("10.0.1.9"),
                true,
            )
            .await
            .unwrap_err(),
        );
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(msg.contains("tenant-a/fw01"), "{msg}");
        let b = store.stored("tenant-b", "fw01").unwrap();
        assert_eq!(
            b.external_id, None,
            "the hand-made entry did not take the id"
        );
        assert_eq!(b.hostname.as_deref(), Some("10.0.1.1"));
        assert_eq!(b.password.as_deref(), Some("typed-in"));
        assert_eq!(
            store
                .stored("tenant-a", "fw01")
                .unwrap()
                .password
                .as_deref(),
            Some("$tenant_a_password")
        );
    }

    #[tokio::test]
    async fn move_upsert_needs_an_external_id() {
        // Without an id there is nothing to match on but the name, which is
        // exactly what must not happen: refused, and nothing is touched.
        let store = FakeStore::with(&[("tenant-a", "fw01", fw01_stored())]);
        let payload = entry(json!({"type": "ssh", "hostname": "10.0.0.1"}));
        let (status, msg) = rejected(
            upsert_entry(&store, "shared", "tenant-b", "fw01", payload, true)
                .await
                .unwrap_err(),
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.contains("external_id"), "{msg}");
        assert_eq!(store.keys(), ["tenant-a/fw01"]);
    }

    #[tokio::test]
    async fn move_upsert_refuses_a_name_held_by_another_device() {
        // Device 1 moves to tenant B, where a different device is already
        // fw01. Neither entry is overwritten or removed.
        let store = FakeStore::with(&[
            ("tenant-a", "fw01", fw01_stored()),
            (
                "tenant-b",
                "fw01",
                entry(
                    json!({"type": "ssh", "hostname": "10.0.1.1", "password": "b-secret",
                             "external_id": "netbox:device:2"}),
                ),
            ),
        ]);
        let (status, _) = rejected(
            upsert_entry(
                &store,
                "shared",
                "tenant-b",
                "fw01",
                fw01_webhook("10.0.1.9"),
                true,
            )
            .await
            .unwrap_err(),
        );
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(store.keys(), ["tenant-a/fw01", "tenant-b/fw01"]);
        let b = store.stored("tenant-b", "fw01").unwrap();
        assert_eq!(b.password.as_deref(), Some("b-secret"));
        assert_eq!(b.hostname.as_deref(), Some("10.0.1.1"));
        assert_eq!(
            store
                .stored("tenant-a", "fw01")
                .unwrap()
                .password
                .as_deref(),
            Some("$tenant_a_password")
        );
    }

    #[tokio::test]
    async fn move_upsert_refuses_an_ambiguous_external_id() {
        // The same id on two entries is a mess to sort out by hand, not
        // something to guess at.
        let store = FakeStore::with(&[
            ("tenant-a", "fw01", fw01_stored()),
            ("tenant-c", "fw01-old", fw01_stored()),
        ]);
        let (status, msg) = rejected(
            upsert_entry(
                &store,
                "shared",
                "tenant-b",
                "fw01",
                fw01_webhook("10.0.1.9"),
                true,
            )
            .await
            .unwrap_err(),
        );
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            msg.contains("tenant-a/fw01") && msg.contains("tenant-c/fw01-old"),
            "{msg}"
        );
        assert_eq!(store.keys(), ["tenant-a/fw01", "tenant-c/fw01-old"]);
    }

    #[tokio::test]
    async fn move_upsert_reports_a_move_it_could_not_finish() {
        // Copied to the target but the original could not be removed: the
        // entry is in both folders, the update is not applied, and the
        // caller is told so rather than given an error it would retry.
        let mut store = FakeStore::with(&[("tenant-a", "fw01", fw01_stored())]);
        store.fail_delete = true;
        match upsert_entry(
            &store,
            "shared",
            "tenant-b",
            "fw01",
            fw01_webhook("10.0.1.9"),
            true,
        )
        .await
        .unwrap_err()
        {
            UpsertError::MoveIncomplete { from: at, .. } => {
                assert_eq!(at, from("tenant-a", "fw01"))
            }
            other => panic!("expected MoveIncomplete, got {other:?}"),
        }
        assert_eq!(store.keys(), ["tenant-a/fw01", "tenant-b/fw01"]);
        assert_eq!(
            store
                .stored("tenant-b", "fw01")
                .unwrap()
                .hostname
                .as_deref(),
            Some("10.0.0.1"),
            "the copy is the stored entry, not the update"
        );
    }

    #[tokio::test]
    async fn plain_upsert_never_moves() {
        // Without ?move=true the same payload is the plain name upsert it
        // always was: created here, the entry elsewhere left alone.
        let store = FakeStore::with(&[("tenant-a", "fw01", fw01_stored())]);
        let out = upsert_entry(
            &store,
            "shared",
            "tenant-b",
            "fw01",
            fw01_webhook("10.0.1.9"),
            false,
        )
        .await
        .unwrap();
        assert_eq!(out.moved_from, None);
        assert_eq!(store.keys(), ["tenant-a/fw01", "tenant-b/fw01"]);
        assert_eq!(
            store.stored("tenant-b", "fw01").unwrap().password,
            None,
            "a plain create has only what the payload carried"
        );
    }

    #[test]
    fn fullscreen_sizing_applies_to_bitmap_sessions_only() {
        let win = (Some(1710), Some(954));
        let scr = (Some(1710), Some(1112));
        // RDP opening fullscreen: created at the screen size rounded down to
        // a multiple of 16, matching guacd's display-channel rounding so there
        // is no post-connect resize (#257). VNC is not mod-16 rounded.
        assert_eq!(
            initial_session_size("rdp", true, win, scr),
            (Some(1696), Some(1104))
        );
        assert_eq!(initial_session_size("vnc", true, win, scr), scr);
        // A screen that is already mod-16 is created at its exact size.
        assert_eq!(
            initial_session_size("rdp", true, win, (Some(1920), Some(1088))),
            (Some(1920), Some(1088))
        );
        // a terminal reflows instantly: window size, fullscreen or not
        assert_eq!(initial_session_size("ssh", true, win, scr), win);
        assert_eq!(initial_session_size("telnet", true, win, scr), win);
        assert_eq!(initial_session_size("web", true, win, scr), win);
        // not fullscreen, or no screen size offered: window size, still on
        // the mod-16 grid for RDP, since the client's first size send is
        // rounded to it by guacd either way (no resize on connect).
        let win16 = (Some(1696), Some(944));
        assert_eq!(initial_session_size("rdp", false, win, scr), win16);
        assert_eq!(initial_session_size("rdp", true, win, (None, None)), win16);
        assert_eq!(
            initial_session_size("rdp", true, win, (Some(0), Some(0))),
            win16
        );
        assert_eq!(initial_session_size("vnc", false, win, scr), win);
        assert_eq!(
            initial_session_size("rdp", false, (None, None), scr),
            (None, None)
        );
    }

    #[test]
    fn round_down_mod16_floors_at_sixteen() {
        assert_eq!(round_down_mod16(1710), 1696);
        assert_eq!(round_down_mod16(1696), 1696);
        assert_eq!(round_down_mod16(16), 16);
        assert_eq!(round_down_mod16(15), 16);
        assert_eq!(round_down_mod16(0), 16);
    }

    #[test]
    fn report_bounds_read_a_bare_date_as_a_whole_local_day() {
        // Sydney in September: UTC+10, so getTimezoneOffset() is -600.
        let tz = -600;
        assert_eq!(
            normalize_report_bound("2026-09-04", tz, false).unwrap(),
            "2026-09-03 14:00:00"
        );
        assert_eq!(
            normalize_report_bound("2026-09-04", tz, true).unwrap(),
            "2026-09-04 13:59:59"
        );
        // No offset given (the scripted case) means UTC, unchanged behaviour.
        assert_eq!(
            normalize_report_bound("2026-09-04", 0, false).unwrap(),
            "2026-09-04 00:00:00"
        );
    }

    #[test]
    fn report_bounds_convert_zoned_values_and_reject_junk() {
        // A value carrying its own zone is converted from it, offset ignored.
        assert_eq!(
            normalize_report_bound("2026-09-04T02:14:07Z", -600, false).unwrap(),
            "2026-09-04 02:14:07"
        );
        assert_eq!(
            normalize_report_bound("2026-09-04T12:14:07+10:00", 0, false).unwrap(),
            "2026-09-04 02:14:07"
        );
        // Zoneless datetimes are shifted like a bare date.
        assert_eq!(
            normalize_report_bound("2026-09-04T12:14:07", -600, false).unwrap(),
            "2026-09-04 02:14:07"
        );
        assert!(normalize_report_bound("last tuesday", 0, false).is_err());
        assert!(normalize_report_bound("", 0, false).is_err());
    }

    #[test]
    fn report_bounds_clamp_a_nonsense_offset() {
        let q = ReportQuery {
            user: None,
            entry: None,
            session_type: None,
            from: Some("2026-09-04".into()),
            to: None,
            tz_offset: Some(999_999),
            limit: None,
            offset: None,
        };
        // Clamped to +840, not applied verbatim.
        assert_eq!(report_bounds(&q).unwrap().0.unwrap(), "2026-09-04 14:00:00");
    }

    #[test]
    fn mark_utc_tags_zoneless_sqlite_timestamps() {
        assert_eq!(mark_utc("2026-09-04 02:14:07"), "2026-09-04T02:14:07Z");
        // Already zoned, or not the SQLite shape at all: left alone.
        assert_eq!(mark_utc("2026-09-04T02:14:07Z"), "2026-09-04T02:14:07Z");
        assert_eq!(
            mark_utc("2026-09-04T02:14:07+00:00"),
            "2026-09-04T02:14:07+00:00"
        );
        assert_eq!(mark_utc(""), "");
    }

    // ── Regression: credential-variable gathering must reach a folder the user
    // can access even when it is nested under an inaccessible ancestor
    // (operator "No credential variables" bug). ──
    struct FakeFolders {
        access: std::collections::HashSet<(String, String)>,
        subs: std::collections::HashMap<(String, String), Vec<String>>,
        vars: std::collections::HashMap<(String, String), Vec<String>>,
    }
    impl FolderSource for FakeFolders {
        async fn accessible(&self, scope: &str, path: &str) -> bool {
            self.access.contains(&(scope.to_string(), path.to_string()))
        }
        async fn subfolders(&self, scope: &str, path: &str) -> Vec<String> {
            self.subs
                .get(&(scope.to_string(), path.to_string()))
                .cloned()
                .unwrap_or_default()
        }
        async fn folder_var_names(&self, scope: &str, path: &str) -> Vec<String> {
            self.vars
                .get(&(scope.to_string(), path.to_string()))
                .cloned()
                .unwrap_or_default()
        }
    }

    fn sp(a: &str, b: &str) -> (String, String) {
        (a.to_string(), b.to_string())
    }

    // ── Folder default credentials: the one resolver both connect paths use
    // (the Connections endpoint and /api/connect quick links). ──
    struct FakeDefaultsSource {
        defaults: std::collections::HashMap<String, crate::vault::FolderDefaults>,
        inherit: std::collections::HashSet<String>,
    }
    impl DefaultsSource for FakeDefaultsSource {
        async fn folder_defaults(
            &self,
            _scope: &str,
            folder: &str,
        ) -> Result<Option<crate::vault::FolderDefaults>, VaultError> {
            Ok(self.defaults.get(folder).cloned())
        }
        async fn takes_parent_defaults(
            &self,
            _scope: &str,
            folder: &str,
        ) -> Result<bool, VaultError> {
            Ok(self.inherit.contains(folder))
        }
    }

    fn defaults_with_ssh_key(key: &str) -> crate::vault::FolderDefaults {
        let mut d = crate::vault::FolderDefaults::new();
        d.insert(
            "ssh".into(),
            crate::vault::DefaultCredentials {
                username: Some("root".into()),
                private_key: Some(key.into()),
                ..Default::default()
            },
        );
        d
    }

    #[tokio::test]
    async fn lend_folder_defaults_fills_a_bare_entry_and_respects_the_boundary() {
        let src = FakeDefaultsSource {
            defaults: [("corp".to_string(), defaults_with_ssh_key("corp-key"))]
                .into_iter()
                .collect(),
            inherit: ["corp/linux"].into_iter().map(String::from).collect(),
        };
        let bare = || AddressBookEntry {
            session_type: "ssh".into(),
            hostname: Some("10.0.0.1".into()),
            ..Default::default()
        };

        // a subfolder that inherits gets corp's key and username
        let e = lend_folder_defaults(&src, "shared", "corp/linux", "box", bare()).await;
        assert_eq!(e.private_key.as_deref(), Some("corp-key"));
        assert_eq!(e.username.as_deref(), Some("root"));

        // an isolated subfolder (inherit_from_parent: false) does not
        let e = lend_folder_defaults(&src, "shared", "corp/guests", "box", bare()).await;
        assert!(e.private_key.is_none() && e.username.is_none());

        // the entry's own secret and username win
        let own = AddressBookEntry {
            password: Some("own".into()),
            username: Some("admin".into()),
            ..bare()
        };
        let e = lend_folder_defaults(&src, "shared", "corp/linux", "box", own).await;
        assert_eq!(e.password.as_deref(), Some("own"));
        assert_eq!(e.username.as_deref(), Some("admin"));
        assert!(e.private_key.is_none());

        // an entry set to prompt is left to prompt
        let prompting = AddressBookEntry {
            prompt_credentials: Some(true),
            ..bare()
        };
        let e = lend_folder_defaults(&src, "shared", "corp/linux", "box", prompting).await;
        assert!(e.private_key.is_none());
    }

    #[tokio::test]
    async fn lend_folder_defaults_leaves_the_entry_alone_when_vault_fails() {
        struct Down;
        impl DefaultsSource for Down {
            async fn folder_defaults(
                &self,
                _s: &str,
                _f: &str,
            ) -> Result<Option<crate::vault::FolderDefaults>, VaultError> {
                Err(VaultError::Forbidden)
            }
            async fn takes_parent_defaults(&self, _s: &str, _f: &str) -> Result<bool, VaultError> {
                Err(VaultError::Forbidden)
            }
        }
        let e = AddressBookEntry {
            session_type: "ssh".into(),
            username: Some("admin".into()),
            ..Default::default()
        };
        let out = lend_folder_defaults(&Down, "shared", "corp/linux", "box", e).await;
        // a failed read must not change the entry
        assert_eq!(out.username.as_deref(), Some("admin"));
        assert!(out.password.is_none() && out.private_key.is_none());
    }

    #[tokio::test]
    async fn credential_vars_reach_accessible_folder_under_inaccessible_parent() {
        // shared/corp is NOT accessible; shared/corp/jumpcloud IS (a subfolder
        // grant). The operator can connect that entry via the tree, so its
        // credential variables must surface in My Credentials. Before the fix
        // the walk short-circuited at "corp" and returned nothing.
        let fake = FakeFolders {
            access: std::collections::HashSet::from([sp("shared", "corp/jumpcloud")]),
            subs: std::collections::HashMap::from([(
                sp("shared", "corp"),
                vec!["corp/jumpcloud".to_string()],
            )]),
            vars: std::collections::HashMap::from([(
                sp("shared", "corp/jumpcloud"),
                vec![
                    "jumpcloud_username".to_string(),
                    "jumpcloud_password".to_string(),
                ],
            )]),
        };
        // Seed only the top-level folder, exactly as list_all_folders does.
        let got = gather_credential_variables(&fake, vec![sp("shared", "corp")]).await;
        assert_eq!(got.get("jumpcloud_password").copied(), Some(1));
        assert_eq!(got.get("jumpcloud_username").copied(), Some(1));
    }

    #[tokio::test]
    async fn credential_vars_not_collected_from_inaccessible_folders() {
        // Descending past inaccessible folders must never surface THEIR
        // variables — only pass through them to accessible descendants.
        let fake = FakeFolders {
            access: std::collections::HashSet::new(), // nothing accessible
            subs: std::collections::HashMap::new(),
            vars: std::collections::HashMap::from([(
                sp("shared", "secret"),
                vec!["secret_password".to_string()],
            )]),
        };
        let got = gather_credential_variables(&fake, vec![sp("shared", "secret")]).await;
        assert!(
            got.is_empty(),
            "must not collect variables from folders the user cannot access"
        );
    }

    #[test]
    fn test_html_escape_special_chars() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape(r#"x"y"#), "x&quot;y");
        assert_eq!(html_escape("it's"), "it&#x27;s");
    }

    #[test]
    fn test_html_escape_passthrough() {
        assert_eq!(html_escape("hello world"), "hello world");
        assert_eq!(html_escape(""), "");
    }

    fn hm(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_partition_single_vault_writes_one_store() {
        // Quick-start invariant: with split=false everything lands in the local
        // map and shared stays empty, so the caller writes the one store once.
        let existing = hm(&[("corp_user", "alice"), ("corp_password", "old")]);
        let incoming = hm(&[("corp_password", "new")]);
        let scopes = hm(&[("corp_password", "shared")]); // ignored when !split
        let (local, shared) = partition_credential_writes(
            existing,
            std::collections::HashMap::new(),
            &incoming,
            &scopes,
            "local",
            false,
        );
        assert_eq!(local.get("corp_user").unwrap(), "alice"); // untouched kept
        assert_eq!(local.get("corp_password").unwrap(), "new"); // updated
        assert!(shared.is_empty(), "single store must not populate shared");
    }

    #[test]
    fn test_partition_blank_keeps_existing() {
        // Blank value = keep existing (the "leave blank to keep" secret path).
        let existing = hm(&[("corp_password", "secret")]);
        let incoming = hm(&[("corp_password", "")]);
        let (local, _shared) = partition_credential_writes(
            existing,
            std::collections::HashMap::new(),
            &incoming,
            &std::collections::HashMap::new(),
            "local",
            false,
        );
        assert_eq!(local.get("corp_password").unwrap(), "secret");
    }

    #[test]
    fn test_partition_split_routes_by_scope() {
        let incoming = hm(&[("shared_pw", "s"), ("local_pw", "l")]);
        let scopes = hm(&[("shared_pw", "shared"), ("local_pw", "local")]);
        let (local, shared) = partition_credential_writes(
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            &incoming,
            &scopes,
            "local",
            true,
        );
        assert_eq!(shared.get("shared_pw").unwrap(), "s");
        assert!(!shared.contains_key("local_pw"));
        assert_eq!(local.get("local_pw").unwrap(), "l");
        assert!(!local.contains_key("shared_pw"));
    }

    #[test]
    fn test_partition_split_moves_between_scopes_keeping_value() {
        // A key currently local, re-saved with scope=shared and a blank value,
        // moves to shared carrying its existing value and leaves local.
        let existing_local = hm(&[("corp_pw", "keepme")]);
        let incoming = hm(&[("corp_pw", "")]); // blank = keep value
        let scopes = hm(&[("corp_pw", "shared")]);
        let (local, shared) = partition_credential_writes(
            existing_local,
            std::collections::HashMap::new(),
            &incoming,
            &scopes,
            "local",
            true,
        );
        assert!(!local.contains_key("corp_pw"), "must leave the local store");
        assert_eq!(shared.get("corp_pw").unwrap(), "keepme");
    }

    #[test]
    fn test_partition_split_default_scope_applies() {
        // No explicit scope for the key → falls back to default_scope.
        let incoming = hm(&[("corp_pw", "v")]);
        let (local, shared) = partition_credential_writes(
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            &incoming,
            &std::collections::HashMap::new(),
            "shared",
            true,
        );
        assert_eq!(shared.get("corp_pw").unwrap(), "v");
        assert!(local.is_empty());
    }

    #[test]
    fn test_html_escape_multiple() {
        assert_eq!(
            html_escape(r#"<a href="x">&</a>"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;"
        );
    }

    #[test]
    fn test_safe_recording_name_valid() {
        let dir = std::env::temp_dir().join("rustguac-test-recordings");
        let _ = std::fs::create_dir_all(&dir);
        let f1 = dir.join("session-abc123.guac");
        let f2 = dir.join("2024-01-01_recording.guac");
        std::fs::write(&f1, b"").unwrap();
        std::fs::write(&f2, b"").unwrap();
        assert!(is_safe_recording_name("session-abc123.guac", &dir));
        assert!(is_safe_recording_name("2024-01-01_recording.guac", &dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_safe_recording_name_no_guac_extension() {
        assert!(!is_safe_recording_name("session.mp4", Path::new("/tmp")));
        assert!(!is_safe_recording_name("session", Path::new("/tmp")));
    }

    #[test]
    fn test_safe_recording_name_path_traversal() {
        assert!(!is_safe_recording_name(
            "../etc/passwd.guac",
            Path::new("/tmp")
        ));
        assert!(!is_safe_recording_name("foo/bar.guac", Path::new("/tmp")));
        assert!(!is_safe_recording_name("foo\\bar.guac", Path::new("/tmp")));
        assert!(!is_safe_recording_name(
            "..%2F..%2Fetc.guac",
            Path::new("/tmp")
        ));
    }

    #[test]
    fn test_safe_recording_name_empty_and_bare_extension() {
        // Empty string and just-the-extension should never pass.
        assert!(!is_safe_recording_name("", Path::new("/tmp")));
        assert!(!is_safe_recording_name(".guac", Path::new("/tmp")));
    }

    #[test]
    fn test_safe_recording_name_nul_byte_rejected() {
        // NUL in a filename can truncate the name at the syscall boundary on
        // some platforms — must be rejected pre-canonicalize.
        assert!(!is_safe_recording_name("session\0.guac", Path::new("/tmp")));
        assert!(!is_safe_recording_name(
            "sess.guac\0.txt",
            Path::new("/tmp")
        ));
    }

    #[test]
    fn test_safe_recording_name_hidden_traversal() {
        // Double-dot must be rejected anywhere in the name, not just as a
        // segment — covers `foo..bar.guac`, `.guac..evil.guac`, etc.
        assert!(!is_safe_recording_name("foo..bar.guac", Path::new("/tmp")));
        assert!(!is_safe_recording_name("..guac", Path::new("/tmp")));
    }

    #[test]
    fn recording_mp4_access_matches_recording_download() {
        // The MP4 endpoints (#241) share the download's check: poweruser or
        // admin, and a plain .guac name inside the recording directory.
        let dir = std::env::temp_dir().join(format!("rustguac-rec-acl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("s.guac"), "x").unwrap();
        let user = |role: &str| {
            Some(Extension(AuthIdentity::User {
                email: "u@example.com".into(),
                role: role.into(),
                groups: vec![],
            }))
        };
        let status = |id: &Option<Extension<AuthIdentity>>, name: &str| {
            check_recording_read(id, name, &dir)
                .err()
                .map(|r| r.status())
        };
        assert_eq!(status(&user("poweruser"), "s.guac"), None);
        assert_eq!(status(&user("admin"), "s.guac"), None);
        assert_eq!(
            status(&Some(Extension(AuthIdentity::ApiKey("k".into()))), "s.guac"),
            None
        );
        assert_eq!(
            status(&user("operator"), "s.guac"),
            Some(StatusCode::FORBIDDEN)
        );
        assert_eq!(
            status(&user("viewer"), "s.guac"),
            Some(StatusCode::FORBIDDEN)
        );
        assert_eq!(status(&None, "s.guac"), Some(StatusCode::FORBIDDEN));
        for bad in ["../s.guac", "a/s.guac", "s.mp4", "..guac", "s.guac\0"] {
            assert_eq!(
                status(&user("admin"), bad),
                Some(StatusCode::BAD_REQUEST),
                "{bad}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_safe_recording_name_extension_case_sensitive() {
        // Rustguac writes lower-case .guac only; allowing .GUAC creates a
        // second naming space that bypasses admin tools expecting lowercase.
        assert!(!is_safe_recording_name("session.GUAC", Path::new("/tmp")));
        assert!(!is_safe_recording_name("session.Guac", Path::new("/tmp")));
    }

    #[test]
    fn test_is_jpeg_magic_happy_path() {
        assert!(is_jpeg_magic(&[0xFF, 0xD8, 0xFF]));
        assert!(is_jpeg_magic(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00]));
    }

    #[test]
    fn test_is_jpeg_magic_rejects_short_body() {
        assert!(!is_jpeg_magic(&[]));
        assert!(!is_jpeg_magic(&[0xFF]));
        assert!(!is_jpeg_magic(&[0xFF, 0xD8]));
    }

    #[test]
    fn test_is_jpeg_magic_rejects_other_formats() {
        // PNG (89 50 4E), GIF (47 49 46), PDF (25 50 44), HTML-ish (3C 21 44).
        assert!(!is_jpeg_magic(b"\x89PNG\r\n\x1a\n"));
        assert!(!is_jpeg_magic(b"GIF89a"));
        assert!(!is_jpeg_magic(b"%PDF-1.4"));
        assert!(!is_jpeg_magic(b"<!DOCTYPE html>"));
    }

    #[test]
    fn test_is_jpeg_magic_off_by_one_byte() {
        // One-byte variations must not slip through.
        assert!(!is_jpeg_magic(&[0xFE, 0xD8, 0xFF]));
        assert!(!is_jpeg_magic(&[0xFF, 0xD7, 0xFF]));
        assert!(!is_jpeg_magic(&[0xFF, 0xD8, 0xFE]));
    }

    #[test]
    fn session_owner_is_trimmed() {
        assert_eq!(
            validate_session_owner("  alice@example.com "),
            Ok("alice@example.com".to_string())
        );
    }

    #[test]
    fn session_owner_rejects_empty_and_junk() {
        assert!(validate_session_owner("").is_err());
        assert!(validate_session_owner("   ").is_err());
        assert!(validate_session_owner("alice @example.com").is_err());
        assert!(validate_session_owner("alice\u{7}@example.com").is_err());
        assert!(validate_session_owner(&"a".repeat(321)).is_err());
    }

    /// #232: moving and copying entries carries working credentials, so it
    /// stays admin-only like every other entry change.
    #[test]
    fn entry_move_and_copy_are_admin_only() {
        let user = |role: &str| {
            Some(Extension(AuthIdentity::User {
                email: "u@example.com".into(),
                role: role.into(),
                groups: vec![],
            }))
        };
        for role in ["viewer", "operator", "poweruser"] {
            let (status, _) = super::require_ab_admin(&user(role)).unwrap_err();
            assert_eq!(status, StatusCode::FORBIDDEN, "{role}");
        }
        assert!(super::require_ab_admin(&None).is_err());
        assert_eq!(
            super::require_ab_admin(&user("admin")).unwrap(),
            "u@example.com"
        );
    }

    #[test]
    fn vault_name_errors_are_client_errors() {
        let (status, _) = super::ab_vault_error(VaultError::BadName("reserved name".into()));
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = super::ab_vault_error(VaultError::NotFound);
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn rename_candidates_skip_policy_is_just_the_name() {
        assert_eq!(super::rename_candidates("web01", false), vec!["web01"]);
    }

    #[test]
    fn rename_candidates_suffix_and_stay_within_name_limit() {
        let c = super::rename_candidates("web01", true);
        assert_eq!(c[0], "web01");
        assert_eq!(c[1], "web01-2");
        assert_eq!(c.last().unwrap(), "web01-99");
        let long = "a".repeat(64);
        for cand in super::rename_candidates(&long, true) {
            assert!(cand.len() <= 64, "{cand}");
        }
        assert_eq!(
            super::rename_candidates(&long, true)[1],
            format!("{}-2", "a".repeat(62))
        );
    }

    #[test]
    fn bulk_request_defaults_to_skip_and_rejects_unknown_actions() {
        let req: super::BulkRequest = serde_json::from_value(json!({
            "action": "move",
            "items": [{"scope": "shared", "folder": "a", "name": "x"}],
            "target": {"scope": "shared", "folder": "b"},
        }))
        .unwrap();
        assert_eq!(req.action, super::BulkAction::Move);
        assert_eq!(req.on_conflict, super::OnConflict::Skip);
        assert!(serde_json::from_value::<super::BulkRequest>(json!({
            "action": "chmod",
            "items": [],
        }))
        .is_err());
        assert!(
            serde_json::from_value::<super::BulkRequest>(json!({
                "action": "copy",
                "items": [],
                "on_conflict": "overwrite",
            }))
            .is_err(),
            "there is no overwrite policy"
        );
    }

    #[test]
    fn allowed_users_are_tidied() {
        let got = super::normalize_allowed_users(vec![
            " jsmith@example.com ".into(),
            "".into(),
            "JSmith@Example.com".into(),
            "sub-1234".into(),
        ])
        .unwrap();
        assert_eq!(got, vec!["jsmith@example.com", "sub-1234"]);
    }

    #[test]
    fn allowed_users_reject_junk_and_cap_size() {
        assert!(super::normalize_allowed_users(vec!["a b@example.com".into()]).is_err());
        assert!(super::normalize_allowed_users(vec!["a\u{7}@example.com".into()]).is_err());
        assert!(super::normalize_allowed_users(vec!["x".repeat(321)]).is_err());
        let many: Vec<String> = (0..=super::MAX_ALLOWED_USERS)
            .map(|i| format!("u{i}@example.com"))
            .collect();
        assert!(super::normalize_allowed_users(many).is_err());
    }

    // ── Multi-protocol entries (#296): the old flat body still works. ──

    /// Exactly what the NetBox webhook template in docs/netbox.md (before
    /// #296) renders for a device with no custom fields set.
    fn netbox_flat_body() -> serde_json::Value {
        json!({
            "type": "ssh",
            "hostname": "10.0.0.9",
            "port": 22,
            "display_name": "fw01 (DC1)",
            "prompt_credentials": true,
            "external_id": "netbox:device:1"
        })
    }

    #[tokio::test]
    async fn old_netbox_body_upserts_moves_keeps_secrets_and_connects_as_before() {
        let store = FakeStore::with(&[("tenant-a", "fw01", fw01_stored())]);
        let body = super::prepare_entry_body(entry(netbox_flat_body())).unwrap();
        assert!(
            body.protocols.is_none(),
            "an old body stays in the old form"
        );
        let out = upsert_entry(&store, "shared", "tenant-b", "fw01", body, true)
            .await
            .unwrap();
        assert_eq!(out.moved_from, Some(from("tenant-a", "fw01")));
        assert_eq!(store.keys(), ["tenant-b/fw01"]);
        let stored = store.stored("tenant-b", "fw01").unwrap();
        // Stored exactly as before #296: flat, no protocols list.
        let v = serde_json::to_value(&stored).unwrap();
        assert_eq!(v["type"], json!("ssh"));
        assert!(v.get("protocols").is_none());
        assert_eq!(stored.hostname.as_deref(), Some("10.0.0.9"));
        assert_eq!(stored.prompt_credentials, Some(true));
        assert_eq!(stored.password.as_deref(), Some("$tenant_a_password"));
        assert_eq!(stored.private_key.as_deref(), Some("-----BEGIN KEY-----"));
        assert_eq!(stored.external_id.as_deref(), Some("netbox:device:1"));
        // The body has no username or jump hosts, so, as before, they go.
        assert_eq!(stored.username, None);
        // And it connects as the flat entry always did.
        let (name, eff) = stored.pick_protocol(None, None).unwrap();
        assert_eq!(name, "ssh");
        assert_eq!(
            serde_json::to_value(&eff).unwrap(),
            serde_json::to_value(&stored).unwrap()
        );
        // The steady state: a second sync is an update in place.
        let again = upsert_entry(
            &store,
            "shared",
            "tenant-b",
            "fw01",
            super::prepare_entry_body(entry(netbox_flat_body())).unwrap(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(again.moved_from, None);
        assert_eq!(
            store
                .stored("tenant-b", "fw01")
                .unwrap()
                .password
                .as_deref(),
            Some("$tenant_a_password")
        );
    }

    #[test]
    fn new_netbox_template_without_the_new_fields_stores_what_it_did() {
        // The multi-protocol template in docs/netbox.md, rendered for a
        // device whose remote_protocols / remote_ports are unset.
        let e = super::prepare_entry_body(entry(json!({
            "hostname": "10.0.0.9",
            "display_name": "fw01 (DC1)",
            "prompt_credentials": true,
            "external_id": "netbox:device:1",
            "protocols": [{"type": "ssh"}]
        })))
        .unwrap();
        let v = serde_json::to_value(&e).unwrap();
        assert!(v.get("protocols").is_none(), "old form: {v}");
        assert_eq!(v["type"], json!("ssh"));
        assert_eq!(v["prompt_credentials"], json!(true));
        // The old template stored port 22; this one leaves it to the
        // session default, which is 22.
        assert_eq!(e.port, None);
        // And with extra protocols it lists them, primary first.
        let e = super::prepare_entry_body(entry(json!({
            "hostname": "10.0.0.9", "display_name": "fw01 (DC1)", "prompt_credentials": true,
            "external_id": "netbox:device:1",
            "protocols": [{"type": "rdp"}, {"type": "ssh", "port": 2222},
                          {"type": "web", "url": "https://10.0.0.9:8443/"}]
        })))
        .unwrap();
        assert_eq!(e.protocol_types(), ["rdp", "ssh", "web"]);
        let (_, ssh) = e.pick_protocol(Some("ssh"), None).unwrap();
        assert_eq!((ssh.port, ssh.prompt_credentials), (Some(2222), Some(true)));
    }

    #[test]
    fn an_old_body_that_changes_the_type_keeps_the_secrets_as_it_did() {
        let merged = merge_entry_update(
            entry(json!({"type": "rdp", "hostname": "h", "port": 3389})),
            entry(json!({"type": "ssh", "hostname": "h", "password": "pw"})),
        );
        assert_eq!(merged.session_type, "rdp");
        assert_eq!(merged.password.as_deref(), Some("pw"));
        assert!(merged.protocols.is_none());
    }

    #[test]
    fn multi_protocol_update_keeps_each_protocols_secrets_by_name() {
        let existing = entry(json!({
            "hostname": "10.0.0.10", "password": "host-pw", "external_id": "netbox:device:4",
            "protocols": [
                {"type": "rdp", "password": "rdp-pw"},
                {"type": "ssh", "name": "ssh-2222", "port": 2222, "private_key": "KEY"}
            ]
        }));
        // The editor sends no secrets, and has reordered the protocols and
        // added one.
        let data = super::prepare_entry_body(entry(json!({
            "hostname": "10.0.0.11",
            "protocols": [
                {"type": "ssh", "name": "ssh-2222", "port": 2222, "username": "admin"},
                {"type": "rdp"},
                {"type": "vnc"}
            ]
        })))
        .unwrap();
        let merged = merge_entry_update(data, existing);
        assert_eq!(merged.password.as_deref(), Some("host-pw"));
        assert_eq!(merged.external_id.as_deref(), Some("netbox:device:4"));
        let ps = merged.protocols.as_ref().unwrap();
        assert_eq!(ps[0].name(), "ssh-2222");
        assert_eq!(ps[0].settings["private_key"], json!("KEY"));
        assert_eq!(ps[1].settings["password"], json!("rdp-pw"));
        assert!(ps[2].settings.get("password").is_none());
        // Effective credentials: own, then the host's.
        assert_eq!(
            merged.effective(Some("vnc")).unwrap().password.as_deref(),
            Some("host-pw")
        );
        assert_eq!(
            merged.effective(None).unwrap().hostname.as_deref(),
            Some("10.0.0.11")
        );
    }

    #[test]
    fn renaming_a_protocol_keeps_its_secrets_with_renamed_from() {
        let existing = entry(json!({
            "hostname": "h",
            "protocols": [
                {"type": "rdp", "password": "rdp-pw"},
                {"type": "ssh", "name": "ssh-2222", "port": 2222, "private_key": "KEY"}
            ]
        }));
        let body = |renamed_from: serde_json::Value| {
            let mut ssh = json!({"type": "ssh", "name": "ssh-alt", "port": 2222});
            if !renamed_from.is_null() {
                ssh["renamed_from"] = renamed_from;
            }
            super::prepare_entry_body(entry(json!({
                "hostname": "h", "protocols": [{"type": "rdp"}, ssh]
            })))
            .unwrap()
        };
        // Renamed with renamed_from: the key follows it.
        let merged = merge_entry_update(body(json!("ssh-2222")), existing.clone());
        let ps = merged.protocols.as_ref().unwrap();
        assert_eq!(ps[1].name(), "ssh-alt");
        assert_eq!(ps[1].settings["private_key"], json!("KEY"));
        assert_eq!(ps[0].settings["password"], json!("rdp-pw"));
        // It is never stored.
        let stored = serde_json::to_string(&merged).unwrap();
        assert!(!stored.contains("renamed_from"), "{stored}");
        // Without it, the new name matches nothing stored: no secret.
        let merged = merge_entry_update(body(serde_json::Value::Null), existing);
        assert!(merged.protocols.as_ref().unwrap()[1]
            .settings
            .get("private_key")
            .is_none());
        // A malformed one is refused like a malformed name.
        assert!(super::prepare_entry_body(entry(json!({
            "hostname": "h",
            "protocols": [{"type": "ssh", "name": "a", "renamed_from": "has space"}, {"type": "rdp"}]
        })))
        .is_err());
    }

    #[test]
    fn a_new_single_protocol_body_is_stored_in_the_old_form() {
        let e = super::prepare_entry_body(entry(json!({
            "hostname": "h", "display_name": "d",
            "protocols": [{"type": "ssh", "name": "ssh", "port": 22, "username": "u"}]
        })))
        .unwrap();
        assert!(e.protocols.is_none());
        assert_eq!(e.session_type, "ssh");
        // With an access rule it cannot be: an older instance would ignore it.
        let e = super::prepare_entry_body(entry(json!({
            "hostname": "h", "allowed_groups": [" ops ", "ops", ""],
            "protocols": [{"type": "ssh"}]
        })))
        .unwrap();
        assert!(e.protocols.is_some());
        assert_eq!(e.allowed_groups.as_deref(), Some(&["ops".to_string()][..]));
        // So must a flat body with one, as the NetBox webhook or a script
        // would send it: an older instance reading the flat form would
        // ignore the rule.
        let e = super::prepare_entry_body(entry(json!({
            "type": "ssh", "hostname": "h", "port": 22, "password": "pw",
            "allowed_users": ["alice@example.com"]
        })))
        .unwrap();
        assert!(e.protocols.is_some(), "stored in the list form");
        assert!(e.session_type.is_empty());
        assert_eq!(
            e.allowed_users.as_deref(),
            Some(&["alice@example.com".to_string()][..])
        );
        let (name, eff) = e.pick_protocol(None, None).unwrap();
        assert_eq!((name.as_str(), eff.port), ("ssh", Some(22)));
        assert_eq!(eff.password.as_deref(), Some("pw"));
        // Without a rule, a flat body stays flat.
        let e = super::prepare_entry_body(entry(json!({"type": "ssh", "hostname": "h"}))).unwrap();
        assert!(e.protocols.is_none());
        assert!(super::prepare_entry_body(entry(json!({"hostname": "h"}))).is_err());
        assert!(super::prepare_entry_body(entry(json!({
            "protocols": [{"type": "ssh", "allowed_users": ["has space@x"]}]
        })))
        .is_err());
    }

    #[test]
    fn listing_shows_only_the_protocols_a_user_may_use_and_no_secrets() {
        let e = entry(json!({
            "hostname": "10.0.0.10", "username": "Administrator", "password": "host-pw",
            "allowed_groups": ["ops"],
            "protocols": [
                {"type": "rdp", "password": "rdp-pw"},
                {"type": "ssh", "username": "admin", "allowed_groups": ["netops"]}
            ]
        }));
        let ops = vec!["ops".to_string()];
        let netops = vec!["netops".to_string()];
        let none: Vec<String> = vec![];
        let as_user = |groups: &[String]| {
            crate::vault::EntryInfo::for_viewer(
                "srv",
                &e,
                None,
                Some(crate::vault::FolderSubject {
                    email: Some("u@example.com"),
                    groups,
                }),
            )
        };
        let info = as_user(&ops).unwrap();
        assert_eq!(info.session_type, "rdp");
        assert_eq!(info.protocol.as_deref(), Some("rdp"));
        assert_eq!(info.protocols.len(), 1);
        let text = serde_json::to_string(&info).unwrap();
        assert!(!text.contains("pw"), "{text}");
        assert!(!text.contains("allowed_groups"), "rules are for admins");
        assert!(!text.contains("settings"));
        // netops reaches only SSH, so that is what the entry shows as.
        let info = as_user(&netops).unwrap();
        assert_eq!(info.session_type, "ssh");
        assert_eq!(info.username.as_deref(), Some("admin"));
        assert_eq!(info.protocols.len(), 1);
        assert!(as_user(&none).is_none(), "no protocol: no entry");
        // An admin sees both, the rules, and each level's own fields.
        let admin = crate::vault::EntryInfo::for_viewer("srv", &e, None, None).unwrap();
        assert_eq!(admin.protocols.len(), 2);
        let text = serde_json::to_string(&admin).unwrap();
        assert!(!text.contains("pw\""), "{text}");
        assert_eq!(admin.allowed_groups.as_deref(), Some(&ops[..]));
        assert_eq!(
            admin.protocols[1].allowed_groups.as_deref(),
            Some(&netops[..])
        );
        assert_eq!(
            admin.settings.as_ref().unwrap()["has_password"],
            json!(true)
        );
        assert_eq!(
            admin.protocols[0].settings.as_ref().unwrap()["has_password"],
            json!(true)
        );
    }

    #[test]
    fn a_flat_entry_lists_as_before_plus_its_one_protocol() {
        let e = fw01_stored();
        let before = serde_json::to_value(crate::vault::EntryInfo::from(("fw01", &e))).unwrap();
        let who = crate::vault::FolderSubject {
            email: Some("u@example.com"),
            groups: &[],
        };
        let now = serde_json::to_value(
            crate::vault::EntryInfo::for_viewer("fw01", &e, None, Some(who)).unwrap(),
        )
        .unwrap();
        for (k, v) in before.as_object().unwrap() {
            assert_eq!(&now[k], v, "{k} unchanged");
        }
        assert_eq!(now["protocol"], json!("ssh"));
        assert_eq!(now["protocols"].as_array().unwrap().len(), 1);
    }
}
