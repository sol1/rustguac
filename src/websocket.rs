//! WebSocket proxy: bridges browser ↔ guacd TCP socket.

use crate::api::AppState;
use crate::auth::{client_ip, AuthIdentity, TrustedProxies};
use crate::guacd::GuacdStream;
use crate::session::SessionManager;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Path, Query, State,
    },
    http::StatusCode,
    response::IntoResponse,
    Extension,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Which side terminated the proxy connection.
enum ProxyResult {
    /// guacd closed the connection (with optional error).
    GuacdEnded(Option<String>),
    /// Browser/WebSocket closed the connection (with optional error).
    BrowserEnded(Option<String>),
    /// Session was cancelled externally.
    Cancelled,
}

#[derive(Deserialize)]
pub struct WsQuery {
    pub token: Option<String>,
}

/// GET /ws/:session_id — Upgrade to WebSocket and proxy to guacd.
#[allow(clippy::too_many_arguments)]
pub async fn ws_handler(
    State(manager): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(session_id): Path<Uuid>,
    Query(query): Query<WsQuery>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let ip = client_ip(&headers, addr.ip(), &proxies);
    let identity = identity.map(|Extension(id)| id);

    // Check if this is an owner connection (session is Pending)
    let is_owner = manager.is_session_pending(session_id).await;

    if is_owner {
        // Owner path: require authenticated identity with operator+ role
        match &identity {
            Some(id) if id.has_role("operator") => {
                // Authorized — proceed
            }
            _ => {
                tracing::warn!(session_id = %session_id, client_ip = %ip, "Unauthorized owner connection attempt");
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(
                        json!({"error": "authentication required to connect as session owner"}),
                    ),
                )
                    .into_response();
            }
        }
    }

    let identity_name = identity.as_ref().map(|id| id.display_name().to_string());

    ws.protocols(["guacamole"])
        .on_upgrade(move |socket| {
            handle_ws(manager, session_id, query.token, socket, ip, identity_name)
        })
        .into_response()
}

async fn handle_ws(
    manager: Arc<SessionManager>,
    session_id: Uuid,
    token: Option<String>,
    ws: WebSocket,
    client_addr: IpAddr,
    identity_name: Option<String>,
) {
    // Try to take the guacd stream (owner/first connection)
    let (guacd_stream, cancel) = if let Some((stream, cancel)) =
        manager.take_guacd_stream(session_id).await
    {
        let identity_str = identity_name.as_deref().unwrap_or("unknown");
        tracing::info!(session_id = %session_id, client_ip = %client_addr, identity = %identity_str, "Session owner connected");
        (stream, cancel)
    } else {
        // Not pending — try to join an active session
        // Joining requires a valid share token
        let token = match token {
            Some(t) => t,
            None => {
                tracing::warn!(session_id = %session_id, client_ip = %client_addr, "Join attempt without share token");
                return;
            }
        };

        if !manager.validate_share_token(session_id, &token).await {
            tracing::warn!(session_id = %session_id, client_ip = %client_addr, "Share token rejected");
            return;
        }

        match manager.join_session(session_id).await {
            Ok((stream, cancel)) => {
                tracing::info!(session_id = %session_id, client_ip = %client_addr, "Viewer connected via share token");
                (stream, cancel)
            }
            Err(e) => {
                tracing::warn!(session_id = %session_id, client_ip = %client_addr, error = %e, "Failed to join session");
                return;
            }
        }
    };

    tracing::info!(session_id = %session_id, client_ip = %client_addr, "Starting proxy");

    // Set up recording file (only for owner connections, and only if recording is enabled)
    let is_recording_enabled = manager.is_recording_enabled(session_id).await;
    let recording_path = manager
        .recording_path()
        .join(format!("{}.guac", session_id));
    let recording_file = if is_recording_enabled && !recording_path.exists() {
        match tokio::fs::File::create(&recording_path).await {
            Ok(f) => {
                // Set restrictive permissions on recording file
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = tokio::fs::set_permissions(
                        &recording_path,
                        std::fs::Permissions::from_mode(0o640),
                    )
                    .await;
                }

                // Write sidecar .meta file if this session has an address book entry
                if let Some((ab_entry, _)) = manager.get_recording_meta(session_id).await {
                    if ab_entry.is_some() {
                        let meta = crate::recording::RecordingMeta {
                            address_book_entry: ab_entry,
                            created_at: chrono::Utc::now().to_rfc3339(),
                        };
                        if let Err(e) = crate::recording::write_meta(&recording_path, &meta) {
                            tracing::warn!(session_id = %session_id, error = %e, "Failed to write recording .meta");
                        }
                    }
                }

                Some(f)
            }
            Err(e) => {
                tracing::error!(session_id = %session_id, error = %e, "Failed to create recording file");
                None
            }
        }
    } else {
        None // Viewer connections don't record, or recording is disabled
    };

    // Run the bidirectional proxy
    let start = Instant::now();
    let proxy_result = proxy_ws_guacd(ws, guacd_stream, recording_file, cancel).await;
    let elapsed = start.elapsed();

    manager.disconnect_viewer(session_id).await;

    // Log termination direction and timing
    let mark_error = match &proxy_result {
        ProxyResult::GuacdEnded(err) => {
            if elapsed.as_secs() < 5 {
                tracing::warn!(
                    session_id = %session_id, client_ip = %client_addr,
                    elapsed_ms = elapsed.as_millis() as u64,
                    error = ?err,
                    "guacd closed connection quickly (possible connection failure)"
                );
                true // mark as error
            } else {
                tracing::info!(
                    session_id = %session_id, client_ip = %client_addr,
                    elapsed_secs = elapsed.as_secs(),
                    "Proxy ended: guacd closed connection"
                );
                false
            }
        }
        ProxyResult::BrowserEnded(err) => {
            tracing::info!(
                session_id = %session_id, client_ip = %client_addr,
                elapsed_secs = elapsed.as_secs(),
                error = ?err,
                "Proxy ended: browser disconnected"
            );
            false
        }
        ProxyResult::Cancelled => {
            tracing::info!(
                session_id = %session_id, client_ip = %client_addr,
                elapsed_secs = elapsed.as_secs(),
                "Proxy ended: session cancelled"
            );
            false
        }
    };

    if mark_error {
        manager.error_session(session_id).await;
    } else {
        // Only mark completed if no more active connections
        let info = manager.get_session(session_id).await;
        if let Some(info) = info {
            if info.active_connections == 0 {
                manager.complete_session(session_id).await;
            }
        }
    }

    // Per-entry recording rotation (after session ends, recording file is complete)
    if is_recording_enabled {
        if let Some((Some(entry_key), Some(max_recs))) =
            manager.get_recording_meta(session_id).await
        {
            if max_recs > 0 {
                let rec_dir = manager.recording_path().to_path_buf();
                tokio::task::spawn_blocking(move || {
                    crate::recording::rotate_per_entry(&rec_dir, &entry_key, max_recs);
                });
            }
        }
    }

    tracing::info!(session_id = %session_id, client_ip = %client_addr, "Session disconnected");
}

/// Bidirectional proxy between WebSocket and guacd stream (TCP or TLS).
async fn proxy_ws_guacd(
    ws: WebSocket,
    guacd: GuacdStream,
    recording_file: Option<tokio::fs::File>,
    cancel: CancellationToken,
) -> ProxyResult {
    let (guacd_read, guacd_write) = tokio::io::split(guacd);
    let (ws_write, ws_read) = ws.split();

    let recording = recording_file.map(|f| Arc::new(tokio::sync::Mutex::new(f)));

    // guacd → browser (also tee to recording)
    let recording_clone = recording.clone();
    let guacd_to_browser =
        tokio::spawn(async move { guacd_to_ws(guacd_read, ws_write, recording_clone).await });

    // browser → guacd
    let browser_to_guacd = tokio::spawn(async move { ws_to_guacd(ws_read, guacd_write).await });

    // Wait for either direction to finish, or cancellation
    tokio::select! {
        result = guacd_to_browser => {
            let err = match result {
                Ok(Err(e)) => Some(e.to_string()),
                Err(e) => Some(e.to_string()),
                _ => None,
            };
            ProxyResult::GuacdEnded(err)
        }
        result = browser_to_guacd => {
            let err = match result {
                Ok(Err(e)) => Some(e.to_string()),
                Err(e) => Some(e.to_string()),
                _ => None,
            };
            ProxyResult::BrowserEnded(err)
        }
        _ = cancel.cancelled() => {
            ProxyResult::Cancelled
        }
    }
}

/// Forward data from guacd to WebSocket, recording along the way.
async fn guacd_to_ws(
    mut guacd: tokio::io::ReadHalf<GuacdStream>,
    mut ws: futures_util::stream::SplitSink<WebSocket, Message>,
    recording: Option<Arc<tokio::sync::Mutex<tokio::fs::File>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = vec![0u8; 8192];

    loop {
        let n = guacd.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        let data = &buf[..n];

        // Write to recording file if available
        if let Some(ref recording) = recording {
            let mut file = recording.lock().await;
            let _ = file.write_all(data).await;
        }

        // Forward to browser via WebSocket
        let text = String::from_utf8_lossy(data).into_owned();
        ws.send(Message::Text(text.into())).await?;
    }

    Ok(())
}

/// Forward data from WebSocket to guacd.
async fn ws_to_guacd(
    mut ws: futures_util::stream::SplitStream<WebSocket>,
    mut guacd: tokio::io::WriteHalf<GuacdStream>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    while let Some(msg) = ws.next().await {
        let msg = msg?;
        match msg {
            Message::Text(text) => {
                guacd.write_all(text.as_bytes()).await?;
            }
            Message::Binary(data) => {
                guacd.write_all(&data).await?;
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    Ok(())
}
