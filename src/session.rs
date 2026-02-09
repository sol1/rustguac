use crate::browser::{BrowserManager, BrowserSession};
use crate::config::Config;
use crate::drive;
use crate::guacd;
use crate::guacd::GuacdStream;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

/// Session type: SSH terminal, web browser, or RDP.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessionType {
    #[default]
    Ssh,
    Web,
    Rdp,
}

/// Parameters for creating a new session.
#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    #[serde(default)]
    pub session_type: SessionType,
    // SSH fields (optional for backwards compat)
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub generate_keypair: Option<bool>,
    // Web fields
    pub url: Option<String>,
    // RDP fields
    pub domain: Option<String>,
    pub security: Option<String>,
    pub ignore_cert: Option<bool>,
    /// NLA auth package: "kerberos", "ntlm", or empty (negotiate).
    pub auth_pkg: Option<String>,
    /// Kerberos KDC URL (optional).
    pub kdc_url: Option<String>,
    /// Kerberos ticket cache path (optional).
    pub kerberos_cache: Option<String>,
    // Common
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub dpi: Option<u32>,
    pub banner: Option<String>,
    /// Override drive/file transfer setting for this session.
    pub enable_drive: Option<bool>,
}

/// Session status in the lifecycle.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    /// guacd connected, waiting for browser
    Pending,
    /// Browser connected, session active
    Active,
    /// Session ended normally
    Completed,
    /// Session ended due to error
    Error,
    /// Session expired (no browser connected in time)
    Expired,
}

/// Public session info returned by the API.
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub session_id: Uuid,
    pub session_type: SessionType,
    pub status: SessionStatus,
    pub created_at: DateTime<Utc>,
    pub client_url: String,
    pub share_url: String,
    pub ws_url: String,
    pub hostname: String,
    pub username: String,
    pub active_connections: u32,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Internal session state including the guacd connection.
pub struct Session {
    pub id: Uuid,
    pub session_type: SessionType,
    pub status: SessionStatus,
    pub created_at: DateTime<Utc>,
    pub hostname: String,
    pub username: String,
    pub url: Option<String>,
    pub banner: Option<String>,
    pub guacd_stream: Option<GuacdStream>,
    pub connection_id: String,
    pub share_token: String,
    pub width: u32,
    pub height: u32,
    pub active_connections: u32,
    pub created_by: String,
    pub cancel: CancellationToken,
    pub browser_session: Option<BrowserSession>,
    /// Connection params for deferred guacd connection (ephemeral keypair sessions).
    /// When set, the guacd connection is established when the WebSocket connects
    /// instead of at session creation time.
    pub deferred_params: Option<guacd::ConnectionParams>,
    /// Per-session drive directory path (RDP sessions with drive enabled).
    pub drive_path: Option<std::path::PathBuf>,
}

fn generate_share_token() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    hex::encode(bytes)
}

/// Check that a host resolves to an IP within the allowed CIDR networks.
fn check_allowed_network(host: &str, port: u16, allowed: &[String]) -> Result<(), SessionError> {
    let networks: Vec<IpNetwork> = allowed
        .iter()
        .filter_map(|s| s.parse::<IpNetwork>().ok())
        .collect();

    if networks.is_empty() {
        return Err(SessionError::ValidationError(
            "no valid CIDR networks configured in allowlist".into(),
        ));
    }

    // Try parsing host as an IP address directly first
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if networks.iter().any(|net| net.contains(ip)) {
            return Ok(());
        }
        return Err(SessionError::ValidationError(format!(
            "host {} is not in the allowed network list",
            host
        )));
    }

    // Resolve hostname to IP addresses
    let addrs: Vec<std::net::SocketAddr> = format!("{}:{}", host, port)
        .to_socket_addrs()
        .map_err(|e| {
            SessionError::ValidationError(format!("failed to resolve host '{}': {}", host, e))
        })?
        .collect();

    if addrs.is_empty() {
        return Err(SessionError::ValidationError(format!(
            "host '{}' did not resolve to any addresses",
            host
        )));
    }

    for addr in &addrs {
        if networks.iter().any(|net| net.contains(addr.ip())) {
            return Ok(());
        }
    }

    Err(SessionError::ValidationError(format!(
        "host '{}' resolves to addresses not in the allowed network list",
        host
    )))
}

impl Session {
    pub fn info(&self) -> SessionInfo {
        SessionInfo {
            session_id: self.id,
            session_type: self.session_type.clone(),
            status: self.status.clone(),
            created_at: self.created_at,
            client_url: format!("/client/{}", self.id),
            share_url: format!("/client/{}?token={}", self.id, self.share_token),
            ws_url: format!("/ws/{}", self.id),
            hostname: self.hostname.clone(),
            username: self.username.clone(),
            active_connections: self.active_connections,
            created_by: self.created_by.clone(),
            banner: self.banner.clone(),
            url: self.url.clone(),
        }
    }
}

/// Manages all active sessions.
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<Uuid, Arc<Mutex<Session>>>>>,
    config: Config,
    browser_manager: Arc<BrowserManager>,
    guacd_tls: Option<TlsConnector>,
}

impl SessionManager {
    pub fn new(config: Config, guacd_tls: Option<TlsConnector>) -> Self {
        // Ensure recording directory exists with restrictive permissions
        if let Err(e) = std::fs::create_dir_all(&config.recording_path) {
            tracing::warn!("Failed to create recording directory: {}", e);
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &config.recording_path,
                    std::fs::Permissions::from_mode(0o750),
                );
            }
        }

        let browser_manager = Arc::new(BrowserManager::new(
            config.xvnc_path.clone(),
            config.chromium_path.clone(),
            config.display_range_start,
            config.display_range_end,
        ));

        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            config,
            browser_manager,
            guacd_tls,
        }
    }

    /// Create a new session: connect to guacd, perform handshake, return session info.
    pub async fn create_session(
        &self,
        req: CreateSessionRequest,
        created_by: String,
    ) -> Result<SessionInfo, SessionError> {
        let session_id = Uuid::new_v4();
        let width = req.width.unwrap_or(1920);
        let height = req.height.unwrap_or(1080);
        let dpi = req.dpi.unwrap_or(96);

        let (
            conn_params,
            hostname,
            username,
            url,
            browser_session,
            banner_override,
            session_drive_path,
        ) = match req.session_type {
            SessionType::Ssh => {
                let hostname = req.hostname.ok_or_else(|| {
                    SessionError::ValidationError("hostname is required for SSH sessions".into())
                })?;
                let port = req.port.unwrap_or(22);
                let username = req.username.clone().unwrap_or_default();

                check_allowed_network(&hostname, port, &self.config.ssh_allowed_networks)?;

                tracing::info!(
                    session_id = %session_id,
                    hostname = %hostname,
                    username = %username,
                    "Creating new SSH session"
                );

                let (private_key, ssh_banner) = if req.generate_keypair.unwrap_or(false) {
                    let keypair = ssh_key::PrivateKey::random(
                        &mut ssh_key::rand_core::OsRng,
                        ssh_key::Algorithm::Ed25519,
                    )
                    .map_err(|e| {
                        SessionError::ValidationError(format!("keypair generation failed: {}", e))
                    })?;

                    let private_pem = keypair.to_openssh(ssh_key::LineEnding::LF).map_err(|e| {
                        SessionError::ValidationError(format!("private key export failed: {}", e))
                    })?;

                    let public_key = format!(
                        "{} rustguac-ephemeral",
                        keypair.public_key().to_openssh().map_err(|e| {
                            SessionError::ValidationError(format!(
                                "public key export failed: {}",
                                e
                            ))
                        })?
                    );

                    let auth_keys_path = if username.is_empty() {
                        "~/.ssh/authorized_keys".to_string()
                    } else {
                        format!("~{}/.ssh/authorized_keys", username)
                    };

                    let mut banner = format!(
                        "Add this public key to {} on the target host:\n\n{}\n\nDo not click Continue until the key is installed — authentication will fail.",
                        auth_keys_path, public_key
                    );
                    if let Some(ref user_banner) = req.banner {
                        banner = format!("{}\n\n{}", user_banner, banner);
                    }

                    tracing::info!(session_id = %session_id, "Generated ephemeral SSH keypair");
                    (Some(private_pem.to_string()), Some(banner))
                } else {
                    (req.private_key.clone(), None)
                };

                let drive_enabled = drive::is_drive_enabled(&self.config.drive, req.enable_drive);
                let drive_cfg = drive::drive_config_or_default(&self.config.drive);

                let params = guacd::ConnectionParams::Ssh(guacd::SshParams {
                    hostname: hostname.clone(),
                    port,
                    username: username.clone(),
                    password: req.password.clone(),
                    private_key,
                    width,
                    height,
                    dpi,
                    enable_sftp: drive_enabled,
                    sftp_disable_download: !drive_cfg.allow_download,
                    sftp_disable_upload: !drive_cfg.allow_upload,
                });
                (params, hostname, username, None, None, ssh_banner, None)
            }
            SessionType::Rdp => {
                let hostname = req.hostname.ok_or_else(|| {
                    SessionError::ValidationError("hostname is required for RDP sessions".into())
                })?;
                let port = req.port.unwrap_or(3389);
                let username = req.username.clone().unwrap_or_default();

                check_allowed_network(&hostname, port, &self.config.rdp_allowed_networks)?;

                tracing::info!(
                    session_id = %session_id,
                    hostname = %hostname,
                    username = %username,
                    "Creating new RDP session"
                );

                let drive_enabled = drive::is_drive_enabled(&self.config.drive, req.enable_drive);
                let drive_cfg = drive::drive_config_or_default(&self.config.drive);

                // Create per-session drive directory for RDP
                let session_drive_path = if drive_enabled {
                    match drive::create_session_dir(&drive_cfg, session_id) {
                        Ok(path) => Some(path),
                        Err(e) => {
                            tracing::warn!(session_id = %session_id, "Failed to create drive dir: {}", e);
                            None
                        }
                    }
                } else {
                    None
                };

                let rdp_ignore_cert = req.ignore_cert.unwrap_or(false);
                let rdp_security = req.security.clone();
                let rdp_enable_drive = session_drive_path.is_some();
                tracing::info!(
                    %session_id,
                    ignore_cert = rdp_ignore_cert,
                    security = ?rdp_security,
                    enable_drive = rdp_enable_drive,
                    domain = ?req.domain,
                    has_password = req.password.is_some(),
                    "RDP session params"
                );
                let params = guacd::ConnectionParams::Rdp(guacd::RdpParams {
                    hostname: hostname.clone(),
                    port,
                    username: username.clone(),
                    password: req.password.clone(),
                    domain: req.domain.clone(),
                    security: rdp_security,
                    width,
                    height,
                    dpi,
                    ignore_cert: rdp_ignore_cert,
                    enable_drive: rdp_enable_drive,
                    drive_path: session_drive_path
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string()),
                    drive_name: drive_cfg.drive_name.clone(),
                    disable_download: !drive_cfg.allow_download,
                    disable_upload: !drive_cfg.allow_upload,
                    auth_pkg: req.auth_pkg.clone(),
                    kdc_url: req.kdc_url.clone(),
                    kerberos_cache: req.kerberos_cache.clone(),
                });
                (
                    params,
                    hostname,
                    username,
                    None,
                    None,
                    None,
                    session_drive_path,
                )
            }
            SessionType::Web => {
                let url = req.url.ok_or_else(|| {
                    SessionError::ValidationError("url is required for web sessions".into())
                })?;

                // Validate URL scheme and structure
                let parsed = Url::parse(&url)
                    .map_err(|e| SessionError::ValidationError(format!("invalid URL: {}", e)))?;
                match parsed.scheme() {
                    "http" | "https" => {}
                    s => {
                        return Err(SessionError::ValidationError(format!(
                            "URL scheme '{}' not allowed (must be http or https)",
                            s
                        )))
                    }
                }
                let url_host = parsed
                    .host_str()
                    .ok_or_else(|| SessionError::ValidationError("URL has no host".into()))?;
                let url_port =
                    parsed
                        .port()
                        .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });

                check_allowed_network(url_host, url_port, &self.config.web_allowed_networks)?;

                tracing::info!(
                    session_id = %session_id,
                    url = %url,
                    "Creating new web session"
                );

                let browser = self
                    .browser_manager
                    .spawn(&url, width, height)
                    .await
                    .map_err(|e| SessionError::BrowserSpawn(e.to_string()))?;

                let vnc_port = browser.vnc_port;

                tracing::info!(
                    session_id = %session_id,
                    vnc_port = %vnc_port,
                    display = %browser.display,
                    "Browser processes ready, connecting guacd via VNC"
                );

                let params = guacd::ConnectionParams::Vnc(guacd::VncParams {
                    hostname: "127.0.0.1".into(),
                    port: vnc_port,
                    width,
                    height,
                    dpi,
                });
                (
                    params,
                    "localhost".into(),
                    String::new(),
                    Some(url),
                    Some(browser),
                    None,
                    None,
                )
            }
        };

        // For ephemeral keypair sessions, defer the guacd connection until
        // the user dismisses the banner (i.e. when the WebSocket connects).
        // This gives the user time to copy the public key and add it to
        // authorized_keys before guacd attempts SSH authentication.
        let deferred = banner_override.is_some();

        let (guacd_stream, connection_id, deferred_params) = if deferred {
            tracing::info!(
                session_id = %session_id,
                "Deferring guacd connection (ephemeral keypair — waiting for user to add public key)"
            );
            (None, String::new(), Some(conn_params))
        } else {
            // Connect to guacd and perform handshake
            let handshake_result = guacd::connect_and_handshake(
                &self.config.guacd_addr,
                &conn_params,
                self.guacd_tls.as_ref(),
            )
            .await;

            // If handshake fails, clean up browser processes
            let (stream, connection_id) = match handshake_result {
                Ok(result) => result,
                Err(e) => {
                    if let Some(mut bs) = browser_session {
                        self.browser_manager.kill(&mut bs).await;
                    }
                    tracing::error!(session_id = %session_id, error = %e, "Failed to connect to guacd");
                    return Err(SessionError::GuacdConnection(e.to_string()));
                }
            };

            tracing::info!(
                session_id = %session_id,
                connection_id = %connection_id,
                "guacd connection established"
            );
            (Some(stream), connection_id, None)
        };

        let session = Session {
            id: session_id,
            session_type: req.session_type,
            status: SessionStatus::Pending,
            created_at: Utc::now(),
            hostname,
            username,
            url,
            banner: banner_override.or(req.banner),
            guacd_stream,
            connection_id,
            share_token: generate_share_token(),
            width,
            height,
            active_connections: 0,
            created_by,
            cancel: CancellationToken::new(),
            browser_session,
            deferred_params,
            drive_path: session_drive_path,
        };

        let info = session.info();
        let session = Arc::new(Mutex::new(session));

        self.sessions
            .write()
            .await
            .insert(session_id, session.clone());

        // Spawn timeout task for pending sessions
        let sessions_ref = Arc::clone(&self.sessions);
        let browser_mgr = Arc::clone(&self.browser_manager);
        let timeout_secs = self.config.session_pending_timeout_secs;
        tokio::spawn(async move {
            time::sleep(time::Duration::from_secs(timeout_secs)).await;
            let sessions_read = sessions_ref.read().await;
            if let Some(session) = sessions_read.get(&session_id) {
                let mut session = session.lock().await;
                if session.status == SessionStatus::Pending {
                    tracing::warn!(session_id = %session_id, "Session expired (no browser connected)");
                    session.status = SessionStatus::Expired;
                    session.guacd_stream = None;
                    cleanup_browser(&browser_mgr, &mut session).await;
                }
            }
        });

        Ok(info)
    }

    /// List all sessions.
    pub async fn list_sessions(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.read().await;
        let mut result = Vec::new();
        for session in sessions.values() {
            let session = session.lock().await;
            result.push(session.info());
        }
        result
    }

    /// Get a specific session's info.
    pub async fn get_session(&self, id: Uuid) -> Option<SessionInfo> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(&id)?;
        let session = session.lock().await;
        Some(session.info())
    }

    /// Take the guacd stream from a session (for the owner/first WebSocket connection).
    /// Transitions the session to Active. Returns the stream and a cancellation token.
    /// For deferred connections (ephemeral keypair), connects to guacd here.
    pub async fn take_guacd_stream(&self, id: Uuid) -> Option<(GuacdStream, CancellationToken)> {
        let sessions = self.sessions.read().await;
        let session_arc = sessions.get(&id)?;
        let mut session = session_arc.lock().await;
        if session.status != SessionStatus::Pending {
            return None;
        }

        // If this is a deferred connection, connect to guacd now
        if let Some(params) = session.deferred_params.take() {
            tracing::info!(session_id = %id, "Establishing deferred guacd connection");
            match guacd::connect_and_handshake(
                &self.config.guacd_addr,
                &params,
                self.guacd_tls.as_ref(),
            )
            .await
            {
                Ok((stream, connection_id)) => {
                    tracing::info!(
                        session_id = %id,
                        connection_id = %connection_id,
                        "Deferred guacd connection established"
                    );
                    session.guacd_stream = Some(stream);
                    session.connection_id = connection_id;
                }
                Err(e) => {
                    tracing::error!(session_id = %id, error = %e, "Deferred guacd connection failed");
                    session.status = SessionStatus::Error;
                    return None;
                }
            }
        }

        let stream = session.guacd_stream.take()?;
        let cancel = session.cancel.clone();
        session.status = SessionStatus::Active;
        session.active_connections += 1;
        tracing::info!(session_id = %id, "Session now active (owner connected)");
        Some((stream, cancel))
    }

    /// Join an active session by opening a new guacd connection.
    /// Returns a new GuacdStream and the session's cancellation token.
    pub async fn join_session(
        &self,
        id: Uuid,
    ) -> Result<(GuacdStream, CancellationToken), SessionError> {
        let (connection_id, width, height, cancel) = {
            let sessions = self.sessions.read().await;
            let session = sessions.get(&id).ok_or(SessionError::NotFound)?;
            let session = session.lock().await;
            if session.status != SessionStatus::Active {
                return Err(SessionError::NotActive);
            }
            (
                session.connection_id.clone(),
                session.width,
                session.height,
                session.cancel.clone(),
            )
        };

        let stream = guacd::join_connection(
            &self.config.guacd_addr,
            &connection_id,
            width,
            height,
            96,
            self.guacd_tls.as_ref(),
        )
        .await
        .map_err(|e| {
            tracing::error!(session_id = %id, error = %e, "Failed to join guacd session");
            SessionError::GuacdConnection(e.to_string())
        })?;

        // Increment active connections
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let mut session = session.lock().await;
            session.active_connections += 1;
        }

        tracing::info!(session_id = %id, "Viewer joined session");
        Ok((stream, cancel))
    }

    /// Validate a share token for a session (constant-time comparison).
    pub async fn validate_share_token(&self, id: Uuid, token: &str) -> bool {
        use sha2::{Digest, Sha256};
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let session = session.lock().await;
            // Compare SHA-256 hashes to avoid timing side-channel on token length/content
            let expected = Sha256::digest(session.share_token.as_bytes());
            let provided = Sha256::digest(token.as_bytes());
            expected == provided
        } else {
            false
        }
    }

    /// Decrement active connection count when a WebSocket disconnects.
    pub async fn disconnect_viewer(&self, id: Uuid) {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let mut session = session.lock().await;
            session.active_connections = session.active_connections.saturating_sub(1);
        }
    }

    /// Mark a session as completed.
    pub async fn complete_session(&self, id: Uuid) {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let mut session = session.lock().await;
            if session.status == SessionStatus::Active {
                session.status = SessionStatus::Completed;
                cleanup_browser(&self.browser_manager, &mut session).await;
                tracing::info!(session_id = %id, "Session completed");
            }
        }
    }

    /// Mark a session as errored.
    pub async fn error_session(&self, id: Uuid) {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let mut session = session.lock().await;
            session.status = SessionStatus::Error;
            session.guacd_stream = None;
            cleanup_browser(&self.browser_manager, &mut session).await;
        }
    }

    /// Check if a session is in Pending status (owner not yet connected).
    pub async fn is_session_pending(&self, id: Uuid) -> bool {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let session = session.lock().await;
            session.status == SessionStatus::Pending
        } else {
            false
        }
    }

    /// Get the creator of a session.
    pub async fn get_session_creator(&self, id: Uuid) -> Option<String> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(&id)?;
        let session = session.lock().await;
        Some(session.created_by.clone())
    }

    /// Terminate a session. Cancels all active proxy connections.
    pub async fn delete_session(&self, id: Uuid) -> bool {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.remove(&id) {
            let mut session = session.lock().await;
            session.cancel.cancel();
            session.status = SessionStatus::Completed;
            session.guacd_stream = None;
            cleanup_browser(&self.browser_manager, &mut session).await;
            tracing::info!(session_id = %id, "Session terminated by API");
            true
        } else {
            false
        }
    }

    /// Reap active sessions that have exceeded the max duration.
    /// Returns the number of sessions reaped.
    pub async fn reap_expired_sessions(&self) -> usize {
        let max_duration = std::time::Duration::from_secs(self.config.session_max_duration_secs);
        let now = Utc::now();
        let mut to_delete = Vec::new();

        {
            let sessions = self.sessions.read().await;
            for (id, session) in sessions.iter() {
                let session = session.lock().await;
                if session.status == SessionStatus::Active
                    || session.status == SessionStatus::Pending
                {
                    let age = now.signed_duration_since(session.created_at);
                    if age.to_std().unwrap_or_default() > max_duration {
                        to_delete.push(*id);
                    }
                }
            }
        }

        let count = to_delete.len();
        for id in to_delete {
            tracing::warn!(session_id = %id, "Reaping session (exceeded max duration)");
            self.delete_session(id).await;
        }
        count
    }

    pub fn recording_path(&self) -> &std::path::Path {
        &self.config.recording_path
    }

    pub fn session_max_duration_secs(&self) -> u64 {
        self.config.session_max_duration_secs
    }
}

/// Kill browser processes if this is a web session, and clean up drive directory.
async fn cleanup_browser(browser_manager: &BrowserManager, session: &mut Session) {
    if let Some(ref mut bs) = session.browser_session {
        browser_manager.kill(bs).await;
    }
    session.browser_session = None;

    // Clean up per-session drive directory
    if let Some(ref drive_path) = session.drive_path {
        drive::cleanup_session_dir(drive_path.clone(), session.id, 0).await;
        session.drive_path = None;
    }
}

#[derive(Debug)]
pub enum SessionError {
    GuacdConnection(String),
    NotFound,
    NotActive,
    ValidationError(String),
    BrowserSpawn(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::GuacdConnection(msg) => write!(f, "guacd connection failed: {}", msg),
            SessionError::NotFound => write!(f, "session not found"),
            SessionError::NotActive => write!(f, "session is not active"),
            SessionError::ValidationError(msg) => write!(f, "validation error: {}", msg),
            SessionError::BrowserSpawn(msg) => write!(f, "browser spawn failed: {}", msg),
        }
    }
}
