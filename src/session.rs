use crate::browser::{BrowserManager, BrowserSession};
use crate::config::Config;
use crate::drive;
use crate::guacd;
use crate::guacd::GuacdStream;
use crate::tunnel;
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

/// Session type: SSH terminal, web browser, RDP, VNC, or VDI container.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessionType {
    #[default]
    Ssh,
    Web,
    Rdp,
    Vnc,
    Vdi,
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
    // VNC fields
    pub color_depth: Option<u8>,
    // SSH tunnel / jump host fields (multi-hop)
    pub jump_hosts: Option<Vec<tunnel::JumpHost>>,
    // Legacy flat fields for backward compat (single jump host)
    pub jump_host: Option<String>,
    pub jump_port: Option<u16>,
    pub jump_username: Option<String>,
    pub jump_password: Option<String>,
    pub jump_private_key: Option<String>,
    // Common
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub dpi: Option<u32>,
    pub banner: Option<String>,
    /// Override drive/file transfer setting for this session.
    pub enable_drive: Option<bool>,
    // RDP RemoteApp (RAIL)
    pub remote_app: Option<String>,
    pub remote_app_dir: Option<String>,
    pub remote_app_args: Option<String>,
    // Recording overrides
    pub enable_recording: Option<bool>,
    /// Address book entry key (e.g. "shared/folder/entry") for recording metadata.
    pub address_book_entry: Option<String>,
    /// Address book folder name (for reporting).
    pub address_book_folder: Option<String>,
    /// Display name of the address book entry (for reporting).
    pub entry_display_name: Option<String>,
    /// Per-entry max recordings to keep.
    pub max_recordings: Option<u32>,
    /// Login script filename to run after browser spawns (web sessions only).
    pub login_script: Option<String>,
    /// Autofill credentials JSON for web sessions.
    /// Array of {"url", "username", "password"} with $USERNAME/$PASSWORD placeholders.
    pub autofill: Option<String>,
    /// Allowed domains for web sessions. When set, Chromium can only reach these domains.
    pub allowed_domains: Option<Vec<String>>,
    /// Disable clipboard copy (server → client).
    pub disable_copy: Option<bool>,
    /// Disable clipboard paste (client → server).
    pub disable_paste: Option<bool>,
    /// Enable RDP Graphics Pipeline Extension (GFX).
    pub enable_gfx: Option<bool>,
    /// Enable desktop composition (DWM) for RDP.
    pub enable_desktop_composition: Option<bool>,
    /// Force lossless encoding (PNG only) for RDP.
    pub force_lossless: Option<bool>,
    /// Enable H.264 passthrough for RDP.
    pub enable_h264: Option<bool>,
    // VDI fields
    /// Docker image for VDI sessions (e.g. "myregistry/desktop:latest").
    pub container_image: Option<String>,
    /// CPU limit override for VDI container (fractional cores).
    pub container_cpu_limit: Option<f64>,
    /// Memory limit override for VDI container in MB.
    pub container_memory_limit: Option<u64>,
    /// Extra environment variables for VDI container.
    pub container_env: Option<std::collections::HashMap<String, String>>,
    /// Override idle timeout for VDI container in minutes.
    pub container_idle_timeout_mins: Option<u64>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_book_entry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_book_folder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
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
    /// SSH tunnel chain (jump hosts) — kept alive for the session duration.
    pub tunnels: Vec<tunnel::SshTunnel>,
    /// Docker container ID for VDI sessions.
    pub container_id: Option<String>,
    /// Whether recording is enabled for this session.
    pub recording_enabled: bool,
    /// Address book entry key (e.g. "shared/folder/entry") for recording metadata.
    pub address_book_entry: Option<String>,
    /// Address book folder name (for reporting).
    pub address_book_folder: Option<String>,
    /// Display name of the address book entry (for reporting).
    pub entry_display_name: Option<String>,
    /// Per-entry max recordings to keep (from address book entry).
    pub max_recordings: Option<u32>,
    /// Login script task handle (aborted on session cleanup).
    pub login_script_handle: Option<tokio::task::JoinHandle<()>>,
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
            address_book_entry: self.address_book_entry.clone(),
            address_book_folder: self.address_book_folder.clone(),
            entry_display_name: self.entry_display_name.clone(),
            thumbnail_url: Some(format!("/api/sessions/{}/thumbnail", self.id)),
        }
    }
}

/// Manages all active sessions.
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<Uuid, Arc<Mutex<Session>>>>>,
    config: Config,
    browser_manager: Arc<BrowserManager>,
    guacd_tls: Option<TlsConnector>,
    db: Option<crate::db::Db>,
    vdi_driver: Option<Arc<dyn crate::vdi::VdiDriver>>,
}

impl SessionManager {
    pub fn new_with_db(config: Config, guacd_tls: Option<TlsConnector>, db: crate::db::Db) -> Self {
        let mut mgr = Self::new(config, guacd_tls);
        mgr.db = Some(db);
        mgr
    }

    pub fn new(config: Config, guacd_tls: Option<TlsConnector>) -> Self {
        // Ensure recording directory exists with restrictive permissions
        let rec_path = config.effective_recording_path();
        if let Err(e) = std::fs::create_dir_all(rec_path) {
            tracing::warn!("Failed to create recording directory: {}", e);
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(rec_path, std::fs::Permissions::from_mode(0o750));
            }
        }

        let browser_manager = Arc::new(BrowserManager::new(
            config.xvnc_path.clone(),
            config.chromium_path.clone(),
            config.display_range_start,
            config.display_range_end,
            config.cdp_port_range_start,
            config.cdp_port_range_end,
            std::path::PathBuf::from(&config.login_scripts_dir),
            config.login_script_timeout_secs,
        ));

        let vdi_driver = Self::init_vdi_driver(&config);

        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            config,
            browser_manager,
            guacd_tls,
            db: None,
            vdi_driver,
        }
    }

    fn init_vdi_driver(config: &Config) -> Option<Arc<dyn crate::vdi::VdiDriver>> {
        let vdi_cfg = config.vdi.as_ref()?;
        if !vdi_cfg.enabled {
            return None;
        }
        match crate::vdi::DockerDriver::new(&vdi_cfg.docker_socket) {
            Ok(driver) => {
                let driver = driver.with_ready_timeout(vdi_cfg.ready_timeout_secs);
                tracing::info!(
                    socket = %vdi_cfg.docker_socket,
                    idle_timeout_mins = vdi_cfg.idle_timeout_mins,
                    "VDI Docker driver initialized"
                );
                Some(Arc::new(driver))
            }
            Err(e) => {
                tracing::error!("Failed to initialize VDI Docker driver: {}", e);
                None
            }
        }
    }

    /// Get the VDI driver (if enabled).
    pub fn vdi_driver(&self) -> Option<&dyn crate::vdi::VdiDriver> {
        self.vdi_driver.as_deref()
    }

    /// Read-only access to the config.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Create a new session: connect to guacd, perform handshake, return session info.
    pub async fn create_session(
        &self,
        req: CreateSessionRequest,
        created_by: String,
    ) -> Result<SessionInfo, SessionError> {
        let session_id = Uuid::new_v4();
        let raw_width = req.width.unwrap_or(1920);
        let raw_height = req.height.unwrap_or(1080);
        let raw_dpi = req.dpi.unwrap_or(96);
        let width = raw_width.clamp(640, 8192);
        let height = raw_height.clamp(480, 8192);
        let dpi = raw_dpi.clamp(16, 384);
        if width != raw_width || height != raw_height || dpi != raw_dpi {
            tracing::warn!(
                session_id = %session_id,
                raw_width, raw_height, raw_dpi,
                clamped_width = width, clamped_height = height, clamped_dpi = dpi,
                "Clamped session dimensions to safe range"
            );
        }

        let (
            mut conn_params,
            hostname,
            username,
            url,
            mut browser_session,
            banner_override,
            session_drive_path,
            container_id,
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
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                });
                (params, hostname, username, None, None, ssh_banner, None, None)
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
                    width, height, dpi,
                    "Creating new RDP session"
                );

                let drive_enabled = drive::is_drive_enabled(&self.config.drive, req.enable_drive);
                let drive_cfg = drive::drive_config_or_default(&self.config.drive);
                tracing::info!(
                    %session_id,
                    drive_enabled,
                    entry_enable_drive = ?req.enable_drive,
                    has_drive_config = self.config.drive.is_some(),
                    drive_path = ?drive_cfg.drive_path,
                    "Drive configuration"
                );

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
                    drive_path = ?session_drive_path,
                    domain = ?req.domain,
                    has_password = req.password.is_some(),
                    "RDP session params"
                );
                let params = guacd::ConnectionParams::Rdp(Box::new(guacd::RdpParams {
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
                    remote_app: req.remote_app.clone(),
                    remote_app_dir: req.remote_app_dir.clone(),
                    remote_app_args: req.remote_app_args.clone(),
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                    enable_gfx: req.enable_gfx.unwrap_or(false),
                    enable_desktop_composition: req.enable_desktop_composition.unwrap_or(false),
                    force_lossless: req.force_lossless.unwrap_or(false),
                    enable_h264: req.enable_h264.unwrap_or(false),
                }));
                (
                    params,
                    hostname,
                    username,
                    None,
                    None,
                    None,
                    session_drive_path,
                    None,
                )
            }
            SessionType::Vnc => {
                let hostname = req.hostname.ok_or_else(|| {
                    SessionError::ValidationError("hostname is required for VNC sessions".into())
                })?;
                let port = req.port.unwrap_or(5900);
                let username = req.username.clone().unwrap_or_default();

                check_allowed_network(&hostname, port, &self.config.vnc_allowed_networks)?;

                tracing::info!(
                    session_id = %session_id,
                    hostname = %hostname,
                    width, height, dpi,
                    "Creating new VNC session"
                );

                let params = guacd::ConnectionParams::Vnc(guacd::VncParams {
                    hostname: hostname.clone(),
                    port,
                    password: req.password.clone(),
                    color_depth: req.color_depth,
                    width,
                    height,
                    dpi,
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                });
                (params, hostname, username, None, None, None, None, None)
            }
            SessionType::Web => {
                let raw_url = req.url.ok_or_else(|| {
                    SessionError::ValidationError("url is required for web sessions".into())
                })?;

                // Step 1: Validate raw URL template (scheme must be http/https)
                let parsed = Url::parse(&raw_url)
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

                // Step 2: URL-encode and substitute credential placeholders
                let enc_user = urlencoding::encode(req.username.as_deref().unwrap_or(""));
                let enc_pass = urlencoding::encode(req.password.as_deref().unwrap_or(""));
                let url = raw_url
                    .replace("$RUSTGUAC_USERNAME", &enc_user)
                    .replace("$RUSTGUAC_PASSWORD", &enc_pass);

                // Step 3: Re-validate substituted URL
                let parsed = Url::parse(&url).map_err(|e| {
                    SessionError::ValidationError(format!(
                        "URL invalid after credential substitution: {}",
                        e
                    ))
                })?;
                match parsed.scheme() {
                    "http" | "https" => {}
                    s => {
                        return Err(SessionError::ValidationError(format!(
                            "URL scheme '{}' after substitution not allowed",
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
                    has_login_script = req.login_script.is_some(),
                    "Creating new web session"
                );

                // Defer browser spawning — we may need to rewrite the URL
                // if jump hosts are configured (tunnel gets set up below).
                // Store a placeholder VNC params with port 0; will be updated
                // after browser spawn.
                let params = guacd::ConnectionParams::Vnc(guacd::VncParams {
                    hostname: "127.0.0.1".into(),
                    port: 0, // placeholder — updated after browser spawn
                    password: None,
                    color_depth: None,
                    width,
                    height,
                    dpi,
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                });
                (
                    params,
                    "localhost".into(),
                    String::new(),
                    Some(url),
                    None, // browser spawned after tunnel setup
                    None,
                    None,
                    None,
                )
            }
            SessionType::Vdi => {
                let vdi_cfg = self.config.vdi.as_ref().filter(|v| v.enabled).ok_or_else(|| {
                    SessionError::VdiError("VDI feature is not enabled".into())
                })?;

                let vdi = self.vdi_driver.as_ref().ok_or_else(|| {
                    SessionError::VdiError("VDI driver not initialized".into())
                })?;

                let image = req.container_image.clone().ok_or_else(|| {
                    SessionError::ValidationError(
                        "container_image is required for VDI sessions".into(),
                    )
                })?;

                // Check allowed images whitelist
                if !vdi_cfg.allowed_images.is_empty()
                    && !vdi_cfg.allowed_images.contains(&image)
                {
                    return Err(SessionError::VdiError(format!(
                        "image '{}' is not in the allowed list",
                        image
                    )));
                }

                // Sanitize username and generate ephemeral password
                let vdi_username = created_by
                    .split('@')
                    .next()
                    .unwrap_or(&created_by)
                    .to_lowercase()
                    .chars()
                    .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                    .collect::<String>();
                let vdi_password = generate_share_token(); // 32 hex chars

                // Merge env vars
                let mut env = req.container_env.unwrap_or_default();
                // Don't let user-provided env override the core VDI vars
                env.entry("VDI_USERNAME".into()).or_insert(vdi_username.clone());
                env.entry("VDI_PASSWORD".into()).or_insert(vdi_password.clone());

                // Resolve resource limits: entry overrides > config defaults
                let cpu_limit = req.container_cpu_limit
                    .unwrap_or(vdi_cfg.default_cpu_limit);
                let memory_limit_mb = req.container_memory_limit
                    .unwrap_or(vdi_cfg.default_memory_limit);

                let spec = crate::vdi::ContainerSpec {
                    image: image.clone(),
                    username: vdi_username.clone(),
                    password: vdi_password.clone(),
                    cpu_limit,
                    memory_limit: memory_limit_mb * 1024 * 1024, // MB to bytes
                    env,
                    home_base: vdi_cfg.home_base.clone(),
                    entry_key: req.address_book_entry.clone(),
                    idle_timeout_mins: req.container_idle_timeout_mins,
                };

                // Clear stale VDI thumbnail before starting/reusing container
                let container_name = format!("rustguac-vdi-{}", vdi_username);
                let stale_thumb = self.vdi_thumbnail_path(&container_name);
                let _ = std::fs::remove_file(&stale_thumb);

                tracing::info!(
                    session_id = %session_id,
                    image = %image,
                    username = %vdi_username,
                    "Creating VDI session"
                );

                let info = vdi.start_or_reuse(&spec).await.map_err(|e| {
                    SessionError::VdiError(e.to_string())
                })?;

                if info.reused {
                    tracing::info!(
                        session_id = %session_id,
                        container_id = %info.container_id,
                        "Reusing existing VDI container"
                    );
                }

                let params = guacd::ConnectionParams::Rdp(Box::new(guacd::RdpParams {
                    hostname: info.rdp_host,
                    port: info.rdp_port,
                    username: vdi_username.clone(),
                    password: Some(vdi_password),
                    domain: None,
                    security: None,
                    width,
                    height,
                    dpi,
                    ignore_cert: true,
                    enable_drive: false,
                    drive_path: None,
                    drive_name: String::new(),
                    disable_download: true,
                    disable_upload: true,
                    auth_pkg: None,
                    kdc_url: None,
                    kerberos_cache: None,
                    remote_app: None,
                    remote_app_dir: None,
                    remote_app_args: None,
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                    enable_gfx: true,
                    enable_desktop_composition: true,
                    force_lossless: false,
                    enable_h264: false,
                }));
                (
                    params,
                    image,
                    vdi_username,
                    None,
                    None,
                    None,
                    None,
                    Some(info.container_id),
                )
            }
        };

        // Resolve jump hosts: prefer jump_hosts array, fall back to legacy flat fields
        let jump_hops: Vec<tunnel::JumpHost> = if let Some(hops) = req.jump_hosts {
            hops
        } else if let Some(ref jh) = req.jump_host {
            if !jh.is_empty() {
                vec![tunnel::JumpHost {
                    hostname: jh.clone(),
                    port: req.jump_port.unwrap_or(22),
                    username: req.jump_username.clone().unwrap_or_default(),
                    password: req.jump_password.clone(),
                    private_key: req.jump_private_key.clone(),
                }]
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Set up SSH tunnel chain if jump hosts are configured.
        // For SSH/RDP/VNC: overrides hostname/port in conn_params so guacd
        // connects to the local tunnel listener instead of the real target.
        // For Web: tunnels to the URL's host:port and rewrites the browser URL.
        let is_web = url.is_some() && browser_session.is_none();
        let ssh_tunnels = if !jump_hops.is_empty() {
            let (target_host, target_port) = if is_web {
                // Web session: tunnel to the URL's host:port
                let parsed = Url::parse(url.as_ref().unwrap())
                    .map_err(|e| SessionError::ValidationError(format!("invalid URL: {}", e)))?;
                let host = parsed.host_str().unwrap_or("localhost").to_string();
                let port = parsed.port_or_known_default().unwrap_or(80);
                (host, port)
            } else {
                match &conn_params {
                    guacd::ConnectionParams::Ssh(p) => (p.hostname.clone(), p.port),
                    guacd::ConnectionParams::Rdp(p) => (p.hostname.clone(), p.port),
                    guacd::ConnectionParams::Vnc(p) => (p.hostname.clone(), p.port),
                }
            };

            let (tunnels, final_addr) = tunnel::start_chain(&jump_hops, &target_host, target_port)
                .await
                .map_err(|e| SessionError::ValidationError(format!("SSH tunnel failed: {}", e)))?;

            if !is_web {
                // Override connection params to point at the final tunnel endpoint
                match &mut conn_params {
                    guacd::ConnectionParams::Ssh(p) => {
                        p.hostname = final_addr.ip().to_string();
                        p.port = final_addr.port();
                    }
                    guacd::ConnectionParams::Rdp(p) => {
                        p.hostname = final_addr.ip().to_string();
                        p.port = final_addr.port();
                    }
                    guacd::ConnectionParams::Vnc(p) => {
                        p.hostname = final_addr.ip().to_string();
                        p.port = final_addr.port();
                    }
                }
            }

            let hop_names: Vec<&str> = jump_hops.iter().map(|h| h.hostname.as_str()).collect();
            tracing::info!(
                session_id = %session_id,
                final_addr = %final_addr,
                hops = ?hop_names,
                "SSH tunnel chain established ({} hops)",
                tunnels.len()
            );

            Some((tunnels, final_addr))
        } else {
            None
        };

        // For web sessions, spawn the browser now (after tunnels are set up).
        // If a tunnel is active, rewrite the URL to go through it.
        if is_web {
            let browser_url = if let Some((_, ref final_addr)) = ssh_tunnels {
                let parsed = Url::parse(url.as_ref().unwrap()).unwrap();
                let scheme = parsed.scheme();
                let path_and_query = if let Some(q) = parsed.query() {
                    format!("{}?{}", parsed.path(), q)
                } else {
                    parsed.path().to_string()
                };
                let rewritten = format!(
                    "{}://127.0.0.1:{}{}",
                    scheme,
                    final_addr.port(),
                    path_and_query,
                );
                tracing::info!(
                    session_id = %session_id,
                    original_url = %url.as_ref().unwrap(),
                    rewritten_url = %rewritten,
                    "Rewrote web session URL to use SSH tunnel"
                );
                rewritten
            } else {
                url.as_ref().unwrap().clone()
            };

            let need_cdp = req.login_script.is_some();

            // Parse autofill credentials JSON and substitute placeholders
            let autofill_creds = parse_autofill_credentials(
                req.autofill.as_deref(),
                req.username.as_deref(),
                req.password.as_deref(),
            );

            let browser = self
                .browser_manager
                .spawn(
                    &browser_url,
                    width,
                    height,
                    need_cdp,
                    autofill_creds.as_deref(),
                    req.allowed_domains.as_deref(),
                )
                .await
                .map_err(|e| SessionError::BrowserSpawn(e.to_string()))?;

            let vnc_port = browser.vnc_port;
            tracing::info!(
                session_id = %session_id,
                vnc_port = %vnc_port,
                display = %browser.display,
                "Browser processes ready, connecting guacd via VNC"
            );

            // Update the VNC params with the actual port
            if let guacd::ConnectionParams::Vnc(ref mut p) = conn_params {
                p.port = vnc_port;
            }
            browser_session = Some(browser);
        }

        let ssh_tunnels = ssh_tunnels.map(|(t, _)| t).unwrap_or_default();

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

        let recording_enabled = req
            .enable_recording
            .unwrap_or(self.config.recording_enabled());

        // Spawn login script if configured (web sessions with CDP port)
        let login_script_handle =
            if let (Some(ref script), Some(ref bs)) = (&req.login_script, &browser_session) {
                if let Some(cdp_port) = bs.cdp_port {
                    match self.browser_manager.run_login_script(
                        script,
                        bs.display,
                        cdp_port,
                        url.as_deref().unwrap_or(""),
                        req.username.as_deref(),
                        req.password.as_deref(),
                        &session_id.to_string(),
                    ) {
                        Ok(handle) => Some(handle),
                        Err(e) => {
                            tracing::warn!(
                                session_id = %session_id,
                                error = %e,
                                "Login script failed to start (session continues)"
                            );
                            None
                        }
                    }
                } else {
                    tracing::warn!(
                        session_id = %session_id,
                        "Login script configured but no CDP port allocated"
                    );
                    None
                }
            } else {
                None
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
            tunnels: ssh_tunnels,
            container_id,
            recording_enabled,
            address_book_entry: req.address_book_entry,
            address_book_folder: req.address_book_folder,
            entry_display_name: req.entry_display_name,
            max_recordings: req.max_recordings,
            login_script_handle,
        };

        let info = session.info();
        let session = Arc::new(Mutex::new(session));

        self.sessions
            .write()
            .await
            .insert(session_id, session.clone());

        // Record in session history
        if let Some(ref db) = self.db {
            let st = format!("{:?}", info.session_type).to_lowercase();
            if let Err(e) = crate::db::insert_session_history(
                db,
                &session_id.to_string(),
                &st,
                &info.hostname,
                None,
                &info.username,
                &info.created_by,
                info.address_book_entry.as_deref(),
                info.address_book_folder.as_deref(),
                info.entry_display_name.as_deref(),
            ) {
                tracing::warn!(session_id = %session_id, error = %e, "Failed to record session history");
            }
        }

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
        use subtle::ConstantTimeEq;
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let session = session.lock().await;
            let expected = Sha256::digest(session.share_token.as_bytes());
            let provided = Sha256::digest(token.as_bytes());
            expected.ct_eq(&provided).into()
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

    /// Record session end in history table.
    pub fn end_session_history(&self, id: Uuid, status: &str, duration_secs: u64, recording: bool) {
        if let Some(ref db) = self.db {
            let rec_file = if recording {
                Some(format!("{}.guac", id))
            } else {
                None
            };
            if let Err(e) = crate::db::end_session_history(
                db,
                &id.to_string(),
                status,
                duration_secs,
                rec_file.as_deref(),
            ) {
                tracing::warn!(session_id = %id, error = %e, "Failed to update session history");
            }
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

    /// Get session type and container_id for a session (used for VDI cleanup).
    pub async fn get_vdi_info(&self, id: Uuid) -> Option<(SessionType, Option<String>)> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(&id)?;
        let session = session.lock().await;
        Some((session.session_type.clone(), session.container_id.clone()))
    }

    /// Stop and remove the VDI container for a session.
    pub async fn stop_vdi_container(&self, id: Uuid) {
        let container_id = {
            let sessions = self.sessions.read().await;
            let session = sessions.get(&id);
            if let Some(session) = session {
                let mut session = session.lock().await;
                session.container_id.take()
            } else {
                None
            }
        };

        if let Some(cid) = container_id {
            if let Some(ref vdi) = self.vdi_driver {
                tracing::info!(session_id = %id, container_id = %cid, "Stopping VDI container (session ended by server)");
                if let Err(e) = vdi.stop_container(&cid).await {
                    tracing::warn!(container_id = %cid, "Failed to stop VDI container: {}", e);
                }
            }
        }
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
        self.config.effective_recording_path()
    }

    /// Path to the thumbnails directory (under recording_path).
    pub fn thumbnails_dir(&self) -> std::path::PathBuf {
        self.config.effective_recording_path().join("thumbnails")
    }

    /// Path to a specific session's thumbnail file.
    pub fn thumbnail_path(&self, session_id: Uuid) -> std::path::PathBuf {
        self.thumbnails_dir().join(format!("{}.jpg", session_id))
    }

    /// Path to a VDI container's thumbnail (persists across sessions).
    pub fn vdi_thumbnail_path(&self, container_name: &str) -> std::path::PathBuf {
        self.thumbnails_dir().join(format!("vdi-{}.jpg", container_name))
    }

    /// Check if recording is enabled for a given session.
    pub async fn is_recording_enabled(&self, id: Uuid) -> bool {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let session = session.lock().await;
            session.recording_enabled
        } else {
            false
        }
    }

    /// Get recording metadata for a session (address_book_entry, max_recordings).
    pub async fn get_recording_meta(&self, id: Uuid) -> Option<(Option<String>, Option<u32>)> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(&id)?;
        let session = session.lock().await;
        Some((session.address_book_entry.clone(), session.max_recordings))
    }

    /// Check if any active session references the given Docker container ID.
    pub async fn has_active_vdi_session(&self, container_id: &str) -> bool {
        let sessions = self.sessions.read().await;
        for session in sessions.values() {
            let session = session.lock().await;
            if session.container_id.as_deref() == Some(container_id)
                && (session.status == SessionStatus::Active
                    || session.status == SessionStatus::Pending)
            {
                return true;
            }
        }
        false
    }

    pub fn session_max_duration_secs(&self) -> u64 {
        self.config.session_max_duration_secs
    }

    pub fn recording_config(&self) -> crate::config::RecordingConfig {
        self.config.recording_config()
    }
}

/// Parse autofill credentials JSON and substitute $USERNAME/$PASSWORD placeholders.
/// Returns None if autofill is not configured or the JSON is invalid.
fn parse_autofill_credentials(
    autofill_json: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
) -> Option<Vec<(String, String, String)>> {
    let json_str = autofill_json?;
    if json_str.is_empty() {
        return None;
    }

    let entries: Vec<serde_json::Value> = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "Invalid autofill JSON, ignoring");
            return None;
        }
    };

    let user = username.unwrap_or("");
    let pass = password.unwrap_or("");

    let creds: Vec<(String, String, String)> = entries
        .iter()
        .filter_map(|entry| {
            let url = entry.get("url")?.as_str()?;
            let u = entry.get("username")?.as_str()?;
            let p = entry.get("password")?.as_str()?;

            let url = url.to_string();
            let u = u.replace("$USERNAME", user);
            let p = p.replace("$PASSWORD", pass);

            Some((url, u, p))
        })
        .collect();

    if creds.is_empty() {
        None
    } else {
        Some(creds)
    }
}

/// Kill browser processes if this is a web session, clean up drive directory,
/// abort any running login script, and shut down any SSH tunnel.
async fn cleanup_browser(browser_manager: &BrowserManager, session: &mut Session) {
    // Abort login script if still running
    if let Some(handle) = session.login_script_handle.take() {
        handle.abort();
    }

    if let Some(ref mut bs) = session.browser_session {
        browser_manager.kill(bs).await;
    }
    session.browser_session = None;

    // Clean up per-session drive directory
    if let Some(ref drive_path) = session.drive_path {
        drive::cleanup_session_dir(drive_path.clone(), session.id, 0).await;
        session.drive_path = None;
    }

    // Shut down SSH tunnel chain (reverse order)
    tunnel::shutdown_chain(&session.tunnels);
    session.tunnels.clear();
}

#[derive(Debug)]
pub enum SessionError {
    GuacdConnection(String),
    NotFound,
    NotActive,
    ValidationError(String),
    BrowserSpawn(String),
    VdiError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_allowed_network_ipv4_match() {
        assert!(check_allowed_network("127.0.0.1", 22, &["127.0.0.0/8".into()]).is_ok());
        assert!(check_allowed_network("10.1.2.3", 80, &["10.0.0.0/8".into()]).is_ok());
    }

    #[test]
    fn test_check_allowed_network_ipv4_denied() {
        let err = check_allowed_network("8.8.8.8", 22, &["127.0.0.0/8".into()]);
        assert!(err.is_err());
    }

    #[test]
    fn test_check_allowed_network_empty_allowlist() {
        let err = check_allowed_network("127.0.0.1", 22, &[]);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("no valid CIDR"), "got: {}", msg);
    }

    #[test]
    fn test_check_allowed_network_multiple_cidrs() {
        let cidrs = vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()];
        assert!(check_allowed_network("10.1.1.1", 22, &cidrs).is_ok());
        assert!(check_allowed_network("192.168.1.1", 22, &cidrs).is_ok());
        assert!(check_allowed_network("172.16.0.1", 22, &cidrs).is_err());
    }

    #[test]
    fn test_check_allowed_network_localhost_resolves() {
        // "localhost" should resolve to 127.0.0.1 or ::1
        let cidrs = vec!["127.0.0.0/8".into(), "::1/128".into()];
        assert!(check_allowed_network("localhost", 80, &cidrs).is_ok());
    }

    #[test]
    fn test_parse_autofill_none() {
        assert!(parse_autofill_credentials(None, None, None).is_none());
    }

    #[test]
    fn test_parse_autofill_empty_string() {
        assert!(parse_autofill_credentials(Some(""), None, None).is_none());
    }

    #[test]
    fn test_parse_autofill_invalid_json() {
        assert!(parse_autofill_credentials(Some("not json"), None, None).is_none());
    }

    #[test]
    fn test_parse_autofill_empty_array() {
        assert!(parse_autofill_credentials(Some("[]"), None, None).is_none());
    }

    #[test]
    fn test_parse_autofill_basic() {
        let json = r#"[{"url":"https://example.com","username":"alice","password":"secret"}]"#;
        let creds = parse_autofill_credentials(Some(json), None, None).unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].0, "https://example.com");
        assert_eq!(creds[0].1, "alice");
        assert_eq!(creds[0].2, "secret");
    }

    #[test]
    fn test_parse_autofill_placeholder_substitution() {
        let json = r#"[{"url":"https://ex.com","username":"$USERNAME","password":"$PASSWORD"}]"#;
        let creds = parse_autofill_credentials(Some(json), Some("bob"), Some("pass123")).unwrap();
        assert_eq!(creds[0].1, "bob");
        assert_eq!(creds[0].2, "pass123");
    }

    #[test]
    fn test_parse_autofill_placeholder_no_credentials() {
        // Placeholders with no username/password should substitute empty strings
        let json = r#"[{"url":"https://ex.com","username":"$USERNAME","password":"$PASSWORD"}]"#;
        let creds = parse_autofill_credentials(Some(json), None, None).unwrap();
        assert_eq!(creds[0].1, "");
        assert_eq!(creds[0].2, "");
    }

    #[test]
    fn test_parse_autofill_multiple_entries() {
        let json = r#"[
            {"url":"https://app.com","username":"$USERNAME","password":"$PASSWORD"},
            {"url":"https://idp.com","username":"$USERNAME","password":"$PASSWORD"}
        ]"#;
        let creds = parse_autofill_credentials(Some(json), Some("alice"), Some("secret")).unwrap();
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0].0, "https://app.com");
        assert_eq!(creds[1].0, "https://idp.com");
    }

    #[test]
    fn test_parse_autofill_missing_fields_skipped() {
        // Entries missing required fields are silently skipped
        let json =
            r#"[{"url":"https://ex.com"},{"url":"https://ok.com","username":"a","password":"b"}]"#;
        let creds = parse_autofill_credentials(Some(json), None, None).unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].0, "https://ok.com");
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::GuacdConnection(msg) => write!(f, "guacd connection failed: {}", msg),
            SessionError::NotFound => write!(f, "session not found"),
            SessionError::NotActive => write!(f, "session is not active"),
            SessionError::ValidationError(msg) => write!(f, "validation error: {}", msg),
            SessionError::BrowserSpawn(msg) => write!(f, "browser spawn failed: {}", msg),
            SessionError::VdiError(msg) => write!(f, "VDI error: {}", msg),
        }
    }
}
