use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// Path to guacd's TLS certificate (PEM). When set, rustguac connects to guacd over TLS.
    pub guacd_cert_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    #[serde(default = "default_oidc_default_role")]
    pub default_role: String,
    /// Name of the OIDC claim containing group memberships (default: "groups").
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    /// Extra OIDC scopes to request beyond openid/email/profile (e.g. ["groups"]).
    #[serde(default)]
    pub extra_scopes: Vec<String>,
}

fn default_oidc_default_role() -> String {
    "operator".into()
}

fn default_groups_claim() -> String {
    "groups".into()
}

#[derive(Debug, Deserialize, Clone)]
pub struct VaultConfig {
    pub addr: String,
    #[serde(default = "default_vault_mount")]
    pub mount: String,
    #[serde(default = "default_vault_base_path")]
    pub base_path: String,
    pub role_id: String,
    pub namespace: Option<String>,
    /// Instance name for instance-scoped address book entries.
    /// Entries under `<base_path>/shared/` are visible to all instances.
    /// Entries under `<base_path>/instance/<instance_name>/` are specific to this instance.
    /// If not set, only shared entries are used.
    pub instance_name: Option<String>,
    /// Skip TLS certificate verification for the Vault connection.
    /// Only use this for development with self-signed certificates.
    #[serde(default)]
    pub tls_skip_verify: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DriveConfig {
    /// Enable drive/file transfer for sessions. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Base directory for per-session drive storage (RDP) or mount point for LUKS.
    /// Each RDP session gets a subdirectory: `<drive_path>/<session_id>/`.
    #[serde(default = "default_drive_path")]
    pub drive_path: PathBuf,
    /// Display name shown in the remote session's file browser.
    #[serde(default = "default_drive_name")]
    pub drive_name: String,
    /// Allow file download from the remote session. Default: true.
    #[serde(default = "default_true")]
    pub allow_download: bool,
    /// Allow file upload to the remote session. Default: true.
    #[serde(default = "default_true")]
    pub allow_upload: bool,
    /// Auto-delete session drive directories after session ends. Default: true.
    #[serde(default = "default_true")]
    pub cleanup_on_close: bool,
    /// Delay in seconds before cleaning up drive dirs (0 = immediate). Default: 0.
    #[serde(default)]
    #[allow(dead_code)]
    pub retention_secs: u64,
    /// LUKS container device/file path (e.g. "/opt/rustguac/drives.luks").
    /// When set (along with luks_key_path), rustguac manages LUKS open/close lifecycle.
    pub luks_device: Option<PathBuf>,
    /// Device-mapper name for the LUKS volume. Default: "rustguac-drives".
    #[serde(default = "default_luks_name")]
    pub luks_name: String,
    /// Vault KV path for the LUKS encryption key (e.g. "rustguac/luks-key").
    /// The secret must have a "key" field containing the passphrase.
    pub luks_key_path: Option<String>,
}

fn default_drive_path() -> PathBuf {
    PathBuf::from("./drives")
}

fn default_drive_name() -> String {
    "Shared Drive".into()
}

fn default_true() -> bool {
    true
}

fn default_luks_name() -> String {
    "rustguac-drives".into()
}

impl Default for DriveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            drive_path: default_drive_path(),
            drive_name: default_drive_name(),
            allow_download: true,
            allow_upload: true,
            cleanup_on_close: true,
            retention_secs: 0,
            luks_device: None,
            luks_name: default_luks_name(),
            luks_key_path: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RecordingConfig {
    /// Path for recording files. Overrides top-level `recording_path`.
    #[serde(default = "default_recording_path")]
    pub path: PathBuf,
    /// Whether recording is enabled globally. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Delete oldest recordings when disk usage exceeds this percent. 0 = disabled.
    #[serde(default = "default_max_disk_percent")]
    pub max_disk_percent: u8,
    /// Keep at most this many recordings globally. 0 = unlimited.
    #[serde(default)]
    pub max_recordings: u32,
    /// How often (in seconds) to run the rotation check. Default: 300 (5 min).
    #[serde(default = "default_rotation_interval_secs")]
    pub rotation_interval_secs: u64,
}

fn default_max_disk_percent() -> u8 {
    80
}

fn default_rotation_interval_secs() -> u64 {
    300
}

impl Default for RecordingConfig {
    fn default() -> Self {
        Self {
            path: default_recording_path(),
            enabled: true,
            max_disk_percent: default_max_disk_percent(),
            max_recordings: 0,
            rotation_interval_secs: default_rotation_interval_secs(),
        }
    }
}

fn default_vault_mount() -> String {
    "secret".into()
}

fn default_vault_base_path() -> String {
    "rustguac".into()
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    #[serde(default = "default_guacd_addr")]
    pub guacd_addr: String,

    #[serde(default = "default_recording_path")]
    pub recording_path: PathBuf,

    #[serde(default = "default_static_path")]
    pub static_path: PathBuf,

    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,

    #[serde(default = "default_session_timeout_secs")]
    pub session_pending_timeout_secs: u64,

    /// Maximum duration for active sessions in seconds. Default: 8 hours.
    /// Sessions exceeding this duration are automatically terminated.
    #[serde(default = "default_session_max_duration_secs")]
    pub session_max_duration_secs: u64,

    /// OIDC auth session TTL in seconds. Default: 86400 (24 hours).
    /// After this period, users must re-authenticate via OIDC.
    #[serde(default = "default_auth_session_ttl_secs")]
    pub auth_session_ttl_secs: u64,

    #[serde(default = "default_xvnc_path")]
    pub xvnc_path: String,

    #[serde(default = "default_chromium_path")]
    pub chromium_path: String,

    #[serde(default = "default_display_range_start")]
    pub display_range_start: u32,

    #[serde(default = "default_display_range_end")]
    pub display_range_end: u32,

    #[serde(default = "default_site_title")]
    pub site_title: String,

    /// CIDR allowlist for SSH session targets. Default: localhost only.
    #[serde(default = "default_localhost_networks")]
    pub ssh_allowed_networks: Vec<String>,

    /// CIDR allowlist for RDP session targets. Default: localhost only.
    #[serde(default = "default_localhost_networks")]
    pub rdp_allowed_networks: Vec<String>,

    /// CIDR allowlist for VNC session targets. Default: localhost only.
    #[serde(default = "default_localhost_networks")]
    pub vnc_allowed_networks: Vec<String>,

    /// CIDR allowlist for web session URL hosts. Default: localhost only.
    #[serde(default = "default_localhost_networks")]
    pub web_allowed_networks: Vec<String>,

    /// Trusted proxy CIDRs. When the connecting IP matches one of these,
    /// the first address in X-Forwarded-For is used as the real client IP.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,

    pub tls: Option<TlsConfig>,
    pub oidc: Option<OidcConfig>,
    pub vault: Option<VaultConfig>,
    pub drive: Option<DriveConfig>,
    pub theme: Option<ThemeConfig>,
    pub recording: Option<RecordingConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ThemeConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_hover: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accent_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accent_hover: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bg_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_muted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub border_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
}

fn default_listen_addr() -> String {
    "127.0.0.1:8089".into()
}

fn default_guacd_addr() -> String {
    "127.0.0.1:4822".into()
}

fn default_recording_path() -> PathBuf {
    PathBuf::from("./recordings")
}

fn default_static_path() -> PathBuf {
    PathBuf::from("./static")
}

fn default_db_path() -> PathBuf {
    PathBuf::from("./rustguac.db")
}

fn default_session_timeout_secs() -> u64 {
    60
}

fn default_session_max_duration_secs() -> u64 {
    8 * 3600 // 8 hours
}

fn default_auth_session_ttl_secs() -> u64 {
    86400 // 24 hours
}

fn default_xvnc_path() -> String {
    "Xvnc".into()
}

fn default_chromium_path() -> String {
    "chromium".into()
}

fn default_display_range_start() -> u32 {
    100
}

fn default_display_range_end() -> u32 {
    199
}

fn default_site_title() -> String {
    "rustguac".into()
}

fn default_localhost_networks() -> Vec<String> {
    vec!["127.0.0.0/8".into(), "::1/128".into()]
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            guacd_addr: default_guacd_addr(),
            recording_path: default_recording_path(),
            static_path: default_static_path(),
            db_path: default_db_path(),
            session_pending_timeout_secs: default_session_timeout_secs(),
            session_max_duration_secs: default_session_max_duration_secs(),
            auth_session_ttl_secs: default_auth_session_ttl_secs(),
            xvnc_path: default_xvnc_path(),
            chromium_path: default_chromium_path(),
            display_range_start: default_display_range_start(),
            display_range_end: default_display_range_end(),
            site_title: default_site_title(),
            ssh_allowed_networks: default_localhost_networks(),
            rdp_allowed_networks: default_localhost_networks(),
            vnc_allowed_networks: default_localhost_networks(),
            web_allowed_networks: default_localhost_networks(),
            trusted_proxies: Vec::new(),
            tls: None,
            oidc: None,
            vault: None,
            drive: None,
            theme: None,
            recording: None,
        }
    }
}

impl Config {
    pub fn load(path: Option<&str>) -> Self {
        let mut config = if let Some(path) = path {
            match std::fs::read_to_string(path) {
                Ok(contents) => match toml::from_str(&contents) {
                    Ok(config) => {
                        tracing::info!("Loaded config from {}", path);
                        config
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse config {}: {}", path, e);
                        Self::default()
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to read config {}: {}", path, e);
                    Self::default()
                }
            }
        } else if std::path::Path::new("/opt/rustguac/config.toml").exists() {
            let path = "/opt/rustguac/config.toml";
            match std::fs::read_to_string(path) {
                Ok(contents) => match toml::from_str(&contents) {
                    Ok(config) => {
                        tracing::info!("Loaded config from {} (default path)", path);
                        config
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse config {}: {}", path, e);
                        Self::default()
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to read config {}: {}", path, e);
                    Self::default()
                }
            }
        } else {
            tracing::info!("Using default configuration");
            Self::default()
        };

        // Allow OIDC client secret to be overridden via environment variable
        if let Some(ref mut oidc) = config.oidc {
            if let Ok(secret) = std::env::var("OIDC_CLIENT_SECRET") {
                oidc.client_secret = secret;
            }
        }

        config
    }

    /// Effective recording path: `[recording].path` overrides top-level `recording_path`.
    pub fn effective_recording_path(&self) -> &std::path::Path {
        if let Some(ref rec) = self.recording {
            &rec.path
        } else {
            &self.recording_path
        }
    }

    /// Whether recording is globally enabled. Defaults to true.
    pub fn recording_enabled(&self) -> bool {
        self.recording.as_ref().is_none_or(|r| r.enabled)
    }

    /// Get recording config (or synthesized default that respects legacy `recording_path`).
    pub fn recording_config(&self) -> RecordingConfig {
        match self.recording.clone() {
            Some(r) => r,
            None => RecordingConfig {
                path: self.recording_path.clone(),
                ..RecordingConfig::default()
            },
        }
    }
}
