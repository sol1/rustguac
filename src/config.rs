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

/// Fully-resolved theme palette with all 26 color fields.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThemeColors {
    pub primary: String,
    pub primary_hover: String,
    pub accent: String,
    pub accent_hover: String,
    pub bg: String,
    pub surface: String,
    pub input: String,
    pub text: String,
    pub text_muted: String,
    pub border: String,
    pub text_dim: String,
    pub text_on_primary: String,
    pub btn_disabled: String,
    pub status_pending: String,
    pub status_active: String,
    pub status_completed: String,
    pub status_error: String,
    pub status_expired: String,
    pub type_ssh_bg: String,
    pub type_ssh_fg: String,
    pub type_rdp_bg: String,
    pub type_rdp_fg: String,
    pub type_vnc_bg: String,
    pub type_vnc_fg: String,
    pub type_web_bg: String,
    pub type_web_fg: String,
    pub hop_bg: String,
    pub hop_fg: String,
}

/// Returns all 6 built-in theme presets.
pub fn builtin_presets() -> Vec<(&'static str, ThemeColors)> {
    vec![
        (
            "dark",
            ThemeColors {
                primary: "#e94560".into(),
                primary_hover: "#c73652".into(),
                accent: "#5bc0be".into(),
                accent_hover: "#4aa3a1".into(),
                bg: "#1a1a2e".into(),
                surface: "#16213e".into(),
                input: "#0f3460".into(),
                text: "#e0e0e0".into(),
                text_muted: "#aaa".into(),
                border: "#333".into(),
                text_dim: "#666".into(),
                text_on_primary: "#fff".into(),
                btn_disabled: "#555".into(),
                status_pending: "#f0c040".into(),
                status_active: "#5bc0be".into(),
                status_completed: "#888".into(),
                status_error: "#e94560".into(),
                status_expired: "#666".into(),
                type_ssh_bg: "#1b4332".into(),
                type_ssh_fg: "#52b788".into(),
                type_rdp_bg: "#3d1f00".into(),
                type_rdp_fg: "#f0a050".into(),
                type_vnc_bg: "#2d1b4e".into(),
                type_vnc_fg: "#b07ff0".into(),
                type_web_bg: "#1a1a4e".into(),
                type_web_fg: "#7b8ff0".into(),
                hop_bg: "#1b4332".into(),
                hop_fg: "#52b788".into(),
            },
        ),
        (
            "light",
            ThemeColors {
                primary: "#2563eb".into(),
                primary_hover: "#1d4ed8".into(),
                accent: "#0d9488".into(),
                accent_hover: "#0f766e".into(),
                bg: "#f8fafc".into(),
                surface: "#fff".into(),
                input: "#f1f5f9".into(),
                text: "#1e293b".into(),
                text_muted: "#64748b".into(),
                border: "#e2e8f0".into(),
                text_dim: "#94a3b8".into(),
                text_on_primary: "#fff".into(),
                btn_disabled: "#cbd5e1".into(),
                status_pending: "#d97706".into(),
                status_active: "#0d9488".into(),
                status_completed: "#94a3b8".into(),
                status_error: "#dc2626".into(),
                status_expired: "#cbd5e1".into(),
                type_ssh_bg: "#dcfce7".into(),
                type_ssh_fg: "#166534".into(),
                type_rdp_bg: "#ffedd5".into(),
                type_rdp_fg: "#9a3412".into(),
                type_vnc_bg: "#f3e8ff".into(),
                type_vnc_fg: "#6b21a8".into(),
                type_web_bg: "#dbeafe".into(),
                type_web_fg: "#1e40af".into(),
                hop_bg: "#dcfce7".into(),
                hop_fg: "#166534".into(),
            },
        ),
        (
            "high-contrast",
            ThemeColors {
                primary: "#ff6b6b".into(),
                primary_hover: "#ff4444".into(),
                accent: "#00ffcc".into(),
                accent_hover: "#00ddaa".into(),
                bg: "#000".into(),
                surface: "#111".into(),
                input: "#1a1a1a".into(),
                text: "#fff".into(),
                text_muted: "#ccc".into(),
                border: "#555".into(),
                text_dim: "#999".into(),
                text_on_primary: "#000".into(),
                btn_disabled: "#444".into(),
                status_pending: "#ffdd00".into(),
                status_active: "#00ffcc".into(),
                status_completed: "#999".into(),
                status_error: "#ff4444".into(),
                status_expired: "#666".into(),
                type_ssh_bg: "#003300".into(),
                type_ssh_fg: "#00ff66".into(),
                type_rdp_bg: "#332200".into(),
                type_rdp_fg: "#ffaa00".into(),
                type_vnc_bg: "#220033".into(),
                type_vnc_fg: "#cc66ff".into(),
                type_web_bg: "#000033".into(),
                type_web_fg: "#6699ff".into(),
                hop_bg: "#003300".into(),
                hop_fg: "#00ff66".into(),
            },
        ),
        (
            "terminal",
            ThemeColors {
                primary: "#f59e0b".into(),
                primary_hover: "#d97706".into(),
                accent: "#22c55e".into(),
                accent_hover: "#16a34a".into(),
                bg: "#0a0a0a".into(),
                surface: "#141414".into(),
                input: "#1e1e1e".into(),
                text: "#33ff33".into(),
                text_muted: "#22aa22".into(),
                border: "#2a2a2a".into(),
                text_dim: "#186818".into(),
                text_on_primary: "#000".into(),
                btn_disabled: "#333".into(),
                status_pending: "#f59e0b".into(),
                status_active: "#33ff33".into(),
                status_completed: "#22aa22".into(),
                status_error: "#ff3333".into(),
                status_expired: "#186818".into(),
                type_ssh_bg: "#0a200a".into(),
                type_ssh_fg: "#33ff33".into(),
                type_rdp_bg: "#201a0a".into(),
                type_rdp_fg: "#f59e0b".into(),
                type_vnc_bg: "#1a0a20".into(),
                type_vnc_fg: "#cc66ff".into(),
                type_web_bg: "#0a0a20".into(),
                type_web_fg: "#6699ff".into(),
                hop_bg: "#0a200a".into(),
                hop_fg: "#33ff33".into(),
            },
        ),
        (
            "nord",
            ThemeColors {
                primary: "#88c0d0".into(),
                primary_hover: "#81a1c1".into(),
                accent: "#a3be8c".into(),
                accent_hover: "#8fbcbb".into(),
                bg: "#2e3440".into(),
                surface: "#3b4252".into(),
                input: "#434c5e".into(),
                text: "#eceff4".into(),
                text_muted: "#d8dee9".into(),
                border: "#4c566a".into(),
                text_dim: "#7b88a1".into(),
                text_on_primary: "#2e3440".into(),
                btn_disabled: "#4c566a".into(),
                status_pending: "#ebcb8b".into(),
                status_active: "#a3be8c".into(),
                status_completed: "#7b88a1".into(),
                status_error: "#bf616a".into(),
                status_expired: "#4c566a".into(),
                type_ssh_bg: "#384838".into(),
                type_ssh_fg: "#a3be8c".into(),
                type_rdp_bg: "#483e38".into(),
                type_rdp_fg: "#ebcb8b".into(),
                type_vnc_bg: "#3e3848".into(),
                type_vnc_fg: "#b48ead".into(),
                type_web_bg: "#384048".into(),
                type_web_fg: "#88c0d0".into(),
                hop_bg: "#384838".into(),
                hop_fg: "#a3be8c".into(),
            },
        ),
        (
            "corporate",
            ThemeColors {
                primary: "#3b82f6".into(),
                primary_hover: "#2563eb".into(),
                accent: "#f97316".into(),
                accent_hover: "#ea580c".into(),
                bg: "#0f172a".into(),
                surface: "#1e293b".into(),
                input: "#334155".into(),
                text: "#f1f5f9".into(),
                text_muted: "#94a3b8".into(),
                border: "#475569".into(),
                text_dim: "#64748b".into(),
                text_on_primary: "#fff".into(),
                btn_disabled: "#475569".into(),
                status_pending: "#fbbf24".into(),
                status_active: "#34d399".into(),
                status_completed: "#64748b".into(),
                status_error: "#ef4444".into(),
                status_expired: "#475569".into(),
                type_ssh_bg: "#14532d".into(),
                type_ssh_fg: "#4ade80".into(),
                type_rdp_bg: "#431407".into(),
                type_rdp_fg: "#fb923c".into(),
                type_vnc_bg: "#3b0764".into(),
                type_vnc_fg: "#c084fc".into(),
                type_web_bg: "#172554".into(),
                type_web_fg: "#60a5fa".into(),
                hop_bg: "#14532d".into(),
                hop_fg: "#4ade80".into(),
            },
        ),
        (
            "avocado",
            ThemeColors {
                primary: "#d4883c".into(),
                primary_hover: "#b8742f".into(),
                accent: "#c5d455".into(),
                accent_hover: "#a8b83e".into(),
                bg: "#151a0e".into(),
                surface: "#1e2414".into(),
                input: "#2a321c".into(),
                text: "#eef0e0".into(),
                text_muted: "#a0a888".into(),
                border: "#3a4228".into(),
                text_dim: "#5a6240".into(),
                text_on_primary: "#151a0e".into(),
                btn_disabled: "#3a4228".into(),
                status_pending: "#d4883c".into(),
                status_active: "#c5d455".into(),
                status_completed: "#6a7252".into(),
                status_error: "#c0392b".into(),
                status_expired: "#3a4228".into(),
                type_ssh_bg: "#1e2a14".into(),
                type_ssh_fg: "#8cb832".into(),
                type_rdp_bg: "#2a2014".into(),
                type_rdp_fg: "#d4a050".into(),
                type_vnc_bg: "#221e2a".into(),
                type_vnc_fg: "#b07ff0".into(),
                type_web_bg: "#1a1e2a".into(),
                type_web_fg: "#7b8ff0".into(),
                hop_bg: "#1e2a14".into(),
                hop_fg: "#8cb832".into(),
            },
        ),
    ]
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ThemeConfig {
    /// Built-in preset name: dark, light, high-contrast, terminal, nord, corporate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
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
    pub text_dim: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_on_primary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub btn_disabled: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_pending: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_active: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_completed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_expired: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_ssh_bg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_ssh_fg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_rdp_bg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_rdp_fg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_vnc_bg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_vnc_fg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_web_bg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_web_fg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hop_bg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hop_fg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
}

impl ThemeConfig {
    /// Resolve config into a full ThemeColors palette.
    /// Starts from the named preset (default: "dark"), then applies overrides.
    pub fn resolve(&self) -> (String, ThemeColors) {
        let preset_name = self.preset.as_deref().unwrap_or("dark");
        let presets = builtin_presets();
        let mut colors = presets
            .iter()
            .find(|(name, _)| *name == preset_name)
            .map(|(_, c)| c.clone())
            .unwrap_or_else(|| presets[0].1.clone());

        macro_rules! apply {
            ($field:ident, $src:ident) => {
                if let Some(ref v) = self.$src {
                    colors.$field = v.clone();
                }
            };
            ($field:ident) => {
                if let Some(ref v) = self.$field {
                    colors.$field = v.clone();
                }
            };
        }

        apply!(primary, primary_color);
        apply!(primary_hover);
        apply!(accent, accent_color);
        apply!(accent_hover);
        apply!(bg, bg_color);
        apply!(surface, surface_color);
        apply!(input, input_color);
        apply!(text, text_color);
        apply!(text_muted);
        apply!(border, border_color);
        apply!(text_dim);
        apply!(text_on_primary);
        apply!(btn_disabled);
        apply!(status_pending);
        apply!(status_active);
        apply!(status_completed);
        apply!(status_error);
        apply!(status_expired);
        apply!(type_ssh_bg);
        apply!(type_ssh_fg);
        apply!(type_rdp_bg);
        apply!(type_rdp_fg);
        apply!(type_vnc_bg);
        apply!(type_vnc_fg);
        apply!(type_web_bg);
        apply!(type_web_fg);
        apply!(hop_bg);
        apply!(hop_fg);

        (preset_name.to_string(), colors)
    }
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
