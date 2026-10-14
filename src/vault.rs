//! HashiVault / OpenBao KV v2 client with AppRole authentication.
//!
//! Stores address book entries (connection credentials) in Vault.
//! Path structure:
//!   <mount>/data/<base_path>/shared/<folder>/<entry>       — shared across instances
//!   <mount>/data/<base_path>/instance/<name>/<folder>/<entry> — instance-specific
//!
//! Each folder has a `.config` sentinel key containing `FolderConfig`
//! (allowed_groups, description) that controls OIDC group-based access.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::VaultConfig;
use crate::tunnel;

// ── Error type ──

#[derive(Debug)]
pub enum VaultError {
    Auth(String),
    NotFound,
    Forbidden,
    Http(reqwest::Error),
    Parse(String),
    BadName(String),
    /// The backend serving this scope is configured but not currently
    /// connected (initial connect pending or the Vault is down). Distinct from
    /// a Vault that returns an error: the request never left rustguac.
    Unavailable,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth(msg) => write!(f, "vault auth error: {}", msg),
            Self::NotFound => write!(f, "not found in vault"),
            Self::Forbidden => write!(f, "vault access denied"),
            Self::Http(e) => write!(f, "vault HTTP error: {}", e),
            Self::Parse(msg) => write!(f, "vault response parse error: {}", msg),
            Self::BadName(msg) => write!(f, "invalid name: {}", msg),
            Self::Unavailable => write!(f, "vault backend not available"),
        }
    }
}

impl From<reqwest::Error> for VaultError {
    fn from(e: reqwest::Error) -> Self {
        VaultError::Http(e)
    }
}

// ── Data types ──

/// Folder access configuration stored at `<folder>/.config` in Vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderConfig {
    pub allowed_groups: Vec<String>,
    /// Users granted access by login email, in addition to `allowed_groups`.
    /// Compared without regard to case. A user need not have logged in yet:
    /// access is decided from their identity at the time they ask. Omitted
    /// from the stored config when empty, so existing configs are unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_users: Vec<String>,
    #[serde(default)]
    pub description: String,
    /// When true, if the folder's own `allowed_groups` doesn't grant access,
    /// the access check walks up the parent path and tries each ancestor's
    /// config. New folders default to `true` in the UI; legacy configs
    /// deserialise as `false` so existing deployments keep their
    /// per-folder-only semantics until an admin opts in.
    #[serde(default)]
    pub inherit_from_parent: bool,
}

/// Who is asking for access to a folder: their login email (absent for API
/// keys, which are admins and never get here) and their OIDC groups.
#[derive(Debug, Clone, Copy)]
pub struct FolderSubject<'a> {
    pub email: Option<&'a str>,
    pub groups: &'a [String],
}

impl FolderConfig {
    /// Whether this folder's own settings let `who` in: a shared group, or
    /// their email in `allowed_users`. Inheritance is the caller's concern.
    pub fn grants(&self, who: FolderSubject<'_>) -> bool {
        if self
            .allowed_groups
            .iter()
            .any(|g| who.groups.iter().any(|ug| ug == g))
        {
            return true;
        }
        match who.email.map(str::trim) {
            Some(email) if !email.is_empty() => self
                .allowed_users
                .iter()
                .any(|u| u.trim().eq_ignore_ascii_case(email)),
            _ => false,
        }
    }
}

/// A connection entry stored in Vault.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddressBookEntry {
    #[serde(rename = "type")]
    pub session_type: String, // "ssh", "rdp", "vnc", "web"
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub url: Option<String>,
    pub domain: Option<String>,
    pub security: Option<String>,
    /// RDP server keyboard layout (guacd `server-layout`, e.g. "en-gb-qwerty").
    /// None/empty lets guacd use its default (en-us-qwerty).
    pub server_layout: Option<String>,
    pub ignore_cert: Option<bool>,
    pub display_name: Option<String>,
    /// Override drive/file transfer setting for this entry.
    pub enable_drive: Option<bool>,
    /// NLA auth package: "kerberos", "ntlm", or empty (negotiate).
    pub auth_pkg: Option<String>,
    /// Kerberos KDC URL (optional).
    pub kdc_url: Option<String>,
    /// Whether to prompt for credentials at connect time (even if stored creds exist).
    pub prompt_credentials: Option<bool>,
    /// VNC color depth (8, 16, 24, 32). Default: 24.
    pub color_depth: Option<u8>,
    /// Multi-hop SSH tunnel jump hosts (ordered).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_hosts: Option<Vec<tunnel::JumpHost>>,
    /// Legacy: single SSH tunnel jump host (migrated to jump_hosts on read).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_host: Option<String>,
    /// Legacy: SSH tunnel jump port (default: 22).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_port: Option<u16>,
    /// Legacy: SSH tunnel jump username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_username: Option<String>,
    /// Legacy: SSH tunnel jump password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_password: Option<String>,
    /// Legacy: SSH tunnel jump private key (PEM).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_private_key: Option<String>,
    /// RDP RemoteApp program path (RAIL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_app: Option<String>,
    /// RDP RemoteApp working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_app_dir: Option<String>,
    /// RDP RemoteApp command-line arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_app_args: Option<String>,
    /// Override recording enabled/disabled for this entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_recording: Option<bool>,
    /// Maximum number of recordings to keep for this entry (0 = unlimited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_recordings: Option<u32>,
    /// Enable SSH typescript recording for this entry (#159). Default off
    /// (per-connection opt-in). Only effective for SSH sessions and only
    /// when `[recording].typescript_path` is configured globally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_typescript: Option<bool>,
    /// Login script filename (relative to login_scripts_dir) to run after browser spawns.
    /// Only applicable to web sessions. The script receives CDP port and credentials
    /// via environment variables and stdin JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_script: Option<String>,
    /// Autofill credentials for web sessions. JSON array of objects:
    /// [{"url": "https://example.com", "username": "$USERNAME", "password": "$PASSWORD"}]
    /// $USERNAME and $PASSWORD are substituted from the entry's credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autofill: Option<String>,
    /// Allowed domains for web sessions. When set, Chromium can only reach
    /// these domains (plus localhost). Uses --host-rules to block all others.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<Vec<String>>,
    /// Disable clipboard copy (server → client). Prevents copying from the remote session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_copy: Option<bool>,
    /// Disable clipboard paste (client → server). Prevents pasting into the remote session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_paste: Option<bool>,
    /// Optional banner text shown before the session starts. User must click Continue to proceed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// Enable RDP Graphics Pipeline Extension (GFX). Enables RemoteFX codec for better video.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_gfx: Option<bool>,
    /// Enable desktop composition (DWM). Improves video overlay rendering in RDP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_desktop_composition: Option<bool>,
    /// Show the remote desktop wallpaper. Disabled by default to save bandwidth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_wallpaper: Option<bool>,
    /// Enable window/control theming (visual styles). Disabled by default to save bandwidth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_theming: Option<bool>,
    /// Show window contents while dragging. Disabled by default to save bandwidth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_full_window_drag: Option<bool>,
    /// Force lossless encoding (PNG only). Better for text-heavy, low-bandwidth sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_lossless: Option<bool>,
    /// Enable H.264 passthrough. Passes raw H.264 from xrdp to browser WebCodecs decoder.
    /// Requires GFX enabled and xrdp with x264 on the target. Default: true when GFX enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_h264: Option<bool>,
    /// Paint AVC444 in full 4:4:4 colour (RDP, with H.264 passthrough).
    ///
    /// Unset or `Some(false)` is Standard colour: AVC444 is still offered --
    /// a Windows host needs that for hardware encoding, and FreeRDP advertises
    /// the RDPGFX 10.x capability sets only alongside it -- but rustguac drops
    /// the auxiliary chroma view in transit wherever the stream proves it can
    /// be spared, and the browser never combines, so 4:2:0 is painted at the
    /// lowest cost available. `Some(true)` keeps both views and lets the
    /// browser combine them, at the price of a plane read-back per picture;
    /// the browser still gives 4:4:4 up when that costs too much.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h264_chroma444: Option<bool>,
    /// Request the framebuffer in the browser's physical pixels rather than its
    /// CSS pixels, so text renders sharply on a HiDPI display.
    ///
    /// Per-entry rather than global because it is only safe where the target
    /// also scales its UI to match. RDP does that automatically (guacd asks via
    /// desktopScaleFactor); an X11 desktop behind xrdp has no per-connection DPI
    /// negotiation, so enabling it there without a session-side scaling hook
    /// just makes every icon and glyph smaller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_resolution: Option<bool>,
    /// Docker image for VDI sessions (e.g. "myregistry/desktop:latest").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_image: Option<String>,
    /// CPU limit override for VDI container (fractional cores). Uses config default if unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_cpu_limit: Option<f64>,
    /// Memory limit override for VDI container in MB. Uses config default if unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_memory_limit: Option<u64>,
    /// Extra environment variables for VDI container (key=value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_env: Option<std::collections::HashMap<String, String>>,
    /// Override idle timeout for VDI container in minutes. Uses global default if unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_idle_timeout_mins: Option<u64>,
    /// Optional fixed username for the VDI container's RDP login. When set,
    /// rustguac uses this username for the RDP connect into the container
    /// instead of deriving one from the operator's identity. Useful when the
    /// container image has a baked-in user that doesn't honour the
    /// VDI_USERNAME env var.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_username: Option<String>,
    /// Optional fixed password matching `container_username`. When set,
    /// rustguac uses this password for the RDP connect instead of
    /// generating an ephemeral one. Stored in Vault alongside the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_password: Option<String>,
    /// Allow users to generate a Share URL for sessions from this entry.
    /// Default: false (admin must opt in per entry). Gates the Share
    /// button in the Connections Active Sessions card — when `false`,
    /// `SessionInfo.share_url` is serialised as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_sharing: Option<bool>,
    /// GitHub #103: when true and this is the calling user's ONLY visible
    /// entry, the Connections page auto-connects to it on first load.
    /// Admin opt-in per entry. No effect for users with more than one
    /// visible entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_open_if_singleton: Option<bool>,
    /// GitHub #154: when true, the client enters fullscreen on first user
    /// gesture after connect and locks the Escape key (Chromium) so it
    /// reaches the remote session instead of exiting fullscreen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fullscreen_on_connect: Option<bool>,
    /// When true, the clipboard/files side tabs auto-hide when idle and
    /// reappear when the pointer nears the left edge of the display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autohide_side_tabs: Option<bool>,
    /// SPICE: connect using TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spice_tls: Option<bool>,
    /// SPICE: TLS port (if the encrypted port differs from `port`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spice_tls_port: Option<u16>,
    /// SPICE: PEM CA certificate for verifying the server TLS (e.g. a Proxmox cluster CA).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spice_ca_cert: Option<String>,
    /// SPICE: expected TLS certificate subject (Proxmox "host-subject").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spice_cert_subject: Option<String>,
    /// SPICE: proxy URL, e.g. a Proxmox SPICE proxy "http://host:3128".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spice_proxy: Option<String>,
    /// Proxmox VE console: PVE API base URL, full URL incl. scheme + port
    /// (e.g. "https://pve.example.com:8006").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox_url: Option<String>,
    /// Proxmox node name hosting the VM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox_node: Option<String>,
    /// Proxmox VM id (QEMU) whose console to open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox_vmid: Option<u32>,
    /// Proxmox API token id ("user@realm!tokenname") — non-secret, shown in the
    /// UI (User column).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox_token_id: Option<String>,
    /// Proxmox API token secret (UUID). Credential — never returned to the
    /// browser (see EntryInfo::has_proxmox_token_secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox_token_secret: Option<String>,
    /// Verify the PVE API + SPICE-proxy TLS certificate (default false; PVE
    /// ships a self-signed cluster cert).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox_verify_tls: Option<bool>,
    /// Total number of monitors to offer for SPICE/Proxmox multi-monitor
    /// (default 1 = single monitor). guacd is told `secondary-monitors =
    /// max_monitors - 1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_monitors: Option<u32>,
    /// SSH terminal font size in points (default: 12). Only applies to SSH
    /// sessions. Lets operators tune readability independently of display DPI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_font_size: Option<u32>,
    /// Wake-on-LAN: send a magic packet to wake the target before connecting.
    /// Passed through to guacd's `wol-send-packet` param (SSH/RDP/VNC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wol_send_packet: Option<bool>,
    /// Wake-on-LAN: target MAC address (e.g. "00:11:22:33:44:55"). Required
    /// when `wol_send_packet` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wol_mac_addr: Option<String>,
    /// Wake-on-LAN: broadcast address to send the magic packet to
    /// (default guacd value: 255.255.255.255).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wol_broadcast_addr: Option<String>,
    /// Wake-on-LAN: UDP port for the magic packet (default guacd value: 9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wol_udp_port: Option<u16>,
    /// Wake-on-LAN: seconds to wait after sending the packet before attempting
    /// to connect, giving the host time to boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wol_wait_time: Option<u32>,
}

impl AddressBookEntry {
    /// Migrate legacy flat jump_host fields into the jump_hosts array.
    /// If `jump_hosts` is already set, this is a no-op.
    pub fn normalize_jump_hosts(&mut self) {
        if self.jump_hosts.is_some() {
            return;
        }
        if let Some(ref host) = self.jump_host {
            if !host.is_empty() {
                self.jump_hosts = Some(vec![tunnel::JumpHost {
                    hostname: host.clone(),
                    port: self.jump_port.unwrap_or(22),
                    username: self.jump_username.clone().unwrap_or_default(),
                    password: self.jump_password.clone(),
                    private_key: self.jump_private_key.clone(),
                    host_key: None,
                }]);
            }
        }
        // Clear legacy fields so they don't get written back
        self.jump_host = None;
        self.jump_port = None;
        self.jump_username = None;
        self.jump_password = None;
        self.jump_private_key = None;
    }
}

/// Entry metadata returned to non-admin users (credentials stripped).
#[derive(Debug, Clone, Serialize)]
pub struct EntryInfo {
    pub name: String,
    pub session_type: String,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub display_name: Option<String>,
    pub domain: Option<String>,
    pub security: Option<String>,
    pub ignore_cert: Option<bool>,
    pub enable_drive: Option<bool>,
    /// NLA auth package: "kerberos", "ntlm", or empty (negotiate).
    pub auth_pkg: Option<String>,
    /// Kerberos KDC URL (optional).
    pub kdc_url: Option<String>,
    /// Whether to prompt for credentials at connect time.
    pub prompt_credentials: Option<bool>,
    /// Whether the entry has a stored password or private key.
    pub has_credentials: bool,
    /// VNC color depth.
    pub color_depth: Option<u8>,
    /// SSH tunnel jump hosts (no credentials exposed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_hosts: Option<Vec<tunnel::JumpHostInfo>>,
    /// RDP RemoteApp program path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_app: Option<String>,
    /// RDP RemoteApp working directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_app_dir: Option<String>,
    /// RDP RemoteApp command-line arguments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_app_args: Option<String>,
    /// Override recording enabled/disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_recording: Option<bool>,
    /// Maximum recordings to keep for this entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_recordings: Option<u32>,
    /// Enable SSH typescript recording for this entry (#159).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_typescript: Option<bool>,
    /// Login script filename (web sessions only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_script: Option<String>,
    /// Autofill credentials JSON (web sessions only). Contains $PASSWORD placeholders, not actual values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autofill: Option<String>,
    /// Allowed domains for web sessions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<Vec<String>>,
    /// Disable clipboard copy (server → client).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_copy: Option<bool>,
    /// Disable clipboard paste (client → server).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_paste: Option<bool>,
    /// Banner text shown before session starts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// Credential variable names referenced by this entry (e.g. ["corp_user", "corp_password"]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub credential_variables: Vec<String>,
    /// Enable RDP Graphics Pipeline Extension (GFX).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_gfx: Option<bool>,
    /// Enable desktop composition (DWM).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_desktop_composition: Option<bool>,
    /// Show the remote desktop wallpaper.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_wallpaper: Option<bool>,
    /// Enable window/control theming (visual styles).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_theming: Option<bool>,
    /// Show window contents while dragging.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_full_window_drag: Option<bool>,
    /// Force lossless encoding (PNG only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_lossless: Option<bool>,
    /// Enable H.264 passthrough.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_h264: Option<bool>,
    /// Paint AVC444 in full 4:4:4 colour. Unset means Standard (4:2:0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h264_chroma444: Option<bool>,
    /// Request the framebuffer in physical rather than CSS pixels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_resolution: Option<bool>,
    /// Docker image for VDI sessions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_image: Option<String>,
    /// CPU limit for VDI container (cores, e.g. 2.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_cpu_limit: Option<f64>,
    /// Memory limit for VDI container (bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_memory_limit: Option<u64>,
    /// Environment variables to inject into the VDI container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_env: Option<std::collections::HashMap<String, String>>,
    /// Idle timeout for VDI container in minutes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_idle_timeout_mins: Option<u64>,
    /// Optional fixed VDI container username (for images with baked-in
    /// accounts that don't honour VDI_USERNAME).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_username: Option<String>,
    /// Whether a fixed VDI container password is stored on this entry.
    /// The actual value is never serialised back to clients.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub has_container_password: bool,
    /// Whether users can generate Share URLs for sessions of this entry.
    /// Defaults to false — admin must opt in per entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_sharing: Option<bool>,
    /// Auto-open on login when this is the user's only visible entry (#103).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_open_if_singleton: Option<bool>,
    /// Open the client in fullscreen on connect (#154).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fullscreen_on_connect: Option<bool>,
    /// Auto-hide the clipboard/files side tabs when idle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autohide_side_tabs: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spice_tls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spice_tls_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spice_ca_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spice_cert_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spice_proxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxmox_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxmox_node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxmox_vmid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxmox_verify_tls: Option<bool>,
    /// Proxmox token id (non-secret; shown in the User column).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxmox_token_id: Option<String>,
    /// Whether a Proxmox token secret is stored (the secret itself is never
    /// returned; the UI shows "leave blank to keep").
    pub has_proxmox_token_secret: bool,
    /// Total monitors offered (SPICE/Proxmox multi-monitor); 1 = single.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_monitors: Option<u32>,
    /// SSH terminal font size in points (SSH only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_font_size: Option<u32>,
    /// Wake-on-LAN: send a magic packet before connecting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wol_send_packet: Option<bool>,
    /// Wake-on-LAN: target MAC address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wol_mac_addr: Option<String>,
    /// Wake-on-LAN: broadcast address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wol_broadcast_addr: Option<String>,
    /// Wake-on-LAN: UDP port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wol_udp_port: Option<u16>,
    /// Wake-on-LAN: wait time (seconds) after sending the packet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wol_wait_time: Option<u32>,
}

impl From<(&str, &AddressBookEntry)> for EntryInfo {
    fn from((name, e): (&str, &AddressBookEntry)) -> Self {
        let jump_hosts = e.jump_hosts.as_ref().map(|hops| {
            hops.iter()
                .map(|h| tunnel::JumpHostInfo {
                    hostname: h.hostname.clone(),
                    port: h.port,
                    username: h.username.clone(),
                    host_key_fingerprint: h
                        .host_key
                        .as_ref()
                        .and_then(|k| tunnel::fingerprint_openssh_key(k).ok()),
                })
                .collect()
        });
        Self {
            name: name.to_string(),
            session_type: e.session_type.clone(),
            hostname: e.hostname.clone(),
            port: e.port,
            username: e.username.clone(),
            url: e.url.clone(),
            display_name: e.display_name.clone(),
            domain: e.domain.clone(),
            security: e.security.clone(),
            ignore_cert: e.ignore_cert,
            enable_drive: e.enable_drive,
            auth_pkg: e.auth_pkg.clone(),
            kdc_url: e.kdc_url.clone(),
            prompt_credentials: e.prompt_credentials,
            has_credentials: e.password.as_ref().is_some_and(|p| !p.is_empty())
                || e.private_key.as_ref().is_some_and(|k| !k.is_empty()),
            color_depth: e.color_depth,
            jump_hosts,
            remote_app: e.remote_app.clone(),
            remote_app_dir: e.remote_app_dir.clone(),
            remote_app_args: e.remote_app_args.clone(),
            enable_recording: e.enable_recording,
            max_recordings: e.max_recordings,
            record_typescript: e.record_typescript,
            login_script: e.login_script.clone(),
            autofill: e.autofill.clone(),
            allowed_domains: e.allowed_domains.clone(),
            disable_copy: e.disable_copy,
            disable_paste: e.disable_paste,
            banner: e.banner.clone(),
            credential_variables: entry_credential_variables(e),
            enable_gfx: e.enable_gfx,
            enable_desktop_composition: e.enable_desktop_composition,
            enable_wallpaper: e.enable_wallpaper,
            enable_theming: e.enable_theming,
            enable_full_window_drag: e.enable_full_window_drag,
            force_lossless: e.force_lossless,
            enable_h264: e.enable_h264,
            h264_chroma444: e.h264_chroma444,
            native_resolution: e.native_resolution,
            container_image: e.container_image.clone(),
            container_cpu_limit: e.container_cpu_limit,
            container_memory_limit: e.container_memory_limit,
            container_env: e.container_env.clone(),
            container_idle_timeout_mins: e.container_idle_timeout_mins,
            container_username: e.container_username.clone(),
            has_container_password: e.container_password.as_ref().is_some_and(|p| !p.is_empty()),
            allow_sharing: e.allow_sharing,
            auto_open_if_singleton: e.auto_open_if_singleton,
            fullscreen_on_connect: e.fullscreen_on_connect,
            autohide_side_tabs: e.autohide_side_tabs,
            spice_tls: e.spice_tls,
            spice_tls_port: e.spice_tls_port,
            spice_ca_cert: e.spice_ca_cert.clone(),
            spice_cert_subject: e.spice_cert_subject.clone(),
            spice_proxy: e.spice_proxy.clone(),
            proxmox_url: e.proxmox_url.clone(),
            proxmox_node: e.proxmox_node.clone(),
            proxmox_vmid: e.proxmox_vmid,
            proxmox_verify_tls: e.proxmox_verify_tls,
            proxmox_token_id: e.proxmox_token_id.clone(),
            has_proxmox_token_secret: e
                .proxmox_token_secret
                .as_ref()
                .is_some_and(|t| !t.is_empty()),
            max_monitors: e.max_monitors,
            ssh_font_size: e.ssh_font_size,
            wol_send_packet: e.wol_send_packet,
            wol_mac_addr: e.wol_mac_addr.clone(),
            wol_broadcast_addr: e.wol_broadcast_addr.clone(),
            wol_udp_port: e.wol_udp_port,
            wol_wait_time: e.wol_wait_time,
        }
    }
}

/// Folder info returned to users.
#[derive(Debug, Clone, Serialize)]
pub struct FolderInfo {
    pub name: String,
    pub description: String,
    /// "shared" or "instance"
    pub scope: String,
    /// Full path from scope root (e.g. "Clients/Acme"). Same as name for top-level folders.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Whether this folder has subfolders (for lazy tree loading).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_children: Option<bool>,
}

// ── Vault client ──

pub struct VaultClient {
    http: reqwest::Client,
    addr: String,
    mount: String,
    base_path: String,
    namespace: Option<String>,
    instance_name: Option<String>,
    token: Arc<RwLock<String>>,
    role_id: String,
    secret_id: String,
}

impl VaultClient {
    /// Create a new Vault client and perform initial AppRole login.
    pub async fn new(config: &VaultConfig, secret_id: &str) -> Result<Self, VaultError> {
        if config.tls_skip_verify {
            tracing::warn!(
                "Vault TLS certificate verification is DISABLED (tls_skip_verify = true)"
            );
        }
        let http = build_vault_http_client(config)?;

        let client = Self {
            http,
            addr: config.addr.trim_end_matches('/').to_string(),
            mount: config.mount.clone(),
            base_path: config.base_path.clone(),
            namespace: config.namespace.clone(),
            instance_name: config.instance_name.clone(),
            token: Arc::new(RwLock::new(String::new())),
            role_id: config.role_id.clone(),
            secret_id: secret_id.to_string(),
        };

        // Perform initial login
        let (token, _ttl) = client.approle_login().await?;
        *client.token.write().await = token;

        Ok(client)
    }

    /// Authenticate via AppRole and return (token, ttl_seconds).
    async fn approle_login(&self) -> Result<(String, u64), VaultError> {
        let url = format!("{}/v1/auth/approle/login", self.addr);
        let body = serde_json::json!({
            "role_id": self.role_id,
            "secret_id": self.secret_id,
        });

        let mut req = self.http.post(&url).json(&body);
        if let Some(ref ns) = self.namespace {
            req = req.header("X-Vault-Namespace", ns.as_str());
        }

        let resp = req.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            // Truncate response body — HTML error pages from reverse proxies are useless noise
            let body_preview = if text.len() > 200 {
                format!(
                    "{}... (truncated, {} bytes total)",
                    &text[..200],
                    text.len()
                )
            } else {
                text
            };
            return Err(VaultError::Auth(format!(
                "AppRole login failed — HTTP {} from {} — response: {}",
                status.as_u16(),
                url,
                body_preview
            )));
        }

        let json: serde_json::Value = resp.json().await?;
        let token = json["auth"]["client_token"]
            .as_str()
            .ok_or_else(|| VaultError::Auth("no client_token in login response".into()))?
            .to_string();
        let ttl = json["auth"]["lease_duration"].as_u64().unwrap_or(3600);

        Ok((token, ttl))
    }

    /// Spawn a background task that renews the token at 50% of TTL.
    pub fn spawn_renewal_task(self: &Arc<Self>) {
        let client = Arc::clone(self);
        tokio::spawn(async move {
            // Initial TTL — re-login to get it
            let mut ttl = match client.approle_login().await {
                Ok((_, ttl)) => ttl,
                Err(_) => 3600,
            };

            loop {
                let sleep_secs = std::cmp::max(ttl / 2, 30);
                tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)).await;

                // Try to renew the existing token first
                let renewed = client.renew_token().await;
                match renewed {
                    Ok(new_ttl) => {
                        tracing::debug!("Vault token renewed, TTL: {}s", new_ttl);
                        ttl = new_ttl;
                    }
                    Err(_) => {
                        // Renewal failed — try full re-login
                        tracing::warn!("Vault token renewal failed, attempting re-login");
                        match client.approle_login().await {
                            Ok((new_token, new_ttl)) => {
                                *client.token.write().await = new_token;
                                ttl = new_ttl;
                                tracing::info!("Vault re-login successful, TTL: {}s", new_ttl);
                            }
                            Err(e) => {
                                tracing::error!("Vault re-login failed: {}", e);
                                ttl = 60; // retry quickly
                            }
                        }
                    }
                }
            }
        });
    }

    /// Renew the current token. Returns new TTL.
    async fn renew_token(&self) -> Result<u64, VaultError> {
        let url = format!("{}/v1/auth/token/renew-self", self.addr);
        let token = self.token.read().await.clone();

        let mut req = self.http.post(&url).header("X-Vault-Token", &token);
        if let Some(ref ns) = self.namespace {
            req = req.header("X-Vault-Namespace", ns.as_str());
        }

        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(VaultError::Auth("token renewal failed".into()));
        }

        let json: serde_json::Value = resp.json().await?;
        Ok(json["auth"]["lease_duration"].as_u64().unwrap_or(3600))
    }

    /// Make an authenticated request to Vault. Retries once on 403 with re-login.
    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<reqwest::Response, VaultError> {
        let url = format!("{}{}", self.addr, path);

        let do_request = |token: String| {
            let mut req = self
                .http
                .request(method.clone(), &url)
                .header("X-Vault-Token", &token);
            if let Some(ref ns) = self.namespace {
                req = req.header("X-Vault-Namespace", ns.as_str());
            }
            if let Some(b) = body {
                req = req.json(b);
            }
            req.send()
        };

        let token = self.token.read().await.clone();
        let resp = do_request(token).await?;

        if resp.status() == reqwest::StatusCode::FORBIDDEN {
            // Re-login and retry once
            tracing::debug!("Vault 403, attempting re-login and retry");
            match self.approle_login().await {
                Ok((new_token, _)) => {
                    *self.token.write().await = new_token.clone();
                    let resp = do_request(new_token).await?;
                    Ok(resp)
                }
                Err(e) => Err(e),
            }
        } else {
            Ok(resp)
        }
    }

    // ── Path helpers ──

    fn data_path(&self, scope_prefix: &str, rest: &str) -> String {
        format!(
            "/v1/{}/data/{}/{}/{}",
            self.mount, self.base_path, scope_prefix, rest
        )
    }

    fn metadata_path(&self, scope_prefix: &str, rest: &str) -> String {
        format!(
            "/v1/{}/metadata/{}/{}/{}",
            self.mount, self.base_path, scope_prefix, rest
        )
    }

    // ── KV v2 operations ──

    /// List top-level folders for a single scope (`"shared"` or `"instance"`).
    ///
    /// Returns an empty vec (not an error) when the scope isn't applicable to
    /// this client — e.g. `"instance"` with no `instance_name` configured — so
    /// the multi-backend fan-out can call it unconditionally.
    pub async fn list_folders_in_scope(&self, scope: &str) -> Result<Vec<FolderInfo>, VaultError> {
        let prefix = match scope {
            "shared" => "shared".to_string(),
            "instance" => match &self.instance_name {
                Some(name) => format!("instance/{}", name),
                None => return Ok(Vec::new()),
            },
            _ => return Err(VaultError::BadName(format!("invalid scope: {}", scope))),
        };

        let mut folders = Vec::new();
        let path = format!("/v1/{}/metadata/{}/{}/", self.mount, self.base_path, prefix);
        match self.kv_list(&path).await {
            Ok(keys) => {
                for name in keys.iter().filter_map(|k| k.strip_suffix('/')) {
                    folders.push(FolderInfo {
                        name: name.to_string(),
                        description: String::new(),
                        scope: scope.to_string(),
                        path: Some(name.to_string()),
                        has_children: None, // enriched below
                    });
                }
            }
            Err(VaultError::NotFound) => {
                // No folders in this scope — that's fine
            }
            Err(e) => return Err(e),
        }

        // Enrich with descriptions and child detection
        for folder in &mut folders {
            if let Ok(config) = self.get_folder_config(&folder.scope, &folder.name).await {
                folder.description = config.description;
            }
            // Check for subfolders by listing children
            if let Ok(children) = self.list_children(&folder.scope, &folder.name).await {
                folder.has_children = Some(children.iter().any(|c| c.strip_suffix('/').is_some()));
            }
        }

        Ok(folders)
    }

    /// List immediate children (subfolders and entries) at a given folder path.
    /// Subfolder names end with `/` in the returned list.
    pub async fn list_children(
        &self,
        scope: &str,
        folder_path: &str,
    ) -> Result<Vec<String>, VaultError> {
        validate_path(folder_path)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = format!("{}/", self.metadata_path(&scope_prefix, folder_path));
        self.kv_list(&path).await
    }

    /// List subfolders at a given path within a scope.
    /// Returns FolderInfo for each subfolder, with has_children populated.
    pub async fn list_subfolders(
        &self,
        scope: &str,
        parent_path: &str,
    ) -> Result<Vec<FolderInfo>, VaultError> {
        let children = self.list_children(scope, parent_path).await?;
        let mut folders = Vec::new();

        for key in &children {
            if let Some(name) = key.strip_suffix('/') {
                let full_path = format!("{}/{}", parent_path, name);
                let mut info = FolderInfo {
                    name: name.to_string(),
                    description: String::new(),
                    scope: scope.to_string(),
                    path: Some(full_path.clone()),
                    has_children: None,
                };
                // Enrich with description
                if let Ok(config) = self.get_folder_config(scope, &full_path).await {
                    info.description = config.description;
                }
                // Check for grandchildren
                if let Ok(grandchildren) = self.list_children(scope, &full_path).await {
                    info.has_children =
                        Some(grandchildren.iter().any(|c| c.strip_suffix('/').is_some()));
                }
                folders.push(info);
            }
        }

        Ok(folders)
    }

    /// Get the .config for a folder in a specific scope.
    pub async fn get_folder_config(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<FolderConfig, VaultError> {
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.data_path(&scope_prefix, &format!("{}/{}", folder, ".config"));
        let resp = self.request(reqwest::Method::GET, &path, None).await?;

        match resp.status().as_u16() {
            200 => {
                let json: serde_json::Value = resp.json().await?;
                let data = &json["data"]["data"];
                serde_json::from_value(data.clone())
                    .map_err(|e| VaultError::Parse(format!("invalid .config: {}", e)))
            }
            404 => Err(VaultError::NotFound),
            403 => Err(VaultError::Forbidden),
            s => Err(VaultError::Parse(format!("unexpected status {}", s))),
        }
    }

    /// Resolve whether `who` may access `folder` under `scope`.
    ///
    /// Checks the folder's own `allowed_groups` and `allowed_users` first
    /// (see `FolderConfig::grants`). If neither matches and the
    /// folder's `inherit_from_parent` is true, walks up the slash-separated
    /// path and evaluates each ancestor's config the same way. Returns `false`
    /// once a folder denies and doesn't inherit, or once the walk reaches the
    /// top-level folder with no match. Missing (`NotFound`) folder configs
    /// are treated as deny; other Vault errors propagate so callers can log.
    pub async fn resolve_folder_access(
        &self,
        scope: &str,
        folder: &str,
        who: FolderSubject<'_>,
    ) -> Result<bool, VaultError> {
        let mut current = folder.to_string();
        loop {
            let config = match self.get_folder_config(scope, &current).await {
                Ok(c) => c,
                Err(VaultError::NotFound) => return Ok(false),
                Err(e) => return Err(e),
            };
            if config.grants(who) {
                return Ok(true);
            }
            if !config.inherit_from_parent {
                return Ok(false);
            }
            // Walk to parent segment; stop at the top-level folder.
            match current.rsplit_once('/') {
                Some((parent, _)) if !parent.is_empty() => current = parent.to_string(),
                _ => return Ok(false),
            }
        }
    }

    /// List entry names in a folder (excludes .config).
    pub async fn list_entries(&self, scope: &str, folder: &str) -> Result<Vec<String>, VaultError> {
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = format!("{}/", self.metadata_path(&scope_prefix, folder));
        let keys = self.kv_list(&path).await?;
        Ok(keys.into_iter().filter(|k| k != ".config").collect())
    }

    /// Get a full entry (with credentials).
    pub async fn get_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<AddressBookEntry, VaultError> {
        validate_path(folder)?;
        validate_name(entry)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.data_path(&scope_prefix, &format!("{}/{}", folder, entry));
        let resp = self.request(reqwest::Method::GET, &path, None).await?;

        match resp.status().as_u16() {
            200 => {
                let json: serde_json::Value = resp.json().await?;
                let data = &json["data"]["data"];
                let mut entry: AddressBookEntry = serde_json::from_value(data.clone())
                    .map_err(|e| VaultError::Parse(format!("invalid entry: {}", e)))?;
                entry.normalize_jump_hosts();
                Ok(entry)
            }
            404 => Err(VaultError::NotFound),
            403 => Err(VaultError::Forbidden),
            s => Err(VaultError::Parse(format!("unexpected status {}", s))),
        }
    }

    /// Write an entry to Vault.
    pub async fn put_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
    ) -> Result<(), VaultError> {
        self.write_entry(scope, folder, entry, data, false)
            .await
            .map(|_| ())
    }

    /// Write an entry only if none exists at that path, enforced by Vault
    /// itself (KV v2 check-and-set with `cas: 0`) rather than by a read
    /// beforehand, so two writers cannot both pass the check. Returns
    /// `Ok(false)` when an entry is already there.
    pub async fn put_entry_if_absent(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
    ) -> Result<bool, VaultError> {
        self.write_entry(scope, folder, entry, data, true).await
    }

    async fn write_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
        only_if_absent: bool,
    ) -> Result<bool, VaultError> {
        validate_path(folder)?;
        validate_name(entry)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.data_path(&scope_prefix, &format!("{}/{}", folder, entry));
        let body = if only_if_absent {
            serde_json::json!({ "options": { "cas": 0 }, "data": data })
        } else {
            serde_json::json!({ "data": data })
        };
        let resp = self
            .request(reqwest::Method::POST, &path, Some(&body))
            .await?;

        match resp.status().as_u16() {
            200 | 204 => Ok(true),
            403 => Err(VaultError::Forbidden),
            s => {
                let text = resp.text().await.unwrap_or_default();
                if only_if_absent && s == 400 && text.contains("check-and-set") {
                    return Ok(false);
                }
                Err(VaultError::Parse(format!(
                    "put entry failed ({}): {}",
                    s, text
                )))
            }
        }
    }

    /// Delete an entry (all versions via metadata endpoint).
    pub async fn delete_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<(), VaultError> {
        validate_name(entry)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.metadata_path(&scope_prefix, &format!("{}/{}", folder, entry));
        let resp = self.request(reqwest::Method::DELETE, &path, None).await?;

        match resp.status().as_u16() {
            200 | 204 => Ok(()),
            404 => Err(VaultError::NotFound),
            403 => Err(VaultError::Forbidden),
            s => Err(VaultError::Parse(format!("delete entry failed ({})", s))),
        }
    }

    /// Write a folder's .config.
    pub async fn put_folder_config(
        &self,
        scope: &str,
        folder: &str,
        config: &FolderConfig,
    ) -> Result<(), VaultError> {
        validate_path(folder)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.data_path(&scope_prefix, &format!("{}/{}", folder, ".config"));
        let body = serde_json::json!({ "data": config });
        let resp = self
            .request(reqwest::Method::POST, &path, Some(&body))
            .await?;

        match resp.status().as_u16() {
            200 | 204 => Ok(()),
            403 => Err(VaultError::Forbidden),
            s => {
                let text = resp.text().await.unwrap_or_default();
                Err(VaultError::Parse(format!(
                    "put folder config failed ({}): {}",
                    s, text
                )))
            }
        }
    }

    /// Delete an entire folder and its subtree (all entries + .config at every
    /// level). Pre-v1.6.0 this only cleared the top folder, which silently
    /// left subfolder keys in Vault; post-subfolders the UI would then refresh
    /// and show the folder still populated with its subtree, so delete
    /// appeared to silently fail. This now walks the whole subtree iteratively.
    ///
    /// Returns (subfolder_count, entry_count) for audit/UI feedback. Subfolder
    /// count excludes the folder itself (i.e. 0 for a leaf).
    pub async fn delete_folder(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<(usize, usize), VaultError> {
        validate_path(folder)?;

        // BFS-collect every folder path in the subtree (including the root).
        let mut queue: Vec<String> = vec![folder.to_string()];
        let mut i = 0;
        while i < queue.len() {
            let current = queue[i].clone();
            if let Ok(subs) = self.list_subfolders(scope, &current).await {
                for sub in subs {
                    let sub_path = sub
                        .path
                        .unwrap_or_else(|| format!("{}/{}", current, sub.name));
                    queue.push(sub_path);
                }
            }
            i += 1;
        }

        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let mut entry_count = 0usize;
        for path in &queue {
            let entries = self.list_entries(scope, path).await.unwrap_or_default();
            for entry in entries {
                let _ = self.delete_entry(scope, path, &entry).await;
                entry_count += 1;
            }
            let cfg_path = self.metadata_path(&scope_prefix, &format!("{}/{}", path, ".config"));
            let _ = self.request(reqwest::Method::DELETE, &cfg_path, None).await;
        }

        let subfolder_count = queue.len().saturating_sub(1);
        Ok((subfolder_count, entry_count))
    }

    // ── Generic KV v2 read ──

    /// Read a single field from an arbitrary KV v2 path (relative to base_path).
    /// Used for reading non-address-book secrets like the LUKS encryption key.
    pub async fn read_kv_field(&self, kv_path: &str, field: &str) -> Result<String, VaultError> {
        let path = format!("/v1/{}/data/{}", self.mount, kv_path);
        let resp = self.request(reqwest::Method::GET, &path, None).await?;

        match resp.status().as_u16() {
            200 => {
                let json: serde_json::Value = resp.json().await?;
                json["data"]["data"][field]
                    .as_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| {
                        VaultError::Parse(format!("field '{}' not found in secret", field))
                    })
            }
            404 => Err(VaultError::NotFound),
            403 => Err(VaultError::Forbidden),
            s => Err(VaultError::Parse(format!("unexpected status {}", s))),
        }
    }

    // ── Internal helpers ──

    /// Resolve "shared" or "instance" scope label to the actual Vault path prefix.
    fn resolve_scope_prefix(&self, scope: &str) -> Result<String, VaultError> {
        match scope {
            "shared" => Ok("shared".to_string()),
            "instance" => match &self.instance_name {
                Some(name) => Ok(format!("instance/{}", name)),
                None => Err(VaultError::BadName("no instance_name configured".into())),
            },
            _ => Err(VaultError::BadName(format!("invalid scope: {}", scope))),
        }
    }

    /// Perform a LIST operation on a Vault path. Returns the keys array.
    async fn kv_list(&self, path: &str) -> Result<Vec<String>, VaultError> {
        // Vault LIST is a GET with ?list=true (also works with HTTP method LIST,
        // but ?list=true is more portable across HTTP clients).
        let url = format!("{}{}?list=true", self.addr, path);
        let token = self.token.read().await.clone();

        let mut req = self.http.get(&url).header("X-Vault-Token", &token);
        if let Some(ref ns) = self.namespace {
            req = req.header("X-Vault-Namespace", ns.as_str());
        }

        let resp = req.send().await?;

        match resp.status().as_u16() {
            200 => {
                let json: serde_json::Value = resp.json().await?;
                let keys = json["data"]["keys"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(keys)
            }
            404 => Err(VaultError::NotFound),
            403 => Err(VaultError::Forbidden),
            s => Err(VaultError::Parse(format!("list failed ({})", s))),
        }
    }

    // ── User credential variables ──

    /// Read a user's stored credential variables from Vault.
    /// Path: `<base_path>/users/<sanitized_email>`
    pub async fn get_user_credentials(
        &self,
        email: &str,
    ) -> Result<HashMap<String, String>, VaultError> {
        self.get_user_credentials_by_key(&sanitize_email_key(email))
            .await
    }

    /// Write a user's credential variables to Vault (full replace).
    /// Path: `<base_path>/users/<sanitized_email>`
    pub async fn put_user_credentials(
        &self,
        email: &str,
        creds: &HashMap<String, String>,
    ) -> Result<(), VaultError> {
        self.put_user_credentials_by_key(&sanitize_email_key(email), creds)
            .await
    }

    /// Read credential variables by the already-sanitised users key. Used by
    /// `vault-migrate` (which enumerates raw keys and must not re-sanitise).
    pub async fn get_user_credentials_by_key(
        &self,
        key: &str,
    ) -> Result<HashMap<String, String>, VaultError> {
        let path = format!("/v1/{}/data/{}/users/{}", self.mount, self.base_path, key);
        let resp = self.request(reqwest::Method::GET, &path, None).await?;

        match resp.status().as_u16() {
            200 => {
                let json: serde_json::Value = resp.json().await?;
                let data = &json["data"]["data"];
                let map = data
                    .as_object()
                    .map(|obj| {
                        obj.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(map)
            }
            404 => Ok(HashMap::new()), // No credentials stored yet
            403 => Err(VaultError::Forbidden),
            s => Err(VaultError::Parse(format!(
                "get user credentials failed ({})",
                s
            ))),
        }
    }

    /// Write credential variables by the already-sanitised users key (full
    /// replace). Companion to [`get_user_credentials_by_key`] for migration.
    pub async fn put_user_credentials_by_key(
        &self,
        key: &str,
        creds: &HashMap<String, String>,
    ) -> Result<(), VaultError> {
        let path = format!("/v1/{}/data/{}/users/{}", self.mount, self.base_path, key);
        let body = serde_json::json!({ "data": creds });
        let resp = self
            .request(reqwest::Method::POST, &path, Some(&body))
            .await?;

        match resp.status().as_u16() {
            200 | 204 => Ok(()),
            403 => Err(VaultError::Forbidden),
            s => {
                let text = resp.text().await.unwrap_or_default();
                Err(VaultError::Parse(format!(
                    "put user credentials failed ({}): {}",
                    s, text
                )))
            }
        }
    }

    /// List the raw key names under `<base_path>/users/` (each a sanitised
    /// email). Empty when no credentials have been stored yet.
    pub async fn list_user_keys(&self) -> Result<Vec<String>, VaultError> {
        let path = format!("/v1/{}/metadata/{}/users/", self.mount, self.base_path);
        match self.kv_list(&path).await {
            Ok(keys) => Ok(keys.into_iter().filter(|k| !k.ends_with('/')).collect()),
            Err(VaultError::NotFound) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Delete a user's credential variables from Vault.
    #[allow(dead_code)] // Will be used by admin endpoint
    pub async fn delete_user_credentials(&self, email: &str) -> Result<(), VaultError> {
        let key = sanitize_email_key(email);
        let path = format!(
            "/v1/{}/metadata/{}/users/{}",
            self.mount, self.base_path, key
        );
        let resp = self.request(reqwest::Method::DELETE, &path, None).await?;

        match resp.status().as_u16() {
            200 | 204 => Ok(()),
            404 => Ok(()), // Already gone
            403 => Err(VaultError::Forbidden),
            s => Err(VaultError::Parse(format!(
                "delete user credentials failed ({})",
                s
            ))),
        }
    }
}

/// Build a reqwest HTTP client from a VaultConfig (extracted for testability).
fn build_vault_http_client(config: &VaultConfig) -> Result<reqwest::Client, VaultError> {
    let needs_custom_tls =
        config.client_cert.is_some() || config.ca_cert.is_some() || config.tls_skip_verify;

    if !needs_custom_tls {
        // Simple path: no custom TLS config needed
        return reqwest::Client::builder()
            .build()
            .map_err(|e| VaultError::Auth(format!("failed to create HTTP client: {}", e)));
    }

    // Ensure ring crypto provider is available (needed when building rustls ClientConfig
    // directly rather than through reqwest's builder).
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Build a rustls ClientConfig directly — this bypasses reqwest::Identity::from_pem()
    // which can fail with the rustls backend for valid PKCS#8 keys from OpenBao/Vault PKI.
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Custom CA certificate for private/self-signed CAs
    if let Some(ref ca_path) = config.ca_cert {
        let ca_pem = std::fs::read(ca_path)
            .map_err(|e| VaultError::Auth(format!("failed to read CA cert {}: {}", ca_path, e)))?;
        let ca_certs: Vec<_> = rustls_pemfile::certs(&mut ca_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| VaultError::Auth(format!("failed to parse CA cert {}: {}", ca_path, e)))?;
        if ca_certs.is_empty() {
            return Err(VaultError::Auth(format!(
                "no certificates found in CA file {}",
                ca_path
            )));
        }
        for cert in &ca_certs {
            root_store.add(cert.clone()).map_err(|e| {
                VaultError::Auth(format!("failed to add CA cert to root store: {}", e))
            })?;
        }
        tracing::info!(
            "Vault TLS: added {} CA certificate(s) from {}",
            ca_certs.len(),
            ca_path
        );
    }

    let tls_config = if let Some(ref cert_path) = config.client_cert {
        // mTLS: parse client cert chain + private key, build rustls config directly
        let key_path = config.client_key.as_deref().ok_or_else(|| {
            VaultError::Auth(
                "client_cert is set but client_key is missing in [vault] config".into(),
            )
        })?;
        let cert_pem = std::fs::read(cert_path).map_err(|e| {
            VaultError::Auth(format!("failed to read client cert {}: {}", cert_path, e))
        })?;
        let key_pem = std::fs::read(key_path).map_err(|e| {
            VaultError::Auth(format!("failed to read client key {}: {}", key_path, e))
        })?;

        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                VaultError::Auth(format!(
                    "failed to parse certificates from {}: {}",
                    cert_path, e
                ))
            })?;
        if certs.is_empty() {
            return Err(VaultError::Auth(format!(
                "no certificates found in {}",
                cert_path
            )));
        }
        tracing::info!(
            "Vault TLS: parsed {} certificate(s) from {}",
            certs.len(),
            cert_path
        );

        let private_key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .map_err(|e| {
                VaultError::Auth(format!(
                    "failed to parse private key from {}: {} \
                     (expected PEM: BEGIN PRIVATE KEY, BEGIN RSA PRIVATE KEY, or BEGIN EC PRIVATE KEY)",
                    key_path, e
                ))
            })?
            .ok_or_else(|| {
                VaultError::Auth(format!(
                    "no private key found in {} \
                     (expected PEM: BEGIN PRIVATE KEY, BEGIN RSA PRIVATE KEY, or BEGIN EC PRIVATE KEY)",
                    key_path
                ))
            })?;
        tracing::info!(
            "Vault TLS: parsed private key from {} ({} bytes DER)",
            key_path,
            private_key.secret_der().len()
        );

        let builder = if config.tls_skip_verify {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
        } else {
            rustls::ClientConfig::builder().with_root_certificates(root_store)
        };

        builder
            .with_client_auth_cert(certs, private_key)
            .map_err(|e| {
                VaultError::Auth(format!(
                    "failed to build mTLS config with {} + {}: {}",
                    cert_path, key_path, e
                ))
            })?
    } else {
        // CA cert only (no mTLS) or tls_skip_verify
        if config.tls_skip_verify {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
    };

    reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .build()
        .map_err(|e| VaultError::Auth(format!("failed to create HTTP client: {}", e)))
}

/// Certificate verifier that accepts all server certificates (for tls_skip_verify).
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Validate that a folder or entry name is safe (alphanumeric, hyphens, underscores, dots — no path traversal).
fn validate_name(name: &str) -> Result<(), VaultError> {
    if name.is_empty() || name.len() > 64 {
        return Err(VaultError::BadName("name must be 1-64 characters".into()));
    }
    if name == ".config" || name == "." || name == ".." {
        return Err(VaultError::BadName("reserved name".into()));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(VaultError::BadName(
            "name cannot contain path separators".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(VaultError::BadName(
            "name must be alphanumeric, hyphens, underscores, or dots".into(),
        ));
    }
    Ok(())
}

/// Validate a folder path that may contain subfolders (e.g. "Clients/Acme/Servers").
/// Each segment is validated with the same rules as `validate_name`.
/// Empty segments, trailing slashes, and leading slashes are rejected.
fn validate_path(path: &str) -> Result<(), VaultError> {
    if path.is_empty() {
        return Err(VaultError::BadName("path cannot be empty".into()));
    }
    if path.len() > 256 {
        return Err(VaultError::BadName("path too long (max 256 chars)".into()));
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(VaultError::BadName(
            "path cannot start or end with /".into(),
        ));
    }
    if path.contains("//") {
        return Err(VaultError::BadName(
            "path cannot contain empty segments".into(),
        ));
    }
    for segment in path.split('/') {
        validate_name(segment)?;
    }
    Ok(())
}

/// Sanitize an email address for use as a Vault path component.
/// Replaces `@` with `_at_` and strips any characters not in `[a-zA-Z0-9._-]`.
fn sanitize_email_key(email: &str) -> String {
    email
        .replace('@', "_at_")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect()
}

/// Check if a string is a credential variable reference (starts with `$`).
pub fn is_credential_variable(s: &str) -> bool {
    s.starts_with('$')
        && s.len() > 1
        && s[1..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Extract the variable name from a `$variable` reference.
fn variable_name(s: &str) -> Option<&str> {
    if is_credential_variable(s) {
        Some(&s[1..])
    } else {
        None
    }
}

/// Collect all credential variable names referenced by an address book entry.
pub fn entry_credential_variables(entry: &AddressBookEntry) -> Vec<String> {
    [
        &entry.username,
        &entry.password,
        &entry.domain,
        &entry.private_key,
        &entry.container_username,
        &entry.container_password,
    ]
    .iter()
    .filter_map(|field| field.as_deref())
    .filter_map(variable_name)
    .map(|s| s.to_string())
    .collect()
}

/// Resolve credential variable references in an address book entry.
/// Returns the entry with `$var` fields substituted from the user's credential map.
/// Fields that are not variable references are left unchanged.
/// Returns `Err(vec_of_missing_var_names)` if any referenced variables are missing.
pub fn resolve_credential_variables(
    entry: &AddressBookEntry,
    user_creds: &HashMap<String, String>,
) -> Result<AddressBookEntry, Vec<String>> {
    let mut resolved = entry.clone();
    let mut missing = Vec::new();

    fn resolve_field(
        field: &mut Option<String>,
        creds: &HashMap<String, String>,
        missing: &mut Vec<String>,
    ) {
        if let Some(ref val) = field {
            if let Some(name) = variable_name(val) {
                if let Some(resolved_val) = creds.get(name) {
                    *field = Some(resolved_val.clone());
                } else {
                    missing.push(name.to_string());
                }
            }
        }
    }

    resolve_field(&mut resolved.username, user_creds, &mut missing);
    resolve_field(&mut resolved.password, user_creds, &mut missing);
    resolve_field(&mut resolved.domain, user_creds, &mut missing);
    resolve_field(&mut resolved.private_key, user_creds, &mut missing);
    resolve_field(&mut resolved.container_username, user_creds, &mut missing);
    resolve_field(&mut resolved.container_password, user_creds, &mut missing);

    if missing.is_empty() {
        Ok(resolved)
    } else {
        Err(missing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(groups: &[&str], users: &[&str]) -> FolderConfig {
        FolderConfig {
            allowed_groups: groups.iter().map(|s| s.to_string()).collect(),
            allowed_users: users.iter().map(|s| s.to_string()).collect(),
            description: String::new(),
            inherit_from_parent: false,
        }
    }

    fn who<'a>(email: Option<&'a str>, groups: &'a [String]) -> FolderSubject<'a> {
        FolderSubject { email, groups }
    }

    #[test]
    fn folder_grants_by_group_or_user() {
        let ops = vec!["ops".to_string()];
        let none: Vec<String> = vec![];
        let c = cfg(&["ops"], &["jsmith@example.com"]);
        assert!(c.grants(who(Some("someone@example.com"), &ops)), "group");
        assert!(c.grants(who(Some("jsmith@example.com"), &none)), "user");
        assert!(
            c.grants(who(Some("JSmith@Example.COM"), &none)),
            "case-insensitive"
        );
        assert!(!c.grants(who(Some("other@example.com"), &none)));
    }

    #[test]
    fn folder_user_grant_needs_a_real_email() {
        let none: Vec<String> = vec![];
        let c = cfg(&[], &["jsmith@example.com"]);
        assert!(!c.grants(who(None, &none)), "no identity email");
        assert!(!c.grants(who(Some(""), &none)), "empty email");
        // An empty or blank entry in the list must not match a blank email.
        let blank = cfg(&[], &["", "  "]);
        assert!(!blank.grants(who(Some(" "), &none)));
    }

    #[test]
    fn empty_folder_config_grants_nobody() {
        let ops = vec!["ops".to_string()];
        assert!(!cfg(&[], &[]).grants(who(Some("jsmith@example.com"), &ops)));
    }

    /// Configs written before allowed_users existed still load, and a config
    /// with no users is stored exactly as before.
    #[test]
    fn folder_config_allowed_users_is_backward_compatible() {
        let old: FolderConfig =
            serde_json::from_str(r#"{"allowed_groups":["ops"],"description":"x"}"#).unwrap();
        assert!(old.allowed_users.is_empty());
        let json = serde_json::to_value(cfg(&["ops"], &[])).unwrap();
        assert!(json.get("allowed_users").is_none(), "{json}");
        let json = serde_json::to_value(cfg(&[], &["a@b.c"])).unwrap();
        assert_eq!(json["allowed_users"][0], "a@b.c");
    }

    fn base_config() -> VaultConfig {
        VaultConfig {
            addr: "https://vault.example.com:8200".into(),
            mount: "secret".into(),
            base_path: "rustguac".into(),
            role_id: "test-role-id".into(),
            namespace: None,
            instance_name: None,
            tls_skip_verify: false,
            ca_cert: None,
            client_cert: None,
            client_key: None,
        }
    }

    #[test]
    fn test_build_client_defaults() {
        let config = base_config();
        let client = build_vault_http_client(&config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_build_client_tls_skip_verify() {
        let mut config = base_config();
        config.tls_skip_verify = true;
        let client = build_vault_http_client(&config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_build_client_ca_cert_missing_file() {
        let mut config = base_config();
        config.ca_cert = Some("/nonexistent/ca.pem".into());
        let err = build_vault_http_client(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed to read CA cert"), "got: {}", msg);
        assert!(msg.contains("/nonexistent/ca.pem"), "got: {}", msg);
    }

    #[test]
    fn test_build_client_ca_cert_invalid_pem() {
        // reqwest::Certificate::from_pem rejects PEM with valid headers but
        // garbage DER content.
        let dir = std::env::temp_dir().join("rustguac-test-vault-tls");
        let _ = std::fs::create_dir_all(&dir);
        let ca_path = dir.join("bad-ca.pem");
        let bad_pem =
            "-----BEGIN CERTIFICATE-----\nDEFINITELYnotvalid!!!\n-----END CERTIFICATE-----\n";
        std::fs::write(&ca_path, bad_pem.as_bytes()).unwrap();

        let mut config = base_config();
        config.ca_cert = Some(ca_path.to_str().unwrap().into());
        let result = build_vault_http_client(&config);
        assert!(result.is_err(), "expected error for invalid PEM");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_client_client_cert_without_key() {
        let dir = std::env::temp_dir().join("rustguac-test-vault-tls-nokey");
        let _ = std::fs::create_dir_all(&dir);
        let cert_path = dir.join("client.pem");
        std::fs::write(&cert_path, b"placeholder").unwrap();

        let mut config = base_config();
        config.client_cert = Some(cert_path.to_str().unwrap().into());
        // client_key intentionally None
        let err = build_vault_http_client(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("client_key is missing"), "got: {}", msg);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_client_client_cert_missing_file() {
        let mut config = base_config();
        config.client_cert = Some("/nonexistent/client.pem".into());
        config.client_key = Some("/nonexistent/client-key.pem".into());
        let err = build_vault_http_client(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed to read client cert"), "got: {}", msg);
    }

    #[test]
    fn test_build_client_client_key_missing_file() {
        let dir = std::env::temp_dir().join("rustguac-test-vault-tls-keyfile");
        let _ = std::fs::create_dir_all(&dir);
        let cert_path = dir.join("client.pem");
        std::fs::write(&cert_path, b"placeholder cert").unwrap();

        let mut config = base_config();
        config.client_cert = Some(cert_path.to_str().unwrap().into());
        config.client_key = Some("/nonexistent/client-key.pem".into());
        let err = build_vault_http_client(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed to read client key"), "got: {}", msg);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_client_valid_ca_cert() {
        let dir = std::env::temp_dir().join("rustguac-test-vault-tls-valid");
        let _ = std::fs::create_dir_all(&dir);
        let ca_path = dir.join("ca.pem");

        // Generate a real self-signed cert via openssl
        let output = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-keyout",
                "/dev/null",
                "-out",
                ca_path.to_str().unwrap(),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=Test CA",
            ])
            .output()
            .expect("openssl must be available for this test");
        assert!(output.status.success(), "openssl failed: {:?}", output);

        let mut config = base_config();
        config.ca_cert = Some(ca_path.to_str().unwrap().into());
        let result = build_vault_http_client(&config);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_config_deserialize_tls_fields() {
        let toml_str = r#"
            addr = "https://vault.example.com:8200"
            role_id = "test-role"
            ca_cert = "/opt/rustguac/certs/ca.pem"
            client_cert = "/opt/rustguac/certs/client.pem"
            client_key = "/opt/rustguac/certs/client-key.pem"
            tls_skip_verify = true
        "#;
        let config: VaultConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.ca_cert.as_deref(),
            Some("/opt/rustguac/certs/ca.pem")
        );
        assert_eq!(
            config.client_cert.as_deref(),
            Some("/opt/rustguac/certs/client.pem")
        );
        assert_eq!(
            config.client_key.as_deref(),
            Some("/opt/rustguac/certs/client-key.pem")
        );
        assert!(config.tls_skip_verify);
    }

    #[test]
    fn test_config_deserialize_no_tls_fields() {
        let toml_str = r#"
            addr = "https://vault.example.com:8200"
            role_id = "test-role"
        "#;
        let config: VaultConfig = toml::from_str(toml_str).unwrap();
        assert!(config.ca_cert.is_none());
        assert!(config.client_cert.is_none());
        assert!(config.client_key.is_none());
        assert!(!config.tls_skip_verify);
    }

    #[test]
    fn test_validate_name_ok() {
        assert!(validate_name("my-entry.v2").is_ok());
        assert!(validate_name("a").is_ok());
    }

    #[test]
    fn test_validate_name_rejects_traversal() {
        assert!(validate_name("../etc").is_err());
        assert!(validate_name("foo/bar").is_err());
        assert!(validate_name(".config").is_err());
    }

    #[test]
    fn test_validate_name_rejects_empty_and_long() {
        assert!(validate_name("").is_err());
        assert!(validate_name(&"a".repeat(65)).is_err());
    }

    #[test]
    fn test_validate_path_ok() {
        assert!(validate_path("my-folder").is_ok());
        assert!(validate_path("Clients/Acme").is_ok());
        assert!(validate_path("Clients/Acme/Servers").is_ok());
        assert!(validate_path("a/b/c/d").is_ok());
    }

    #[test]
    fn test_validate_path_rejects_bad_input() {
        assert!(validate_path("").is_err()); // empty
        assert!(validate_path("/leading").is_err()); // leading slash
        assert!(validate_path("trailing/").is_err()); // trailing slash
        assert!(validate_path("a//b").is_err()); // empty segment
        assert!(validate_path("a/../b").is_err()); // traversal
        assert!(validate_path("a/.config/b").is_err()); // reserved name
        assert!(validate_path(&format!("a/{}", "x".repeat(65))).is_err()); // segment too long
    }

    #[test]
    fn test_build_client_mtls_pkcs8_key() {
        // This test reproduces issue #51: PKCS#8 keys from OpenBao should work.
        let dir = std::env::temp_dir().join("rustguac-test-vault-mtls");
        let _ = std::fs::create_dir_all(&dir);
        let cert_path = dir.join("client.pem");
        let key_path = dir.join("client-key.pem");

        // Generate CA
        let ca_key = dir.join("ca-key.pem");
        let ca_cert_path = dir.join("ca.pem");
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-keyout",
                ca_key.to_str().unwrap(),
                "-out",
                ca_cert_path.to_str().unwrap(),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=Test CA",
            ])
            .output()
            .expect("openssl needed");
        assert!(status.status.success(), "CA gen failed");

        // Generate client cert signed by CA (PKCS#8 key — OpenBao default)
        let csr_path = dir.join("client.csr");
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-keyout",
                key_path.to_str().unwrap(),
                "-out",
                csr_path.to_str().unwrap(),
                "-nodes",
                "-subj",
                "/CN=client",
            ])
            .output()
            .expect("openssl needed");
        assert!(status.status.success(), "CSR gen failed");

        let status = std::process::Command::new("openssl")
            .args([
                "x509",
                "-req",
                "-in",
                csr_path.to_str().unwrap(),
                "-CA",
                ca_cert_path.to_str().unwrap(),
                "-CAkey",
                ca_key.to_str().unwrap(),
                "-CAcreateserial",
                "-out",
                cert_path.to_str().unwrap(),
                "-days",
                "1",
            ])
            .output()
            .expect("openssl needed");
        assert!(status.status.success(), "client cert gen failed");

        // Verify the key is PKCS#8 (BEGIN PRIVATE KEY, not BEGIN EC PRIVATE KEY)
        let key_pem = std::fs::read_to_string(&key_path).unwrap();
        assert!(
            key_pem.contains("BEGIN PRIVATE KEY"),
            "expected PKCS#8 key, got: {}",
            key_pem.lines().next().unwrap_or("")
        );

        let mut config = base_config();
        config.ca_cert = Some(ca_cert_path.to_str().unwrap().into());
        config.client_cert = Some(cert_path.to_str().unwrap().into());
        config.client_key = Some(key_path.to_str().unwrap().into());
        let result = build_vault_http_client(&config);
        assert!(
            result.is_ok(),
            "mTLS with PKCS#8 key failed: {:?}",
            result.err()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_client_mtls_fullchain_cert() {
        // Test with fullchain cert (leaf + CA) — as OpenBao typically delivers.
        let dir = std::env::temp_dir().join("rustguac-test-vault-mtls-chain");
        let _ = std::fs::create_dir_all(&dir);
        let key_path = dir.join("client-key.pem");
        let fullchain_path = dir.join("client-fullchain.pem");

        // Generate CA
        let ca_key = dir.join("ca-key.pem");
        let ca_cert_path = dir.join("ca.pem");
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-keyout",
                ca_key.to_str().unwrap(),
                "-out",
                ca_cert_path.to_str().unwrap(),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=Test CA",
            ])
            .output()
            .expect("openssl needed");
        assert!(status.status.success());

        // Generate client cert
        let csr_path = dir.join("client.csr");
        let leaf_path = dir.join("client-leaf.pem");
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-keyout",
                key_path.to_str().unwrap(),
                "-out",
                csr_path.to_str().unwrap(),
                "-nodes",
                "-subj",
                "/CN=client",
            ])
            .output()
            .expect("openssl needed");
        assert!(status.status.success());

        let status = std::process::Command::new("openssl")
            .args([
                "x509",
                "-req",
                "-in",
                csr_path.to_str().unwrap(),
                "-CA",
                ca_cert_path.to_str().unwrap(),
                "-CAkey",
                ca_key.to_str().unwrap(),
                "-CAcreateserial",
                "-out",
                leaf_path.to_str().unwrap(),
                "-days",
                "1",
            ])
            .output()
            .expect("openssl needed");
        assert!(status.status.success());

        // Build fullchain: leaf + CA (as OpenBao delivers)
        let leaf = std::fs::read_to_string(&leaf_path).unwrap();
        let ca = std::fs::read_to_string(&ca_cert_path).unwrap();
        std::fs::write(&fullchain_path, format!("{}{}", leaf, ca)).unwrap();

        let mut config = base_config();
        config.ca_cert = Some(ca_cert_path.to_str().unwrap().into());
        config.client_cert = Some(fullchain_path.to_str().unwrap().into());
        config.client_key = Some(key_path.to_str().unwrap().into());
        let result = build_vault_http_client(&config);
        assert!(
            result.is_ok(),
            "mTLS with fullchain cert failed: {:?}",
            result.err()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sanitize_email_key() {
        assert_eq!(
            sanitize_email_key("alice@example.com"),
            "alice_at_example.com"
        );
        assert_eq!(sanitize_email_key("bob+tag@foo.co"), "bobtag_at_foo.co");
        assert_eq!(sanitize_email_key("../../evil"), "....evil");
    }

    #[test]
    fn test_is_credential_variable() {
        assert!(is_credential_variable("$corp_user"));
        assert!(is_credential_variable("$lab_password"));
        assert!(is_credential_variable("$x"));
        assert!(!is_credential_variable("$"));
        assert!(!is_credential_variable("plain_text"));
        assert!(!is_credential_variable(""));
        assert!(!is_credential_variable("$has spaces"));
        assert!(is_credential_variable("$has-dashes")); // hyphens allowed since v0.8.0
    }

    #[test]
    fn test_entry_credential_variables() {
        let entry = AddressBookEntry {
            username: Some("$corp_user".into()),
            password: Some("$corp_password".into()),
            domain: Some("CORP".into()), // literal, not a variable
            ..AddressBookEntry::default()
        };
        let vars = entry_credential_variables(&entry);
        assert_eq!(vars, vec!["corp_user", "corp_password"]);
    }

    #[test]
    fn test_resolve_credential_variables_success() {
        let entry = AddressBookEntry {
            username: Some("$corp_user".into()),
            password: Some("$corp_password".into()),
            domain: Some("CORP".into()),
            hostname: Some("rdp.example.com".into()),
            ..AddressBookEntry::default()
        };

        let mut creds = HashMap::new();
        creds.insert("corp_user".into(), "alice".into());
        creds.insert("corp_password".into(), "s3cret".into());

        let resolved = resolve_credential_variables(&entry, &creds).unwrap();
        assert_eq!(resolved.username.as_deref(), Some("alice"));
        assert_eq!(resolved.password.as_deref(), Some("s3cret"));
        assert_eq!(resolved.domain.as_deref(), Some("CORP")); // unchanged
        assert_eq!(resolved.hostname.as_deref(), Some("rdp.example.com")); // unchanged
    }

    #[test]
    fn test_resolve_credential_variables_missing() {
        let entry = AddressBookEntry {
            username: Some("$corp_user".into()),
            password: Some("$corp_password".into()),
            ..AddressBookEntry::default()
        };

        let creds = HashMap::new(); // empty
        let err = resolve_credential_variables(&entry, &creds).unwrap_err();
        assert_eq!(err, vec!["corp_user", "corp_password"]);
    }

    #[test]
    fn test_resolve_credential_variables_no_variables() {
        let entry = AddressBookEntry {
            username: Some("alice".into()),
            password: Some("literal_pass".into()),
            ..AddressBookEntry::default()
        };

        let creds = HashMap::new();
        let resolved = resolve_credential_variables(&entry, &creds).unwrap();
        assert_eq!(resolved.username.as_deref(), Some("alice"));
        assert_eq!(resolved.password.as_deref(), Some("literal_pass"));
    }

    #[test]
    fn test_enable_h264_serde_roundtrip() {
        // With enable_h264 set
        let json = r#"{"type":"rdp","hostname":"test","enable_gfx":true,"enable_h264":true}"#;
        let entry: AddressBookEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.enable_h264, Some(true));
        let out = serde_json::to_string(&entry).unwrap();
        assert!(out.contains("\"enable_h264\":true"));

        // Without enable_h264 (defaults to None)
        let json2 = r#"{"type":"rdp","hostname":"test","enable_gfx":true}"#;
        let entry2: AddressBookEntry = serde_json::from_str(json2).unwrap();
        assert_eq!(entry2.enable_h264, None);

        // Explicit false
        let json3 = r#"{"type":"rdp","hostname":"test","enable_h264":false}"#;
        let entry3: AddressBookEntry = serde_json::from_str(json3).unwrap();
        assert_eq!(entry3.enable_h264, Some(false));
    }

    #[test]
    fn test_h264_chroma444_round_trips_and_is_absent_by_default() {
        let json = r#"{"type":"rdp","hostname":"test","enable_h264":true}"#;
        let entry: AddressBookEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.h264_chroma444, None);
        assert!(!serde_json::to_string(&entry)
            .unwrap()
            .contains("h264_chroma444"));

        let json = r#"{"type":"rdp","hostname":"test","h264_chroma444":true}"#;
        let entry: AddressBookEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.h264_chroma444, Some(true));
        assert!(serde_json::to_string(&entry)
            .unwrap()
            .contains("\"h264_chroma444\":true"));
    }

    // ── Path-traversal regression tests (v1.5.4 fix) ──────────────────────
    // Locks down the validate_name / validate_path invariants. Any future
    // relaxation of these rules (or a bug that re-opens `../` handling) must
    // fail these tests, not land silently.

    #[test]
    fn validate_name_accepts_plain_names() {
        assert!(validate_name("acme").is_ok());
        assert!(validate_name("acme-prod").is_ok());
        assert!(validate_name("acme_prod").is_ok());
        assert!(validate_name("host.example").is_ok());
        assert!(validate_name("A1b2C3").is_ok());
    }

    #[test]
    fn validate_name_rejects_traversal() {
        assert!(validate_name("..").is_err());
        assert!(validate_name(".").is_err());
        assert!(validate_name("../etc").is_err());
        assert!(validate_name("foo/bar").is_err());
        assert!(validate_name("foo\\bar").is_err());
    }

    #[test]
    fn validate_name_rejects_reserved() {
        assert!(validate_name(".config").is_err());
    }

    #[test]
    fn validate_name_rejects_encoded_traversal() {
        // Encoded forms should fail because `%` is not in the whitelist.
        assert!(validate_name("%2e%2e").is_err());
        assert!(validate_name("%2E%2E%2F").is_err());
        assert!(validate_name("..%2F..").is_err());
    }

    #[test]
    fn validate_name_rejects_nul_and_control() {
        assert!(validate_name("foo\0bar").is_err());
        assert!(validate_name("foo\nbar").is_err());
        assert!(validate_name("foo\tbar").is_err());
    }

    #[test]
    fn validate_name_rejects_unicode() {
        // Unicode letters/digits shouldn't sneak past the ascii-alphanumeric
        // whitelist (blocks homoglyph and normalization tricks).
        assert!(validate_name("café").is_err());
        assert!(validate_name("Ⅰ").is_err()); // Roman numeral 1
        assert!(validate_name("а").is_err()); // Cyrillic 'a'
    }

    #[test]
    fn validate_name_rejects_empty_and_overlong() {
        assert!(validate_name("").is_err());
        let overlong = "a".repeat(65);
        assert!(validate_name(&overlong).is_err());
        let at_limit = "a".repeat(64);
        assert!(validate_name(&at_limit).is_ok());
    }

    #[test]
    fn validate_name_rejects_spaces_and_special() {
        assert!(validate_name("foo bar").is_err());
        assert!(validate_name("foo;rm -rf").is_err());
        assert!(validate_name("foo$bar").is_err());
        assert!(validate_name("foo@bar").is_err());
    }

    #[test]
    fn validate_path_accepts_nested() {
        assert!(validate_path("Clients/Acme/Servers").is_ok());
        assert!(validate_path("a").is_ok());
        assert!(validate_path("a/b").is_ok());
    }

    #[test]
    fn validate_path_rejects_leading_or_trailing_slash() {
        assert!(validate_path("/foo").is_err());
        assert!(validate_path("foo/").is_err());
        assert!(validate_path("/").is_err());
    }

    #[test]
    fn validate_path_rejects_empty_segments() {
        assert!(validate_path("").is_err());
        assert!(validate_path("a//b").is_err());
        assert!(validate_path("a///b").is_err());
    }

    #[test]
    fn validate_path_rejects_traversal_in_any_segment() {
        assert!(validate_path("../etc").is_err());
        assert!(validate_path("foo/../etc").is_err());
        assert!(validate_path("foo/..").is_err());
        assert!(validate_path("foo/./bar").is_err());
    }

    #[test]
    fn validate_path_rejects_overlong() {
        let overlong = "a".repeat(257);
        assert!(validate_path(&overlong).is_err());
    }
}
