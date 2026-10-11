use crate::browser::{BrowserManager, BrowserSession};
use crate::config::{Config, DriveConfig};
use crate::drive;
use crate::guacd;
use crate::guacd::GuacdStream;
use crate::tunnel;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

/// Session type: SSH terminal, web browser, RDP, VNC, VDI container, direct
/// SPICE, or Proxmox VE console (SPICE brokered via the PVE spiceproxy API).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessionType {
    #[default]
    Ssh,
    Web,
    Rdp,
    Vnc,
    Vdi,
    Spice,
    Proxmox,
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
    /// RDP server keyboard layout (guacd `server-layout`).
    pub server_layout: Option<String>,
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
    /// Enable SSH typescript recording for this session (#159). Default
    /// off; SSH only; requires `[recording].typescript_path` configured.
    pub record_typescript: Option<bool>,
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
    /// Show the remote desktop wallpaper (RDP).
    pub enable_wallpaper: Option<bool>,
    /// Enable window/control theming (RDP).
    pub enable_theming: Option<bool>,
    /// Show window contents while dragging (RDP).
    pub enable_full_window_drag: Option<bool>,
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
    /// Fixed VDI container username override (matches the baked-in account
    /// in container images that don't honour VDI_USERNAME). Auto-derived
    /// from the operator's identity when unset.
    pub container_username: Option<String>,
    /// Fixed VDI container password override matching `container_username`.
    /// Ephemerally generated when unset.
    pub container_password: Option<String>,
    /// Allow the owner to generate a Share URL for this session.
    /// Default false. For entry-derived sessions this is populated from
    /// the entry's `allow_sharing` flag; ad-hoc sessions are never
    /// shareable (per GitHub-less admin gating requirement).
    pub allow_sharing: Option<bool>,
    /// Open the client in fullscreen on connect (#154). Populated from
    /// the source entry's `fullscreen_on_connect` flag; ad-hoc sessions
    /// leave it None and the client behaves as if false.
    pub fullscreen_on_connect: Option<bool>,
    /// Auto-hide the clipboard/files side tabs when idle (they reappear
    /// when the pointer nears the left edge). Populated from the source
    /// entry; ad-hoc sessions leave it None (client behaves as if false).
    pub autohide_side_tabs: Option<bool>,
    /// SPICE: connect using TLS.
    pub spice_tls: Option<bool>,
    /// SPICE: TLS port (if the encrypted port differs from `port`).
    pub spice_tls_port: Option<u16>,
    /// SPICE: PEM CA certificate for verifying the server's TLS (e.g. a
    /// Proxmox cluster CA).
    pub spice_ca_cert: Option<String>,
    /// SPICE: expected TLS certificate subject (Proxmox "host-subject").
    pub spice_cert_subject: Option<String>,
    /// SPICE: proxy URL, e.g. a Proxmox SPICE proxy "http://host:3128".
    pub spice_proxy: Option<String>,
    /// Proxmox VE console (SessionType::Proxmox): PVE API base URL, a full URL
    /// including scheme and port (e.g. "https://pve.example.com:8006"). rustguac
    /// fetches a just-in-time SPICE ticket + config from the PVE spiceproxy API
    /// at connect.
    pub proxmox_url: Option<String>,
    /// Proxmox node name hosting the VM (e.g. "pve").
    pub proxmox_node: Option<String>,
    /// Proxmox VM id (QEMU) whose console to open.
    pub proxmox_vmid: Option<u32>,
    /// Proxmox API token id ("user@realm!tokenname") — the non-secret half.
    pub proxmox_token_id: Option<String>,
    /// Proxmox API token secret (the UUID half). Joined with the id as
    /// "id=secret" for the API. Kept separate so the id can be shown while the
    /// secret stays masked.
    pub proxmox_token_secret: Option<String>,
    /// Verify the PVE API server's TLS certificate (default false; PVE ships a
    /// self-signed cluster cert). Also controls SPICE-proxy cert verification.
    pub proxmox_verify_tls: Option<bool>,
    /// Total number of monitors to offer (SPICE/Proxmox multi-monitor). guacd
    /// is told `secondary-monitors = max_monitors - 1`, which it advertises to
    /// the client. Default 1 (single monitor).
    pub max_monitors: Option<u32>,
    /// Create the session on behalf of this user (their email). They become
    /// its creator and the only identity that may connect to it first.
    /// Admin callers only; handled by the API handler, never set internally.
    pub owner: Option<String>,
    /// Set by the API for ad-hoc sessions from non-admin callers: also fence
    /// the first jump host and Proxmox endpoints with the network
    /// allowlists. Connection entries and admins are trusted to name their
    /// own bastions and clusters. Never read from the request body.
    #[serde(skip)]
    pub fence_all_targets: bool,
    /// SSH terminal font size in points (SSH only; default 12).
    pub ssh_font_size: Option<u32>,
    /// Wake-on-LAN: send a magic packet before connecting (SSH/RDP/VNC).
    pub wol_send_packet: Option<bool>,
    /// Wake-on-LAN: target MAC address.
    pub wol_mac_addr: Option<String>,
    /// Wake-on-LAN: broadcast address.
    pub wol_broadcast_addr: Option<String>,
    /// Wake-on-LAN: UDP port.
    pub wol_udp_port: Option<u16>,
    /// Wake-on-LAN: wait time in seconds after sending the packet.
    pub wol_wait_time: Option<u32>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub share_url: Option<String>,
    /// View-only counterpart of `share_url`: a separate token, so a
    /// recipient cannot upgrade it to control by editing the URL. Present
    /// exactly when `share_url` is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub share_url_readonly: Option<String>,
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
    /// Open the client in fullscreen on connect (#154). Read by client.html
    /// from the /api/sessions/:id fetch; omitted when false/unset.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub fullscreen_on_connect: bool,
    /// Auto-hide the clipboard/files side tabs when idle. Read by
    /// client.html from the /api/sessions/:id fetch; omitted when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub autohide_side_tabs: bool,
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
    /// Second share token whose joins are read-only (guacd drops their
    /// keyboard, mouse and clipboard input).
    pub share_token_ro: String,
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
    /// Docker container name for VDI sessions.
    pub container_name: Option<String>,
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
    /// Short-lived admin-issued viewer tokens (Shadow — plan in
    /// project_shadow_sessions_plan.md). Stores only a sha256 hex of the
    /// raw token, the admin that issued it, and expiry. Validated
    /// alongside share_token in validate_share_token; expired entries
    /// are pruned when new tokens are minted.
    pub shadow_tokens: Vec<ShadowToken>,
    /// Admin-controlled: does this session allow user-initiated
    /// sharing? Copied from the source entry's `allow_sharing` at
    /// creation. When false, `SessionInfo.share_url` is `None` — the
    /// Connections card hides its Share button. Does not block admin
    /// shadow (`/shadow`), which has its own audit trail.
    pub share_allowed: bool,
    /// Copied from the source entry's `fullscreen_on_connect` flag
    /// (#154). Surfaced verbatim in `SessionInfo` so client.html can
    /// trigger fullscreen on first user gesture after CONNECTED.
    pub fullscreen_on_connect: bool,
    /// Copied from the source entry's `autohide_side_tabs` flag.
    /// Surfaced in `SessionInfo` so client.html can auto-hide the
    /// clipboard/files side tabs.
    pub autohide_side_tabs: bool,
}

/// A short-lived viewer token issued by an admin to shadow an active session.
/// The raw token is handed to the admin once; only the hash is persisted in
/// memory so the token can't be lifted from a runtime snapshot.
#[derive(Debug, Clone)]
pub struct ShadowToken {
    pub token_hash: String,
    pub issued_by: String,
    pub expires_at: DateTime<Utc>,
    /// Joins with this token are view-only.
    pub read_only: bool,
}

/// Result of validating a share-or-shadow token. Callers use this to tell
/// owner traffic from admin-minted shadow viewers, and to audit each shadow
/// use (the raw mint is audited separately; re-use is logged per connection
/// so a leaked token's blast radius is observable after the fact).
#[derive(Debug, Clone, PartialEq)]
pub enum ShareTokenValidation {
    Invalid,
    /// The session's read/write share token.
    Owner,
    /// The session's read-only share token.
    OwnerReadOnly,
    Shadow {
        issued_by: String,
        read_only: bool,
    },
}

impl ShareTokenValidation {
    pub fn is_valid(&self) -> bool {
        !matches!(self, ShareTokenValidation::Invalid)
    }

    /// Whether a join made with this token must be view-only.
    pub fn is_read_only(&self) -> bool {
        match self {
            ShareTokenValidation::OwnerReadOnly => true,
            ShareTokenValidation::Shadow { read_only, .. } => *read_only,
            ShareTokenValidation::Owner | ShareTokenValidation::Invalid => false,
        }
    }
}

fn generate_share_token() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    hex::encode(bytes)
}

/// Resolve the RDP NLA authentication package for this session.
///
/// Precedence: per-entry (or per-request) value if non-empty, else the
/// server-wide `[rdp] default_auth_pkg`, else `"ntlm"`. We default to
/// NTLM because Kerberos requires a KDC reachable via DNS (often over
/// TCP) and its failure mode is a silent hang that looks like a stuck
/// RDP connection. Admins who actually run Kerberos-integrated hosts
/// can set `default_auth_pkg = "kerberos"` or `"negotiate"` in
/// `config.toml`.
fn resolve_rdp_auth_pkg(entry_value: Option<&str>, config: &Config) -> Option<String> {
    if let Some(v) = entry_value {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Some(ref rdp) = config.rdp {
        if let Some(ref pkg) = rdp.default_auth_pkg {
            let trimmed = pkg.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    Some("ntlm".to_string())
}

#[cfg(test)]
mod auth_pkg_tests {
    use super::*;

    fn cfg(default_auth_pkg: Option<&str>) -> Config {
        Config {
            rdp: Some(crate::config::RdpConfig {
                default_auth_pkg: default_auth_pkg.map(|s| s.to_string()),
            }),
            ..Config::default()
        }
    }

    #[test]
    fn entry_value_wins_over_server_default() {
        let c = cfg(Some("ntlm"));
        assert_eq!(
            resolve_rdp_auth_pkg(Some("kerberos"), &c),
            Some("kerberos".into())
        );
    }

    #[test]
    fn empty_entry_value_falls_through_to_server_default() {
        let c = cfg(Some("kerberos"));
        assert_eq!(resolve_rdp_auth_pkg(Some(""), &c), Some("kerberos".into()));
        assert_eq!(
            resolve_rdp_auth_pkg(Some("   "), &c),
            Some("kerberos".into())
        );
    }

    #[test]
    fn no_entry_no_config_defaults_to_ntlm() {
        let c = Config::default();
        assert_eq!(resolve_rdp_auth_pkg(None, &c), Some("ntlm".into()));
    }

    #[test]
    fn empty_config_default_falls_through_to_ntlm() {
        let c = cfg(Some(""));
        assert_eq!(resolve_rdp_auth_pkg(None, &c), Some("ntlm".into()));
    }

    #[test]
    fn server_default_applies_when_entry_none() {
        let c = cfg(Some("negotiate"));
        assert_eq!(resolve_rdp_auth_pkg(None, &c), Some("negotiate".into()));
    }
}

/// Parse a host and port from a full URL ("https://host:8006") or a bare
/// authority ("host:3128" / "host"), falling back to `default_port` when the
/// input carries no explicit port. Used to tunnel Proxmox's PVE API and SPICE
/// proxy endpoints through a jump-host chain.
fn parse_host_port(input: &str, default_port: u16) -> Result<(String, u16), SessionError> {
    let parsed = if input.contains("://") {
        Url::parse(input)
    } else {
        Url::parse(&format!("tcp://{input}"))
    }
    .map_err(|e| SessionError::ValidationError(format!("invalid host/URL '{input}': {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| SessionError::ValidationError(format!("no host in '{input}'")))?
        .to_string();
    let port = parsed.port().unwrap_or(default_port);
    Ok((host, port))
}

/// Validate the network for the connection rustguac itself will make.
///
/// Without jump hosts that is the target host, so the target is checked against
/// the protocol's allowlist. With a jump-host chain, rustguac only ever dials
/// hop 0 -- the target's name is resolved by the last hop and need not resolve
/// here at all, so resolving it locally would reject perfectly valid
/// bastion-only names, and an address it did resolve to would say nothing
/// about where the bastion connects. Hop 0 is fenced, for untrusted callers,
/// where the chain is built (`fence_all_targets`); what lies beyond it is the
/// bastion's to permit.
async fn check_session_network(
    target_host: &str,
    target_port: u16,
    allowed: &[String],
    jump_hops: &[tunnel::JumpHost],
) -> Result<(), SessionError> {
    if jump_hops.is_empty() {
        return check_allowed_network(target_host, target_port, allowed).await;
    }
    tracing::debug!(
        target = %target_host,
        "Jump chain configured -- target resolved by the bastion, not checked here"
    );
    Ok(())
}

/// Check that a host resolves to an IP within the allowed CIDR networks.
///
/// Passes if ANY resolved address is allowed. Callers that can connect by
/// address should use [`allowed_address`] and dial the address it returns,
/// since a hostname re-resolved later (by guacd, say) can give a different
/// answer than it gave here.
async fn check_allowed_network(
    host: &str,
    port: u16,
    allowed: &[String],
) -> Result<(), SessionError> {
    allowed_address(host, port, allowed).await.map(|_| ())
}

/// Longest a target hostname lookup may take before the connect fails.
const DNS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Resolve `host:port` without tying up the async runtime.
///
/// The system resolver blocks, and with a DNS server that does not answer it
/// blocks for its whole retry budget (tens of seconds). Called directly from
/// a request handler, a few of those occupied every tokio worker thread, and
/// rustguac stopped answering anything, health checks included, until they
/// gave up. `lookup_host` runs the resolver on the blocking thread pool, and
/// the timeout fails this one connect promptly instead of holding it open.
async fn resolve_host(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>, SessionError> {
    match tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host, port))).await {
        Ok(Ok(addrs)) => Ok(addrs.collect()),
        Ok(Err(e)) => Err(SessionError::ValidationError(format!(
            "failed to resolve host '{}': {}",
            host, e
        ))),
        Err(_) => Err(SessionError::ValidationError(format!(
            "failed to resolve host '{}': DNS did not answer within {} seconds",
            host,
            DNS_TIMEOUT.as_secs()
        ))),
    }
}

/// Resolve `host` and return the first address inside the allowlist.
///
/// Dialling this address, rather than handing the hostname on, pins the
/// connection to what was actually checked. Otherwise a hostname whose DNS
/// the caller controls could resolve to an allowed address for the check and
/// to an internal one (guacd, Vault, a metadata service) for the connection.
/// Addresses outside the allowlist are ignored rather than rejected, so a
/// dual-stack host whose IPv6 address is not listed still works over IPv4.
pub(crate) async fn allowed_address(
    host: &str,
    port: u16,
    allowed: &[String],
) -> Result<std::net::IpAddr, SessionError> {
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
            return Ok(ip);
        }
        return Err(SessionError::ValidationError(format!(
            "host {} is not in the allowed network list",
            host
        )));
    }

    // Resolve hostname to IP addresses
    let addrs = resolve_host(host, port).await?;

    if addrs.is_empty() {
        return Err(SessionError::ValidationError(format!(
            "host '{}' did not resolve to any addresses",
            host
        )));
    }

    addrs
        .iter()
        .map(|a| a.ip())
        .find(|ip| networks.iter().any(|net| net.contains(*ip)))
        .ok_or_else(|| {
            SessionError::ValidationError(format!(
                "host '{}' resolves to addresses not in the allowed network list",
                host
            ))
        })
}

/// Longest Wake-on-LAN wait rustguac will ask guacd for, in seconds.
const MAX_WOL_WAIT_SECS: u32 = 600;
/// Bounds for the SSH terminal font size, in points.
const MIN_SSH_FONT: u32 = 6;
const MAX_SSH_FONT: u32 = 72;

/// Wake-on-LAN settings for guacd.
///
/// guacd sends the magic packet to whatever broadcast address and UDP port
/// it is given, then waits the given time before connecting, so for an
/// ad-hoc request from a non-admin these come from the caller. They are
/// dropped there: Wake-on-LAN is configured on connection entries. The
/// wait is capped either way so one session cannot hold a guacd process for
/// days.
fn wol_params(req: &CreateSessionRequest, fence_all_targets: bool) -> guacd::WolParams {
    if fence_all_targets {
        return guacd::WolParams::default();
    }
    guacd::WolParams {
        send_packet: req.wol_send_packet.unwrap_or(false),
        mac_addr: req.wol_mac_addr.clone(),
        broadcast_addr: req.wol_broadcast_addr.clone(),
        udp_port: req.wol_udp_port,
        wait_time: req.wol_wait_time.map(|t| t.min(MAX_WOL_WAIT_SECS)),
    }
}

/// An address formatted for a `host:port` string (IPv6 in brackets), as
/// the SSH tunnel and probe code builds its dial address that way.
pub(crate) fn dial_host(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

impl Session {
    pub fn info(&self) -> SessionInfo {
        SessionInfo {
            session_id: self.id,
            session_type: self.session_type.clone(),
            status: self.status.clone(),
            created_at: self.created_at,
            client_url: format!("/client/{}", self.id),
            share_url: if self.share_allowed {
                Some(format!("/client/{}?token={}", self.id, self.share_token))
            } else {
                None
            },
            share_url_readonly: if self.share_allowed {
                Some(format!("/client/{}?token={}", self.id, self.share_token_ro))
            } else {
                None
            },
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
            fullscreen_on_connect: self.fullscreen_on_connect,
            autohide_side_tabs: self.autohide_side_tabs,
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
                let mut driver = driver
                    .with_ready_timeout(vdi_cfg.ready_timeout_secs)
                    .with_container_hook(
                        vdi_cfg.container_hook_script.clone(),
                        vdi_cfg.container_hook_timeout_secs,
                    );
                match (vdi_cfg.port_range_start, vdi_cfg.port_range_end) {
                    (Some(start), Some(end)) => {
                        driver = match driver.with_host_port_range(start, end) {
                            Ok(driver) => driver,
                            Err(e) => {
                                tracing::error!("Failed to initialize VDI Docker driver: {}", e);
                                return None;
                            }
                        };
                    }
                    (None, None) => {}
                    _ => {
                        tracing::error!(
                            "Failed to initialize VDI Docker driver: port_range_start and port_range_end must be set together"
                        );
                        return None;
                    }
                }
                tracing::info!(
                    socket = %vdi_cfg.docker_socket,
                    idle_timeout_mins = vdi_cfg.idle_timeout_mins,
                    port_range_start = ?vdi_cfg.port_range_start,
                    port_range_end = ?vdi_cfg.port_range_end,
                    container_hook_script = ?vdi_cfg.container_hook_script,
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
        // Enforce session limits (only count active/pending sessions)
        {
            let sessions = self.sessions.read().await;
            let max_global = self.config.max_sessions;
            let max_per_user = self.config.max_sessions_per_user;

            if max_global > 0 {
                let active_count = sessions.values().count(); // includes all states still in HashMap
                if active_count >= max_global {
                    return Err(SessionError::ValidationError(format!(
                        "maximum concurrent sessions reached ({})",
                        max_global
                    )));
                }
            }

            if max_per_user > 0 {
                let mut user_count = 0usize;
                for session in sessions.values() {
                    let s = session.lock().await;
                    if s.created_by == created_by
                        && matches!(s.status, SessionStatus::Pending | SessionStatus::Active)
                    {
                        user_count += 1;
                    }
                }
                if user_count >= max_per_user {
                    return Err(SessionError::ValidationError(format!(
                        "maximum sessions per user reached ({})",
                        max_per_user
                    )));
                }
            }
        }

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

        // Resolve jump hosts (SSH tunnel chain) up-front: the Proxmox branch
        // needs them to tunnel its PVE API + SPICE-proxy connections in-branch,
        // and the generic tunnel setup after the match uses them for the other
        // session types.
        let fence_all_targets = req.fence_all_targets;
        // Wake-on-LAN params, applied to SSH/RDP/VNC alike (passed through to guacd).
        let wol = wol_params(&req, fence_all_targets);
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
                    host_key: None,
                }]
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        // rustguac dials the first jump host itself, so for an untrusted
        // caller it is fenced by the SSH allowlist like any SSH target, and
        // pinned to the checked address. Later hops are dialled from inside
        // the chain and resolve from the bastion's point of view.
        let mut jump_hops = jump_hops;
        if let Some(first) = jump_hops.first_mut().filter(|_| fence_all_targets) {
            let ip = allowed_address(
                &first.hostname,
                first.port,
                &self.config.ssh_allowed_networks,
            )
            .await
            .map_err(|e| SessionError::ValidationError(format!("jump host: {e}")))?;
            first.hostname = dial_host(ip);
        }
        // Tunnels the Proxmox branch establishes in-branch (PVE API + SPICE
        // proxy hops); merged into the session's tunnel list after the match.
        let mut proxmox_tunnels: Vec<tunnel::SshTunnel> = Vec::new();

        let (
            mut conn_params,
            hostname,
            username,
            url,
            mut browser_session,
            banner_override,
            session_drive_path,
            container_id,
            container_name,
        ) = match req.session_type {
            SessionType::Ssh => {
                let hostname = req.hostname.ok_or_else(|| {
                    SessionError::ValidationError("hostname is required for SSH sessions".into())
                })?;
                let port = req.port.unwrap_or(22);
                let username = req.username.clone().unwrap_or_default();

                // With jump hosts the bastion resolves the target, so keep the
                // name, unchecked: resolving it here would refuse a name only
                // the bastion can see. Otherwise guacd dials the address
                // checked here.
                let connect_host = if jump_hops.is_empty() {
                    allowed_address(&hostname, port, &self.config.ssh_allowed_networks)
                        .await?
                        .to_string()
                } else {
                    hostname.clone()
                };

                tracing::info!(
                    session_id = %session_id,
                    hostname = %hostname,
                    username = %username,
                    width,
                    height,
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

                // SSH typescript recording (#159): per-connection opt-in
                // (default off), and only when a global typescript_path is
                // configured. rustguac expands the name template (guacd
                // uses it verbatim) so audit files are identifiable per
                // user + connection.
                let typescript = self
                    .config
                    .ssh_typescript()
                    .filter(|_| req.record_typescript == Some(true))
                    .map(|(path, name, create)| {
                        let template = name.as_deref().unwrap_or(DEFAULT_TYPESCRIPT_NAME);
                        let connection = req
                            .entry_display_name
                            .as_deref()
                            .filter(|s| !s.is_empty())
                            .unwrap_or(&hostname);
                        let expanded = expand_typescript_name(
                            template,
                            &username,
                            &hostname,
                            connection,
                            &session_id,
                            Utc::now(),
                        );
                        (path, expanded, create)
                    });
                let params = guacd::ConnectionParams::Ssh(guacd::SshParams {
                    hostname: connect_host,
                    port,
                    username: username.clone(),
                    password: req.password.clone(),
                    private_key,
                    width,
                    height,
                    // SSH terminal text size is driven by font_size, not device
                    // DPI. The client sends a devicePixelRatio-scaled DPI (correct
                    // for RDP/VNC) which would render the terminal font oversized
                    // on HiDPI displays, so pin SSH to a 96 baseline — the client
                    // auto-scales the canvas to fit regardless.
                    dpi: 96,
                    enable_sftp: drive_enabled,
                    sftp_disable_download: !drive_cfg.allow_download,
                    sftp_disable_upload: !drive_cfg.allow_upload,
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                    typescript_path: typescript.as_ref().map(|(p, _, _)| p.clone()),
                    typescript_name: typescript.as_ref().map(|(_, n, _)| n.clone()),
                    create_typescript_path: typescript
                        .as_ref()
                        .map(|(_, _, c)| *c)
                        .unwrap_or(false),
                    font_size: req
                        .ssh_font_size
                        .map(|s| s.clamp(MIN_SSH_FONT, MAX_SSH_FONT)),
                    wol: wol.clone(),
                });
                (
                    params, hostname, username, None, None, ssh_banner, None, None, None,
                )
            }
            SessionType::Rdp => {
                let hostname = req.hostname.ok_or_else(|| {
                    SessionError::ValidationError("hostname is required for RDP sessions".into())
                })?;
                let port = req.port.unwrap_or(3389);
                let username = req.username.clone().unwrap_or_default();

                check_session_network(
                    &hostname,
                    port,
                    &self.config.rdp_allowed_networks,
                    &jump_hops,
                )
                .await?;

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
                    server_layout: req.server_layout.clone(),
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
                    auth_pkg: resolve_rdp_auth_pkg(req.auth_pkg.as_deref(), &self.config),
                    kdc_url: req.kdc_url.clone(),
                    kerberos_cache: req.kerberos_cache.clone(),
                    remote_app: req.remote_app.clone(),
                    remote_app_dir: req.remote_app_dir.clone(),
                    remote_app_args: req.remote_app_args.clone(),
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                    enable_gfx: req.enable_gfx.unwrap_or(false),
                    enable_desktop_composition: req.enable_desktop_composition.unwrap_or(false),
                    enable_wallpaper: req.enable_wallpaper.unwrap_or(false),
                    enable_theming: req.enable_theming.unwrap_or(false),
                    enable_full_window_drag: req.enable_full_window_drag.unwrap_or(false),
                    force_lossless: req.force_lossless.unwrap_or(false),
                    enable_h264: req.enable_h264.unwrap_or(false),
                    secondary_monitors: req.max_monitors.unwrap_or(1).saturating_sub(1),
                    wol: wol.clone(),
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
                    None,
                )
            }
            SessionType::Vnc => {
                let hostname = req.hostname.ok_or_else(|| {
                    SessionError::ValidationError("hostname is required for VNC sessions".into())
                })?;
                let port = req.port.unwrap_or(5900);
                let username = req.username.clone().unwrap_or_default();

                // With jump hosts the bastion resolves the target, so keep the
                // name, unchecked: resolving it here would refuse a name only
                // the bastion can see. Otherwise guacd dials the address
                // checked here.
                let connect_host = if jump_hops.is_empty() {
                    allowed_address(&hostname, port, &self.config.vnc_allowed_networks)
                        .await?
                        .to_string()
                } else {
                    hostname.clone()
                };

                tracing::info!(
                    session_id = %session_id,
                    hostname = %hostname,
                    width, height, dpi,
                    "Creating new VNC session"
                );

                let params = guacd::ConnectionParams::Vnc(guacd::VncParams {
                    hostname: connect_host,
                    port,
                    username: req.username.clone().filter(|u| !u.is_empty()),
                    password: req.password.clone(),
                    color_depth: req.color_depth,
                    width,
                    height,
                    dpi,
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                    wol: wol.clone(),
                });
                (
                    params, hostname, username, None, None, None, None, None, None,
                )
            }
            SessionType::Spice => {
                let username = req.username.clone().unwrap_or_default();

                // Direct SPICE connection to a SPICE server (e.g. libvirt/QEMU).
                let hostname = req.hostname.clone().ok_or_else(|| {
                    SessionError::ValidationError("hostname is required for SPICE sessions".into())
                })?;
                let port = req.port.unwrap_or(5900);
                check_session_network(
                    &hostname,
                    port,
                    &self.config.vnc_allowed_networks,
                    &jump_hops,
                )
                .await?;

                let spice = guacd::SpiceParams {
                    hostname: hostname.clone(),
                    port,
                    password: req.password.clone(),
                    username: req.username.clone(),
                    tls: req.spice_tls.unwrap_or(false),
                    tls_port: req.spice_tls_port,
                    ca_cert: req.spice_ca_cert.clone(),
                    cert_subject: req.spice_cert_subject.clone(),
                    ignore_cert: req.ignore_cert.unwrap_or(false),
                    proxy: req.spice_proxy.clone(),
                    color_depth: req.color_depth,
                    width,
                    height,
                    dpi,
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                    enable_audio: false,
                    // Secondary monitors = total requested minus the primary.
                    secondary_monitors: req.max_monitors.unwrap_or(1).saturating_sub(1),
                };
                tracing::info!(
                    session_id = %session_id,
                    hostname = %hostname,
                    width, height, dpi,
                    "Creating new SPICE session"
                );

                let params = guacd::ConnectionParams::Spice(Box::new(spice));
                (
                    params, hostname, username, None, None, None, None, None, None,
                )
            }
            SessionType::Proxmox => {
                let username = req.username.clone().unwrap_or_default();

                // Proxmox VE console: SPICE brokered through the PVE spiceproxy
                // API. Tickets are one-time and short-lived, so fetch a
                // just-in-time SPICE config at connect rather than storing it.
                let pve_url = req.proxmox_url.clone().ok_or_else(|| {
                    SessionError::ValidationError("Proxmox sessions require proxmox_url".into())
                })?;
                let vmid = req.proxmox_vmid.unwrap_or(0);
                if vmid == 0 {
                    return Err(SessionError::ValidationError(
                        "Proxmox sessions require proxmox_vmid".into(),
                    ));
                }
                let verify_tls = req.proxmox_verify_tls.unwrap_or(false);

                // rustguac calls the PVE API itself and guacd then dials the
                // SPICE proxy that API names, so for an untrusted caller both
                // are fenced by the same allowlist as direct SPICE. Through
                // jump hosts they resolve at the bastion and the first hop is
                // checked instead.
                if fence_all_targets && jump_hops.is_empty() {
                    let (api_host, api_port) = parse_host_port(&pve_url, 8006)?;
                    check_allowed_network(&api_host, api_port, &self.config.vnc_allowed_networks)
                        .await
                        .map_err(|e| SessionError::ValidationError(format!("Proxmox API: {e}")))?;
                }

                // Join the token id and secret into PVE's "id=secret" form. If
                // the secret is empty, treat the id as already-joined (lenient:
                // allows pasting a full "id=secret" into the id field).
                let token_id = req.proxmox_token_id.clone().unwrap_or_default();
                let secret = req.proxmox_token_secret.clone().unwrap_or_default();
                let api_token = if secret.is_empty() {
                    token_id
                } else {
                    format!("{token_id}={secret}")
                };

                // If jump hosts are configured, tunnel the PVE API endpoint so
                // the broker call reaches it through the bastion. The tunnelled
                // endpoint is 127.0.0.1, which no PVE cert matches, so cert
                // verification is disabled for this hop (the SSH tunnel secures
                // the transport). The SPICE server cert is still verified below.
                let (broker_base, broker_verify) = if !jump_hops.is_empty() {
                    let (api_host, api_port) = parse_host_port(&pve_url, 8006)?;
                    let (mut tuns, api_local) =
                        tunnel::start_chain(&jump_hops, &api_host, api_port)
                            .await
                            .map_err(|e| {
                                SessionError::ValidationError(format!(
                                    "Proxmox API tunnel failed: {e}"
                                ))
                            })?;
                    proxmox_tunnels.append(&mut tuns);
                    tracing::info!(
                        session_id = %session_id,
                        api_local = %api_local,
                        hops = jump_hops.len(),
                        "Tunnelled Proxmox PVE API through jump host(s)"
                    );
                    (format!("https://{api_local}"), false)
                } else {
                    (pve_url, verify_tls)
                };

                let broker = crate::pve::PveBroker {
                    base_url: broker_base,
                    api_token,
                    verify_tls: broker_verify,
                };

                // The node is optional: if not given, resolve which node hosts
                // the VM via /cluster/resources (as the PVE web UI does), so the
                // node-scoped console API can be reached with only the VM id.
                let node = match req.proxmox_node.clone().filter(|n| !n.trim().is_empty()) {
                    Some(n) => n,
                    None => broker.resolve_node(vmid).await.map_err(|e| {
                        SessionError::ValidationError(format!("Proxmox node lookup failed: {e}"))
                    })?,
                };

                let mut cfg = broker
                    .fetch_spice_config(&node, vmid, None)
                    .await
                    .map_err(|e| {
                        SessionError::ValidationError(format!("Proxmox SPICE broker failed: {e}"))
                    })?;
                if fence_all_targets && jump_hops.is_empty() {
                    let (proxy_host, proxy_port) = parse_host_port(&cfg.proxy, 3128)?;
                    check_allowed_network(
                        &proxy_host,
                        proxy_port,
                        &self.config.vnc_allowed_networks,
                    )
                    .await
                    .map_err(|e| {
                        SessionError::ValidationError(format!("Proxmox SPICE proxy: {e}"))
                    })?;
                }
                tracing::info!(
                    session_id = %session_id,
                    node = %node,
                    vmid,
                    proxy = %cfg.proxy,
                    "Creating Proxmox VE SPICE console session"
                );

                // Tunnel the SPICE proxy too, and point guacd at the local
                // forward. The proxy hop is plain HTTP; the SPICE-over-TLS link
                // is tunnelled transparently inside the proxy CONNECT, so the
                // SPICE server cert still verifies.
                if !jump_hops.is_empty() {
                    let (proxy_host, proxy_port) = parse_host_port(&cfg.proxy, 3128)?;
                    let (mut tuns, proxy_local) =
                        tunnel::start_chain(&jump_hops, &proxy_host, proxy_port)
                            .await
                            .map_err(|e| {
                                SessionError::ValidationError(format!(
                                    "Proxmox SPICE proxy tunnel failed: {e}"
                                ))
                            })?;
                    proxmox_tunnels.append(&mut tuns);
                    tracing::info!(
                        session_id = %session_id,
                        proxy_local = %proxy_local,
                        "Tunnelled Proxmox SPICE proxy through jump host(s)"
                    );
                    cfg.proxy = format!("http://{proxy_local}");
                }

                // Proxmox SPICE is TLS-only: no plaintext port (guacd sends an
                // empty "port" arg whenever tls is set). The one-time ticket is
                // the SPICE password. PVE ships a self-signed cluster cert; when
                // verification is requested, verify against the returned cluster
                // CA + host subject, otherwise skip verification entirely.
                let spice = guacd::SpiceParams {
                    hostname: cfg.host.clone(),
                    port: 0,
                    password: Some(cfg.ticket),
                    username: req.username.clone(),
                    tls: true,
                    tls_port: Some(cfg.tls_port),
                    ca_cert: if verify_tls { Some(cfg.ca_cert) } else { None },
                    cert_subject: if verify_tls {
                        Some(cfg.host_subject)
                    } else {
                        None
                    },
                    ignore_cert: !verify_tls,
                    proxy: Some(cfg.proxy),
                    color_depth: req.color_depth,
                    width,
                    height,
                    dpi,
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                    enable_audio: false,
                    // Secondary monitors = total requested minus the primary.
                    secondary_monitors: req.max_monitors.unwrap_or(1).saturating_sub(1),
                };

                // `cfg.host` is an opaque PVE routing token, used as the display
                // hostname for the session.
                let hostname = cfg.host;
                let params = guacd::ConnectionParams::Spice(Box::new(spice));
                (
                    params, hostname, username, None, None, None, None, None, None,
                )
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

                check_session_network(
                    url_host,
                    url_port,
                    &self.config.web_allowed_networks,
                    &jump_hops,
                )
                .await?;

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
                    username: None,
                    password: None,
                    color_depth: None,
                    width,
                    height,
                    dpi,
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                    // Local Xvnc — WoL not applicable.
                    wol: guacd::WolParams::default(),
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
                    None,
                )
            }
            SessionType::Vdi => {
                let vdi_cfg = self
                    .config
                    .vdi
                    .as_ref()
                    .filter(|v| v.enabled)
                    .ok_or_else(|| SessionError::VdiError("VDI feature is not enabled".into()))?;

                let vdi = self
                    .vdi_driver
                    .as_ref()
                    .ok_or_else(|| SessionError::VdiError("VDI driver not initialized".into()))?;

                let image = req.container_image.clone().ok_or_else(|| {
                    SessionError::ValidationError(
                        "container_image is required for VDI sessions".into(),
                    )
                })?;

                // Check allowed images whitelist
                if !vdi_cfg.allowed_images.is_empty() && !vdi_cfg.allowed_images.contains(&image) {
                    return Err(SessionError::VdiError(format!(
                        "image '{}' is not in the allowed list",
                        image
                    )));
                }

                // Username: per-entry override if set (for images with baked-in
                // accounts that don't honour VDI_USERNAME), otherwise derive
                // from the operator's identity. The derived form is also used
                // as the deterministic container-name suffix, so containers
                // are scoped per-operator. When the override is set the same
                // container is shared by everyone connecting with that entry,
                // which is the desired behaviour for shared baked-in accounts.
                let vdi_username = req
                    .container_username
                    .as_ref()
                    .filter(|s| !s.is_empty())
                    .cloned()
                    .unwrap_or_else(|| {
                        created_by
                            .split('@')
                            .next()
                            .unwrap_or(&created_by)
                            .to_lowercase()
                            .chars()
                            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                            .collect::<String>()
                    });
                let vdi_password = req
                    .container_password
                    .as_ref()
                    .filter(|s| !s.is_empty())
                    .cloned()
                    .unwrap_or_else(generate_share_token); // 32 hex chars

                // Merge env vars. We still set VDI_USERNAME/VDI_PASSWORD even
                // when the override is in use - that way images which DO read
                // the env vars get the right values, and images which ignore
                // them aren't affected. User-provided env never overrides the
                // core VDI vars.
                let mut env = req.container_env.unwrap_or_default();
                env.insert("VDI_USERNAME".into(), vdi_username.clone());
                env.insert("VDI_PASSWORD".into(), vdi_password.clone());

                // Resolve resource limits: entry overrides > config defaults
                let cpu_limit = req.container_cpu_limit.unwrap_or(vdi_cfg.default_cpu_limit);
                let memory_limit_mb = req
                    .container_memory_limit
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

                tracing::info!(
                    session_id = %session_id,
                    image = %image,
                    username = %vdi_username,
                    "Creating VDI session"
                );

                let info = vdi
                    .start_or_reuse(&spec)
                    .await
                    .map_err(|e| SessionError::VdiError(e.to_string()))?;

                // Clear stale VDI thumbnail now that the driver has resolved
                // the deterministic container name.
                let stale_thumb = self.vdi_thumbnail_path(&info.container_name);
                let _ = std::fs::remove_file(&stale_thumb);

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
                    server_layout: None,
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
                    enable_wallpaper: false,
                    enable_theming: false,
                    enable_full_window_drag: false,
                    force_lossless: false,
                    enable_h264: true,
                    secondary_monitors: req.max_monitors.unwrap_or(1).saturating_sub(1),
                    // VDI container on the Docker host — WoL not applicable.
                    wol: guacd::WolParams::default(),
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
                    Some(info.container_name),
                )
            }
        };

        // Set up SSH tunnel chain if jump hosts are configured.
        // For SSH/RDP/VNC: overrides hostname/port in conn_params so guacd
        // connects to the local tunnel listener instead of the real target.
        // For Web: tunnels to the URL's host:port and rewrites the browser URL.
        // Proxmox is excluded: it tunnels its own PVE API + SPICE-proxy hops
        // in-branch (the routing token / proxy field don't fit this rewrite).
        let is_web = url.is_some() && browser_session.is_none();
        let is_proxmox = matches!(req.session_type, SessionType::Proxmox);
        let ssh_tunnels = if !jump_hops.is_empty() && !is_proxmox {
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
                    // TLS SPICE connects on tls_port, so tunnel that port.
                    guacd::ConnectionParams::Spice(p) => {
                        if p.tls {
                            (p.hostname.clone(), p.tls_port.unwrap_or(p.port))
                        } else {
                            (p.hostname.clone(), p.port)
                        }
                    }
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
                        // guacd now dials loopback, so FreeRDP validates the
                        // server's TLS cert against "127.0.0.1" and derives any
                        // NLA SPN from it (TERMSRV/127.0.0.1). Neither matches
                        // the real host, and RDP exposes no cert-name or SPN
                        // override, so warn rather than fail obscurely later.
                        if !p.ignore_cert {
                            tracing::warn!(
                                real_host = %p.hostname,
                                tunnel_addr = %final_addr,
                                "Tunnelled RDP with certificate checking on — FreeRDP will \
                                 validate against the tunnel's loopback address, not the real \
                                 host, and may reject it. Enable \"ignore certificate\" on this \
                                 entry if the connection fails on a certificate name mismatch."
                            );
                        }
                        if p.auth_pkg.as_deref() == Some("kerberos") {
                            tracing::warn!(
                                real_host = %p.hostname,
                                "Tunnelled RDP with auth-pkg=kerberos — the SPN is built from \
                                 the tunnel's loopback address, so Kerberos will not find a \
                                 matching principal. Use negotiate or ntlm through a jump host."
                            );
                        }
                        p.hostname = final_addr.ip().to_string();
                        p.port = final_addr.port();
                    }
                    guacd::ConnectionParams::Vnc(p) => {
                        p.hostname = final_addr.ip().to_string();
                        p.port = final_addr.port();
                    }
                    guacd::ConnectionParams::Spice(p) => {
                        p.hostname = final_addr.ip().to_string();
                        // Rewrite the port guacd actually dials. Cert-subject
                        // verification still holds (the server presents the same
                        // cert regardless of the tunnel).
                        if p.tls {
                            p.tls_port = Some(final_addr.port());
                        } else {
                            p.port = final_addr.port();
                        }
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

        let mut ssh_tunnels = ssh_tunnels.map(|(t, _)| t).unwrap_or_default();
        // Fold in any tunnels the Proxmox branch established in-branch.
        ssh_tunnels.append(&mut proxmox_tunnels);

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

        // Gate:
        //  - If the request explicitly sets allow_sharing, honour it.
        //  - Otherwise: entry-derived sessions default off (admin opt-in
        //    per entry via allow_sharing), ad-hoc sessions default on
        //    (preserves the long-standing API-key session-creation
        //    behaviour where share_url is expected in the response).
        let share_allowed = req
            .allow_sharing
            .unwrap_or(req.address_book_entry.is_none());

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
            share_token_ro: generate_share_token(),
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
            container_name,
            recording_enabled,
            address_book_entry: req.address_book_entry,
            address_book_folder: req.address_book_folder,
            entry_display_name: req.entry_display_name,
            max_recordings: req.max_recordings,
            login_script_handle,
            shadow_tokens: Vec::new(),
            share_allowed,
            fullscreen_on_connect: req.fullscreen_on_connect.unwrap_or(false),
            autohide_side_tabs: req.autohide_side_tabs.unwrap_or(false),
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
        let (cleanup_on_close, retention_secs) = drive_cleanup_settings(&self.config.drive);
        tokio::spawn(async move {
            time::sleep(time::Duration::from_secs(timeout_secs)).await;
            let sessions_read = sessions_ref.read().await;
            if let Some(session) = sessions_read.get(&session_id) {
                let mut session = session.lock().await;
                if session.status == SessionStatus::Pending {
                    tracing::warn!(session_id = %session_id, "Session expired (no browser connected)");
                    session.status = SessionStatus::Expired;
                    session.guacd_stream = None;
                    cleanup_browser(&browser_mgr, &mut session, cleanup_on_close, retention_secs)
                        .await;
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
    /// A `read_only` join sees the session but guacd ignores its input.
    pub async fn join_session(
        &self,
        id: Uuid,
        read_only: bool,
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
            read_only,
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

        tracing::info!(session_id = %id, read_only, "Viewer joined session");
        Ok((stream, cancel))
    }

    /// Validate a share-or-shadow token for a session (constant-time
    /// comparison). Returns which kind of token matched so callers can
    /// audit shadow uses; returns `Invalid` if neither matches or the
    /// session is unknown.
    pub async fn validate_share_token(&self, id: Uuid, token: &str) -> ShareTokenValidation {
        let sessions = self.sessions.read().await;
        let Some(session) = sessions.get(&id) else {
            return ShareTokenValidation::Invalid;
        };
        let session = session.lock().await;
        check_share_token_match(
            &session.share_token,
            &session.share_token_ro,
            &session.shadow_tokens,
            token,
            Utc::now(),
        )
    }

    /// Mint a new short-lived (10 min) shadow token for a session.
    /// Returns the raw token (hand to admin once) and its expiry.
    /// Expired tokens on the session are pruned on mint.
    ///
    /// Refuses a session whose owner has not connected yet. The WebSocket
    /// handler hands a pending session's stream to whoever connects first,
    /// before any token is looked at, so a shadow link to a pending session
    /// would make the admin its owner and lock the real owner out.
    pub async fn mint_shadow_token(
        &self,
        id: Uuid,
        issued_by: &str,
        read_only: bool,
    ) -> Result<(String, DateTime<Utc>), SessionError> {
        use sha2::{Digest, Sha256};
        let sessions = self.sessions.read().await;
        let session = sessions.get(&id).ok_or(SessionError::NotFound)?;
        let mut session = session.lock().await;
        if session.status != SessionStatus::Active {
            return Err(SessionError::NotActive);
        }

        let now = Utc::now();
        session.shadow_tokens.retain(|t| t.expires_at > now);

        let mut rng = rand::rng();
        let bytes: [u8; 16] = rng.random();
        let raw = hex::encode(bytes);
        let hash = hex::encode(Sha256::digest(raw.as_bytes()));
        let expires_at = now + chrono::Duration::minutes(10);
        session.shadow_tokens.push(ShadowToken {
            token_hash: hash,
            issued_by: issued_by.to_string(),
            expires_at,
            read_only,
        });
        Ok((raw, expires_at))
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
                let (c, r) = drive_cleanup_settings(&self.config.drive);
                cleanup_browser(&self.browser_manager, &mut session, c, r).await;
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
            let (c, r) = drive_cleanup_settings(&self.config.drive);
            cleanup_browser(&self.browser_manager, &mut session, c, r).await;
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

    /// Get session type and container metadata for a session (used for VDI cleanup).
    pub async fn get_vdi_info(
        &self,
        id: Uuid,
    ) -> Option<(SessionType, Option<String>, Option<String>)> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(&id)?;
        let session = session.lock().await;
        Some((
            session.session_type.clone(),
            session.container_id.clone(),
            session.container_name.clone(),
        ))
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
            let (c, r) = drive_cleanup_settings(&self.config.drive);
            cleanup_browser(&self.browser_manager, &mut session, c, r).await;
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

    /// Remove sessions in terminal states (Completed, Error, Expired) that have
    /// been in that state longer than the configured cleanup delay. The session
    /// history in SQLite is not affected — this only frees in-memory state.
    pub async fn reap_completed_sessions(&self) -> usize {
        let delay = std::time::Duration::from_secs(self.config.session_cleanup_delay_secs);
        let now = Utc::now();
        let mut to_remove = Vec::new();

        {
            let sessions = self.sessions.read().await;
            for (id, session) in sessions.iter() {
                let session = session.lock().await;
                match session.status {
                    SessionStatus::Completed | SessionStatus::Error | SessionStatus::Expired => {
                        let age = now.signed_duration_since(session.created_at);
                        if age.to_std().unwrap_or_default() > delay {
                            to_remove.push(*id);
                        }
                    }
                    _ => {}
                }
            }
        }

        if !to_remove.is_empty() {
            let mut sessions = self.sessions.write().await;
            for id in &to_remove {
                sessions.remove(id);
            }
        }

        to_remove.len()
    }

    pub fn recording_path(&self) -> &std::path::Path {
        self.config.effective_recording_path()
    }

    /// Recording paths of sessions that are still live. Their `.guac` files may
    /// be open for writing by the recording tee, so rotation must never delete
    /// them (unlinking an open recording loses the in-progress capture and
    /// frees no disk space). Names follow the tee's `<recording_dir>/<id>.guac`
    /// convention (see `websocket.rs`).
    pub async fn active_recording_paths(&self) -> std::collections::HashSet<std::path::PathBuf> {
        let dir = self.recording_path();
        let sessions = self.sessions.read().await;
        sessions
            .keys()
            .map(|id| dir.join(format!("{}.guac", id)))
            .collect()
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
        self.thumbnails_dir()
            .join(format!("vdi-{}.jpg", container_name))
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

/// Default typescript filename template when `[recording].typescript_name`
/// is unset. Produces audit-friendly per-session names (#159).
const DEFAULT_TYPESCRIPT_NAME: &str = "{connection}-{user}-{date}-{time}";

/// Expand rustguac's brace tokens in a typescript filename template (#159).
///
/// guacd uses the typescript name verbatim (it appends a numeric suffix
/// only to avoid clobbering an existing file), so rustguac does this
/// substitution itself to produce audit-friendly, per-session filenames
/// like `coreswitch01-alice-20260610-143022`. Every substituted value is
/// sanitised to `[A-Za-z0-9_-]`, so the result is always a safe basename:
/// no path separators, no traversal, no surprises from OIDC usernames or
/// free-text entry names.
///
/// Tokens: `{user}`, `{connection}`, `{host}`, `{date}` (UTC YYYYMMDD),
/// `{time}` (UTC HHMMSS), `{session}` (first 8 chars of the session id).
/// Unknown braces are left untouched.
fn expand_typescript_name(
    template: &str,
    username: &str,
    hostname: &str,
    connection: &str,
    session_id: &Uuid,
    when: DateTime<Utc>,
) -> String {
    fn sanitize(s: &str) -> String {
        let mapped: String = s
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        let collapsed = mapped
            .split('-')
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join("-");
        if collapsed.is_empty() {
            "unknown".to_string()
        } else {
            collapsed
        }
    }

    let short_session: String = session_id.simple().to_string().chars().take(8).collect();

    template
        .replace("{user}", &sanitize(username))
        .replace("{connection}", &sanitize(connection))
        .replace("{host}", &sanitize(hostname))
        .replace("{date}", &when.format("%Y%m%d").to_string())
        .replace("{time}", &when.format("%H%M%S").to_string())
        .replace("{session}", &short_session)
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
///
/// `cleanup_on_close` and `retention_secs` are sourced from `[drive]` config
/// at each call site (see `drive_cleanup_settings`). Per-session drive dirs
/// are only removed when `cleanup_on_close = true`. `retention_secs > 0`
/// schedules the removal that long after session end. With `cleanup_on_close
/// = false` the directory is left in place; the field is also cleared from
/// the session struct so subsequent reads don't think we still own it.
///
/// Note: cross-session persistence (the new session reading the old
/// session's files on disk) is NOT what these flags control. Each session
/// gets its own per-UUID subdirectory under `drive_path`, so even with
/// cleanup_on_close=false the next session sees an empty drive view.
async fn cleanup_browser(
    browser_manager: &BrowserManager,
    session: &mut Session,
    cleanup_on_close: bool,
    retention_secs: u64,
) {
    // Abort login script if still running
    if let Some(handle) = session.login_script_handle.take() {
        handle.abort();
    }

    if let Some(ref mut bs) = session.browser_session {
        browser_manager.kill(bs).await;
    }
    session.browser_session = None;

    // Clean up per-session drive directory if configured to do so.
    if let Some(drive_path) = session.drive_path.take() {
        if cleanup_on_close {
            drive::cleanup_session_dir(drive_path, session.id, retention_secs).await;
        } else {
            tracing::debug!(
                session_id = %session.id,
                "drive cleanup_on_close=false; leaving session drive directory on disk"
            );
        }
    }

    // Shut down SSH tunnel chain (reverse order)
    tunnel::shutdown_chain(&session.tunnels);
    session.tunnels.clear();
}

/// Resolve cleanup behaviour from optional `[drive]` config. Falls back to
/// the historical "always wipe immediately" defaults when no config is set
/// (preserves existing behaviour for installs that never enabled drive).
fn drive_cleanup_settings(drive: &Option<DriveConfig>) -> (bool, u64) {
    match drive {
        Some(d) => (d.cleanup_on_close, d.retention_secs),
        None => (true, 0),
    }
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

/// Pure token-matching helper — constant-time comparison of a provided
/// token against the session's long-lived share tokens (read/write and
/// read-only) and the in-memory set of short-lived admin shadow tokens.
/// Factored out so the logic is unit-testable without spinning up a full
/// `SessionManager`.
pub(crate) fn check_share_token_match(
    share_token: &str,
    share_token_ro: &str,
    shadow_tokens: &[ShadowToken],
    provided: &str,
    now: DateTime<Utc>,
) -> ShareTokenValidation {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    let provided_digest = Sha256::digest(provided.as_bytes());

    // 1. Owner's long-lived share token.
    let expected = Sha256::digest(share_token.as_bytes());
    if bool::from(expected.ct_eq(&provided_digest)) {
        return ShareTokenValidation::Owner;
    }
    let expected_ro = Sha256::digest(share_token_ro.as_bytes());
    if bool::from(expected_ro.ct_eq(&provided_digest)) {
        return ShareTokenValidation::OwnerReadOnly;
    }

    // 2. Short-lived admin shadow tokens (sha256 compared to the
    //    pre-hashed hex stored on the session).
    let provided_hex = hex::encode(provided_digest);
    for t in shadow_tokens {
        if t.expires_at <= now {
            continue;
        }
        if t.token_hash.len() == provided_hex.len()
            && t.token_hash
                .as_bytes()
                .ct_eq(provided_hex.as_bytes())
                .into()
        {
            return ShareTokenValidation::Shadow {
                issued_by: t.issued_by.clone(),
                read_only: t.read_only,
            };
        }
    }
    ShareTokenValidation::Invalid
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Typescript filename templating (#159) ──

    fn ts_when() -> DateTime<Utc> {
        // 2026-06-10 14:30:22 UTC
        DateTime::from_timestamp(1_781_101_822, 0).unwrap()
    }

    fn ts_id() -> Uuid {
        Uuid::parse_str("0123abcd-1111-2222-3333-444455556666").unwrap()
    }

    #[test]
    fn typescript_name_expands_all_tokens() {
        let got = expand_typescript_name(
            "{connection}-{user}-{date}-{time}-{host}-{session}",
            "alice",
            "switch01",
            "Core Switch 01",
            &ts_id(),
            ts_when(),
        );
        assert_eq!(
            got,
            "Core-Switch-01-alice-20260610-143022-switch01-0123abcd"
        );
    }

    #[test]
    fn typescript_name_default_template() {
        let got = expand_typescript_name(
            DEFAULT_TYPESCRIPT_NAME,
            "bob",
            "rtr-2",
            "Edge Router",
            &ts_id(),
            ts_when(),
        );
        assert_eq!(got, "Edge-Router-bob-20260610-143022");
    }

    #[test]
    fn typescript_name_sanitises_path_traversal_and_oidc_email() {
        // A crafted entry name must not escape the typescript dir, and an
        // OIDC email username must reduce to a safe basename.
        let got = expand_typescript_name(
            "{connection}-{user}",
            "alice@sol1.com.au",
            "h",
            "../../etc/cron.d/evil",
            &ts_id(),
            ts_when(),
        );
        assert!(!got.contains('/'), "no path separators: {got}");
        assert!(!got.contains(".."), "no traversal: {got}");
        assert_eq!(got, "etc-cron-d-evil-alice-sol1-com-au");
    }

    #[test]
    fn typescript_name_empty_value_falls_back_to_unknown() {
        let got = expand_typescript_name("{user}", "", "h", "c", &ts_id(), ts_when());
        assert_eq!(got, "unknown");
    }

    #[test]
    fn typescript_name_unknown_token_left_literal() {
        let got = expand_typescript_name("pre-{bogus}-{user}", "x", "h", "c", &ts_id(), ts_when());
        assert_eq!(got, "pre-{bogus}-x");
    }

    fn make_shadow(raw: &str, issued_by: &str, expires_at: DateTime<Utc>) -> ShadowToken {
        use sha2::{Digest, Sha256};
        ShadowToken {
            token_hash: hex::encode(Sha256::digest(raw.as_bytes())),
            issued_by: issued_by.to_string(),
            expires_at,
            read_only: false,
        }
    }

    #[test]
    fn share_token_owner_match() {
        let now = Utc::now();
        let v = check_share_token_match("owner-secret", "ro-secret", &[], "owner-secret", now);
        assert_eq!(v, ShareTokenValidation::Owner);
    }

    #[test]
    fn share_token_wrong_returns_invalid() {
        let now = Utc::now();
        let v = check_share_token_match("owner-secret", "ro-secret", &[], "wrong", now);
        assert_eq!(v, ShareTokenValidation::Invalid);
    }

    #[test]
    fn share_token_empty_provided_invalid() {
        let now = Utc::now();
        let v = check_share_token_match("owner-secret", "ro-secret", &[], "", now);
        assert_eq!(v, ShareTokenValidation::Invalid);
    }

    #[test]
    fn share_token_shadow_hit_returns_issued_by() {
        let now = Utc::now();
        let shadow = make_shadow(
            "shadow-raw",
            "admin@example.com",
            now + chrono::Duration::minutes(5),
        );
        let v = check_share_token_match("owner-secret", "ro-secret", &[shadow], "shadow-raw", now);
        assert_eq!(
            v,
            ShareTokenValidation::Shadow {
                issued_by: "admin@example.com".into(),
                read_only: false,
            }
        );
    }

    #[test]
    fn share_token_expired_shadow_rejected() {
        let now = Utc::now();
        let expired = make_shadow("shadow-raw", "admin", now - chrono::Duration::minutes(1));
        let v = check_share_token_match("owner-secret", "ro-secret", &[expired], "shadow-raw", now);
        assert_eq!(v, ShareTokenValidation::Invalid);
    }

    #[test]
    fn share_token_expires_at_now_treated_as_expired() {
        // Boundary: expires_at <= now must reject.
        let now = Utc::now();
        let at_boundary = make_shadow("shadow-raw", "admin", now);
        let v = check_share_token_match(
            "owner-secret",
            "ro-secret",
            &[at_boundary],
            "shadow-raw",
            now,
        );
        assert_eq!(v, ShareTokenValidation::Invalid);
    }

    #[test]
    fn share_token_multiple_shadows_one_matches() {
        let now = Utc::now();
        let ttl = now + chrono::Duration::minutes(5);
        let a = make_shadow("aaa", "admin1", ttl);
        let b = make_shadow("bbb", "admin2", ttl);
        let c = make_shadow("ccc", "admin3", ttl);
        let shadows = vec![a, b, c];
        let v = check_share_token_match("owner", "ro-secret", &shadows, "bbb", now);
        assert_eq!(
            v,
            ShareTokenValidation::Shadow {
                issued_by: "admin2".into(),
                read_only: false,
            }
        );
    }

    #[test]
    fn share_token_owner_wins_over_shadow_of_same_string() {
        // If somehow a shadow's raw value equalled the owner's share token,
        // the owner path takes precedence (owner is checked first).
        let now = Utc::now();
        let shadow = make_shadow("collide", "admin", now + chrono::Duration::minutes(5));
        let v = check_share_token_match("collide", "ro-secret", &[shadow], "collide", now);
        assert_eq!(v, ShareTokenValidation::Owner);
    }

    #[test]
    fn share_token_validation_is_valid_helper() {
        assert!(ShareTokenValidation::Owner.is_valid());
        assert!(ShareTokenValidation::OwnerReadOnly.is_valid());
        assert!(ShareTokenValidation::Shadow {
            issued_by: "x".into(),
            read_only: false,
        }
        .is_valid());
        assert!(!ShareTokenValidation::Invalid.is_valid());
    }

    #[test]
    fn share_token_readonly_match() {
        let now = Utc::now();
        let v = check_share_token_match("owner-secret", "ro-secret", &[], "ro-secret", now);
        assert_eq!(v, ShareTokenValidation::OwnerReadOnly);
        assert!(v.is_read_only());
    }

    #[test]
    fn share_token_read_write_is_not_read_only() {
        let now = Utc::now();
        let v = check_share_token_match("owner-secret", "ro-secret", &[], "owner-secret", now);
        assert!(!v.is_read_only());
    }

    #[test]
    fn share_token_read_only_shadow_carries_flag() {
        let now = Utc::now();
        let mut shadow = make_shadow("shadow-raw", "admin", now + chrono::Duration::minutes(5));
        shadow.read_only = true;
        let v = check_share_token_match("owner-secret", "ro-secret", &[shadow], "shadow-raw", now);
        assert_eq!(
            v,
            ShareTokenValidation::Shadow {
                issued_by: "admin".into(),
                read_only: true,
            }
        );
        assert!(v.is_read_only());
    }

    // ── SessionManager async tests (in-memory, no disk/browser/guacd) ──
    //
    // These exercise the mint → validate → audit path end-to-end without
    // spinning up guacd, a browser, or touching the real recording dir.

    fn seed_test_session(share_token: &str) -> Session {
        Session {
            id: Uuid::new_v4(),
            session_type: SessionType::Ssh,
            status: SessionStatus::Active,
            created_at: Utc::now(),
            hostname: "test-host".into(),
            username: "alice".into(),
            url: None,
            banner: None,
            guacd_stream: None,
            connection_id: "conn-test".into(),
            share_token: share_token.to_string(),
            share_token_ro: format!("{share_token}-ro"),
            width: 1024,
            height: 768,
            active_connections: 0,
            created_by: "alice".into(),
            cancel: CancellationToken::new(),
            browser_session: None,
            deferred_params: None,
            drive_path: None,
            tunnels: Vec::new(),
            container_id: None,
            container_name: None,
            recording_enabled: false,
            address_book_entry: None,
            address_book_folder: None,
            entry_display_name: None,
            max_recordings: None,
            login_script_handle: None,
            shadow_tokens: Vec::new(),
            share_allowed: true,
            fullscreen_on_connect: false,
            autohide_side_tabs: false,
        }
    }

    fn new_manager_for_tests() -> SessionManager {
        // Build a config pointing at a unique temp recording dir so the
        // real dir isn't touched and parallel tests don't collide.
        let mut config = crate::config::Config::default();
        let tmp = std::env::temp_dir().join(format!("rustguac-sessmgr-test-{}", Uuid::new_v4()));
        config.recording_path = tmp.clone();
        // xvnc/chromium paths are only stored, not exec'd — placeholders are fine.
        config.xvnc_path = "/bin/true".into();
        config.chromium_path = "/bin/true".into();
        config.login_scripts_dir = "/tmp".into();
        SessionManager::new(config, None)
    }

    async fn insert_session(mgr: &SessionManager, session: Session) -> Uuid {
        let id = session.id;
        mgr.sessions
            .write()
            .await
            .insert(id, Arc::new(Mutex::new(session)));
        id
    }

    #[tokio::test]
    async fn manager_owner_token_validates() {
        let mgr = new_manager_for_tests();
        let id = insert_session(&mgr, seed_test_session("owner-secret")).await;
        assert_eq!(
            mgr.validate_share_token(id, "owner-secret").await,
            ShareTokenValidation::Owner
        );
        assert_eq!(
            mgr.validate_share_token(id, "wrong").await,
            ShareTokenValidation::Invalid
        );
    }

    #[tokio::test]
    async fn manager_mint_shadow_then_validate() {
        let mgr = new_manager_for_tests();
        let id = insert_session(&mgr, seed_test_session("owner-secret")).await;

        let (raw, expires_at) = mgr
            .mint_shadow_token(id, "admin@example.com", false)
            .await
            .expect("mint");
        assert!(expires_at > Utc::now());
        // 10-minute TTL — allow small scheduling drift.
        let ttl_ms = (expires_at - Utc::now()).num_milliseconds();
        assert!(ttl_ms > 9 * 60 * 1000 && ttl_ms <= 10 * 60 * 1000);

        // Shadow validates and returns the issuer.
        match mgr.validate_share_token(id, &raw).await {
            ShareTokenValidation::Shadow {
                issued_by,
                read_only,
            } => {
                assert_eq!(issued_by, "admin@example.com");
                assert!(!read_only);
            }
            other => panic!("expected Shadow variant, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn manager_shadow_token_is_session_scoped() {
        // IDOR guard: a shadow token minted for session A must NOT validate
        // against session B.
        let mgr = new_manager_for_tests();
        let id_a = insert_session(&mgr, seed_test_session("owner-a")).await;
        let id_b = insert_session(&mgr, seed_test_session("owner-b")).await;
        let (raw, _) = mgr
            .mint_shadow_token(id_a, "admin", false)
            .await
            .expect("mint");
        assert_eq!(
            mgr.validate_share_token(id_b, &raw).await,
            ShareTokenValidation::Invalid
        );
    }

    #[tokio::test]
    async fn manager_mint_prunes_expired_shadow_tokens() {
        let mgr = new_manager_for_tests();
        let mut session = seed_test_session("owner");
        let id = session.id;
        // Seed an already-expired shadow token directly.
        session.shadow_tokens.push(ShadowToken {
            token_hash: "deadbeef".into(),
            issued_by: "stale".into(),
            expires_at: Utc::now() - chrono::Duration::hours(1),
            read_only: false,
        });
        mgr.sessions
            .write()
            .await
            .insert(id, Arc::new(Mutex::new(session)));

        // Mint pruning is documented on mint_shadow_token.
        let _ = mgr.mint_shadow_token(id, "admin", false).await.unwrap();

        let sessions = mgr.sessions.read().await;
        let guard = sessions.get(&id).unwrap().lock().await;
        assert_eq!(guard.shadow_tokens.len(), 1, "expired should be pruned");
        assert_ne!(guard.shadow_tokens[0].issued_by, "stale");
    }

    #[tokio::test]
    async fn manager_readonly_share_token_validates() {
        let mgr = new_manager_for_tests();
        let id = insert_session(&mgr, seed_test_session("owner-secret")).await;
        let v = mgr.validate_share_token(id, "owner-secret-ro").await;
        assert_eq!(v, ShareTokenValidation::OwnerReadOnly);
    }

    #[test]
    fn session_info_exposes_both_share_urls_only_when_allowed() {
        let mut session = seed_test_session("rw");
        let info = session.info();
        assert_eq!(
            info.share_url.as_deref(),
            Some(format!("/client/{}?token=rw", session.id).as_str())
        );
        assert_eq!(
            info.share_url_readonly.as_deref(),
            Some(format!("/client/{}?token=rw-ro", session.id).as_str())
        );

        session.share_allowed = false;
        let info = session.info();
        assert!(info.share_url.is_none());
        assert!(info.share_url_readonly.is_none());
    }

    #[tokio::test]
    async fn manager_mint_read_only_shadow() {
        let mgr = new_manager_for_tests();
        let id = insert_session(&mgr, seed_test_session("owner")).await;
        let (raw, _) = mgr.mint_shadow_token(id, "admin", true).await.unwrap();
        assert!(mgr.validate_share_token(id, &raw).await.is_read_only());
    }

    /// H3: shadowing a session nobody has connected to yet would make the
    /// admin its owner (the stream goes to the first connection), so mint
    /// must refuse it.
    #[tokio::test]
    async fn manager_mint_refuses_pending_session() {
        let mgr = new_manager_for_tests();
        let mut seed = seed_test_session("owner");
        seed.status = SessionStatus::Pending;
        let id = insert_session(&mgr, seed).await;
        assert!(matches!(
            mgr.mint_shadow_token(id, "admin", false).await,
            Err(SessionError::NotActive)
        ));
        let sessions = mgr.sessions.read().await;
        let guard = sessions.get(&id).unwrap().lock().await;
        assert!(guard.shadow_tokens.is_empty());
    }

    #[tokio::test]
    async fn manager_mint_unknown_session_not_found() {
        let mgr = new_manager_for_tests();
        assert!(matches!(
            mgr.mint_shadow_token(Uuid::new_v4(), "admin", false).await,
            Err(SessionError::NotFound)
        ));
    }

    #[tokio::test]
    async fn manager_validate_rejects_unknown_session() {
        let mgr = new_manager_for_tests();
        let phantom = Uuid::new_v4();
        assert_eq!(
            mgr.validate_share_token(phantom, "anything").await,
            ShareTokenValidation::Invalid
        );
    }

    #[tokio::test]
    async fn manager_disconnect_viewer_saturating_decrement() {
        let mgr = new_manager_for_tests();
        let mut seed = seed_test_session("owner");
        seed.active_connections = 2;
        let id = insert_session(&mgr, seed).await;

        mgr.disconnect_viewer(id).await;
        mgr.disconnect_viewer(id).await;
        // One extra call must NOT underflow to u32::MAX.
        mgr.disconnect_viewer(id).await;

        let sessions = mgr.sessions.read().await;
        let guard = sessions.get(&id).unwrap().lock().await;
        assert_eq!(guard.active_connections, 0);
    }

    #[tokio::test]
    async fn test_check_allowed_network_ipv4_match() {
        assert!(
            check_allowed_network("127.0.0.1", 22, &["127.0.0.0/8".into()])
                .await
                .is_ok()
        );
        assert!(
            check_allowed_network("10.1.2.3", 80, &["10.0.0.0/8".into()])
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_check_allowed_network_ipv4_denied() {
        let err = check_allowed_network("8.8.8.8", 22, &["127.0.0.0/8".into()]).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_check_allowed_network_empty_allowlist() {
        let err = check_allowed_network("127.0.0.1", 22, &[]).await;
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("no valid CIDR"), "got: {}", msg);
    }

    #[tokio::test]
    async fn test_check_allowed_network_multiple_cidrs() {
        let cidrs = vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()];
        assert!(check_allowed_network("10.1.1.1", 22, &cidrs).await.is_ok());
        assert!(check_allowed_network("192.168.1.1", 22, &cidrs)
            .await
            .is_ok());
        assert!(check_allowed_network("172.16.0.1", 22, &cidrs)
            .await
            .is_err());
    }

    /// The fence flag is server-set; a request body must not switch it off.
    #[test]
    fn fence_flag_is_never_read_from_json() {
        let req: CreateSessionRequest = serde_json::from_value(serde_json::json!({
            "session_type": "ssh",
            "hostname": "127.0.0.1",
            "fence_all_targets": true,
        }))
        .unwrap();
        assert!(!req.fence_all_targets);
    }

    fn fenced_request(extra: serde_json::Value) -> CreateSessionRequest {
        let mut body = serde_json::json!({ "hostname": "127.0.0.1" });
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let mut req: CreateSessionRequest = serde_json::from_value(body).unwrap();
        req.fence_all_targets = true;
        req
    }

    /// H5: a non-admin ad-hoc session cannot use a jump host outside the SSH
    /// allowlist to make rustguac dial an arbitrary address.
    #[tokio::test]
    async fn fenced_jump_host_outside_allowlist_refused() {
        let mgr = new_manager_for_tests();
        let req = fenced_request(serde_json::json!({
            "session_type": "ssh",
            "jump_host": "192.0.2.10",
        }));
        match mgr.create_session(req, "pu@example.com".into()).await {
            Err(SessionError::ValidationError(msg)) => {
                assert!(msg.contains("jump host"), "got: {msg}")
            }
            other => panic!(
                "expected jump host refusal, got {:?}",
                other.map(|i| i.session_id)
            ),
        }
    }

    #[tokio::test]
    async fn fenced_proxmox_api_outside_allowlist_refused() {
        let mgr = new_manager_for_tests();
        let req = fenced_request(serde_json::json!({
            "session_type": "proxmox",
            "proxmox_url": "https://192.0.2.20:8006",
            "proxmox_vmid": 100,
        }));
        match mgr.create_session(req, "pu@example.com".into()).await {
            Err(SessionError::ValidationError(msg)) => {
                assert!(msg.contains("Proxmox API"), "got: {msg}")
            }
            other => panic!(
                "expected Proxmox refusal, got {:?}",
                other.map(|i| i.session_id)
            ),
        }
    }

    #[test]
    fn wol_is_dropped_for_untrusted_ad_hoc_and_wait_is_capped() {
        let req = fenced_request(serde_json::json!({
            "session_type": "ssh",
            "wol_send_packet": true,
            "wol_mac_addr": "00:11:22:33:44:55",
            "wol_broadcast_addr": "192.0.2.255",
            "wol_udp_port": 4822,
            "wol_wait_time": 999999,
        }));
        let fenced = wol_params(&req, true);
        assert!(!fenced.send_packet && fenced.broadcast_addr.is_none());
        let trusted = wol_params(&req, false);
        assert!(trusted.send_packet);
        assert_eq!(trusted.wait_time, Some(MAX_WOL_WAIT_SECS));
    }

    async fn allowed_address_for_test(host: &str) -> Result<std::net::IpAddr, SessionError> {
        allowed_address(host, 22, &["10.0.0.0/8".to_string()]).await
    }

    /// Reproduces the DNS stall: with a resolver that never answers, the
    /// allowlist lookup held tokio worker threads for the whole resolver
    /// timeout, so the rest of rustguac (including /api/health) stopped.
    /// Needs a dead resolver, so it is ignored by default. Run it with:
    ///
    ///   printf 'nameserver 10.255.255.1\noptions timeout:3 attempts:2\n' > /tmp/dead.conf
    ///   unshare -rm sh -c 'mount --bind /tmp/dead.conf /etc/resolv.conf && \
    ///     cargo test slow_dns_does_not_stall_the_runtime -- --ignored'
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs a resolver that does not answer; see the comment"]
    async fn slow_dns_does_not_stall_the_runtime() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let beats = Arc::new(AtomicU64::new(0));
        let b = beats.clone();
        let heartbeat = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                b.fetch_add(1, Ordering::Relaxed);
            }
        });
        let lookups: Vec<_> = (0..4)
            .map(|i| {
                tokio::spawn(async move {
                    let host = format!("host{i}.unresolvable.example");
                    let _ = allowed_address_for_test(&host).await;
                })
            })
            .collect();
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let n = beats.load(Ordering::Relaxed);
        heartbeat.abort();
        for l in lookups {
            l.abort();
        }
        // 3s at one beat per 50ms is ~60; a stalled runtime manages almost none.
        assert!(
            n >= 30,
            "runtime stalled during DNS lookups: {n} heartbeats in 3s"
        );
    }

    #[tokio::test]
    async fn test_allowed_address_returns_literal() {
        let ip = allowed_address("10.1.2.3", 22, &["10.0.0.0/8".into()])
            .await
            .unwrap();
        assert_eq!(ip.to_string(), "10.1.2.3");
    }

    /// A dual-stack name with only one family allowed still resolves to the
    /// allowed address instead of failing.
    #[tokio::test]
    async fn test_allowed_address_skips_disallowed_family() {
        let ip = allowed_address("localhost", 22, &["127.0.0.0/8".into()])
            .await
            .unwrap();
        assert!(ip.is_ipv4() && ip.is_loopback(), "got {ip}");
    }

    #[tokio::test]
    async fn test_allowed_address_rejects_when_none_allowed() {
        assert!(allowed_address("localhost", 22, &["10.0.0.0/8".into()])
            .await
            .is_err());
    }

    #[test]
    fn test_dial_host_brackets_ipv6() {
        assert_eq!(dial_host("10.0.0.1".parse().unwrap()), "10.0.0.1");
        assert_eq!(dial_host("::1".parse().unwrap()), "[::1]");
    }

    fn hop(hostname: &str, port: u16) -> tunnel::JumpHost {
        tunnel::JumpHost {
            hostname: hostname.into(),
            port,
            username: "u".into(),
            password: None,
            private_key: None,
            host_key: None,
        }
    }

    #[tokio::test]
    async fn session_network_without_hops_checks_the_target() {
        let cidrs = vec!["127.0.0.0/8".into()];
        assert!(check_session_network("127.0.0.1", 3389, &cidrs, &[])
            .await
            .is_ok());
        assert!(check_session_network("8.8.8.8", 3389, &cidrs, &[])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn session_network_with_hops_skips_unresolvable_target() {
        // The whole point of a bastion: the target name resolves only there.
        let rdp = vec!["10.0.0.0/8".into()];
        let hops = vec![hop("127.0.0.1", 22)];
        assert!(
            check_session_network("liva-z-remote", 3389, &rdp, &hops)
                .await
                .is_ok(),
            "bastion-only target name must not be resolved locally"
        );
    }

    /// Hop 0 is fenced only for untrusted callers, where the chain is built
    /// (see `fenced_jump_host_outside_allowlist_refused`); admins and
    /// connection entries name their own bastions.
    #[tokio::test]
    async fn session_network_leaves_hop_zero_to_the_fence() {
        let rdp = vec!["10.0.0.0/8".into()];
        let hops = vec![hop("192.0.2.10", 22), hop("unresolvable-second-hop", 22)];
        assert!(check_session_network("liva-z-remote", 3389, &rdp, &hops)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_check_allowed_network_localhost_resolves() {
        // "localhost" should resolve to 127.0.0.1 or ::1
        let cidrs = vec!["127.0.0.0/8".into(), "::1/128".into()];
        assert!(check_allowed_network("localhost", 80, &cidrs).await.is_ok());
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

    #[test]
    fn drive_cleanup_settings_no_config_uses_legacy_defaults() {
        // No drive config = legacy "always wipe immediately" so existing
        // installs that never touched [drive] keep prior behaviour.
        assert_eq!(drive_cleanup_settings(&None), (true, 0));
    }

    #[test]
    fn drive_cleanup_settings_passes_through_config() {
        let cfg = DriveConfig {
            enabled: true,
            cleanup_on_close: false,
            retention_secs: 600,
            ..DriveConfig::default()
        };
        assert_eq!(drive_cleanup_settings(&Some(cfg)), (false, 600));
    }

    #[test]
    fn drive_cleanup_settings_default_drive_config() {
        // The default DriveConfig uses cleanup_on_close=true, retention=0.
        let cfg = DriveConfig::default();
        assert_eq!(drive_cleanup_settings(&Some(cfg)), (true, 0));
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
