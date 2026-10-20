//! guacd connection and Guacamole protocol handshake.

use crate::protocol::{Instruction, InstructionParser};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Apply TCP keepalive to a connected guacd socket. Long-lived guacd sockets
/// can sit idle for minutes (idle terminal, idle desktop). Without keepalive,
/// a silent network drop (NAT eviction, intermediate firewall rebuild) is only
/// caught when something tries to write — which can be never if both sides are
/// quiet. 30s/10s/3 means a dead path is detected within ~60s.
fn apply_keepalive(stream: &TcpStream) {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10))
        .with_retries(3);
    let sock = socket2::SockRef::from(stream);
    if let Err(e) = sock.set_tcp_keepalive(&keepalive) {
        tracing::warn!(error = %e, "failed to enable TCP keepalive on guacd socket");
    }
    if let Err(e) = sock.set_tcp_nodelay(true) {
        tracing::warn!(error = %e, "failed to set TCP_NODELAY on guacd socket");
    }
}

/// Combined trait for async bidirectional streams.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// A type-erased async stream for the guacd connection (plain TCP or TLS).
pub type GuacdStream = Box<dyn AsyncStream>;

/// Wake-on-LAN parameters, passed through to guacd's `wol-*` connection args.
/// guacd supports these for SSH, RDP, VNC, and telnet. Empty/None fields fall
/// back to guacd's own defaults.
#[derive(Default, Clone)]
pub struct WolParams {
    /// Send a magic packet to wake the host before connecting.
    pub send_packet: bool,
    /// Target MAC address (required when `send_packet` is true).
    pub mac_addr: Option<String>,
    /// Broadcast address for the magic packet (guacd default: 255.255.255.255).
    pub broadcast_addr: Option<String>,
    /// UDP port for the magic packet (guacd default: 9).
    pub udp_port: Option<u16>,
    /// Seconds to wait after sending before connecting (lets the host boot).
    pub wait_time: Option<u32>,
}

/// Resolve a guacd `wol-*` arg name to its value. Returns None for non-WoL
/// arg names so callers can fall through to their default handling.
fn wol_arg_value(name: &str, w: &WolParams) -> Option<String> {
    match name {
        "wol-send-packet" => Some(if w.send_packet { "true" } else { "false" }.into()),
        "wol-mac-addr" => Some(w.mac_addr.clone().unwrap_or_default()),
        "wol-broadcast-addr" => Some(w.broadcast_addr.clone().unwrap_or_default()),
        "wol-udp-port" => Some(w.udp_port.map(|p| p.to_string()).unwrap_or_default()),
        "wol-wait-time" => Some(w.wait_time.map(|t| t.to_string()).unwrap_or_default()),
        _ => None,
    }
}

/// SSH connection parameters to pass to guacd.
pub struct SshParams {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub width: u32,
    pub height: u32,
    pub dpi: u32,
    pub enable_sftp: bool,
    pub sftp_disable_download: bool,
    pub sftp_disable_upload: bool,
    pub disable_copy: bool,
    pub disable_paste: bool,
    /// SSH typescript recording (#159). guacd writes the raw terminal
    /// session to a plain-text file (compatible with `scriptreplay`).
    /// An empty `typescript_path` disables it (guacd records nothing).
    /// These are guacd-side paths: the guacd process must be able to
    /// write to `typescript_path`.
    pub typescript_path: Option<String>,
    /// Base filename for the typescript, already expanded by rustguac
    /// (guacd does not substitute tokens here). Empty falls back to
    /// guacd's own default of "typescript".
    pub typescript_name: Option<String>,
    /// Ask guacd to create `typescript_path` if it doesn't exist.
    pub create_typescript_path: bool,
    /// Terminal font size in points (guacd default: 12).
    pub font_size: Option<u32>,
    /// Wake-on-LAN parameters.
    pub wol: WolParams,
}

/// VNC connection parameters to pass to guacd.
pub struct VncParams {
    pub hostname: String,
    pub port: u16,
    /// Only used by servers with username auth (VeNCrypt, RealVNC, macOS).
    pub username: Option<String>,
    pub password: Option<String>,
    pub color_depth: Option<u8>,
    pub width: u32,
    pub height: u32,
    pub dpi: u32,
    pub disable_copy: bool,
    pub disable_paste: bool,
    /// Ask the VNC server to change its screen to the browser's size. Only
    /// servers with their own virtual screen can (Xvnc, TigerVNC); a physical
    /// console (UltraVNC, RealVNC, x11vnc) can't, and libvncclient then stops
    /// requesting updates while it waits for a resize that never comes, so
    /// the session all but freezes. Off, guacd scales the screen instead.
    pub display_resize: bool,
    /// How the VNC server should encode the screen for guacd: encodings in
    /// order of preference, and Tight's zlib compression and JPEG quality
    /// (0-9). `None` leaves libvncclient's defaults.
    pub encodings: Option<String>,
    pub compress_level: Option<u8>,
    pub quality_level: Option<u8>,
    /// Wake-on-LAN parameters.
    pub wol: WolParams,
}

/// A VNC "network" preset, like UltraVNC Viewer's quick options: how to
/// trade picture quality for bandwidth between the VNC server and guacd.
/// Returns (encodings, compress level, quality level, colour depth to use
/// when the connection doesn't set one). `None` for `auto` or an unknown
/// name, which leave every setting at its default.
pub fn vnc_network_preset(preset: &str) -> Option<(&'static str, u8, u8, Option<u8>)> {
    match preset {
        // Fast, lossless-looking: UltraVNC's own LZO encoding first.
        "lan" => Some(("ultra zrle hextile copyrect raw", 1, 9, None)),
        // Tight with JPEG for photos and video, moderate compression.
        "wan" => Some(("tight zrle copyrect", 6, 6, None)),
        // As little bandwidth as possible.
        "slow" => Some(("tight copyrect", 9, 3, Some(16))),
        _ => None,
    }
}

/// The preset names `vnc_network_preset` knows, `auto` included.
pub const VNC_NETWORK_PRESETS: &[&str] = &["auto", "lan", "wan", "slow"];

/// SPICE connection parameters to pass to guacd.
///
/// Credentials (`password`/`username`) are sent as connect args: guacd's SPICE
/// client authenticates during `connect` without awaiting an `argv` stream, so
/// argv delivery would race the auth. The TLS + proxy + cert-subject fields
/// support brokered Proxmox VE consoles (which connect via a SPICE proxy with a
/// one-time ticket and cluster-CA TLS).
pub struct SpiceParams {
    pub hostname: String,
    pub port: u16,
    /// SPICE ticket / password, sent as the `password` connect arg.
    pub password: Option<String>,
    /// Optional SPICE username, sent as the `username` connect arg.
    pub username: Option<String>,
    pub tls: bool,
    pub tls_port: Option<u16>,
    /// PEM CA certificate for verifying the SPICE server's TLS (Proxmox cluster CA).
    pub ca_cert: Option<String>,
    /// Expected TLS certificate subject (Proxmox "host-subject").
    pub cert_subject: Option<String>,
    pub ignore_cert: bool,
    /// SPICE proxy URL, e.g. "http://proxy.example.com:3128" (Proxmox SPICE proxy).
    pub proxy: Option<String>,
    pub color_depth: Option<u8>,
    pub width: u32,
    pub height: u32,
    pub dpi: u32,
    pub disable_copy: bool,
    pub disable_paste: bool,
    pub enable_audio: bool,
    /// Number of secondary monitors to allow (beyond the primary). guacd
    /// advertises this to the client as `secondary-monitors` so a multi-monitor
    /// client can offer the right number of monitor windows. 0 = single monitor.
    pub secondary_monitors: u32,
}

impl SpiceParams {
    /// The port guacd dials: the TLS port with TLS on (falling back to `port`
    /// when no separate TLS port is set), otherwise `port`.
    pub fn dial_port(&self) -> u16 {
        if self.tls {
            self.tls_port.unwrap_or(self.port)
        } else {
            self.port
        }
    }
}

/// The value guacd gets for one VNC argument.
fn vnc_arg_value(name: &str, p: &VncParams) -> String {
    match name {
        "hostname" => p.hostname.clone(),
        "port" => p.port.to_string(),
        "width" => p.width.to_string(),
        "height" => p.height.to_string(),
        "dpi" => p.dpi.to_string(),
        "username" => p.username.clone().unwrap_or_default(),
        "password" => p.password.clone().unwrap_or_default(),
        "color-depth" => p.color_depth.map_or("24".into(), |d| d.to_string()),
        "cursor" => "local".into(),
        "read-only" => "false".into(),
        "swap-red-blue" => "false".into(),
        "dest-host" => String::new(),
        "dest-port" => String::new(),
        "enable-audio" => "false".into(),
        "disable-copy" => if p.disable_copy { "true" } else { "false" }.into(),
        "disable-paste" => if p.disable_paste { "true" } else { "false" }.into(),
        "disable-display-resize" => if p.display_resize { "false" } else { "true" }.into(),
        "encodings" => p.encodings.clone().unwrap_or_default(),
        "compress-level" => p.compress_level.map(|v| v.to_string()).unwrap_or_default(),
        "quality-level" => p.quality_level.map(|v| v.to_string()).unwrap_or_default(),
        _ => wol_arg_value(name, &p.wol).unwrap_or_else(|| {
            tracing::debug!("Unknown guacd VNC parameter '{}', sending empty", name);
            String::new()
        }),
    }
}

/// Resolve a guacd SPICE connect arg name to its value.
///
/// SPICE has no width/height/dpi connect args: it sizes via the `size`
/// instruction.
fn spice_arg_value(name: &str, p: &SpiceParams) -> String {
    match name {
        "hostname" => p.hostname.clone(),
        // TLS SPICE (e.g. Proxmox) is TLS-only: send an empty plain
        // port so guacd/spice-gtk connects via tls-port with TLS rather
        // than plaintext against a TLS endpoint.
        "port" => {
            if p.tls {
                String::new()
            } else {
                p.port.to_string()
            }
        }
        // Credentials go in the connect args (not a post-connect argv
        // stream): guacd's SPICE client sets settings->password on the
        // session and authenticates during connect without awaiting
        // argv, so argv delivery races the auth. The connect arg is set
        // before the server connection is opened.
        "username" => p.username.clone().unwrap_or_default(),
        "password" => p.password.clone().unwrap_or_default(),
        "tls" => if p.tls { "true" } else { "false" }.into(),
        // With TLS on, always name the port to dial: a blank TLS port means
        // "same as Port" (as in the editor and the jump-host tunnel), and an
        // empty value would make guacd fall back to 5900.
        "tls-port" => {
            if p.tls {
                p.dial_port().to_string()
            } else {
                p.tls_port.map(|x| x.to_string()).unwrap_or_default()
            }
        }
        "ca-cert" => p.ca_cert.clone().unwrap_or_default(),
        "cert-subject" => p.cert_subject.clone().unwrap_or_default(),
        "ignore-cert" => if p.ignore_cert { "true" } else { "false" }.into(),
        "proxy" => p.proxy.clone().unwrap_or_default(),
        "color-depth" => p.color_depth.map_or("24".into(), |d| d.to_string()),
        "read-only" => "false".into(),
        "swap-red-blue" => "false".into(),
        "enable-audio" => if p.enable_audio { "true" } else { "false" }.into(),
        "disable-copy" => if p.disable_copy { "true" } else { "false" }.into(),
        "disable-paste" => if p.disable_paste { "true" } else { "false" }.into(),
        "secondary-monitors" => p.secondary_monitors.to_string(),
        _ => {
            tracing::debug!("Unknown guacd SPICE parameter '{}', sending empty", name);
            String::new()
        }
    }
}

/// RDP connection parameters to pass to guacd.
pub struct RdpParams {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub domain: Option<String>,
    pub security: Option<String>,
    /// RDP server keyboard layout (guacd `server-layout`). Empty = guacd default.
    pub server_layout: Option<String>,
    pub width: u32,
    pub height: u32,
    pub dpi: u32,
    pub ignore_cert: bool,
    pub enable_drive: bool,
    pub drive_path: Option<String>,
    pub drive_name: String,
    pub disable_download: bool,
    pub disable_upload: bool,
    /// NLA authentication package: "kerberos", "ntlm", or empty (negotiate).
    pub auth_pkg: Option<String>,
    /// Kerberos KDC URL (optional, uses system krb5.conf if unset).
    pub kdc_url: Option<String>,
    /// Path to Kerberos ticket cache file (optional).
    pub kerberos_cache: Option<String>,
    /// RemoteApp program path (RAIL).
    pub remote_app: Option<String>,
    /// RemoteApp working directory.
    pub remote_app_dir: Option<String>,
    /// RemoteApp command-line arguments.
    pub remote_app_args: Option<String>,
    pub disable_copy: bool,
    pub disable_paste: bool,
    /// Enable Graphics Pipeline Extension (GFX/RDPGFX). Enables RemoteFX codec, 32bpp.
    pub enable_gfx: bool,
    /// Enable desktop composition (DWM). Required for smooth video overlay rendering.
    pub enable_desktop_composition: bool,
    /// Show the remote desktop wallpaper. Disabled by default to save bandwidth.
    pub enable_wallpaper: bool,
    /// Enable window/control theming (visual styles). Disabled by default to save bandwidth.
    pub enable_theming: bool,
    /// Show window contents while dragging. Disabled by default to save bandwidth.
    pub enable_full_window_drag: bool,
    /// Force lossless encoding (PNG only). Better for text-heavy workloads.
    pub force_lossless: bool,
    /// Enable H.264 passthrough. Raw H.264 NAL units sent to browser WebCodecs decoder.
    pub enable_h264: bool,
    /// DPI scaling percentage the remote session should render its UI at, sent
    /// to the server as desktopScaleFactor. `None` leaves the server at its
    /// default of 100%.
    ///
    /// Only meaningful alongside a framebuffer requested in physical rather
    /// than logical pixels: without it, the extra pixels shrink every element
    /// of the desktop instead of sharpening it.
    pub desktop_scale: Option<u32>,
    /// Number of secondary monitors to allow (beyond the primary). guacd
    /// advertises this to the client as `secondary-monitors` and drives RDP
    /// multi-monitor via the Display Control channel. 0 = single monitor.
    pub secondary_monitors: u32,
    /// Wake-on-LAN parameters.
    pub wol: WolParams,
}

/// Connection parameters — SSH, VNC, or RDP.
pub enum ConnectionParams {
    Ssh(SshParams),
    Vnc(VncParams),
    Rdp(Box<RdpParams>),
    Spice(Box<SpiceParams>),
}

/// Connect to guacd and perform the Guacamole protocol handshake.
///
/// Returns the connected stream (ready for bidirectional instruction streaming)
/// and the connection ID assigned by guacd.
pub async fn connect_and_handshake(
    guacd_addr: &str,
    params: &ConnectionParams,
    tls: Option<&tokio_rustls::TlsConnector>,
) -> Result<(GuacdStream, String), GuacdError> {
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(guacd_addr))
        .await
        .map_err(|_| {
            GuacdError::Connection(format!("Timeout connecting to guacd at {}", guacd_addr))
        })?
        .map_err(|e| {
            GuacdError::Connection(format!(
                "Failed to connect to guacd at {}: {}",
                guacd_addr, e
            ))
        })?;

    apply_keepalive(&tcp);
    tracing::debug!("Connected to guacd at {}", guacd_addr);

    let mut stream: GuacdStream = wrap_tls(tcp, tls, guacd_addr).await?;

    // Send select instruction to choose protocol
    let protocol = match params {
        ConnectionParams::Ssh(_) => "ssh",
        ConnectionParams::Vnc(_) => "vnc",
        ConnectionParams::Rdp(_) => "rdp",
        ConnectionParams::Spice(_) => "spice",
    };
    let select = Instruction::new("select", vec![protocol.into()]);
    stream
        .write_all(select.encode().as_bytes())
        .await
        .map_err(|e| GuacdError::Io(e.to_string()))?;

    tracing::debug!("Sent select instruction for {}", protocol);

    // Read the args instruction from guacd — this tells us what parameters it expects
    let args_instruction = read_instruction(&mut stream).await?;
    if args_instruction.opcode != "args" {
        return Err(GuacdError::Protocol(format!(
            "Expected 'args' instruction, got '{}'",
            args_instruction.opcode
        )));
    }

    tracing::debug!(
        "Received args instruction with {} parameters: {:?}",
        args_instruction.args.len(),
        args_instruction.args
    );

    // Build the connect instruction with values matching the args order.
    let arg_values: Vec<String> = args_instruction
        .args
        .iter()
        .map(|name| match params {
            ConnectionParams::Ssh(p) => match name.as_str() {
                "hostname" => p.hostname.clone(),
                "port" => p.port.to_string(),
                "username" => p.username.clone(),
                "password" => p.password.clone().unwrap_or_default(),
                "private-key" => p.private_key.clone().unwrap_or_default(),
                "width" => p.width.to_string(),
                "height" => p.height.to_string(),
                "dpi" => p.dpi.to_string(),
                "color-scheme" => "gray-black".into(),
                "font-size" => p.font_size.unwrap_or(12).to_string(),
                "font-name" => "monospace".into(),
                "terminal-type" => "xterm-256color".into(),
                "scrollback" => "1000".into(),
                "backspace" => "127".into(),
                "enable-sftp" => if p.enable_sftp { "true" } else { "false" }.into(),
                "sftp-disable-download" => if p.sftp_disable_download {
                    "true"
                } else {
                    "false"
                }
                .into(),
                "sftp-disable-upload" => if p.sftp_disable_upload {
                    "true"
                } else {
                    "false"
                }
                .into(),
                "disable-copy" => if p.disable_copy { "true" } else { "false" }.into(),
                "disable-paste" => if p.disable_paste { "true" } else { "false" }.into(),
                "read-only" => "false".into(),
                "locale" => "en_US.UTF-8".into(),
                "server-alive-interval" => "0".into(),
                "command" => String::new(),
                "typescript-path" => p.typescript_path.clone().unwrap_or_default(),
                "typescript-name" => p.typescript_name.clone().unwrap_or_default(),
                "create-typescript-path" => if p.create_typescript_path {
                    "true"
                } else {
                    "false"
                }
                .into(),
                _ => wol_arg_value(name, &p.wol).unwrap_or_else(|| {
                    tracing::debug!("Unknown guacd SSH parameter '{}', sending empty", name);
                    String::new()
                }),
            },
            ConnectionParams::Vnc(p) => vnc_arg_value(name.as_str(), p),
            ConnectionParams::Rdp(p) => match name.as_str() {
                "hostname" => p.hostname.clone(),
                "port" => p.port.to_string(),
                "username" => p.username.clone(),
                "password" => p.password.clone().unwrap_or_default(),
                "domain" => p.domain.clone().unwrap_or_default(),
                "security" => p.security.clone().unwrap_or_else(|| "any".into()),
                "width" => p.width.to_string(),
                "height" => p.height.to_string(),
                "dpi" => p.dpi.to_string(),
                "color-depth" => "32".into(),
                "ignore-cert" => if p.ignore_cert { "true" } else { "false" }.into(),
                "disable-auth" => "false".into(),
                "cursor" => "local".into(),
                "enable-wallpaper" => if p.enable_wallpaper { "true" } else { "false" }.into(),
                "enable-theming" => if p.enable_theming { "true" } else { "false" }.into(),
                "enable-font-smoothing" => "true".into(),
                "enable-full-window-drag" => if p.enable_full_window_drag {
                    "true"
                } else {
                    "false"
                }
                .into(),
                "enable-desktop-composition" => if p.enable_desktop_composition {
                    "true"
                } else {
                    "false"
                }
                .into(),
                "enable-menu-animations" => "false".into(),
                "disable-bitmap-caching" => "false".into(),
                "disable-offscreen-caching" => "false".into(),
                "resize-method" => "display-update".into(),
                "secondary-monitors" => p.secondary_monitors.to_string(),
                "read-only" => "false".into(),
                "gateway-hostname" => String::new(),
                "gateway-port" => String::new(),
                "gateway-domain" => String::new(),
                "gateway-username" => String::new(),
                "gateway-password" => String::new(),
                "disable-copy" => if p.disable_copy { "true" } else { "false" }.into(),
                "disable-paste" => if p.disable_paste { "true" } else { "false" }.into(),
                "console" => "false".into(),
                "server-layout" => p.server_layout.clone().unwrap_or_default(),
                "timezone" => String::new(),
                "disable-audio" => "false".into(),
                "enable-audio-input" => "false".into(),
                "enable-printing" => "false".into(),
                "enable-drive" => if p.enable_drive { "true" } else { "false" }.into(),
                "drive-path" => p.drive_path.clone().unwrap_or_default(),
                "create-drive-path" => if p.enable_drive { "true" } else { "false" }.into(),
                "drive-name" => p.drive_name.clone(),
                "disable-download" => if p.disable_download { "true" } else { "false" }.into(),
                "disable-upload" => if p.disable_upload { "true" } else { "false" }.into(),
                "auth-pkg" => p.auth_pkg.clone().unwrap_or_default(),
                "kdc-url" => p.kdc_url.clone().unwrap_or_default(),
                "kerberos-cache" => p.kerberos_cache.clone().unwrap_or_default(),
                "disable-gfx" => if p.enable_gfx { "false" } else { "true" }.into(),
                "force-lossless" => if p.force_lossless { "true" } else { "false" }.into(),
                "enable-h264" => if p.enable_h264 { "true" } else { "false" }.into(),
                "desktop-scale" => p.desktop_scale.map_or(String::new(), |s| s.to_string()),
                "remote-app" => p.remote_app.clone().unwrap_or_default(),
                "remote-app-dir" => p.remote_app_dir.clone().unwrap_or_default(),
                "remote-app-args" => p.remote_app_args.clone().unwrap_or_default(),
                _ => wol_arg_value(name, &p.wol).unwrap_or_else(|| {
                    tracing::debug!("Unknown guacd RDP parameter '{}', sending empty", name);
                    String::new()
                }),
            },
            ConnectionParams::Spice(p) => spice_arg_value(name, p),
        })
        .collect();

    // Send handshake instructions: size, audio, video, image, timezone, connect
    let (width, height, dpi, h264) = match &params {
        ConnectionParams::Ssh(p) => (p.width, p.height, p.dpi, false),
        ConnectionParams::Vnc(p) => (p.width, p.height, p.dpi, false),
        ConnectionParams::Rdp(p) => (p.width, p.height, p.dpi, p.enable_h264),
        ConnectionParams::Spice(p) => (p.width, p.height, p.dpi, false),
    };
    send_handshake(&mut stream, width, height, dpi, h264).await?;

    let connect = Instruction::new("connect", arg_values);
    stream
        .write_all(connect.encode().as_bytes())
        .await
        .map_err(|e| GuacdError::Io(e.to_string()))?;

    tracing::debug!("Sent handshake instructions");

    // Read the ready instruction — confirms connection is established
    let ready = read_instruction(&mut stream).await?;
    if ready.opcode != "ready" {
        return Err(GuacdError::Protocol(format!(
            "Expected 'ready' instruction, got '{}' (args: {:?})",
            ready.opcode, ready.args
        )));
    }

    let connection_id = ready
        .args
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown".into());

    tracing::info!("guacd handshake complete, connection_id={}", connection_id);

    Ok((stream, connection_id))
}

/// Join an existing guacd connection by its connection_id.
///
/// Opens a new TCP connection to guacd and sends `select` with the connection_id
/// instead of a protocol name. guacd routes this to the existing session process,
/// allowing multiple users to share the same session.
///
/// `read_only` is enforced by guacd itself: settings are parsed per joining
/// user, and every protocol skips installing that user's key, mouse and
/// clipboard handlers when its `read-only` arg is true.
pub async fn join_connection(
    guacd_addr: &str,
    connection_id: &str,
    width: u32,
    height: u32,
    dpi: u32,
    read_only: bool,
    tls: Option<&tokio_rustls::TlsConnector>,
) -> Result<GuacdStream, GuacdError> {
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(guacd_addr))
        .await
        .map_err(|_| {
            GuacdError::Connection(format!("Timeout connecting to guacd at {}", guacd_addr))
        })?
        .map_err(|e| {
            GuacdError::Connection(format!(
                "Failed to connect to guacd at {}: {}",
                guacd_addr, e
            ))
        })?;

    apply_keepalive(&tcp);
    tracing::debug!(
        "Connected to guacd for join, connection_id={}",
        connection_id
    );

    let mut stream: GuacdStream = wrap_tls(tcp, tls, guacd_addr).await?;

    // Send select with the connection_id to join the existing session
    let select = Instruction::new("select", vec![connection_id.into()]);
    stream
        .write_all(select.encode().as_bytes())
        .await
        .map_err(|e| GuacdError::Io(e.to_string()))?;

    // Read args instruction (guacd still sends args for joining users)
    let args_instruction = read_instruction(&mut stream).await?;
    if args_instruction.opcode != "args" {
        return Err(GuacdError::Protocol(format!(
            "Expected 'args' from join, got '{}'",
            args_instruction.opcode
        )));
    }

    tracing::debug!("Join args: {:?}", args_instruction.args);

    let arg_values = join_arg_values(&args_instruction.args, read_only);

    // Send handshake instructions (joining user — h264 inherited from session)
    send_handshake(&mut stream, width, height, dpi, false).await?;

    let connect = Instruction::new("connect", arg_values);
    stream
        .write_all(connect.encode().as_bytes())
        .await
        .map_err(|e| GuacdError::Io(e.to_string()))?;

    // Read ready
    let ready = read_instruction(&mut stream).await?;
    if ready.opcode != "ready" {
        return Err(GuacdError::Protocol(format!(
            "Expected 'ready' from join, got '{}' (args: {:?})",
            ready.opcode, ready.args
        )));
    }

    tracing::info!("Joined existing connection {}", connection_id);

    Ok(stream)
}

/// Values for a joining user's `connect`. Everything is left empty because
/// the connection is already configured, except `read-only`, which guacd
/// applies to this user alone.
fn join_arg_values(arg_names: &[String], read_only: bool) -> Vec<String> {
    arg_names
        .iter()
        .map(|name| match name.as_str() {
            "read-only" => if read_only { "true" } else { "false" }.into(),
            _ => String::new(),
        })
        .collect()
}

/// Optionally wrap a TCP stream in TLS. Returns a boxed GuacdStream.
/// Derives the TLS server name from `guacd_addr` (host:port format).
async fn wrap_tls(
    tcp: TcpStream,
    tls: Option<&tokio_rustls::TlsConnector>,
    guacd_addr: &str,
) -> Result<GuacdStream, GuacdError> {
    match tls {
        Some(connector) => {
            // Extract hostname from "host:port" address
            let hostname = guacd_addr
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(guacd_addr);
            let server_name =
                tokio_rustls::rustls::pki_types::ServerName::try_from(hostname.to_string())
                    .map_err(|e| {
                        GuacdError::Connection(format!(
                            "Invalid TLS server name '{}': {}",
                            hostname, e
                        ))
                    })?
                    .to_owned();
            let tls_stream = connector.connect(server_name, tcp).await.map_err(|e| {
                GuacdError::Connection(format!("TLS handshake with guacd failed: {}", e))
            })?;
            tracing::debug!(
                "TLS connection to guacd established (server_name={})",
                hostname
            );
            Ok(Box::new(tls_stream))
        }
        None => Ok(Box::new(tcp)),
    }
}

/// Send the common handshake instructions (size, audio, video, image, timezone).
async fn send_handshake(
    stream: &mut (impl AsyncWrite + Unpin),
    width: u32,
    height: u32,
    dpi: u32,
    enable_h264: bool,
) -> Result<(), GuacdError> {
    let video_args = if enable_h264 {
        vec!["video/h264".into()]
    } else {
        vec![]
    };

    let instructions = [
        Instruction::new(
            "size",
            vec![width.to_string(), height.to_string(), dpi.to_string()],
        ),
        Instruction::new("audio", vec!["audio/L16".into(), "audio/L8".into()]),
        Instruction::new("video", video_args),
        Instruction::new(
            "image",
            vec!["image/png".into(), "image/jpeg".into(), "image/webp".into()],
        ),
        Instruction::new("timezone", vec!["Australia/Brisbane".into()]),
    ];

    for inst in &instructions {
        stream
            .write_all(inst.encode().as_bytes())
            .await
            .map_err(|e| GuacdError::Io(e.to_string()))?;
    }

    Ok(())
}

/// Read a single complete instruction from an async stream.
async fn read_instruction(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<Instruction, GuacdError> {
    let mut parser = InstructionParser::new();
    let mut buf = [0u8; 4096];

    loop {
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| GuacdError::Io(e.to_string()))?;
        if n == 0 {
            return Err(GuacdError::Connection("guacd closed connection".into()));
        }
        let data = std::str::from_utf8(&buf[..n])
            .map_err(|e| GuacdError::Protocol(format!("Invalid UTF-8 from guacd: {}", e)))?;

        let results = parser.receive(data);
        if let Some(result) = results.into_iter().next() {
            return result.map_err(|e| GuacdError::Protocol(e.to_string()));
        }
    }
}

#[derive(Debug)]
pub enum GuacdError {
    Connection(String),
    Io(String),
    Protocol(String),
}

impl std::fmt::Display for GuacdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuacdError::Connection(msg) => write!(f, "connection error: {}", msg),
            GuacdError::Io(msg) => write!(f, "I/O error: {}", msg),
            GuacdError::Protocol(msg) => write!(f, "protocol error: {}", msg),
        }
    }
}

impl std::error::Error for GuacdError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn vnc(display_resize: bool) -> VncParams {
        VncParams {
            hostname: "192.0.2.10".into(),
            port: 5900,
            username: None,
            password: None,
            color_depth: None,
            width: 2560,
            height: 1266,
            dpi: 96,
            disable_copy: false,
            disable_paste: false,
            display_resize,
            encodings: None,
            compress_level: None,
            quality_level: None,
            wol: WolParams::default(),
        }
    }

    #[test]
    fn vnc_network_presets_set_encodings_compression_and_quality() {
        // Auto (no preset): every one empty, so guacd keeps libvncclient's
        // own defaults.
        let p = vnc(false);
        for arg in ["encodings", "compress-level", "quality-level"] {
            assert_eq!(vnc_arg_value(arg, &p), "", "{arg}");
        }
        let (enc, compress, quality, depth) = vnc_network_preset("slow").unwrap();
        let mut p = vnc(false);
        p.encodings = Some(enc.into());
        p.compress_level = Some(compress);
        p.quality_level = Some(quality);
        assert_eq!(vnc_arg_value("encodings", &p), "tight copyrect");
        assert_eq!(vnc_arg_value("compress-level", &p), "9");
        assert_eq!(vnc_arg_value("quality-level", &p), "3");
        assert_eq!(depth, Some(16));
        // Every listed preset other than auto resolves; anything else doesn't.
        for name in VNC_NETWORK_PRESETS.iter().filter(|n| **n != "auto") {
            let (enc, c, q, _) = vnc_network_preset(name).unwrap();
            assert!(!enc.is_empty() && c <= 9 && q <= 9, "{name}");
        }
        assert!(vnc_network_preset("auto").is_none());
        assert!(vnc_network_preset("modem").is_none());
    }

    #[test]
    fn vnc_display_resize_is_off_unless_asked() {
        // A physical console can't resize, and libvncclient then stops asking
        // for updates while it waits: guacd must be told not to try.
        assert_eq!(vnc_arg_value("disable-display-resize", &vnc(false)), "true");
        assert_eq!(vnc_arg_value("disable-display-resize", &vnc(true)), "false");
        assert_eq!(vnc_arg_value("hostname", &vnc(false)), "192.0.2.10");
    }

    #[test]
    fn join_args_read_write_by_default() {
        let got = join_arg_values(&names(&["VERSION_1_5_0", "hostname", "read-only"]), false);
        assert_eq!(got, vec!["", "", "false"]);
    }

    #[test]
    fn join_args_read_only() {
        let got = join_arg_values(&names(&["hostname", "read-only", "port"]), true);
        assert_eq!(got, vec!["", "true", ""]);
    }

    fn spice(tls: bool, port: u16, tls_port: Option<u16>) -> SpiceParams {
        SpiceParams {
            hostname: "spice.example.com".into(),
            port,
            password: None,
            username: None,
            tls,
            tls_port,
            ca_cert: None,
            cert_subject: None,
            ignore_cert: false,
            proxy: None,
            color_depth: None,
            width: 1024,
            height: 768,
            dpi: 96,
            disable_copy: false,
            disable_paste: false,
            enable_audio: false,
            secondary_monitors: 0,
        }
    }

    #[test]
    fn spice_tls_blank_tls_port_uses_port() {
        let p = spice(true, 61000, None);
        assert_eq!(p.dial_port(), 61000);
        assert_eq!(spice_arg_value("port", &p), "");
        assert_eq!(spice_arg_value("tls-port", &p), "61000");
    }

    #[test]
    fn spice_tls_explicit_tls_port_wins() {
        let p = spice(true, 5900, Some(5901));
        assert_eq!(p.dial_port(), 5901);
        assert_eq!(spice_arg_value("port", &p), "");
        assert_eq!(spice_arg_value("tls-port", &p), "5901");
    }

    #[test]
    fn spice_plain_sends_port_only() {
        let p = spice(false, 5930, None);
        assert_eq!(p.dial_port(), 5930);
        assert_eq!(spice_arg_value("port", &p), "5930");
        assert_eq!(spice_arg_value("tls-port", &p), "");
        assert_eq!(spice_arg_value("tls", &p), "false");
    }
}
