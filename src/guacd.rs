//! guacd connection and Guacamole protocol handshake.

use crate::protocol::{Instruction, InstructionParser};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Combined trait for async bidirectional streams.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// A type-erased async stream for the guacd connection (plain TCP or TLS).
pub type GuacdStream = Box<dyn AsyncStream>;

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
}

/// VNC connection parameters to pass to guacd.
pub struct VncParams {
    pub hostname: String,
    pub port: u16,
    pub password: Option<String>,
    pub color_depth: Option<u8>,
    pub width: u32,
    pub height: u32,
    pub dpi: u32,
}

/// RDP connection parameters to pass to guacd.
pub struct RdpParams {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub domain: Option<String>,
    pub security: Option<String>,
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
}

/// Connection parameters — SSH, VNC, or RDP.
pub enum ConnectionParams {
    Ssh(SshParams),
    Vnc(VncParams),
    Rdp(Box<RdpParams>),
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

    tracing::debug!("Connected to guacd at {}", guacd_addr);

    let mut stream: GuacdStream = wrap_tls(tcp, tls, guacd_addr).await?;

    // Send select instruction to choose protocol
    let protocol = match params {
        ConnectionParams::Ssh(_) => "ssh",
        ConnectionParams::Vnc(_) => "vnc",
        ConnectionParams::Rdp(_) => "rdp",
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
                "font-size" => "12".into(),
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
                "disable-copy" => "false".into(),
                "disable-paste" => "false".into(),
                "read-only" => "false".into(),
                "locale" => "en_US.UTF-8".into(),
                "server-alive-interval" => "0".into(),
                "command" => String::new(),
                _ => {
                    tracing::debug!("Unknown guacd SSH parameter '{}', sending empty", name);
                    String::new()
                }
            },
            ConnectionParams::Vnc(p) => match name.as_str() {
                "hostname" => p.hostname.clone(),
                "port" => p.port.to_string(),
                "width" => p.width.to_string(),
                "height" => p.height.to_string(),
                "dpi" => p.dpi.to_string(),
                "password" => p.password.clone().unwrap_or_default(),
                "color-depth" => p.color_depth.map_or("24".into(), |d| d.to_string()),
                "cursor" => "local".into(),
                "read-only" => "false".into(),
                "swap-red-blue" => "false".into(),
                "dest-host" => String::new(),
                "dest-port" => String::new(),
                "enable-audio" => "false".into(),
                "disable-copy" => "false".into(),
                "disable-paste" => "false".into(),
                _ => {
                    tracing::debug!("Unknown guacd VNC parameter '{}', sending empty", name);
                    String::new()
                }
            },
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
                "color-depth" => "24".into(),
                "ignore-cert" => if p.ignore_cert { "true" } else { "false" }.into(),
                "disable-auth" => "false".into(),
                "cursor" => "local".into(),
                "enable-wallpaper" => "false".into(),
                "enable-theming" => "false".into(),
                "enable-font-smoothing" => "true".into(),
                "enable-full-window-drag" => "false".into(),
                "enable-desktop-composition" => "false".into(),
                "enable-menu-animations" => "false".into(),
                "disable-bitmap-caching" => "false".into(),
                "disable-offscreen-caching" => "false".into(),
                "resize-method" => "display-update".into(),
                "read-only" => "false".into(),
                "gateway-hostname" => String::new(),
                "gateway-port" => String::new(),
                "gateway-domain" => String::new(),
                "gateway-username" => String::new(),
                "gateway-password" => String::new(),
                "disable-copy" => "false".into(),
                "disable-paste" => "false".into(),
                "console" => "false".into(),
                "server-layout" => String::new(),
                "timezone" => String::new(),
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
                "remote-app" => p.remote_app.clone().unwrap_or_default(),
                "remote-app-dir" => p.remote_app_dir.clone().unwrap_or_default(),
                "remote-app-args" => p.remote_app_args.clone().unwrap_or_default(),
                _ => {
                    tracing::debug!("Unknown guacd RDP parameter '{}', sending empty", name);
                    String::new()
                }
            },
        })
        .collect();

    // Send handshake instructions: size, audio, video, image, timezone, connect
    let (width, height, dpi) = match params {
        ConnectionParams::Ssh(p) => (p.width, p.height, p.dpi),
        ConnectionParams::Vnc(p) => (p.width, p.height, p.dpi),
        ConnectionParams::Rdp(p) => (p.width, p.height, p.dpi),
    };
    send_handshake(&mut stream, width, height, dpi).await?;

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
pub async fn join_connection(
    guacd_addr: &str,
    connection_id: &str,
    width: u32,
    height: u32,
    dpi: u32,
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

    // For joining, send empty values for all args (the connection is already configured)
    let arg_values: Vec<String> = args_instruction
        .args
        .iter()
        .map(|name| match name.as_str() {
            "read-only" => "false".into(),
            _ => String::new(),
        })
        .collect();

    // Send handshake instructions
    send_handshake(&mut stream, width, height, dpi).await?;

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
) -> Result<(), GuacdError> {
    let instructions = [
        Instruction::new(
            "size",
            vec![width.to_string(), height.to_string(), dpi.to_string()],
        ),
        Instruction::new("audio", vec![]),
        Instruction::new("video", vec![]),
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
