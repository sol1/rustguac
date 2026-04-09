//! SSH tunnel (jump host / bastion) support.
//!
//! Creates an SSH connection to a jump host, then for each incoming local TCP
//! connection, opens a `direct-tcpip` channel to the real target and bridges
//! traffic bidirectionally. guacd connects to the local listener instead of
//! the real target.
//!
//! Supports multi-hop chains: You → hop0 → hop1 → ... → target.

use russh::client;
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{HashAlg, PublicKey};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// A single jump host in a multi-hop chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpHost {
    pub hostname: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// SSH server public key in OpenSSH format (e.g. "ssh-ed25519 AAAA...").
    /// Stored on first verification and checked on subsequent connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,
}

fn default_ssh_port() -> u16 {
    22
}

/// Non-secret jump host metadata for API responses.
#[derive(Debug, Clone, Serialize)]
pub struct JumpHostInfo {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    /// SSH server host key fingerprint (e.g. "SHA256:...") if pinned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_key_fingerprint: Option<String>,
}

/// A running SSH tunnel. Dropping or cancelling shuts it down.
pub struct SshTunnel {
    /// Local address that the next hop (or guacd) should connect to.
    pub local_addr: SocketAddr,
    cancel: CancellationToken,
    _join_handle: JoinHandle<()>,
}

impl SshTunnel {
    /// Stop the tunnel (listener + SSH session).
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

impl Drop for SshTunnel {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Configuration for establishing an SSH tunnel.
pub struct TunnelConfig {
    pub jump_host: String,
    pub jump_port: u16,
    pub jump_username: String,
    pub jump_password: Option<String>,
    pub jump_private_key: Option<String>,
    pub target_host: String,
    pub target_port: u16,
    /// Expected SSH server host key in OpenSSH format. If set, the connection
    /// is rejected when the server presents a different key.
    pub expected_host_key: Option<String>,
}

/// Errors from tunnel setup.
#[derive(Debug)]
pub enum TunnelError {
    Ssh(usize, String),
    Auth(usize, String),
    Bind(usize, String),
    Key(usize, String),
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ssh(hop, msg) => write!(f, "hop {}: SSH tunnel error: {}", hop, msg),
            Self::Auth(hop, msg) => write!(f, "hop {}: SSH tunnel auth failed: {}", hop, msg),
            Self::Bind(hop, msg) => write!(f, "hop {}: SSH tunnel bind failed: {}", hop, msg),
            Self::Key(hop, msg) => write!(f, "hop {}: SSH tunnel key error: {}", hop, msg),
        }
    }
}

/// Compute the SHA-256 fingerprint of an OpenSSH-format public key string.
pub fn fingerprint_openssh_key(openssh_key: &str) -> Result<String, String> {
    let pubkey = russh::keys::parse_public_key_base64(
        openssh_key
            .split_whitespace()
            .nth(1)
            .unwrap_or(openssh_key),
    )
    .map_err(|e| format!("invalid host key: {}", e))?;
    Ok(pubkey.fingerprint(HashAlg::Sha256).to_string())
}

/// SSH client handler that verifies the server's host key against an expected
/// key stored in the address book. If no expected key is set (legacy entries),
/// the connection is accepted with a warning log.
struct TunnelHandler {
    expected_key: Option<String>,
    hop_index: usize,
    jump_host: String,
}

impl client::Handler for TunnelHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let fingerprint = server_public_key.fingerprint(HashAlg::Sha256);
        let algorithm = server_public_key.algorithm();

        let Some(ref expected) = self.expected_key else {
            tracing::warn!(
                hop = self.hop_index,
                host = %self.jump_host,
                fingerprint = %fingerprint,
                algorithm = %algorithm,
                "SSH host key not pinned — accepting on trust (TOFU). \
                 Pin this key in the address book to prevent MITM attacks."
            );
            return Ok(true);
        };

        // Parse the stored OpenSSH key and compare
        let expected_pubkey = match russh::keys::parse_public_key_base64(
            expected.split_whitespace().nth(1).unwrap_or(expected),
        ) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(
                    hop = self.hop_index,
                    host = %self.jump_host,
                    error = %e,
                    "Failed to parse stored host key — accepting connection but key verification skipped"
                );
                return Ok(true);
            }
        };

        if *server_public_key == expected_pubkey {
            tracing::debug!(
                hop = self.hop_index,
                host = %self.jump_host,
                fingerprint = %fingerprint,
                "SSH host key verified"
            );
            Ok(true)
        } else {
            let expected_fp = expected_pubkey.fingerprint(HashAlg::Sha256);
            tracing::error!(
                hop = self.hop_index,
                host = %self.jump_host,
                expected = %expected_fp,
                actual = %fingerprint,
                "SSH HOST KEY MISMATCH — possible MITM attack! \
                 Update the host key in the address book if the server was re-provisioned."
            );
            Ok(false)
        }
    }
}

/// Handler used by `probe_host_key` to capture the server's public key
/// during key exchange without authenticating.
struct ProbeHandler {
    captured_key: Arc<Mutex<Option<String>>>,
}

impl client::Handler for ProbeHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let openssh = server_public_key
            .to_openssh()
            .map_err(|e| russh::Error::Keys(russh::keys::Error::SshKey(e)))?;
        *self.captured_key.lock().await = Some(openssh);
        Ok(true)
    }
}

/// Probe an SSH server to retrieve its host key without authenticating.
/// Returns the public key in OpenSSH format.
pub async fn probe_host_key(hostname: &str, port: u16) -> Result<String, TunnelError> {
    let addr = format!("{}:{}", hostname, port);
    let captured = Arc::new(Mutex::new(None));

    let ssh_config = Arc::new(client::Config {
        ..Default::default()
    });

    let handler = ProbeHandler {
        captured_key: captured.clone(),
    };

    // Connect with a 10-second timeout — we only need the key exchange
    let handle = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client::connect(ssh_config, &addr, handler),
    )
    .await
    .map_err(|_| TunnelError::Ssh(0, format!("timeout probing host key for {}", addr)))?
    .map_err(|e| TunnelError::Ssh(0, format!("failed to probe host key for {}: {}", addr, e)))?;

    // Disconnect cleanly
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await;

    let result = captured
        .lock()
        .await
        .take()
        .ok_or_else(|| TunnelError::Ssh(0, format!("no host key received from {}", addr)));
    result
}

/// Start a multi-hop SSH tunnel chain.
///
/// Each hop connects through the previous hop's local listener.
/// Returns the full Vec of tunnels and the final local address
/// that guacd should connect to.
pub async fn start_chain(
    hops: &[JumpHost],
    target_host: &str,
    target_port: u16,
) -> Result<(Vec<SshTunnel>, SocketAddr), TunnelError> {
    let mut tunnels: Vec<SshTunnel> = Vec::with_capacity(hops.len());

    for (i, hop) in hops.iter().enumerate() {
        // Determine what this hop's SSH connects to
        let connect_host;
        let connect_port;
        if i == 0 {
            // First hop connects directly to its hostname
            connect_host = hop.hostname.clone();
            connect_port = hop.port;
        } else {
            // Subsequent hops connect through the previous tunnel's local listener
            let prev_addr = tunnels[i - 1].local_addr;
            connect_host = prev_addr.ip().to_string();
            connect_port = prev_addr.port();
        }

        // Determine the direct-tcpip target for this hop
        let fwd_host;
        let fwd_port;
        if i + 1 < hops.len() {
            // Not the last hop — forward to the next hop
            fwd_host = hops[i + 1].hostname.clone();
            fwd_port = hops[i + 1].port;
        } else {
            // Last hop — forward to the real target
            fwd_host = target_host.to_string();
            fwd_port = target_port;
        }

        let config = TunnelConfig {
            jump_host: connect_host,
            jump_port: connect_port,
            jump_username: hop.username.clone(),
            jump_password: hop.password.clone(),
            jump_private_key: hop.private_key.clone(),
            target_host: fwd_host,
            target_port: fwd_port,
            expected_host_key: hop.host_key.clone(),
        };

        let tunnel = start(config, i).await?;

        tracing::info!(
            hop = i,
            local_addr = %tunnel.local_addr,
            jump_host = %hop.hostname,
            "SSH tunnel hop established"
        );

        tunnels.push(tunnel);
    }

    let final_addr = tunnels
        .last()
        .expect("start_chain called with empty hops")
        .local_addr;

    Ok((tunnels, final_addr))
}

/// Shut down a chain of tunnels in reverse order (last hop first).
pub fn shutdown_chain(tunnels: &[SshTunnel]) {
    for tunnel in tunnels.iter().rev() {
        tunnel.shutdown();
    }
}

/// Start an SSH tunnel. Returns the tunnel handle with the local address.
pub async fn start(config: TunnelConfig, hop_index: usize) -> Result<SshTunnel, TunnelError> {
    let jump_addr = format!("{}:{}", config.jump_host, config.jump_port);

    // Connect to the jump host
    let ssh_config = Arc::new(client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(300)),
        keepalive_interval: Some(std::time::Duration::from_secs(30)),
        ..Default::default()
    });

    let handler = TunnelHandler {
        expected_key: config.expected_host_key,
        hop_index,
        jump_host: jump_addr.clone(),
    };

    let mut handle = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        client::connect(ssh_config, &jump_addr, handler),
    )
    .await
    .map_err(|_| {
        TunnelError::Ssh(
            hop_index,
            format!("timeout connecting to jump host {}", jump_addr),
        )
    })?
    .map_err(|e| {
        TunnelError::Ssh(
            hop_index,
            format!("failed to connect to jump host {}: {}", jump_addr, e),
        )
    })?;

    tracing::debug!(hop = hop_index, "SSH connected to jump host {}", jump_addr);

    // Authenticate: try private key first, then password
    let auth_result = if let Some(ref key_pem) = config.jump_private_key {
        let private_key = russh::keys::decode_secret_key(key_pem, None).map_err(|e| {
            TunnelError::Key(hop_index, format!("failed to decode private key: {}", e))
        })?;
        let key = PrivateKeyWithHashAlg::new(Arc::new(private_key), None);
        handle
            .authenticate_publickey(&config.jump_username, key)
            .await
            .map_err(|e| TunnelError::Auth(hop_index, format!("public key auth error: {}", e)))?
    } else if let Some(ref password) = config.jump_password {
        handle
            .authenticate_password(&config.jump_username, password)
            .await
            .map_err(|e| TunnelError::Auth(hop_index, format!("password auth error: {}", e)))?
    } else {
        return Err(TunnelError::Auth(
            hop_index,
            "no password or private key provided for jump host".into(),
        ));
    };

    if !auth_result.success() {
        return Err(TunnelError::Auth(
            hop_index,
            format!(
                "authentication failed for {}@{}",
                config.jump_username, jump_addr
            ),
        ));
    }

    tracing::debug!(
        hop = hop_index,
        "SSH authenticated to jump host {} as {}",
        jump_addr,
        config.jump_username
    );

    // Bind a local TCP listener on an OS-assigned port
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
        TunnelError::Bind(hop_index, format!("failed to bind local listener: {}", e))
    })?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| TunnelError::Bind(hop_index, format!("failed to get local address: {}", e)))?;

    tracing::info!(
        "SSH tunnel listening on {} -> {}:{} via {}",
        local_addr,
        config.target_host,
        config.target_port,
        jump_addr
    );

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let target_host = config.target_host;
    let target_port = config.target_port;

    let join_handle = tokio::spawn(async move {
        tunnel_task(handle, listener, target_host, target_port, cancel_clone).await;
    });

    Ok(SshTunnel {
        local_addr,
        cancel,
        _join_handle: join_handle,
    })
}

/// Background task: accept TCP connections and bridge through SSH channels.
async fn tunnel_task(
    handle: client::Handle<TunnelHandler>,
    listener: TcpListener,
    target_host: String,
    target_port: u16,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("SSH tunnel cancelled, shutting down");
                break;
            }
            result = listener.accept() => {
                let (tcp_stream, peer) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("SSH tunnel listener accept error: {}", e);
                        continue;
                    }
                };

                tracing::debug!(
                    peer = %peer,
                    target = %format!("{}:{}", target_host, target_port),
                    "SSH tunnel: new connection"
                );

                let channel = match handle.channel_open_direct_tcpip(
                    target_host.clone(),
                    target_port as u32,
                    "127.0.0.1",
                    0,
                ).await {
                    Ok(ch) => ch,
                    Err(e) => {
                        tracing::warn!("SSH tunnel: failed to open direct-tcpip channel: {}", e);
                        continue;
                    }
                };

                // Bridge TCP <-> SSH channel in a background task
                tokio::spawn(async move {
                    let mut ch_stream = channel.into_stream();
                    let mut tcp = tcp_stream;
                    match tokio::io::copy_bidirectional(&mut tcp, &mut ch_stream).await {
                        Ok((tx, rx)) => {
                            tracing::debug!(
                                peer = %peer,
                                tx_bytes = tx,
                                rx_bytes = rx,
                                "SSH tunnel: connection closed"
                            );
                        }
                        Err(e) => {
                            tracing::debug!(peer = %peer, error = %e, "SSH tunnel: connection error");
                        }
                    }
                });
            }
        }
    }

    // Dropping the handle closes the SSH session
    tracing::debug!("SSH tunnel task exiting");
}
