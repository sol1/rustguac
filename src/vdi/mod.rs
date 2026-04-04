//! Virtual Desktop Infrastructure (VDI) — ephemeral container sessions.
//!
//! The `VdiDriver` trait abstracts container backends. rustguac ships a Docker
//! driver; downstream forks (JumpboxVDI) can add Nomad, Proxmox, etc.

pub mod docker;

pub use docker::DockerDriver;

use std::collections::HashMap;

/// Specification for creating/reusing a container.
pub struct ContainerSpec {
    /// Docker image (e.g. "myregistry/desktop:latest").
    pub image: String,
    /// Username for the container (used in container name and VDI_USERNAME env).
    pub username: String,
    /// Generated password for RDP login (VDI_PASSWORD env).
    pub password: String,
    /// CPU limit in fractional cores (e.g. 2.0). 0 = no limit.
    pub cpu_limit: f64,
    /// Memory limit in bytes. 0 = no limit.
    pub memory_limit: u64,
    /// Extra environment variables (merged with VDI_USERNAME/VDI_PASSWORD).
    pub env: HashMap<String, String>,
    /// Host path for persistent home directory (bind mount).
    /// When set, `{home_base}/{username}` is mounted as `/home/{username}`.
    pub home_base: Option<String>,
    /// Address book entry key (e.g. "shared/folder/entry") for reconnect.
    pub entry_key: Option<String>,
}

/// Info about a managed VDI container (for the active desktops list).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ManagedContainer {
    pub container_id: String,
    pub container_name: String,
    pub username: String,
    pub image: String,
    /// Address book entry key for reconnecting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_key: Option<String>,
    /// URL to the container's thumbnail (if captured before disconnect).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
    /// Whether this container has an active session right now.
    pub has_active_session: bool,
}

/// Result of a successfully started/reused container.
pub struct ContainerInfo {
    /// Docker container ID.
    pub container_id: String,
    /// RDP host (always "127.0.0.1" for local Docker).
    pub rdp_host: String,
    /// Mapped host port for 3389/tcp.
    pub rdp_port: u16,
    /// True if an existing running container was reused.
    pub reused: bool,
}

/// Errors specific to VDI operations.
#[derive(Debug)]
pub enum VdiError {
    /// Docker API or communication error.
    Docker(String),
    /// Container started but xrdp never became ready.
    Timeout(String),
    /// Image not in the allowed list.
    ImageNotAllowed(String),
    /// VDI feature not enabled.
    NotEnabled,
}

impl std::fmt::Display for VdiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Docker(msg) => write!(f, "VDI Docker error: {}", msg),
            Self::Timeout(msg) => write!(f, "VDI ready timeout: {}", msg),
            Self::ImageNotAllowed(img) => write!(f, "VDI image not allowed: {}", img),
            Self::NotEnabled => write!(f, "VDI feature is not enabled"),
        }
    }
}

/// Trait for VDI container drivers.
///
/// The default implementation uses local Docker via bollard.
/// JumpboxVDI can implement this for Nomad, Proxmox, etc.
///
/// Uses boxed futures for dyn-compatibility (trait object dispatch).
pub trait VdiDriver: Send + Sync {
    /// Start a new container or reuse an existing one for this user.
    fn start_or_reuse<'a>(
        &'a self,
        spec: &'a ContainerSpec,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ContainerInfo, VdiError>> + Send + 'a>>;

    /// Stop and remove a container by ID.
    fn stop_container<'a>(
        &'a self,
        container_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), VdiError>> + Send + 'a>>;

    /// Check if the driver backend is reachable (e.g. Docker socket exists).
    fn health_check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), VdiError>> + Send + '_>>;

    /// List container IDs managed by rustguac (label `rustguac.managed=true`).
    fn list_managed_containers(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<String>, VdiError>> + Send + '_>>;

    /// List managed containers with full metadata (for active desktops UI).
    fn list_managed_containers_detail(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<ManagedContainer>, VdiError>> + Send + '_>>;
}
