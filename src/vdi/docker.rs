//! Docker-based VDI driver using bollard (unix socket).

use super::{ContainerInfo, ContainerSpec, VdiDriver, VdiError};
use bollard::container::{
    Config as ContainerConfig, CreateContainerOptions, ListContainersOptions,
    RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
};
use bollard::exec::CreateExecOptions;
use bollard::models::{HostConfig, PortBinding};
use bollard::Docker;
use std::collections::HashMap;
use std::time::Duration;

/// Docker-based VDI driver. Connects to the local Docker daemon via unix socket.
pub struct DockerDriver {
    client: Docker,
    ready_timeout: Duration,
}

impl DockerDriver {
    /// Connect to the Docker daemon.
    pub fn new(socket_path: &str) -> Result<Self, VdiError> {
        let client = if socket_path == "/var/run/docker.sock" {
            Docker::connect_with_socket_defaults()
        } else {
            Docker::connect_with_socket(socket_path, 120, bollard::API_DEFAULT_VERSION)
        }
        .map_err(|e| VdiError::Docker(format!("failed to connect to Docker socket: {}", e)))?;

        Ok(Self {
            client,
            ready_timeout: Duration::from_secs(30),
        })
    }

    /// Set the timeout for waiting for xrdp readiness.
    pub fn with_ready_timeout(mut self, secs: u64) -> Self {
        self.ready_timeout = Duration::from_secs(secs);
        self
    }

    /// Sanitize a username into a valid Docker container name suffix.
    fn sanitize_username(username: &str) -> String {
        username
            .to_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>()
            .trim_matches('-')
            .to_string()
    }

    /// Container name for a given username.
    fn container_name(username: &str) -> String {
        format!("rustguac-vdi-{}", Self::sanitize_username(username))
    }

    /// Extract the host-mapped port for container port 3389/tcp from inspect data.
    fn extract_mapped_port(
        inspect: &bollard::models::ContainerInspectResponse,
    ) -> Result<u16, VdiError> {
        let network = inspect
            .network_settings
            .as_ref()
            .and_then(|ns| ns.ports.as_ref())
            .and_then(|ports| ports.get("3389/tcp"))
            .and_then(|bindings| bindings.as_ref())
            .and_then(|bindings| bindings.first())
            .and_then(|b| b.host_port.as_ref())
            .ok_or_else(|| VdiError::Docker("no port mapping found for 3389/tcp".into()))?;

        network
            .parse::<u16>()
            .map_err(|e| VdiError::Docker(format!("invalid mapped port '{}': {}", network, e)))
    }

    /// Poll until xrdp is accepting connections.
    /// After TCP connect succeeds, waits a few seconds for xrdp to finish
    /// loading TLS certs and complete initialization.
    async fn wait_for_ready(&self, host: &str, port: u16) -> Result<(), VdiError> {
        let deadline = tokio::time::Instant::now() + self.ready_timeout;
        let addr = format!("{}:{}", host, port);

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(VdiError::Timeout(format!(
                    "xrdp not ready on {} after {}s",
                    addr,
                    self.ready_timeout.as_secs()
                )));
            }
            match tokio::net::TcpStream::connect(&addr).await {
                Ok(_) => {
                    // xrdp binds the port before fully initializing —
                    // give it time to load TLS certs and start the listener loop
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    return Ok(());
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }
    }
}

impl VdiDriver for DockerDriver {
    fn start_or_reuse<'a>(
        &'a self,
        spec: &'a ContainerSpec,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ContainerInfo, VdiError>> + Send + 'a>> {
        Box::pin(self.do_start_or_reuse(spec))
    }

    fn stop_container<'a>(
        &'a self,
        container_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), VdiError>> + Send + 'a>> {
        Box::pin(self.do_stop_container(container_id))
    }

    fn health_check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), VdiError>> + Send + '_>> {
        Box::pin(self.do_health_check())
    }

    fn list_managed_containers(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<String>, VdiError>> + Send + '_>> {
        Box::pin(self.do_list_managed_containers())
    }

    fn list_managed_containers_detail(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<super::ManagedContainer>, VdiError>> + Send + '_>> {
        Box::pin(self.do_list_managed_containers_detail())
    }
}

impl DockerDriver {
    /// Update the user password inside a running container via `chpasswd`.
    /// Update user password inside a running container.
    async fn update_container_password(
        &self,
        container: &str,
        username: &str,
        password: &str,
    ) -> Result<(), VdiError> {
        // Defence in depth: reject anything that could break the shell command.
        // Username is pre-sanitized to [a-z0-9_] and password is hex-only,
        // but validate here as a safety net.
        if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(VdiError::Docker("invalid characters in username".into()));
        }
        if !password.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(VdiError::Docker("invalid characters in password".into()));
        }
        let exec = self
            .client
            .create_exec(
                container,
                CreateExecOptions {
                    cmd: Some(vec![
                        "sh",
                        "-c",
                        &format!("printf '%s:%s' '{}' '{}' | chpasswd", username, password),
                    ]),
                    attach_stdout: Some(false),
                    attach_stderr: Some(false),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| VdiError::Docker(format!("failed to create exec for chpasswd: {}", e)))?;

        self.client
            .start_exec(&exec.id, None)
            .await
            .map_err(|e| VdiError::Docker(format!("failed to exec chpasswd: {}", e)))?;

        Ok(())
    }

    async fn do_start_or_reuse(&self, spec: &ContainerSpec) -> Result<ContainerInfo, VdiError> {
        let name = Self::container_name(&spec.username);

        // Check if container already exists
        match self.client.inspect_container(&name, None).await {
            Ok(inspect) => {
                // Check if the image changed — if so, replace the container
                let existing_image = inspect
                    .config
                    .as_ref()
                    .and_then(|c| c.image.as_deref())
                    .unwrap_or("");
                if existing_image != spec.image {
                    tracing::info!(
                        container = %name,
                        old_image = %existing_image,
                        new_image = %spec.image,
                        "VDI image changed — replacing container"
                    );
                    let cid = inspect.id.as_deref().unwrap_or(&name);
                    let _ = self.do_stop_container(cid).await;
                    // Container removed — recurse to create fresh
                    return Box::pin(self.do_start_or_reuse(spec)).await;
                }

                let running = inspect
                    .state
                    .as_ref()
                    .and_then(|s| s.running)
                    .unwrap_or(false);

                if running {
                    // Container is running — reuse it, but update password
                    let port = Self::extract_mapped_port(&inspect)?;
                    self.update_container_password(&name, &spec.username, &spec.password)
                        .await?;
                    tracing::info!(
                        container = %name,
                        port,
                        "Reusing existing VDI container"
                    );
                    return Ok(ContainerInfo {
                        container_id: inspect.id.unwrap_or_default(),
                        rdp_host: "127.0.0.1".into(),
                        rdp_port: port,
                        reused: true,
                    });
                }

                // Container exists but stopped — start it
                tracing::info!(container = %name, "Starting stopped VDI container");
                self.client
                    .start_container(&name, None::<StartContainerOptions<String>>)
                    .await
                    .map_err(|e| VdiError::Docker(format!("failed to start container: {}", e)))?;

                // Re-inspect to get port mapping
                let inspect = self
                    .client
                    .inspect_container(&name, None)
                    .await
                    .map_err(|e| {
                        VdiError::Docker(format!("failed to inspect after start: {}", e))
                    })?;
                let port = Self::extract_mapped_port(&inspect)?;
                self.wait_for_ready("127.0.0.1", port).await?;
                self.update_container_password(&name, &spec.username, &spec.password)
                    .await?;

                Ok(ContainerInfo {
                    container_id: inspect.id.unwrap_or_default(),
                    rdp_host: "127.0.0.1".into(),
                    rdp_port: port,
                    reused: true,
                })
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {
                // Container doesn't exist — create it
                tracing::info!(
                    container = %name,
                    image = %spec.image,
                    "Creating new VDI container"
                );

                // Build environment variables
                let mut env_vec: Vec<String> = vec![
                    format!("VDI_USERNAME={}", spec.username),
                    format!("VDI_PASSWORD={}", spec.password),
                ];
                for (k, v) in &spec.env {
                    // Validate env var names (alphanumeric + underscore only)
                    if !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                        return Err(VdiError::Docker(format!(
                            "invalid environment variable name: {}",
                            k
                        )));
                    }
                    // Reject values with newlines (could inject additional env vars)
                    if v.contains('\n') || v.contains('\r') {
                        return Err(VdiError::Docker(format!(
                            "environment variable '{}' contains newline",
                            k
                        )));
                    }
                    env_vec.push(format!("{}={}", k, v));
                }

                // Port binding: 3389/tcp → random host port
                let mut port_bindings = HashMap::new();
                port_bindings.insert(
                    "3389/tcp".to_string(),
                    Some(vec![PortBinding {
                        host_ip: Some("127.0.0.1".into()),
                        host_port: Some("0".into()), // random port
                    }]),
                );

                // Labels
                let mut labels = HashMap::new();
                labels.insert("rustguac.managed".to_string(), "true".to_string());
                labels.insert("rustguac.username".to_string(), spec.username.clone());
                if let Some(ref entry_key) = spec.entry_key {
                    labels.insert("rustguac.entry".to_string(), entry_key.clone());
                }
                if let Some(timeout) = spec.idle_timeout_mins {
                    labels.insert("rustguac.idle_timeout_mins".to_string(), timeout.to_string());
                }
                labels.insert("rustguac.image".to_string(), spec.image.clone());

                // Resource limits
                let nano_cpus = if spec.cpu_limit > 0.0 {
                    Some((spec.cpu_limit * 1_000_000_000.0) as i64)
                } else {
                    None
                };
                let memory = if spec.memory_limit > 0 {
                    Some(spec.memory_limit as i64)
                } else {
                    None
                };

                // Persistent home directory bind mount
                let binds = if let Some(ref base) = spec.home_base {
                    let base_path = std::path::Path::new(base);
                    let host_path = base_path.join(&spec.username);
                    // Verify no path traversal (username is sanitized but belt-and-suspenders)
                    if !host_path.starts_with(base_path) {
                        return Err(VdiError::Docker("path traversal in home_base".into()));
                    }
                    // Ensure host directory exists
                    if let Err(e) = std::fs::create_dir_all(&host_path) {
                        tracing::warn!(path = ?host_path, "Failed to create VDI home dir: {}", e);
                    }
                    let mount = format!("{}:/home/{}", host_path.display(), spec.username);
                    tracing::info!(mount = %mount, "VDI home directory bind mount");
                    Some(vec![mount])
                } else {
                    None
                };

                let host_config = HostConfig {
                    port_bindings: Some(port_bindings),
                    nano_cpus,
                    memory,
                    binds,
                    ..Default::default()
                };

                let config = ContainerConfig {
                    image: Some(spec.image.clone()),
                    env: Some(env_vec),
                    labels: Some(labels),
                    host_config: Some(host_config),
                    ..Default::default()
                };

                let opts = CreateContainerOptions {
                    name: name.clone(),
                    ..Default::default()
                };

                let created = self
                    .client
                    .create_container(Some(opts), config)
                    .await
                    .map_err(|e| VdiError::Docker(format!("failed to create container: {}", e)))?;

                self.client
                    .start_container(&name, None::<StartContainerOptions<String>>)
                    .await
                    .map_err(|e| VdiError::Docker(format!("failed to start container: {}", e)))?;

                // Inspect to get the mapped port
                let inspect = self
                    .client
                    .inspect_container(&name, None)
                    .await
                    .map_err(|e| {
                        VdiError::Docker(format!("failed to inspect after create: {}", e))
                    })?;
                let port = Self::extract_mapped_port(&inspect)?;
                self.wait_for_ready("127.0.0.1", port).await?;

                tracing::info!(
                    container = %name,
                    container_id = %created.id,
                    port,
                    "VDI container ready"
                );

                Ok(ContainerInfo {
                    container_id: created.id,
                    rdp_host: "127.0.0.1".into(),
                    rdp_port: port,
                    reused: false,
                })
            }
            Err(e) => Err(VdiError::Docker(format!(
                "failed to inspect container: {}",
                e
            ))),
        }
    }

    async fn do_stop_container(&self, container_id: &str) -> Result<(), VdiError> {
        // Stop with 5s grace period
        let _ = self
            .client
            .stop_container(
                container_id,
                Some(StopContainerOptions { t: 5 }),
            )
            .await;

        // Force remove
        self.client
            .remove_container(
                container_id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| VdiError::Docker(format!("failed to remove container: {}", e)))?;

        Ok(())
    }

    #[allow(dead_code)]
    async fn do_health_check(&self) -> Result<(), VdiError> {
        self.client
            .ping()
            .await
            .map_err(|e| VdiError::Docker(format!("Docker ping failed: {}", e)))?;
        Ok(())
    }

    #[allow(dead_code)]
    async fn do_list_managed_containers(&self) -> Result<Vec<String>, VdiError> {
        let mut filters = HashMap::new();
        filters.insert("label", vec!["rustguac.managed=true"]);

        let opts = ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        };

        let containers = self
            .client
            .list_containers(Some(opts))
            .await
            .map_err(|e| VdiError::Docker(format!("failed to list containers: {}", e)))?;

        Ok(containers
            .into_iter()
            .filter_map(|c| c.id)
            .collect())
    }

    async fn do_list_managed_containers_detail(&self) -> Result<Vec<super::ManagedContainer>, VdiError> {
        let mut filters = HashMap::new();
        filters.insert("label", vec!["rustguac.managed=true"]);

        let opts = ListContainersOptions {
            all: false, // only running containers
            filters,
            ..Default::default()
        };

        let containers = self
            .client
            .list_containers(Some(opts))
            .await
            .map_err(|e| VdiError::Docker(format!("failed to list containers: {}", e)))?;

        Ok(containers
            .into_iter()
            .map(|c| {
                let labels = c.labels.unwrap_or_default();
                let names = c.names.unwrap_or_default();
                let container_name = names
                    .first()
                    .map(|n| n.trim_start_matches('/').to_string())
                    .unwrap_or_default();
                super::ManagedContainer {
                    container_id: c.id.unwrap_or_default(),
                    container_name,
                    username: labels.get("rustguac.username").cloned().unwrap_or_default(),
                    image: labels.get("rustguac.image").cloned()
                        .or_else(|| c.image.clone())
                        .unwrap_or_default(),
                    entry_key: labels.get("rustguac.entry").cloned(),
                    thumbnail_url: None, // populated by API layer
                    has_active_session: false, // populated by API layer
                    idle_timeout_mins: labels
                        .get("rustguac.idle_timeout_mins")
                        .and_then(|v| v.parse().ok()),
                }
            })
            .collect())
    }
}
