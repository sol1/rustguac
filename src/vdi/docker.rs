//! Docker-based VDI driver using bollard (unix socket).

use super::{ContainerInfo, ContainerSpec, VdiDriver, VdiError};
use bollard::exec::CreateExecOptions;
use bollard::models::{ContainerCreateBody, HostConfig, PortBinding};
use bollard::query_parameters::{
    CreateContainerOptions, ListContainersOptions, RemoveContainerOptions, StartContainerOptions,
    StopContainerOptions,
};
use bollard::Docker;
use std::collections::HashMap;
use std::time::Duration;
use tokio::process::Command;

/// Docker-based VDI driver. Connects to the local Docker daemon via unix socket.
pub struct DockerDriver {
    client: Docker,
    ready_timeout: Duration,
    host_port_range: Option<(u16, u16)>,
    container_hook_script: Option<String>,
    container_hook_timeout: Duration,
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
            host_port_range: None,
            container_hook_script: None,
            container_hook_timeout: Duration::from_secs(10),
        })
    }

    /// Set the timeout for waiting for xrdp readiness.
    pub fn with_ready_timeout(mut self, secs: u64) -> Self {
        self.ready_timeout = Duration::from_secs(secs);
        self
    }

    /// Restrict Docker's published host port for RDP to an inclusive range.
    pub fn with_host_port_range(mut self, start: u16, end: u16) -> Result<Self, VdiError> {
        if start == 0 || start > end {
            return Err(VdiError::Docker(format!(
                "invalid VDI port range: {}-{}",
                start, end
            )));
        }
        self.host_port_range = Some((start, end));
        Ok(self)
    }

    /// Configure an external VDI container hook script.
    pub fn with_container_hook(mut self, script: Option<String>, timeout_secs: u64) -> Self {
        self.container_hook_script = script.filter(|s| !s.trim().is_empty());
        self.container_hook_timeout = Duration::from_secs(timeout_secs.max(1));
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

    /// Candidate host ports to ask Docker to bind. Without a configured range,
    /// `0` preserves Docker's default random-port allocation.
    fn host_port_candidates(host_port_range: Option<(u16, u16)>, username: &str) -> Vec<String> {
        let Some((start, end)) = host_port_range else {
            return vec!["0".into()];
        };

        let len = end as u32 - start as u32 + 1;
        let hash = username.bytes().fold(0xcbf29ce484222325_u64, |hash, b| {
            hash.wrapping_mul(0x100000001b3) ^ b as u64
        });
        let offset = (hash % len as u64) as u32;

        (0..len)
            .map(|i| {
                let port = start as u32 + ((offset + i) % len);
                port.to_string()
            })
            .collect()
    }

    fn port_in_configured_range(&self, port: u16) -> bool {
        match self.host_port_range {
            Some((start, end)) => (start..=end).contains(&port),
            None => true,
        }
    }

    fn extract_container_name(
        inspect: &bollard::models::ContainerInspectResponse,
        fallback: &str,
    ) -> String {
        inspect
            .name
            .as_deref()
            .unwrap_or(fallback)
            .trim_start_matches('/')
            .to_string()
    }

    async fn run_container_hook(
        &self,
        action: &str,
        port: u16,
        container_id: &str,
        container_name: &str,
    ) -> Result<(), VdiError> {
        let Some(script) = self.container_hook_script.as_deref() else {
            return Ok(());
        };

        let mut child = Command::new(script);
        child
            .arg(action)
            .arg(port.to_string())
            .arg(container_id)
            .arg(container_name)
            .env("RUSTGUAC_VDI_HOOK_ACTION", action)
            .env("RUSTGUAC_VDI_PORT", port.to_string())
            .env("RUSTGUAC_VDI_CONTAINER_ID", container_id)
            .env("RUSTGUAC_VDI_CONTAINER_NAME", container_name);

        let output = tokio::time::timeout(self.container_hook_timeout, child.output())
            .await
            .map_err(|_| {
                VdiError::Timeout(format!(
                    "VDI container hook '{}' timed out after {}s",
                    script,
                    self.container_hook_timeout.as_secs()
                ))
            })?
            .map_err(|e| {
                VdiError::Docker(format!(
                    "failed to run VDI container hook '{}': {}",
                    script, e
                ))
            })?;

        if output.status.success() {
            tracing::info!(
                hook = %script,
                action,
                port,
                container = %container_name,
                "VDI container hook completed"
            );
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(VdiError::Docker(format!(
            "VDI container hook '{}' failed for action '{}' with status {}{}{}",
            script,
            action,
            output.status,
            if stdout.trim().is_empty() {
                String::new()
            } else {
                format!("; stdout: {}", stdout.trim())
            },
            if stderr.trim().is_empty() {
                String::new()
            } else {
                format!("; stderr: {}", stderr.trim())
            }
        )))
    }

    async fn prepare_rdp_endpoint(
        &self,
        port: u16,
        container_id: &str,
        container_name: &str,
    ) -> Result<(), VdiError> {
        self.run_container_hook("up", port, container_id, container_name)
            .await?;
        self.wait_for_ready("127.0.0.1", port).await
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
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ContainerInfo, VdiError>> + Send + 'a>,
    > {
        Box::pin(self.do_start_or_reuse(spec))
    }

    fn stop_container<'a>(
        &'a self,
        container_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), VdiError>> + Send + 'a>>
    {
        Box::pin(self.do_stop_container(container_id))
    }

    fn health_check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), VdiError>> + Send + '_>>
    {
        Box::pin(self.do_health_check())
    }

    fn list_managed_containers(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<String>, VdiError>> + Send + '_>,
    > {
        Box::pin(self.do_list_managed_containers())
    }

    fn list_managed_containers_detail(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Vec<super::ManagedContainer>, VdiError>>
                + Send
                + '_,
        >,
    > {
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
        if !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
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
                    let container_id = inspect.id.as_deref().unwrap_or(&name).to_string();
                    let container_name = Self::extract_container_name(&inspect, &name);
                    if !self.port_in_configured_range(port) {
                        tracing::info!(
                            container = %name,
                            port,
                            "VDI container port is outside configured range — replacing container"
                        );
                        let cid = inspect.id.as_deref().unwrap_or(&name);
                        let _ = self.do_stop_container(cid).await;
                        return Box::pin(self.do_start_or_reuse(spec)).await;
                    }
                    self.update_container_password(&name, &spec.username, &spec.password)
                        .await?;
                    tracing::info!(
                        container = %name,
                        port,
                        "Reusing existing VDI container"
                    );
                    if let Err(e) = self
                        .prepare_rdp_endpoint(port, &container_id, &container_name)
                        .await
                    {
                        if self.host_port_range.is_some() {
                            tracing::warn!(
                                container = %name,
                                port,
                                "Reused VDI container endpoint failed; replacing container: {}",
                                e
                            );
                            let _ = self.do_stop_container(&container_id).await;
                            return Box::pin(self.do_start_or_reuse(spec)).await;
                        }
                        return Err(e);
                    }
                    return Ok(ContainerInfo {
                        container_id,
                        rdp_host: "127.0.0.1".into(),
                        rdp_port: port,
                        reused: true,
                    });
                }

                // Container exists but stopped — start it
                let port = Self::extract_mapped_port(&inspect)?;
                let container_id = inspect.id.as_deref().unwrap_or(&name).to_string();
                let container_name = Self::extract_container_name(&inspect, &name);
                if !self.port_in_configured_range(port) {
                    tracing::info!(
                        container = %name,
                        port,
                        "Stopped VDI container port is outside configured range — replacing container"
                    );
                    let cid = inspect.id.as_deref().unwrap_or(&name);
                    let _ = self.do_stop_container(cid).await;
                    return Box::pin(self.do_start_or_reuse(spec)).await;
                }

                // Container exists but stopped with an acceptable port — start it
                tracing::info!(container = %name, "Starting stopped VDI container");
                if let Err(e) = self
                    .client
                    .start_container(&name, None::<StartContainerOptions>)
                    .await
                {
                    if self.host_port_range.is_some() {
                        tracing::warn!(
                            container = %name,
                            port,
                            "Stopped VDI container failed to start; replacing container: {}",
                            e
                        );
                        let _ = self.do_stop_container(&container_id).await;
                        return Box::pin(self.do_start_or_reuse(spec)).await;
                    }
                    return Err(VdiError::Docker(format!(
                        "failed to start container: {}",
                        e
                    )));
                }

                if let Err(e) = self
                    .prepare_rdp_endpoint(port, &container_id, &container_name)
                    .await
                {
                    if self.host_port_range.is_some() {
                        tracing::warn!(
                            container = %name,
                            port,
                            "Started VDI container endpoint failed; replacing container: {}",
                            e
                        );
                        let _ = self.do_stop_container(&container_id).await;
                        return Box::pin(self.do_start_or_reuse(spec)).await;
                    }
                    return Err(e);
                }
                self.update_container_password(&name, &spec.username, &spec.password)
                    .await?;

                Ok(ContainerInfo {
                    container_id,
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

                // Labels
                let mut labels = HashMap::new();
                labels.insert("rustguac.managed".to_string(), "true".to_string());
                labels.insert("rustguac.username".to_string(), spec.username.clone());
                if let Some(ref entry_key) = spec.entry_key {
                    labels.insert("rustguac.entry".to_string(), entry_key.clone());
                }
                if let Some(timeout) = spec.idle_timeout_mins {
                    labels.insert(
                        "rustguac.idle_timeout_mins".to_string(),
                        timeout.to_string(),
                    );
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
                    let mount = format!(
                        "{}:/home/{}:nosuid,nodev",
                        host_path.display(),
                        spec.username
                    );
                    tracing::info!(mount = %mount, "VDI home directory bind mount");
                    Some(vec![mount])
                } else {
                    None
                };

                let mut last_error = None;
                for host_port in Self::host_port_candidates(self.host_port_range, &spec.username) {
                    // Port binding: 3389/tcp → selected localhost host port.
                    // A configured range uses explicit ports; no range uses
                    // Docker's random allocation via host port 0.
                    let mut port_bindings = HashMap::new();
                    port_bindings.insert(
                        "3389/tcp".to_string(),
                        Some(vec![PortBinding {
                            host_ip: Some("127.0.0.1".into()),
                            host_port: Some(host_port.clone()),
                        }]),
                    );

                    let host_config = HostConfig {
                        port_bindings: Some(port_bindings),
                        nano_cpus,
                        memory,
                        binds: binds.clone(),
                        ..Default::default()
                    };

                    let config = ContainerCreateBody {
                        image: Some(spec.image.clone()),
                        env: Some(env_vec.clone()),
                        labels: Some(labels.clone()),
                        host_config: Some(host_config),
                        ..Default::default()
                    };

                    let opts = CreateContainerOptions {
                        name: Some(name.clone()),
                        ..Default::default()
                    };

                    let created = match self.client.create_container(Some(opts), config).await {
                        Ok(created) => created,
                        Err(e) => {
                            last_error = Some(format!("failed to create container: {}", e));
                            break;
                        }
                    };

                    if let Err(e) = self
                        .client
                        .start_container(&name, None::<StartContainerOptions>)
                        .await
                    {
                        last_error = Some(format!(
                            "failed to start container with host port {}: {}",
                            host_port, e
                        ));
                        let _ = self.do_stop_container(&created.id).await;
                        if self.host_port_range.is_some() {
                            continue;
                        }
                        break;
                    }

                    // Inspect to get the mapped port
                    let inspect =
                        self.client
                            .inspect_container(&name, None)
                            .await
                            .map_err(|e| {
                                VdiError::Docker(format!("failed to inspect after create: {}", e))
                            })?;
                    let port = Self::extract_mapped_port(&inspect)?;
                    let container_name = Self::extract_container_name(&inspect, &name);
                    if let Err(e) = self
                        .prepare_rdp_endpoint(port, &created.id, &container_name)
                        .await
                    {
                        last_error = Some(format!(
                            "failed to prepare VDI endpoint with host port {}: {}",
                            port, e
                        ));
                        let _ = self.do_stop_container(&created.id).await;
                        if self.host_port_range.is_some() {
                            continue;
                        }
                        break;
                    }

                    tracing::info!(
                        container = %name,
                        container_id = %created.id,
                        port,
                        "VDI container ready"
                    );

                    return Ok(ContainerInfo {
                        container_id: created.id,
                        rdp_host: "127.0.0.1".into(),
                        rdp_port: port,
                        reused: false,
                    });
                }

                Err(VdiError::Docker(last_error.unwrap_or_else(|| {
                    "failed to allocate a VDI host port".into()
                })))
            }
            Err(e) => Err(VdiError::Docker(format!(
                "failed to inspect container: {}",
                e
            ))),
        }
    }

    async fn do_stop_container(&self, container_id: &str) -> Result<(), VdiError> {
        let hook_info = match self.client.inspect_container(container_id, None).await {
            Ok(inspect) => {
                let port = Self::extract_mapped_port(&inspect).ok();
                let name = Self::extract_container_name(&inspect, container_id);
                port.map(|port| (port, name))
            }
            Err(e) => {
                tracing::debug!(
                    container_id,
                    "Skipping VDI container hook teardown; inspect failed: {}",
                    e
                );
                None
            }
        };

        if let Some((port, name)) = hook_info {
            if let Err(e) = self
                .run_container_hook("down", port, container_id, &name)
                .await
            {
                tracing::warn!(
                    container_id,
                    container = %name,
                    port,
                    "VDI container hook teardown failed: {}",
                    e
                );
            }
        }

        // Stop with 5s grace period
        let _ = self
            .client
            .stop_container(
                container_id,
                Some(StopContainerOptions {
                    t: Some(5),
                    signal: Default::default(),
                }),
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
        filters.insert(
            "label".to_string(),
            vec!["rustguac.managed=true".to_string()],
        );

        let opts = ListContainersOptions {
            all: true,
            filters: Some(filters),
            ..Default::default()
        };

        let containers = self
            .client
            .list_containers(Some(opts))
            .await
            .map_err(|e| VdiError::Docker(format!("failed to list containers: {}", e)))?;

        Ok(containers.into_iter().filter_map(|c| c.id).collect())
    }

    async fn do_list_managed_containers_detail(
        &self,
    ) -> Result<Vec<super::ManagedContainer>, VdiError> {
        let mut filters = HashMap::new();
        filters.insert(
            "label".to_string(),
            vec!["rustguac.managed=true".to_string()],
        );

        let opts = ListContainersOptions {
            all: false, // only running containers
            filters: Some(filters),
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
                    image: labels
                        .get("rustguac.image")
                        .cloned()
                        .or_else(|| c.image.clone())
                        .unwrap_or_default(),
                    entry_key: labels.get("rustguac.entry").cloned(),
                    thumbnail_url: None,       // populated by API layer
                    has_active_session: false, // populated by API layer
                    idle_timeout_mins: labels
                        .get("rustguac.idle_timeout_mins")
                        .and_then(|v| v.parse().ok()),
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sanitization invariants: output must be safe for use as a Docker
    // container-name suffix (Docker requires `[a-zA-Z0-9_.-]` and must not
    // start/end with `-`). A hostile OIDC IdP should not be able to collide
    // one user's container with another, escape the name prefix, or
    // inject a separator.

    fn san(s: &str) -> String {
        DockerDriver::sanitize_username(s)
    }

    #[test]
    fn sanitize_username_lowercases() {
        assert_eq!(san("Alice"), "alice");
        assert_eq!(san("BOB"), "bob");
    }

    #[test]
    fn sanitize_username_replaces_specials_with_dash() {
        // Each non-alphanumeric char maps 1:1 to '-' (no collapsing).
        // That's still Docker-safe — interior `--` is legal; only leading/
        // trailing dashes are disallowed and those are trimmed below.
        assert_eq!(san("alice.bob"), "alice-bob");
        assert_eq!(san("alice@corp"), "alice-corp");
        assert_eq!(san("a b"), "a-b");
        assert_eq!(san("a$b"), "a-b");
        assert_eq!(san("a/b"), "a-b");
        assert_eq!(san("a\\b"), "a-b");
        // Two consecutive specials → two dashes (no collapse).
        assert_eq!(san("a..b"), "a--b");
        assert_eq!(san("a@@b"), "a--b");
    }

    #[test]
    fn sanitize_username_strips_leading_trailing_dashes() {
        // Leading/trailing specials collapse then trim — required because
        // Docker rejects names starting with `-`.
        assert_eq!(san("--alice--"), "alice");
        assert_eq!(san("@alice@"), "alice");
        assert_eq!(san(".alice."), "alice");
    }

    #[test]
    fn sanitize_username_drops_unicode() {
        // `is_ascii_alphanumeric` is strict — unicode homoglyphs collapse.
        assert_eq!(san("café"), "caf");
        // Cyrillic 'а' → non-ASCII, becomes dash then trimmed.
        assert_eq!(san("аlice"), "lice");
    }

    #[test]
    fn sanitize_username_collapses_to_empty() {
        // Pathological input: nothing ascii-alphanumeric. Output is empty
        // (which would produce `rustguac-vdi-` — an invalid Docker name).
        // Documented here so the caller knows to reject empty output if it
        // ever matters (currently login requires a non-empty OIDC `sub`).
        assert_eq!(san("@@@"), "");
        assert_eq!(san(""), "");
        assert_eq!(san("___"), "");
    }

    #[test]
    fn sanitize_username_collision_resistant_on_ascii() {
        // Two different ascii-alphanumeric usernames must not collide.
        assert_ne!(san("alice"), san("bob"));
        assert_ne!(san("alice1"), san("alice2"));
    }

    #[test]
    fn sanitize_username_preserves_digits_and_underscore_dropped() {
        // Digits survive; underscore is NOT alphanumeric per the map() and
        // becomes a dash (so `a_b` and `a-b` both collapse to `a-b`).
        assert_eq!(san("bench001"), "bench001");
        assert_eq!(san("a_b"), "a-b");
        assert_eq!(san("a-b"), "a-b");
    }

    #[test]
    fn container_name_prefix_enforced() {
        // Container name must always start with the fixed prefix so a
        // hostile username can't pretend to be someone else's container.
        assert!(DockerDriver::container_name("alice").starts_with("rustguac-vdi-"));
        assert!(DockerDriver::container_name("@@@").starts_with("rustguac-vdi-"));
        assert_eq!(DockerDriver::container_name("alice"), "rustguac-vdi-alice");
    }

    #[test]
    fn container_name_no_newlines_or_shell_metachars() {
        // Output must not contain any character a shell or Docker CLI would
        // treat specially if the name were ever concatenated into a command.
        for input in [
            "alice\nroot",
            "alice;rm",
            "alice`id`",
            "alice$(id)",
            "alice\"quoted\"",
            "alice'quoted'",
            "alice|pipe",
            "alice&bg",
        ] {
            let name = DockerDriver::container_name(input);
            for bad in ['\n', ';', '`', '$', '\"', '\'', '|', '&', ' ', '/', '\\'] {
                assert!(
                    !name.contains(bad),
                    "container name `{}` contains {:?} for input {:?}",
                    name,
                    bad,
                    input
                );
            }
        }
    }

    #[test]
    fn host_port_candidates_defaults_to_docker_random() {
        assert_eq!(
            DockerDriver::host_port_candidates(None, "alice"),
            vec!["0".to_string()]
        );
    }

    #[test]
    fn host_port_candidates_stay_within_configured_range() {
        let ports = DockerDriver::host_port_candidates(Some((39000, 39003)), "alice");
        assert_eq!(ports.len(), 4);
        for port in ports {
            let port = port.parse::<u16>().unwrap();
            assert!((39000..=39003).contains(&port));
        }
    }

    #[test]
    fn host_port_candidates_try_each_port_once() {
        let mut ports = DockerDriver::host_port_candidates(Some((39000, 39003)), "alice");
        ports.sort();
        assert_eq!(
            ports,
            vec![
                "39000".to_string(),
                "39001".to_string(),
                "39002".to_string(),
                "39003".to_string()
            ]
        );
    }
}
