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
    #[serde(default)]
    pub description: String,
}

/// A connection entry stored in Vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

impl From<(&str, &AddressBookEntry)> for EntryInfo {
    fn from((name, e): (&str, &AddressBookEntry)) -> Self {
        let jump_hosts = e.jump_hosts.as_ref().map(|hops| {
            hops.iter()
                .map(|h| tunnel::JumpHostInfo {
                    hostname: h.hostname.clone(),
                    port: h.port,
                    username: h.username.clone(),
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
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(config.tls_skip_verify)
            .build()
            .map_err(|e| VaultError::Auth(format!("failed to create HTTP client: {}", e)))?;

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

    /// Returns the path prefixes to scan: ["shared"] and optionally ["instance/<name>"].
    fn scope_prefixes(&self) -> Vec<(&str, String)> {
        let mut prefixes = vec![("shared", "shared".to_string())];
        if let Some(ref name) = self.instance_name {
            prefixes.push(("instance", format!("instance/{}", name)));
        }
        prefixes
    }

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

    /// List folders visible across all scopes (shared + instance).
    pub async fn list_folders(&self) -> Result<Vec<FolderInfo>, VaultError> {
        let mut folders = Vec::new();

        for (scope_label, prefix) in self.scope_prefixes() {
            let path = format!("/v1/{}/metadata/{}/{}/", self.mount, self.base_path, prefix);
            match self.kv_list(&path).await {
                Ok(keys) => {
                    for key in keys {
                        // Folder names end with "/"
                        if let Some(name) = key.strip_suffix('/') {
                            folders.push(FolderInfo {
                                name: name.to_string(),
                                description: String::new(),
                                scope: scope_label.to_string(),
                            });
                        }
                    }
                }
                Err(VaultError::NotFound) => {
                    // No folders in this scope — that's fine
                }
                Err(e) => return Err(e),
            }
        }

        // Enrich with descriptions from .config
        for folder in &mut folders {
            if let Ok(config) = self.get_folder_config(&folder.scope, &folder.name).await {
                folder.description = config.description;
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

    /// List entry names in a folder (excludes .config).
    pub async fn list_entries(&self, scope: &str, folder: &str) -> Result<Vec<String>, VaultError> {
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
        validate_name(folder)?;
        validate_name(entry)?;
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.data_path(&scope_prefix, &format!("{}/{}", folder, entry));
        let body = serde_json::json!({ "data": data });
        let resp = self
            .request(reqwest::Method::POST, &path, Some(&body))
            .await?;

        match resp.status().as_u16() {
            200 | 204 => Ok(()),
            403 => Err(VaultError::Forbidden),
            s => {
                let text = resp.text().await.unwrap_or_default();
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
        validate_name(folder)?;
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

    /// Delete an entire folder (all entries + .config).
    pub async fn delete_folder(&self, scope: &str, folder: &str) -> Result<(), VaultError> {
        validate_name(folder)?;
        // List and delete all entries
        let entries = self.list_entries(scope, folder).await.unwrap_or_default();
        for entry in entries {
            let _ = self.delete_entry(scope, folder, &entry).await;
        }
        // Delete .config
        let scope_prefix = self.resolve_scope_prefix(scope)?;
        let path = self.metadata_path(&scope_prefix, &format!("{}/{}", folder, ".config"));
        let _ = self.request(reqwest::Method::DELETE, &path, None).await;
        Ok(())
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
