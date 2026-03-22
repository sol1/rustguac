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
            login_script: e.login_script.clone(),
            autofill: e.autofill.clone(),
            allowed_domains: e.allowed_domains.clone(),
            disable_copy: e.disable_copy,
            disable_paste: e.disable_paste,
            banner: e.banner.clone(),
            credential_variables: entry_credential_variables(e),
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

    // ── User credential variables ──

    /// Read a user's stored credential variables from Vault.
    /// Path: `<base_path>/users/<sanitized_email>`
    pub async fn get_user_credentials(
        &self,
        email: &str,
    ) -> Result<HashMap<String, String>, VaultError> {
        let key = sanitize_email_key(email);
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

    /// Write a user's credential variables to Vault (full replace).
    /// Path: `<base_path>/users/<sanitized_email>`
    pub async fn put_user_credentials(
        &self,
        email: &str,
        creds: &HashMap<String, String>,
    ) -> Result<(), VaultError> {
        let key = sanitize_email_key(email);
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

    if missing.is_empty() {
        Ok(resolved)
    } else {
        Err(missing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut entry = AddressBookEntry::default();
        entry.username = Some("$corp_user".into());
        entry.password = Some("$corp_password".into());
        entry.domain = Some("CORP".into()); // literal, not a variable
        let vars = entry_credential_variables(&entry);
        assert_eq!(vars, vec!["corp_user", "corp_password"]);
    }

    #[test]
    fn test_resolve_credential_variables_success() {
        let mut entry = AddressBookEntry::default();
        entry.username = Some("$corp_user".into());
        entry.password = Some("$corp_password".into());
        entry.domain = Some("CORP".into());
        entry.hostname = Some("rdp.example.com".into());

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
        let mut entry = AddressBookEntry::default();
        entry.username = Some("$corp_user".into());
        entry.password = Some("$corp_password".into());

        let creds = HashMap::new(); // empty
        let err = resolve_credential_variables(&entry, &creds).unwrap_err();
        assert_eq!(err, vec!["corp_user", "corp_password"]);
    }

    #[test]
    fn test_resolve_credential_variables_no_variables() {
        let mut entry = AddressBookEntry::default();
        entry.username = Some("alice".into());
        entry.password = Some("literal_pass".into());

        let creds = HashMap::new();
        let resolved = resolve_credential_variables(&entry, &creds).unwrap();
        assert_eq!(resolved.username.as_deref(), Some("alice"));
        assert_eq!(resolved.password.as_deref(), Some("literal_pass"));
    }
}
