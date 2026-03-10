//! Process lifecycle manager for Xvnc + Chromium browser sessions.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::{timeout, Duration};

use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use hmac::Hmac;
use sha1::Sha1;

/// Allocates numbers from a fixed range pool.
struct RangeAllocator {
    in_use: Mutex<HashSet<u32>>,
    range_start: u32,
    range_end: u32,
}

impl RangeAllocator {
    fn new(range_start: u32, range_end: u32) -> Self {
        Self {
            in_use: Mutex::new(HashSet::new()),
            range_start,
            range_end,
        }
    }

    fn allocate(&self) -> Option<u32> {
        let mut in_use = self.in_use.lock().unwrap();
        for n in self.range_start..=self.range_end {
            if !in_use.contains(&n) {
                in_use.insert(n);
                return Some(n);
            }
        }
        None
    }

    fn release(&self, n: u32) {
        let mut in_use = self.in_use.lock().unwrap();
        in_use.remove(&n);
    }
}

/// Handles for the spawned Xvnc and Chromium processes.
pub struct BrowserSession {
    pub display: u32,
    pub vnc_port: u16,
    pub xvnc_child: Child,
    pub chromium_child: Child,
    pub profile_dir: PathBuf,
    /// CDP port allocated for this session (if login script requested).
    pub cdp_port: Option<u16>,
}

/// Manages spawning and killing browser sessions.
pub struct BrowserManager {
    display_allocator: RangeAllocator,
    cdp_allocator: RangeAllocator,
    xvnc_path: String,
    chromium_path: String,
    login_scripts_dir: PathBuf,
    login_script_timeout_secs: u64,
}

impl BrowserManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        xvnc_path: String,
        chromium_path: String,
        display_range_start: u32,
        display_range_end: u32,
        cdp_port_range_start: u16,
        cdp_port_range_end: u16,
        login_scripts_dir: PathBuf,
        login_script_timeout_secs: u64,
    ) -> Self {
        Self {
            display_allocator: RangeAllocator::new(display_range_start, display_range_end),
            cdp_allocator: RangeAllocator::new(
                cdp_port_range_start as u32,
                cdp_port_range_end as u32,
            ),
            xvnc_path,
            chromium_path,
            login_scripts_dir,
            login_script_timeout_secs,
        }
    }

    /// Spawn Xvnc and Chromium for the given URL.
    /// If `need_cdp` is true, allocates a CDP port and starts Chromium with
    /// `--remote-debugging-port` so login scripts can connect via DevTools Protocol.
    /// If `autofill_credentials` is provided, pre-populates Chromium's Login Data
    /// SQLite before launch so autofill works natively on matching forms.
    pub async fn spawn(
        &self,
        url: &str,
        width: u32,
        height: u32,
        need_cdp: bool,
        autofill_credentials: Option<&[(String, String, String)]>,
        allowed_domains: Option<&[String]>,
    ) -> Result<BrowserSession, BrowserError> {
        let display_num = self.display_allocator.allocate().ok_or_else(|| {
            tracing::error!(
                "No X display numbers available (range {}–{})",
                self.display_allocator.range_start,
                self.display_allocator.range_end
            );
            BrowserError::NoDisplayAvailable
        })?;

        let cdp_port = if need_cdp {
            let port = self.cdp_allocator.allocate().ok_or_else(|| {
                self.display_allocator.release(display_num);
                tracing::error!(
                    "No CDP ports available (range {}–{})",
                    self.cdp_allocator.range_start,
                    self.cdp_allocator.range_end
                );
                BrowserError::NoCdpPortAvailable
            })?;
            Some(port as u16)
        } else {
            None
        };

        let vnc_port = 5900 + display_num as u16;
        let geometry = format!("{}x{}", width, height);

        // Create a unique profile directory for this session (UUID avoids stale crash state)
        let profile_dir =
            std::env::temp_dir().join(format!("rustguac-chromium-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&profile_dir); // clean slate
        if let Err(e) = std::fs::create_dir_all(&profile_dir) {
            self.display_allocator.release(display_num);
            if let Some(p) = cdp_port {
                self.cdp_allocator.release(p as u32);
            }
            let msg = format!("Failed to create profile dir {:?}: {}", profile_dir, e);
            tracing::error!("{}", msg);
            return Err(BrowserError::ChromiumSpawn(msg));
        }

        // Pre-populate Chromium autofill database if credentials are provided
        if let Some(creds) = autofill_credentials {
            if let Err(e) = populate_login_data(&profile_dir, creds) {
                tracing::warn!(
                    error = %e,
                    "Failed to populate Chromium autofill (session continues without autofill)"
                );
            } else {
                tracing::info!(
                    count = creds.len(),
                    "Pre-populated Chromium Login Data with {} credential(s)",
                    creds.len()
                );
            }
        }

        tracing::info!(
            xvnc_path = %self.xvnc_path,
            display = %display_num,
            vnc_port = %vnc_port,
            geometry = %geometry,
            "Spawning Xvnc"
        );

        // Spawn Xvnc
        let mut xvnc_child = Command::new(&self.xvnc_path)
            .arg(format!(":{}", display_num))
            .args([
                "-geometry",
                &geometry,
                "-depth",
                "24",
                "-SecurityTypes",
                "None",
                "-localhost",
                "-AlwaysShared",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                self.display_allocator.release(display_num);
                if let Some(p) = cdp_port {
                    self.cdp_allocator.release(p as u32);
                }
                let _ = std::fs::remove_dir_all(&profile_dir);
                let msg = format!("Failed to spawn '{}': {}", self.xvnc_path, e);
                tracing::error!("{}", msg);
                BrowserError::XvncSpawn(msg)
            })?;

        tracing::info!(
            display = %display_num,
            pid = ?xvnc_child.id(),
            "Xvnc process spawned, waiting for VNC port {} to accept connections",
            vnc_port
        );

        // Wait for VNC port to accept connections (up to 2s)
        let addr = format!("127.0.0.1:{}", vnc_port);
        let port_ready = timeout(Duration::from_secs(2), async {
            loop {
                if TcpStream::connect(&addr).await.is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;

        if port_ready.is_err() {
            // Collect stderr to help diagnose why Xvnc didn't start
            let stderr_output = collect_stderr(&mut xvnc_child).await;
            let _ = xvnc_child.kill().await;
            self.display_allocator.release(display_num);
            if let Some(p) = cdp_port {
                self.cdp_allocator.release(p as u32);
            }
            let _ = std::fs::remove_dir_all(&profile_dir);
            let msg = format!(
                "Xvnc did not start listening on port {} within 2s{}",
                vnc_port,
                if stderr_output.is_empty() {
                    String::new()
                } else {
                    format!("; stderr: {}", stderr_output)
                }
            );
            tracing::error!("{}", msg);
            return Err(BrowserError::XvncSpawn(msg));
        }

        tracing::info!(display = %display_num, vnc_port = %vnc_port, "Xvnc is ready and accepting connections");

        tracing::info!(
            chromium_path = %self.chromium_path,
            display = %display_num,
            profile_dir = %profile_dir.display(),
            url = %url,
            cdp_port = ?cdp_port,
            "Spawning Chromium"
        );

        // Spawn Chromium with isolated profile
        let window_size = format!("--window-size={},{}", width, height);
        let user_data_dir = format!("--user-data-dir={}", profile_dir.display());
        let cdp_arg = cdp_port.map(|p| format!("--remote-debugging-port={}", p));

        let mut chromium_args = vec![
            "--start-fullscreen",
            "--no-first-run",
            "--noerrdialogs",
            "--disable-infobars",
            "--disable-translate",
            "--disable-features=TranslateUI,VizDisplayCompositor,AutofillServerCommunication,MediaRouter,PasswordImport",
            // GPU / rendering — safe for headless VMs without GPU
            "--disable-gpu",
            "--disable-gpu-compositing",
            "--disable-software-rasterizer",
            "--disable-dev-shm-usage",
            "--use-gl=angle",
            "--use-angle=swiftshader",
            "--in-process-gpu",
            // Stability
            "--disable-background-networking",
            "--disable-sync",
            "--disable-breakpad",
            "--disable-crash-reporter",
            "--no-default-browser-check",
            "--window-position=0,0",
        ];
        // Owned strings that need to outlive the args slice
        chromium_args.push(&window_size);
        chromium_args.push(&user_data_dir);
        if let Some(ref arg) = cdp_arg {
            chromium_args.push(arg);
        }

        // Per-session domain allowlist via --host-rules.
        // Maps all hosts to a non-routable address except the allowed ones.
        // Also adds --enable-automation to suppress the "unsupported flag" infobar.
        let host_rules_arg = allowed_domains.and_then(|domains| {
            if domains.is_empty() {
                return None;
            }
            let mut rules = String::from("MAP * ~NOTFOUND");
            for domain in domains {
                let d = domain.trim();
                if d.is_empty() {
                    continue;
                }
                rules.push_str(&format!(", EXCLUDE {}", d));
                if !d.starts_with("*.") {
                    rules.push_str(&format!(", EXCLUDE *.{}", d));
                }
            }
            rules.push_str(", EXCLUDE localhost, EXCLUDE 127.0.0.1");
            Some(format!("--host-rules={}", rules))
        });
        if let Some(ref arg) = host_rules_arg {
            chromium_args.push(arg);
            // Suppress the "unsupported command-line flag" infobar.
            // Shows "controlled by automated test software" bar instead, which is acceptable.
            // Cannot use --test-type here as it disables the password manager (breaks autofill).
            chromium_args.push("--enable-automation");
        }

        chromium_args.push(url);

        let chromium_result = Command::new(&self.chromium_path)
            .env("DISPLAY", format!(":{}", display_num))
            .args(&chromium_args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn();

        let chromium_child = match chromium_result {
            Ok(child) => {
                tracing::info!(
                    display = %display_num,
                    pid = ?child.id(),
                    url = %url,
                    "Chromium process spawned"
                );
                child
            }
            Err(e) => {
                let _ = xvnc_child.kill().await;
                self.display_allocator.release(display_num);
                if let Some(p) = cdp_port {
                    self.cdp_allocator.release(p as u32);
                }
                let _ = std::fs::remove_dir_all(&profile_dir);
                let msg = format!("Failed to spawn '{}': {}", self.chromium_path, e);
                tracing::error!("{}", msg);
                return Err(BrowserError::ChromiumSpawn(msg));
            }
        };

        Ok(BrowserSession {
            display: display_num,
            vnc_port,
            xvnc_child,
            chromium_child,
            profile_dir,
            cdp_port,
        })
    }

    /// Kill both Chromium and Xvnc, release the display number and CDP port,
    /// and clean up the profile dir.
    pub async fn kill(&self, session: &mut BrowserSession) {
        tracing::info!(
            display = %session.display,
            chromium_pid = ?session.chromium_child.id(),
            xvnc_pid = ?session.xvnc_child.id(),
            "Killing browser session processes"
        );
        let _ = session.chromium_child.kill().await;
        let _ = session.xvnc_child.kill().await;
        self.display_allocator.release(session.display);
        if let Some(p) = session.cdp_port.take() {
            self.cdp_allocator.release(p as u32);
        }

        // Clean up the per-session Chromium profile directory
        let profile_dir = session.profile_dir.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = std::fs::remove_dir_all(&profile_dir) {
                tracing::warn!(path = %profile_dir.display(), error = %e, "Failed to clean up Chromium profile dir");
            }
        });

        tracing::info!(display = %session.display, "Browser session cleaned up, display released");
    }

    /// Run a login script as a child process with env vars for CDP port, credentials, etc.
    /// Returns a `JoinHandle` that completes when the script finishes (or times out).
    /// Script failures log a warning but do not kill the session.
    #[allow(clippy::too_many_arguments)]
    pub fn run_login_script(
        &self,
        script_name: &str,
        display: u32,
        cdp_port: u16,
        url: &str,
        username: Option<&str>,
        password: Option<&str>,
        session_id: &str,
    ) -> Result<tokio::task::JoinHandle<()>, BrowserError> {
        // Validate: resolve relative to login_scripts_dir, block path traversal
        let script_path = self.login_scripts_dir.join(script_name);
        let canonical = script_path.canonicalize().map_err(|e| {
            BrowserError::LoginScript(format!("login script '{}' not found: {}", script_name, e))
        })?;
        let canonical_base = self.login_scripts_dir.canonicalize().map_err(|e| {
            BrowserError::LoginScript(format!(
                "login_scripts_dir '{}' not found: {}",
                self.login_scripts_dir.display(),
                e
            ))
        })?;
        if !canonical.starts_with(&canonical_base) {
            return Err(BrowserError::LoginScript(format!(
                "login script '{}' is outside scripts directory",
                script_name
            )));
        }

        // Check the script is executable
        if !is_executable(&canonical) {
            return Err(BrowserError::LoginScript(format!(
                "login script '{}' is not executable",
                script_name
            )));
        }

        let timeout_secs = self.login_script_timeout_secs;
        let script_path_owned = canonical;
        let url_owned = url.to_string();
        let username_owned = username.unwrap_or("").to_string();
        let password_owned = password.unwrap_or("").to_string();
        let session_id_owned = session_id.to_string();

        let handle = tokio::spawn(async move {
            tracing::info!(
                script = %script_path_owned.display(),
                session_id = %session_id_owned,
                cdp_port = %cdp_port,
                "Running login script"
            );

            // Build credentials JSON for stdin
            let stdin_json = serde_json::json!({
                "username": username_owned,
                "password": password_owned,
                "url": url_owned,
                "cdp_port": cdp_port,
                "session_id": session_id_owned,
            })
            .to_string();

            let result = timeout(Duration::from_secs(timeout_secs), async {
                let mut child = match Command::new(&script_path_owned)
                    .env("DISPLAY", format!(":{}", display))
                    .env("RUSTGUAC_CDP_PORT", cdp_port.to_string())
                    .env("RUSTGUAC_URL", &url_owned)
                    .env("RUSTGUAC_USERNAME", &username_owned)
                    .env("RUSTGUAC_PASSWORD", &password_owned)
                    .env("RUSTGUAC_SESSION_ID", &session_id_owned)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                {
                    Ok(child) => child,
                    Err(e) => {
                        tracing::warn!(
                            script = %script_path_owned.display(),
                            error = %e,
                            "Failed to spawn login script"
                        );
                        return;
                    }
                };

                // Write credentials JSON to stdin, then close
                if let Some(mut stdin) = child.stdin.take() {
                    use tokio::io::AsyncWriteExt;
                    let _ = stdin.write_all(stdin_json.as_bytes()).await;
                    // stdin dropped here, closing the pipe
                }

                match child.wait_with_output().await {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if output.status.success() {
                            tracing::info!(
                                script = %script_path_owned.display(),
                                session_id = %session_id_owned,
                                "Login script completed successfully"
                            );
                        } else {
                            tracing::warn!(
                                script = %script_path_owned.display(),
                                session_id = %session_id_owned,
                                exit_code = ?output.status.code(),
                                "Login script failed"
                            );
                        }
                        if !stdout.is_empty() {
                            tracing::info!(
                                session_id = %session_id_owned,
                                "Login script stdout: {}",
                                stdout.trim()
                            );
                        }
                        if !stderr.is_empty() {
                            tracing::warn!(
                                session_id = %session_id_owned,
                                "Login script stderr: {}",
                                stderr.trim()
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            script = %script_path_owned.display(),
                            error = %e,
                            "Failed to wait for login script"
                        );
                    }
                }
            })
            .await;

            if result.is_err() {
                tracing::warn!(
                    script = %script_path_owned.display(),
                    session_id = %session_id_owned,
                    timeout_secs = timeout_secs,
                    "Login script timed out, killing"
                );
            }
        });

        Ok(handle)
    }
}

/// Encrypt a password using Chromium's Linux "basic" os_crypt backend.
///
/// On Linux without a keyring (our case — headless Xvnc), Chromium uses:
/// 1. PBKDF2("peanuts", "saltysalt", 1 iteration, SHA-1) → 16-byte AES key
/// 2. AES-128-CBC with IV = 16 × 0x20 (space chars)
/// 3. Blob format: "v10" prefix + encrypted ciphertext
fn encrypt_chromium_password(plaintext: &str) -> Result<Vec<u8>, String> {
    // Derive the AES key: PBKDF2(password="peanuts", salt="saltysalt", iterations=1, dkLen=16)
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2::<Hmac<Sha1>>(b"peanuts", b"saltysalt", 1, &mut key)
        .map_err(|e| format!("PBKDF2 derivation failed: {}", e))?;

    // IV is 16 space characters (0x20)
    let iv = [0x20u8; 16];

    // Encrypt with AES-128-CBC + PKCS7 padding
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
    let plaintext_bytes = plaintext.as_bytes();
    // Buffer needs room for plaintext + up to one block of padding
    let mut buf = vec![0u8; plaintext_bytes.len() + 16];
    buf[..plaintext_bytes.len()].copy_from_slice(plaintext_bytes);
    let encrypted = Aes128CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_bytes.len())
        .map_err(|e| format!("AES encryption failed: {}", e))?;

    // Prepend "v10" version tag
    let mut blob = Vec::with_capacity(3 + encrypted.len());
    blob.extend_from_slice(b"v10");
    blob.extend_from_slice(encrypted);
    Ok(blob)
}

/// Pre-populate Chromium's Login Data SQLite with credentials for autofill.
///
/// Creates the `{profile_dir}/Default/Login Data` SQLite database with the
/// `logins` table and inserts encrypted credentials for each (origin_url,
/// username, password) tuple.
fn populate_login_data(
    profile_dir: &Path,
    credentials: &[(String, String, String)],
) -> Result<(), String> {
    let default_dir = profile_dir.join("Default");
    std::fs::create_dir_all(&default_dir).map_err(|e| format!("create Default dir: {}", e))?;

    // Write Preferences to enable the password manager and autofill
    let prefs = serde_json::json!({
        "credentials_enable_service": true,
        "credentials_enable_autosignin": true,
        "profile": {
            "password_manager_enabled": true
        },
        "autofill": {
            "enabled": true
        },
        "password_manager": {
            "saving_enabled": false
        },
        "download": {
            "prompt_for_download": false
        }
    });
    let prefs_path = default_dir.join("Preferences");
    std::fs::write(&prefs_path, prefs.to_string())
        .map_err(|e| format!("write Preferences: {}", e))?;

    let db_path = default_dir.join("Login Data");
    let conn =
        rusqlite::Connection::open(&db_path).map_err(|e| format!("open Login Data: {}", e))?;

    // Schema must match what Chromium expects exactly, including the meta table
    // with version/last_compatible_version. Without this, Chromium crashes on startup.
    // Schema sourced from Chromium 134 on Debian 13 (version 43).
    conn.execute_batch(
        "CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
        INSERT INTO meta VALUES('mmap_status','-1');
        INSERT INTO meta VALUES('version','43');
        INSERT INTO meta VALUES('last_compatible_version','40');
        CREATE TABLE logins (
            origin_url VARCHAR NOT NULL,
            action_url VARCHAR,
            username_element VARCHAR,
            username_value VARCHAR,
            password_element VARCHAR,
            password_value BLOB,
            submit_element VARCHAR,
            signon_realm VARCHAR NOT NULL,
            date_created INTEGER NOT NULL,
            blacklisted_by_user INTEGER NOT NULL,
            scheme INTEGER NOT NULL,
            password_type INTEGER,
            times_used INTEGER,
            form_data BLOB,
            display_name VARCHAR,
            icon_url VARCHAR,
            federation_url VARCHAR,
            skip_zero_click INTEGER,
            generation_upload_status INTEGER,
            possible_username_pairs BLOB,
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date_last_used INTEGER NOT NULL DEFAULT 0,
            moving_blocked_for BLOB,
            date_password_modified INTEGER NOT NULL DEFAULT 0,
            sender_email VARCHAR,
            sender_name VARCHAR,
            date_received INTEGER,
            sharing_notification_displayed INTEGER NOT NULL DEFAULT 0,
            keychain_identifier BLOB,
            sender_profile_image_url VARCHAR,
            date_last_filled INTEGER NOT NULL DEFAULT 0,
            actor_login_approved INTEGER NOT NULL DEFAULT 0,
            UNIQUE (origin_url, username_element, username_value, password_element, signon_realm)
        );
        CREATE INDEX logins_signon ON logins (signon_realm);
        CREATE TABLE sync_entities_metadata (storage_key INTEGER PRIMARY KEY AUTOINCREMENT, metadata VARCHAR NOT NULL);
        CREATE TABLE sync_model_metadata (id INTEGER PRIMARY KEY AUTOINCREMENT, model_metadata VARCHAR NOT NULL);
        CREATE TABLE insecure_credentials (parent_id INTEGER REFERENCES logins ON UPDATE CASCADE ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED, insecurity_type INTEGER NOT NULL, create_time INTEGER NOT NULL, is_muted INTEGER NOT NULL DEFAULT 0, trigger_notification_from_backend INTEGER NOT NULL DEFAULT 0, UNIQUE (parent_id, insecurity_type));
        CREATE INDEX foreign_key_index ON insecure_credentials (parent_id);
        CREATE TABLE password_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, parent_id INTEGER NOT NULL REFERENCES logins ON UPDATE CASCADE ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED, key VARCHAR NOT NULL, value BLOB, date_created INTEGER NOT NULL, confidential INTEGER, UNIQUE (parent_id, key));
        CREATE INDEX foreign_key_index_notes ON password_notes (parent_id);
        CREATE TABLE stats (origin_domain VARCHAR NOT NULL, username_value VARCHAR, dismissal_count INTEGER, update_time INTEGER NOT NULL, UNIQUE(origin_domain, username_value));
        CREATE INDEX stats_origin ON stats(origin_domain);",
    )
    .map_err(|e| format!("create Login Data schema: {}", e))?;

    let now = chrono::Utc::now().timestamp_micros();

    for (origin_url, username, password) in credentials {
        let encrypted = encrypt_chromium_password(password)?;

        // signon_realm is the origin with trailing slash (Chromium's format for HTML forms)
        let signon_realm = match url::Url::parse(origin_url) {
            Ok(u) => format!(
                "{}://{}{}/",
                u.scheme(),
                u.host_str().unwrap_or(""),
                u.port().map(|p| format!(":{}", p)).unwrap_or_default()
            ),
            Err(_) => format!("{}/", origin_url),
        };

        // Ensure origin_url has trailing slash to match Chromium's convention
        let origin_with_slash = if origin_url.ends_with('/') {
            origin_url.clone()
        } else {
            format!("{}/", origin_url)
        };

        conn.execute(
            "INSERT INTO logins (origin_url, action_url, username_element, username_value, password_element, password_value, submit_element, signon_realm, date_created, blacklisted_by_user, scheme, password_type, times_used, skip_zero_click, date_last_used, date_password_modified)
             VALUES (?1, '', '', ?2, '', ?3, '', ?4, ?5, 0, 0, 0, 1, 0, ?5, ?5)",
            rusqlite::params![origin_with_slash, username, encrypted, signon_realm, now],
        )
        .map_err(|e| format!("insert login: {}", e))?;
    }

    Ok(())
}

/// Check if a path is an executable file.
fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            meta.is_file() && (meta.permissions().mode() & 0o111 != 0)
        } else {
            false
        }
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// Read whatever stderr is available from a child process (non-blocking, best-effort).
async fn collect_stderr(child: &mut Child) -> String {
    use tokio::io::AsyncReadExt;
    if let Some(ref mut stderr) = child.stderr {
        let mut buf = vec![0u8; 4096];
        match timeout(Duration::from_millis(200), stderr.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&buf[..n]).trim().to_string(),
            _ => String::new(),
        }
    } else {
        String::new()
    }
}

#[derive(Debug)]
pub enum BrowserError {
    NoDisplayAvailable,
    NoCdpPortAvailable,
    XvncSpawn(String),
    ChromiumSpawn(String),
    LoginScript(String),
}

impl std::fmt::Display for BrowserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrowserError::NoDisplayAvailable => write!(f, "no X display numbers available"),
            BrowserError::NoCdpPortAvailable => write!(f, "no CDP ports available"),
            BrowserError::XvncSpawn(msg) => write!(f, "Xvnc spawn failed: {}", msg),
            BrowserError::ChromiumSpawn(msg) => write!(f, "Chromium spawn failed: {}", msg),
            BrowserError::LoginScript(msg) => write!(f, "login script error: {}", msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_chromium_password_v10_prefix() {
        let blob = encrypt_chromium_password("secret").unwrap();
        assert_eq!(&blob[..3], b"v10");
    }

    #[test]
    fn test_encrypt_chromium_password_deterministic() {
        let a = encrypt_chromium_password("test123").unwrap();
        let b = encrypt_chromium_password("test123").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_encrypt_chromium_password_different_inputs() {
        let a = encrypt_chromium_password("password1").unwrap();
        let b = encrypt_chromium_password("password2").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_encrypt_chromium_password_block_aligned() {
        // AES-128-CBC with PKCS7: output is always multiple of 16 bytes
        let blob = encrypt_chromium_password("short").unwrap();
        let ciphertext_len = blob.len() - 3; // minus "v10" prefix
        assert_eq!(ciphertext_len % 16, 0);
    }

    #[test]
    fn test_encrypt_chromium_password_empty() {
        let blob = encrypt_chromium_password("").unwrap();
        assert_eq!(&blob[..3], b"v10");
        // Empty plaintext + PKCS7 padding = one full block
        assert_eq!(blob.len(), 3 + 16);
    }

    #[test]
    fn test_populate_login_data_creates_db() {
        let dir = std::env::temp_dir().join("rustguac-test-login-data");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let creds = vec![(
            "https://example.com".into(),
            "alice".into(),
            "secret".into(),
        )];
        populate_login_data(&dir, &creds).unwrap();

        let db_path = dir.join("Default/Login Data");
        assert!(db_path.exists(), "Login Data SQLite should be created");

        // Verify the database is valid SQLite and has data
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM logins", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);

        let origin: String = conn
            .query_row("SELECT origin_url FROM logins", [], |r| r.get(0))
            .unwrap();
        assert_eq!(origin, "https://example.com/");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_populate_login_data_multiple_creds() {
        let dir = std::env::temp_dir().join("rustguac-test-login-data-multi");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let creds = vec![
            ("https://app.com".into(), "user1".into(), "pass1".into()),
            ("https://idp.com".into(), "user2".into(), "pass2".into()),
        ];
        populate_login_data(&dir, &creds).unwrap();

        let db_path = dir.join("Default/Login Data");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM logins", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_range_allocator() {
        let alloc = RangeAllocator::new(100, 102);
        let a = alloc.allocate().unwrap();
        let b = alloc.allocate().unwrap();
        let c = alloc.allocate().unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
        // Pool exhausted
        assert!(alloc.allocate().is_none());
        // Release one and re-allocate
        alloc.release(b);
        let d = alloc.allocate().unwrap();
        assert_eq!(d, b);
    }
}
