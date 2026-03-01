mod api;
mod auth;
mod browser;
mod config;
mod db;
mod drive;
mod guacd;
mod oidc;
mod protocol;
mod recording;
mod session;
mod tunnel;
mod vault;
mod websocket;

use crate::api::{AppState, OidcEnabled, SiteTitle, ThemeData, VaultConfigured, VaultState};
use crate::config::Config;
use crate::db::Db;
use crate::session::SessionManager;
use axum::extract::{DefaultBodyLimit, Request};
use axum::response::Html;
use axum::response::Response;
use axum::routing::{delete, get, post, put};
use axum::{middleware, Extension, Router};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};
use tower_http::services::ServeDir;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "rustguac", about = "Lightweight Guacamole SSH proxy")]
struct Cli {
    /// Path to TOML config file
    #[arg(short, long)]
    config: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server (default)
    Serve,

    /// Create a new admin with an API key
    AddAdmin {
        /// Admin name (unique)
        #[arg(long)]
        name: String,
        /// Comma-separated allowed IP CIDRs (e.g. "10.0.0.0/8,192.168.1.0/24")
        #[arg(long)]
        allowed_ips: Option<String>,
        /// Expiry date in ISO 8601 format (e.g. "2025-12-31T23:59:59Z")
        #[arg(long)]
        expires: Option<String>,
    },

    /// List all admin accounts
    ListAdmins,

    /// Disable an admin account
    DisableAdmin {
        #[arg(long)]
        name: String,
    },

    /// Enable an admin account
    EnableAdmin {
        #[arg(long)]
        name: String,
    },

    /// Delete an admin account permanently
    DeleteAdmin {
        #[arg(long)]
        name: String,
    },

    /// Rotate an admin's API key (generates new key, invalidates old)
    RotateKey {
        #[arg(long)]
        name: String,
    },

    /// Generate a self-signed TLS certificate for development/testing
    GenerateCert {
        /// Hostname for the certificate (e.g. "rustguac.example.com")
        #[arg(long)]
        hostname: String,
        /// Output directory for cert.pem and key.pem
        #[arg(long, default_value = ".")]
        out_dir: String,
        /// Additional Subject Alternative Names (hostnames or IPs). localhost and 127.0.0.1 are always included.
        #[arg(long = "san")]
        extra_sans: Vec<String>,
    },

    /// List all OIDC users
    ListUsers,

    /// Set a user's role
    SetRole {
        /// User email
        #[arg(long)]
        email: String,
        /// Role: admin, poweruser, operator, or viewer
        #[arg(long)]
        role: String,
    },

    /// Disable an OIDC user
    DisableUser {
        #[arg(long)]
        email: String,
    },

    /// Delete an OIDC user
    DeleteUser {
        #[arg(long)]
        email: String,
    },
}

#[tokio::main]
async fn main() {
    // Install rustls crypto provider before any TLS usage (reqwest, axum-server, etc.)
    // Required when both ring and aws-lc-rs features are present.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    // Load config
    let config = Config::load(cli.config.as_deref());

    // Open database
    let database = db::init_db(&config.db_path).expect("Failed to open database");

    match cli.command {
        None | Some(Command::Serve) => run_server(config, database).await,
        Some(Command::AddAdmin {
            name,
            allowed_ips,
            expires,
        }) => {
            cmd_add_admin(&database, &name, allowed_ips.as_deref(), expires.as_deref());
        }
        Some(Command::ListAdmins) => cmd_list_admins(&database),
        Some(Command::DisableAdmin { name }) => cmd_disable_admin(&database, &name),
        Some(Command::EnableAdmin { name }) => cmd_enable_admin(&database, &name),
        Some(Command::DeleteAdmin { name }) => cmd_delete_admin(&database, &name),
        Some(Command::RotateKey { name }) => cmd_rotate_key(&database, &name),
        Some(Command::GenerateCert {
            hostname,
            out_dir,
            extra_sans,
        }) => {
            cmd_generate_cert(&hostname, &out_dir, &extra_sans);
        }
        Some(Command::ListUsers) => cmd_list_users(&database),
        Some(Command::SetRole { email, role }) => cmd_set_role(&database, &email, &role),
        Some(Command::DisableUser { email }) => cmd_disable_user(&database, &email),
        Some(Command::DeleteUser { email }) => cmd_delete_user(&database, &email),
    }
}

fn cmd_add_admin(database: &Db, name: &str, allowed_ips: Option<&str>, expires: Option<&str>) {
    match db::add_admin(database, name, allowed_ips, expires) {
        Ok(key) => {
            println!("Admin '{}' created.", name);
            println!("API Key: {}", key);
            println!();
            println!("Store this key securely — it cannot be retrieved again.");
        }
        Err(e) => {
            eprintln!("Error creating admin: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_list_admins(database: &Db) {
    match db::list_admins(database) {
        Ok(admins) => {
            if admins.is_empty() {
                println!("No admins configured.");
                return;
            }
            println!(
                "{:<4} {:<20} {:<10} {:<24} {:<24} Allowed IPs",
                "ID", "Name", "Status", "Expires", "Last Used",
            );
            println!("{}", "-".repeat(100));
            for a in admins {
                let status = if a.disabled { "disabled" } else { "active" };
                let expires = a.expires_at.as_deref().unwrap_or("never");
                let last_used = a.last_used_at.as_deref().unwrap_or("never");
                let ips = a.allowed_ips.as_deref().unwrap_or("any");
                println!(
                    "{:<4} {:<20} {:<10} {:<24} {:<24} {}",
                    a.id, a.name, status, expires, last_used, ips
                );
            }
        }
        Err(e) => {
            eprintln!("Error listing admins: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_disable_admin(database: &Db, name: &str) {
    match db::disable_admin(database, name) {
        Ok(true) => println!("Admin '{}' disabled.", name),
        Ok(false) => {
            eprintln!("Admin '{}' not found.", name);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_enable_admin(database: &Db, name: &str) {
    match db::enable_admin(database, name) {
        Ok(true) => println!("Admin '{}' enabled.", name),
        Ok(false) => {
            eprintln!("Admin '{}' not found.", name);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_delete_admin(database: &Db, name: &str) {
    match db::delete_admin(database, name) {
        Ok(true) => println!("Admin '{}' deleted.", name),
        Ok(false) => {
            eprintln!("Admin '{}' not found.", name);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_rotate_key(database: &Db, name: &str) {
    match db::rotate_key(database, name) {
        Ok(Some(key)) => {
            println!("API key rotated for '{}'.", name);
            println!("New API Key: {}", key);
            println!();
            println!("Store this key securely — it cannot be retrieved again.");
        }
        Ok(None) => {
            eprintln!("Admin '{}' not found.", name);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_generate_cert(hostname: &str, out_dir: &str, extra_sans: &[String]) {
    use rcgen::{generate_simple_self_signed, CertifiedKey};

    let mut sans = vec![
        hostname.to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];
    for san in extra_sans {
        if !sans.contains(san) {
            sans.push(san.clone());
        }
    }

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(sans.clone()).expect("Failed to generate certificate");

    let cert_path = std::path::Path::new(out_dir).join("cert.pem");
    let key_path = std::path::Path::new(out_dir).join("key.pem");

    std::fs::write(&cert_path, cert.pem()).expect("Failed to write cert.pem");
    std::fs::write(&key_path, signing_key.serialize_pem()).expect("Failed to write key.pem");

    println!("Generated self-signed certificate:");
    println!("  Certificate: {}", cert_path.display());
    println!("  Private key: {}", key_path.display());
    println!("  SANs:        {}", sans.join(", "));
    println!();
    println!("Add to config.toml:");
    println!("  [tls]");
    println!("  cert_path = \"{}\"", cert_path.display());
    println!("  key_path = \"{}\"", key_path.display());
}

fn cmd_list_users(database: &Db) {
    match db::list_users(database) {
        Ok(users) => {
            if users.is_empty() {
                println!("No OIDC users.");
                return;
            }
            println!(
                "{:<4} {:<30} {:<20} {:<10} {:<10} {:<24}",
                "ID", "Email", "Name", "Role", "Status", "Last Login"
            );
            println!("{}", "-".repeat(100));
            for u in users {
                let status = if u.disabled { "disabled" } else { "active" };
                let last_login = u.last_login_at.as_deref().unwrap_or("never");
                println!(
                    "{:<4} {:<30} {:<20} {:<10} {:<10} {:<24}",
                    u.id, u.email, u.name, u.role, status, last_login
                );
            }
        }
        Err(e) => {
            eprintln!("Error listing users: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_set_role(database: &Db, email: &str, role: &str) {
    if !["admin", "poweruser", "operator", "viewer"].contains(&role) {
        eprintln!("Role must be admin, poweruser, operator, or viewer.");
        std::process::exit(1);
    }
    match db::set_user_role(database, email, role) {
        Ok(true) => println!("User '{}' role set to '{}'.", email, role),
        Ok(false) => {
            eprintln!("User '{}' not found.", email);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_disable_user(database: &Db, email: &str) {
    match db::disable_user(database, email) {
        Ok(true) => println!("User '{}' disabled.", email),
        Ok(false) => {
            eprintln!("User '{}' not found.", email);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_delete_user(database: &Db, email: &str) {
    match db::delete_user(database, email) {
        Ok(true) => println!("User '{}' deleted.", email),
        Ok(false) => {
            eprintln!("User '{}' not found.", email);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Whether TLS is enabled (used by security headers middleware).
#[derive(Clone)]
struct TlsEnabled(bool);

async fn security_headers(
    tls: Extension<TlsEnabled>,
    request: Request,
    next: middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert(
        "Referrer-Policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()".parse().unwrap(),
    );
    headers.insert(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss: ws:".parse().unwrap(),
    );
    if tls.0 .0 {
        headers.insert(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains".parse().unwrap(),
        );
    }
    response
}

async fn run_server(config: Config, database: Db) {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let listen_addr = config.listen_addr.clone();
    let static_path = config.static_path.clone();
    let tls_config = config.tls.clone();

    // Initialize OIDC if configured
    let oidc_state = if let Some(ref oidc_config) = config.oidc {
        match oidc::init_oidc(oidc_config, config.auth_session_ttl_secs).await {
            Ok(state) => {
                tracing::info!("OIDC configured with issuer: {}", oidc_config.issuer_url);
                Some(state)
            }
            Err(e) => {
                tracing::error!("Failed to initialize OIDC: {}", e);
                tracing::warn!("Continuing without OIDC — only API key auth will work");
                None
            }
        }
    } else {
        None
    };

    // Initialize Vault client if configured
    let vault_client: VaultState = Arc::new(tokio::sync::RwLock::new(None));

    if let Some(ref vault_config) = config.vault {
        let secret_id = match std::env::var("VAULT_SECRET_ID") {
            Ok(s) => s,
            Err(_) => {
                tracing::error!("VAULT_SECRET_ID env var required when [vault] is configured");
                tracing::error!("Address book and drive features will be unavailable");
                String::new()
            }
        };

        if !secret_id.is_empty() {
            match vault::VaultClient::new(vault_config, &secret_id).await {
                Ok(client) => {
                    let client = Arc::new(client);
                    client.spawn_renewal_task();
                    tracing::info!("Vault client initialized: {}", vault_config.addr);
                    *vault_client.write().await = Some(client);
                }
                Err(e) => {
                    tracing::error!("=============================================");
                    tracing::error!("VAULT CONNECTION FAILED");
                    tracing::error!("  Address: {}", vault_config.addr);
                    tracing::error!("  Error: {}", e);
                    tracing::error!("  Address book and drive features are UNAVAILABLE");
                    tracing::error!("  Sessions (SSH/RDP/VNC) will still work normally");
                    tracing::error!("  Retrying Vault connection every 30s in background");
                    tracing::error!("=============================================");

                    // Spawn background retry task
                    let retry_vault_config = vault_config.clone();
                    let retry_secret_id = secret_id.clone();
                    let retry_vault_state = vault_client.clone();
                    let retry_drive_config = config.drive.clone();
                    tokio::spawn(async move {
                        let mut interval =
                            tokio::time::interval(std::time::Duration::from_secs(30));
                        interval.tick().await; // skip immediate tick
                        loop {
                            interval.tick().await;
                            tracing::debug!(
                                "Retrying Vault connection to {}...",
                                retry_vault_config.addr
                            );
                            match vault::VaultClient::new(&retry_vault_config, &retry_secret_id)
                                .await
                            {
                                Ok(client) => {
                                    let client = Arc::new(client);
                                    client.spawn_renewal_task();
                                    tracing::info!(
                                        "Vault client connected (retry succeeded): {}",
                                        retry_vault_config.addr
                                    );
                                    *retry_vault_state.write().await = Some(client.clone());

                                    // Mount LUKS now that Vault is available
                                    if let Some(ref dc) = retry_drive_config {
                                        if dc.enabled && drive::luks_configured(dc) {
                                            match drive::mount_luks(dc, &client).await {
                                                Ok(_) => tracing::info!(
                                                    "LUKS drive volume mounted (deferred)"
                                                ),
                                                Err(e) => tracing::error!(
                                                    "Failed to mount LUKS drive volume: {}",
                                                    e
                                                ),
                                            }
                                        }
                                    }
                                    break;
                                }
                                Err(e) => {
                                    tracing::warn!("Vault retry failed: {} — will retry in 30s", e);
                                }
                            }
                        }
                    });
                }
            }
        }
    }

    // Initialize drive / LUKS if configured (and Vault is already available)
    if let Some(ref drive_config) = config.drive {
        if drive_config.enabled {
            // Mount LUKS volume if configured and Vault is available now
            if drive::luks_configured(drive_config) {
                let vc = vault_client.read().await;
                if let Some(ref client) = *vc {
                    match drive::mount_luks(drive_config, client).await {
                        Ok(_) => tracing::info!("LUKS drive volume mounted"),
                        Err(e) => {
                            tracing::error!("Failed to mount LUKS drive volume: {}", e);
                        }
                    }
                } else {
                    tracing::warn!("LUKS configured but Vault not yet available — will mount when Vault connects");
                }
            }
            // Ensure base drive directory exists
            if let Err(e) = drive::ensure_base_dir(drive_config) {
                tracing::warn!("Failed to create drive base directory: {}", e);
            }
        }
    }

    let oidc_enabled = OidcEnabled(oidc_state.is_some());
    let vault_configured = VaultConfigured(config.vault.is_some());
    let site_title = SiteTitle(config.site_title.clone());
    let theme_data = {
        let (admin_preset, admin_colors) = config
            .theme
            .as_ref()
            .map(|t| t.resolve())
            .unwrap_or_else(|| ("dark".into(), crate::config::builtin_presets()[0].1.clone()));
        let logo_url = config.theme.as_ref().and_then(|t| t.logo_url.clone());
        let presets: std::collections::HashMap<String, crate::config::ThemeColors> =
            crate::config::builtin_presets()
                .into_iter()
                .map(|(name, colors)| (name.to_string(), colors))
                .collect();
        ThemeData {
            admin_preset,
            admin_colors,
            logo_url,
            presets,
        }
    };
    let trusted_proxies = auth::TrustedProxies(config.trusted_proxies.clone());

    // Periodically clean up expired auth sessions from the database
    let cleanup_db = database.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        interval.tick().await; // first tick is immediate, skip it
        loop {
            interval.tick().await;
            match db::cleanup_expired_sessions(&cleanup_db) {
                Ok(n) if n > 0 => tracing::info!("Cleaned up {} expired auth sessions", n),
                Err(e) => tracing::warn!("Failed to clean up expired sessions: {}", e),
                _ => {}
            }
            match db::cleanup_expired_user_tokens(&cleanup_db) {
                Ok(n) if n > 0 => tracing::info!("Cleaned up {} expired user API tokens", n),
                Err(e) => tracing::warn!("Failed to clean up expired tokens: {}", e),
                _ => {}
            }
            match db::cleanup_old_audit_log(&cleanup_db, 90) {
                Ok(n) if n > 0 => tracing::info!("Cleaned up {} old audit log entries", n),
                Err(e) => tracing::warn!("Failed to clean up audit log: {}", e),
                _ => {}
            }
        }
    });

    // Log session max duration setting
    let max_dur_hours = config.session_max_duration_secs as f64 / 3600.0;
    tracing::info!(
        "Session max duration: {:.1}h ({}s)",
        max_dur_hours,
        config.session_max_duration_secs
    );

    // Store drive config for shutdown cleanup (before config is moved)
    let shutdown_drive_config = config.drive.clone();

    // Build TLS connector for guacd if configured
    let guacd_tls = build_guacd_tls(&config);

    // Create session manager
    let manager: AppState = Arc::new(SessionManager::new(config, guacd_tls));

    // Spawn background task to reap sessions that exceed max duration
    {
        let reaper_manager = manager.clone();
        let check_interval = std::cmp::max(manager.session_max_duration_secs() / 4, 60);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(check_interval));
            interval.tick().await; // skip immediate first tick
            loop {
                interval.tick().await;
                let reaped = reaper_manager.reap_expired_sessions().await;
                if reaped > 0 {
                    tracing::info!("Reaped {} expired sessions", reaped);
                }
            }
        });
    }

    // Spawn recording rotation background task
    {
        let rec_config = manager.recording_config();
        if rec_config.max_disk_percent > 0 || rec_config.max_recordings > 0 {
            let interval_secs = rec_config.rotation_interval_secs.max(30);
            tracing::info!(
                "Recording rotation enabled (max_disk={}%, max_count={}, interval={}s)",
                rec_config.max_disk_percent,
                rec_config.max_recordings,
                interval_secs
            );
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(interval_secs));
                interval.tick().await; // skip immediate first tick
                loop {
                    interval.tick().await;
                    let cfg = rec_config.clone();
                    let _ = tokio::task::spawn_blocking(move || recording::rotate(&cfg)).await;
                }
            });
        }
    }

    // Rate limit configs
    let api_governor_conf = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(10)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("Failed to build API rate limit config");

    let session_create_governor_conf = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(5)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("Failed to build session creation rate limit config");

    let ws_governor_conf = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(20)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("Failed to build WebSocket rate limit config");

    // Session creation route with extra rate limit layer
    let session_create_route = Router::new()
        .route("/api/sessions", post(api::create_session))
        .with_state(manager.clone())
        .layer(GovernorLayer::new(session_create_governor_conf));

    // API routes that require authentication
    let api_routes = Router::new()
        .route("/api/sessions", get(api::list_sessions))
        .route("/api/sessions/{id}", get(api::get_session))
        .route("/api/sessions/{id}", delete(api::delete_session))
        .route("/api/recordings", get(api::list_recordings))
        .route("/api/recordings/{name}", get(api::serve_recording))
        .route("/api/recordings/{name}", delete(api::delete_recording))
        .route("/api/users", get(api::list_users))
        .route("/api/users/{email}/role", put(api::set_user_role))
        .route(
            "/api/users/{email}/sessions",
            delete(api::delete_user_sessions),
        )
        .route("/api/users/{email}", delete(api::delete_user))
        .route("/api/users/{email}/disable", post(api::disable_user))
        .route("/api/users/{email}/enable", post(api::enable_user))
        .route("/api/admin/group-mappings", get(api::list_group_mappings))
        .route("/api/admin/group-mappings", post(api::create_group_mapping))
        .route(
            "/api/admin/group-mappings/{id}",
            put(api::update_group_mapping),
        )
        .route(
            "/api/admin/group-mappings/{id}",
            delete(api::delete_group_mapping),
        )
        .route("/api/me", get(api::me))
        // User API token self-service
        .route("/api/me/tokens", get(api::list_my_tokens))
        .route("/api/me/tokens", post(api::create_my_token))
        .route("/api/me/tokens/{id}", delete(api::revoke_my_token))
        // Admin token management
        .route("/api/admin/user-tokens", get(api::admin_list_user_tokens))
        .route("/api/admin/user-tokens", post(api::admin_create_user_token))
        .route(
            "/api/admin/user-tokens/{id}",
            delete(api::admin_revoke_user_token),
        )
        .route("/api/admin/token-audit", get(api::admin_token_audit))
        // Address book routes
        .route("/api/addressbook/folders", get(api::ab_list_folders))
        .route("/api/addressbook/folders", post(api::ab_create_folder))
        .route(
            "/api/addressbook/folders/{scope}/{folder}",
            put(api::ab_update_folder),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}",
            delete(api::ab_delete_folder),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/entries",
            get(api::ab_list_entries),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/entries",
            post(api::ab_create_entry),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/entries/{entry}",
            put(api::ab_update_entry),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/entries/{entry}",
            delete(api::ab_delete_entry),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/entries/{entry}/connect",
            post(api::ab_connect_entry),
        )
        .merge(session_create_route)
        .with_state(manager.clone())
        .layer(GovernorLayer::new(api_governor_conf))
        .layer(middleware::from_fn(auth::require_auth))
        .layer(Extension(vault_client.clone()))
        .layer(Extension(vault_configured.clone()))
        .layer(Extension(database.clone()));

    // WebSocket route with optional auth and rate limiting
    let ws_route = Router::new()
        .route("/ws/{session_id}", get(websocket::ws_handler))
        .with_state(manager.clone())
        .layer(GovernorLayer::new(ws_governor_conf))
        .layer(middleware::from_fn(auth::optional_auth))
        .layer(Extension(database.clone()));

    // Quick-connect route with optional auth (handles its own redirect-to-login)
    let connect_route = Router::new()
        .route("/api/connect", get(api::quick_connect))
        .with_state(manager.clone())
        .layer(middleware::from_fn(auth::optional_auth))
        .layer(Extension(vault_client.clone()))
        .layer(Extension(oidc_enabled.clone()))
        .layer(Extension(database.clone()));

    // Unauthenticated stateful routes
    let unauth_routes = Router::new()
        .route("/api/health", get(api::health))
        .route("/api/docs", get(api::get_docs))
        .route("/api/sessions/{id}/banner", get(api::get_session_banner))
        .route("/client/{session_id}", get(serve_client_page))
        .with_state(manager);

    // Build full router (all Router<()> at this point)
    let mut app: Router<()> = Router::new()
        .route("/api/auth/status", get(api::auth_status))
        .merge(api_routes)
        .merge(ws_route)
        .merge(connect_route)
        .merge(unauth_routes);

    // Add OIDC routes if configured
    if let Some(ref oidc_st) = oidc_state {
        let oidc_routes = Router::new()
            .route("/auth/login", get(oidc::login))
            .route("/auth/callback", get(oidc::callback))
            .with_state(oidc_st.clone())
            .layer(Extension(database.clone()));

        let logout_route = Router::new()
            .route("/auth/logout", get(oidc::logout))
            .layer(Extension(database.clone()));

        app = app.merge(oidc_routes).merge(logout_route);
    }

    // Add shared layers
    let tls_enabled = TlsEnabled(tls_config.is_some());
    app = app
        .layer(DefaultBodyLimit::max(64 * 1024)) // 64 KB max request body
        .layer(middleware::from_fn(security_headers))
        .layer(Extension(tls_enabled))
        .layer(Extension(oidc_enabled))
        .layer(Extension(site_title))
        .layer(Extension(theme_data))
        .layer(Extension(trusted_proxies))
        .fallback_service(ServeDir::new(&static_path));

    let scheme = if tls_config.is_some() {
        "https"
    } else {
        "http"
    };
    tracing::info!("rustguac starting on {}://{}", scheme, listen_addr);
    tracing::info!("Static files served from {:?}", static_path);

    if let Some(ref tls) = tls_config {
        use axum_server::tls_rustls::RustlsConfig;

        let rustls_config = RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path)
            .await
            .expect("Failed to load TLS certificates");

        let addr: SocketAddr = listen_addr.parse().expect("Invalid listen address");
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .expect("Server error");
    } else {
        let listener = tokio::net::TcpListener::bind(&listen_addr)
            .await
            .expect("Failed to bind listener");

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("Shutdown signal received");
        })
        .await
        .expect("Server error");
    }

    // Cleanup LUKS on shutdown
    if let Some(ref drive_config) = shutdown_drive_config {
        if drive_config.enabled && drive::luks_configured(drive_config) {
            tracing::info!("Unmounting LUKS drive volume...");
            if let Err(e) = drive::unmount_luks(drive_config).await {
                tracing::warn!("Failed to unmount LUKS volume on shutdown: {}", e);
            }
        }
    }
}

/// Build a TLS connector for the guacd connection, if `tls.guacd_cert_path` is configured.
fn build_guacd_tls(config: &Config) -> Option<tokio_rustls::TlsConnector> {
    let cert_path = config.tls.as_ref()?.guacd_cert_path.as_ref()?;

    let pem_data = std::fs::read(cert_path)
        .unwrap_or_else(|e| panic!("Failed to read guacd cert {}: {}", cert_path.display(), e));

    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    let certs: Vec<_> = rustls_pemfile::certs(&mut &pem_data[..])
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| panic!("Failed to parse guacd cert PEM: {}", e));

    for cert in certs {
        root_store
            .add(cert)
            .unwrap_or_else(|e| panic!("Failed to add guacd cert to root store: {}", e));
    }

    let tls_config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    tracing::info!(
        "guacd TLS enabled, trusting cert from {}",
        cert_path.display()
    );
    Some(tokio_rustls::TlsConnector::from(Arc::new(tls_config)))
}

/// Serve the client HTML page for SSH sessions.
/// The session_id is extracted by the JS on the page, not by this handler.
async fn serve_client_page() -> Html<&'static str> {
    Html(include_str!("../static/client.html"))
}
