//! SQLite database layer for admin/API key management.

use chrono::{DateTime, Utc};
use rand::Rng;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub type Db = Arc<Mutex<Connection>>;

/// Admin record (safe to display — no key material).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdminInfo {
    pub id: i64,
    pub name: String,
    pub allowed_ips: Option<String>,
    pub expires_at: Option<String>,
    pub disabled: bool,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// User record from OIDC login.
#[derive(Debug, Clone, serde::Serialize)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub name: String,
    pub oidc_subject: Option<String>,
    pub role: String,
    pub disabled: bool,
    pub created_at: String,
    pub last_login_at: Option<String>,
    /// Comma-separated OIDC group memberships (updated on each login).
    #[serde(default)]
    pub oidc_groups: String,
}

impl User {
    /// Return OIDC groups as a Vec, splitting the comma-separated string.
    pub fn groups_vec(&self) -> Vec<String> {
        if self.oidc_groups.is_empty() {
            Vec::new()
        } else {
            self.oidc_groups.split(',').map(|s| s.to_string()).collect()
        }
    }
}

/// User API token record (safe to display — no key material).
#[derive(Debug, Clone, serde::Serialize)]
pub struct UserApiToken {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub max_role: Option<String>,
    pub expires_at: Option<String>,
    pub disabled: bool,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// Token audit log entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenAuditEntry {
    pub id: i64,
    pub token_id: Option<i64>,
    pub token_name: Option<String>,
    pub user_email: String,
    pub action: String,
    pub ip_addr: Option<String>,
    pub details: Option<String>,
    pub created_at: String,
}

/// Open (or create) the database and run migrations.
pub fn init_db(path: &Path) -> rusqlite::Result<Db> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS admins (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT NOT NULL UNIQUE,
            api_key_hash  TEXT NOT NULL,
            allowed_ips   TEXT,
            expires_at    TEXT,
            disabled      INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            last_used_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            email         TEXT NOT NULL UNIQUE,
            name          TEXT NOT NULL DEFAULT '',
            oidc_subject  TEXT,
            role          TEXT NOT NULL DEFAULT 'viewer',
            disabled      INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            last_login_at TEXT
        );

        CREATE TABLE IF NOT EXISTS auth_sessions (
            token         TEXT PRIMARY KEY,
            user_id       INTEGER NOT NULL REFERENCES users(id),
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS group_role_mappings (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            oidc_group TEXT NOT NULL UNIQUE,
            role       TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS user_api_tokens (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL REFERENCES users(id),
            name          TEXT NOT NULL,
            token_hash    TEXT NOT NULL UNIQUE,
            max_role      TEXT,
            expires_at    TEXT,
            disabled      INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            last_used_at  TEXT,
            UNIQUE(user_id, name)
        );

        CREATE TABLE IF NOT EXISTS token_audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id   INTEGER,
            token_name TEXT,
            user_email TEXT NOT NULL,
            action     TEXT NOT NULL,
            ip_addr    TEXT,
            details    TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )?;

    // Migration: add oidc_groups column if it doesn't exist
    let has_oidc_groups: bool = conn
        .prepare("SELECT oidc_groups FROM users LIMIT 0")
        .is_ok();
    if !has_oidc_groups {
        conn.execute_batch("ALTER TABLE users ADD COLUMN oidc_groups TEXT NOT NULL DEFAULT ''")?;
    }

    Ok(Arc::new(Mutex::new(conn)))
}

/// Hash an API key with SHA-256 and return hex.
fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a 256-bit random API key as hex (64 chars).
fn generate_key() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// Create a new admin. Returns the plaintext API key (shown once).
pub fn add_admin(
    db: &Db,
    name: &str,
    allowed_ips: Option<&str>,
    expires_at: Option<&str>,
) -> rusqlite::Result<String> {
    let key = generate_key();
    let key_hash = hash_key(&key);
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO admins (name, api_key_hash, allowed_ips, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![name, key_hash, allowed_ips, expires_at],
    )?;
    Ok(key)
}

/// List all admins (no key material).
pub fn list_admins(db: &Db) -> rusqlite::Result<Vec<AdminInfo>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, name, allowed_ips, expires_at, disabled, created_at, last_used_at FROM admins ORDER BY id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(AdminInfo {
            id: row.get(0)?,
            name: row.get(1)?,
            allowed_ips: row.get(2)?,
            expires_at: row.get(3)?,
            disabled: row.get::<_, i32>(4)? != 0,
            created_at: row.get(5)?,
            last_used_at: row.get(6)?,
        })
    })?;
    rows.collect()
}

/// Validate an API key against the database.
/// Checks: exists, not disabled, not expired, IP allowed.
/// On success, updates last_used_at and returns the admin info.
/// Uses constant-time hash comparison (defence-in-depth against timing attacks).
pub fn validate_api_key(
    db: &Db,
    key: &str,
    client_ip: Option<IpAddr>,
) -> Result<AdminInfo, AuthError> {
    use subtle::ConstantTimeEq;

    let key_hash = hash_key(key);
    let conn = db.lock().unwrap();

    // Fetch all admins and compare hashes in constant time
    let mut stmt = conn
        .prepare(
            "SELECT id, name, allowed_ips, expires_at, disabled, created_at, last_used_at, api_key_hash
             FROM admins",
        )
        .map_err(|_| AuthError::InvalidKey)?;
    let admin = stmt
        .query_map([], |row| {
            let stored_hash: String = row.get(7)?;
            Ok((
                AdminInfo {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    allowed_ips: row.get(2)?,
                    expires_at: row.get(3)?,
                    disabled: row.get::<_, i32>(4)? != 0,
                    created_at: row.get(5)?,
                    last_used_at: row.get(6)?,
                },
                stored_hash,
            ))
        })
        .map_err(|_| AuthError::InvalidKey)?
        .filter_map(|r| r.ok())
        .find(|(_, stored_hash)| key_hash.as_bytes().ct_eq(stored_hash.as_bytes()).into())
        .map(|(admin, _)| admin)
        .ok_or(AuthError::InvalidKey)?;

    if admin.disabled {
        return Err(AuthError::Disabled);
    }

    if let Some(ref exp) = admin.expires_at {
        if let Ok(expires) = exp.parse::<DateTime<Utc>>() {
            if Utc::now() > expires {
                return Err(AuthError::Expired);
            }
        }
    }

    if let (Some(ref cidrs), Some(ip)) = (&admin.allowed_ips, client_ip) {
        let allowed = cidrs.split(',').any(|cidr| {
            cidr.trim()
                .parse::<ipnetwork::IpNetwork>()
                .map(|net| net.contains(ip))
                .unwrap_or(false)
        });
        if !allowed {
            return Err(AuthError::IpNotAllowed);
        }
    }

    // Update last_used_at
    let _ = conn.execute(
        "UPDATE admins SET last_used_at = datetime('now') WHERE id = ?1",
        params![admin.id],
    );

    Ok(admin)
}

/// Disable an admin by name.
pub fn disable_admin(db: &Db, name: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE admins SET disabled = 1 WHERE name = ?1",
        params![name],
    )?;
    Ok(changed > 0)
}

/// Enable an admin by name.
pub fn enable_admin(db: &Db, name: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE admins SET disabled = 0 WHERE name = ?1",
        params![name],
    )?;
    Ok(changed > 0)
}

/// Delete an admin by name.
pub fn delete_admin(db: &Db, name: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute("DELETE FROM admins WHERE name = ?1", params![name])?;
    Ok(changed > 0)
}

/// Rotate an admin's API key. Returns the new plaintext key.
pub fn rotate_key(db: &Db, name: &str) -> rusqlite::Result<Option<String>> {
    let key = generate_key();
    let key_hash = hash_key(&key);
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE admins SET api_key_hash = ?1 WHERE name = ?2",
        params![key_hash, name],
    )?;
    if changed > 0 {
        Ok(Some(key))
    } else {
        Ok(None)
    }
}

#[derive(Debug)]
pub enum AuthError {
    InvalidKey,
    Disabled,
    Expired,
    IpNotAllowed,
    InvalidSession,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "invalid API key"),
            Self::Disabled => write!(f, "admin account is disabled"),
            Self::Expired => write!(f, "API key has expired"),
            Self::IpNotAllowed => write!(f, "client IP not in allowed list"),
            Self::InvalidSession => write!(f, "invalid or expired session"),
        }
    }
}

// ── User management ──

/// Upsert a user from OIDC login. Creates on first login, updates last_login_at on subsequent.
pub fn upsert_user(
    db: &Db,
    email: &str,
    name: &str,
    oidc_subject: Option<&str>,
    default_role: &str,
    groups: &[String],
) -> rusqlite::Result<User> {
    let groups_str = groups.join(",");
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO users (email, name, oidc_subject, role, oidc_groups)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(email) DO UPDATE SET
             name = excluded.name,
             oidc_subject = COALESCE(excluded.oidc_subject, users.oidc_subject),
             oidc_groups = excluded.oidc_groups,
             last_login_at = datetime('now')",
        params![email, name, oidc_subject, default_role, groups_str],
    )?;
    conn.query_row(
        "SELECT id, email, name, oidc_subject, role, disabled, created_at, last_login_at, oidc_groups
         FROM users WHERE email = ?1",
        params![email],
        |row| {
            Ok(User {
                id: row.get(0)?,
                email: row.get(1)?,
                name: row.get(2)?,
                oidc_subject: row.get(3)?,
                role: row.get(4)?,
                disabled: row.get::<_, i32>(5)? != 0,
                created_at: row.get(6)?,
                last_login_at: row.get(7)?,
                oidc_groups: row.get(8)?,
            })
        },
    )
}

/// Create an auth session for a user. Returns the session token (256-bit hex).
/// `ttl_secs` controls how long the session is valid.
pub fn create_auth_session(db: &Db, user_id: i64, ttl_secs: u64) -> rusqlite::Result<String> {
    let token = generate_key();
    let conn = db.lock().unwrap();
    let ttl_modifier = format!("+{} seconds", ttl_secs);
    conn.execute(
        "INSERT INTO auth_sessions (token, user_id, expires_at)
         VALUES (?1, ?2, datetime('now', ?3))",
        params![token, user_id, ttl_modifier],
    )?;
    Ok(token)
}

/// Delete all auth sessions for a user (force logout).
pub fn delete_user_sessions(db: &Db, user_id: i64) -> rusqlite::Result<usize> {
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM auth_sessions WHERE user_id = ?1",
        params![user_id],
    )
}

/// Look up a user by email.
pub fn get_user_by_email(db: &Db, email: &str) -> rusqlite::Result<User> {
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT id, email, name, oidc_subject, role, disabled, created_at, last_login_at, oidc_groups
         FROM users WHERE email = ?1",
        params![email],
        |row| {
            Ok(User {
                id: row.get(0)?,
                email: row.get(1)?,
                name: row.get(2)?,
                oidc_subject: row.get(3)?,
                role: row.get(4)?,
                disabled: row.get::<_, i32>(5)? != 0,
                created_at: row.get(6)?,
                last_login_at: row.get(7)?,
                oidc_groups: row.get(8)?,
            })
        },
    )
}

/// Validate an auth session token. Returns the user if valid and not expired/disabled.
pub fn validate_auth_session(db: &Db, token: &str) -> Result<User, AuthError> {
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT u.id, u.email, u.name, u.oidc_subject, u.role, u.disabled, u.created_at, u.last_login_at, u.oidc_groups
         FROM auth_sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token = ?1 AND s.expires_at > datetime('now')",
        params![token],
        |row| {
            Ok(User {
                id: row.get(0)?,
                email: row.get(1)?,
                name: row.get(2)?,
                oidc_subject: row.get(3)?,
                role: row.get(4)?,
                disabled: row.get::<_, i32>(5)? != 0,
                created_at: row.get(6)?,
                last_login_at: row.get(7)?,
                oidc_groups: row.get(8)?,
            })
        },
    )
    .map_err(|_| AuthError::InvalidSession)
    .and_then(|user| {
        if user.disabled {
            Err(AuthError::Disabled)
        } else {
            Ok(user)
        }
    })
}

/// Delete an auth session (logout).
pub fn delete_auth_session(db: &Db, token: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute("DELETE FROM auth_sessions WHERE token = ?1", params![token])?;
    Ok(changed > 0)
}

/// Clean up expired auth sessions.
pub fn cleanup_expired_sessions(db: &Db) -> rusqlite::Result<usize> {
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM auth_sessions WHERE expires_at <= datetime('now')",
        [],
    )
}

/// List all users.
pub fn list_users(db: &Db) -> rusqlite::Result<Vec<User>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, email, name, oidc_subject, role, disabled, created_at, last_login_at, oidc_groups
         FROM users ORDER BY id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(User {
            id: row.get(0)?,
            email: row.get(1)?,
            name: row.get(2)?,
            oidc_subject: row.get(3)?,
            role: row.get(4)?,
            disabled: row.get::<_, i32>(5)? != 0,
            created_at: row.get(6)?,
            last_login_at: row.get(7)?,
            oidc_groups: row.get(8)?,
        })
    })?;
    rows.collect()
}

/// Set a user's role by email.
pub fn set_user_role(db: &Db, email: &str, role: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE users SET role = ?1 WHERE email = ?2",
        params![role, email],
    )?;
    Ok(changed > 0)
}

/// Disable a user by email.
pub fn disable_user(db: &Db, email: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE users SET disabled = 1 WHERE email = ?1",
        params![email],
    )?;
    Ok(changed > 0)
}

/// Enable a user by email.
pub fn enable_user(db: &Db, email: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE users SET disabled = 0 WHERE email = ?1",
        params![email],
    )?;
    Ok(changed > 0)
}

/// Delete a user by email (also deletes their auth sessions and API tokens).
pub fn delete_user(db: &Db, email: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    // Delete auth sessions first
    conn.execute(
        "DELETE FROM auth_sessions WHERE user_id IN (SELECT id FROM users WHERE email = ?1)",
        params![email],
    )?;
    // Delete user API tokens
    conn.execute(
        "DELETE FROM user_api_tokens WHERE user_id IN (SELECT id FROM users WHERE email = ?1)",
        params![email],
    )?;
    let changed = conn.execute("DELETE FROM users WHERE email = ?1", params![email])?;
    Ok(changed > 0)
}

// ── Group-to-role mappings ──

/// A mapping from an OIDC group name to a role.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GroupRoleMapping {
    pub id: i64,
    pub oidc_group: String,
    pub role: String,
    pub created_at: String,
}

/// List all group-to-role mappings.
pub fn list_group_mappings(db: &Db) -> rusqlite::Result<Vec<GroupRoleMapping>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT id, oidc_group, role, created_at FROM group_role_mappings ORDER BY id")?;
    let rows = stmt.query_map([], |row| {
        Ok(GroupRoleMapping {
            id: row.get(0)?,
            oidc_group: row.get(1)?,
            role: row.get(2)?,
            created_at: row.get(3)?,
        })
    })?;
    rows.collect()
}

/// Create a group-to-role mapping. Returns the new mapping.
pub fn create_group_mapping(
    db: &Db,
    oidc_group: &str,
    role: &str,
) -> rusqlite::Result<GroupRoleMapping> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO group_role_mappings (oidc_group, role) VALUES (?1, ?2)",
        params![oidc_group, role],
    )?;
    let id = conn.last_insert_rowid();
    conn.query_row(
        "SELECT id, oidc_group, role, created_at FROM group_role_mappings WHERE id = ?1",
        params![id],
        |row| {
            Ok(GroupRoleMapping {
                id: row.get(0)?,
                oidc_group: row.get(1)?,
                role: row.get(2)?,
                created_at: row.get(3)?,
            })
        },
    )
}

/// Update a group-to-role mapping by id.
pub fn update_group_mapping(
    db: &Db,
    id: i64,
    oidc_group: &str,
    role: &str,
) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE group_role_mappings SET oidc_group = ?1, role = ?2 WHERE id = ?3",
        params![oidc_group, role, id],
    )?;
    Ok(changed > 0)
}

/// Delete a group-to-role mapping by id.
pub fn delete_group_mapping(db: &Db, id: i64) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute("DELETE FROM group_role_mappings WHERE id = ?1", params![id])?;
    Ok(changed > 0)
}

// ── User API tokens ──

/// Create a user API token. Returns the plaintext token (shown once).
/// The token is prefixed with `rgu_` to distinguish from admin keys.
pub fn create_user_token(
    db: &Db,
    user_id: i64,
    name: &str,
    max_role: Option<&str>,
    expires_at: Option<&str>,
) -> rusqlite::Result<(i64, String)> {
    let raw_key = generate_key();
    let token = format!("rgu_{}", raw_key);
    let token_hash = hash_key(&token);
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO user_api_tokens (user_id, name, token_hash, max_role, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![user_id, name, token_hash, max_role, expires_at],
    )?;
    let id = conn.last_insert_rowid();
    Ok((id, token))
}

/// List all tokens for a specific user (no key material).
pub fn list_user_tokens(db: &Db, user_id: i64) -> rusqlite::Result<Vec<UserApiToken>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, user_id, name, max_role, expires_at, disabled, created_at, last_used_at
         FROM user_api_tokens WHERE user_id = ?1 ORDER BY id",
    )?;
    let rows = stmt.query_map(params![user_id], |row| {
        Ok(UserApiToken {
            id: row.get(0)?,
            user_id: row.get(1)?,
            name: row.get(2)?,
            max_role: row.get(3)?,
            expires_at: row.get(4)?,
            disabled: row.get::<_, i32>(5)? != 0,
            created_at: row.get(6)?,
            last_used_at: row.get(7)?,
        })
    })?;
    rows.collect()
}

/// Admin view: list all user tokens with the user's email.
pub fn list_all_user_tokens(db: &Db) -> rusqlite::Result<Vec<(UserApiToken, String)>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT t.id, t.user_id, t.name, t.max_role, t.expires_at, t.disabled, t.created_at, t.last_used_at, u.email
         FROM user_api_tokens t
         JOIN users u ON u.id = t.user_id
         ORDER BY t.id",
    )?;
    let rows = stmt.query_map([], |row| {
        let token = UserApiToken {
            id: row.get(0)?,
            user_id: row.get(1)?,
            name: row.get(2)?,
            max_role: row.get(3)?,
            expires_at: row.get(4)?,
            disabled: row.get::<_, i32>(5)? != 0,
            created_at: row.get(6)?,
            last_used_at: row.get(7)?,
        };
        let email: String = row.get(8)?;
        Ok((token, email))
    })?;
    rows.collect()
}

/// Validate a user API token. Returns the user and token metadata.
/// Checks: exists, not disabled, not expired, user not disabled.
/// Updates last_used_at on success.
/// Uses constant-time hash comparison (defence-in-depth against timing attacks).
pub fn validate_user_token(db: &Db, token: &str) -> Result<(User, UserApiToken), AuthError> {
    use subtle::ConstantTimeEq;

    let token_hash = hash_key(token);
    let conn = db.lock().unwrap();

    // Fetch all tokens with their users and compare hashes in constant time
    let mut stmt = conn
        .prepare(
            "SELECT t.id, t.user_id, t.name, t.max_role, t.expires_at, t.disabled, t.created_at, t.last_used_at,
                    u.id, u.email, u.name, u.oidc_subject, u.role, u.disabled, u.created_at, u.last_login_at, u.oidc_groups,
                    t.token_hash
             FROM user_api_tokens t
             JOIN users u ON u.id = t.user_id",
        )
        .map_err(|_| AuthError::InvalidKey)?;
    let (user, token_info) = stmt
        .query_map([], |row| {
            let stored_hash: String = row.get(17)?;
            let token_info = UserApiToken {
                id: row.get(0)?,
                user_id: row.get(1)?,
                name: row.get(2)?,
                max_role: row.get(3)?,
                expires_at: row.get(4)?,
                disabled: row.get::<_, i32>(5)? != 0,
                created_at: row.get(6)?,
                last_used_at: row.get(7)?,
            };
            let user = User {
                id: row.get(8)?,
                email: row.get(9)?,
                name: row.get(10)?,
                oidc_subject: row.get(11)?,
                role: row.get(12)?,
                disabled: row.get::<_, i32>(13)? != 0,
                created_at: row.get(14)?,
                last_login_at: row.get(15)?,
                oidc_groups: row.get(16)?,
            };
            Ok((user, token_info, stored_hash))
        })
        .map_err(|_| AuthError::InvalidKey)?
        .filter_map(|r| r.ok())
        .find(|(_, _, stored_hash)| token_hash.as_bytes().ct_eq(stored_hash.as_bytes()).into())
        .map(|(user, token_info, _)| (user, token_info))
        .ok_or(AuthError::InvalidKey)?;

    if token_info.disabled {
        return Err(AuthError::Disabled);
    }

    if user.disabled {
        return Err(AuthError::Disabled);
    }

    if let Some(ref exp) = token_info.expires_at {
        if let Ok(expires) = exp.parse::<DateTime<Utc>>() {
            if Utc::now() > expires {
                return Err(AuthError::Expired);
            }
        }
    }

    // Update last_used_at
    let _ = conn.execute(
        "UPDATE user_api_tokens SET last_used_at = datetime('now') WHERE id = ?1",
        params![token_info.id],
    );

    Ok((user, token_info))
}

/// Revoke (delete) a specific token. Ownership check: user_id must match.
pub fn revoke_user_token(db: &Db, user_id: i64, token_id: i64) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "DELETE FROM user_api_tokens WHERE id = ?1 AND user_id = ?2",
        params![token_id, user_id],
    )?;
    Ok(changed > 0)
}

/// Admin: revoke any user's token by ID (no ownership check).
pub fn admin_revoke_user_token(db: &Db, token_id: i64) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "DELETE FROM user_api_tokens WHERE id = ?1",
        params![token_id],
    )?;
    Ok(changed > 0)
}

/// Revoke all tokens for a user.
#[allow(dead_code)]
pub fn revoke_all_user_tokens(db: &Db, user_id: i64) -> rusqlite::Result<usize> {
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM user_api_tokens WHERE user_id = ?1",
        params![user_id],
    )
}

/// Clean up expired user API tokens.
pub fn cleanup_expired_user_tokens(db: &Db) -> rusqlite::Result<usize> {
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM user_api_tokens WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')",
        [],
    )
}

// ── Token audit log ──

/// Log a token lifecycle event.
pub fn log_token_event(
    db: &Db,
    token_id: Option<i64>,
    token_name: Option<&str>,
    user_email: &str,
    action: &str,
    ip_addr: Option<&str>,
    details: Option<&str>,
) -> rusqlite::Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO token_audit_log (token_id, token_name, user_email, action, ip_addr, details)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![token_id, token_name, user_email, action, ip_addr, details],
    )?;
    Ok(())
}

/// List token audit log entries, most recent first, with optional limit.
pub fn list_token_audit_log(
    db: &Db,
    limit: u32,
    user_email: Option<&str>,
) -> rusqlite::Result<Vec<TokenAuditEntry>> {
    let conn = db.lock().unwrap();
    let (sql, params_vec): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) =
        if let Some(email) = user_email {
            (
                "SELECT id, token_id, token_name, user_email, action, ip_addr, details, created_at
             FROM token_audit_log WHERE user_email = ?1 ORDER BY id DESC LIMIT ?2",
                vec![Box::new(email.to_string()), Box::new(limit)],
            )
        } else {
            (
                "SELECT id, token_id, token_name, user_email, action, ip_addr, details, created_at
             FROM token_audit_log ORDER BY id DESC LIMIT ?1",
                vec![Box::new(limit)],
            )
        };
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(params_vec.iter()), |row| {
        Ok(TokenAuditEntry {
            id: row.get(0)?,
            token_id: row.get(1)?,
            token_name: row.get(2)?,
            user_email: row.get(3)?,
            action: row.get(4)?,
            ip_addr: row.get(5)?,
            details: row.get(6)?,
            created_at: row.get(7)?,
        })
    })?;
    rows.collect()
}

/// Clean up old audit log entries (retain last N days).
pub fn cleanup_old_audit_log(db: &Db, retain_days: u32) -> rusqlite::Result<usize> {
    let conn = db.lock().unwrap();
    let modifier = format!("-{} days", retain_days);
    conn.execute(
        "DELETE FROM token_audit_log WHERE created_at < datetime('now', ?1)",
        params![modifier],
    )
}

/// Resolve the best role for a user based on their OIDC groups and the group-to-role mappings.
/// Returns `Some(role)` if at least one group matched a mapping (highest wins),
/// or `None` if no mappings matched (caller should preserve the existing role).
pub fn resolve_role_from_groups(db: &Db, groups: &[String]) -> rusqlite::Result<Option<String>> {
    if groups.is_empty() {
        return Ok(None);
    }

    let mappings = list_group_mappings(db)?;
    if mappings.is_empty() {
        return Ok(None);
    }

    fn role_level(role: &str) -> u8 {
        match role {
            "admin" => 4,
            "poweruser" => 3,
            "operator" => 2,
            "viewer" => 1,
            _ => 0,
        }
    }

    let mut best_level = 0u8;
    let mut best_role: Option<String> = None;

    for mapping in &mappings {
        if groups.iter().any(|g| g == &mapping.oidc_group) {
            let level = role_level(&mapping.role);
            if level > best_level {
                best_level = level;
                best_role = Some(mapping.role.clone());
            }
        }
    }

    Ok(best_role)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_key_sha256() {
        let hash = hash_key("test-api-key");
        assert_eq!(hash.len(), 64); // SHA-256 = 64 hex chars
                                    // Deterministic
        assert_eq!(hash, hash_key("test-api-key"));
    }

    #[test]
    fn test_hash_key_different_inputs() {
        assert_ne!(hash_key("key-a"), hash_key("key-b"));
    }

    #[test]
    fn test_generate_key_format() {
        let key = generate_key();
        assert_eq!(key.len(), 64); // 32 bytes = 64 hex chars
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_key_unique() {
        let a = generate_key();
        let b = generate_key();
        assert_ne!(a, b);
    }

    #[test]
    fn test_user_groups_vec() {
        let user = User {
            id: 1,
            oidc_subject: None,
            created_at: "2025-01-01".into(),
            last_login_at: None,
            email: "test@test.com".into(),
            name: "test".into(),
            role: "viewer".into(),
            disabled: false,
            oidc_groups: "admins,developers,ops".into(),
        };
        assert_eq!(user.groups_vec(), vec!["admins", "developers", "ops"]);
    }

    #[test]
    fn test_user_groups_vec_empty() {
        let user = User {
            id: 1,
            oidc_subject: None,
            created_at: "2025-01-01".into(),
            last_login_at: None,
            email: "test@test.com".into(),
            name: "test".into(),
            role: "viewer".into(),
            disabled: false,
            oidc_groups: String::new(),
        };
        assert!(user.groups_vec().is_empty());
    }

    #[test]
    fn test_user_groups_vec_single() {
        let user = User {
            id: 1,
            oidc_subject: None,
            created_at: "2025-01-01".into(),
            last_login_at: None,
            email: "test@test.com".into(),
            name: "test".into(),
            role: "viewer".into(),
            disabled: false,
            oidc_groups: "solo-group".into(),
        };
        assert_eq!(user.groups_vec(), vec!["solo-group"]);
    }
}
