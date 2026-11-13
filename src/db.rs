//! SQLite database layer for admin/API key management.

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use rand::RngExt;
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

/// Connections (address book) audit log entry. Persisted in SQLite, never in
/// Vault, so only headline metadata goes here: action name, target path, and
/// small counts. Entry field values (passwords, keys, usernames) must never
/// be written to `details` — see feedback_audit_log_scope.md.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AddressbookAuditEntry {
    pub id: i64,
    pub user_email: String,
    pub action: String,
    pub scope: String,
    pub folder_path: String,
    pub entry_name: Option<String>,
    pub ip_addr: Option<String>,
    pub details: Option<String>,
    pub created_at: String,
}

/// If we're running as root and the db's parent directory is owned by a non-root
/// user (the typical `/opt/rustguac/data` owned by `rustguac:rustguac` case),
/// chown the db file and any `-wal` / `-shm` sidecars to match the parent dir.
///
/// Why: CLI commands like `add-admin` are often run under `sudo`, which would
/// otherwise create a root-owned db that the systemd service (running as the
/// unprivileged `rustguac` user) can't write to — surfacing later as
/// "attempt to write a readonly database" on the first OIDC login.
fn repair_db_ownership(path: &Path) {
    use std::os::unix::fs::MetadataExt;

    // Only act when running as root — otherwise chown(2) would fail anyway.
    // SAFETY: geteuid is always safe, takes no args.
    if unsafe { libc::geteuid() } != 0 {
        return;
    }

    let Some(parent) = path.parent() else { return };
    let Ok(parent_meta) = std::fs::metadata(parent) else {
        return;
    };
    let target_uid = parent_meta.uid();
    let target_gid = parent_meta.gid();
    if target_uid == 0 && target_gid == 0 {
        return;
    }

    let stem = path.as_os_str().to_os_string();
    let mut wal = stem.clone();
    wal.push("-wal");
    let mut shm = stem.clone();
    shm.push("-shm");

    for candidate in [path.as_os_str(), wal.as_os_str(), shm.as_os_str()] {
        let p = Path::new(candidate);
        let Ok(meta) = std::fs::metadata(p) else {
            continue;
        };
        if meta.uid() == target_uid && meta.gid() == target_gid {
            continue;
        }
        let c_path = match std::ffi::CString::new(candidate.as_encoded_bytes()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // SAFETY: c_path is a valid NUL-terminated C string pointing to an existing file.
        let rc = unsafe { libc::chown(c_path.as_ptr(), target_uid, target_gid) };
        if rc != 0 {
            eprintln!(
                "warning: failed to chown {} to {}:{}: {}",
                p.display(),
                target_uid,
                target_gid,
                std::io::Error::last_os_error()
            );
        }
    }
}

/// Open (or create) the database and run migrations.
pub fn init_db(path: &Path) -> rusqlite::Result<Db> {
    let conn = Connection::open(path)?;
    repair_db_ownership(path);
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
            token_hash    TEXT PRIMARY KEY,
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

        CREATE TABLE IF NOT EXISTS seen_groups (
            name       TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL DEFAULT (datetime('now')),
            last_seen  TEXT NOT NULL DEFAULT (datetime('now'))
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
        );

        CREATE TABLE IF NOT EXISTS session_history (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id         TEXT NOT NULL,
            session_type       TEXT NOT NULL,
            hostname           TEXT NOT NULL,
            port               INTEGER,
            username           TEXT NOT NULL DEFAULT '',
            created_by         TEXT NOT NULL,
            address_book_entry TEXT,
            address_book_folder TEXT,
            entry_display_name TEXT,
            started_at         TEXT NOT NULL DEFAULT (datetime('now')),
            ended_at           TEXT,
            duration_secs      INTEGER,
            recording_file     TEXT,
            status             TEXT NOT NULL DEFAULT 'active'
        );
        CREATE INDEX IF NOT EXISTS idx_sh_created_by ON session_history(created_by);
        CREATE INDEX IF NOT EXISTS idx_sh_entry ON session_history(address_book_entry);
        CREATE INDEX IF NOT EXISTS idx_sh_started ON session_history(started_at);

        CREATE TABLE IF NOT EXISTS addressbook_audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email  TEXT NOT NULL,
            action      TEXT NOT NULL,
            scope       TEXT NOT NULL,
            folder_path TEXT NOT NULL,
            entry_name  TEXT,
            ip_addr     TEXT,
            details     TEXT,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_ab_audit_created ON addressbook_audit_log(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ab_audit_user ON addressbook_audit_log(user_email);

        CREATE TABLE IF NOT EXISTS cli_audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            os_user    TEXT NOT NULL,
            action     TEXT NOT NULL,
            target     TEXT,
            details    TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_cli_audit_created ON cli_audit_log(created_at DESC);

        -- Custom roles (#294). Built-in roles are defined in code, never here.
        CREATE TABLE IF NOT EXISTS roles (
            name         TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            description  TEXT NOT NULL DEFAULT '',
            created_at   TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS role_permissions (
            role       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
            permission TEXT NOT NULL,
            PRIMARY KEY (role, permission)
        );

        -- Role, user and mapping changes made through the API (#294).
        CREATE TABLE IF NOT EXISTS admin_audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            actor      TEXT NOT NULL,
            action     TEXT NOT NULL,
            target     TEXT NOT NULL,
            details    TEXT,
            ip_addr    TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit_log(created_at DESC);",
    )?;

    // Migration: add oidc_groups column if it doesn't exist
    let has_oidc_groups: bool = conn
        .prepare("SELECT oidc_groups FROM users LIMIT 0")
        .is_ok();
    if !has_oidc_groups {
        conn.execute_batch("ALTER TABLE users ADD COLUMN oidc_groups TEXT NOT NULL DEFAULT ''")?;
    }

    // Migration: auth_sessions token → token_hash (v1.0.0 security hardening)
    let has_old_token_col: bool = conn
        .prepare("SELECT token FROM auth_sessions LIMIT 0")
        .is_ok();
    if has_old_token_col {
        conn.execute_batch(
            "DROP TABLE auth_sessions;
             CREATE TABLE auth_sessions (
                 token_hash    TEXT PRIMARY KEY,
                 user_id       INTEGER NOT NULL REFERENCES users(id),
                 created_at    TEXT NOT NULL DEFAULT (datetime('now')),
                 expires_at    TEXT NOT NULL
             );",
        )?;
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
/// Parse a stored `expires_at` value for expiry enforcement.
///
/// Accepts RFC 3339 (with offset), ISO without a zone and SQLite
/// `datetime('now')` format (both treated as UTC), and a bare `YYYY-MM-DD`
/// date (treated as end-of-day UTC). Returns `None` for anything unparseable
/// so callers can **fail closed** (treat an unparseable expiry as expired)
/// rather than the previous behaviour of silently ignoring it, which let a
/// malformed value authenticate forever.
pub(crate) fn parse_expires_at(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&ndt));
        }
    }
    if let Ok(nd) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Some(Utc.from_utc_datetime(&nd.and_hms_opt(23, 59, 59)?));
    }
    None
}

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
        // Fail closed: an unparseable expiry is treated as expired rather than
        // ignored, so a malformed value cannot authenticate indefinitely.
        match parse_expires_at(exp) {
            Some(expires) if Utc::now() <= expires => {}
            _ => return Err(AuthError::Expired),
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

/// Check an email an admin gives for a new user: what an identity provider
/// could send, not just anything. Returns the reason it is refused.
pub fn check_user_email(email: &str) -> Result<(), &'static str> {
    if email.is_empty() {
        return Err("email is required");
    }
    if email.len() > 254 {
        return Err("email is longer than 254 characters");
    }
    if email.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("email must not contain spaces or control characters");
    }
    if !email.contains('@') {
        return Err("email must contain @");
    }
    Ok(())
}

/// Check a display name an admin gives for a new user.
pub fn check_user_name(name: &str) -> Result<(), &'static str> {
    if name.chars().count() > 200 {
        return Err("name is longer than 200 characters");
    }
    if name.chars().any(|c| c.is_control()) {
        return Err("name must not contain control characters");
    }
    Ok(())
}

/// How an OIDC login matched the users table (`upsert_user`).
#[derive(Debug)]
pub enum OidcLogin {
    /// Logged in: the user's profile and last_login_at were updated, or the
    /// user was created.
    User(User),
    /// No user has this email, and creating one was not allowed
    /// (`auto_create_users = false`).
    NoAccount,
    /// The user with this email is bound to a different OIDC subject. Their
    /// identity provider account is not the one that logged in before, so
    /// the login is refused; `rustguac reset-oidc-subject` releases the
    /// binding after a provider migration.
    SubjectMismatch,
    /// More than one user has this email in a different case, so it is not
    /// clear who is logging in. Nothing was changed.
    Ambiguous,
}

/// Which user an email names (`find_user_for_email`).
enum EmailMatch {
    /// One user: their id and recorded OIDC subject.
    One(i64, Option<String>),
    None,
    /// Several users match ignoring case and none exactly.
    Ambiguous,
}

/// The user an email names: an exact match, or else the one user whose email
/// matches ignoring case (providers and admins do not always agree on case).
fn find_user_for_email(conn: &Connection, email: &str) -> rusqlite::Result<EmailMatch> {
    let exact = conn.query_row(
        "SELECT id, oidc_subject FROM users WHERE email = ?1",
        params![email],
        |row| Ok(EmailMatch::One(row.get(0)?, row.get(1)?)),
    );
    match exact {
        Ok(found) => return Ok(found),
        Err(rusqlite::Error::QueryReturnedNoRows) => {}
        Err(e) => return Err(e),
    }
    let mut stmt =
        conn.prepare("SELECT id, oidc_subject FROM users WHERE lower(email) = lower(?1)")?;
    let mut rows: Vec<EmailMatch> = stmt
        .query_map(params![email], |row| {
            Ok(EmailMatch::One(row.get(0)?, row.get(1)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(match rows.len() {
        0 => EmailMatch::None,
        1 => rows.remove(0),
        _ => EmailMatch::Ambiguous,
    })
}

fn user_by_id(conn: &Connection, id: i64) -> rusqlite::Result<User> {
    conn.query_row(
        "SELECT id, email, name, oidc_subject, role, disabled, created_at, last_login_at, oidc_groups
         FROM users WHERE id = ?1",
        params![id],
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

/// Record an OIDC login.
///
/// The user is found by email, ignoring case. A user who has logged in before
/// is bound to the OIDC subject (`sub`) their provider sent then: a login
/// with the same email but a different subject is refused
/// (`SubjectMismatch`), because the email alone is not proof of identity (a
/// provider may let people set it). A user who has not logged in yet, such
/// as one an admin added, takes the subject of their first login.
///
/// A user not in the table is created with `default_role` when
/// `create_if_missing` is set; otherwise `NoAccount` and nothing is written
/// (OIDC `auto_create_users = false`).
pub fn upsert_user(
    db: &Db,
    email: &str,
    name: &str,
    oidc_subject: Option<&str>,
    default_role: &str,
    groups: &[String],
    create_if_missing: bool,
) -> rusqlite::Result<OidcLogin> {
    let groups_str = groups.join(",");
    let conn = db.lock().unwrap();
    let id = match find_user_for_email(&conn, email)? {
        EmailMatch::Ambiguous => return Ok(OidcLogin::Ambiguous),
        EmailMatch::One(id, recorded) => {
            if let (Some(recorded), Some(subject)) = (recorded.as_deref(), oidc_subject) {
                if recorded != subject {
                    return Ok(OidcLogin::SubjectMismatch);
                }
            }
            conn.execute(
                "UPDATE users SET
                     name = ?2,
                     oidc_subject = COALESCE(?3, oidc_subject),
                     oidc_groups = ?4,
                     last_login_at = datetime('now')
                 WHERE id = ?1",
                params![id, name, oidc_subject, groups_str],
            )?;
            id
        }
        EmailMatch::None if create_if_missing => {
            conn.execute(
                "INSERT INTO users (email, name, oidc_subject, role, oidc_groups, last_login_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))",
                params![email, name, oidc_subject, default_role, groups_str],
            )?;
            conn.last_insert_rowid()
        }
        EmailMatch::None => return Ok(OidcLogin::NoAccount),
    };
    user_by_id(&conn, id).map(OidcLogin::User)
}

/// Why `create_user` did not add a user.
#[derive(Debug)]
pub enum CreateUserError {
    /// A user with this email already exists, in any case.
    Exists,
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for CreateUserError {
    fn from(e: rusqlite::Error) -> Self {
        CreateUserError::Db(e)
    }
}

impl std::fmt::Display for CreateUserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CreateUserError::Exists => write!(f, "a user with that email already exists"),
            CreateUserError::Db(e) => write!(f, "{e}"),
        }
    }
}

/// Pre-provision a user so they can log in via OIDC when automatic account
/// creation is disabled. The OIDC subject, name and groups are filled in on
/// first login. Refused if a user with the same email exists in any case,
/// since logins match email ignoring case.
pub fn create_user(db: &Db, email: &str, name: &str, role: &str) -> Result<User, CreateUserError> {
    let conn = db.lock().unwrap();
    let taken: i64 = conn.query_row(
        "SELECT COUNT(*) FROM users WHERE lower(email) = lower(?1)",
        params![email],
        |row| row.get(0),
    )?;
    if taken > 0 {
        return Err(CreateUserError::Exists);
    }
    conn.execute(
        "INSERT INTO users (email, name, role) VALUES (?1, ?2, ?3)",
        params![email, name, role],
    )?;
    Ok(user_by_id(&conn, conn.last_insert_rowid())?)
}

/// Forget the OIDC subject a user is bound to, so their next login binds to
/// whatever subject it brings. For moving to a different identity provider,
/// where every user's subject changes. Returns the user's stored email, or
/// `None` when no user (or, ignoring case, more than one) has this email.
pub fn reset_oidc_subject(db: &Db, email: &str) -> rusqlite::Result<Option<String>> {
    let conn = db.lock().unwrap();
    match find_user_for_email(&conn, email)? {
        EmailMatch::One(id, _) => {
            conn.execute(
                "UPDATE users SET oidc_subject = NULL WHERE id = ?1",
                params![id],
            )?;
            Ok(Some(user_by_id(&conn, id)?.email))
        }
        _ => Ok(None),
    }
}

/// Create an auth session for a user. Returns the plaintext session token
/// (256-bit hex). Only the SHA-256 hash is stored in the database.
pub fn create_auth_session(db: &Db, user_id: i64, ttl_secs: u64) -> rusqlite::Result<String> {
    let token = generate_key();
    let token_hash = hash_key(&token);
    let conn = db.lock().unwrap();
    let ttl_modifier = format!("+{} seconds", ttl_secs);
    conn.execute(
        "INSERT INTO auth_sessions (token_hash, user_id, expires_at)
         VALUES (?1, ?2, datetime('now', ?3))",
        params![token_hash, user_id, ttl_modifier],
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
/// The token is hashed before lookup — only hashes are stored in the database.
pub fn validate_auth_session(db: &Db, token: &str) -> Result<User, AuthError> {
    let token_hash = hash_key(token);
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT u.id, u.email, u.name, u.oidc_subject, u.role, u.disabled, u.created_at, u.last_login_at, u.oidc_groups
         FROM auth_sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ?1 AND s.expires_at > datetime('now')",
        params![token_hash],
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

/// Delete an auth session (logout). Token is hashed before lookup.
pub fn delete_auth_session(db: &Db, token: &str) -> rusqlite::Result<bool> {
    let token_hash = hash_key(token);
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "DELETE FROM auth_sessions WHERE token_hash = ?1",
        params![token_hash],
    )?;
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

/// Upsert OIDC groups observed in a login token, updating last_seen.
pub fn upsert_seen_groups(db: &Db, groups: &[String]) -> rusqlite::Result<()> {
    if groups.is_empty() {
        return Ok(());
    }
    let mut conn = db.lock().unwrap();
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO seen_groups (name) VALUES (?1)
             ON CONFLICT(name) DO UPDATE SET last_seen = datetime('now')",
        )?;
        for g in groups {
            let trimmed = g.trim();
            if !trimmed.is_empty() {
                stmt.execute(params![trimmed])?;
            }
        }
    }
    tx.commit()?;
    Ok(())
}

/// List all known OIDC groups — union of configured role-mappings and groups
/// ever seen in a user's login claims. Sorted case-insensitively.
pub fn list_known_groups(db: &Db) -> rusqlite::Result<Vec<String>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT g FROM (
            SELECT oidc_group AS g FROM group_role_mappings
            UNION
            SELECT name AS g FROM seen_groups
         )
         WHERE g IS NOT NULL AND g <> ''
         ORDER BY g COLLATE NOCASE",
    )?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect()
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
        // Fail closed: an unparseable expiry is treated as expired rather than
        // ignored, so a malformed value cannot authenticate indefinitely.
        match parse_expires_at(exp) {
            Some(expires) if Utc::now() <= expires => {}
            _ => return Err(AuthError::Expired),
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
    let tok = conn.execute(
        "DELETE FROM token_audit_log WHERE created_at < datetime('now', ?1)",
        params![&modifier],
    )?;
    let ab = conn.execute(
        "DELETE FROM addressbook_audit_log WHERE created_at < datetime('now', ?1)",
        params![&modifier],
    )?;
    let cli = conn.execute(
        "DELETE FROM cli_audit_log WHERE created_at < datetime('now', ?1)",
        params![&modifier],
    )?;
    let admin = conn.execute(
        "DELETE FROM admin_audit_log WHERE created_at < datetime('now', ?1)",
        params![&modifier],
    )?;
    Ok(tok + ab + cli + admin)
}

// ── Connections (address book) audit log ──

/// Log a destructive or mutating connections action. Persisted in SQLite.
///
/// `details` is a free-form text blob (callers typically write JSON) but must
/// never contain entry field values or full request bodies (see
/// feedback_audit_log_scope.md). Counts, booleans, field-name lists are fine.
#[allow(clippy::too_many_arguments)]
pub fn log_addressbook_event(
    db: &Db,
    user_email: &str,
    action: &str,
    scope: &str,
    folder_path: &str,
    entry_name: Option<&str>,
    ip_addr: Option<&str>,
    details: Option<&str>,
) -> rusqlite::Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO addressbook_audit_log
            (user_email, action, scope, folder_path, entry_name, ip_addr, details)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            user_email,
            action,
            scope,
            folder_path,
            entry_name,
            ip_addr,
            details
        ],
    )?;
    Ok(())
}

// ── CLI audit log ──

/// Record an administrative action performed through the CLI.
///
/// CLI commands run locally with direct database access, so they bypass the
/// API's authenticated audit trail entirely; without this a role grant or an
/// account deletion made from a shell leaves no record at all.
///
/// `target` names what was acted on (an admin name, a user email, an OIDC
/// group). `details` is free-form and, like the other audit logs, must stay a
/// headline: never API keys, passwords, or full field values (see
/// feedback_audit_log_scope.md).
pub fn log_cli_event(
    db: &Db,
    os_user: &str,
    action: &str,
    target: Option<&str>,
    details: Option<&str>,
) -> rusqlite::Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO cli_audit_log (os_user, action, target, details)
         VALUES (?1, ?2, ?3, ?4)",
        params![os_user, action, target, details],
    )?;
    Ok(())
}

/// List connections audit log entries, most recent first, with optional
/// filters for limit and user_email.
pub fn list_addressbook_audit_log(
    db: &Db,
    limit: u32,
    user_email: Option<&str>,
) -> rusqlite::Result<Vec<AddressbookAuditEntry>> {
    let conn = db.lock().unwrap();
    let (sql, params_vec): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) =
        if let Some(email) = user_email {
            (
                "SELECT id, user_email, action, scope, folder_path, entry_name,
                        ip_addr, details, created_at
                 FROM addressbook_audit_log WHERE user_email = ?1
                 ORDER BY id DESC LIMIT ?2",
                vec![Box::new(email.to_string()), Box::new(limit)],
            )
        } else {
            (
                "SELECT id, user_email, action, scope, folder_path, entry_name,
                        ip_addr, details, created_at
                 FROM addressbook_audit_log ORDER BY id DESC LIMIT ?1",
                vec![Box::new(limit)],
            )
        };
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(params_vec.iter()), |row| {
        Ok(AddressbookAuditEntry {
            id: row.get(0)?,
            user_email: row.get(1)?,
            action: row.get(2)?,
            scope: row.get(3)?,
            folder_path: row.get(4)?,
            entry_name: row.get(5)?,
            ip_addr: row.get(6)?,
            details: row.get(7)?,
            created_at: row.get(8)?,
        })
    })?;
    rows.collect()
}

// ── Session history ──

/// Record a new session in the history table.
#[allow(clippy::too_many_arguments)]
pub fn insert_session_history(
    db: &Db,
    session_id: &str,
    session_type: &str,
    hostname: &str,
    port: Option<u16>,
    username: &str,
    created_by: &str,
    address_book_entry: Option<&str>,
    address_book_folder: Option<&str>,
    entry_display_name: Option<&str>,
) -> rusqlite::Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO session_history
         (session_id, session_type, hostname, port, username, created_by,
          address_book_entry, address_book_folder, entry_display_name)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            session_id,
            session_type,
            hostname,
            port.map(|p| p as i64),
            username,
            created_by,
            address_book_entry,
            address_book_folder,
            entry_display_name,
        ],
    )?;
    Ok(())
}

/// Mark a session as ended in the history table.
pub fn end_session_history(
    db: &Db,
    session_id: &str,
    status: &str,
    duration_secs: u64,
    recording_file: Option<&str>,
) -> rusqlite::Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE session_history
         SET ended_at = datetime('now'), duration_secs = ?2, status = ?3, recording_file = ?4
         WHERE session_id = ?1 AND ended_at IS NULL",
        params![session_id, duration_secs as i64, status, recording_file],
    )?;
    Ok(())
}

/// Query session history with optional filters. Returns JSON-ready rows.
#[allow(clippy::too_many_arguments)]
pub fn query_session_history(
    db: &Db,
    user: Option<&str>,
    entry: Option<&str>,
    session_type: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
    limit: u32,
    offset: u32,
) -> rusqlite::Result<(Vec<serde_json::Value>, u32)> {
    let conn = db.lock().unwrap();
    let mut conditions = vec!["1=1".to_string()];
    let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    let mut idx = 1;

    if let Some(u) = user {
        conditions.push(format!("created_by LIKE ?{}", idx));
        params_vec.push(Box::new(format!("%{}%", u)));
        idx += 1;
    }
    if let Some(e) = entry {
        conditions.push(format!(
            "(address_book_entry LIKE ?{} OR entry_display_name LIKE ?{})",
            idx, idx
        ));
        params_vec.push(Box::new(format!("%{}%", e)));
        idx += 1;
    }
    if let Some(t) = session_type {
        conditions.push(format!("session_type = ?{}", idx));
        params_vec.push(Box::new(t.to_string()));
        idx += 1;
    }
    if let Some(f) = from {
        conditions.push(format!("started_at >= ?{}", idx));
        params_vec.push(Box::new(f.to_string()));
        idx += 1;
    }
    if let Some(t) = to {
        conditions.push(format!("started_at <= ?{}", idx));
        params_vec.push(Box::new(t.to_string()));
        idx += 1;
    }

    let where_clause = conditions.join(" AND ");

    // Count total matching rows
    let count_sql = format!(
        "SELECT COUNT(*) FROM session_history WHERE {}",
        where_clause
    );
    let total: u32 = {
        let mut stmt = conn.prepare(&count_sql)?;
        stmt.query_row(rusqlite::params_from_iter(params_vec.iter()), |row| {
            row.get(0)
        })?
    };

    // Fetch page
    let query_sql = format!(
        "SELECT session_id, session_type, hostname, port, username, created_by,
                address_book_entry, address_book_folder, entry_display_name,
                started_at, ended_at, duration_secs, recording_file, status
         FROM session_history WHERE {} ORDER BY started_at DESC LIMIT ?{} OFFSET ?{}",
        where_clause,
        idx,
        idx + 1
    );
    params_vec.push(Box::new(limit));
    params_vec.push(Box::new(offset));

    let mut stmt = conn.prepare(&query_sql)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params_vec.iter()), |row| {
            Ok(serde_json::json!({
                "session_id": row.get::<_, String>(0)?,
                "session_type": row.get::<_, String>(1)?,
                "hostname": row.get::<_, String>(2)?,
                "port": row.get::<_, Option<i64>>(3)?,
                "username": row.get::<_, String>(4)?,
                "created_by": row.get::<_, String>(5)?,
                "address_book_entry": row.get::<_, Option<String>>(6)?,
                "address_book_folder": row.get::<_, Option<String>>(7)?,
                "entry_display_name": row.get::<_, Option<String>>(8)?,
                "started_at": row.get::<_, String>(9)?,
                "ended_at": row.get::<_, Option<String>>(10)?,
                "duration_secs": row.get::<_, Option<i64>>(11)?,
                "recording_file": row.get::<_, Option<String>>(12)?,
                "status": row.get::<_, String>(13)?,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();

    Ok((rows, total))
}

/// Top connections by session count and total hours.
pub fn top_connections(db: &Db, limit: u32) -> rusqlite::Result<Vec<serde_json::Value>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT COALESCE(entry_display_name, hostname) AS name,
                address_book_entry, address_book_folder, session_type,
                COUNT(*) AS session_count,
                COALESCE(SUM(duration_secs), 0) AS total_secs
         FROM session_history
         GROUP BY COALESCE(address_book_entry, hostname || ':' || COALESCE(port, 0))
         ORDER BY session_count DESC
         LIMIT ?1",
    )?;
    let rows = stmt
        .query_map(params![limit], |row| {
            Ok(serde_json::json!({
                "name": row.get::<_, String>(0)?,
                "address_book_entry": row.get::<_, Option<String>>(1)?,
                "folder": row.get::<_, Option<String>>(2)?,
                "session_type": row.get::<_, Option<String>>(3)?,
                "session_count": row.get::<_, i64>(4)?,
                "total_hours": row.get::<_, i64>(5)? as f64 / 3600.0,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// Top users by session count and total hours.
pub fn top_users(db: &Db, limit: u32) -> rusqlite::Result<Vec<serde_json::Value>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT created_by,
                COUNT(*) AS session_count,
                COALESCE(SUM(duration_secs), 0) AS total_secs,
                MAX(started_at) AS last_session
         FROM session_history
         GROUP BY created_by
         ORDER BY session_count DESC
         LIMIT ?1",
    )?;
    let rows = stmt
        .query_map(params![limit], |row| {
            Ok(serde_json::json!({
                "user": row.get::<_, String>(0)?,
                "session_count": row.get::<_, i64>(1)?,
                "total_hours": row.get::<_, i64>(2)? as f64 / 3600.0,
                "last_session": row.get::<_, String>(3)?,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// Summary statistics.
pub fn session_summary(db: &Db) -> rusqlite::Result<serde_json::Value> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT COUNT(*) AS total_sessions,
                COALESCE(SUM(duration_secs), 0) AS total_secs,
                COUNT(DISTINCT created_by) AS unique_users,
                SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active_now
         FROM session_history",
    )?;
    stmt.query_row([], |row| {
        Ok(serde_json::json!({
            "total_sessions": row.get::<_, i64>(0)?,
            "total_hours": row.get::<_, i64>(1)? as f64 / 3600.0,
            "unique_users": row.get::<_, i64>(2)?,
            "active_now": row.get::<_, i64>(3)?,
        }))
    })
}

/// Clean up old session history entries (retain last N days). Returns rows deleted.
pub fn cleanup_session_history(db: &Db, retain_days: u32) -> rusqlite::Result<usize> {
    if retain_days == 0 {
        return Ok(0); // 0 = keep forever
    }
    let conn = db.lock().unwrap();
    let modifier = format!("-{} days", retain_days);
    conn.execute(
        "DELETE FROM session_history WHERE started_at < datetime('now', ?1)",
        params![modifier],
    )
}

/// The role to record for a user at login from their OIDC groups and the
/// group-to-role mappings. Returns `Some(role)` if at least one group matched
/// a mapping, or `None` if none did (the caller chooses its fallback policy).
///
/// Permissions come from every matching mapping (`roles::user_access`); this
/// is only the single role written to `users.role`, as before: the highest
/// matching built-in, or failing that the first matching custom role by name
/// (see `roles::login_role_for`).
pub fn resolve_role_from_groups(db: &Db, groups: &[String]) -> rusqlite::Result<Option<String>> {
    if groups.is_empty() {
        return Ok(None);
    }
    let matched: Vec<String> = list_group_mappings(db)?
        .into_iter()
        .filter(|m| groups.iter().any(|g| g == &m.oidc_group))
        .map(|m| m.role)
        .collect();
    Ok(crate::roles::login_role_for(&matched))
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

    fn test_db() -> Db {
        init_db(std::path::Path::new(":memory:")).unwrap()
    }

    #[test]
    fn test_session_history_insert_and_query() {
        let db = test_db();
        insert_session_history(
            &db,
            "sess-1",
            "rdp",
            "10.0.0.1",
            Some(3389),
            "bench01",
            "dave@sol1.com.au",
            Some("shared/prod/rdp-host-1"),
            Some("prod"),
            Some("RDP Host 1"),
        )
        .unwrap();
        insert_session_history(
            &db,
            "sess-2",
            "ssh",
            "10.0.0.2",
            Some(22),
            "bench02",
            "andy@sol1.com.au",
            None,
            None,
            None,
        )
        .unwrap();

        let (rows, total) =
            query_session_history(&db, None, None, None, None, None, 100, 0).unwrap();
        assert_eq!(total, 2);
        assert_eq!(rows.len(), 2);
        // Most recent first
        assert_eq!(rows[0]["session_id"], "sess-2");
        assert_eq!(rows[1]["session_id"], "sess-1");
    }

    #[test]
    fn test_session_history_filter_by_user() {
        let db = test_db();
        insert_session_history(
            &db,
            "s1",
            "rdp",
            "h1",
            None,
            "",
            "dave@sol1.com.au",
            None,
            None,
            None,
        )
        .unwrap();
        insert_session_history(
            &db,
            "s2",
            "ssh",
            "h2",
            None,
            "",
            "andy@sol1.com.au",
            None,
            None,
            None,
        )
        .unwrap();

        let (rows, total) =
            query_session_history(&db, Some("dave"), None, None, None, None, 100, 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0]["created_by"], "dave@sol1.com.au");
    }

    #[test]
    fn test_session_history_filter_by_type() {
        let db = test_db();
        insert_session_history(&db, "s1", "rdp", "h1", None, "", "user1", None, None, None)
            .unwrap();
        insert_session_history(&db, "s2", "ssh", "h2", None, "", "user2", None, None, None)
            .unwrap();

        let (rows, total) =
            query_session_history(&db, None, None, Some("ssh"), None, None, 100, 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0]["session_type"], "ssh");
    }

    #[test]
    fn test_session_history_end() {
        let db = test_db();
        insert_session_history(&db, "s1", "rdp", "h1", None, "", "user1", None, None, None)
            .unwrap();
        end_session_history(&db, "s1", "completed", 3600, Some("s1.guac")).unwrap();

        let (rows, _) = query_session_history(&db, None, None, None, None, None, 100, 0).unwrap();
        assert_eq!(rows[0]["status"], "completed");
        assert_eq!(rows[0]["duration_secs"], 3600);
        assert_eq!(rows[0]["recording_file"], "s1.guac");
    }

    #[test]
    fn test_top_connections() {
        let db = test_db();
        for i in 0..5 {
            insert_session_history(
                &db,
                &format!("s{}", i),
                "rdp",
                "host-a",
                None,
                "",
                "user1",
                Some("shared/prod/host-a"),
                Some("prod"),
                Some("Host A"),
            )
            .unwrap();
            end_session_history(&db, &format!("s{}", i), "completed", 600, None).unwrap();
        }
        for i in 5..7 {
            insert_session_history(
                &db,
                &format!("s{}", i),
                "ssh",
                "host-b",
                None,
                "",
                "user2",
                Some("shared/dev/host-b"),
                Some("dev"),
                Some("Host B"),
            )
            .unwrap();
            end_session_history(&db, &format!("s{}", i), "completed", 300, None).unwrap();
        }

        let top = top_connections(&db, 10).unwrap();
        assert_eq!(top.len(), 2);
        assert_eq!(top[0]["name"], "Host A");
        assert_eq!(top[0]["session_count"], 5);
        assert_eq!(top[1]["name"], "Host B");
        assert_eq!(top[1]["session_count"], 2);
    }

    #[test]
    fn test_top_users() {
        let db = test_db();
        for i in 0..3 {
            insert_session_history(
                &db,
                &format!("s{}", i),
                "rdp",
                "h",
                None,
                "",
                "alice@co.com",
                None,
                None,
                None,
            )
            .unwrap();
            end_session_history(&db, &format!("s{}", i), "completed", 1800, None).unwrap();
        }
        insert_session_history(
            &db,
            "s9",
            "ssh",
            "h",
            None,
            "",
            "bob@co.com",
            None,
            None,
            None,
        )
        .unwrap();
        end_session_history(&db, "s9", "completed", 3600, None).unwrap();

        let top = top_users(&db, 10).unwrap();
        assert_eq!(top.len(), 2);
        assert_eq!(top[0]["user"], "alice@co.com");
        assert_eq!(top[0]["session_count"], 3);
        assert_eq!(top[1]["user"], "bob@co.com");
        assert_eq!(top[1]["session_count"], 1);
    }

    #[test]
    fn test_session_summary() {
        let db = test_db();
        insert_session_history(&db, "s1", "rdp", "h", None, "", "alice", None, None, None).unwrap();
        end_session_history(&db, "s1", "completed", 7200, None).unwrap();
        insert_session_history(&db, "s2", "ssh", "h", None, "", "bob", None, None, None).unwrap();
        // s2 still active

        let summary = session_summary(&db).unwrap();
        assert_eq!(summary["total_sessions"], 2);
        assert_eq!(summary["unique_users"], 2);
        assert_eq!(summary["active_now"], 1);
        assert_eq!(summary["total_hours"], 7200.0 / 3600.0);
    }

    #[test]
    fn test_cleanup_session_history_zero_keeps_all() {
        let db = test_db();
        insert_session_history(&db, "s1", "rdp", "h", None, "", "u", None, None, None).unwrap();
        let deleted = cleanup_session_history(&db, 0).unwrap();
        assert_eq!(deleted, 0);
        let (_, total) = query_session_history(&db, None, None, None, None, None, 100, 0).unwrap();
        assert_eq!(total, 1);
    }

    #[test]
    fn test_session_history_pagination() {
        let db = test_db();
        for i in 0..25 {
            insert_session_history(
                &db,
                &format!("s{:02}", i),
                "rdp",
                "h",
                None,
                "",
                "u",
                None,
                None,
                None,
            )
            .unwrap();
        }

        let (rows, total) =
            query_session_history(&db, None, None, None, None, None, 10, 0).unwrap();
        assert_eq!(total, 25);
        assert_eq!(rows.len(), 10);

        let (rows2, _) = query_session_history(&db, None, None, None, None, None, 10, 10).unwrap();
        assert_eq!(rows2.len(), 10);

        let (rows3, _) = query_session_history(&db, None, None, None, None, None, 10, 20).unwrap();
        assert_eq!(rows3.len(), 5);
    }

    // ── OIDC groups bounds (end-to-end) ─────────────────────────────────
    // Verifies the pipeline: a large input list passes through
    // upsert_seen_groups into the DB without growing unbounded. The
    // front-end cap lives in oidc::extract_groups_from_jwt; this test
    // covers the DB side — it must accept any input without blowing up
    // and de-duplicate on repeat logins.

    #[test]
    fn seen_groups_upsert_deduplicates() {
        let db = test_db();
        upsert_seen_groups(&db, &["admins".into(), "ops".into(), "admins".into()]).unwrap();
        // Second login with overlapping groups.
        upsert_seen_groups(&db, &["admins".into(), "new".into()]).unwrap();
        let groups = list_known_groups(&db).unwrap();
        assert!(groups.contains(&"admins".into()));
        assert!(groups.contains(&"ops".into()));
        assert!(groups.contains(&"new".into()));
        // No duplicates.
        let mut sorted = groups.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(groups.len(), sorted.len());
    }

    #[test]
    fn seen_groups_upsert_skips_empty() {
        let db = test_db();
        upsert_seen_groups(&db, &["".into(), " ".into(), "\t".into(), "valid".into()]).unwrap();
        let groups = list_known_groups(&db).unwrap();
        assert_eq!(groups, vec!["valid".to_string()]);
    }

    #[test]
    fn seen_groups_upsert_accepts_large_batch_without_panic() {
        // The OIDC layer caps arrays at 64 entries, but the DB must accept
        // whatever is passed without integer/row overflow.
        let db = test_db();
        let many: Vec<String> = (0..500).map(|i| format!("group-{i:04}")).collect();
        upsert_seen_groups(&db, &many).unwrap();
        let groups = list_known_groups(&db).unwrap();
        assert_eq!(groups.len(), 500);
    }

    #[test]
    fn seen_groups_tolerates_special_characters() {
        // Group names from arbitrary IdPs may contain `'`, spaces, etc.
        // Parameterised query must bind them safely (regression test vs
        // any future refactor that concatenates names into SQL).
        let db = test_db();
        let names = vec![
            "DROP TABLE seen_groups;--".into(),
            "ops; SELECT * FROM users".into(),
            "alice's-group".into(),
            "Domain Admins".into(),
        ];
        upsert_seen_groups(&db, &names).unwrap();
        let got = list_known_groups(&db).unwrap();
        for n in &names {
            assert!(got.contains(n), "missing: {n:?}");
        }
    }

    #[test]
    fn parse_expires_at_accepts_expected_formats() {
        assert!(parse_expires_at("2030-01-01T00:00:00Z").is_some()); // RFC 3339
        assert!(parse_expires_at("2030-01-01 00:00:00").is_some()); // SQLite datetime
        assert!(parse_expires_at("2030-01-01T00:00:00").is_some()); // ISO, no zone
        assert!(parse_expires_at("2030-12-31").is_some()); // bare date
                                                           // Garbage / empty must be None so the caller fails closed.
        assert!(parse_expires_at("not-a-date").is_none());
        assert!(parse_expires_at("").is_none());
        assert!(parse_expires_at("2026-13-40").is_none());
        // Bare date resolves to end-of-day UTC, not midnight.
        assert_eq!(
            parse_expires_at("2030-06-15").unwrap(),
            Utc.with_ymd_and_hms(2030, 6, 15, 23, 59, 59).unwrap()
        );
    }

    #[test]
    fn admin_key_expiry_fails_closed() {
        let db = test_db();
        // Past expiry -> expired.
        let k = add_admin(&db, "past", None, Some("2000-01-01T00:00:00Z")).unwrap();
        assert!(matches!(
            validate_api_key(&db, &k, None),
            Err(AuthError::Expired)
        ));
        // Malformed expiry -> expired (fail closed; previously authenticated forever).
        let k = add_admin(&db, "garbage", None, Some("whenever")).unwrap();
        assert!(matches!(
            validate_api_key(&db, &k, None),
            Err(AuthError::Expired)
        ));
        // Future expiry and no expiry -> valid.
        let k = add_admin(&db, "future", None, Some("2999-01-01T00:00:00Z")).unwrap();
        assert!(validate_api_key(&db, &k, None).is_ok());
        let k = add_admin(&db, "none", None, None).unwrap();
        assert!(validate_api_key(&db, &k, None).is_ok());
    }

    #[test]
    fn test_upsert_user_creates_when_allowed() {
        let db = test_db();
        let groups = vec!["ops".to_string()];
        let user = upsert_user(
            &db,
            "a@example.com",
            "A",
            Some("sub-a"),
            "operator",
            &groups,
            true,
        )
        .unwrap();
        let user = logged_in(user);
        assert_eq!(user.role, "operator");
        assert_eq!(user.oidc_subject.as_deref(), Some("sub-a"));
    }

    #[test]
    fn test_upsert_user_without_create_rejects_unknown() {
        let db = test_db();
        let res = upsert_user(
            &db,
            "x@example.com",
            "X",
            Some("sub-x"),
            "admin",
            &[],
            false,
        )
        .unwrap();
        assert!(matches!(res, OidcLogin::NoAccount));
        assert!(get_user_by_email(&db, "x@example.com").is_err());
    }

    #[test]
    fn test_upsert_user_without_create_logs_in_provisioned() {
        let db = test_db();
        create_user(&db, "p@example.com", "", "viewer").unwrap();
        let groups = vec!["devs".to_string()];
        let user = upsert_user(
            &db,
            "p@example.com",
            "P",
            Some("sub-p"),
            "admin",
            &groups,
            false,
        )
        .unwrap();
        let user = logged_in(user);
        // Pre-provisioned role is kept, default_role is not applied.
        assert_eq!(user.role, "viewer");
        assert_eq!(user.name, "P");
        assert_eq!(user.oidc_subject.as_deref(), Some("sub-p"));
        assert_eq!(user.oidc_groups, "devs");
        assert!(user.last_login_at.is_some());
    }

    #[test]
    fn test_create_user_duplicate_fails() {
        let db = test_db();
        create_user(&db, "d@example.com", "", "viewer").unwrap();
        let err = create_user(&db, "d@example.com", "", "admin").unwrap_err();
        assert!(matches!(err, CreateUserError::Exists));
        // Logins match email ignoring case, so a different case is the same user.
        let err = create_user(&db, "D@Example.com", "", "admin").unwrap_err();
        assert!(matches!(err, CreateUserError::Exists));
    }

    fn logged_in(o: OidcLogin) -> User {
        match o {
            OidcLogin::User(u) => u,
            other => panic!("expected a login, got {other:?}"),
        }
    }

    fn login(db: &Db, email: &str, sub: &str, create: bool) -> OidcLogin {
        upsert_user(db, email, "N", Some(sub), "viewer", &[], create).unwrap()
    }

    #[test]
    fn oidc_login_is_bound_to_the_first_subject() {
        // An admin-added user takes the subject of their first login...
        let db = test_db();
        create_user(&db, "alice@corp.example", "", "admin").unwrap();
        logged_in(login(&db, "alice@corp.example", "sub-alice", false));
        logged_in(login(&db, "alice@corp.example", "sub-alice", false));
        // ...and someone else's provider account carrying the same email is
        // refused, with auto-create on or off, and nothing is changed.
        for create in [false, true] {
            assert!(matches!(
                login(&db, "alice@corp.example", "sub-mallory", create),
                OidcLogin::SubjectMismatch
            ));
        }
        let alice = get_user_by_email(&db, "alice@corp.example").unwrap();
        assert_eq!(alice.oidc_subject.as_deref(), Some("sub-alice"));
        assert_eq!(alice.role, "admin");
    }

    #[test]
    fn reset_oidc_subject_lets_the_next_login_bind_again() {
        // A move to a different identity provider gives everyone a new
        // subject; the admin releases the old binding and the next login
        // records the new one.
        let db = test_db();
        logged_in(login(&db, "bob@corp.example", "old-idp-bob", true));
        assert!(matches!(
            login(&db, "bob@corp.example", "new-idp-bob", true),
            OidcLogin::SubjectMismatch
        ));
        assert_eq!(
            reset_oidc_subject(&db, "BOB@corp.example")
                .unwrap()
                .as_deref(),
            Some("bob@corp.example")
        );
        let bob = logged_in(login(&db, "bob@corp.example", "new-idp-bob", true));
        assert_eq!(bob.oidc_subject.as_deref(), Some("new-idp-bob"));
        assert_eq!(
            reset_oidc_subject(&db, "nobody@corp.example").unwrap(),
            None
        );
    }

    #[test]
    fn oidc_login_matches_email_ignoring_case() {
        // The admin typed the email in one case and the provider sends
        // another: the same user logs in, with the role the admin chose, and
        // no second account appears.
        let db = test_db();
        create_user(&db, "JSmith@Example.com", "", "operator").unwrap();
        let u = logged_in(login(&db, "jsmith@example.com", "sub-j", false));
        assert_eq!(u.role, "operator");
        let u = logged_in(login(&db, "jsmith@example.com", "sub-j", true));
        assert_eq!(u.role, "operator");
        assert_eq!(list_users(&db).unwrap().len(), 1);
    }

    #[test]
    fn oidc_login_refuses_an_ambiguous_email() {
        // Two users already differ only in case (created before logins
        // ignored case): refuse rather than guess, and change nothing.
        let db = test_db();
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "INSERT INTO users (email, role) VALUES ('Ann@x.example', 'viewer')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO users (email, role) VALUES ('ANN@x.example', 'admin')",
                [],
            )
            .unwrap();
        }
        assert!(matches!(
            login(&db, "ann@x.example", "sub-ann", true),
            OidcLogin::Ambiguous
        ));
        assert_eq!(list_users(&db).unwrap().len(), 2);
        // An exact match is never ambiguous.
        logged_in(login(&db, "Ann@x.example", "sub-ann", false));
    }
}
