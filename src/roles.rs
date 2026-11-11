//! Custom roles and how a user's permissions are worked out (#294).
//!
//! Built-in roles live in code (`perms.rs`); custom roles live in the
//! `roles` and `role_permissions` tables. A user's permissions are the union
//! of their roles: the roles of every group mapping their OIDC groups match,
//! or, when none match, their directly assigned role. That is exactly what
//! "the highest mapped role wins" gave for the nested built-ins.

use crate::db::{self, Db, User};
use crate::perms::{self, Perm, PermSet};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

/// A custom role as stored.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CustomRole {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, PartialEq)]
pub enum RoleError {
    /// Not a valid role name: lowercase letters, digits, `-` and `_`, 1-32.
    InvalidName,
    /// A built-in role's name, or one that differs from an existing role
    /// only in case.
    NameTaken,
    /// A permission name this release doesn't know.
    UnknownPermission(String),
    NotFound,
    /// Built-in roles can't be changed or deleted.
    BuiltIn,
    /// Still assigned somewhere; reassign first.
    InUse(RoleUsage),
    Db(String),
}

impl std::fmt::Display for RoleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoleError::InvalidName => f.write_str(
                "role names are 1-32 characters: lowercase letters, digits, '-' and '_'",
            ),
            RoleError::NameTaken => f.write_str("a role with that name already exists"),
            RoleError::UnknownPermission(p) => write!(f, "unknown permission: {p}"),
            RoleError::NotFound => f.write_str("role not found"),
            RoleError::BuiltIn => f.write_str("built-in roles can't be changed"),
            RoleError::InUse(u) => write!(
                f,
                "role is in use by {} user(s), {} group mapping(s) and {} API token cap(s){}; reassign them first",
                u.users.len(),
                u.mappings.len(),
                u.token_caps,
                if u.default_role { " and is [oidc] default_role" } else { "" }
            ),
            RoleError::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

impl From<rusqlite::Error> for RoleError {
    fn from(e: rusqlite::Error) -> Self {
        RoleError::Db(e.to_string())
    }
}

/// Where a role is assigned.
#[derive(Debug, Default, Clone, Serialize, PartialEq)]
pub struct RoleUsage {
    /// Emails of users whose directly assigned role it is.
    pub users: Vec<String>,
    /// OIDC groups mapped to it.
    pub mappings: Vec<String>,
    /// API tokens capped at it.
    pub token_caps: usize,
    /// Whether it's the configured `[oidc] default_role`.
    pub default_role: bool,
}

impl RoleUsage {
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
            && self.mappings.is_empty()
            && self.token_caps == 0
            && !self.default_role
    }
}

pub fn valid_role_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

pub fn is_builtin(name: &str) -> bool {
    perms::BUILTIN_ROLES.contains(&name)
}

/// Parse permission names, refusing any this release doesn't know.
pub fn parse_permissions(names: &[String]) -> Result<PermSet, RoleError> {
    let mut set = PermSet::EMPTY;
    for n in names {
        match Perm::from_name(n.trim()) {
            Some(p) => set = set.union(PermSet::of(&[p])),
            None => return Err(RoleError::UnknownPermission(n.clone())),
        }
    }
    Ok(set)
}

fn read_custom(conn: &rusqlite::Connection, name: &str) -> rusqlite::Result<Option<CustomRole>> {
    let row = conn
        .query_row(
            "SELECT name, display_name, description, created_at, updated_at FROM roles WHERE name = ?1",
            params![name],
            |r| {
                Ok(CustomRole {
                    name: r.get(0)?,
                    display_name: r.get(1)?,
                    description: r.get(2)?,
                    permissions: Vec::new(),
                    created_at: r.get(3)?,
                    updated_at: r.get(4)?,
                })
            },
        )
        .optional()?;
    let Some(mut role) = row else { return Ok(None) };
    role.permissions = custom_perms(conn, name)?
        .names()
        .into_iter()
        .map(String::from)
        .collect();
    Ok(Some(role))
}

/// A custom role's permissions. Names this release doesn't know (written by
/// a newer release) are ignored: they grant nothing here.
fn custom_perms(conn: &rusqlite::Connection, name: &str) -> rusqlite::Result<PermSet> {
    let mut stmt = conn.prepare("SELECT permission FROM role_permissions WHERE role = ?1")?;
    let names = stmt.query_map(params![name], |r| r.get::<_, String>(0))?;
    let mut set = PermSet::EMPTY;
    for n in names {
        if let Some(p) = Perm::from_name(&n?) {
            set = set.union(PermSet::of(&[p]));
        }
    }
    Ok(set)
}

fn perms_of(conn: &rusqlite::Connection, role: &str) -> rusqlite::Result<PermSet> {
    match perms::builtin_role_perms(role) {
        Some(p) => Ok(p),
        None => custom_perms(conn, role),
    }
}

/// What a role grants: a built-in's fixed set, a custom role's stored set,
/// or nothing for a name that isn't a role.
pub fn role_perms(db: &Db, role: &str) -> rusqlite::Result<PermSet> {
    let conn = db.lock().unwrap();
    perms_of(&conn, role)
}

/// Whether `name` is a built-in or custom role.
pub fn role_exists(db: &Db, name: &str) -> rusqlite::Result<bool> {
    if is_builtin(name) {
        return Ok(true);
    }
    let conn = db.lock().unwrap();
    Ok(conn
        .query_row("SELECT 1 FROM roles WHERE name = ?1", params![name], |_| {
            Ok(())
        })
        .optional()?
        .is_some())
}

pub fn list_custom_roles(db: &Db) -> rusqlite::Result<Vec<CustomRole>> {
    let conn = db.lock().unwrap();
    let names: Vec<String> = {
        let mut stmt = conn.prepare("SELECT name FROM roles ORDER BY name")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let mut out = Vec::new();
    for n in names {
        if let Some(r) = read_custom(&conn, &n)? {
            out.push(r);
        }
    }
    Ok(out)
}

pub fn get_custom_role(db: &Db, name: &str) -> rusqlite::Result<Option<CustomRole>> {
    let conn = db.lock().unwrap();
    read_custom(&conn, name)
}

pub fn create_custom_role(
    db: &Db,
    name: &str,
    display_name: &str,
    description: &str,
    permissions: PermSet,
) -> Result<CustomRole, RoleError> {
    if !valid_role_name(name) {
        return Err(RoleError::InvalidName);
    }
    let mut conn = db.lock().unwrap();
    if perms::BUILTIN_ROLES
        .iter()
        .any(|b| b.eq_ignore_ascii_case(name))
        || conn
            .query_row(
                "SELECT 1 FROM roles WHERE lower(name) = lower(?1)",
                params![name],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
    {
        return Err(RoleError::NameTaken);
    }
    let display = if display_name.trim().is_empty() {
        name
    } else {
        display_name.trim()
    };
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO roles (name, display_name, description) VALUES (?1, ?2, ?3)",
        params![name, display, description.trim()],
    )?;
    for p in permissions.iter() {
        tx.execute(
            "INSERT INTO role_permissions (role, permission) VALUES (?1, ?2)",
            params![name, p.name()],
        )?;
    }
    tx.commit()?;
    read_custom(&conn, name)?.ok_or(RoleError::NotFound)
}

pub fn update_custom_role(
    db: &Db,
    name: &str,
    display_name: &str,
    description: &str,
    permissions: PermSet,
) -> Result<CustomRole, RoleError> {
    if is_builtin(name) {
        return Err(RoleError::BuiltIn);
    }
    let mut conn = db.lock().unwrap();
    let tx = conn.transaction()?;
    let display = if display_name.trim().is_empty() {
        name
    } else {
        display_name.trim()
    };
    let n = tx.execute(
        "UPDATE roles SET display_name = ?2, description = ?3, updated_at = datetime('now') WHERE name = ?1",
        params![name, display, description.trim()],
    )?;
    if n == 0 {
        return Err(RoleError::NotFound);
    }
    tx.execute(
        "DELETE FROM role_permissions WHERE role = ?1",
        params![name],
    )?;
    for p in permissions.iter() {
        tx.execute(
            "INSERT INTO role_permissions (role, permission) VALUES (?1, ?2)",
            params![name, p.name()],
        )?;
    }
    tx.commit()?;
    read_custom(&conn, name)?.ok_or(RoleError::NotFound)
}

/// Where a role is assigned. `default_role` is the configured
/// `[oidc] default_role`, if any.
pub fn role_usage(db: &Db, name: &str, default_role: Option<&str>) -> rusqlite::Result<RoleUsage> {
    let conn = db.lock().unwrap();
    let users = {
        let mut stmt = conn.prepare("SELECT email FROM users WHERE role = ?1 ORDER BY email")?;
        let rows = stmt.query_map(params![name], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<Vec<String>>>()?
    };
    let mappings = {
        let mut stmt = conn.prepare(
            "SELECT oidc_group FROM group_role_mappings WHERE role = ?1 ORDER BY oidc_group",
        )?;
        let rows = stmt.query_map(params![name], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<Vec<String>>>()?
    };
    let token_caps: i64 = conn.query_row(
        "SELECT COUNT(*) FROM user_api_tokens WHERE max_role = ?1",
        params![name],
        |r| r.get(0),
    )?;
    Ok(RoleUsage {
        users,
        mappings,
        token_caps: token_caps as usize,
        default_role: default_role == Some(name),
    })
}

/// Delete a custom role. If it's assigned anywhere, `reassign_to` (an
/// existing role) takes its place on those users, mappings and token caps in
/// the same transaction; without it, a role in use is refused. A role that is
/// `[oidc] default_role` can't be deleted: the config would point at nothing.
pub fn delete_custom_role(
    db: &Db,
    name: &str,
    reassign_to: Option<&str>,
    default_role: Option<&str>,
) -> Result<RoleUsage, RoleError> {
    if is_builtin(name) {
        return Err(RoleError::BuiltIn);
    }
    if get_custom_role(db, name)?.is_none() {
        return Err(RoleError::NotFound);
    }
    let usage = role_usage(db, name, default_role)?;
    if usage.default_role {
        return Err(RoleError::InUse(usage));
    }
    if !usage.is_empty() {
        match reassign_to {
            Some(to) if to != name && role_exists(db, to)? => {}
            Some(_) => return Err(RoleError::NotFound),
            None => return Err(RoleError::InUse(usage)),
        }
    }
    let mut conn = db.lock().unwrap();
    let tx = conn.transaction()?;
    if let Some(to) = reassign_to {
        tx.execute(
            "UPDATE users SET role = ?2 WHERE role = ?1",
            params![name, to],
        )?;
        tx.execute(
            "UPDATE group_role_mappings SET role = ?2 WHERE role = ?1",
            params![name, to],
        )?;
        tx.execute(
            "UPDATE user_api_tokens SET max_role = ?2 WHERE max_role = ?1",
            params![name, to],
        )?;
    }
    tx.execute(
        "DELETE FROM role_permissions WHERE role = ?1",
        params![name],
    )?;
    tx.execute("DELETE FROM roles WHERE name = ?1", params![name])?;
    tx.commit()?;
    Ok(usage)
}

/// A user's roles and permissions, and where they came from.
#[derive(Debug, Clone, Serialize)]
pub struct UserAccess {
    /// The directly assigned role (`users.role`).
    pub direct_role: String,
    /// Whether the direct role applies: only when none of the user's groups
    /// has a mapping.
    pub direct_role_in_effect: bool,
    /// Group mappings the user's recorded groups match, as (group, role).
    pub group_roles: Vec<(String, String)>,
    /// The roles in effect.
    pub roles: Vec<String>,
    /// The union of those roles' permissions.
    #[serde(skip)]
    pub permissions: PermSet,
}

/// Work out a user's roles and permissions from their recorded groups (as of
/// their last login), the current group mappings and their direct role.
pub fn user_access(db: &Db, user: &User) -> rusqlite::Result<UserAccess> {
    let mappings = db::list_group_mappings(db)?;
    let groups = user.groups_vec();
    let group_roles: Vec<(String, String)> = mappings
        .iter()
        .filter(|m| groups.iter().any(|g| g == &m.oidc_group))
        .map(|m| (m.oidc_group.clone(), m.role.clone()))
        .collect();
    let conn = db.lock().unwrap();
    let (direct_role_in_effect, mut roles) = if group_roles.is_empty() {
        (true, vec![user.role.clone()])
    } else {
        (
            false,
            group_roles
                .iter()
                .map(|(_, r)| r.clone())
                .collect::<Vec<_>>(),
        )
    };
    roles.sort();
    roles.dedup();
    let mut permissions = PermSet::EMPTY;
    for r in &roles {
        permissions = permissions.union(perms_of(&conn, r)?);
    }
    Ok(UserAccess {
        direct_role: user.role.clone(),
        direct_role_in_effect,
        group_roles,
        roles,
        permissions,
    })
}

/// The role to record in `users.role` at login when the user's groups match
/// mappings: the highest matching built-in, or failing that the first
/// matching custom role by name. Only an older release reads this after a
/// downgrade, and either choice grants no more there than the union does
/// here (a custom role is no access at all to an older release).
pub fn login_role_for(group_roles: &[String]) -> Option<String> {
    let best_builtin = perms::BUILTIN_ROLES
        .iter()
        .rev()
        .find(|b| group_roles.iter().any(|r| r == *b));
    if let Some(b) = best_builtin {
        return Some(b.to_string());
    }
    let mut custom: Vec<&String> = group_roles.iter().collect();
    custom.sort();
    custom.first().map(|s| s.to_string())
}

/// Whether, after `change`, anything could still manage roles: an enabled,
/// unexpired admin API key, or an enabled user whose permissions include
/// `admin.roles`. Guards against locking everyone out of the Admin page.
pub fn admin_roles_survives(db: &Db, change: &Change) -> rusqlite::Result<bool> {
    let now = chrono::Utc::now();
    let usable_key = db::list_admins(db)?.into_iter().any(|a| {
        !a.disabled
            && a.expires_at
                .as_deref()
                .is_none_or(|e| db::parse_expires_at(e).is_some_and(|t| now <= t))
    });
    if usable_key {
        return Ok(true);
    }
    let mut mappings: Vec<(String, String)> = db::list_group_mappings(db)?
        .into_iter()
        .map(|m| (m.oidc_group, m.role))
        .collect();
    if let Change::Mappings(changes) = change {
        for (group, role) in changes {
            mappings.retain(|(g, _)| g != group);
            if let Some(r) = role {
                mappings.push((group.clone(), r.clone()));
            }
        }
    }
    let custom: Vec<(String, PermSet)> = {
        let conn = db.lock().unwrap();
        let mut out = Vec::new();
        let names: Vec<String> = {
            let mut stmt = conn.prepare("SELECT name FROM roles")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for n in names {
            let mut p = custom_perms(&conn, &n)?;
            if let Change::RolePerms(name, perms) = change {
                if *name == n {
                    p = *perms;
                }
            }
            out.push((n, p));
        }
        out
    };
    let perms_for = |role: &str| -> PermSet {
        perms::builtin_role_perms(role)
            .or_else(|| custom.iter().find(|(n, _)| n == role).map(|(_, p)| *p))
            .unwrap_or(PermSet::EMPTY)
    };
    for user in db::list_users(db)? {
        let (disabled, role) = match change {
            Change::UserRole(email, r) if *email == user.email => (user.disabled, r.as_str()),
            Change::UserDisabled(email) | Change::UserDeleted(email) if *email == user.email => {
                (true, user.role.as_str())
            }
            _ => (user.disabled, user.role.as_str()),
        };
        if disabled {
            continue;
        }
        let groups = user.groups_vec();
        let mapped: Vec<&str> = mappings
            .iter()
            .filter(|(g, _)| groups.iter().any(|ug| ug == g))
            .map(|(_, r)| r.as_str())
            .collect();
        let perms = if mapped.is_empty() {
            perms_for(role)
        } else {
            mapped
                .iter()
                .fold(PermSet::EMPTY, |acc, r| acc.union(perms_for(r)))
        };
        if perms.contains(Perm::AdminRoles) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A change to check with `admin_roles_survives` before making it.
pub enum Change {
    UserRole(String, String),
    UserDisabled(String),
    UserDeleted(String),
    /// Set (Some) or remove (None) the mapping for each group, in order.
    Mappings(Vec<(String, Option<String>)>),
    /// A custom role's new permissions.
    RolePerms(String, PermSet),
}

/// Record an admin action in `admin_audit_log`. Headline only: what was done
/// to what, never secrets or full request bodies.
pub fn log_admin_event(
    db: &Db,
    actor: &str,
    action: &str,
    target: &str,
    details: Option<&str>,
    ip: Option<&str>,
) {
    let conn = db.lock().unwrap();
    if let Err(e) = conn.execute(
        "INSERT INTO admin_audit_log (actor, action, target, details, ip_addr) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![actor, action, target, details, ip],
    ) {
        tracing::warn!(error = %e, action, "failed to write admin audit log");
    }
}

#[derive(Debug, Serialize)]
pub struct AdminAuditEntry {
    pub id: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub details: Option<String>,
    pub ip_addr: Option<String>,
    pub created_at: String,
}

pub fn list_admin_audit(db: &Db, limit: u32) -> rusqlite::Result<Vec<AdminAuditEntry>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, actor, action, target, details, ip_addr, created_at
         FROM admin_audit_log ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit], |r| {
        Ok(AdminAuditEntry {
            id: r.get(0)?,
            actor: r.get(1)?,
            action: r.get(2)?,
            target: r.get(3)?,
            details: r.get(4)?,
            ip_addr: r.get(5)?,
            created_at: r.get(6)?,
        })
    })?;
    rows.collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Db {
        db::init_db(std::path::Path::new(":memory:")).unwrap()
    }

    fn set_groups(db: &Db, email: &str, groups: &str) {
        db.lock()
            .unwrap()
            .execute(
                "UPDATE users SET oidc_groups = ?2 WHERE email = ?1",
                params![email, groups],
            )
            .unwrap();
    }

    fn access(db: &Db, email: &str) -> UserAccess {
        user_access(db, &db::get_user_by_email(db, email).unwrap()).unwrap()
    }

    fn perms(names: &[Perm]) -> PermSet {
        PermSet::of(names)
    }

    #[test]
    fn mapped_roles_are_unioned_and_replace_the_direct_role() {
        let db = test_db();
        create_custom_role(&db, "reporter", "", "", perms(&[Perm::ReportsView])).unwrap();
        create_custom_role(&db, "player", "", "", perms(&[Perm::RecordingsView])).unwrap();
        db::create_group_mapping(&db, "g-reports", "reporter").unwrap();
        db::create_group_mapping(&db, "g-play", "player").unwrap();
        db::create_user(&db, "a@example.com", "", "admin").unwrap();

        // No mapping matches: the direct role applies.
        let a = access(&db, "a@example.com");
        assert!(a.direct_role_in_effect);
        assert_eq!(a.permissions, PermSet::all());

        // Both groups: the union of their roles, and the direct admin role is
        // replaced, as a matching mapping always replaced it.
        set_groups(&db, "a@example.com", "g-reports,g-play,unmapped");
        let a = access(&db, "a@example.com");
        assert!(!a.direct_role_in_effect);
        assert_eq!(a.roles, ["player", "reporter"]);
        assert_eq!(
            a.permissions,
            perms(&[Perm::ReportsView, Perm::RecordingsView])
        );
        assert_eq!(a.group_roles.len(), 2);
    }

    #[test]
    fn builtin_mappings_resolve_as_the_highest_did() {
        let db = test_db();
        db::create_group_mapping(&db, "ops", "operator").unwrap();
        db::create_group_mapping(&db, "power", "poweruser").unwrap();
        db::create_user(&db, "b@example.com", "", "viewer").unwrap();
        set_groups(&db, "b@example.com", "ops,power");
        assert_eq!(
            access(&db, "b@example.com").permissions,
            crate::perms::role_perms("poweruser")
        );
        assert_eq!(
            login_role_for(&["operator".into(), "poweruser".into()]).as_deref(),
            Some("poweruser")
        );
        // A built-in wins over custom roles for the recorded role; among
        // custom roles the first by name.
        assert_eq!(
            login_role_for(&["zeta".into(), "operator".into()]).as_deref(),
            Some("operator")
        );
        assert_eq!(
            login_role_for(&["zeta".into(), "alpha".into()]).as_deref(),
            Some("alpha")
        );
        assert_eq!(login_role_for(&[]), None);
    }

    #[test]
    fn role_names_are_checked() {
        let db = test_db();
        let none = PermSet::EMPTY;
        assert_eq!(
            create_custom_role(&db, "Bad Name", "", "", none),
            Err(RoleError::InvalidName)
        );
        assert_eq!(
            create_custom_role(&db, "", "", "", none),
            Err(RoleError::InvalidName)
        );
        assert_eq!(
            create_custom_role(&db, "admin", "", "", none),
            Err(RoleError::NameTaken)
        );
        create_custom_role(&db, "editor", "Connection editor", "", none).unwrap();
        assert_eq!(
            create_custom_role(&db, "editor", "", "", none),
            Err(RoleError::NameTaken)
        );
        assert_eq!(
            update_custom_role(&db, "operator", "", "", none),
            Err(RoleError::BuiltIn)
        );
        assert_eq!(
            parse_permissions(&["connections.edit".into(), "nope".into()]),
            Err(RoleError::UnknownPermission("nope".into()))
        );
        let r = get_custom_role(&db, "editor").unwrap().unwrap();
        assert_eq!(r.display_name, "Connection editor");
        assert!(role_exists(&db, "editor").unwrap());
        assert!(role_exists(&db, "viewer").unwrap());
        assert!(!role_exists(&db, "nobody").unwrap());
    }

    #[test]
    fn permissions_from_a_newer_release_grant_nothing() {
        let db = test_db();
        create_custom_role(&db, "r", "", "", perms(&[Perm::DocsView])).unwrap();
        db.lock()
            .unwrap()
            .execute(
                "INSERT INTO role_permissions (role, permission) VALUES ('r', 'future.thing')",
                [],
            )
            .unwrap();
        assert_eq!(role_perms(&db, "r").unwrap(), perms(&[Perm::DocsView]));
    }

    #[test]
    fn a_role_in_use_is_deleted_only_by_reassigning_it() {
        let db = test_db();
        create_custom_role(&db, "temp", "", "", perms(&[Perm::DocsView])).unwrap();
        db::create_user(&db, "c@example.com", "", "temp").unwrap();
        db::create_group_mapping(&db, "g", "temp").unwrap();
        let u = db::get_user_by_email(&db, "c@example.com").unwrap();
        db::create_user_token(&db, u.id, "t", Some("temp"), None).unwrap();

        match delete_custom_role(&db, "temp", None, None) {
            Err(RoleError::InUse(usage)) => {
                assert_eq!(usage.users, ["c@example.com"]);
                assert_eq!(usage.mappings, ["g"]);
                assert_eq!(usage.token_caps, 1);
            }
            other => panic!("expected InUse, got {other:?}"),
        }
        assert_eq!(
            delete_custom_role(&db, "temp", Some("nobody"), None).err(),
            Some(RoleError::NotFound)
        );
        // The configured default role can't be deleted at all.
        assert!(matches!(
            delete_custom_role(&db, "temp", Some("viewer"), Some("temp")),
            Err(RoleError::InUse(_))
        ));

        delete_custom_role(&db, "temp", Some("viewer"), None).unwrap();
        assert_eq!(
            db::get_user_by_email(&db, "c@example.com").unwrap().role,
            "viewer"
        );
        assert_eq!(db::list_group_mappings(&db).unwrap()[0].role, "viewer");
        assert!(role_usage(&db, "temp", None).unwrap().is_empty());
        assert!(get_custom_role(&db, "temp").unwrap().is_none());
        assert_eq!(
            delete_custom_role(&db, "viewer", None, None).err(),
            Some(RoleError::BuiltIn)
        );
    }

    #[test]
    fn the_last_way_to_manage_roles_is_kept() {
        let db = test_db();
        db::create_user(&db, "boss@example.com", "", "admin").unwrap();
        db::create_user(&db, "op@example.com", "", "operator").unwrap();
        let ok = |c: Change| admin_roles_survives(&db, &c).unwrap();

        assert!(ok(Change::UserRole(
            "op@example.com".into(),
            "viewer".into()
        )));
        assert!(!ok(Change::UserRole(
            "boss@example.com".into(),
            "operator".into()
        )));
        assert!(!ok(Change::UserDisabled("boss@example.com".into())));
        assert!(!ok(Change::UserDeleted("boss@example.com".into())));
        // A group mapping that would demote the only admin.
        set_groups(&db, "boss@example.com", "staff");
        assert!(!ok(Change::Mappings(vec![(
            "staff".into(),
            Some("operator".into())
        )])));
        assert!(ok(Change::Mappings(vec![(
            "staff".into(),
            Some("admin".into())
        )])));

        // A custom role holding admin.roles counts, until it loses it.
        create_custom_role(&db, "keeper", "", "", perms(&[Perm::AdminRoles])).unwrap();
        db::create_user(&db, "k@example.com", "", "keeper").unwrap();
        assert!(ok(Change::UserRole(
            "boss@example.com".into(),
            "operator".into()
        )));
        db::set_user_role(&db, "boss@example.com", "operator").unwrap();
        assert!(!ok(Change::RolePerms("keeper".into(), PermSet::EMPTY)));

        // An enabled admin API key can always manage roles.
        db::add_admin(&db, "ops", None, None).unwrap();
        assert!(ok(Change::RolePerms("keeper".into(), PermSet::EMPTY)));
    }

    #[test]
    fn a_token_gets_what_both_its_owner_and_its_cap_allow() {
        let db = test_db();
        create_custom_role(
            &db,
            "mix",
            "",
            "",
            perms(&[Perm::ReportsView, Perm::ConnectionsEdit]),
        )
        .unwrap();
        db::create_user(&db, "t@example.com", "", "poweruser").unwrap();
        let user = || db::get_user_by_email(&db, "t@example.com").unwrap();
        let capped = crate::auth::user_identity(&db, user(), Some("mix"));
        assert_eq!(capped.permissions(), perms(&[Perm::ReportsView]));
        let viewer_cap = crate::auth::user_identity(&db, user(), Some("viewer"));
        assert_eq!(viewer_cap.permissions(), crate::perms::role_perms("viewer"));
        assert_eq!(viewer_cap.role(), "viewer");
        let uncapped = crate::auth::user_identity(&db, user(), None);
        assert_eq!(
            uncapped.permissions(),
            crate::perms::role_perms("poweruser")
        );
    }
}
