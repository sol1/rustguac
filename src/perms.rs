//! Permissions (#294).
//!
//! Every access check on the server asks for a permission rather than a
//! role. Roles are named sets of permissions; the four built-in roles grant
//! exactly what the old role ladder did, and are defined here in code so a
//! release can never change what they grant by accident.

use std::fmt;

/// One thing a caller may be allowed to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Perm {
    /// See folders and entries in Connections, connect to them, and join,
    /// list and end one's own sessions and VDI containers.
    ConnectionsConnect,
    /// Save one's own credential variables.
    CredentialsSelf,
    /// Ad-hoc sessions to any host, ad-hoc `/api/connect` links, and the
    /// SSH host-key probe they use.
    ConnectionsAdhoc,
    /// List and play recordings and typescripts.
    RecordingsView,
    /// Reports.
    ReportsView,
    /// Create and revoke one's own API tokens.
    TokensSelf,
    /// Create, edit, move, copy and delete entries and folders, and folder
    /// default credentials. Sees and connects to every folder.
    ConnectionsEdit,
    /// Change who can open a folder. Whoever holds this can give
    /// themselves any folder, so it is effectively admin.
    FoldersManageAccess,
    /// Ad-hoc and link sessions skip the ad-hoc policy (network fencing,
    /// entry-only options, recording, drive and VDI limits).
    ConnectionsUnrestricted,
    /// See, thumbnail and end anyone's session.
    SessionsViewAll,
    /// Shadow someone else's session.
    SessionsShadow,
    /// Delete recordings.
    RecordingsDelete,
    /// Manage users and the API tokens issued to them.
    AdminUsers,
    /// Roles, role assignment and group mappings.
    AdminRoles,
    /// Audit logs.
    AdminAudit,
    /// Detailed system status.
    AdminSystem,
    /// Documentation.
    DocsView,
}

impl Perm {
    /// Every permission, in the order they're listed to admins.
    pub const ALL: [Perm; 17] = [
        Perm::ConnectionsConnect,
        Perm::CredentialsSelf,
        Perm::ConnectionsAdhoc,
        Perm::RecordingsView,
        Perm::ReportsView,
        Perm::TokensSelf,
        Perm::ConnectionsEdit,
        Perm::FoldersManageAccess,
        Perm::ConnectionsUnrestricted,
        Perm::SessionsViewAll,
        Perm::SessionsShadow,
        Perm::RecordingsDelete,
        Perm::AdminUsers,
        Perm::AdminRoles,
        Perm::AdminAudit,
        Perm::AdminSystem,
        Perm::DocsView,
    ];

    /// The stable name, as stored for custom roles and returned by the API.
    pub fn name(self) -> &'static str {
        match self {
            Perm::ConnectionsConnect => "connections.connect",
            Perm::CredentialsSelf => "credentials.self",
            Perm::ConnectionsAdhoc => "connections.adhoc",
            Perm::RecordingsView => "recordings.view",
            Perm::ReportsView => "reports.view",
            Perm::TokensSelf => "tokens.self",
            Perm::ConnectionsEdit => "connections.edit",
            Perm::FoldersManageAccess => "folders.manage_access",
            Perm::ConnectionsUnrestricted => "connections.unrestricted",
            Perm::SessionsViewAll => "sessions.view_all",
            Perm::SessionsShadow => "sessions.shadow",
            Perm::RecordingsDelete => "recordings.delete",
            Perm::AdminUsers => "admin.users",
            Perm::AdminRoles => "admin.roles",
            Perm::AdminAudit => "admin.audit",
            Perm::AdminSystem => "admin.system",
            Perm::DocsView => "docs.view",
        }
    }

    /// The permission with this name, if this release knows it. A name from
    /// a newer release is unknown here and grants nothing.
    pub fn from_name(name: &str) -> Option<Perm> {
        Perm::ALL.into_iter().find(|p| p.name() == name)
    }

    /// What it allows, for admins choosing permissions.
    pub fn description(self) -> &'static str {
        match self {
            Perm::ConnectionsConnect => "See folders and entries in Connections and connect to them; list and end own sessions and VDI containers",
            Perm::CredentialsSelf => "Save own credential variables",
            Perm::ConnectionsAdhoc => "Ad-hoc connections to any host (Connect to a host), ad-hoc links and the SSH host-key probe",
            Perm::RecordingsView => "List and play recordings and typescripts",
            Perm::ReportsView => "Reports",
            Perm::TokensSelf => "Create and revoke own API tokens",
            Perm::ConnectionsEdit => "Create, edit, move, copy and delete entries and folders, and folder default credentials; sees and connects to every folder",
            Perm::FoldersManageAccess => "Change who can open a folder",
            Perm::ConnectionsUnrestricted => "Ad-hoc and link sessions skip the ad-hoc policy (network fencing, entry-only options, site limits)",
            Perm::SessionsViewAll => "See, thumbnail and end anyone's session",
            Perm::SessionsShadow => "Shadow someone else's session",
            Perm::RecordingsDelete => "Delete recordings",
            Perm::AdminUsers => "Manage users and the API tokens issued to them",
            Perm::AdminRoles => "Roles, role assignment and group mappings",
            Perm::AdminAudit => "Audit logs",
            Perm::AdminSystem => "Detailed system status",
            Perm::DocsView => "Documentation",
        }
    }

    /// Whether holding this is close to holding admin, so granting it
    /// deserves a warning.
    pub fn sensitive(self) -> bool {
        matches!(
            self,
            Perm::FoldersManageAccess
                | Perm::ConnectionsUnrestricted
                | Perm::AdminUsers
                | Perm::AdminRoles
        )
    }

    fn bit(self) -> u32 {
        1 << (self as u32)
    }
}

impl fmt::Display for Perm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A set of permissions.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct PermSet(u32);

impl PermSet {
    pub const EMPTY: PermSet = PermSet(0);

    pub fn all() -> PermSet {
        PermSet::of(&Perm::ALL)
    }

    pub fn of(perms: &[Perm]) -> PermSet {
        PermSet(perms.iter().fold(0, |acc, p| acc | p.bit()))
    }

    pub fn contains(self, p: Perm) -> bool {
        self.0 & p.bit() != 0
    }

    pub fn union(self, other: PermSet) -> PermSet {
        PermSet(self.0 | other.0)
    }

    pub fn intersection(self, other: PermSet) -> PermSet {
        PermSet(self.0 & other.0)
    }

    /// Whether every permission in `self` is also in `other`.
    pub fn is_subset(self, other: PermSet) -> bool {
        self.0 & !other.0 == 0
    }

    /// The permissions in the set, in `Perm::ALL` order.
    pub fn iter(self) -> impl Iterator<Item = Perm> {
        Perm::ALL.into_iter().filter(move |p| self.contains(*p))
    }

    /// The permissions' names, in `Perm::ALL` order.
    pub fn names(self) -> Vec<&'static str> {
        self.iter().map(Perm::name).collect()
    }
}

impl fmt::Debug for PermSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.names()).finish()
    }
}

/// The built-in roles, lowest first. Each grants everything the one before
/// it does, exactly as the old role ladder did.
pub const BUILTIN_ROLES: [&str; 4] = ["viewer", "operator", "poweruser", "admin"];

/// What a built-in role grants, or `None` for any other name. `admin` grants
/// every permission, including any added in a later release.
pub fn builtin_role_perms(role: &str) -> Option<PermSet> {
    let viewer = PermSet::of(&[Perm::DocsView]);
    let operator = viewer.union(PermSet::of(&[
        Perm::ConnectionsConnect,
        Perm::CredentialsSelf,
    ]));
    let poweruser = operator.union(PermSet::of(&[
        Perm::ConnectionsAdhoc,
        Perm::RecordingsView,
        Perm::ReportsView,
        Perm::TokensSelf,
    ]));
    match role {
        "viewer" => Some(viewer),
        "operator" => Some(operator),
        "poweruser" => Some(poweruser),
        "admin" => Some(PermSet::all()),
        _ => None,
    }
}

/// What a role grants. Unknown roles grant nothing, as they always have.
pub fn role_perms(role: &str) -> PermSet {
    builtin_role_perms(role).unwrap_or(PermSet::EMPTY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for p in Perm::ALL {
            assert!(seen.insert(p.name()), "duplicate name {}", p.name());
            assert_eq!(PermSet::of(&[p]).names(), [p.name()]);
        }
        assert!(Perm::ALL.len() <= 32, "PermSet is a u32 bitmask");
    }

    #[test]
    fn builtin_roles_are_nested_like_the_old_ladder() {
        for pair in BUILTIN_ROLES.windows(2) {
            let (lower, higher) = (role_perms(pair[0]), role_perms(pair[1]));
            assert!(
                lower.is_subset(higher),
                "{} must be within {}",
                pair[0],
                pair[1]
            );
            assert_ne!(
                lower, higher,
                "{} must grant more than {}",
                pair[1], pair[0]
            );
        }
        assert_eq!(role_perms("admin"), PermSet::all());
        assert_eq!(role_perms("garbage"), PermSet::EMPTY);
        assert_eq!(role_perms(""), PermSet::EMPTY);
        assert_eq!(role_perms("Admin"), PermSet::EMPTY, "role names are exact");
    }

    /// Stage 1 of #294 replaced every role check with a permission check and
    /// must not change who is allowed what. This is every converted check as
    /// it stood before (the minimum role it asked for) next to the permission
    /// it asks for now: each built-in role must pass the new check exactly
    /// when it passed the old one.
    #[test]
    fn every_converted_check_allows_exactly_the_roles_it_did() {
        use crate::auth::role_level;
        let checks: &[(&str, &str, Perm)] = &[
            (
                "create_session: ad-hoc policy skipped",
                "admin",
                Perm::ConnectionsUnrestricted,
            ),
            (
                "create_session: session for another owner",
                "admin",
                Perm::AdminUsers,
            ),
            (
                "create_session / can_connect_adhoc",
                "poweruser",
                Perm::ConnectionsAdhoc,
            ),
            ("redact_share_url", "admin", Perm::SessionsViewAll),
            ("list_sessions ?all", "admin", Perm::SessionsViewAll),
            ("get_session (not owner)", "admin", Perm::SessionsViewAll),
            ("delete_session (own)", "operator", Perm::ConnectionsConnect),
            ("delete_session (anyone's)", "admin", Perm::SessionsViewAll),
            (
                "put/get_session_thumbnail (not owner)",
                "admin",
                Perm::SessionsViewAll,
            ),
            ("shadow_session", "admin", Perm::SessionsShadow),
            ("list_vdi_containers", "operator", Perm::ConnectionsConnect),
            (
                "get_vdi_container_thumbnail (not owner)",
                "admin",
                Perm::SessionsViewAll,
            ),
            ("list_login_scripts", "operator", Perm::ConnectionsConnect),
            ("system_status (detail)", "admin", Perm::AdminSystem),
            (
                "list_recordings / list_typescripts / serve_recording",
                "poweruser",
                Perm::RecordingsView,
            ),
            ("report_*", "poweruser", Perm::ReportsView),
            ("delete_recording", "admin", Perm::RecordingsDelete),
            (
                "list/create/delete/disable/enable users, end their sessions",
                "admin",
                Perm::AdminUsers,
            ),
            ("set_user_role", "admin", Perm::AdminRoles),
            ("group mappings, known groups", "admin", Perm::AdminRoles),
            ("check_folder_access bypass", "admin", Perm::ConnectionsEdit),
            (
                "ab_list_folders / subfolders / entries / all / search / version",
                "operator",
                Perm::ConnectionsConnect,
            ),
            ("ab_list_* see every folder", "admin", Perm::ConnectionsEdit),
            (
                "folder defaults get/put/delete",
                "admin",
                Perm::ConnectionsEdit,
            ),
            (
                "ssh_probe_host_key (entry editor, unfenced)",
                "admin",
                Perm::ConnectionsEdit,
            ),
            ("ab_connect_entry", "operator", Perm::ConnectionsConnect),
            (
                "ab_adhoc_connect: ad-hoc policy skipped",
                "admin",
                Perm::ConnectionsUnrestricted,
            ),
            (
                "folder and entry create/update/delete, bulk",
                "admin",
                Perm::ConnectionsEdit,
            ),
            (
                "create_my_token / revoke_my_token",
                "poweruser",
                Perm::TokensSelf,
            ),
            ("put_my_credentials", "operator", Perm::CredentialsSelf),
            (
                "list_credential_variables",
                "operator",
                Perm::CredentialsSelf,
            ),
            ("admin user tokens", "admin", Perm::AdminUsers),
            ("token and connections audit", "admin", Perm::AdminAudit),
            (
                "quick_connect entry link",
                "operator",
                Perm::ConnectionsConnect,
            ),
            (
                "quick_connect ad-hoc link: ad-hoc policy skipped",
                "admin",
                Perm::ConnectionsUnrestricted,
            ),
            (
                "ws_handler: join own session",
                "operator",
                Perm::ConnectionsConnect,
            ),
        ];
        for (site, old_min_role, perm) in checks {
            for role in BUILTIN_ROLES {
                let before = role_level(role) >= role_level(old_min_role);
                let after = role_perms(role).contains(*perm);
                assert_eq!(
                    before, after,
                    "{site}: role {role} was {before} under `{old_min_role}`, is {after} under {perm}"
                );
            }
        }
    }

    /// API keys from `add-admin` hold everything, and admin always gets every
    /// permission, including ones added later.
    #[test]
    fn admin_keys_and_admin_role_hold_every_permission() {
        let key = crate::auth::AuthIdentity::ApiKey("ops".into());
        for p in Perm::ALL {
            assert!(key.has_perm(p), "{p}");
            assert!(role_perms("admin").contains(p), "{p}");
        }
    }

    #[test]
    fn set_operations() {
        let a = PermSet::of(&[Perm::DocsView, Perm::ReportsView]);
        let b = PermSet::of(&[Perm::ReportsView, Perm::TokensSelf]);
        assert_eq!(
            a.union(b).names(),
            ["reports.view", "tokens.self", "docs.view"]
        );
        assert!(PermSet::EMPTY.is_subset(a));
        assert!(!a.is_subset(b));
    }
}
