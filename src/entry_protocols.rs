//! Multi-protocol connection entries (#296).
//!
//! An entry describes one host. Its top-level fields are the host's
//! defaults, and `protocols` lists the ways to connect to it, each a session
//! type plus the fields it overrides:
//!
//! ```json
//! {
//!   "hostname": "10.0.0.10",
//!   "display_name": "server01.example.com",
//!   "username": "Administrator",
//!   "protocols": [
//!     { "type": "rdp", "port": 3389 },
//!     { "type": "ssh", "port": 22, "username": "admin" },
//!     { "type": "web", "url": "https://10.0.0.10/", "hostname": "" }
//!   ]
//! }
//! ```
//!
//! A protocol inherits every host field it does not set, and clears one by
//! setting it empty (`""` or `[]`). `port` is the exception: it is never
//! inherited, so a protocol without one connects on its type's standard
//! port. The first protocol is the primary, the one Connect uses.
//!
//! `AddressBookEntry::effective` resolves the host and one protocol into a
//! plain single-type entry, which is what the connect path, folder defaults
//! and credential variables have always worked on, so they are unchanged.
//!
//! An entry stored before this existed has a top-level `type` and no
//! `protocols`. It is read as a one-protocol entry ([`split`]): the host
//! keeps the fields that describe the machine (see [`HOST_KEYS`]) and the
//! protocol gets everything else, credentials included, so a protocol added
//! later does not silently inherit them. Its effective entry is the stored
//! entry exactly. Nothing is rewritten on upgrade, and an entry that can be
//! written in the old form without losing anything is still written that
//! way ([`compact`]), so instances that do not know about `protocols` keep
//! reading it.
//!
//! [`split`]: AddressBookEntry::split
//! [`compact`]: AddressBookEntry::compact

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::vault::{AddressBookEntry, FolderSubject};

/// Session types a protocol may have.
pub const PROTOCOL_TYPES: &[&str] = &["ssh", "rdp", "vnc", "spice", "proxmox", "web", "vdi"];

/// Fields an entry in the old single-protocol form keeps on the host when it
/// is read as a one-protocol entry: what describes the machine rather than
/// how to connect to it, and whether to prompt for credentials (a policy
/// for the host, which the NetBox webhook sets there). Everything else,
/// credentials included, moves to the protocol.
pub const HOST_KEYS: &[&str] = &[
    "hostname",
    "display_name",
    "external_id",
    "banner",
    "prompt_credentials",
    "wol_send_packet",
    "wol_mac_addr",
    "wol_broadcast_addr",
    "wol_udp_port",
    "wol_wait_time",
    "allowed_groups",
    "allowed_users",
];

/// Fields that hold a secret. They are kept on update when the request
/// omits them, and never sent to a browser.
pub const SECRET_KEYS: &[&str] = &[
    "password",
    "private_key",
    "container_password",
    "proxmox_token_secret",
];

/// Most protocols one entry may have.
pub const MAX_PROTOCOLS: usize = 16;

/// One way to connect to an entry's host: a session type and the host
/// fields it overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProtocolEntry {
    #[serde(rename = "type")]
    pub session_type: String,
    /// Tells two protocols of the same type apart (`ssh` and `ssh-2222`).
    /// Defaults to the type; unique within the entry. The connect API, access
    /// rules, updates and sessions refer to a protocol by it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Write-only, in an update: the name this protocol had before, so its
    /// stored secrets follow it to the new name. Never stored or returned.
    #[serde(default, skip_serializing)]
    pub renamed_from: Option<String>,
    /// Who may use this protocol. Unset inherits the host's rule; set (even
    /// empty) replaces it, and an empty rule admits everyone who can open
    /// the folder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_groups: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_users: Option<Vec<String>>,
    /// Every other field, as stored: any entry field, overriding the host's.
    #[serde(flatten)]
    pub settings: Map<String, Value>,
}

impl ProtocolEntry {
    /// The protocol's name: `name` when set, else its type.
    pub fn name(&self) -> &str {
        self.name
            .as_deref()
            .filter(|n| !n.is_empty())
            .unwrap_or(&self.session_type)
    }

    /// Whether the protocol has an access rule of its own.
    fn has_own_rule(&self) -> bool {
        self.allowed_groups.is_some() || self.allowed_users.is_some()
    }
}

/// Whether `rule` (groups and users, as in a folder `.config`) admits `who`.
fn rule_grants(groups: &[String], users: &[String], who: FolderSubject<'_>) -> bool {
    if groups.iter().any(|g| who.groups.iter().any(|ug| ug == g)) {
        return true;
    }
    match who.email.map(str::trim) {
        Some(email) if !email.is_empty() => {
            users.iter().any(|u| u.trim().eq_ignore_ascii_case(email))
        }
        _ => false,
    }
}

fn slice(v: &Option<Vec<String>>) -> &[String] {
    v.as_deref().unwrap_or(&[])
}

/// Whether `who` may use `protocol` of an entry whose host is `host`. The
/// caller has already checked the folder, which stays the boundary: these
/// rules only narrow it.
///
/// The protocol's own rule wins when it has one; otherwise the host's rule
/// applies when it has one; otherwise everyone who can open the folder may.
/// `who` is `None` for an admin, who may use everything.
pub fn protocol_allowed(
    host: &AddressBookEntry,
    protocol: &ProtocolEntry,
    who: Option<FolderSubject<'_>>,
) -> bool {
    let Some(who) = who else { return true };
    if protocol.has_own_rule() {
        let (g, u) = (
            slice(&protocol.allowed_groups),
            slice(&protocol.allowed_users),
        );
        return (g.is_empty() && u.is_empty()) || rule_grants(g, u, who);
    }
    let (g, u) = (slice(&host.allowed_groups), slice(&host.allowed_users));
    if g.is_empty() && u.is_empty() {
        return true;
    }
    rule_grants(g, u, who)
}

/// Drop JSON nulls: an absent field and a null one mean the same (inherit).
fn non_null(map: Map<String, Value>) -> Map<String, Value> {
    map.into_iter().filter(|(_, v)| !v.is_null()).collect()
}

fn to_map(e: &AddressBookEntry) -> Map<String, Value> {
    match serde_json::to_value(e) {
        Ok(Value::Object(m)) => non_null(m),
        _ => Map::new(),
    }
}

/// Why an entry body was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryShapeError(pub String);

impl std::fmt::Display for EntryShapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A protocol name: what an entry name may be (it appears in links).
fn valid_protocol_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

impl AddressBookEntry {
    /// Whether the entry lists its protocols (the multi-protocol form) rather
    /// than having a single top-level `type`.
    pub fn has_protocol_list(&self) -> bool {
        self.protocols.as_ref().is_some_and(|p| !p.is_empty())
    }

    /// The host and its protocols. An entry in the old single-protocol form
    /// becomes one protocol: the host keeps [`HOST_KEYS`], the protocol gets
    /// every other field it has.
    pub fn split(&self) -> (AddressBookEntry, Vec<ProtocolEntry>) {
        if self.has_protocol_list() {
            let mut host = self.clone();
            let protocols = host.protocols.take().unwrap_or_default();
            host.session_type = String::new();
            return (host, protocols);
        }
        let mut flat = self.clone();
        flat.protocols = None;
        flat.normalize_jump_hosts();
        let mut host = Map::new();
        let mut settings = Map::new();
        for (k, v) in to_map(&flat) {
            if k == "type" {
                continue;
            }
            if HOST_KEYS.contains(&k.as_str()) {
                host.insert(k, v);
            } else {
                settings.insert(k, v);
            }
        }
        let host: AddressBookEntry =
            serde_json::from_value(Value::Object(host)).unwrap_or_default();
        let protocol = ProtocolEntry {
            session_type: self.session_type.clone(),
            settings,
            ..Default::default()
        };
        (host, vec![protocol])
    }

    /// The protocols in order, the primary first.
    pub fn protocol_list(&self) -> Vec<ProtocolEntry> {
        self.split().1
    }

    /// The single-type entry for one protocol: the host's fields with the
    /// protocol's on top. `None` picks the primary. An unknown name, or a
    /// protocol whose fields do not form a valid entry, is `None`.
    #[cfg(test)]
    pub fn effective(&self, protocol: Option<&str>) -> Option<AddressBookEntry> {
        let (host, protocols) = self.split();
        let p = match protocol {
            None => protocols.first(),
            Some(name) => protocols.iter().find(|p| p.name() == name),
        }?;
        effective_of(&host, p).ok()
    }

    /// Write in the old single-protocol form when nothing would be lost by
    /// it: one protocol, without a name of its own or any access rule, whose
    /// fields and the host's fall exactly where [`split`] would put them back.
    /// Such an entry stays readable by instances that predate `protocols`.
    /// Anything else is returned as it is.
    ///
    /// [`split`]: AddressBookEntry::split
    pub fn compact(self) -> AddressBookEntry {
        let Some(protocols) = self.protocols.as_ref() else {
            return self;
        };
        let [p] = protocols.as_slice() else {
            return self;
        };
        if p.name
            .as_deref()
            .is_some_and(|n| !n.is_empty() && n != p.session_type)
            || p.has_own_rule()
            || self.allowed_groups.is_some()
            || self.allowed_users.is_some()
            || p.session_type.is_empty()
        {
            return self;
        }
        let mut host = self.clone();
        host.protocols = None;
        host.session_type = String::new();
        let mut flat = to_map(&host);
        if flat.keys().any(|k| !HOST_KEYS.contains(&k.as_str())) {
            return self;
        }
        for (k, v) in non_null(p.settings.clone()) {
            if HOST_KEYS.contains(&k.as_str()) || k == "type" || k == "protocols" {
                return self;
            }
            flat.insert(k, v);
        }
        flat.insert("type".into(), Value::String(p.session_type.clone()));
        match serde_json::from_value::<AddressBookEntry>(Value::Object(flat)) {
            Ok(mut e) => {
                e.normalize_jump_hosts();
                e
            }
            Err(_) => self,
        }
    }

    /// Check an entry body. The old single-protocol form needs a `type`; the
    /// multi-protocol form needs `protocols` and no top-level `type`, each
    /// protocol of a known type, with a unique name, and fields that make a
    /// valid entry. `port` is set per protocol, never on the host.
    pub fn check_shape(&self) -> Result<(), EntryShapeError> {
        let err = |m: String| Err(EntryShapeError(m));
        let Some(protocols) = self.protocols.as_ref() else {
            if self.session_type.trim().is_empty() {
                return err("type is required (or a protocols list)".into());
            }
            return Ok(());
        };
        if protocols.is_empty() {
            return err("protocols must list at least one protocol".into());
        }
        if protocols.len() > MAX_PROTOCOLS {
            return err(format!("at most {MAX_PROTOCOLS} protocols per entry"));
        }
        if !self.session_type.is_empty() {
            return err(
                "an entry with protocols has no top-level type: set type on each protocol".into(),
            );
        }
        if self.port.is_some() {
            return err("port is set per protocol, not on the host".into());
        }
        let (host, _) = self.split();
        let mut seen: Vec<&str> = Vec::new();
        for (i, p) in protocols.iter().enumerate() {
            if !PROTOCOL_TYPES.contains(&p.session_type.as_str()) {
                return err(format!(
                    "protocols[{i}]: unknown type {:?} (use one of {})",
                    p.session_type,
                    PROTOCOL_TYPES.join(", ")
                ));
            }
            for (field, n) in [("name", &p.name), ("renamed_from", &p.renamed_from)] {
                if n.as_deref().is_some_and(|n| !valid_protocol_name(n)) {
                    return err(format!(
                        "protocols[{i}]: {field} must be 1-64 letters, digits, '-', '_' or '.'"
                    ));
                }
            }
            if seen.contains(&p.name()) {
                return err(format!(
                    "protocols[{i}]: two protocols are named {:?}; give one a name",
                    p.name()
                ));
            }
            seen.push(p.name());
            if p.settings.contains_key("protocols") {
                return err(format!("protocols[{i}]: a protocol cannot list protocols"));
            }
            if let Err(e) = effective_of(&host, p) {
                return err(format!("protocols[{i}]: {e}"));
            }
        }
        Ok(())
    }

    /// The protocol `who` should get for `requested` (`None` for the first
    /// they may use, which is the primary unless it is closed to them): the
    /// protocol's name and its effective entry. A name that matches no
    /// protocol is tried as a type, so a link that names the type of a
    /// single-protocol entry (`&protocol=rdp`) keeps working. A protocol
    /// `who` may not use is reported as missing, so it does not show.
    pub fn pick_protocol(
        &self,
        requested: Option<&str>,
        who: Option<FolderSubject<'_>>,
    ) -> Option<(String, AddressBookEntry)> {
        let (host, protocols) = self.split();
        let allowed = |p: &&ProtocolEntry| protocol_allowed(&host, p, who);
        let p = match requested.map(str::trim).filter(|r| !r.is_empty()) {
            None => protocols.iter().find(allowed),
            Some(r) => protocols
                .iter()
                .find(|p| p.name() == r)
                .or_else(|| protocols.iter().find(|p| p.session_type == r))
                .filter(allowed),
        }?;
        let eff = effective_of(&host, p).ok()?;
        Some((p.name().to_string(), eff))
    }

    /// The protocols `who` may use, with their effective entries, in order.
    pub fn visible_protocols(
        &self,
        who: Option<FolderSubject<'_>>,
    ) -> Vec<(ProtocolEntry, AddressBookEntry)> {
        let (host, protocols) = self.split();
        protocols
            .into_iter()
            .filter(|p| protocol_allowed(&host, p, who))
            .filter_map(|p| effective_of(&host, &p).ok().map(|e| (p, e)))
            .collect()
    }

    /// The session types of the entry's protocols, in order (for audit).
    pub fn protocol_types(&self) -> Vec<String> {
        self.protocol_list()
            .into_iter()
            .map(|p| p.session_type)
            .collect()
    }
}

/// The effective single-type entry of `protocol` on `host`: the host's
/// fields, less `port` (never inherited), with every field the protocol sets
/// on top, an empty one included (that is how a protocol clears one).
pub fn effective_of(
    host: &AddressBookEntry,
    protocol: &ProtocolEntry,
) -> Result<AddressBookEntry, String> {
    let mut m = to_map(host);
    for k in [
        "protocols",
        "allowed_groups",
        "allowed_users",
        "type",
        "port",
    ] {
        m.remove(k);
    }
    for (k, v) in &protocol.settings {
        if v.is_null() || k == "protocols" {
            continue;
        }
        m.insert(k.clone(), v.clone());
    }
    m.insert("type".into(), Value::String(protocol.session_type.clone()));
    let mut e: AddressBookEntry =
        serde_json::from_value(Value::Object(m)).map_err(|e| e.to_string())?;
    e.normalize_jump_hosts();
    e.protocols = None;
    e.allowed_groups = None;
    e.allowed_users = None;
    Ok(e)
}

/// Keep the stored secrets an update omits, in one protocol's or the host's
/// fields: a secret the request leaves out is kept, one it sends (even
/// empty, to clear it) wins. Jump host credentials and host keys are kept
/// per hop by position, as for the host.
pub fn keep_secrets(new: &mut Map<String, Value>, old: &Map<String, Value>) {
    for k in SECRET_KEYS {
        let absent = new.get(*k).is_none_or(Value::is_null);
        if absent {
            if let Some(v) = old.get(*k).filter(|v| !v.is_null()) {
                new.insert((*k).to_string(), v.clone());
            }
        }
    }
    if let (Some(Value::Array(new_hops)), Some(Value::Array(old_hops))) =
        (new.get_mut("jump_hosts"), old.get("jump_hosts"))
    {
        for (i, hop) in new_hops.iter_mut().enumerate() {
            let (Some(hop), Some(Value::Object(old_hop))) = (hop.as_object_mut(), old_hops.get(i))
            else {
                continue;
            };
            for k in ["password", "private_key", "host_key"] {
                if hop.get(k).is_none_or(Value::is_null) {
                    if let Some(v) = old_hop.get(k).filter(|v| !v.is_null()) {
                        hop.insert(k.to_string(), v.clone());
                    }
                }
            }
        }
    }
}

/// One level's own fields (the host's, or a protocol's overrides) as an
/// admin's editor may see them: every secret replaced by a `has_<field>`
/// flag (an empty one, which clears an inherited secret, is kept as it is),
/// jump hosts without their credentials and with the host key as its
/// fingerprint. For admins only: it shows the access rules.
pub fn editor_settings(settings: &Map<String, Value>) -> Value {
    let mut out = Map::new();
    for (k, v) in settings {
        if v.is_null() {
            continue;
        }
        if SECRET_KEYS.contains(&k.as_str()) {
            match v.as_str() {
                Some("") => {
                    out.insert(k.clone(), Value::String(String::new()));
                }
                _ => {
                    out.insert(format!("has_{k}"), Value::Bool(true));
                }
            }
            continue;
        }
        if k == "jump_hosts" {
            let hops: Vec<Value> = v
                .as_array()
                .map(|hops| {
                    hops.iter()
                        .map(|h| {
                            let mut o = Map::new();
                            for f in ["hostname", "port", "username"] {
                                if let Some(x) = h.get(f) {
                                    o.insert(f.into(), x.clone());
                                }
                            }
                            if let Some(fp) = h
                                .get("host_key")
                                .and_then(Value::as_str)
                                .and_then(|k| crate::tunnel::fingerprint_openssh_key(k).ok())
                            {
                                o.insert("host_key_fingerprint".into(), Value::String(fp));
                            }
                            for f in ["password", "private_key"] {
                                if h.get(f)
                                    .and_then(Value::as_str)
                                    .is_some_and(|s| !s.is_empty())
                                {
                                    o.insert(format!("has_{f}"), Value::Bool(true));
                                }
                            }
                            Value::Object(o)
                        })
                        .collect()
                })
                .unwrap_or_default();
            out.insert(k.clone(), Value::Array(hops));
            continue;
        }
        // Legacy single jump host fields never reach here (normalised), but
        // their secrets must not either.
        if k == "jump_password" || k == "jump_private_key" {
            continue;
        }
        out.insert(k.clone(), v.clone());
    }
    Value::Object(out)
}

/// The host's own fields, for [`editor_settings`].
pub fn host_settings(host: &AddressBookEntry) -> Map<String, Value> {
    let mut m = to_map(host);
    for k in ["protocols", "type", "allowed_groups", "allowed_users"] {
        m.remove(k);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(v: Value) -> AddressBookEntry {
        serde_json::from_value(v).unwrap()
    }

    fn who<'a>(email: Option<&'a str>, groups: &'a [String]) -> FolderSubject<'a> {
        FolderSubject { email, groups }
    }

    /// An entry in the old single-protocol form with every kind of field.
    fn legacy_rdp() -> Value {
        json!({
            "type": "rdp", "hostname": "10.0.0.10", "port": 3390,
            "username": "Administrator", "password": "pw", "domain": "CORP",
            "security": "nla", "ignore_cert": true, "display_name": "server01",
            "prompt_credentials": false, "banner": "Authorised use only",
            "enable_recording": true, "max_recordings": 5,
            "jump_hosts": [{"hostname": "bastion", "port": 22, "username": "j", "password": "jp"}],
            "wol_send_packet": true, "wol_mac_addr": "00:11:22:33:44:55",
            "external_id": "netbox:device:7", "allow_sharing": true,
            "fullscreen_on_connect": true, "disable_copy": true
        })
    }

    #[test]
    fn a_legacy_entry_reads_as_one_protocol_with_its_credentials() {
        let e = entry(legacy_rdp());
        let (host, protocols) = e.split();
        assert_eq!(protocols.len(), 1);
        let p = &protocols[0];
        assert_eq!(p.session_type, "rdp");
        assert_eq!(p.name(), "rdp");
        assert_eq!(p.settings["port"], json!(3390));
        assert_eq!(p.settings["password"], json!("pw"));
        assert_eq!(p.settings["username"], json!("Administrator"));
        assert!(p.settings.get("hostname").is_none());
        assert_eq!(host.hostname.as_deref(), Some("10.0.0.10"));
        assert_eq!(host.display_name.as_deref(), Some("server01"));
        assert_eq!(host.external_id.as_deref(), Some("netbox:device:7"));
        assert_eq!(host.banner.as_deref(), Some("Authorised use only"));
        assert_eq!(host.wol_send_packet, Some(true));
        assert_eq!(host.password, None, "credentials stay with the protocol");
        assert_eq!(host.username, None);
    }

    #[test]
    fn a_legacy_entry_resolves_to_exactly_itself() {
        // Back-compat: the effective entry of item 0 of a stored flat entry
        // is the stored entry, field for field.
        for v in [
            legacy_rdp(),
            json!({"type": "ssh", "hostname": "h", "port": 22}),
            json!({"type": "web", "url": "https://x/", "allowed_domains": []}),
            json!({"type": "ssh", "hostname": "h", "jump_host": "b", "jump_password": "x"}),
            json!({"type": "vdi", "container_image": "img", "container_env": {"A": "1"}}),
        ] {
            let mut stored = entry(v.clone());
            stored.normalize_jump_hosts();
            let eff = stored.effective(None).unwrap();
            assert_eq!(
                serde_json::to_value(&eff).unwrap(),
                serde_json::to_value(&stored).unwrap(),
                "{v}"
            );
            assert!(stored.effective(Some(&stored.session_type)).is_some());
        }
    }

    #[test]
    fn a_legacy_entry_round_trips_through_compact_unchanged() {
        let stored = entry(legacy_rdp());
        let (host, protocols) = stored.split();
        let mut rebuilt = host;
        rebuilt.protocols = Some(protocols);
        let compacted = rebuilt.compact();
        assert!(compacted.protocols.is_none(), "written in the old form");
        let mut expect = stored.clone();
        expect.normalize_jump_hosts();
        assert_eq!(
            serde_json::to_value(&compacted).unwrap(),
            serde_json::to_value(&expect).unwrap()
        );
    }

    #[test]
    fn compact_keeps_the_new_form_when_the_old_one_would_lose_something() {
        // Two protocols.
        let two = entry(json!({"hostname": "h", "protocols": [{"type": "ssh"}, {"type": "rdp"}]}));
        assert!(two.compact().has_protocol_list());
        // A host default the old form would move into the protocol.
        let host_user =
            entry(json!({"hostname": "h", "username": "u", "protocols": [{"type": "ssh"}]}));
        assert!(host_user.compact().has_protocol_list());
        // A protocol override of a host field.
        let cleared =
            entry(json!({"hostname": "h", "protocols": [{"type": "web", "hostname": ""}]}));
        assert!(cleared.compact().has_protocol_list());
        // Access rules, which an older instance would ignore.
        let acl = entry(
            json!({"hostname": "h", "allowed_groups": ["ops"], "protocols": [{"type": "ssh"}]}),
        );
        assert!(acl.compact().has_protocol_list());
        let pacl =
            entry(json!({"hostname": "h", "protocols": [{"type": "ssh", "allowed_users": []}]}));
        assert!(pacl.compact().has_protocol_list());
        // A name of its own.
        let named =
            entry(json!({"hostname": "h", "protocols": [{"type": "ssh", "name": "ssh-alt"}]}));
        assert!(named.compact().has_protocol_list());
        // But a plain single protocol is written the old way.
        let plain = entry(json!({"hostname": "h", "display_name": "d",
            "protocols": [{"type": "ssh", "port": 2222, "username": "u", "name": "ssh"}]}))
        .compact();
        assert!(!plain.has_protocol_list());
        assert_eq!(plain.session_type, "ssh");
        assert_eq!(plain.port, Some(2222));
        assert_eq!(plain.username.as_deref(), Some("u"));
        assert_eq!(plain.hostname.as_deref(), Some("h"));
    }

    #[test]
    fn protocols_inherit_override_and_clear_host_fields() {
        let e = entry(json!({
            "hostname": "10.0.0.10", "username": "Administrator", "display_name": "server01",
            "password": "host-pw",
            "protocols": [
                {"type": "rdp", "port": 3389},
                {"type": "ssh", "port": 22, "username": "admin"},
                {"type": "web", "url": "https://10.0.0.10/", "hostname": "", "password": ""}
            ]
        }));
        let rdp = e.effective(None).unwrap();
        assert_eq!(rdp.session_type, "rdp");
        assert_eq!(rdp.hostname.as_deref(), Some("10.0.0.10"));
        assert_eq!(rdp.username.as_deref(), Some("Administrator"));
        assert_eq!(rdp.password.as_deref(), Some("host-pw"));
        assert_eq!(rdp.port, Some(3389));
        let ssh = e.effective(Some("ssh")).unwrap();
        assert_eq!(ssh.username.as_deref(), Some("admin"));
        assert_eq!(ssh.password.as_deref(), Some("host-pw"));
        assert_eq!(ssh.display_name.as_deref(), Some("server01"));
        let web = e.effective(Some("web")).unwrap();
        assert_eq!(web.hostname.as_deref(), Some(""));
        assert_eq!(web.password.as_deref(), Some(""));
        assert!(!crate::vault::entry_has_own_credentials(&web));
        assert_eq!(web.url.as_deref(), Some("https://10.0.0.10/"));
        assert!(e.effective(Some("vnc")).is_none());
    }

    #[test]
    fn port_is_never_inherited_so_a_protocol_gets_its_standard_port() {
        // A host-level port is refused on write, but even if one is stored
        // it never reaches a protocol: an SSH protocol without a port must
        // not dial the RDP port.
        let e = entry(json!({"hostname": "h", "port": 3389,
            "protocols": [{"type": "rdp", "port": 3390}, {"type": "ssh"}]}));
        assert_eq!(e.effective(Some("rdp")).unwrap().port, Some(3390));
        assert_eq!(
            e.effective(Some("ssh")).unwrap().port,
            None,
            "session default: 22"
        );
        assert!(e.check_shape().is_err());
    }

    #[test]
    fn check_shape_accepts_both_forms_and_refuses_a_muddle() {
        assert!(entry(legacy_rdp()).check_shape().is_ok());
        assert!(entry(json!({"hostname": "h", "protocols": [{"type": "ssh"}, {"type": "ssh", "name": "ssh-2222", "port": 2222}]}))
            .check_shape()
            .is_ok());
        for bad in [
            json!({"hostname": "h"}),
            json!({"hostname": "h", "protocols": []}),
            json!({"type": "ssh", "protocols": [{"type": "ssh"}]}),
            json!({"protocols": [{"type": "telnet"}]}),
            json!({"protocols": [{"type": "ssh"}, {"type": "ssh"}]}),
            json!({"protocols": [{"type": "ssh", "name": "has space"}]}),
            json!({"protocols": [{"type": "ssh", "port": "twenty-two"}]}),
            json!({"protocols": [{"type": "ssh", "protocols": []}]}),
        ] {
            assert!(entry(bad.clone()).check_shape().is_err(), "{bad}");
        }
    }

    /// Matt's table on #296: a host rule and a protocol rule, each allowing
    /// or denying the user. The entry also has a protocol without a rule of
    /// its own, which follows the host. The host is visible when any
    /// protocol is.
    #[test]
    fn host_and_protocol_rules_follow_the_table() {
        let groups = vec!["ops".to_string()];
        let me = who(Some("me@example.com"), &groups);
        let rule = |allow: bool| {
            if allow {
                json!(["ops"])
            } else {
                json!(["finance"])
            }
        };
        for (host_allow, proto_allow, host_visible, proto_visible) in [
            (true, true, true, true),
            (true, false, true, false),
            (false, true, true, true),
            (false, false, false, false),
        ] {
            let e = entry(json!({
                "hostname": "h", "allowed_groups": rule(host_allow),
                "protocols": [
                    {"type": "ssh", "allowed_groups": rule(proto_allow)},
                    {"type": "rdp"}
                ]
            }));
            let visible: Vec<String> = e
                .visible_protocols(Some(me))
                .into_iter()
                .map(|(p, _)| p.name().to_string())
                .collect();
            let case = format!("host {host_allow} proto {proto_allow}");
            assert_eq!(!visible.is_empty(), host_visible, "host visible: {case}");
            assert_eq!(
                visible.contains(&"ssh".to_string()),
                proto_visible,
                "{case}"
            );
            assert_eq!(
                visible.contains(&"rdp".to_string()),
                host_allow,
                "inherits: {case}"
            );
            assert_eq!(
                e.pick_protocol(Some("ssh"), Some(me)).is_some(),
                proto_visible,
                "{case}"
            );
            // An admin sees and may use everything.
            assert_eq!(e.visible_protocols(None).len(), 2);
            assert!(e.pick_protocol(Some("ssh"), None).is_some());
        }
    }

    #[test]
    fn rules_inherit_from_the_host_and_then_the_folder() {
        let none: Vec<String> = vec![];
        let ops = vec!["ops".to_string()];
        let alice = who(Some("Alice@Example.com"), &none);
        let bob = who(Some("bob@example.com"), &ops);
        // No rule anywhere: everyone who can open the folder.
        let open = entry(json!({"hostname": "h", "protocols": [{"type": "ssh"}]}));
        assert_eq!(open.visible_protocols(Some(alice)).len(), 1);
        // Host rule by user, matched without regard to case; protocols inherit it.
        let host_rule = entry(
            json!({"hostname": "h", "allowed_users": ["alice@example.com"],
            "protocols": [{"type": "ssh"}, {"type": "rdp"}]}),
        );
        assert_eq!(host_rule.visible_protocols(Some(alice)).len(), 2);
        assert_eq!(host_rule.visible_protocols(Some(bob)).len(), 0);
        // An empty rule of its own opens a protocol to the whole folder.
        let reopened = entry(
            json!({"hostname": "h", "allowed_users": ["alice@example.com"],
            "protocols": [{"type": "ssh"}, {"type": "web", "allowed_groups": [], "allowed_users": []}]}),
        );
        let bob_sees: Vec<String> = reopened
            .visible_protocols(Some(bob))
            .into_iter()
            .map(|(p, _)| p.name().to_string())
            .collect();
        assert_eq!(bob_sees, ["web"]);
        // The primary is the first protocol the user may use.
        let (name, eff) = reopened.pick_protocol(None, Some(bob)).unwrap();
        assert_eq!((name.as_str(), eff.session_type.as_str()), ("web", "web"));
        let (name, _) = reopened.pick_protocol(None, Some(alice)).unwrap();
        assert_eq!(name, "ssh");
        // A legacy entry has no rules: unchanged access.
        assert!(entry(legacy_rdp()).pick_protocol(None, Some(bob)).is_some());
    }

    #[test]
    fn pick_protocol_falls_back_from_name_to_type() {
        let e = entry(json!({"hostname": "h", "protocols": [
            {"type": "ssh", "name": "ssh-2222", "port": 2222}, {"type": "rdp"}]}));
        assert_eq!(
            e.pick_protocol(Some("ssh-2222"), None).unwrap().0,
            "ssh-2222"
        );
        assert_eq!(e.pick_protocol(Some("ssh"), None).unwrap().0, "ssh-2222");
        assert_eq!(e.pick_protocol(Some("rdp"), None).unwrap().0, "rdp");
        assert_eq!(e.pick_protocol(Some(""), None).unwrap().0, "ssh-2222");
        assert!(e.pick_protocol(Some("vnc"), None).is_none());
        // An old quick link naming the type of a single-protocol entry.
        assert_eq!(
            entry(legacy_rdp())
                .pick_protocol(Some("rdp"), None)
                .unwrap()
                .0,
            "rdp"
        );
    }

    #[test]
    fn keep_secrets_keeps_what_the_update_omits() {
        let old = json!({"password": "p", "private_key": "k", "proxmox_token_secret": "t",
            "jump_hosts": [{"hostname": "b", "username": "j", "password": "jp", "host_key": "hk"}]});
        let mut new = json!({"username": "u", "private_key": "",
            "jump_hosts": [{"hostname": "b", "username": "j"}]});
        keep_secrets(new.as_object_mut().unwrap(), old.as_object().unwrap());
        assert_eq!(new["password"], json!("p"));
        assert_eq!(new["private_key"], json!(""), "an empty one clears");
        assert_eq!(new["proxmox_token_secret"], json!("t"));
        assert_eq!(new["jump_hosts"][0]["password"], json!("jp"));
        assert_eq!(new["jump_hosts"][0]["host_key"], json!("hk"));
    }

    #[test]
    fn editor_settings_never_carry_a_secret() {
        let s = json!({"username": "u", "password": "p", "private_key": "", "container_password": "c",
            "jump_hosts": [{"hostname": "b", "port": 22, "username": "j", "password": "jp", "private_key": "k"}]});
        let out = editor_settings(s.as_object().unwrap());
        let text = out.to_string();
        for secret in ["\"p\"", "\"c\"", "jp", "\"k\""] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        assert_eq!(out["has_password"], json!(true));
        assert_eq!(out["has_container_password"], json!(true));
        assert_eq!(
            out["private_key"],
            json!(""),
            "a cleared secret shows as cleared"
        );
        assert_eq!(out["jump_hosts"][0]["has_password"], json!(true));
        assert_eq!(out["username"], json!("u"));
    }
}
