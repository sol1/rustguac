//! Moving a folder (#372): to another parent, to the top level, or to a new
//! name, with everything under it.
//!
//! A folder's path is where its keys live in Vault, and KV v2 cannot rename a
//! path, so a move copies every key in the subtree (each entry with its
//! secrets, each folder's `.config` and `.defaults`) and only then removes
//! the originals. If any copy fails, what was copied is removed again and
//! the source is left as it was. If the copy succeeds but removing the
//! source does not, the folder is in both places and the caller is told so,
//! the same way a single entry move reports it.
//!
//! Moving can change who can open the folder: one with `inherit_from_parent`
//! takes its new parent's audience, and the default credentials lent to its
//! entries follow the new parent too. `preview` says what changes, so the UI
//! can show it before anything is written.

use std::collections::BTreeSet;

use futures_util::StreamExt;
use serde::Serialize;

use crate::vault::{AddressBookEntry, FolderConfig, FolderDefaults, VaultError};

/// Entries copied or removed at once.
const CONCURRENCY: usize = 8;

/// What a move reads and writes. A trait so the walk, the copy and the
/// rollback are unit-testable without a Vault.
#[allow(async_fn_in_trait)]
pub trait FolderStore {
    /// Full paths of the folder's immediate subfolders; empty when none.
    async fn subfolders(&self, scope: &str, folder: &str) -> Result<Vec<String>, VaultError>;
    /// Names of the entries directly in the folder; empty when none.
    async fn entries(&self, scope: &str, folder: &str) -> Result<Vec<String>, VaultError>;
    async fn config(&self, scope: &str, folder: &str) -> Result<Option<FolderConfig>, VaultError>;
    async fn defaults(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<Option<FolderDefaults>, VaultError>;
    async fn get_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<AddressBookEntry, VaultError>;
    /// Write only if nothing is stored there; `Ok(false)` when something is.
    async fn put_entry_if_absent(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
    ) -> Result<bool, VaultError>;
    async fn delete_entry(&self, scope: &str, folder: &str, entry: &str) -> Result<(), VaultError>;
    async fn put_config(
        &self,
        scope: &str,
        folder: &str,
        config: &FolderConfig,
    ) -> Result<(), VaultError>;
    async fn put_defaults(
        &self,
        scope: &str,
        folder: &str,
        defaults: &FolderDefaults,
    ) -> Result<(), VaultError>;
    async fn delete_config(&self, scope: &str, folder: &str) -> Result<(), VaultError>;
    async fn delete_defaults(&self, scope: &str, folder: &str) -> Result<(), VaultError>;
}

/// One folder of the subtree being moved, as it was read.
#[derive(Debug, Clone)]
pub struct TreeFolder {
    /// Path below the moved folder: `""` for the folder itself, `"a/b"` for
    /// a subfolder two levels down.
    pub rel: String,
    pub config: Option<FolderConfig>,
    pub defaults: Option<FolderDefaults>,
    pub entries: Vec<String>,
}

/// Where a folder goes: its new path is `parent/name`, or `name` at the top
/// level when `parent` is empty.
pub fn target_path(parent: &str, name: &str) -> String {
    let parent = parent.trim_matches('/');
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

/// The last segment of a folder path.
pub fn folder_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// `rel` under `base`.
fn join(base: &str, rel: &str) -> String {
    if rel.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{rel}")
    }
}

/// Why a move cannot even be attempted, before anything is read.
pub fn check_paths(
    scope: &str,
    folder: &str,
    target_scope: &str,
    target: &str,
) -> Result<(), String> {
    crate::vault::validate_path(folder).map_err(|e| e.to_string())?;
    crate::vault::validate_path(target).map_err(|e| e.to_string())?;
    if scope == target_scope {
        if target == folder {
            return Err(format!(
                "the folder is already at {scope}/{folder}; choose another parent or name"
            ));
        }
        if target.starts_with(&format!("{folder}/")) {
            return Err("a folder cannot be moved into itself".into());
        }
    }
    Ok(())
}

/// Whether anything is stored at `path`: a config, defaults, an entry or a
/// subfolder.
pub async fn exists<S: FolderStore>(
    store: &S,
    scope: &str,
    path: &str,
) -> Result<bool, VaultError> {
    Ok(store.config(scope, path).await?.is_some()
        || store.defaults(scope, path).await?.is_some()
        || !store.entries(scope, path).await?.is_empty()
        || !store.subfolders(scope, path).await?.is_empty())
}

/// Read the whole subtree under `folder`, parents before their children.
/// Any read error stops it: a move must not leave part of a tree behind
/// because a listing failed.
pub async fn read_tree<S: FolderStore>(
    store: &S,
    scope: &str,
    folder: &str,
) -> Result<Vec<TreeFolder>, VaultError> {
    let mut out: Vec<TreeFolder> = Vec::new();
    let mut i = 0;
    out.push(read_one(store, scope, folder, String::new()).await?);
    while i < out.len() {
        let abs = join(folder, &out[i].rel);
        let mut subs = store.subfolders(scope, &abs).await?;
        subs.sort();
        for sub in subs {
            let Some(rel) = sub.strip_prefix(&format!("{folder}/")) else {
                continue;
            };
            out.push(read_one(store, scope, &sub, rel.to_string()).await?);
        }
        i += 1;
    }
    Ok(out)
}

async fn read_one<S: FolderStore>(
    store: &S,
    scope: &str,
    path: &str,
    rel: String,
) -> Result<TreeFolder, VaultError> {
    let mut entries = store.entries(scope, path).await?;
    entries.sort();
    Ok(TreeFolder {
        rel,
        config: store.config(scope, path).await?,
        defaults: store.defaults(scope, path).await?,
        entries,
    })
}

/// Who can open a folder: the groups and users of its own rule and of each
/// ancestor it inherits through, and the folders those come from.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct Audience {
    pub groups: Vec<String>,
    pub users: Vec<String>,
    /// The folders whose rules apply, nearest first.
    pub from: Vec<String>,
}

/// A default credential lent to entries in the folder, by session type.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Lent {
    pub session_type: String,
    /// The folder that lends it.
    pub from: String,
}

/// The folder at `path`, and each ancestor's config and defaults, nearest
/// first.
type Chain = Vec<(String, Option<FolderConfig>, Option<FolderDefaults>)>;

async fn ancestors<S: FolderStore>(
    store: &S,
    scope: &str,
    path: &str,
) -> Result<Chain, VaultError> {
    let mut out = Vec::new();
    let mut cur = path.to_string();
    while let Some(i) = cur.rfind('/') {
        cur.truncate(i);
        out.push((
            cur.clone(),
            store.config(scope, &cur).await?,
            store.defaults(scope, &cur).await?,
        ));
    }
    Ok(out)
}

/// Who can open a folder whose chain (itself, then its ancestors) is
/// `chain`, as `resolve_folder_access` decides it: its own rule, then each
/// parent's while the folder just visited inherits. A folder with no config
/// admits nobody and stops the walk.
fn audience(chain: &Chain) -> Audience {
    let mut groups = BTreeSet::new();
    let mut users = BTreeSet::new();
    let mut from = Vec::new();
    for (path, config, _) in chain {
        let Some(c) = config else { break };
        if !c.allowed_groups.is_empty() || !c.allowed_users.is_empty() {
            from.push(path.clone());
        }
        groups.extend(c.allowed_groups.iter().cloned());
        users.extend(c.allowed_users.iter().map(|u| u.trim().to_lowercase()));
        if !c.inherit_from_parent {
            break;
        }
    }
    Audience {
        groups: groups.into_iter().collect(),
        users: users.into_iter().collect(),
        from,
    }
}

/// The default credentials lent to entries in a folder whose chain is
/// `chain`, as `resolve_effective_defaults` decides it: the nearest folder
/// wins per type, and the walk goes up only while the folder just visited
/// shares its parent's audience.
fn lent(chain: &Chain) -> Vec<Lent> {
    let mut out: Vec<Lent> = Vec::new();
    for (path, config, defaults) in chain {
        for session_type in defaults.iter().flat_map(|d| d.keys()) {
            if !out.iter().any(|l| &l.session_type == session_type) {
                out.push(Lent {
                    session_type: session_type.clone(),
                    from: path.clone(),
                });
            }
        }
        if !config.as_ref().is_some_and(|c| c.shares_parent_audience()) {
            break;
        }
    }
    out.sort_by(|a, b| a.session_type.cmp(&b.session_type));
    out
}

/// What a move would do, for the UI to show before it is confirmed.
#[derive(Debug, Clone, Serialize)]
pub struct Preview {
    pub subfolders: usize,
    pub entries: usize,
    pub access_before: Audience,
    pub access_after: Audience,
    pub access_changes: bool,
    pub defaults_before: Vec<Lent>,
    pub defaults_after: Vec<Lent>,
    pub defaults_change: bool,
}

/// Compare who can open the moved folder, and which defaults reach its
/// entries, before and after the move. The folder's own config and defaults
/// go with it; only what it inherits changes. Subfolders that inherit
/// through it change the same way, so the folder itself stands for them.
pub async fn preview<S: FolderStore>(
    store: &S,
    tree: &[TreeFolder],
    scope: &str,
    folder: &str,
    target_scope: &str,
    target: &str,
) -> Result<Preview, VaultError> {
    let root = &tree[0];
    let own = |path: &str| (path.to_string(), root.config.clone(), root.defaults.clone());
    let mut before: Chain = vec![own(folder)];
    before.extend(ancestors(store, scope, folder).await?);
    let mut after: Chain = vec![own(target)];
    after.extend(ancestors(store, target_scope, target).await?);

    let (access_before, access_after) = (audience(&before), audience(&after));
    let (defaults_before, defaults_after) = (lent(&before), lent(&after));
    // The folder's own rule moves with it, so compare who gets in, not
    // where the rule is stored.
    let same_access = access_before.groups == access_after.groups
        && access_before.users == access_after.users
        && scope == target_scope;
    // A default the folder lends itself goes with it under the new path.
    let norm = |l: &[Lent], own: &str| -> Vec<(String, Option<String>)> {
        l.iter()
            .map(|x| {
                (
                    x.session_type.clone(),
                    (x.from != own).then(|| x.from.clone()),
                )
            })
            .collect()
    };
    let same_defaults =
        norm(&defaults_before, folder) == norm(&defaults_after, target) && scope == target_scope;
    Ok(Preview {
        subfolders: tree.len() - 1,
        entries: tree.iter().map(|f| f.entries.len()).sum(),
        access_changes: !same_access,
        defaults_change: !same_defaults,
        access_before,
        access_after,
        defaults_before,
        defaults_after,
    })
}

/// A move that did not finish.
#[derive(Debug)]
pub enum MoveFailure {
    /// The copy failed and was undone: nothing changed, unless `leftover`
    /// keys of the partial copy could not be removed from the target.
    Copy { error: String, leftover: usize },
    /// Everything was copied, but `failed` keys of the source could not be
    /// removed, so the folder is in both places.
    Incomplete { error: String, failed: usize },
}

/// One key the copy wrote, so a failed copy can be undone.
enum Written {
    Config(String),
    Defaults(String),
    Entry(String, String),
}

/// Move the subtree read as `tree` from `scope`/`folder` to
/// `target_scope`/`target`. The caller has checked the paths and that
/// nothing is stored at `target`.
pub async fn execute<S: FolderStore>(
    store: &S,
    tree: &[TreeFolder],
    scope: &str,
    folder: &str,
    target_scope: &str,
    target: &str,
) -> Result<(), MoveFailure> {
    let mut written: Vec<Written> = Vec::new();
    if let Err(error) = copy(
        store,
        tree,
        scope,
        folder,
        target_scope,
        target,
        &mut written,
    )
    .await
    {
        let leftover = undo(store, target_scope, written).await;
        return Err(MoveFailure::Copy { error, leftover });
    }

    // Remove the source, deepest folders first.
    let mut failed = 0usize;
    let mut first_error: Option<String> = None;
    for f in tree.iter().rev() {
        let path = join(folder, &f.rel);
        let results: Vec<Result<(), VaultError>> =
            futures_util::stream::iter(f.entries.iter().cloned().map(|e| {
                let path = path.clone();
                async move { store.delete_entry(scope, &path, &e).await }
            }))
            .buffer_unordered(CONCURRENCY)
            .collect()
            .await;
        let mut sentinels = Vec::new();
        if f.defaults.is_some() {
            sentinels.push(store.delete_defaults(scope, &path).await);
        }
        if f.config.is_some() {
            sentinels.push(store.delete_config(scope, &path).await);
        }
        for r in results.into_iter().chain(sentinels) {
            match r {
                Ok(()) | Err(VaultError::NotFound) => {}
                Err(e) => {
                    failed += 1;
                    first_error.get_or_insert_with(|| e.to_string());
                }
            }
        }
    }
    match first_error {
        None => Ok(()),
        Some(error) => Err(MoveFailure::Incomplete { error, failed }),
    }
}

async fn copy<S: FolderStore>(
    store: &S,
    tree: &[TreeFolder],
    scope: &str,
    folder: &str,
    target_scope: &str,
    target: &str,
    written: &mut Vec<Written>,
) -> Result<(), String> {
    for f in tree {
        let src = join(folder, &f.rel);
        let dst = join(target, &f.rel);
        if let Some(c) = &f.config {
            store
                .put_config(target_scope, &dst, c)
                .await
                .map_err(|e| format!("{dst}: {e}"))?;
            written.push(Written::Config(dst.clone()));
        }
        if let Some(d) = &f.defaults {
            store
                .put_defaults(target_scope, &dst, d)
                .await
                .map_err(|e| format!("{dst}: {e}"))?;
            written.push(Written::Defaults(dst.clone()));
        }
        let results: Vec<(String, Result<bool, VaultError>)> =
            futures_util::stream::iter(f.entries.iter().cloned().map(|name| {
                let (src, dst) = (src.clone(), dst.clone());
                async move {
                    let r = match store.get_entry(scope, &src, &name).await {
                        Ok(full) => {
                            store
                                .put_entry_if_absent(target_scope, &dst, &name, &full)
                                .await
                        }
                        Err(e) => Err(e),
                    };
                    (name, r)
                }
            }))
            .buffer_unordered(CONCURRENCY)
            .collect()
            .await;
        let mut error = None;
        for (name, r) in results {
            match r {
                Ok(true) => written.push(Written::Entry(dst.clone(), name)),
                Ok(false) => {
                    error.get_or_insert_with(|| format!("{dst}/{name} already exists"));
                }
                Err(e) => {
                    error.get_or_insert_with(|| format!("{src}/{name}: {e}"));
                }
            }
        }
        if let Some(e) = error {
            return Err(e);
        }
    }
    Ok(())
}

/// Remove what a failed copy wrote. Returns how many keys stayed.
async fn undo<S: FolderStore>(store: &S, scope: &str, written: Vec<Written>) -> usize {
    let mut left = 0;
    for w in written.into_iter().rev() {
        let r = match &w {
            Written::Config(p) => store.delete_config(scope, p).await,
            Written::Defaults(p) => store.delete_defaults(scope, p).await,
            Written::Entry(p, e) => store.delete_entry(scope, p, e).await,
        };
        if r.is_err() {
            left += 1;
        }
    }
    left
}

/// Missing is empty: a listing of a folder with nothing in it is a 404.
fn or_empty<T: Default>(r: Result<T, VaultError>) -> Result<T, VaultError> {
    match r {
        Err(VaultError::NotFound) => Ok(T::default()),
        r => r,
    }
}

fn or_none<T>(r: Result<T, VaultError>) -> Result<Option<T>, VaultError> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(VaultError::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

impl FolderStore for crate::api::VaultBackends {
    async fn subfolders(&self, scope: &str, folder: &str) -> Result<Vec<String>, VaultError> {
        Ok(or_empty(self.list_subfolders(scope, folder).await)?
            .into_iter()
            .map(|f| f.path.unwrap_or_else(|| format!("{folder}/{}", f.name)))
            .collect())
    }
    async fn entries(&self, scope: &str, folder: &str) -> Result<Vec<String>, VaultError> {
        // The KV listing also returns subfolders, as `name/`.
        Ok(or_empty(self.list_entries(scope, folder).await)?
            .into_iter()
            .filter(|n| !n.ends_with('/'))
            .collect())
    }
    async fn config(&self, scope: &str, folder: &str) -> Result<Option<FolderConfig>, VaultError> {
        or_none(self.get_folder_config(scope, folder).await)
    }
    async fn defaults(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<Option<FolderDefaults>, VaultError> {
        or_none(self.get_folder_defaults(scope, folder).await)
    }
    async fn get_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<AddressBookEntry, VaultError> {
        crate::api::VaultBackends::get_entry(self, scope, folder, entry).await
    }
    async fn put_entry_if_absent(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
    ) -> Result<bool, VaultError> {
        crate::api::VaultBackends::put_entry_if_absent(self, scope, folder, entry, data).await
    }
    async fn delete_entry(&self, scope: &str, folder: &str, entry: &str) -> Result<(), VaultError> {
        crate::api::VaultBackends::delete_entry(self, scope, folder, entry).await
    }
    async fn put_config(
        &self,
        scope: &str,
        folder: &str,
        config: &FolderConfig,
    ) -> Result<(), VaultError> {
        self.put_folder_config(scope, folder, config).await
    }
    async fn put_defaults(
        &self,
        scope: &str,
        folder: &str,
        defaults: &FolderDefaults,
    ) -> Result<(), VaultError> {
        self.put_folder_defaults(scope, folder, defaults).await
    }
    async fn delete_config(&self, scope: &str, folder: &str) -> Result<(), VaultError> {
        self.delete_folder_config(scope, folder).await
    }
    async fn delete_defaults(&self, scope: &str, folder: &str) -> Result<(), VaultError> {
        self.delete_folder_defaults(scope, folder).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashSet};
    use std::sync::Mutex;

    /// Keys by (scope, path). A folder's sentinels are `<path>/.config` and
    /// `<path>/.defaults`; an entry is `<path>/<name>`.
    #[derive(Default)]
    struct Mem {
        configs: Mutex<BTreeMap<(String, String), FolderConfig>>,
        defaults: Mutex<BTreeMap<(String, String), FolderDefaults>>,
        entries: Mutex<BTreeMap<(String, String, String), AddressBookEntry>>,
        /// Writes to these folder paths fail.
        fail_writes_under: Mutex<HashSet<String>>,
        /// Deletes of these entry names fail.
        fail_deletes: Mutex<HashSet<String>>,
    }

    fn k(s: &str, p: &str) -> (String, String) {
        (s.into(), p.into())
    }

    impl Mem {
        fn folder(&self, scope: &str, path: &str, groups: &[&str], inherit: bool) {
            self.configs.lock().unwrap().insert(
                k(scope, path),
                FolderConfig {
                    allowed_groups: groups.iter().map(|g| g.to_string()).collect(),
                    allowed_users: vec![],
                    description: String::new(),
                    display_name: String::new(),
                    inherit_from_parent: inherit,
                },
            );
        }
        fn entry(&self, scope: &str, path: &str, name: &str, password: &str) {
            let e = AddressBookEntry {
                session_type: "ssh".into(),
                hostname: Some("10.0.0.1".into()),
                password: Some(password.into()),
                ..Default::default()
            };
            self.entries
                .lock()
                .unwrap()
                .insert((scope.into(), path.into(), name.into()), e);
        }
        fn lend(&self, scope: &str, path: &str, session_type: &str) {
            let mut d = FolderDefaults::new();
            d.insert(
                session_type.into(),
                crate::vault::DefaultCredentials {
                    username: Some("svc".into()),
                    password: Some("pw".into()),
                    ..Default::default()
                },
            );
            self.defaults.lock().unwrap().insert(k(scope, path), d);
        }
        fn all_paths(&self, scope: &str) -> BTreeSet<String> {
            let mut out = BTreeSet::new();
            for (s, p) in self.configs.lock().unwrap().keys() {
                if s == scope {
                    out.insert(p.clone());
                }
            }
            for (s, p) in self.defaults.lock().unwrap().keys() {
                if s == scope {
                    out.insert(p.clone());
                }
            }
            for (s, p, _) in self.entries.lock().unwrap().keys() {
                if s == scope {
                    out.insert(p.clone());
                }
            }
            // Every ancestor of a stored key is a folder too, as in Vault.
            let mut all = BTreeSet::new();
            for p in out {
                let mut cur = p.as_str();
                all.insert(cur.to_string());
                while let Some(i) = cur.rfind('/') {
                    cur = &cur[..i];
                    all.insert(cur.to_string());
                }
            }
            all
        }
        fn write_fails(&self, path: &str) -> Result<(), VaultError> {
            if self.fail_writes_under.lock().unwrap().contains(path) {
                Err(VaultError::Parse("write refused".into()))
            } else {
                Ok(())
            }
        }
        fn keys(&self, scope: &str) -> Vec<String> {
            let mut out: Vec<String> = Vec::new();
            for (s, p) in self.configs.lock().unwrap().keys() {
                if s == scope {
                    out.push(format!("{p}/.config"));
                }
            }
            for (s, p) in self.defaults.lock().unwrap().keys() {
                if s == scope {
                    out.push(format!("{p}/.defaults"));
                }
            }
            for (s, p, e) in self.entries.lock().unwrap().keys() {
                if s == scope {
                    out.push(format!("{p}/{e}"));
                }
            }
            out.sort();
            out
        }
    }

    impl FolderStore for Mem {
        async fn subfolders(&self, scope: &str, folder: &str) -> Result<Vec<String>, VaultError> {
            let prefix = format!("{folder}/");
            Ok(self
                .all_paths(scope)
                .into_iter()
                .filter(|p| p.strip_prefix(&prefix).is_some_and(|r| !r.contains('/')))
                .collect())
        }
        async fn entries(&self, scope: &str, folder: &str) -> Result<Vec<String>, VaultError> {
            Ok(self
                .entries
                .lock()
                .unwrap()
                .keys()
                .filter(|(s, p, _)| s == scope && p == folder)
                .map(|(_, _, e)| e.clone())
                .collect())
        }
        async fn config(
            &self,
            scope: &str,
            folder: &str,
        ) -> Result<Option<FolderConfig>, VaultError> {
            Ok(self.configs.lock().unwrap().get(&k(scope, folder)).cloned())
        }
        async fn defaults(
            &self,
            scope: &str,
            folder: &str,
        ) -> Result<Option<FolderDefaults>, VaultError> {
            Ok(self
                .defaults
                .lock()
                .unwrap()
                .get(&k(scope, folder))
                .cloned())
        }
        async fn get_entry(
            &self,
            scope: &str,
            folder: &str,
            entry: &str,
        ) -> Result<AddressBookEntry, VaultError> {
            self.entries
                .lock()
                .unwrap()
                .get(&(scope.into(), folder.into(), entry.into()))
                .cloned()
                .ok_or(VaultError::NotFound)
        }
        async fn put_entry_if_absent(
            &self,
            scope: &str,
            folder: &str,
            entry: &str,
            data: &AddressBookEntry,
        ) -> Result<bool, VaultError> {
            self.write_fails(folder)?;
            let mut m = self.entries.lock().unwrap();
            let key = (scope.to_string(), folder.to_string(), entry.to_string());
            if m.contains_key(&key) {
                return Ok(false);
            }
            m.insert(key, data.clone());
            Ok(true)
        }
        async fn delete_entry(
            &self,
            scope: &str,
            folder: &str,
            entry: &str,
        ) -> Result<(), VaultError> {
            if self.fail_deletes.lock().unwrap().contains(entry) {
                return Err(VaultError::Parse("delete refused".into()));
            }
            self.entries
                .lock()
                .unwrap()
                .remove(&(scope.into(), folder.into(), entry.into()))
                .map(|_| ())
                .ok_or(VaultError::NotFound)
        }
        async fn put_config(
            &self,
            scope: &str,
            folder: &str,
            config: &FolderConfig,
        ) -> Result<(), VaultError> {
            self.write_fails(folder)?;
            self.configs
                .lock()
                .unwrap()
                .insert(k(scope, folder), config.clone());
            Ok(())
        }
        async fn put_defaults(
            &self,
            scope: &str,
            folder: &str,
            defaults: &FolderDefaults,
        ) -> Result<(), VaultError> {
            self.write_fails(folder)?;
            self.defaults
                .lock()
                .unwrap()
                .insert(k(scope, folder), defaults.clone());
            Ok(())
        }
        async fn delete_config(&self, scope: &str, folder: &str) -> Result<(), VaultError> {
            self.configs.lock().unwrap().remove(&k(scope, folder));
            Ok(())
        }
        async fn delete_defaults(&self, scope: &str, folder: &str) -> Result<(), VaultError> {
            self.defaults.lock().unwrap().remove(&k(scope, folder));
            Ok(())
        }
    }

    /// The issue's example: Engineering/Software moves under DevOps.
    fn sample() -> Mem {
        let m = Mem::default();
        m.folder("shared", "Engineering", &["engineers"], false);
        m.folder("shared", "Engineering/Software", &["software"], true);
        m.folder("shared", "Engineering/Software/Build", &[], true);
        m.entry("shared", "Engineering/Software", "git01", "s3cret");
        m.entry("shared", "Engineering/Software/Build", "ci01", "k3y");
        m.lend("shared", "Engineering/Software/Build", "ssh");
        m.folder("shared", "DevOps", &["devops"], false);
        m.entry("shared", "Engineering", "wiki", "w");
        m
    }

    #[test]
    fn paths_are_checked_before_anything_is_read() {
        assert_eq!(target_path("", "Software"), "Software");
        assert_eq!(target_path("DevOps", "Software"), "DevOps/Software");
        assert_eq!(folder_name("Engineering/Software"), "Software");
        assert!(check_paths("shared", "A/B", "shared", "C/B").is_ok());
        assert!(check_paths("shared", "A", "shared", "A").is_err());
        assert!(check_paths("shared", "A", "shared", "A/B/A").is_err());
        // A sibling whose name starts the same is not inside it.
        assert!(check_paths("shared", "A", "shared", "AB/A").is_ok());
        // The same path in the other scope is a different folder.
        assert!(check_paths("shared", "A", "instance", "A").is_ok());
        assert!(check_paths("shared", "A", "shared", "../A").is_err());
    }

    #[tokio::test]
    async fn a_move_takes_the_whole_subtree_with_its_secrets() {
        let m = sample();
        let tree = read_tree(&m, "shared", "Engineering/Software")
            .await
            .unwrap();
        assert_eq!(tree.len(), 2);
        execute(
            &m,
            &tree,
            "shared",
            "Engineering/Software",
            "shared",
            "DevOps/Software",
        )
        .await
        .unwrap();
        assert_eq!(
            m.keys("shared"),
            vec![
                "DevOps/.config",
                "DevOps/Software/.config",
                "DevOps/Software/Build/.config",
                "DevOps/Software/Build/.defaults",
                "DevOps/Software/Build/ci01",
                "DevOps/Software/git01",
                "Engineering/.config",
                "Engineering/wiki",
            ]
        );
        let moved = m
            .get_entry("shared", "DevOps/Software/Build", "ci01")
            .await
            .unwrap();
        assert_eq!(moved.password.as_deref(), Some("k3y"));
    }

    #[tokio::test]
    async fn the_preview_shows_who_gains_and_loses_access() {
        let m = sample();
        let tree = read_tree(&m, "shared", "Engineering/Software")
            .await
            .unwrap();
        let p = preview(
            &m,
            &tree,
            "shared",
            "Engineering/Software",
            "shared",
            "DevOps/Software",
        )
        .await
        .unwrap();
        assert_eq!((p.subfolders, p.entries), (1, 2));
        assert_eq!(p.access_before.groups, vec!["engineers", "software"]);
        assert_eq!(p.access_after.groups, vec!["devops", "software"]);
        assert_eq!(p.access_after.from, vec!["DevOps/Software", "DevOps"]);
        assert!(p.access_changes);
        assert!(!p.defaults_change);

        // To the top level: only its own rule is left.
        let p = preview(
            &m,
            &tree,
            "shared",
            "Engineering/Software",
            "shared",
            "Software",
        )
        .await
        .unwrap();
        assert_eq!(p.access_after.groups, vec!["software"]);
        assert!(p.access_changes);

        // A rename in place changes neither.
        let p = preview(
            &m,
            &tree,
            "shared",
            "Engineering/Software",
            "shared",
            "Engineering/Dev",
        )
        .await
        .unwrap();
        assert!(!p.access_changes && !p.defaults_change);
    }

    #[tokio::test]
    async fn the_preview_shows_defaults_it_stops_or_starts_borrowing() {
        let m = Mem::default();
        m.folder("shared", "Old", &["ops"], false);
        m.lend("shared", "Old", "rdp");
        m.folder("shared", "Old/Leaf", &[], true);
        m.folder("shared", "New", &["ops"], false);
        m.lend("shared", "New", "ssh");
        let tree = read_tree(&m, "shared", "Old/Leaf").await.unwrap();
        let p = preview(&m, &tree, "shared", "Old/Leaf", "shared", "New/Leaf")
            .await
            .unwrap();
        assert_eq!(
            p.defaults_before,
            vec![Lent {
                session_type: "rdp".into(),
                from: "Old".into()
            }]
        );
        assert_eq!(
            p.defaults_after,
            vec![Lent {
                session_type: "ssh".into(),
                from: "New".into()
            }]
        );
        assert!(p.defaults_change);
        assert!(!p.access_changes);

        // Its own defaults go with it and are not a change.
        let m2 = Mem::default();
        m2.folder("shared", "Old", &["ops"], false);
        m2.folder("shared", "Old/Leaf", &["x"], false);
        m2.lend("shared", "Old/Leaf", "vnc");
        let tree = read_tree(&m2, "shared", "Old/Leaf").await.unwrap();
        let p = preview(&m2, &tree, "shared", "Old/Leaf", "shared", "Leaf")
            .await
            .unwrap();
        assert!(!p.defaults_change && !p.access_changes);
    }

    #[tokio::test]
    async fn a_failed_copy_is_undone_and_the_source_is_untouched() {
        let m = sample();
        let before = m.keys("shared");
        m.fail_writes_under
            .lock()
            .unwrap()
            .insert("DevOps/Software/Build".into());
        let tree = read_tree(&m, "shared", "Engineering/Software")
            .await
            .unwrap();
        let err = execute(
            &m,
            &tree,
            "shared",
            "Engineering/Software",
            "shared",
            "DevOps/Software",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, MoveFailure::Copy { leftover: 0, .. }),
            "{err:?}"
        );
        assert_eq!(m.keys("shared"), before);
    }

    #[tokio::test]
    async fn an_entry_already_at_the_target_is_never_overwritten() {
        let m = sample();
        m.entry("shared", "DevOps/Software", "git01", "theirs");
        let tree = read_tree(&m, "shared", "Engineering/Software")
            .await
            .unwrap();
        let err = execute(
            &m,
            &tree,
            "shared",
            "Engineering/Software",
            "shared",
            "DevOps/Software",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, MoveFailure::Copy { .. }));
        let kept = m
            .get_entry("shared", "DevOps/Software", "git01")
            .await
            .unwrap();
        assert_eq!(kept.password.as_deref(), Some("theirs"));
        assert!(m
            .get_entry("shared", "Engineering/Software", "git01")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn a_source_that_will_not_go_is_reported_not_hidden() {
        let m = sample();
        m.fail_deletes.lock().unwrap().insert("ci01".into());
        let tree = read_tree(&m, "shared", "Engineering/Software")
            .await
            .unwrap();
        let err = execute(
            &m,
            &tree,
            "shared",
            "Engineering/Software",
            "shared",
            "DevOps/Software",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, MoveFailure::Incomplete { failed: 1, .. }),
            "{err:?}"
        );
        assert!(m
            .get_entry("shared", "DevOps/Software/Build", "ci01")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn across_scopes() {
        let m = sample();
        let tree = read_tree(&m, "shared", "Engineering/Software")
            .await
            .unwrap();
        assert!(!exists(&m, "instance", "Software").await.unwrap());
        execute(
            &m,
            &tree,
            "shared",
            "Engineering/Software",
            "instance",
            "Software",
        )
        .await
        .unwrap();
        assert_eq!(
            m.keys("instance"),
            vec![
                "Software/.config",
                "Software/Build/.config",
                "Software/Build/.defaults",
                "Software/Build/ci01",
                "Software/git01",
            ]
        );
        assert!(exists(&m, "instance", "Software").await.unwrap());
        assert!(!exists(&m, "shared", "Engineering/Software").await.unwrap());
    }
}
