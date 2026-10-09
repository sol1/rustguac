//! Import connections from an Apache Guacamole MySQL dump into the Vault address book.
//!
//! Parses `INSERT INTO` statements for `guacamole_connection`,
//! `guacamole_connection_parameter`, and `guacamole_connection_group` tables,
//! then writes entries via the existing VaultClient API.

use std::collections::HashMap;

use crate::config::Config;
use crate::vault::{AddressBookEntry, FolderConfig, VaultClient};

/// Parse `--map FROM=TO` pairs into (from, to) tuples. Splits on the first
/// `=`, so the replacement may itself contain `=`. Rejects entries with no
/// `=` or an empty FROM.
fn parse_credential_maps(raw: &[String]) -> Result<Vec<(String, String)>, String> {
    raw.iter()
        .map(|m| match m.split_once('=') {
            Some((from, to)) if !from.is_empty() => Ok((from.to_string(), to.to_string())),
            _ => Err(format!("--map must be FROM=TO (got \"{}\")", m)),
        })
        .collect()
}

/// Apply the parsed `--map` replacements to a single credential-field value,
/// in order. With no maps this is the identity.
fn apply_credential_maps(value: &str, maps: &[(String, String)]) -> String {
    let mut out = value.to_string();
    for (from, to) in maps {
        out = out.replace(from.as_str(), to.as_str());
    }
    out
}

/// Run the import-guacamole subcommand.
pub async fn cmd_import_guacamole(
    config: &Config,
    file: &str,
    folder: &str,
    scope: &str,
    allowed_groups: &[String],
    dry_run: bool,
    maps: &[String],
) {
    // Validate scope
    if scope != "shared" && scope != "instance" {
        eprintln!("Error: --scope must be \"shared\" or \"instance\"");
        std::process::exit(1);
    }

    // Parse --map FROM=TO pairs. These rewrite substrings in the credential
    // fields during import, e.g. mapping Apache Guacamole passthrough tokens
    // (${GUAC_USERNAME}) to rustguac credential variables ($corp_username).
    let cred_maps = match parse_credential_maps(maps) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    if !cred_maps.is_empty() {
        println!("Credential field maps:");
        for (from, to) in &cred_maps {
            println!("  {} -> {}", from, to);
        }
    }

    // Read SQL file (lossy: replace non-UTF-8 bytes from binary blobs)
    let sql = match std::fs::read(file) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) => {
            eprintln!("Error reading {}: {}", file, e);
            std::process::exit(1);
        }
    };

    // Parse the three tables
    let connections = parse_connections(&sql);
    let parameters = parse_parameters(&sql);
    let groups = parse_groups(&sql);

    if connections.is_empty() {
        eprintln!("No connections found in SQL dump.");
        eprintln!("Expected INSERT INTO `guacamole_connection` statements.");
        std::process::exit(1);
    }

    // Build group name lookup: group_id → sanitized subfolder path (e.g. "Production/DMZ").
    let group_paths = build_group_paths(&groups);

    // Build entries keyed by (subfolder_path, entry_name).
    // subfolder_path is relative to the target root folder; empty string means "at root".
    let mut entries: Vec<((String, String), AddressBookEntry)> = Vec::new();
    let mut skipped = 0;
    let mut mapped = 0;

    for conn in &connections {
        let protocol = conn.protocol.to_lowercase();
        if protocol != "ssh" && protocol != "rdp" && protocol != "vnc" {
            eprintln!(
                "  Skipping: {} (unsupported protocol: {})",
                conn.name, conn.protocol
            );
            skipped += 1;
            continue;
        }

        let params = parameters.get(&conn.id).cloned().unwrap_or_default();
        let param_map: HashMap<&str, &str> = params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let entry = AddressBookEntry {
            session_type: protocol,
            hostname: param_map.get("hostname").map(|s| s.to_string()),
            port: param_map.get("port").and_then(|s| s.parse().ok()),
            username: param_map
                .get("username")
                .map(|s| apply_credential_maps(s, &cred_maps)),
            password: param_map
                .get("password")
                .map(|s| apply_credential_maps(s, &cred_maps)),
            private_key: param_map
                .get("private-key")
                .map(|s| apply_credential_maps(s, &cred_maps)),
            url: None,
            domain: param_map
                .get("domain")
                .map(|s| apply_credential_maps(s, &cred_maps)),
            security: param_map.get("security").map(|s| s.to_string()),
            server_layout: param_map.get("server-layout").map(|s| s.to_string()),
            ignore_cert: param_map
                .get("ignore-cert")
                .map(|s| s.eq_ignore_ascii_case("true")),
            display_name: Some(conn.name.clone()),
            enable_drive: param_map
                .get("enable-drive")
                .map(|s| s.eq_ignore_ascii_case("true")),
            auth_pkg: None,
            kdc_url: None,
            prompt_credentials: None,
            color_depth: param_map.get("color-depth").and_then(|s| s.parse().ok()),
            jump_hosts: None,
            jump_host: None,
            jump_port: None,
            jump_username: None,
            jump_password: None,
            jump_private_key: None,
            remote_app: param_map.get("remote-app").map(|s| s.to_string()),
            remote_app_dir: param_map.get("remote-app-dir").map(|s| s.to_string()),
            remote_app_args: param_map.get("remote-app-args").map(|s| s.to_string()),
            enable_recording: None,
            max_recordings: None,
            record_typescript: None,
            login_script: None,
            autofill: None,
            allowed_domains: None,
            disable_copy: None,
            disable_paste: None,
            banner: None,
            enable_gfx: None,
            enable_desktop_composition: None,
            enable_wallpaper: None,
            enable_theming: None,
            enable_full_window_drag: None,
            force_lossless: None,
            enable_h264: None,
            h264_chroma444: None,
            native_resolution: None,
            container_image: None,
            container_cpu_limit: None,
            container_memory_limit: None,
            container_env: None,
            container_username: None,
            container_password: None,
            container_idle_timeout_mins: None,
            allow_sharing: None,
            auto_open_if_singleton: None,
            fullscreen_on_connect: None,
            autohide_side_tabs: None,
            spice_tls: None,
            spice_tls_port: None,
            spice_ca_cert: None,
            spice_cert_subject: None,
            spice_proxy: None,
            proxmox_url: None,
            proxmox_node: None,
            proxmox_vmid: None,
            proxmox_token_id: None,
            proxmox_token_secret: None,
            proxmox_verify_tls: None,
            max_monitors: None,
            ssh_font_size: param_map.get("font-size").and_then(|s| s.parse().ok()),
            wol_send_packet: param_map
                .get("wol-send-packet")
                .map(|s| s.eq_ignore_ascii_case("true")),
            wol_mac_addr: param_map.get("wol-mac-addr").map(|s| s.to_string()),
            wol_broadcast_addr: param_map.get("wol-broadcast-addr").map(|s| s.to_string()),
            wol_udp_port: param_map.get("wol-udp-port").and_then(|s| s.parse().ok()),
            wol_wait_time: param_map.get("wol-wait-time").and_then(|s| s.parse().ok()),
        };

        if !cred_maps.is_empty()
            && ["username", "password", "private-key", "domain"]
                .iter()
                .any(|k| {
                    param_map.get(k).is_some_and(|v| {
                        cred_maps.iter().any(|(from, _)| v.contains(from.as_str()))
                    })
                })
        {
            mapped += 1;
        }

        // Place the entry into a subfolder matching its parent group path.
        // Connections with no parent group land at the root of the target folder.
        let subfolder = conn
            .parent_id
            .and_then(|gid| group_paths.get(&gid))
            .cloned()
            .unwrap_or_default();
        let entry_name = sanitize_name(&conn.name);
        entries.push(((subfolder, entry_name), entry));
    }

    // Deduplicate entry names within each subfolder.
    deduplicate_names(&mut entries);

    println!(
        "Found {} connections ({} skipped, {} to import)",
        connections.len(),
        skipped,
        entries.len()
    );
    if !cred_maps.is_empty() {
        println!(
            "Applied credential maps to {} of {} imported entries.",
            mapped,
            entries.len()
        );
    }

    if dry_run {
        println!(
            "\n[DRY RUN] Would import under folder \"{}\" (scope: {}):\n",
            folder, scope
        );
        for ((subfolder, name), entry) in &entries {
            let full = if subfolder.is_empty() {
                format!("{}/{}", folder, name)
            } else {
                format!("{}/{}/{}", folder, subfolder, name)
            };
            println!(
                "  {} ({}) → {}:{}",
                full,
                entry.session_type,
                entry.hostname.as_deref().unwrap_or("?"),
                entry
                    .port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "?".into()),
            );
            if let Some(ref dn) = entry.display_name {
                if dn != name {
                    println!("    display_name: {}", dn);
                }
            }
            // Show the username when it resolves to a credential variable, so a
            // --map run can be verified. Passwords/keys are never printed.
            if let Some(u) = &entry.username {
                if u.starts_with('$') {
                    println!("    username: {}", u);
                }
            }
        }
        println!("\nRe-run without --dry-run to import.");
        return;
    }

    // Connect to Vault
    let vault_config = match config.vault {
        Some(ref vc) => vc,
        None => {
            eprintln!("Error: [vault] section required in config for import");
            std::process::exit(1);
        }
    };

    let secret_id = match std::env::var("VAULT_SECRET_ID") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            eprintln!("Error: VAULT_SECRET_ID env var required");
            std::process::exit(1);
        }
    };

    let client = match VaultClient::new(vault_config, &secret_id).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error connecting to Vault: {}", e);
            std::process::exit(1);
        }
    };

    // Create the root folder (idempotent). The root carries the ACL chosen
    // by --allowed-groups; subfolders default to inherit_from_parent=true so
    // the whole imported tree picks up the same access rules without having
    // to write identical allowed_groups on every child.
    let root_config = FolderConfig {
        allowed_groups: allowed_groups.to_vec(),
        allowed_users: Vec::new(),
        description: "Imported from Guacamole".to_string(),
        inherit_from_parent: false,
    };
    if let Err(e) = client.put_folder_config(scope, folder, &root_config).await {
        eprintln!("Error creating folder \"{}\": {}", folder, e);
        std::process::exit(1);
    }

    // Create a .config for every subfolder used by any entry (including intermediate
    // ancestors, so an empty parent still shows up in the tree with a description).
    // Deduplicate before writing so we don't hit Vault N times for the same path.
    let mut subfolder_paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for ((subfolder, _), _) in &entries {
        if subfolder.is_empty() {
            continue;
        }
        let mut acc = String::new();
        for seg in subfolder.split('/') {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(seg);
            subfolder_paths.insert(acc.clone());
        }
    }
    for sub in &subfolder_paths {
        let full = format!("{}/{}", folder, sub);
        let cfg = FolderConfig {
            allowed_groups: vec![],
            allowed_users: Vec::new(),
            description: format!("Imported from Guacamole: {}", sub),
            inherit_from_parent: true,
        };
        if let Err(e) = client.put_folder_config(scope, &full, &cfg).await {
            eprintln!("  Warning: failed to create subfolder \"{}\": {}", full, e);
        }
    }

    // Write entries into their respective subfolders.
    let mut success = 0;
    let mut failed = 0;
    for ((subfolder, name), entry) in &entries {
        let target_folder = if subfolder.is_empty() {
            folder.to_string()
        } else {
            format!("{}/{}", folder, subfolder)
        };
        match client.put_entry(scope, &target_folder, name, entry).await {
            Ok(()) => {
                println!("  Imported: {}/{}", target_folder, name);
                success += 1;
            }
            Err(e) => {
                eprintln!("  Failed: {}/{} — {}", target_folder, name, e);
                failed += 1;
            }
        }
    }

    println!("\nDone: {} imported, {} failed.", success, failed);
}

// ── SQL parsing ──

struct Connection {
    id: i64,
    name: String,
    parent_id: Option<i64>,
    protocol: String,
}

struct Group {
    id: i64,
    parent_id: Option<i64>,
    name: String,
}

/// Split a SQL dump into individual statements on top-level (unquoted)
/// semicolons.
///
/// mysqldump / mariadb-dump emit multi-row INSERTs with the `VALUES` keyword on
/// one line and each row tuple on its own subsequent line, so a line-by-line
/// scan never sees a tuple attached to its `INSERT INTO`. Reconstructing whole
/// statements first fixes that. String literals (`'...'`, with backslash
/// escapes), backtick identifiers, and `--` / `#` / `/* */` comments are
/// skipped so their contents (semicolons, apostrophes) can neither split a
/// statement early nor corrupt quote tracking.
fn split_statements(sql: &str) -> Vec<String> {
    let chars: Vec<char> = sql.chars().collect();
    let n = chars.len();
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut i = 0;
    let mut in_quote = false; // inside a '...' string literal
    let mut in_ident = false; // inside a `...` backtick identifier

    while i < n {
        let ch = chars[i];

        if in_quote {
            current.push(ch);
            if ch == '\\' && i + 1 < n {
                // Preserve the escaped char verbatim; unescape_sql decodes later.
                current.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if ch == '\'' {
                in_quote = false;
            }
            i += 1;
            continue;
        }
        if in_ident {
            current.push(ch);
            if ch == '`' {
                in_ident = false;
            }
            i += 1;
            continue;
        }

        // Line comment: `#` or `-- ` (dash-dash followed by whitespace/EOL).
        if ch == '#' {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if ch == '-' && i + 1 < n && chars[i + 1] == '-' {
            let after = chars.get(i + 2).copied();
            if matches!(
                after,
                None | Some(' ') | Some('\t') | Some('\r') | Some('\n')
            ) {
                while i < n && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
        }
        // Block comment: `/* ... */` (includes MySQL `/*! ... */` executable
        // comments — none of the tables we import live inside one).
        if ch == '/' && i + 1 < n && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < n && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(n); // consume the closing */
            continue;
        }

        match ch {
            '\'' => {
                in_quote = true;
                current.push(ch);
            }
            '`' => {
                in_ident = true;
                current.push(ch);
            }
            ';' => {
                if !current.trim().is_empty() {
                    statements.push(current.clone());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
        i += 1;
    }
    if !current.trim().is_empty() {
        statements.push(current);
    }
    statements
}

/// Parse `INSERT INTO `guacamole_connection`` rows.
/// Expected columns: (connection_id, connection_name, parent_id, protocol, ...)
fn parse_connections(sql: &str) -> Vec<Connection> {
    let mut results = Vec::new();
    for stmt in split_statements(sql) {
        let trimmed = stmt.trim();
        if !matches_insert(trimmed, "guacamole_connection")
            || matches_insert(trimmed, "guacamole_connection_parameter")
            || matches_insert(trimmed, "guacamole_connection_group")
        {
            continue;
        }
        for tuple in extract_tuples(trimmed) {
            let vals = parse_tuple(&tuple);
            if vals.len() >= 4 {
                let id = match vals[0].parse::<i64>() {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let name = unescape_sql(&vals[1]);
                let parent_id = parse_nullable_int(&vals[2]);
                let protocol = unescape_sql(&vals[3]);
                results.push(Connection {
                    id,
                    name,
                    parent_id,
                    protocol,
                });
            }
        }
    }
    results
}

/// Parse `INSERT INTO `guacamole_connection_parameter`` rows.
/// Expected columns: (connection_id, parameter_name, parameter_value)
fn parse_parameters(sql: &str) -> HashMap<i64, Vec<(String, String)>> {
    let mut results: HashMap<i64, Vec<(String, String)>> = HashMap::new();
    for stmt in split_statements(sql) {
        let trimmed = stmt.trim();
        if !matches_insert(trimmed, "guacamole_connection_parameter") {
            continue;
        }
        for tuple in extract_tuples(trimmed) {
            let vals = parse_tuple(&tuple);
            if vals.len() >= 3 {
                let id = match vals[0].parse::<i64>() {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let param_name = unescape_sql(&vals[1]);
                let param_value = unescape_sql(&vals[2]);
                results
                    .entry(id)
                    .or_default()
                    .push((param_name, param_value));
            }
        }
    }
    results
}

/// Parse `INSERT INTO `guacamole_connection_group`` rows.
/// Expected columns: (connection_group_id, parent_id, connection_group_name, type, ...)
fn parse_groups(sql: &str) -> Vec<Group> {
    let mut results = Vec::new();
    for stmt in split_statements(sql) {
        let trimmed = stmt.trim();
        if !matches_insert(trimmed, "guacamole_connection_group") {
            continue;
        }
        for tuple in extract_tuples(trimmed) {
            let vals = parse_tuple(&tuple);
            if vals.len() >= 3 {
                let id = match vals[0].parse::<i64>() {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let parent_id = parse_nullable_int(&vals[1]);
                let name = unescape_sql(&vals[2]);
                results.push(Group {
                    id,
                    parent_id,
                    name,
                });
            }
        }
    }
    results
}

/// Check if a line is an INSERT INTO for the given table.
fn matches_insert(line: &str, table: &str) -> bool {
    let upper = line.to_uppercase();
    // Match both backtick-quoted and unquoted table names
    upper.contains("INSERT INTO")
        && (line.contains(&format!("`{}`", table))
            || upper.contains(&format!(" {} ", table.to_uppercase()))
            || upper.contains(&format!(" {}(", table.to_uppercase())))
}

/// Extract value tuples from an INSERT statement.
/// `INSERT INTO t VALUES (a,b),(c,d);` → ["a,b", "c,d"]
fn extract_tuples(line: &str) -> Vec<String> {
    let mut results = Vec::new();
    // Find VALUES keyword
    let upper = line.to_uppercase();
    let values_pos = match upper.find("VALUES") {
        Some(p) => p + 6,
        None => return results,
    };
    let rest = &line[values_pos..];

    let mut depth = 0;
    let mut in_quote = false;
    let mut escape = false;
    let mut start = None;

    for (i, ch) in rest.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' && in_quote {
            escape = true;
            continue;
        }
        if ch == '\'' {
            in_quote = !in_quote;
            continue;
        }
        if in_quote {
            continue;
        }
        if ch == '(' {
            depth += 1;
            if depth == 1 {
                start = Some(i + 1);
            }
        } else if ch == ')' {
            depth -= 1;
            if depth == 0 {
                if let Some(s) = start {
                    results.push(rest[s..i].to_string());
                }
                start = None;
            }
        }
    }
    results
}

/// Parse a single tuple's comma-separated values, respecting quoted strings.
/// Returns raw values with surrounding quotes stripped but internal escapes intact.
fn parse_tuple(tuple: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut escape = false;

    for ch in tuple.chars() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }
        if ch == '\\' && in_quote {
            escape = true;
            // Don't push the backslash — unescape_sql handles the value
            current.push(ch);
            continue;
        }
        if ch == '\'' {
            in_quote = !in_quote;
            continue; // strip quotes
        }
        if ch == ',' && !in_quote {
            values.push(current.trim().to_string());
            current = String::new();
            continue;
        }
        current.push(ch);
    }
    values.push(current.trim().to_string());
    values
}

/// Unescape MySQL string escapes: \\ → \, \' → ', \n → newline, etc.
fn unescape_sql(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('0') => result.push('\0'),
                Some(c) => result.push(c), // \\ → \, \' → ', etc.
                None => result.push('\\'),
            }
        } else {
            result.push(ch);
        }
    }
    result
}

fn parse_nullable_int(s: &str) -> Option<i64> {
    if s.eq_ignore_ascii_case("NULL") {
        None
    } else {
        s.parse().ok()
    }
}

// ── Group path building ──

/// Build a map of group_id → sanitized subfolder path (e.g. "Production/DMZ").
/// Each segment is sanitized individually so the path is valid for Vault (each
/// slash-delimited segment must satisfy `validate_name`).
fn build_group_paths(groups: &[Group]) -> HashMap<i64, String> {
    let group_map: HashMap<i64, &Group> = groups.iter().map(|g| (g.id, g)).collect();
    let mut paths = HashMap::new();

    for g in groups {
        if paths.contains_key(&g.id) {
            continue;
        }
        let path = resolve_group_path(g.id, &group_map, &mut paths);
        paths.insert(g.id, path);
    }
    paths
}

fn resolve_group_path(
    id: i64,
    groups: &HashMap<i64, &Group>,
    cache: &mut HashMap<i64, String>,
) -> String {
    if let Some(cached) = cache.get(&id) {
        return cached.clone();
    }
    let group = match groups.get(&id) {
        Some(g) => g,
        None => return String::new(),
    };
    let name = sanitize_name(&group.name);
    match group.parent_id {
        Some(pid) if groups.contains_key(&pid) => {
            let parent_path = resolve_group_path(pid, groups, cache);
            let full = if parent_path.is_empty() {
                name
            } else {
                format!("{}/{}", parent_path, name)
            };
            cache.insert(id, full.clone());
            full
        }
        _ => {
            cache.insert(id, name.clone());
            name
        }
    }
}

// ── Name sanitization ──

/// Sanitize a name for Vault: replace spaces with hyphens, strip invalid chars, truncate to 64.
fn sanitize_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c == ' ' {
                '-'
            } else if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                // skip
                '\0'
            }
        })
        .filter(|&c| c != '\0')
        .collect();

    // Truncate to 64 chars
    let truncated = if sanitized.len() > 64 {
        sanitized[..64].to_string()
    } else {
        sanitized
    };

    if truncated.is_empty() {
        "unnamed".to_string()
    } else {
        truncated
    }
}

/// Deduplicate entry names per-subfolder by appending -2, -3, etc.
/// Two entries with the same name in different subfolders do not collide.
fn deduplicate_names(entries: &mut [((String, String), AddressBookEntry)]) {
    let mut seen: HashMap<(String, String), usize> = HashMap::new();
    for ((subfolder, name), _) in entries.iter_mut() {
        let key = (subfolder.clone(), name.clone());
        let count = seen.entry(key).or_insert(0);
        *count += 1;
        if *count > 1 {
            let suffix = format!("-{}", count);
            let max_base = 64 - suffix.len();
            let base = if name.len() > max_base {
                &name[..max_base]
            } else {
                name.as_str()
            };
            *name = format!("{}{}", base, suffix);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_maps_parse_and_apply() {
        let maps = parse_credential_maps(&[
            "${GUAC_USERNAME}=$corp_username".to_string(),
            "${GUAC_PASSWORD}=$corp_password".to_string(),
        ])
        .unwrap();
        assert_eq!(maps.len(), 2);
        assert_eq!(
            apply_credential_maps("${GUAC_USERNAME}", &maps),
            "$corp_username"
        );
        assert_eq!(
            apply_credential_maps("${GUAC_PASSWORD}", &maps),
            "$corp_password"
        );
        // Non-matching values pass through untouched.
        assert_eq!(apply_credential_maps("admin", &maps), "admin");
        // A token embedded in a larger value is rewritten in place.
        assert_eq!(
            apply_credential_maps("EXAMPLE\\${GUAC_USERNAME}", &maps),
            "EXAMPLE\\$corp_username"
        );
    }

    #[test]
    fn credential_maps_reject_malformed() {
        assert!(parse_credential_maps(&["noequalsign".to_string()]).is_err());
        assert!(parse_credential_maps(&["=missingfrom".to_string()]).is_err());
    }

    #[test]
    fn credential_maps_empty_is_identity() {
        let maps = parse_credential_maps(&[]).unwrap();
        assert!(maps.is_empty());
        assert_eq!(
            apply_credential_maps("${GUAC_USERNAME}", &maps),
            "${GUAC_USERNAME}"
        );
    }

    #[test]
    fn test_sanitize_name() {
        assert_eq!(sanitize_name("My Server (prod) #1"), "My-Server-prod-1");
        assert_eq!(sanitize_name("simple"), "simple");
        assert_eq!(sanitize_name("a/b\\c"), "abc");
        assert_eq!(sanitize_name(""), "unnamed");
        assert_eq!(sanitize_name("###"), "unnamed");
    }

    #[test]
    fn test_parse_tuple() {
        let vals = parse_tuple("1,'web-server','ssh'");
        assert_eq!(vals, vec!["1", "web-server", "ssh"]);
    }

    #[test]
    fn test_parse_tuple_with_null() {
        let vals = parse_tuple("1,'test',NULL,'rdp'");
        assert_eq!(vals, vec!["1", "test", "NULL", "rdp"]);
    }

    #[test]
    fn test_parse_tuple_escaped_quote() {
        let vals = parse_tuple("1,'it\\'s a test','ssh'");
        assert_eq!(vals, vec!["1", "it\\'s a test", "ssh"]);
        assert_eq!(unescape_sql(&vals[1]), "it's a test");
    }

    #[test]
    fn test_extract_tuples() {
        let line =
            "INSERT INTO `guacamole_connection` VALUES (1,'web',NULL,'ssh'),(2,'db',1,'rdp');";
        let tuples = extract_tuples(line);
        assert_eq!(tuples.len(), 2);
        assert_eq!(tuples[0], "1,'web',NULL,'ssh'");
        assert_eq!(tuples[1], "2,'db',1,'rdp'");
    }

    #[test]
    fn test_matches_insert() {
        assert!(matches_insert(
            "INSERT INTO `guacamole_connection` VALUES",
            "guacamole_connection"
        ));
        assert!(!matches_insert(
            "INSERT INTO `guacamole_connection_parameter` VALUES",
            "guacamole_connection"
        ));
        assert!(matches_insert(
            "INSERT INTO `guacamole_connection_parameter` VALUES",
            "guacamole_connection_parameter"
        ));
    }

    #[test]
    fn test_deduplicate_names() {
        let entry = || AddressBookEntry {
            session_type: "ssh".into(),
            ..Default::default()
        };
        let mut entries = vec![
            (("".into(), "web".into()), entry()),
            (("".into(), "web".into()), entry()),
            (("".into(), "web".into()), entry()),
            (("".into(), "db".into()), entry()),
            // Same name in a different subfolder must NOT be renamed.
            (("Prod".into(), "web".into()), entry()),
            (("Prod".into(), "web".into()), entry()),
        ];
        deduplicate_names(&mut entries);
        assert_eq!(entries[0].0 .1, "web");
        assert_eq!(entries[1].0 .1, "web-2");
        assert_eq!(entries[2].0 .1, "web-3");
        assert_eq!(entries[3].0 .1, "db");
        assert_eq!(entries[4].0 .1, "web");
        assert_eq!(entries[5].0 .1, "web-2");
    }

    #[test]
    fn test_parse_connections() {
        let sql = "INSERT INTO `guacamole_connection` VALUES (1,'Web Server',NULL,'ssh',NULL,NULL,NULL,0,NULL,NULL,NULL);";
        let conns = parse_connections(sql);
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].id, 1);
        assert_eq!(conns[0].name, "Web Server");
        assert!(conns[0].parent_id.is_none());
        assert_eq!(conns[0].protocol, "ssh");
    }

    #[test]
    fn test_parse_parameters() {
        let sql = "INSERT INTO `guacamole_connection_parameter` VALUES (1,'hostname','10.0.0.1'),(1,'port','22'),(1,'username','admin');";
        let params = parse_parameters(sql);
        let p = params.get(&1).unwrap();
        assert_eq!(p.len(), 3);
        assert!(p.contains(&("hostname".into(), "10.0.0.1".into())));
        assert!(p.contains(&("port".into(), "22".into())));
    }

    #[test]
    fn test_parse_groups() {
        let sql = "INSERT INTO `guacamole_connection_group` VALUES (1,NULL,'Production','ORGANIZATIONAL',NULL,NULL,NULL);";
        let groups = parse_groups(sql);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, 1);
        assert!(groups[0].parent_id.is_none());
        assert_eq!(groups[0].name, "Production");
    }

    #[test]
    fn test_group_path_nesting() {
        let groups = vec![
            Group {
                id: 1,
                parent_id: None,
                name: "Production".into(),
            },
            Group {
                id: 2,
                parent_id: Some(1),
                name: "DMZ".into(),
            },
            Group {
                id: 3,
                parent_id: Some(2),
                name: "Web".into(),
            },
        ];
        let paths = build_group_paths(&groups);
        assert_eq!(paths[&1], "Production");
        assert_eq!(paths[&2], "Production/DMZ");
        assert_eq!(paths[&3], "Production/DMZ/Web");
    }

    #[test]
    fn test_group_path_sanitizes_segments() {
        // Group names with spaces/punctuation must be sanitized *per segment*
        // so the resulting path is accepted by Vault's validate_path.
        let groups = vec![
            Group {
                id: 1,
                parent_id: None,
                name: "Client (Acme)".into(),
            },
            Group {
                id: 2,
                parent_id: Some(1),
                name: "Prod DMZ".into(),
            },
        ];
        let paths = build_group_paths(&groups);
        assert_eq!(paths[&1], "Client-Acme");
        assert_eq!(paths[&2], "Client-Acme/Prod-DMZ");
    }

    #[test]
    fn test_unescape_sql() {
        assert_eq!(unescape_sql("hello\\nworld"), "hello\nworld");
        assert_eq!(unescape_sql("it\\'s"), "it's");
        assert_eq!(unescape_sql("back\\\\slash"), "back\\slash");
    }

    #[test]
    fn test_split_statements_basic() {
        let sql = "CREATE TABLE `t` (`a` int);\nINSERT INTO `t` VALUES (1),(2);\n";
        let stmts = split_statements(sql);
        assert_eq!(stmts.len(), 2);
        assert!(stmts[1].contains("INSERT INTO `t` VALUES (1),(2)"));
    }

    #[test]
    fn test_split_statements_skips_comments_and_semicolons_in_strings() {
        // `--` and `/*! */` comments (each ending in `;`) must not become
        // statements, and a `;` inside a quoted value must not split.
        let sql = "-- a comment; with a semicolon\n\
                   /*!40101 SET NAMES utf8mb4 */;\n\
                   INSERT INTO `t` VALUES (1,'a;b');\n";
        let stmts = split_statements(sql);
        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].contains("INSERT INTO `t` VALUES (1,'a;b')"));
    }

    #[test]
    fn test_split_statements_comment_apostrophe_does_not_corrupt() {
        // A stray apostrophe inside a `--` comment must not open a string that
        // swallows the following INSERT.
        let sql = "-- it's a dump\nINSERT INTO `t` VALUES (1,'ok');\n";
        let stmts = split_statements(sql);
        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].contains("(1,'ok')"));
    }

    #[test]
    fn test_parse_connections_multiline_dump() {
        // mariadb-dump format: VALUES on its own line, one tuple per line,
        // trailing `;` after the last tuple. This is the format that regressed.
        let sql = "INSERT INTO `guacamole_connection` VALUES\n\
                   (1,'web-server',1,'ssh',NULL,NULL,NULL,0,0,NULL,0),\n\
                   (3,'app-desktop',3,'rdp',NULL,NULL,NULL,NULL,NULL,NULL,0),\n\
                   (8,'db-shell',4,'ssh',NULL,NULL,NULL,16,16,NULL,0);\n";
        let conns = parse_connections(sql);
        assert_eq!(conns.len(), 3);
        assert_eq!(conns[0].id, 1);
        assert_eq!(conns[0].name, "web-server");
        assert_eq!(conns[0].parent_id, Some(1));
        assert_eq!(conns[1].protocol, "rdp");
        assert_eq!(conns[2].parent_id, Some(4));
    }

    #[test]
    fn test_parse_parameters_multiline_with_semicolons_in_value() {
        // The `color-scheme` value contains both `;` and escaped `\n`; neither
        // may break tuple extraction across the multi-line INSERT.
        let sql = "INSERT INTO `guacamole_connection_parameter` VALUES\n\
                   (2,'color-scheme','fg: rgb:11/22/33;\\nbg: rgb:44/55/66;'),\n\
                   (2,'hostname','192.0.2.10'),\n\
                   (2,'port','22');\n";
        let params = parse_parameters(sql);
        let p = params.get(&2).unwrap();
        assert_eq!(p.len(), 3);
        assert!(p.contains(&("hostname".into(), "192.0.2.10".into())));
        assert!(p.contains(&("port".into(), "22".into())));
        let scheme = &p.iter().find(|(k, _)| k == "color-scheme").unwrap().1;
        assert!(scheme.contains("fg: rgb:11/22/33;"));
        assert!(scheme.contains('\n')); // \n was unescaped to a real newline
    }

    #[test]
    fn test_parse_groups_multiline_dump() {
        let sql = "INSERT INTO `guacamole_connection_group` VALUES\n\
                   (1,NULL,'Production','ORGANIZATIONAL',NULL,NULL,0),\n\
                   (4,NULL,'Staging','ORGANIZATIONAL',12,6,0);\n";
        let groups = parse_groups(sql);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].name, "Production");
        assert_eq!(groups[1].id, 4);
        assert_eq!(groups[1].name, "Staging");
    }
}
