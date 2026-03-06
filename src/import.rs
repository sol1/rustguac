//! Import connections from an Apache Guacamole MySQL dump into the Vault address book.
//!
//! Parses `INSERT INTO` statements for `guacamole_connection`,
//! `guacamole_connection_parameter`, and `guacamole_connection_group` tables,
//! then writes entries via the existing VaultClient API.

use std::collections::HashMap;

use crate::config::Config;
use crate::vault::{AddressBookEntry, FolderConfig, VaultClient};

/// Run the import-guacamole subcommand.
pub async fn cmd_import_guacamole(
    config: &Config,
    file: &str,
    folder: &str,
    scope: &str,
    dry_run: bool,
) {
    // Validate scope
    if scope != "shared" && scope != "instance" {
        eprintln!("Error: --scope must be \"shared\" or \"instance\"");
        std::process::exit(1);
    }

    // Read SQL file
    let sql = match std::fs::read_to_string(file) {
        Ok(s) => s,
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

    // Build group name lookup: group_id → full path name (handles nesting)
    let group_names = build_group_paths(&groups);

    // Build entries
    let mut entries: Vec<(String, AddressBookEntry)> = Vec::new();
    let mut skipped = 0;

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
            username: param_map.get("username").map(|s| s.to_string()),
            password: param_map.get("password").map(|s| s.to_string()),
            private_key: param_map.get("private-key").map(|s| s.to_string()),
            url: None,
            domain: param_map.get("domain").map(|s| s.to_string()),
            security: param_map.get("security").map(|s| s.to_string()),
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
            login_script: None,
            autofill: None,
            allowed_domains: None,
            disable_copy: None,
            disable_paste: None,
        };

        // Build entry name: group prefix + sanitized connection name
        let group_prefix = conn
            .parent_id
            .and_then(|gid| group_names.get(&gid))
            .map(|g| format!("{}-", sanitize_name(g)))
            .unwrap_or_default();

        let raw_name = format!("{}{}", group_prefix, sanitize_name(&conn.name));
        entries.push((raw_name, entry));
    }

    // Deduplicate names
    deduplicate_names(&mut entries);

    println!(
        "Found {} connections ({} skipped, {} to import)",
        connections.len(),
        skipped,
        entries.len()
    );

    if dry_run {
        println!("\n[DRY RUN] Would import to folder \"{}\" (scope: {}):\n", folder, scope);
        for (name, entry) in &entries {
            println!(
                "  {} ({}) → {}:{}",
                name,
                entry.session_type,
                entry.hostname.as_deref().unwrap_or("?"),
                entry.port.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
            );
            if let Some(ref dn) = entry.display_name {
                if dn != name {
                    println!("    display_name: {}", dn);
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

    // Create folder (idempotent)
    let folder_config = FolderConfig {
        allowed_groups: vec![],
        description: "Imported from Guacamole".to_string(),
    };
    if let Err(e) = client.put_folder_config(scope, folder, &folder_config).await {
        eprintln!("Error creating folder \"{}\": {}", folder, e);
        std::process::exit(1);
    }

    // Write entries
    let mut success = 0;
    let mut failed = 0;
    for (name, entry) in &entries {
        match client.put_entry(scope, folder, name, entry).await {
            Ok(()) => {
                println!("  Imported: {}", name);
                success += 1;
            }
            Err(e) => {
                eprintln!("  Failed: {} — {}", name, e);
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

/// Parse `INSERT INTO `guacamole_connection`` rows.
/// Expected columns: (connection_id, connection_name, parent_id, protocol, ...)
fn parse_connections(sql: &str) -> Vec<Connection> {
    let mut results = Vec::new();
    for line in sql.lines() {
        let trimmed = line.trim();
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
    for line in sql.lines() {
        let trimmed = line.trim();
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
                results.entry(id).or_default().push((param_name, param_value));
            }
        }
    }
    results
}

/// Parse `INSERT INTO `guacamole_connection_group`` rows.
/// Expected columns: (connection_group_id, parent_id, connection_group_name, type, ...)
fn parse_groups(sql: &str) -> Vec<Group> {
    let mut results = Vec::new();
    for line in sql.lines() {
        let trimmed = line.trim();
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
            if in_quote {
                in_quote = false;
            } else {
                in_quote = true;
            }
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

/// Build a map of group_id → full path name (e.g. "Production-DMZ").
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
    let name = group.name.clone();
    match group.parent_id {
        Some(pid) if groups.contains_key(&pid) => {
            let parent_path = resolve_group_path(pid, groups, cache);
            let full = if parent_path.is_empty() {
                name
            } else {
                format!("{}-{}", parent_path, name)
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

/// Deduplicate entry names by appending -2, -3, etc.
fn deduplicate_names(entries: &mut [(String, AddressBookEntry)]) {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for i in 0..entries.len() {
        let name = entries[i].0.clone();
        let count = seen.entry(name.clone()).or_insert(0);
        *count += 1;
        if *count > 1 {
            let suffix = format!("-{}", count);
            // Ensure we don't exceed 64 chars with the suffix
            let max_base = 64 - suffix.len();
            let base = if name.len() > max_base {
                &name[..max_base]
            } else {
                &name
            };
            entries[i].0 = format!("{}{}", base, suffix);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let line = "INSERT INTO `guacamole_connection` VALUES (1,'web',NULL,'ssh'),(2,'db',1,'rdp');";
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
            hostname: None,
            port: None,
            username: None,
            password: None,
            private_key: None,
            url: None,
            domain: None,
            security: None,
            ignore_cert: None,
            display_name: None,
            enable_drive: None,
            auth_pkg: None,
            kdc_url: None,
            prompt_credentials: None,
            color_depth: None,
            jump_hosts: None,
            jump_host: None,
            jump_port: None,
            jump_username: None,
            jump_password: None,
            jump_private_key: None,
            remote_app: None,
            remote_app_dir: None,
            remote_app_args: None,
            enable_recording: None,
            max_recordings: None,
            login_script: None,
            autofill: None,
            allowed_domains: None,
            disable_copy: None,
            disable_paste: None,
        };
        let mut entries = vec![
            ("web".into(), entry()),
            ("web".into(), entry()),
            ("web".into(), entry()),
            ("db".into(), entry()),
        ];
        deduplicate_names(&mut entries);
        assert_eq!(entries[0].0, "web");
        assert_eq!(entries[1].0, "web-2");
        assert_eq!(entries[2].0, "web-3");
        assert_eq!(entries[3].0, "db");
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
            Group { id: 1, parent_id: None, name: "Production".into() },
            Group { id: 2, parent_id: Some(1), name: "DMZ".into() },
            Group { id: 3, parent_id: Some(2), name: "Web".into() },
        ];
        let paths = build_group_paths(&groups);
        assert_eq!(paths[&1], "Production");
        assert_eq!(paths[&2], "Production-DMZ");
        assert_eq!(paths[&3], "Production-DMZ-Web");
    }

    #[test]
    fn test_unescape_sql() {
        assert_eq!(unescape_sql("hello\\nworld"), "hello\nworld");
        assert_eq!(unescape_sql("it\\'s"), "it's");
        assert_eq!(unescape_sql("back\\\\slash"), "back\\slash");
    }
}
