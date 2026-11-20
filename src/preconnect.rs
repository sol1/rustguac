//! Pre-connect scripts (#329): an admin-provided executable that runs before
//! rustguac connects to a saved entry, for example to power on a VM through
//! a provider's API. The entry only names the script; scripts live in
//! `pre_connect_scripts_dir`, which only whoever edits the server's config
//! controls, so editing connections never lets anyone run a program of their
//! choosing.
//!
//! The script gets the connection's details (never its credentials) as JSON
//! on stdin and as `RUSTGUAC_*` environment variables, in an environment
//! cleared of rustguac's own (which holds secrets such as `VAULT_SECRET_ID`).
//! Exit status 0 lets the connection go ahead; anything else, or running past
//! `pre_connect_timeout_secs`, stops it with the last line the script wrote
//! to stderr.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// What a pre-connect script is told about the connection.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PreConnectInfo {
    pub scope: String,
    pub folder: String,
    pub entry: String,
    pub protocol: String,
    pub session_type: String,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    /// Who is connecting (their login, or the API key's name).
    pub user: String,
}

/// The port a session type connects to when the entry sets none, as
/// `SessionManager::create_session` fills it in. `None` for types without one
/// (web, VDI, Proxmox).
pub fn standard_port(session_type: &str) -> Option<u16> {
    match session_type {
        "ssh" => Some(22),
        "rdp" => Some(3389),
        "vnc" | "spice" => Some(5900),
        _ => None,
    }
}

/// A script name as an entry may give it: a plain file name, no path, not
/// hidden.
pub fn valid_script_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// The scripts an entry may name: the executable files in `dir`, sorted.
pub fn list_scripts(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_string();
            resolve(dir, &name).is_ok().then_some(name)
        })
        .collect();
    out.sort();
    out
}

/// The script's real path, inside `dir`, executable.
fn resolve(dir: &Path, name: &str) -> Result<PathBuf, String> {
    if !valid_script_name(name) {
        return Err(format!(
            "pre-connect script name {name:?} is not a plain file name"
        ));
    }
    let base = dir
        .canonicalize()
        .map_err(|_| format!("pre_connect_scripts_dir {} not found", dir.display()))?;
    let path = dir
        .join(name)
        .canonicalize()
        .map_err(|_| format!("pre-connect script {name:?} not found"))?;
    if !path.starts_with(&base) {
        return Err(format!(
            "pre-connect script {name:?} is outside the scripts directory"
        ));
    }
    if !is_executable(&path) {
        return Err(format!("pre-connect script {name:?} is not executable"));
    }
    Ok(path)
}

/// The last non-empty line of a script's stderr, trimmed and cut short, to
/// show the user why it stopped the connection.
fn last_line(stderr: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stderr);
    let line = text.lines().rev().map(str::trim).find(|l| !l.is_empty())?;
    let mut out: String = line.chars().filter(|c| !c.is_control()).take(200).collect();
    if line.chars().count() > 200 {
        out.push('…');
    }
    Some(out)
}

/// Run `name` from `dir` for `info`, waiting up to `timeout`. `Ok(())` when it
/// exits 0; otherwise why the connection should not go ahead.
pub async fn run(
    dir: &Path,
    name: &str,
    timeout: Duration,
    info: &PreConnectInfo,
) -> Result<(), String> {
    let path = resolve(dir, name)?;
    let input = serde_json::to_vec(info).unwrap_or_default();
    let mut cmd = Command::new(&path);
    cmd.env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("RUSTGUAC_SCOPE", &info.scope)
        .env("RUSTGUAC_FOLDER", &info.folder)
        .env("RUSTGUAC_ENTRY", &info.entry)
        .env("RUSTGUAC_PROTOCOL", &info.protocol)
        .env("RUSTGUAC_SESSION_TYPE", &info.session_type)
        .env("RUSTGUAC_HOSTNAME", info.hostname.as_deref().unwrap_or(""))
        .env(
            "RUSTGUAC_PORT",
            info.port.map(|p| p.to_string()).unwrap_or_default(),
        )
        .env("RUSTGUAC_USER", &info.user)
        .current_dir(path.parent().unwrap_or(dir))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        // Its own process group, so a timeout can stop what it started too.
        .process_group(0)
        .kill_on_drop(true);
    if let Ok(home) = std::env::var("HOME") {
        cmd.env("HOME", home);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("pre-connect script {name:?} could not start: {e}"))?;
    let pgid = child.id();
    if let Some(mut stdin) = child.stdin.take() {
        // A script that never reads stdin must not hold the connect up.
        let _ = stdin.write_all(&input).await;
    }
    tracing::info!(script = name, entry = %info.entry, user = %info.user, "Running pre-connect script");
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Err(_) => {
            if let Some(pgid) = pgid.and_then(|p| i32::try_from(p).ok()) {
                // SAFETY: signals only the process group the script leads.
                unsafe { libc::kill(-pgid, libc::SIGKILL) };
            }
            tracing::warn!(script = name, entry = %info.entry, "Pre-connect script timed out");
            Err(format!(
                "pre-connect script {name:?} did not finish within {}s",
                timeout.as_secs()
            ))
        }
        Ok(Err(e)) => Err(format!("pre-connect script {name:?} failed: {e}")),
        Ok(Ok(out)) if out.status.success() => {
            tracing::info!(script = name, entry = %info.entry, "Pre-connect script finished");
            Ok(())
        }
        Ok(Ok(out)) => {
            let why = last_line(&out.stderr);
            tracing::warn!(
                script = name,
                entry = %info.entry,
                status = %out.status,
                stderr = %String::from_utf8_lossy(&out.stderr).chars().take(2000).collect::<String>(),
                "Pre-connect script failed"
            );
            Err(match (out.status.code(), why) {
                (Some(code), Some(why)) => {
                    format!("pre-connect script {name:?} failed (exit {code}): {why}")
                }
                (Some(code), None) => format!("pre-connect script {name:?} failed (exit {code})"),
                (None, _) => format!("pre-connect script {name:?} was killed"),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn info() -> PreConnectInfo {
        PreConnectInfo {
            scope: "shared".into(),
            folder: "lab".into(),
            entry: "win11".into(),
            protocol: "rdp".into(),
            session_type: "rdp".into(),
            hostname: Some("10.0.0.5".into()),
            port: Some(3389),
            user: "alice@example.com".into(),
        }
    }

    fn script(dir: &Path, name: &str, body: &str) {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("rustguac-preconnect-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn an_unset_port_is_the_protocols_standard_one() {
        assert_eq!(standard_port("ssh"), Some(22));
        assert_eq!(standard_port("rdp"), Some(3389));
        assert_eq!(standard_port("vnc"), Some(5900));
        assert_eq!(standard_port("web"), None);
    }

    #[test]
    fn names_are_plain_file_names() {
        for ok in ["power-on.sh", "wake_vm", "pve.start.py"] {
            assert!(valid_script_name(ok), "{ok}");
        }
        for bad in ["", "../etc/passwd", "a/b", ".hidden", "with space", "x;rm"] {
            assert!(!valid_script_name(bad), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn exit_zero_goes_ahead_and_sees_the_details_but_not_our_environment() {
        let d = dir();
        let out = d.join("seen");
        // Writes what it was given; fails if a variable from rustguac's own
        // environment leaked through.
        script(
            &d,
            "ok.sh",
            &format!(
                "cat > {out}.json; echo \"$RUSTGUAC_HOSTNAME:$RUSTGUAC_PORT:$RUSTGUAC_USER\" > {out}.env; \
                 [ -z \"$RUSTGUAC_TEST_SECRET\" ] || exit 9",
                out = out.display()
            ),
        );
        std::env::set_var("RUSTGUAC_TEST_SECRET", "s3cret");
        run(&d, "ok.sh", Duration::from_secs(10), &info())
            .await
            .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(d.join("seen.json")).unwrap()).unwrap();
        assert_eq!(json["entry"], "win11");
        assert_eq!(json["port"], 3389);
        assert!(json.get("password").is_none());
        assert_eq!(
            std::fs::read_to_string(d.join("seen.env")).unwrap().trim(),
            "10.0.0.5:3389:alice@example.com"
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[tokio::test]
    async fn failure_timeout_and_bad_names_stop_the_connection() {
        let d = dir();
        script(
            &d,
            "fail.sh",
            "echo 'starting'; echo 'VM win11 not found' >&2; exit 3",
        );
        let err = run(&d, "fail.sh", Duration::from_secs(10), &info())
            .await
            .unwrap_err();
        assert!(
            err.contains("exit 3") && err.contains("VM win11 not found"),
            "{err}"
        );

        script(&d, "slow.sh", "sleep 30");
        let started = std::time::Instant::now();
        let err = run(&d, "slow.sh", Duration::from_millis(300), &info())
            .await
            .unwrap_err();
        assert!(err.contains("did not finish"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "killed, not waited for"
        );

        std::fs::write(d.join("plain.txt"), "not a script").unwrap();
        assert!(run(&d, "plain.txt", Duration::from_secs(1), &info())
            .await
            .unwrap_err()
            .contains("not executable"));
        assert!(run(&d, "missing.sh", Duration::from_secs(1), &info())
            .await
            .unwrap_err()
            .contains("not found"));
        assert!(run(&d, "../x", Duration::from_secs(1), &info())
            .await
            .unwrap_err()
            .contains("plain file name"));

        // A symlink out of the directory is refused.
        let outside = dir();
        script(&outside, "evil.sh", "exit 0");
        std::os::unix::fs::symlink(outside.join("evil.sh"), d.join("link.sh")).unwrap();
        assert!(run(&d, "link.sh", Duration::from_secs(1), &info())
            .await
            .unwrap_err()
            .contains("outside"));

        assert_eq!(list_scripts(&d), vec!["fail.sh", "slow.sh"]);
        std::fs::remove_dir_all(d).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }
}
