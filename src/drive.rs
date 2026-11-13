//! Drive / file transfer support.
//!
//! Manages per-session drive directories for RDP (guacd drive redirection)
//! and optional LUKS encryption with Vault-managed keys.

use crate::config::DriveConfig;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug)]
pub enum DriveError {
    Io(String),
    Luks(String),
    Vault(String),
}

impl std::fmt::Display for DriveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "drive I/O error: {}", msg),
            Self::Luks(msg) => write!(f, "LUKS error: {}", msg),
            Self::Vault(msg) => write!(f, "vault error: {}", msg),
        }
    }
}

impl std::error::Error for DriveError {}

/// Check whether drive is enabled in the config, optionally overridden per-entry.
pub fn is_drive_enabled(config: &Option<DriveConfig>, override_enabled: Option<bool>) -> bool {
    match override_enabled {
        Some(v) => v,
        None => config.as_ref().is_some_and(|d| d.enabled),
    }
}

/// Get the drive config, returning the default if not configured.
pub fn drive_config_or_default(config: &Option<DriveConfig>) -> DriveConfig {
    config.clone().unwrap_or_default()
}

/// Create the base drive directory on startup and clean up any orphaned
/// session directories left over from a previous run.
pub fn ensure_base_dir(config: &DriveConfig) -> Result<(), DriveError> {
    std::fs::create_dir_all(&config.drive_path).map_err(|e| {
        DriveError::Io(format!(
            "failed to create drive base directory {:?}: {}",
            config.drive_path, e
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ =
            std::fs::set_permissions(&config.drive_path, std::fs::Permissions::from_mode(0o750));
    }

    // Clean up orphaned session directories from previous runs.
    // Session dirs are named by UUID, so we can identify them by pattern.
    if config.cleanup_on_close {
        match std::fs::read_dir(&config.drive_path) {
            Ok(entries) => {
                let mut cleaned = 0u32;
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    // Session dirs are UUIDs (36 chars with hyphens)
                    if Uuid::parse_str(&name_str).is_ok() {
                        if let Err(e) = std::fs::remove_dir_all(entry.path()) {
                            tracing::warn!(
                                "Failed to clean up orphaned drive dir {:?}: {}",
                                entry.path(),
                                e
                            );
                        } else {
                            cleaned += 1;
                        }
                    }
                }
                if cleaned > 0 {
                    tracing::info!("Cleaned up {} orphaned session drive directories", cleaned);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to read drive directory for cleanup: {}", e);
            }
        }
    }

    Ok(())
}

/// Create a per-session drive directory. Returns the canonicalized absolute path.
///
/// The path is canonicalized so that guacd (which runs as a separate process
/// with a different working directory) resolves it correctly.
pub fn create_session_dir(config: &DriveConfig, session_id: Uuid) -> Result<PathBuf, DriveError> {
    let dir = config.drive_path.join(session_id.to_string());
    std::fs::create_dir_all(&dir).map_err(|e| {
        DriveError::Io(format!(
            "failed to create session drive directory {:?}: {}",
            dir, e
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)) {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(DriveError::Io(format!(
                "failed to set permissions on session drive directory {:?}: {}",
                dir, e
            )));
        }
    }
    // Canonicalize to absolute path — guacd runs as a separate systemd service
    // with a different WorkingDirectory, so relative paths won't resolve correctly.
    let abs_dir = std::fs::canonicalize(&dir).map_err(|e| {
        DriveError::Io(format!(
            "failed to canonicalize session drive directory {:?}: {}",
            dir, e
        ))
    })?;
    tracing::info!(session_id = %session_id, "Created session drive directory: {:?}", abs_dir);
    Ok(abs_dir)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn session_drive_directory_has_restricted_permissions() {
        let base = std::env::temp_dir().join(format!("rustguac-drive-test-{}", Uuid::new_v4()));
        let config = DriveConfig {
            drive_path: base.clone(),
            ..DriveConfig::default()
        };

        let path = create_session_dir(&config, Uuid::new_v4()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750);

        std::fs::remove_dir_all(base).unwrap();
    }
}

/// Clean up a session drive directory, optionally with a retention delay.
pub async fn cleanup_session_dir(path: PathBuf, session_id: Uuid, retention_secs: u64) {
    if retention_secs == 0 {
        do_cleanup(&path, session_id).await;
    } else {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(retention_secs)).await;
            do_cleanup(&path, session_id).await;
        });
    }
}

async fn do_cleanup(path: &Path, session_id: Uuid) {
    match tokio::fs::remove_dir_all(path).await {
        Ok(_) => tracing::info!(session_id = %session_id, "Cleaned up session drive directory"),
        Err(e) => {
            tracing::warn!(session_id = %session_id, "Failed to clean up drive directory: {}", e)
        }
    }
}

// ── LUKS volume management ──

/// Mount a LUKS volume using a key from Vault.
///
/// Steps:
/// 1. Read encryption key from Vault KV
/// 2. Open LUKS container via `sudo cryptsetup open`
/// 3. Mount the mapped device at `drive_path`
/// 4. Set ownership to the current user
///
/// Requires sudoers rules for cryptsetup/mount commands.
#[cfg(target_os = "linux")]
pub async fn mount_luks(
    config: &DriveConfig,
    vault: &crate::vault::VaultClient,
) -> Result<(), DriveError> {
    let luks_device = config
        .luks_device
        .as_ref()
        .ok_or_else(|| DriveError::Luks("luks_device not configured".into()))?;
    let luks_key_path = config
        .luks_key_path
        .as_ref()
        .ok_or_else(|| DriveError::Luks("luks_key_path not configured".into()))?;
    let luks_name = &config.luks_name;
    let mapper_path = format!("/dev/mapper/{}", luks_name);

    // 1. Read LUKS key from Vault
    let key = vault
        .read_kv_field(luks_key_path, "key")
        .await
        .map_err(|e| {
            DriveError::Vault(format!(
                "failed to read LUKS key from Vault path '{}': {}",
                luks_key_path, e
            ))
        })?;

    tracing::info!("Retrieved LUKS key from Vault (path: {})", luks_key_path);

    // 2. Open LUKS container if not already open
    if !std::path::Path::new(&mapper_path).exists() {
        tracing::info!(
            "Opening LUKS container {:?} as '{}'",
            luks_device,
            luks_name
        );
        let mut child = tokio::process::Command::new("sudo")
            .args(["cryptsetup", "open", "--type", "luks", "--key-file=-"])
            .arg(luks_device)
            .arg(luks_name)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| DriveError::Luks(format!("failed to run cryptsetup: {}", e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(key.as_bytes()).await.map_err(|e| {
                DriveError::Luks(format!("failed to pipe key to cryptsetup: {}", e))
            })?;
            drop(stdin);
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| DriveError::Luks(format!("cryptsetup failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DriveError::Luks(format!(
                "cryptsetup open failed: {}",
                stderr
            )));
        }

        tracing::info!("LUKS container opened successfully");
    } else {
        tracing::info!("LUKS volume '{}' already open", luks_name);
    }

    // 3. Mount if not already mounted
    std::fs::create_dir_all(&config.drive_path).map_err(|e| {
        DriveError::Io(format!(
            "failed to create mount point {:?}: {}",
            config.drive_path, e
        ))
    })?;

    // Check if already mounted
    let mount_check = tokio::process::Command::new("mountpoint")
        .arg("-q")
        .arg(&config.drive_path)
        .status()
        .await;

    if mount_check.map_or(true, |s| !s.success()) {
        let output = tokio::process::Command::new("sudo")
            .args(["mount", &mapper_path])
            .arg(&config.drive_path)
            .output()
            .await
            .map_err(|e| DriveError::Luks(format!("failed to run mount: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DriveError::Luks(format!("mount failed: {}", stderr)));
        }

        tracing::info!("LUKS volume mounted at {:?}", config.drive_path);
    } else {
        tracing::info!("Drive path {:?} already mounted", config.drive_path);
    }

    // 4. Ensure the current user owns the mount point contents
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let _ = tokio::process::Command::new("sudo")
        .args(["chown", &format!("{}:{}", uid, gid)])
        .arg(&config.drive_path)
        .status()
        .await;

    Ok(())
}

/// Unmount and close the LUKS volume.
#[cfg(target_os = "linux")]
pub async fn unmount_luks(config: &DriveConfig) -> Result<(), DriveError> {
    let luks_name = &config.luks_name;

    // Unmount
    let _ = tokio::process::Command::new("sudo")
        .args(["umount"])
        .arg(&config.drive_path)
        .status()
        .await;

    // Close LUKS
    let output = tokio::process::Command::new("sudo")
        .args(["cryptsetup", "close", luks_name])
        .output()
        .await
        .map_err(|e| DriveError::Luks(format!("failed to run cryptsetup close: {}", e)))?;

    if output.status.success() {
        tracing::info!("LUKS volume '{}' closed", luks_name);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!("cryptsetup close warning: {}", stderr);
    }

    Ok(())
}

/// Check if LUKS is configured (has both device and key path).
pub fn luks_configured(config: &DriveConfig) -> bool {
    config.luks_device.is_some() && config.luks_key_path.is_some()
}
