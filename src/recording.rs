//! Recording rotation and disk-space management.
//!
//! Provides functions to:
//! - Check disk usage percentage via `statvfs`
//! - List `.guac` recordings sorted by age (oldest first)
//! - Read/write sidecar `.meta` JSON files for per-entry tracking
//! - Rotate recordings globally (by count and disk usage)
//! - Rotate recordings per address-book entry

use crate::config::RecordingConfig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Sidecar metadata written alongside each `.guac` recording file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingMeta {
    /// Address book entry key (e.g. "shared/folder/entry").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_book_entry: Option<String>,
    /// ISO 8601 timestamp when the recording was created.
    pub created_at: String,
}

/// Get the disk usage percentage for the filesystem containing `path`.
/// Returns 0.0–100.0, or an error if the syscall fails.
pub fn disk_usage_percent(path: &Path) -> std::io::Result<f64> {
    use std::ffi::CString;

    let c_path = CString::new(path.to_string_lossy().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let total = stat.f_blocks as f64;
        if total == 0.0 {
            return Ok(0.0);
        }
        let free = stat.f_bfree as f64;
        let used = total - free;
        Ok((used / total) * 100.0)
    }
}

/// List all `.guac` recordings in `dir`, sorted oldest-first.
/// Returns `(path, modified_time, size_bytes)`.
pub fn list_recordings_by_age(dir: &Path) -> Vec<(PathBuf, SystemTime, u64)> {
    let mut recordings = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return recordings,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("guac") {
            continue;
        }
        if let Ok(meta) = std::fs::metadata(&path) {
            let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            recordings.push((path, modified, meta.len()));
        }
    }

    recordings.sort_by_key(|(_, time, _)| *time);
    recordings
}

/// Read the sidecar `.meta` JSON for a `.guac` file.
pub fn read_meta(guac_path: &Path) -> Option<RecordingMeta> {
    let meta_path = guac_path.with_extension("meta");
    let data = std::fs::read_to_string(&meta_path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Write a sidecar `.meta` JSON alongside a `.guac` file.
pub fn write_meta(guac_path: &Path, meta: &RecordingMeta) -> std::io::Result<()> {
    let meta_path = guac_path.with_extension("meta");
    let json = serde_json::to_string(meta).map_err(std::io::Error::other)?;
    std::fs::write(&meta_path, json)?;

    // Restrictive permissions on meta file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&meta_path, std::fs::Permissions::from_mode(0o640));
    }

    Ok(())
}

/// Delete a recording and its sidecar `.meta` file.
fn delete_recording(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        tracing::warn!("Failed to delete recording {}: {}", path.display(), e);
    } else {
        tracing::info!("Rotated recording: {}", path.display());
    }
    // Also remove sidecar meta
    let meta_path = path.with_extension("meta");
    let _ = std::fs::remove_file(&meta_path);
}

/// Run global rotation based on `RecordingConfig`.
/// Deletes oldest recordings when:
/// 1. Total count exceeds `max_recordings` (if > 0)
/// 2. Disk usage exceeds `max_disk_percent` (if > 0)
///
/// Returns the number of recordings deleted.
pub fn rotate(config: &RecordingConfig) -> usize {
    let mut deleted = 0;
    let dir = &config.path;

    // Phase 1: enforce max_recordings count
    if config.max_recordings > 0 {
        let recordings = list_recordings_by_age(dir);
        let over = recordings
            .len()
            .saturating_sub(config.max_recordings as usize);
        for (path, _, _) in recordings.iter().take(over) {
            delete_recording(path);
            deleted += 1;
        }
    }

    // Phase 2: enforce max_disk_percent
    if config.max_disk_percent > 0 {
        let threshold = config.max_disk_percent as f64;
        loop {
            let usage = match disk_usage_percent(dir) {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!("Failed to check disk usage: {}", e);
                    break;
                }
            };
            if usage <= threshold {
                break;
            }
            // Find the oldest recording and delete it
            let recordings = list_recordings_by_age(dir);
            if let Some((path, _, _)) = recordings.first() {
                delete_recording(path);
                deleted += 1;
            } else {
                break; // no more recordings to delete
            }
        }
    }

    if deleted > 0 {
        tracing::info!("Recording rotation: deleted {} files", deleted);
    }
    deleted
}

/// Rotate recordings for a specific address book entry.
/// Deletes oldest recordings whose `.meta` matches `entry_key`
/// until the count is at most `max`.
///
/// Returns the number of recordings deleted.
pub fn rotate_per_entry(recording_dir: &Path, entry_key: &str, max: u32) -> usize {
    if max == 0 {
        return 0; // unlimited
    }

    let recordings = list_recordings_by_age(recording_dir);

    // Filter to recordings matching this entry
    let mut matching: Vec<&PathBuf> = Vec::new();
    for (path, _, _) in &recordings {
        if let Some(meta) = read_meta(path) {
            if meta.address_book_entry.as_deref() == Some(entry_key) {
                matching.push(path);
            }
        }
    }

    // Already sorted oldest-first
    let over = matching.len().saturating_sub(max as usize);
    let mut deleted = 0;
    for path in matching.iter().take(over) {
        delete_recording(path);
        deleted += 1;
    }

    if deleted > 0 {
        tracing::info!(
            "Per-entry rotation for '{}': deleted {} files ({} remaining)",
            entry_key,
            deleted,
            matching.len() - deleted
        );
    }
    deleted
}
