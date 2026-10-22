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
use std::collections::HashSet;
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
    /// User who created the session (email).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Address book folder name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// Display name of the address book entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_display_name: Option<String>,
    /// Session type (ssh, rdp, vnc, web).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_type: Option<String>,
    /// Name of the entry protocol the session used (#296).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
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
/// `active` is the set of recording paths belonging to still-live sessions.
/// These are NEVER deleted: their `.guac` files may be open for writing by the
/// recording tee, and unlinking an open file loses the in-progress capture
/// while freeing no disk space (the blocks stay pinned until the fd closes).
/// Deleting one therefore does not lower `statvfs` usage, which previously let
/// the disk-based phase delete every recording in a single pass without ever
/// getting under the threshold.
///
/// Returns the number of recordings deleted.
pub fn rotate(config: &RecordingConfig, active: &HashSet<PathBuf>) -> usize {
    let dir = &config.path;
    let mut deleted = 0;

    // Phase 1: enforce max_recordings count.
    if config.max_recordings > 0 {
        deleted += enforce_count_limit(dir, active, config.max_recordings as usize);
    }

    // Phase 2: enforce max_disk_percent.
    if config.max_disk_percent > 0 {
        deleted += enforce_disk_limit(dir, active, config.max_disk_percent as f64, || {
            disk_usage_percent(dir).ok()
        });
    }

    if deleted > 0 {
        tracing::info!("Recording rotation: deleted {} files", deleted);
    }
    deleted
}

/// Oldest recording in `dir` that is not currently being written (not in
/// `active`). `None` if every recording belongs to a live session.
fn oldest_rotatable(dir: &Path, active: &HashSet<PathBuf>) -> Option<PathBuf> {
    list_recordings_by_age(dir)
        .into_iter()
        .map(|(path, _, _)| path)
        .find(|path| !active.contains(path))
}

/// Delete the oldest closed recordings so the total on-disk count is at most
/// `max`. In-progress (active) recordings are never deleted, but they still
/// count toward the total, so a burst of live sessions cannot force old
/// recordings to be culled below what the operator asked to keep.
fn enforce_count_limit(dir: &Path, active: &HashSet<PathBuf>, max: usize) -> usize {
    let recordings = list_recordings_by_age(dir);
    let over = recordings.len().saturating_sub(max);
    if over == 0 {
        return 0;
    }
    let mut deleted = 0;
    for (path, _, _) in recordings.iter().filter(|(p, _, _)| !active.contains(p)) {
        if deleted >= over {
            break;
        }
        delete_recording(path);
        deleted += 1;
    }
    deleted
}

/// Delete oldest closed recordings while the filesystem is over `threshold`
/// percent used. Two rules prevent the runaway that once wiped an entire
/// recordings directory: it never deletes an `active` (open) recording, and it
/// stops the moment a deletion frees no space. An unlinked-but-open file keeps
/// its blocks, so usage would never fall and the loop would otherwise delete
/// every recording without recovering any space. `usage` is injected (rather
/// than calling `disk_usage_percent` directly) so the loop is testable without
/// an actually-full disk.
fn enforce_disk_limit(
    dir: &Path,
    active: &HashSet<PathBuf>,
    threshold: f64,
    mut usage: impl FnMut() -> Option<f64>,
) -> usize {
    let mut deleted = 0;
    loop {
        let before = match usage() {
            Some(u) => u,
            None => {
                tracing::warn!("Recording rotation: failed to read disk usage; stopping");
                break;
            }
        };
        if before <= threshold {
            break;
        }
        let Some(path) = oldest_rotatable(dir, active) else {
            tracing::warn!(
                "Recording rotation: disk at {:.0}% (over {:.0}%) but every remaining recording belongs to a live session; not deleting in-progress recordings",
                before,
                threshold
            );
            break;
        };
        delete_recording(&path);
        deleted += 1;
        // Progress guard: if usage did not drop, the file we just unlinked was
        // still open (its blocks are pinned). Stop rather than deleting the
        // whole directory chasing a threshold we cannot reach. (A concurrent
        // live session writing faster than we free can also trip this; that is
        // a safe early stop -- the next rotation pass retries.)
        if let Some(after) = usage() {
            if after >= before {
                tracing::warn!(
                    "Recording rotation: deleting {} freed no space (still {:.0}%); stopping to avoid deleting recordings that cannot free space",
                    path.display(),
                    after
                );
                break;
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(0);

    fn tmp_dir() -> PathBuf {
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("rg-rot-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn make_guac(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, b"x").unwrap();
        p
    }

    #[test]
    fn oldest_rotatable_skips_active_and_reports_none() {
        let dir = tmp_dir();
        let a = make_guac(&dir, "a.guac");
        let b = make_guac(&dir, "b.guac");
        let mut active = HashSet::new();
        active.insert(a.clone());
        // Only b is closed, so it is the sole rotation candidate.
        assert_eq!(oldest_rotatable(&dir, &active), Some(b.clone()));
        // With every recording live, nothing is rotatable.
        active.insert(b);
        assert_eq!(oldest_rotatable(&dir, &active), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn count_limit_never_deletes_active() {
        let dir = tmp_dir();
        for i in 0..5 {
            make_guac(&dir, &format!("{i}.guac"));
        }
        let mut active = HashSet::new();
        active.insert(dir.join("0.guac"));
        active.insert(dir.join("1.guac"));
        // over = 5 - 1 = 4, but only 3 recordings are closed -> delete those 3,
        // keep both live ones untouched.
        let deleted = enforce_count_limit(&dir, &active, 1);
        assert_eq!(deleted, 3);
        assert!(dir.join("0.guac").exists());
        assert!(dir.join("1.guac").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_limit_stops_when_deletion_frees_no_space() {
        // Regression for the disk-fill incident: an unlinked-but-open recording
        // frees no blocks, so usage never drops. The progress guard must bound
        // deletion to a single file instead of wiping the whole directory.
        let dir = tmp_dir();
        for i in 0..5 {
            make_guac(&dir, &format!("{i}.guac"));
        }
        let active = HashSet::new();
        let deleted = enforce_disk_limit(&dir, &active, 80.0, || Some(90.0));
        assert_eq!(deleted, 1, "progress guard must bound deletion to one file");
        assert_eq!(list_recordings_by_age(&dir).len(), 4);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_limit_never_deletes_active_recordings() {
        // Every recording is live; even though the disk reads over threshold,
        // nothing may be deleted.
        let dir = tmp_dir();
        let mut active = HashSet::new();
        for i in 0..3 {
            active.insert(make_guac(&dir, &format!("{i}.guac")));
        }
        let deleted = enforce_disk_limit(&dir, &active, 80.0, || Some(99.0));
        assert_eq!(deleted, 0, "in-progress recordings must never be deleted");
        assert_eq!(list_recordings_by_age(&dir).len(), 3);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_limit_terminates_normally() {
        // usage falls as closed recordings are removed; the loop stops once
        // under threshold rather than deleting everything.
        let dir = tmp_dir();
        for i in 0..8 {
            make_guac(&dir, &format!("{i}.guac"));
        }
        let active = HashSet::new();
        // Model usage as 10% per remaining recording; threshold 30% -> keep 3.
        let deleted = enforce_disk_limit(&dir, &active, 30.0, || {
            Some(list_recordings_by_age(&dir).len() as f64 * 10.0)
        });
        assert_eq!(deleted, 5);
        assert_eq!(list_recordings_by_age(&dir).len(), 3);
        let _ = fs::remove_dir_all(&dir);
    }
}
