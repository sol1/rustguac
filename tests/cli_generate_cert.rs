//! `rustguac generate-cert` writes the private key readable by its owner
//! only, also when it replaces a key that was readable by everyone (the
//! Docker image before 1.14.4 shipped one, GHSA-j4r4-h9h8-fj4v).

use assert_cmd::Command;
use std::os::unix::fs::PermissionsExt;

#[test]
fn the_key_is_owner_only_even_over_a_world_readable_one() {
    let dir = std::env::temp_dir().join(format!("rustguac-cli-gencert-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // The binary opens its database before any subcommand: keep it here.
    std::fs::write(dir.join("config.toml"), "db_path = \"./rustguac.db\"\n").unwrap();
    let key = dir.join("key.pem");
    std::fs::write(&key, "old").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

    Command::cargo_bin("rustguac")
        .unwrap()
        .current_dir(&dir)
        .args([
            "--config",
            "config.toml",
            "generate-cert",
            "--hostname",
            "localhost",
            "--out-dir",
        ])
        .arg(&dir)
        .assert()
        .success();

    let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
    let pem = std::fs::read_to_string(&key).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(mode, 0o600, "key.pem mode {mode:o}");
    assert!(pem.contains("PRIVATE KEY"));
}
