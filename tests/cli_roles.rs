//! CLI behaviour for custom roles (#294): `add-role`, `list-roles`,
//! `show-user`, `delete-role`, and custom role names in `add-user`,
//! `set-role` and `map-group`.
//!
//! Integration tests because they run the built binary (see
//! tests/cli_map_group.rs for why that has to happen here).

use assert_cmd::Command;
use rusqlite::Connection;

struct ScratchDir(std::path::PathBuf);

impl ScratchDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("rustguac-cli-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch dir");
        std::fs::write(path.join("config.toml"), "db_path = \"./rustguac.db\"\n")
            .expect("write config");
        ScratchDir(path)
    }

    fn conn(&self) -> Connection {
        Connection::open(self.0.join("rustguac.db")).expect("open database")
    }

    fn run(&self, args: &[&str]) -> assert_cmd::assert::Assert {
        let mut cmd = Command::cargo_bin("rustguac").unwrap();
        cmd.current_dir(&self.0)
            .args(["--config", "config.toml"])
            .args(args)
            .assert()
    }

    fn role_of(&self, email: &str) -> String {
        self.conn()
            .query_row("SELECT role FROM users WHERE email = ?1", [email], |r| {
                r.get(0)
            })
            .expect("user")
    }
}

/// Stdout and stderr of a finished command.
fn out(a: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&a.get_output().stdout).to_string()
}
fn err(a: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&a.get_output().stderr).to_string()
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn custom_roles_from_the_cli() {
    let dir = ScratchDir::new("roles");
    let a = dir
        .run(&[
            "add-role",
            "--name",
            "editor",
            "--display-name",
            "Connection editor",
            "--perm",
            "connections.connect",
            "--perm",
            "connections.edit",
        ])
        .success();
    assert!(out(&a).contains("Role 'editor' created"), "{}", out(&a));
    let a = dir
        .run(&["add-role", "--name", "bad", "--perm", "nope"])
        .failure();
    assert!(err(&a).contains("unknown permission: nope"), "{}", err(&a));
    dir.run(&["add-role", "--name", "Admin"]).failure();

    let a = dir.run(&["list-roles"]).success();
    assert!(
        out(&a).contains("editor (Connection editor)"),
        "{}",
        out(&a)
    );
    assert!(
        out(&a).contains("connections.connect connections.edit"),
        "{}",
        out(&a)
    );

    // Custom role names work wherever a role is taken.
    dir.run(&["add-user", "--email", "jon@example.com", "--role", "editor"])
        .success();
    assert_eq!(dir.role_of("jon@example.com"), "editor");
    dir.run(&["map-group", "--group", "editors", "--role", "editor"])
        .success();
    let a = dir
        .run(&["set-role", "--email", "jon@example.com", "--role", "nobody"])
        .failure();
    assert!(err(&a).contains("No role named 'nobody'"), "{}", err(&a));

    let a = dir
        .run(&["show-user", "--email", "jon@example.com"])
        .success();
    assert!(out(&a).contains("direct role: editor"), "{}", out(&a));
    assert!(out(&a).contains("connections.edit"), "{}", out(&a));

    // In use: refused until reassigned, and the reassignment is applied.
    let a = dir.run(&["delete-role", "--name", "editor"]).failure();
    assert!(err(&a).contains("user: jon@example.com"), "{}", err(&a));
    assert!(err(&a).contains("group mapping: editors"), "{}", err(&a));
    dir.run(&[
        "delete-role",
        "--name",
        "editor",
        "--reassign-to",
        "operator",
    ])
    .success();
    assert_eq!(dir.role_of("jon@example.com"), "operator");
    let mapped: String = dir
        .conn()
        .query_row(
            "SELECT role FROM group_role_mappings WHERE oidc_group = 'editors'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(mapped, "operator");
    let (action, target): (String, String) = dir
        .conn()
        .query_row(
            "SELECT action, target FROM cli_audit_log ORDER BY id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (action.as_str(), target.as_str()),
        ("delete_role", "editor")
    );
}
