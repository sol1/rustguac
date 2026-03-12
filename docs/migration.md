# Migrating from Apache Guacamole

rustguac can import connections from an Apache Guacamole MySQL/MariaDB database into its Vault-backed address book.

## Prerequisites

- A running Vault/OpenBao instance with `[vault]` configured in `config.toml`
- `VAULT_SECRET_ID` environment variable set
- A MySQL/MariaDB dump of your Guacamole database

## Step 1: Export the Guacamole database

On the Guacamole database server, create a SQL dump:

```bash
mysqldump -u guacamole_user -p guacamole_db \
  guacamole_connection \
  guacamole_connection_parameter \
  guacamole_connection_group \
  > guacamole-dump.sql
```

Only these three tables are needed. The dump must contain `INSERT INTO` statements (the default for mysqldump).

## Step 2: Preview the import

Use `--dry-run` to see what would be imported without writing anything:

```bash
rustguac --config /opt/rustguac/config.toml \
  import-guacamole \
  --file guacamole-dump.sql \
  --dry-run
```

Example output:

```
Found 42 connections (3 skipped, 39 to import)

[DRY RUN] Would import to folder "imported" (scope: shared):

  Web-Server (ssh) → 10.0.0.1:22
  Database-Primary (ssh) → 10.0.0.5:22
  Windows-DC (rdp) → 10.0.1.10:3389
  Production-DMZ-Firewall (ssh) → 10.0.2.1:22
  ...

Re-run without --dry-run to import.
```

Connections with unsupported protocols (e.g. telnet, kubernetes) are automatically skipped.

## Step 3: Import

```bash
VAULT_SECRET_ID=your-secret-id \
rustguac --config /opt/rustguac/config.toml \
  import-guacamole \
  --file guacamole-dump.sql \
  --folder my-servers \
  --scope shared
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--file` | (required) | Path to the mysqldump SQL file |
| `--folder` | `imported` | Target folder in the address book |
| `--scope` | `shared` | `shared` (visible to all instances) or `instance` (this instance only) |
| `--dry-run` | off | Preview without writing to Vault |

## What gets imported

The importer maps Guacamole connection parameters to rustguac address book fields:

| Guacamole parameter | Address book field |
|--------------------|--------------------|
| `hostname` | `hostname` |
| `port` | `port` |
| `username` | `username` |
| `password` | `password` |
| `private-key` | `private_key` |
| `domain` | `domain` |
| `security` | `security` |
| `ignore-cert` | `ignore_cert` |
| `color-depth` | `color_depth` |
| `enable-drive` | `enable_drive` |
| `remote-app` | `remote_app` |
| `remote-app-dir` | `remote_app_dir` |
| `remote-app-args` | `remote_app_args` |

### Supported protocols

- **SSH** connections
- **RDP** connections (including RemoteApp)
- **VNC** connections

Unsupported protocols (telnet, kubernetes, etc.) are skipped with a warning.

### Connection groups

Guacamole's connection group hierarchy is flattened into entry name prefixes. For example, a connection named "Firewall" in group "Production > DMZ" becomes `Production-DMZ-Firewall`.

### Name handling

- Spaces are replaced with hyphens
- Special characters are stripped
- Duplicate names get a `-2`, `-3` suffix
- Names are truncated to 64 characters
- The original connection name is preserved in the `display_name` field

## After import

Once imported, connections appear in the address book UI. You can:

- Edit entries to add features not available in Guacamole (login scripts, autofill, domain allowlists)
- Move entries between folders
- Set folder-level access controls via `allowed_groups`
- Enable per-entry clipboard restrictions (`disable_copy`/`disable_paste`)

## Notes

- The import is additive: existing entries in the target folder are not deleted or overwritten. If you re-run the import, entries with the same name will be updated.
- Guacamole user/group permissions are not imported. Use rustguac's OIDC group mappings and folder `allowed_groups` instead.
- Credentials (passwords, private keys) are imported into Vault where they are stored encrypted at rest and never touch disk.
