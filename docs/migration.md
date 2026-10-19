# Migrating from Apache Guacamole

rustguac can import connections from an Apache Guacamole MySQL/MariaDB database into its Vault-backed connections.

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

Only these three tables are needed. Both the default multi-row dump format and `--skip-extended-insert` single-row dumps are supported; the dump just needs `INSERT INTO` statements for those tables.

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
| `--folder` | `imported` | Target folder in the connections |
| `--scope` | `shared` | `shared` (visible to all instances) or `instance` (this instance only) |
| `--dry-run` | off | Preview without writing to Vault |
| `--map` | (none) | Rewrite a substring in the credential fields, repeatable; format `FROM=TO`. See [Mapping credential tokens](#mapping-credential-tokens). |

## What gets imported

The importer maps Guacamole connection parameters to rustguac connections fields:

| Guacamole parameter | Connections field |
|--------------------|--------------------|
| `hostname` | `hostname` |
| `port` | `port` |
| `username` | `username` |
| `password` | `password` |
| `private-key` | `private_key` |
| `domain` | `domain` |
| `security` | `security` |
| `server-layout` | `server_layout` |
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

## Mapping credential tokens

Apache Guacamole uses passthrough tokens like `${GUAC_USERNAME}` and `${GUAC_PASSWORD}` in connection parameters, substituted from the logged-in user's Guacamole credentials (typically via LDAP). rustguac has no such tokens; it uses named [credential variables](credential-variables.md) instead. Imported verbatim, a `${GUAC_USERNAME}` value is just a literal string that rustguac cannot resolve.

The `--map FROM=TO` flag rewrites substrings in the credential fields (`username`, `password`, `domain`, `private_key`) as they are imported, so you can convert Guacamole's tokens into rustguac credential variables in one pass. The flag is repeatable and the replacements are applied in order.

For example, to route every imported connection through a `jumpcloud` credential domain:

```bash
rustguac --config /opt/rustguac/config.toml \
  import-guacamole \
  --file guacamole-dump.sql \
  --map '${GUAC_USERNAME}=$jumpcloud_username' \
  --map '${GUAC_PASSWORD}=$jumpcloud_password' \
  --dry-run
```

Single-quote each mapping so your shell does not expand `$`. The run echoes the maps, reports how many entries were affected, and (in `--dry-run`) shows each entry's resulting username so you can confirm the rewrite:

```
Credential field maps:
  ${GUAC_USERNAME} -> $jumpcloud_username
  ${GUAC_PASSWORD} -> $jumpcloud_password
Found 42 connections (3 skipped, 39 to import)
Applied credential maps to 39 of 39 imported entries.
...
  imported/web-server (ssh) → 192.0.2.10:22
    username: $jumpcloud_username
```

After importing, each user sets their `jumpcloud` username and password once in **My Credentials** and every imported connection resolves. See [Credential Variables](credential-variables.md) for the naming convention (`$<domain>_<suffix>`) and how users fill them in.

`--map` is a plain substring replacement applied only to those four credential fields (the ones rustguac expands at connect time). Passwords and keys are never printed in the output.

## After import

Once imported, connections appear in the connections UI. You can:

- Edit entries to add features not available in Guacamole (login scripts, autofill, domain allowlists)
- Move entries between folders
- Set folder-level access controls via `allowed_groups`
- Enable per-entry clipboard restrictions (`disable_copy`/`disable_paste`)

## Notes

- The import is additive: existing entries in the target folder are not deleted or overwritten. If you re-run the import, entries with the same name will be updated.
- Guacamole user/group permissions are not imported. Use rustguac's OIDC group mappings and folder `allowed_groups` instead.
- Credentials (passwords, private keys) are imported into Vault where they are stored encrypted at rest and never touch disk.

## Multi-protocol entries

Connection entries can list several [protocols](api.md#multi-protocol-entries) for one host (RDP, SSH and a web UI on the same server), with host-level defaults that each protocol can override.

Nothing needs to be done on upgrade:

- Existing entries are read as they are, as entries with one protocol, and connect exactly as before. Nothing in Vault is rewritten.
- Existing links (`/api/connect?scope=…&folder=…&entry=…`), API clients, scripts, imports and the original single-protocol NetBox webhook keep working, since the single-protocol form (a top-level `type`) is still accepted everywhere.
- An entry that can be stored in the old form without losing anything still is, whether it was saved from the editor, the API or a webhook, so older instances keep reading it.

An entry is stored in the new form only when it needs it: more than one protocol, a protocol with a name of its own, or a host-level default such as a shared username. **Older rustguac versions cannot read an entry in the new form**: they leave it out of their lists and cannot connect to it. An update from them (an edit, or the NetBox webhook's `PUT`) is refused rather than written over it, but creating a new entry of the same name there replaces it. It is missing for everyone on that instance until it is upgraded.

So, when several rustguac instances share a Vault (including a `[vault_shared]` scope), upgrade every one of them before anyone adds a second protocol or a protocol name to an entry, or switches the NetBox webhook to the [multi-protocol template](netbox.md#multi-protocol-entries).

There is no bulk conversion command, and none is needed: old entries keep working in the old form, and each entry moves to the new one only when it is edited to use something that needs it.

## Splitting to multiple Vaults (disaster recovery)

If you already run a single Vault serving both the `shared` and `instance`
scopes and want to move a scope onto a dedicated Vault (see
[Multiple Vault backends](configuration.md#multiple-vault-backends-disaster-recovery)),
the `vault-migrate` subcommand copies a scope's whole subtree between two
configured backends. Because the scope-to-path layout is identical in every
backend, this is a same-identity copy, not a rewrite: it moves the entries
**and** each folder's access config (`.config`) and default credentials
(`.defaults`), so `allowed_groups`, inheritance and the credentials entries
borrow all travel with them.

### Step 1: Preview

Configure the new backend block (e.g. `[vault_shared]`) and its
`VAULT_SHARED_SECRET_ID`, then dry-run the copy:

```bash
VAULT_SECRET_ID=... VAULT_SHARED_SECRET_ID=... \
rustguac --config /opt/rustguac/config.toml \
  vault-migrate --scope shared --from vault --to vault_shared --dry-run
```

### Step 2: Copy

```bash
VAULT_SECRET_ID=... VAULT_SHARED_SECRET_ID=... \
rustguac --config /opt/rustguac/config.toml \
  vault-migrate --scope shared --from vault --to vault_shared
```

#### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--scope` | (required) | `shared` or `instance` |
| `--from` / `--to` | (required) | Backend names: `vault`, `vault_shared`, or `vault_local` |
| `--dry-run` | off | Preview without writing to the destination |
| `--overwrite` | off | Overwrite entries that already exist at the destination (default: skip existing) |
| `--users` | off | Also copy every per-user credential secret (`users/*`). This makes those credentials shared; normally you toggle per-credential in My Credentials instead. |

### Step 3: Cut over

Routing is deterministic and single-source: once `[vault_shared]` is configured,
the `shared` scope reads only from it, with no fall-back to `[vault]`. So the
order matters:

1. Copy the subtree first (Step 2).
2. Then add the `[vault_shared]` block and restart rustguac.

Doing it the other way round makes shared connections briefly disappear (the
data is safe in the old Vault, just not being read). Entries and folders are
single-source; only per-user credentials merge across backends, so those never
have a gap.
