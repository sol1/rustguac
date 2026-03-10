# Configuration Reference

rustguac reads a TOML configuration file. All settings have sensible defaults and are optional.

```bash
rustguac --config /opt/rustguac/config.toml serve
```

See `config.example.toml` for a fully commented reference.

## Server settings

| Key | Default | Description |
|-----|---------|-------------|
| `listen_addr` | `127.0.0.1:8089` | Address and port to listen on |
| `guacd_addr` | `127.0.0.1:4822` | guacd TCP address |
| `recording_path` | `./recordings` | Session recording directory |
| `static_path` | `./static` | Static web files directory |
| `db_path` | `./rustguac.db` | SQLite database path |
| `site_title` | `rustguac` | Browser tab and page header title |

## Session timeouts

| Key | Default | Description |
|-----|---------|-------------|
| `session_pending_timeout_secs` | `60` | Seconds before pending sessions expire |
| `session_max_duration_secs` | `28800` (8h) | Maximum active session duration |
| `auth_session_ttl_secs` | `86400` (24h) | OIDC auth session cookie TTL |

## Browser session settings

| Key | Default | Description |
|-----|---------|-------------|
| `xvnc_path` | `Xvnc` | Path to Xvnc binary |
| `chromium_path` | `chromium` | Path to Chromium binary |
| `display_range_start` | `100` | First X display number |
| `display_range_end` | `199` | Last X display number |
| `cdp_port_range_start` | `9200` | First Chrome DevTools Protocol port (for login scripts) |
| `cdp_port_range_end` | `9299` | Last CDP port |
| `login_scripts_dir` | `/opt/rustguac/scripts` | Directory containing login scripts |
| `login_script_timeout_secs` | `120` | Maximum runtime for login scripts before they are killed |

## Connection allowlists

CIDR ranges controlling which hosts sessions can connect to. All default to localhost only.

**Important:** These are top-level TOML keys and must appear *before* any `[section]` header. Keys placed after a section header (e.g., `[tls]`) are scoped to that section and will be silently ignored.

| Key | Default | Description |
|-----|---------|-------------|
| `ssh_allowed_networks` | `["127.0.0.0/8", "::1/128"]` | Allowed SSH targets |
| `rdp_allowed_networks` | `["127.0.0.0/8", "::1/128"]` | Allowed RDP targets |
| `vnc_allowed_networks` | `["127.0.0.0/8", "::1/128"]` | Allowed VNC targets |
| `web_allowed_networks` | `["127.0.0.0/8", "::1/128"]` | Allowed web session URL hosts |

## Trusted proxies

| Key | Default | Description |
|-----|---------|-------------|
| `trusted_proxies` | `[]` | CIDRs of reverse proxies whose X-Forwarded-For to trust |

## `[tls]` section

Enables HTTPS and optionally TLS to guacd. Omit the entire section for plain HTTP.

| Key | Required | Description |
|-----|----------|-------------|
| `cert_path` | Yes | HTTPS certificate path (PEM) |
| `key_path` | Yes | HTTPS private key path (PEM) |
| `guacd_cert_path` | No | Trust certificate for guacd TLS connection |

## `[oidc]` section

Enables OpenID Connect authentication. When configured, the web UI shows a login button. API key auth continues to work alongside OIDC.

| Key | Default | Description |
|-----|---------|-------------|
| `issuer_url` | — | OIDC provider issuer URL (required) |
| `client_id` | — | OIDC client ID (required) |
| `client_secret` | — | OIDC client secret (or use `OIDC_CLIENT_SECRET` env var) |
| `redirect_uri` | — | Redirect URI: `https://your-host/auth/callback` (required) |
| `default_role` | `operator` | Role assigned to new users on first login |
| `groups_claim` | `groups` | JWT claim name containing group memberships |
| `extra_scopes` | `[]` | Additional OIDC scopes to request |

## `[vault]` section

Enables the Vault-backed address book. Requires `VAULT_SECRET_ID` environment variable.

| Key | Default | Description |
|-----|---------|-------------|
| `addr` | — | Vault server address (required) |
| `role_id` | — | AppRole role ID (required) |
| `mount` | `secret` | KV v2 mount path |
| `base_path` | `rustguac` | Base path under the mount |
| `namespace` | — | Vault Enterprise / OpenBao namespace |
| `instance_name` | — | Instance name for instance-scoped entries |
| `tls_skip_verify` | `false` | Skip TLS certificate verification (dev only) |
| `ca_cert` | — | Path to custom CA certificate (PEM) for verifying the Vault server |
| `client_cert` | — | Path to client certificate (PEM) for mTLS |
| `client_key` | — | Path to client private key (PEM) for mTLS (required if `client_cert` is set) |

## `[drive]` section

Enables file transfer for RDP (drive redirection) and SSH (SFTP).

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `false` | Enable drive/file transfer |
| `drive_path` | `./drives` | Base directory for per-session storage |
| `drive_name` | `Shared Drive` | Name shown in remote RDP session |
| `allow_download` | `true` | Allow file download from remote |
| `allow_upload` | `true` | Allow file upload to remote |
| `cleanup_on_close` | `true` | Delete session drive directory on disconnect |
| `retention_secs` | `0` | Delay before cleanup (0 = immediate) |
| `luks_device` | — | LUKS container file path |
| `luks_name` | `rustguac-drives` | Device-mapper name |
| `luks_key_path` | — | Vault KV path for LUKS encryption key |

## Environment variables

| Variable | Description |
|----------|-------------|
| `OIDC_CLIENT_SECRET` | Override OIDC client secret from config file |
| `VAULT_SECRET_ID` | Vault AppRole secret ID |
| `RUST_LOG` | Log level (e.g., `info`, `debug`, `rustguac=debug`) |

### Setting environment variables for systemd

The shipped systemd unit (`rustguac.service`) does not include an `EnvironmentFile` directive by default. To provide secrets like `VAULT_SECRET_ID` and `OIDC_CLIENT_SECRET`, create a systemd drop-in override:

**1. Create the env file** with your secrets:

```bash
cat > /opt/rustguac/env <<'EOF'
VAULT_SECRET_ID=your-vault-secret-id
OIDC_CLIENT_SECRET=your-oidc-client-secret
EOF
chmod 600 /opt/rustguac/env
chown rustguac:rustguac /opt/rustguac/env
```

**2. Create a systemd override** to load the env file:

```bash
sudo systemctl edit rustguac
```

This opens an editor. Add the following:

```ini
[Service]
EnvironmentFile=/opt/rustguac/env
```

Save and close. This creates a drop-in file at `/etc/systemd/system/rustguac.service.d/override.conf`.

**3. Reload and restart:**

```bash
sudo systemctl daemon-reload
sudo systemctl restart rustguac
```

The override persists across package upgrades — `dpkg` will not overwrite files in the `.d/` directory.

### Verifying the environment

To confirm the env file is loaded:

```bash
sudo systemctl show rustguac | grep EnvironmentFile
```

You should see:

```
EnvironmentFile=/opt/rustguac/env
```
