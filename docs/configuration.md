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
| `rate_limit` | `false` | Enable API rate limiting. Not needed when behind a rate-limiting reverse proxy. |
| `session_history_retention_days` | `90` | Days to keep session history in the database. 0 = keep forever. |

## `[tls]` section

Configures TLS for the web server and/or the guacd connection. There is no `enabled` toggle — the presence of the relevant fields controls behaviour:

- **Server HTTPS**: Provide both `cert_path` and `key_path` to serve HTTPS. Omit them to serve plain HTTP (useful behind a TLS-terminating reverse proxy like Traefik/HAProxy).
- **guacd TLS**: Provide `guacd_cert_path` to connect to guacd over TLS. This is independent of server HTTPS.

All fields are optional. The `[tls]` section can contain any combination.

| Key | Description |
|-----|-------------|
| `cert_path` | HTTPS certificate path (PEM). Both `cert_path` and `key_path` must be set for HTTPS. |
| `key_path` | HTTPS private key path (PEM). Both `cert_path` and `key_path` must be set for HTTPS. |
| `guacd_cert_path` | Trust certificate for guacd TLS connection (independent of server HTTPS) |

**Examples:**

HTTPS + guacd TLS (self-hosted):
```toml
[tls]
cert_path = "/opt/rustguac/tls/cert.pem"
key_path = "/opt/rustguac/tls/key.pem"
guacd_cert_path = "/opt/rustguac/tls/cert.pem"
```

HTTP server + guacd TLS (behind a reverse proxy):
```toml
[tls]
guacd_cert_path = "/opt/rustguac/tls/guacd-cert.pem"
```

HTTPS only (guacd on localhost, no TLS needed):
```toml
[tls]
cert_path = "/opt/rustguac/tls/cert.pem"
key_path = "/opt/rustguac/tls/key.pem"
```

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
| `ca_cert` | — | Path to CA certificate (PEM) for verifying the OIDC provider |
| `tls_skip_verify` | `false` | Skip TLS verification (debugging only — exposes secrets to MITM) |

**Note:** `issuer_url` must match the discovered issuer URI **exactly**, including default ports and trailing slashes. For example, `https://idp.example.com/` and `https://idp.example.com` may be treated as different issuers. Check your provider's `.well-known/openid-configuration` for the canonical value.

## `[vault]` section

Enables the Vault-backed connections. Requires `VAULT_SECRET_ID` environment variable.

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

## `[theme]` section

Customises the UI appearance — base preset, individual colours, and logo. All fields are optional. A minimal example:

```toml
[theme]
preset = "light"
logo_url = "/acme-logo.png"
primary_color = "#003366"
accent_color = "#FF6600"
```

**See [themes.md](themes.md) for the full reference**: built-in preset list, every overridable field, the per-user picker, and how to author your own themes as `.toml` files under `<static_path>/themes/` (no recompile needed).

Place the logo file in the `static_path` directory (e.g. `/opt/rustguac/static/acme-logo.png`). In Docker, mount it as a volume:
```
-v /path/to/acme-logo.png:/opt/rustguac/static/acme-logo.png:ro
```

## `[recording]` section

Controls session recording behaviour and disk management.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `path` | string | `recording_path` | Path for recording files. Overrides the top-level `recording_path`. |
| `enabled` | bool | `true` | Whether recording is enabled globally. |
| `max_disk_percent` | integer | `80` | Delete oldest recordings when disk usage exceeds this percent. 0 = disabled. |
| `max_recordings` | integer | `0` | Keep at most this many recordings globally. 0 = unlimited. |
| `rotation_interval_secs` | integer | `300` | How often (seconds) to run the rotation check. |
| `typescript_path` | string | (unset) | Directory for SSH typescript (raw terminal text) files. Unset = disabled. See below. |
| `typescript_name` | string | `{connection}-{user}-{date}-{time}` | Filename template for typescripts. Tokens listed below. |
| `create_typescript_path` | bool | `false` | Ask guacd to create `typescript_path` if it does not exist. |

```toml
[recording]
enabled = true
max_disk_percent = 80
max_recordings = 1000
rotation_interval_secs = 300
```

### SSH typescript recording

The graphical recording above captures the session as a replayable
Guacamole stream. For SSH sessions you can additionally write a
**typescript**: a plain-text log of the full terminal output, compatible
with the standard `script` / `scriptreplay` tools and trivially
greppable. This is aimed at audit and compliance (a human-readable record
of what was typed and seen on a switch or server).

Set `typescript_path` to enable it for all SSH sessions. The typescript
is produced by guacd, so the path must be writable by the guacd process
(on a bare-metal install that is the `rustguac-guacd` service user; in
Docker it is inside the container). guacd writes two files per session,
`NAME` and `NAME.timing`.

```toml
[recording]
typescript_path = "/opt/rustguac/data/typescripts"
typescript_name = "{connection}-{user}-{date}-{time}"
create_typescript_path = true
```

**Filename tokens.** guacd does not template typescript names itself (it
uses the name verbatim and only appends a numeric suffix to avoid
overwriting an existing file). rustguac therefore expands its own tokens
in `typescript_name` before handing it over, so each file is identifiable:

| Token | Expands to |
|-------|-----------|
| `{user}` | Session username |
| `{connection}` | Address-book entry name (falls back to the hostname for ad-hoc sessions) |
| `{host}` | Target hostname |
| `{date}` | Connect date, UTC `YYYYMMDD` |
| `{time}` | Connect time, UTC `HHMMSS` |
| `{session}` | First 8 characters of the session id |

Substituted values are sanitised to `[A-Za-z0-9_-]` (everything else
becomes `-`), so usernames like `alice@example.com` and free-text entry
names are always reduced to a safe basename with no path separators.
Unknown `{tokens}` are left untouched.

> **Note:** these are rustguac's own tokens, not guacd's, and they are
> unrelated to [credential variables](credential-variables.md) (which use
> `$name` syntax and apply only to connection-entry credential fields).
> guacd's own `${GUAC_*}` tokens are **not** interpreted for typescripts.

Keystroke logging in the *graphical* recording (guacd's
`recording-include-keys`, parseable by `guaclog`) is a separate mechanism
that depends on guacd-driven graphical recording, which rustguac does not
use (it records the proxied stream itself). It is therefore not wired up;
the typescript is the supported text-audit path.

## `[vdi]` section

Enables VDI (Virtual Desktop Infrastructure) sessions using Docker containers. Each user gets an ephemeral Linux desktop in a Docker container, accessed via xrdp through guacd.

**Prerequisites:** Docker must be installed on the host and the `rustguac` user must be in the `docker` group. See [VDI Desktop Containers](vdi.md) for full setup.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable VDI sessions. |
| `docker_socket` | string | `/var/run/docker.sock` | Docker daemon socket path. |
| `default_cpu_limit` | float | `0` | Default CPU limit for containers (fractional cores, e.g. 2.0). 0 = no limit. |
| `default_memory_limit` | integer | `0` | Default memory limit in MB. 0 = no limit. |
| `ready_timeout_secs` | integer | `30` | Seconds to wait for xrdp to become ready in a new container. |
| `port_range_start` | integer | *(none)* | First localhost port Docker may bind VDI RDP to. Must be set with `port_range_end`. |
| `port_range_end` | integer | *(none)* | Last localhost port Docker may bind VDI RDP to. Must be set with `port_range_start`. |
| `container_hook_script` | string | *(none)* | Optional VDI container hook script. Called as `<script> up <port> <container_id> <container_name>` before readiness checks and `<script> down <port> <container_id> <container_name>` before removal. |
| `container_hook_timeout_secs` | integer | `10` | Seconds to wait for the VDI container hook script. |
| `idle_timeout_mins` | integer | `60` | Minutes a container persists after last session disconnect. 0 = remove immediately. |
| `allowed_images` | list | `[]` | Allowed Docker images (exact match). Empty = allow all. |
| `home_base` | string | *(none)* | Base directory for persistent user home dirs. Each user gets `{home_base}/{username}` mounted into the container. |

```toml
[vdi]
enabled = true
idle_timeout_mins = 60
# port_range_start = 39000
# port_range_end = 39999
# container_hook_script = "/opt/rustguac/vdi-container-hook.sh"
# container_hook_timeout_secs = 10
home_base = "/vdi-homes"
# allowed_images = ["myregistry/desktop:latest"]
```

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
