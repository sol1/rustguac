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

## `[theme]` section

Customises the UI appearance — colours, logo, and background. All fields are optional. Start from a built-in preset and override individual colours, or set everything from scratch.

**Built-in presets:** `dark` (default), `light`, `high-contrast`, `terminal`, `nord`, `corporate`

| Key | Description |
|-----|-------------|
| `preset` | Base preset name (default: `dark`) |
| `logo_url` | URL or path to a custom logo image (replaces the default rustguac logo) |
| `primary_color` | Primary action colour (buttons, links) |
| `primary_hover` | Primary hover state |
| `accent_color` | Accent/secondary colour |
| `accent_hover` | Accent hover state |
| `bg_color` | Page background |
| `surface_color` | Card/panel backgrounds |
| `input_color` | Form input backgrounds |
| `text_color` | Primary text |
| `text_muted` | Secondary/muted text |
| `text_dim` | Tertiary/dim text |
| `text_on_primary` | Text on primary-coloured backgrounds |
| `border_color` | Borders and dividers |
| `btn_disabled` | Disabled button colour |
| `bg_pattern` | CSS background pattern for the page body |
| `status_pending` | Pending session badge |
| `status_active` | Active session badge |
| `status_completed` | Completed session badge |
| `status_error` | Error session badge |
| `status_expired` | Expired session badge |
| `type_ssh_bg` / `type_ssh_fg` | SSH session type badge |
| `type_rdp_bg` / `type_rdp_fg` | RDP session type badge |
| `type_vnc_bg` / `type_vnc_fg` | VNC session type badge |
| `type_web_bg` / `type_web_fg` | Web session type badge |
| `hop_bg` / `hop_fg` | Jump host badge |

All colour values are CSS colour strings (e.g. `"#003366"`, `"rgb(0,51,102)"`).

Users can also switch between presets from the gear menu in the UI. The admin preset is the default; users can override it locally via their browser.

**Example: corporate branding with custom logo and colours:**
```toml
site_title = "Acme Remote Console"

[theme]
preset = "light"
logo_url = "/acme-logo.png"
primary_color = "#003366"
accent_color = "#FF6600"
```

Place the logo file in the `static_path` directory (e.g. `/opt/rustguac/static/acme-logo.png`). In Docker, mount it as a volume:
```
-v /path/to/acme-logo.png:/opt/rustguac/static/acme-logo.png:ro
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
