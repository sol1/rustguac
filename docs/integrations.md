# Integrations

## OIDC Single Sign-On

rustguac supports OpenID Connect for user authentication. Any OIDC provider works: Authentik, Keycloak, Okta, Azure AD, Google, etc.

### Setup

1. **Register an application** with your OIDC provider
2. Set the redirect URI to `https://your-host/auth/callback`
3. Note the client ID and client secret
4. Add the `[oidc]` section to your config:

```toml
[oidc]
issuer_url = "https://authentik.example.com/application/o/rustguac/"
client_id = "your-client-id"
client_secret = "your-client-secret"
redirect_uri = "https://your-host/auth/callback"
default_role = "operator"
groups_claim = "groups"
extra_scopes = ["groups"]
```

### Client secret

The `client_secret` can be provided via the `OIDC_CLIENT_SECRET` environment variable, which takes precedence over the config file. This is recommended for production:

```bash
# For systemd
echo 'OIDC_CLIENT_SECRET=your-secret' >> /opt/rustguac/env
chmod 600 /opt/rustguac/env
```

### OIDC groups

rustguac extracts group memberships from the OIDC ID token. The claim name is configurable (default: `groups`). Groups are used for:

- **Automatic role assignment** via group-to-role mappings (see [Roles and Access Control](roles-and-access-control.md))
- **Address book folder access** — folders can be restricted to specific OIDC groups

If your provider requires additional scopes to include groups in the token, add them to `extra_scopes`:

```toml
extra_scopes = ["groups"]
```

### Login flow

1. User clicks "Login" on the web UI
2. Redirected to OIDC provider with PKCE challenge
3. After authentication, provider redirects to `/auth/callback`
4. rustguac validates the token (PKCE + nonce), extracts user info and groups
5. User is created or updated in the database
6. Group-to-role mappings are evaluated (highest matching role wins)
7. A session cookie is set and the user is redirected to the application

### Logout

`GET /auth/logout` clears the session cookie and deletes the auth session from the database.

### Authentik setup guide

[Authentik](https://goauthentik.io/) is a recommended open-source identity provider that works well with rustguac.

**1. Create a provider** in Authentik:

- Go to **Applications > Providers > Create**
- Select **OAuth2/OpenID Connect**
- Name: `rustguac`
- Authorization flow: pick your default authorization flow (e.g., `default-provider-authorization-implicit-consent`)
- Client type: **Confidential**
- Redirect URIs: `https://your-rustguac-host/auth/callback`
- Under **Advanced protocol settings**:
  - Scopes: ensure `openid`, `email`, `profile` are selected
  - Add the `groups` scope (creates the `groups` claim in the ID token)

**2. Create an application:**

- Go to **Applications > Applications > Create**
- Name: `rustguac`
- Slug: `rustguac`
- Provider: select the provider you just created
- Launch URL: `https://your-rustguac-host/`

**3. Note the provider details:**

- Go back to the provider and note the **Client ID** and **Client Secret**
- The **OpenID Configuration Issuer** will be: `https://authentik.example.com/application/o/rustguac/`

**4. Configure rustguac:**

```toml
[oidc]
issuer_url = "https://authentik.example.com/application/o/rustguac/"
client_id = "your-client-id"
redirect_uri = "https://your-rustguac-host/auth/callback"
default_role = "operator"
groups_claim = "groups"
extra_scopes = ["groups"]
```

```bash
echo 'OIDC_CLIENT_SECRET=your-client-secret' >> /opt/rustguac/env
chmod 600 /opt/rustguac/env
sudo systemctl restart rustguac
```

**5. (Optional) Set up group-to-role mappings:**

Create groups in Authentik (e.g., `rustguac-admins`, `rustguac-operators`) and assign users to them. Then configure group-to-role mappings in the rustguac Admin page so that group membership automatically assigns roles on login. See [Roles and Access Control](roles-and-access-control.md) for details.

---

## Vault / OpenBao Address Book

The address book stores connection entries in [HashiCorp Vault](https://www.vaultproject.io/) or [OpenBao](https://openbao.org/) KV v2. Credentials are read server-side and never sent to the browser.

### Vault setup

**1. Enable KV v2** (skip if already enabled):

```bash
vault secrets enable -path=secret kv-v2
```

**2. Create a policy** for rustguac:

```bash
vault policy write rustguac - <<'EOF'
path "secret/data/rustguac/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "secret/metadata/rustguac/*" {
  capabilities = ["list", "read", "delete"]
}
EOF
```

**3. Enable AppRole auth** and create a role:

```bash
vault auth enable approle

vault write auth/approle/role/rustguac \
    token_policies="rustguac" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=0

# Get the role_id (put in config.toml)
vault read auth/approle/role/rustguac/role-id

# Generate a secret_id (set as VAULT_SECRET_ID env var)
vault write -f auth/approle/role/rustguac/secret-id
```

**4. Configure rustguac:**

```toml
[vault]
addr = "https://vault.example.com:8200"
role_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
# mount = "secret"          # KV v2 mount (default)
# base_path = "rustguac"    # base path (default)
# namespace = "my-ns"       # Vault Enterprise / OpenBao
# instance_name = "prod-1"  # instance-scoped entries
```

Set the secret ID:

```bash
echo 'VAULT_SECRET_ID=<secret_id>' > /opt/rustguac/env
chmod 600 /opt/rustguac/env
```

### KV v2 path structure

| Path | Description |
|------|-------------|
| `rustguac/shared/<folder>/.config` | Folder metadata: `{"allowed_groups":[...], "description":"..."}` |
| `rustguac/shared/<folder>/<entry>` | Connection entry (shared across all instances) |
| `rustguac/instance/<name>/<folder>/<entry>` | Instance-specific entry (requires `instance_name`) |

### AppRole token management

rustguac manages Vault tokens automatically:

- Authenticates via AppRole (`role_id` + `secret_id`) on startup
- Renews tokens at 50% of their TTL
- Falls back to full re-authentication on 403 Forbidden responses
- Retries every 30 seconds if Vault is unavailable at startup (non-fatal)

### Multi-instance support

When `instance_name` is set, rustguac sees both shared entries and entries scoped to its instance:

- `shared/` entries are visible to all rustguac instances
- `instance/<name>/` entries are only visible to the named instance

This allows a fleet of rustguac instances to share common entries while maintaining instance-specific ones.

### Entry types

Address book entries can be SSH, RDP, or Web connections. Each entry stores:

- Connection type and target (hostname, port, URL)
- Credentials (username, password, private key)
- Protocol-specific settings (domain, security mode, certificate ignore, drive override)

### Name validation

Folder and entry names are validated: alphanumeric characters, hyphens, underscores, and dots only. Length 1-64. Characters like `/`, `\`, and `..` are blocked to prevent path traversal in Vault.

---

## Drive / File Transfer / LUKS Encryption

rustguac supports file transfer for RDP and SSH sessions.

### RDP drive redirection

When drive is enabled, each RDP session gets a per-session directory under `drive_path`. guacd mounts this as a virtual drive visible in the remote Windows session (e.g., "Shared Drive" in Explorer).

- Files are **temporary** — the session directory is deleted when the session ends (configurable)
- The drive appears as a network drive in the Windows session
- Upload and download can be independently enabled/disabled

```toml
[drive]
enabled = true
drive_path = "/mnt/rustguac-drives"
drive_name = "Shared Drive"
allow_download = true
allow_upload = true
cleanup_on_close = true
retention_secs = 0
```

### SSH SFTP

For SSH sessions, SFTP file transfer happens directly between the browser and the target SSH server via guacd. No files are stored on the rustguac server.

### LUKS encryption

For RDP drive storage, the `drive_path` can be backed by a LUKS-encrypted volume. The encryption key is stored in Vault and the volume is only unlocked while rustguac is running.

```toml
[drive]
enabled = true
drive_path = "/mnt/rustguac-drives"
luks_device = "/opt/rustguac/drives.luks"
luks_name = "rustguac-drives"
luks_key_path = "rustguac/luks-key"
```

#### LUKS lifecycle

On startup:
1. Read encryption key from Vault KV
2. Open LUKS container via `sudo cryptsetup open --type luks --key-file=-`
3. Mount the mapped device at `drive_path`
4. Set ownership to the rustguac user

On shutdown:
1. Unmount the volume
2. Close the LUKS container via `sudo cryptsetup close`

The key is passed to cryptsetup via stdin — never on the command line or written to disk.

#### Setup

Run the interactive setup script:

```bash
sudo /opt/rustguac/bin/drive-setup.sh
```

This creates the LUKS container file, generates a random encryption key, stores the key in Vault, and configures the necessary sudoers rules.

#### Sudoers rules

The rustguac user needs specific sudo permissions for LUKS operations. These are installed automatically:

```
rustguac ALL=(root) NOPASSWD: /usr/sbin/cryptsetup open --type luks --key-file=- <device> <name>
rustguac ALL=(root) NOPASSWD: /usr/sbin/cryptsetup close <name>
rustguac ALL=(root) NOPASSWD: /bin/mount /dev/mapper/<name> <mount_point>
rustguac ALL=(root) NOPASSWD: /bin/umount <mount_point>
rustguac ALL=(root) NOPASSWD: /bin/chown *:* <mount_point>
```

---

## HAProxy Reverse Proxy

An example HAProxy configuration is provided in `haproxy.example.cfg`. This is the recommended production deployment pattern.

### Features

- **TLS termination** at HAProxy with modern ciphersuites (TLS 1.2+, ECDHE)
- **HTTP to HTTPS redirect**
- **X-Forwarded-For handling** — strips incoming headers and adds the real client IP
- **WebSocket support** — `timeout tunnel 8h` for long-lived sessions
- **Health checks** against `/api/health`
- **Slowloris protection** — `timeout http-request 10s`
- **HSTS header** — `max-age=31536000; includeSubDomains`

### Minimal example

```
frontend https
    bind *:443 ssl crt /etc/ssl/private/rustguac.pem alpn h2,http/1.1
    bind *:80
    http-request redirect scheme https unless { ssl_fc }
    http-request del-header X-Forwarded-For
    option forwardfor
    default_backend rustguac

backend rustguac
    option httpchk GET /api/health
    server rustguac 127.0.0.1:8089 ssl verify none check inter 30s
```

rustguac must trust HAProxy's IP:

```toml
trusted_proxies = ["127.0.0.1/32"]
```

### Double TLS

In the default configuration, traffic is encrypted twice on the loopback:
1. HAProxy terminates the client's TLS connection
2. HAProxy connects to rustguac over TLS (rustguac's own self-signed cert)

This is belt-and-suspenders for environments where even loopback traffic should be encrypted.

---

## Knocknoc Zero-Trust Access

[Knocknoc](https://knocknoc.io) provides identity-aware network access control. The integration works at the HAProxy layer: knocknoc-agent dynamically adds and removes client IPs to HAProxy ACLs via the admin socket.

### How it works

1. User authenticates through Knocknoc (SSO, MFA, etc.)
2. knocknoc-agent adds the user's IP to HAProxy ACL #600 via the admin socket
3. HAProxy allows access to the login page (`/` path only)
4. User logs in via OIDC (rustguac's own auth layer)
5. When the Knocknoc session expires, the IP is removed from the ACL

### What is gated

Only the front page (`/`) is gated behind Knocknoc. All other paths pass through to rustguac's own authentication:

- `/api/*` — API key or OIDC session auth
- `/auth/*` — OIDC login/callback flow
- `/ws/*` — WebSocket connections (session auth)
- `/share/*` — Share links (share token auth)

This ensures OIDC callbacks and share links work even when the user hasn't authenticated through Knocknoc, while hiding the login UI from scanners and bots.

### HAProxy configuration

```
# Admin socket for knocknoc-agent
stats socket /run/haproxy/admin.sock mode 0660 level admin

# Dynamic ACL (ACL ID 600 must match Knocknoc config)
acl knoc_rustguac src -u 600
acl is_root path /

# Gate only the front page
use_backend rustguac if is_rustguac is_root knoc_rustguac
use_backend denied   if is_rustguac is_root
use_backend rustguac if is_rustguac
```

### Verifying ACL state

```bash
echo "show acl #600" | socat stdio /run/haproxy/admin.sock
```
