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
- **Prompt for credentials** — when enabled, users are asked for username/password at connect time, even if stored credentials exist
- **NLA auth package** (RDP only) — force Kerberos or NTLM for NLA authentication
- **KDC URL** (RDP only) — Kerberos Key Distribution Center proxy URL

### Name validation

Folder and entry names are validated: alphanumeric characters, hyphens, underscores, and dots only. Length 1-64. Characters like `/`, `\`, and `..` are blocked to prevent path traversal in Vault.

### Credential prompting

Address book entries can be configured to prompt users for credentials at connect time. This is useful for:

- **Entries without stored credentials** — e.g., RDP servers where each user has their own AD account. The admin creates the entry with just hostname/port, and users supply their own credentials when connecting.
- **Entries with stored credentials but prompt enabled** — e.g., a jump host where the stored credentials are a fallback, but users should normally use their own.

The credential prompt appears automatically when:
1. The entry has **Prompt for credentials** enabled, OR
2. The entry has no stored password or private key (SSH/RDP only; Web sessions don't use credentials)

Prompted credentials are **never stored** — they're used for the current session only and discarded.

---

## RDP Kerberos NLA Authentication

rustguac includes a patched guacd with Kerberos NLA (Network Level Authentication) support. This allows RDP connections to authenticate using Kerberos instead of NTLM, which is important as Microsoft is phasing out NTLM.

### Background

Windows NLA (Network Level Authentication) normally negotiates the authentication protocol. By default, this typically uses NTLM. Microsoft has announced a multi-phase NTLM deprecation:

- **Phase 1** (current): Auditing and awareness
- **Phase 2** (H2 2026): New Kerberos features, NTLMv1 blocked by default
- **Phase 3** (future): NTLM disabled by default

AD accounts in the **Protected Users** security group already cannot use NTLM at all. The `auth_pkg` setting forces Kerberos for NLA, ensuring compatibility as NTLM is deprecated and enabling connections to Protected Users accounts.

### How it works

FreeRDP does not implement its own Kerberos stack. The chain is:

```
guacd -> libfreerdp3 -> libwinpr3 (SSPI/Negotiate) -> libgssapi_krb5 -> libkrb5 (MIT Kerberos)
```

FreeRDP's WinPR layer implements Windows SSPI on top of the system's MIT Kerberos libraries. This means it reads `/etc/krb5.conf`, uses the system credential cache, and respects `KRB5_CONFIG` and `KRB5_TRACE` environment variables. Username and password are still required — Kerberos replaces the wire authentication protocol (NTLM -> Kerberos), not the credential input.

### Per-entry configuration

These settings are configured per address book entry in the admin UI:

| Setting | Values | Description |
|---------|--------|-------------|
| **NLA Auth Package** | `(default)`, `ntlm`, `kerberos` | Force a specific NLA authentication method. Default lets the client and server negotiate. |
| **KDC URL** | URL | KDC or KDC Proxy URL. Overrides DNS SRV and krb5.conf for KDC discovery. |
| **Prompt for credentials** | checkbox | Prompt users for username/password/domain at connect time. |

### System prerequisites

#### Packages

On Debian 13, the Kerberos runtime libraries (`libkrb5-3`, `libgssapi-krb5-2`) are already installed as dependencies of FreeRDP 3 (`libwinpr3-3`). No extra packages are required for Kerberos to work.

For **testing and debugging**, install the Kerberos user tools:

```bash
apt install krb5-user
```

This provides `kinit`, `klist`, and `kdestroy`, and creates `/etc/krb5.conf` during installation.

#### Network requirements

| Port | Direction | Purpose |
|------|-----------|---------|
| TCP 88 | guacd -> Domain Controller | Kerberos AS-REQ/TGS-REQ |
| TCP 443 | guacd -> KDC Proxy | HTTPS KDC Proxy tunnel (only if using `kdc-url`) |
| TCP 3389 | guacd -> RDP target | RDP connection |

If using a **KDC Proxy URL** (`kdc-url`), direct access to port 88 is not needed. The KDC Proxy protocol tunnels Kerberos messages over HTTPS, making it ideal for environments where the guacd server is on a different network than the domain controller.

#### Time synchronisation

Kerberos has a default clock skew tolerance of **5 minutes**. Ensure NTP is configured on the rustguac server:

```bash
timedatectl status   # verify time is synced
```

#### DNS requirements

**The RDP target hostname MUST be a fully-qualified domain name (FQDN).** Kerberos constructs a service principal name (`TERMSRV/server.example.com@REALM`) from the hostname. Using IP addresses or NetBIOS short names will cause Kerberos ticket acquisition to fail.

For automatic KDC discovery (without `kdc-url` or `krb5.conf`), the domain needs DNS SRV records:

```
_kerberos._tcp.EXAMPLE.COM.  SRV  0 0 88  dc1.example.com.
```

The guacd server itself does not need to be domain-joined — it only needs network access to the KDC.

### KDC discovery: three options

FreeRDP/libkrb5 finds the KDC in this order of priority:

**Option 1: KDC Proxy URL (simplest for remote networks)**

Set the **KDC URL** field on the address book entry to your KDC Proxy endpoint (e.g., `https://dc.example.com/KdcProxy`). This bypasses DNS SRV and krb5.conf entirely. Windows Server's KDC Proxy Service can serve this role.

**Option 2: DNS SRV records (simplest for on-network)**

If the guacd server uses the domain's DNS servers and `_kerberos._tcp.REALM` SRV records exist, Kerberos will discover the KDC automatically. No configuration needed on the guacd host.

**Option 3: /etc/krb5.conf (explicit configuration)**

If DNS SRV records are not available and you're not using a KDC proxy, create `/etc/krb5.conf`:

```ini
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    udp_preference_limit = 1

[realms]
    EXAMPLE.COM = {
        kdc = tcp/dc1.example.com
        admin_server = dc1.example.com
    }
    example.com = {
        kdc = tcp/dc1.example.com
        admin_server = dc1.example.com
    }

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM
```

Important notes for krb5.conf:

- **Define realms in both uppercase AND lowercase** — GSSAPI on Linux is case-sensitive (unlike Windows)
- **Use `tcp/` prefix** for KDC entries to force TCP transport (avoids UDP response size issues)
- **A broken krb5.conf is worse than none** — if krb5.conf points to unreachable KDCs, FreeRDP 3 can **hang indefinitely** during authentication (deadlock in the SSPI/Negotiate layer). Delete or fix any stale krb5.conf.

### Username format

Use **UPN format** for usernames: `user@EXAMPLE.COM` (e.g., `jdoe@CORP.EXAMPLE.COM`). This is more reliable with GSSAPI on Linux than the `DOMAIN\user` format.

The **Domain** field should be the AD domain name (e.g., `EXAMPLE.COM`).

### Example: Kerberos RDP entry

Create an address book entry with:

- **Type**: RDP
- **Hostname**: `fileserver.corp.example.com` (must be FQDN)
- **Port**: 3389
- **Security**: NLA
- **NLA Auth Package**: Kerberos
- **KDC URL**: `https://dc.corp.example.com/KdcProxy` (if KDC is not directly reachable)
- **Prompt for credentials**: checked (users supply their own AD credentials)
- **Domain**: `CORP.EXAMPLE.COM`

When a user connects, they'll be prompted for username, password, and domain. The connection will authenticate via Kerberos NLA to the target.

### guacd patch details

The Kerberos NLA support is provided by patch `002-kerberos-nla.patch`, which adds three connection parameters to guacd's RDP handler:

| Parameter | FreeRDP 3 setting | Description |
|-----------|-------------------|-------------|
| `auth-pkg` | `AuthenticationPackageList` | `kerberos` sets `!ntlm,kerberos`; `ntlm` sets `ntlm,!kerberos`; empty negotiates |
| `kdc-url` | `KerberosKdcUrl` | KDC or KDC Proxy URL — overrides DNS SRV and krb5.conf |
| `kerberos-cache` | `KerberosCache` | Path to a credential cache (ccache) file — advanced use |

This patch is based on the upstream [GUACAMOLE-2057](https://issues.apache.org/jira/browse/GUACAMOLE-2057) work (guacamole-server PR #581), adapted for FreeRDP 3.x on Debian 13. Differences from upstream: dropped the FreeRDP 2 code path, fixed a `guac_strdup()` memory leak, and fixed typos.

### Troubleshooting

**Enable Kerberos tracing** by adding to the rustguac environment file:

```bash
echo 'KRB5_TRACE=/dev/stderr' >> /opt/rustguac/env
sudo systemctl restart rustguac
# View trace output:
journalctl -u rustguac -f
```

**Test Kerberos manually** from the guacd server:

```bash
# Check DNS SRV records
dig SRV _kerberos._tcp.EXAMPLE.COM

# Test obtaining a ticket
kinit user@EXAMPLE.COM
klist

# Test RDP directly with xfreerdp3
xfreerdp3 /v:server.example.com /u:user@EXAMPLE.COM /d:EXAMPLE.COM \
  /auth-pkg-list:'!ntlm,kerberos' /cert:ignore
```

**Common issues:**

| Problem | Cause | Fix |
|---------|-------|-----|
| Connection hangs indefinitely | Broken `/etc/krb5.conf` with unreachable KDC entries | Delete or fix krb5.conf, or use `kdc-url` instead |
| "Authentication failed" | Wrong username format, unreachable KDC, or wrong domain | Use UPN format (`user@REALM`), verify KDC connectivity |
| "Clock skew too great" | Time out of sync by more than 5 minutes | Configure NTP: `timedatectl set-ntp true` |
| Kerberos fails, no NTLM fallback | `auth-pkg` set to `kerberos` disables NTLM | Fix Kerberos setup, or use default (negotiate) to allow fallback |
| "Cannot resolve host" / SPN failure | RDP hostname is an IP or short name | Use FQDN (e.g., `server.example.com` not `server` or `10.0.1.5`) |
| TGT succeeds but TGS fails | SPN mismatch — hostname doesn't match AD computer object | Verify the hostname matches the AD computer account's DNS name |

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
