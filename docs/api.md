# API Reference

All API endpoints are under `/api/`. Authentication is via `Authorization: Bearer <api-key>` header, `X-API-Key: <key>` header, or OIDC session cookie.

## Health

### `GET /api/health`

No authentication required. Returns 200 OK when the server is running.

## Quick Connect

### `GET /api/connect`

Quick-connect endpoint for external integrations (e.g., NetBox Custom Links). Creates a session and redirects to the client page. If the user is not authenticated and OIDC is configured, redirects to SSO login and back after authentication.

**Ad-hoc mode** (poweruser+):

    /api/connect?hostname=10.0.1.50&protocol=ssh

**Address book mode** (operator+):

    /api/connect?scope=shared&folder=production&entry=web-server-01

| Parameter | Type | Description |
|-----------|------|-------------|
| `protocol` | string | `ssh`, `rdp`, `vnc`, or `web` (default: ssh) |
| `hostname` | string | Target hostname or IP |
| `port` | integer | Target port (uses protocol default if omitted) |
| `username` | string | Username (optional) |
| `url` | string | Target URL (web sessions) |
| `scope` | string | Address book scope: `shared` or `instance` |
| `folder` | string | Address book folder name |
| `entry` | string | Address book entry name |
| `width` | integer | Display width in pixels |
| `height` | integer | Display height in pixels |
| `dpi` | integer | Display DPI |

When `scope`, `folder`, and `entry` are all provided, the endpoint connects via the address book (credentials from Vault). Otherwise it creates an ad-hoc session. No credentials are passed in the URL for ad-hoc mode — if the target requires authentication, the user will see guacd's login prompt.

If the address book entry has `prompt_credentials: true` or has no stored password/key, the endpoint returns an inline credential form instead of creating the session immediately. The user enters credentials, which are POSTed to the connect endpoint and used for that session only (never stored).

See [NetBox Integration](netbox.md) for usage with NetBox Custom Links.

## Sessions

### `POST /api/sessions`

Create a new session. Requires **poweruser** role or higher.

**SSH session (password):**

```json
{
  "session_type": "ssh",
  "hostname": "10.0.0.1",
  "port": 22,
  "username": "root",
  "password": "secret"
}
```

**SSH session (ephemeral keypair):**

```json
{
  "session_type": "ssh",
  "hostname": "10.0.0.1",
  "username": "root",
  "generate_keypair": true
}
```

The response includes the public key in the `banner_text` field. The SSH connection is deferred until the user clicks "Continue" on the banner page.

**SSH session (private key):**

```json
{
  "session_type": "ssh",
  "hostname": "10.0.0.1",
  "username": "root",
  "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
}
```

**RDP session:**

```json
{
  "session_type": "rdp",
  "hostname": "10.0.0.1",
  "port": 3389,
  "username": "Administrator",
  "password": "secret",
  "ignore_cert": true,
  "domain": "EXAMPLE"
}
```

**RDP session with Kerberos NLA:**

```json
{
  "session_type": "rdp",
  "hostname": "fileserver.corp.example.com",
  "port": 3389,
  "username": "jdoe@CORP.EXAMPLE.COM",
  "password": "secret",
  "domain": "CORP.EXAMPLE.COM",
  "security": "nla",
  "auth_pkg": "kerberos",
  "kdc_url": "https://dc.corp.example.com/KdcProxy"
}
```

**VNC session:**

```json
{
  "session_type": "vnc",
  "hostname": "10.0.0.1",
  "port": 5900,
  "password": "vnc-secret"
}
```

**Web browser session:**

```json
{
  "session_type": "web",
  "url": "https://example.com"
}
```

**Session with multi-hop SSH tunnel (any type):**

```json
{
  "session_type": "rdp",
  "hostname": "10.10.10.1",
  "port": 3389,
  "username": "Administrator",
  "password": "secret",
  "jump_hosts": [
    {
      "hostname": "bastion.example.com",
      "port": 22,
      "username": "jump-user",
      "password": "jump-pass"
    },
    {
      "hostname": "internal-gw.corp.local",
      "port": 22,
      "username": "gw-user",
      "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
    }
  ]
}
```

**Web session with SSH tunnel:**

```json
{
  "session_type": "web",
  "url": "https://internal-app.corp.local:8443/dashboard",
  "jump_hosts": [
    {
      "hostname": "bastion.example.com",
      "port": 22,
      "username": "jump-user",
      "password": "jump-pass"
    }
  ]
}
```

For web sessions, the tunnel forwards to the URL's host and port (inferred from the scheme: 80 for HTTP, 443 for HTTPS, or explicit port in the URL). The URL is rewritten to `{scheme}://127.0.0.1:{tunnel_port}{path}` for Chromium. HTTPS targets will show certificate warnings since the hostname changes.

The `jump_hosts` array defines an ordered chain of SSH bastion hops. Each hop connects through the previous hop's tunnel. The final hop forwards to the session target. Jump hosts are supported for all session types.

**Legacy single jump host fields** (`jump_host`, `jump_port`, `jump_username`, `jump_password`, `jump_private_key`) are still accepted for backward compatibility but `jump_hosts` takes precedence when both are provided.

**All session fields:**

| Field | Type | Used by | Description |
|-------|------|---------|-------------|
| `session_type` | string | All | `ssh`, `rdp`, `vnc`, or `web` (required) |
| `hostname` | string | SSH, RDP, VNC | Target hostname or IP |
| `port` | integer | SSH, RDP, VNC | Target port (defaults: SSH=22, RDP=3389, VNC=5900) |
| `username` | string | SSH, RDP | Username for authentication |
| `password` | string | SSH, RDP, VNC | Password (VNC uses this as the VNC password) |
| `private_key` | string | SSH | OpenSSH PEM private key |
| `generate_keypair` | boolean | SSH | Generate an ephemeral Ed25519 keypair |
| `url` | string | Web | Target URL for web browser session |
| `domain` | string | RDP | Windows domain |
| `security` | string | RDP | `tls`, `nla`, or `rdp` |
| `ignore_cert` | boolean | RDP | Ignore TLS certificate errors |
| `auth_pkg` | string | RDP | NLA auth package: `kerberos`, `ntlm`, or empty (negotiate) |
| `kdc_url` | string | RDP | Kerberos KDC or KDC Proxy URL |
| `kerberos_cache` | string | RDP | Path to Kerberos credential cache (advanced) |
| `color_depth` | integer | RDP | Color depth in bits (8, 16, 24, 32) |
| `enable_drive` | boolean | RDP, SSH | Enable file transfer / drive redirection |
| `jump_hosts` | array | All | Multi-hop SSH tunnel chain (see below) |
| `width` | integer | All | Display width in pixels |
| `height` | integer | All | Display height in pixels |
| `dpi` | integer | All | Display DPI |
| `banner` | string | All | Banner message shown before session starts |

**Jump host object fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hostname` | string | Yes | SSH bastion hostname |
| `port` | integer | No | SSH port (default: 22) |
| `username` | string | Yes | SSH username |
| `password` | string | No | SSH password |
| `private_key` | string | No | OpenSSH PEM private key |

**Response:**

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_url": "/client/550e8400-e29b-41d4-a716-446655440000",
  "share_url": "/client/550e8400-e29b-41d4-a716-446655440000&key=abc123"
}
```

### `GET /api/sessions`

List all sessions. Requires **operator** role or higher.

### `GET /api/sessions/:id`

Get session details. Requires **operator** role or higher.

### `DELETE /api/sessions/:id`

Terminate a session. Requires **operator** role or higher. Non-admins can only delete their own sessions.

### `GET /api/sessions/:id/banner`

Get session banner text. Authenticates via share token (not credentials). Used for the ephemeral keypair banner display.

## Recordings

### `GET /api/recordings`

List all recording files. Requires **operator** role or higher.

### `GET /api/recordings/:name`

Serve a recording file for playback. Requires **operator** role or higher. Filename is validated against path traversal.

### `DELETE /api/recordings/:name`

Delete a recording file. Requires **admin** role.

## Users (admin only)

### `GET /api/users`

List all OIDC users.

### `PUT /api/users/:email/role`

Set a user's role.

```json
{
  "role": "poweruser"
}
```

Valid roles: `admin`, `poweruser`, `operator`, `viewer`.

### `DELETE /api/users/:email`

Delete a user.

### `POST /api/users/:email/disable`

Disable a user (blocks login).

### `POST /api/users/:email/enable`

Re-enable a disabled user.

### `DELETE /api/users/:email/sessions`

Force-logout a user by deleting all their auth sessions.

## Group-to-Role Mappings (admin only)

### `GET /api/admin/group-mappings`

List all group-to-role mappings.

### `POST /api/admin/group-mappings`

Create a mapping.

```json
{
  "oidc_group": "engineering",
  "role": "poweruser"
}
```

Returns 409 Conflict if a mapping for the group already exists.

### `PUT /api/admin/group-mappings/:id`

Update a mapping.

```json
{
  "oidc_group": "engineering",
  "role": "admin"
}
```

### `DELETE /api/admin/group-mappings/:id`

Delete a mapping.

## Address Book (requires Vault)

### `GET /api/addressbook/folders`

List visible folders. Filtered by OIDC group membership (admins see all).

### `GET /api/addressbook/folders/:scope/:folder/entries`

List entries in a folder. Scope is `shared` or `instance`. Requires folder group access.

### `POST /api/addressbook/folders/:scope/:folder/entries/:entry/connect`

Create a session from an address book entry. Reads credentials (including jump host credentials) from Vault server-side and creates a session. Requires **operator** role and folder group access.

Optional body to override or supply credentials at connect time:

```json
{
  "username": "jdoe@CORP.EXAMPLE.COM",
  "password": "user-password",
  "domain": "CORP.EXAMPLE.COM",
  "banner": "Custom banner message",
  "width": 1920,
  "height": 1080,
  "dpi": 96
}
```

Prompted credentials are used for the current session only and are never stored. Jump host credentials always come from the Vault entry and cannot be overridden at connect time.

### `POST /api/addressbook/folders` (admin)

Create a folder.

```json
{
  "scope": "shared",
  "name": "production",
  "allowed_groups": ["engineering", "devops"],
  "description": "Production servers"
}
```

### `PUT /api/addressbook/folders/:scope/:folder` (admin)

Update folder configuration (allowed_groups, description).

### `DELETE /api/addressbook/folders/:scope/:folder` (admin)

Delete a folder and all its entries.

### `POST /api/addressbook/folders/:scope/:folder/entries` (admin)

Create a connection entry. The body includes a `name` field plus all entry fields:

```json
{
  "name": "prod-db",
  "type": "ssh",
  "hostname": "db.internal.example.com",
  "port": 22,
  "username": "admin",
  "password": "secret",
  "jump_hosts": [
    {
      "hostname": "bastion.example.com",
      "port": 22,
      "username": "jump-user",
      "password": "jump-pass"
    }
  ]
}
```

**Address book entry fields:**

| Field | Type | Used by | Description |
|-------|------|---------|-------------|
| `type` | string | All | `ssh`, `rdp`, `vnc`, or `web` |
| `hostname` | string | SSH, RDP, VNC | Target hostname or IP |
| `port` | integer | SSH, RDP, VNC | Target port |
| `username` | string | SSH, RDP | Username |
| `password` | string | SSH, RDP, VNC | Password |
| `private_key` | string | SSH | OpenSSH PEM private key |
| `url` | string | Web | Target URL |
| `domain` | string | RDP | Windows domain |
| `security` | string | RDP | Security mode |
| `ignore_cert` | boolean | RDP | Ignore certificate errors |
| `auth_pkg` | string | RDP | NLA auth package |
| `kdc_url` | string | RDP | Kerberos KDC URL |
| `color_depth` | integer | RDP | Color depth |
| `enable_drive` | boolean | RDP, SSH | Enable file transfer |
| `display_name` | string | All | Friendly display name (shown as banner) |
| `prompt_credentials` | boolean | All | Prompt user for credentials at connect time |
| `jump_hosts` | array | All | Multi-hop SSH tunnel chain (same format as session creation) |

### `PUT /api/addressbook/folders/:scope/:folder/entries/:entry` (admin)

Update a connection entry. Uses read-modify-write: reads existing entry from Vault, merges incoming fields on top. Credentials (`password`, `private_key`) that are omitted from the request are preserved from the existing entry. Jump host credentials are merged per-hop by index.

### `DELETE /api/addressbook/folders/:scope/:folder/entries/:entry` (admin)

Delete a connection entry.

## User API Tokens (self-service)

User API tokens allow OIDC users to authenticate via API key for automation and scripting. Tokens inherit the user's identity and are subject to role restrictions.

### `POST /api/me/tokens`

Create a personal API token. Requires **poweruser** role or higher. Only available to OIDC-authenticated users (not API key admins).

```json
{
  "name": "my-ci-token",
  "max_role": "operator",
  "expires_at": "2026-12-31T23:59:59Z"
}
```

- `name` — required, 1-100 characters, must be unique per user
- `max_role` — optional, caps the token's effective role (cannot exceed the user's current role)
- `expires_at` — optional, ISO 8601 timestamp

**Response:**

```json
{
  "id": 1,
  "name": "my-ci-token",
  "token": "rgu_a1b2c3d4e5f6...",
  "max_role": "operator",
  "expires_at": "2026-12-31T23:59:59Z"
}
```

The `token` field is the plaintext token — it is only returned once at creation and cannot be retrieved again.

### `GET /api/me/tokens`

List your own tokens. Available to any OIDC user (operator+). Returns token metadata only (never the plaintext token).

### `DELETE /api/me/tokens/:id`

Revoke one of your own tokens. Requires **poweruser** role or higher. The token is immediately invalidated.

## User API Tokens (admin)

Admins can manage tokens for any user, including creating tokens for operators who cannot create their own.

### `POST /api/admin/user-tokens`

Create a token for any OIDC user. Requires **admin** role.

```json
{
  "email": "operator@example.com",
  "name": "operator-automation",
  "max_role": "operator",
  "expires_at": "2026-06-30T23:59:59Z"
}
```

Response is the same as `POST /api/me/tokens`.

### `GET /api/admin/user-tokens`

List all user tokens across all users. Requires **admin** role.

### `DELETE /api/admin/user-tokens/:id`

Revoke any user token. Requires **admin** role.

### `GET /api/admin/token-audit`

View the token audit log. Requires **admin** role.

**Query parameters:**

- `limit` — max entries to return (default: 200, max: 1000)
- `email` — filter by user email

Returns an array of audit events with fields: `created_at`, `user_email`, `token_name`, `action`, `ip_addr`, `details`.

## Authentication

### `GET /api/auth/status`

No authentication required. Returns whether OIDC is enabled and the site title.

```json
{
  "oidc_enabled": true,
  "site_title": "rustguac"
}
```

### `GET /api/me`

Returns current user info. Requires authentication.

```json
{
  "name": "User Name",
  "email": "user@example.com",
  "role": "operator",
  "groups": ["engineering"],
  "auth_type": "oidc",
  "vault_enabled": true,
  "vault_configured": true
}
```

### `GET /auth/login`

Redirects to OIDC provider for authentication.

### `GET /auth/callback`

OIDC callback endpoint. Handles token exchange, user creation/update, and session creation.

### `GET /auth/logout`

Clears the session cookie and deletes the auth session.
