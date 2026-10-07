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

**Connections mode** (operator+):

    /api/connect?scope=shared&folder=production&entry=web-server-01

| Parameter | Type | Description |
|-----------|------|-------------|
| `protocol` | string | `ssh`, `rdp`, `vnc`, or `web` (default: ssh) |
| `hostname` | string | Target hostname or IP |
| `port` | integer | Target port (uses protocol default if omitted) |
| `username` | string | Username (optional) |
| `url` | string | Target URL (web sessions) |
| `scope` | string | Connections scope: `shared` or `instance` |
| `folder` | string | Connections folder name |
| `entry` | string | Connections entry name |
| `width` | integer | Display width in pixels |
| `height` | integer | Display height in pixels |
| `dpi` | integer | Display DPI |

When `scope`, `folder`, and `entry` are all provided, the endpoint connects via the connections (credentials from Vault). Otherwise it creates an ad-hoc session. No credentials are passed in the URL for ad-hoc mode — if the target requires authentication, the user will see guacd's login prompt.

If the connections entry has `prompt_credentials: true` or has no stored password/key, the endpoint returns an inline credential form instead of creating the session immediately. The user enters credentials, which are POSTed to the connect endpoint and used for that session only (never stored).

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

**Web session with autofill and domain restriction:**

```json
{
  "session_type": "web",
  "url": "https://www.saucedemo.com",
  "username": "standard_user",
  "password": "secret_sauce",
  "autofill": "[{\"url\":\"https://www.saucedemo.com\",\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}]",
  "allowed_domains": ["saucedemo.com"],
  "disable_copy": true
}
```

The `autofill` field is a JSON string containing an array of objects with `url`, `username`, and `password`. The placeholders `$USERNAME` and `$PASSWORD` are substituted with the session's credentials. Multiple entries support SSO redirect chains where credentials are needed on different domains.

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
| `session_type` | string | All | `ssh`, `rdp`, `vnc`, `spice`, `proxmox`, `web`, or `vdi` (required) |
| `hostname` | string | SSH, RDP, VNC | Target hostname or IP |
| `port` | integer | SSH, RDP, VNC | Target port (defaults: SSH=22, RDP=3389, VNC=5900) |
| `username` | string | SSH, RDP, VNC | Username for authentication (VNC: only for servers with username auth, e.g. VeNCrypt, RealVNC, macOS) |
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
| `disable_copy` | boolean | All | Disable clipboard copy (server → client) |
| `disable_paste` | boolean | All | Disable clipboard paste (client → server) |
| `autofill` | string | Web | JSON array of autofill credentials (see below) |
| `allowed_domains` | array | Web | Domain allowlist — browser can only reach these domains |
| `login_script` | string | Web | Login script filename (relative to `login_scripts_dir`) |
| `jump_hosts` | array | All | Multi-hop SSH tunnel chain (see below) |
| `width` | integer | All | Display width in pixels |
| `height` | integer | All | Display height in pixels |
| `dpi` | integer | All | Display DPI |
| `banner` | string | All | Banner message shown before session starts |
| `owner` | string | All | Create the session on behalf of this user (their login email). Admin callers only, see [Creating a session for someone else](#creating-a-session-for-someone-else) |

**SPICE fields** (`session_type: spice`, direct connection to a SPICE server):

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | string | SPICE server hostname or IP (required) |
| `port` | integer | SPICE port (default 5900) |
| `password` | string | SPICE password / ticket |
| `spice_tls` | boolean | Connect using TLS |
| `spice_tls_port` | integer | TLS port, when different from `port` |
| `spice_ca_cert` | string | PEM CA certificate for TLS verification |
| `spice_cert_subject` | string | Expected TLS certificate subject |
| `spice_proxy` | string | SPICE proxy URL, e.g. `http://host:3128` |
| `ignore_cert` | boolean | Accept any TLS certificate (insecure) |
| `color_depth` | integer | Color depth in bits |

**Proxmox VE console fields** (`session_type: proxmox`, SPICE brokered through the PVE API):

| Field | Type | Description |
|-------|------|-------------|
| `proxmox_url` | string | PVE API base URL including scheme and port, e.g. `https://pve.example.com:8006` (required) |
| `proxmox_vmid` | integer | VM id whose console to open (required) |
| `proxmox_node` | string | Cluster node hosting the VM. Optional: auto-resolved from the VM id (via `/cluster/resources`) when left blank |
| `proxmox_token_id` | string | API token id, formatted `user@realm!tokenname` |
| `proxmox_token_secret` | string | API token secret (the UUID half) |
| `proxmox_verify_tls` | boolean | Verify the PVE / SPICE-proxy TLS certificate (default false; PVE ships a self-signed cluster cert) |

The token needs `VM.Console` (and `VM.Audit` for node auto-detect) on the target VM. rustguac calls the PVE `spiceproxy` API at connect to fetch a one-time SPICE ticket, so nothing sensitive is stored beyond the token.

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
  "status": "pending",
  "client_url": "/client/550e8400-e29b-41d4-a716-446655440000",
  "ws_url": "/ws/550e8400-e29b-41d4-a716-446655440000",
  "share_url": "/client/550e8400-e29b-41d4-a716-446655440000?token=abc123",
  "share_url_readonly": "/client/550e8400-e29b-41d4-a716-446655440000?token=def456"
}
```

- `client_url` opens the session in the built-in client (see [Connecting to a session](#connecting-to-a-session)).
- `ws_url` is the raw WebSocket endpoint for a custom client.
- `share_url` is present only when sharing is allowed; its `token` lets a second viewer **join** an active session with keyboard, mouse and clipboard control (it is not owner access).
- `share_url_readonly` is present whenever `share_url` is. It joins the same session view-only: guacd ignores that participant's keyboard, mouse and clipboard input. It is a separate token, so the recipient cannot turn it into the control link.
- Both share URLs are shown only to the session's creator and to admins.

### Creating a session for someone else

A backend that creates sessions with an API key and then opens them in a user's own browser (where the user is logged in through OIDC) must name that user as the session's `owner`:

```json
{
  "session_type": "ssh",
  "hostname": "10.0.0.5",
  "owner": "engineer@example.com"
}
```

- The session is recorded as created by `owner`, so session history and reports name the person rather than the API key.
- Only `owner` can make the first connection to the session (see [Owner vs. join](#owner-vs-join)). The match is on the login email, ignoring case.
- `owner` is accepted from admin callers only (API keys are always admin). Anyone else gets `403`.
- Without `owner`, the session belongs to the caller, as before.

### `GET /api/sessions`

List all sessions. Requires **operator** role or higher.

### `GET /api/sessions/:id`

Get session details. Requires **operator** role or higher.

### `DELETE /api/sessions/:id`

Terminate a session. Requires **operator** role or higher. Non-admins can only delete their own sessions.

### `POST /api/sessions/:id/shadow`

Mint a short-lived token that lets an admin join another user's **active** session. Requires **admin** role. The body is optional:

```json
{ "read_only": true }
```

`read_only` defaults to `false` (keyboard and mouse control). With `true` the admin watches without being able to type or click.

```json
{
  "url": "/client/550e8400-e29b-41d4-a716-446655440000?token=...",
  "expires_at": "2026-10-01T04:10:00+00:00",
  "ttl_seconds": 600,
  "read_only": true
}
```

The token is valid for 10 minutes and every use is written to the audit log. A session whose owner has not connected yet returns `409`: the owner must connect first.

### `GET /api/sessions/:id/banner`

Get session banner text. Authenticates via share token (not credentials). Used for the ephemeral keypair banner display.

## Connecting to a session

Creating a session (`POST /api/sessions`) only opens the connection to the target; it does **not** display anything. A browser then attaches over a WebSocket to stream the session. Understanding the two connection roles avoids the most common integration mistake.

### Owner vs. join

- The **first** connection to a freshly created session is the **owner** connection. It requires an authenticated identity with the **operator** role or higher that is the session's creator: the caller that created it, or the `owner` it was created for. No other user can make it, admins included.
- A **share token** (`share_url` or `share_url_readonly`) or an admin **shadow token** only lets another viewer **join** a session that is already active. It is not an identity and cannot open the owner connection.

If the owner connection is not authenticated, or is authenticated as someone other than the creator, rustguac rejects the WebSocket with `403`, no browser attaches, and guacd eventually reports `User is not responding` (its timeout for a session whose client never arrived, roughly 15 seconds after creation). If you see `User is not responding`, the browser did not connect as the session's authenticated owner. A backend that creates sessions with an API key for a user who then connects with their own login must set `owner` (see [Creating a session for someone else](#creating-a-session-for-someone-else)).

### Authenticating the owner connection

The built-in client (`client_url`) authenticates the owner WebSocket one of three ways:

1. **OIDC session cookie** — the user is logged into rustguac in that browser. Open `client_url` and the cookie authenticates.
2. **`sessionStorage.rustguac_api_key`** — the client exchanges the key for a single-use ticket before connecting.
3. **A ws-ticket in the URL** — `client_url?ticket=<ticket>`. Used for headless integrations (below).

### `POST /api/ws-ticket`

Exchange an API key or OIDC session for a **single-use, short-lived** WebSocket ticket. Requires an authenticated identity with **operator** role or higher.

```
POST /api/ws-ticket
Authorization: Bearer <api-key>
```

```json
{ "ticket": "wst_1a2b3c..." }
```

The ticket is valid for 30 seconds, may be used once, and inherits the caller's role. Present it on the WebSocket as `/ws/{id}?ticket=<ticket>`, or on the built-in client as `/client/{id}?ticket=<ticket>` (the page GET does not consume it; the WebSocket does).

### Headless API integration

When the browser has no rustguac login of its own (no OIDC cookie), a backend that holds an API key can still hand off a ready-to-open session without exposing that key to the browser:

1. `POST /api/sessions` (Bearer API key) to create the session.
2. `POST /api/ws-ticket` (Bearer API key) to mint a ticket. The ticket carries the API key's identity, which is the session's creator, so the owner connection is accepted. Do not set `owner` in this flow: the ticket would then belong to someone other than the owner and be refused.
3. Send the browser to `client_url?ticket=<ticket>` (i.e. `/client/{id}?ticket=wst_...`).

The single-use, 30-second ticket is safe to place in a URL; the durable API key never leaves the backend. Because guacd drops a session whose client has not attached within ~15 seconds, mint the ticket and open the browser promptly after creating the session (on a reload, mint a fresh ticket).

### Custom clients

To build your own client, open the WebSocket at `ws_url` with the `guacamole` sub-protocol and a `?ticket=<ticket>` query parameter, then speak the [Guacamole protocol](https://guacamole.apache.org/doc/gug/guacamole-protocol.html). This is the same endpoint the built-in client uses.

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

## Connections (requires Vault)

### `GET /api/addressbook/folders`

List visible folders. Filtered by OIDC group membership (admins see all).

### `GET /api/addressbook/folders/:scope/:folder/entries`

List entries in a folder. Scope is `shared` or `instance`. Requires folder group access.

### `POST /api/addressbook/folders/:scope/:folder/entries/:entry/connect`

Create a session from an connections entry. Reads credentials (including jump host credentials) from Vault server-side and creates a session. Requires **operator** role and folder group access.

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

**Connections entry fields:**

| Field | Type | Used by | Description |
|-------|------|---------|-------------|
| `type` | string | All | `ssh`, `rdp`, `vnc`, `spice`, `proxmox`, `web`, or `vdi` |
| `hostname` | string | SSH, RDP, VNC | Target hostname or IP |
| `port` | integer | SSH, RDP, VNC | Target port |
| `username` | string | SSH, RDP, VNC | Username |
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
| `disable_copy` | boolean | All | Disable clipboard copy (server → client) |
| `disable_paste` | boolean | All | Disable clipboard paste (client → server) |
| `autofill` | string | Web | JSON array of autofill credentials |
| `allowed_domains` | array | Web | Domain allowlist for the browser session |
| `login_script` | string | Web | Login script filename |
| `display_name` | string | All | Friendly display name (shown as banner) |
| `prompt_credentials` | boolean | All | Prompt user for credentials at connect time |
| `jump_hosts` | array | All | Multi-hop SSH tunnel chain (same format as session creation) |

For `spice` and `proxmox` entries, the `spice_*` and `proxmox_*` fields listed under [`POST /api/sessions`](#post-apisessions) apply here too. The `proxmox_token_secret` is write-only: it is never returned by the read endpoints (a `has_proxmox_token_secret` boolean indicates whether one is stored), and it is preserved on update when omitted.

### `PUT /api/addressbook/folders/:scope/:folder/entries/:entry` (admin)

Update a connection entry. Uses read-modify-write: reads existing entry from Vault, merges incoming fields on top. Credentials (`password`, `private_key`) that are omitted from the request are preserved from the existing entry. Jump host credentials are merged per-hop by index.

### `DELETE /api/addressbook/folders/:scope/:folder/entries/:entry` (admin)

Delete a connection entry. Returns `404` if there is no such entry.

### `POST /api/addressbook/folders/:scope/:folder/entries/:entry/move` (admin)

Move an entry to another folder with everything stored in it, credentials included. The entry is written to the target first and the original is removed only after that succeeds.

```json
{ "target_scope": "shared", "target_folder": "servers/linux" }
```

Returns `409` if an entry of the same name already exists in the target (it is never overwritten), and `400` for an invalid scope, folder or name. If the copy succeeds but the original cannot be removed, the response is `502` with `"copied": true`: the entry then exists in both folders.

Do not move an entry by creating it in the new folder and deleting the old one: the read endpoints never return credentials, so a copy made that way has none.

### `POST /api/addressbook/folders/:scope/:folder/entries/:entry/copy` (admin)

Copy an entry, credentials included, to `target_scope`/`target_folder` under `new_name` (default: the same name). Returns `409` if the target exists. Apply further changes to the copy with the `PUT` above, which keeps stored credentials it is not given.

```json
{ "target_scope": "shared", "target_folder": "servers/linux", "new_name": "web01-copy" }
```

### `POST /api/addressbook/bulk` (admin)

Move, copy or delete up to 1000 entries in one request. Each entry is handled on its own, with the same rules as the single-entry endpoints above: credentials go with moved and copied entries, an existing entry is never overwritten, and a move removes the original only after the copy is written.

```json
{
  "action": "move",
  "items": [
    { "scope": "shared", "folder": "imported", "name": "web01" },
    { "scope": "shared", "folder": "imported", "name": "web02" }
  ],
  "target": { "scope": "shared", "folder": "servers/linux" },
  "on_conflict": "skip"
}
```

- `action` is `move`, `copy` or `delete`. `target` is required for `move` and `copy`.
- `on_conflict` decides what happens when the target already has an entry of the same name: `skip` (default) leaves that entry where it is, `rename` uses the first free `name-2`, `name-3`, and so on. There is no overwrite option.

The response lists what happened to each entry, plus a count per outcome:

```json
{
  "results": [
    { "scope": "shared", "folder": "imported", "name": "web01", "status": "moved" },
    { "scope": "shared", "folder": "imported", "name": "web02", "status": "skipped",
      "error": "an entry with that name already exists in the target folder" }
  ],
  "summary": { "moved": 1, "skipped": 1 }
}
```

`status` is one of `moved`, `copied`, `deleted`, `skipped`, `failed`, or `copied_not_removed` (a move whose copy was written but whose original could not be removed, so the entry is in both folders). A renamed copy also carries `new_name`. Every entry acted on is recorded in the address book audit log.

### `GET /api/addressbook/folder-paths` (admin)

Every folder in both scopes, as `{ "folders": [{ "scope": "shared", "path": "servers/linux" }, ...] }`. Used to choose a target for bulk moves and copies.

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
