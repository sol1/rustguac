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
| `protocol` | string | Ad-hoc mode: `ssh`, `rdp`, `vnc`, or `web` (default: ssh). Connections mode: which of the entry's [protocols](#multi-protocol-entries) to open, by name (falling back to type); default the primary |
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

In connections mode, `&protocol=ssh` opens the entry's SSH protocol; links without it open the primary, so links made before multi-protocol entries keep working. A protocol the user may not use is answered like one that does not exist (`404`).

If the connections entry has `prompt_credentials: true` or has no stored password/key, the endpoint returns an inline credential form instead of creating the session immediately. The user enters credentials, which are POSTed to the connect endpoint and used for that session only (never stored). An entry without its own secret that is covered by [folder default credentials](credential-variables.md#folder-default-credentials) connects with those, exactly as it does from the Connections page.

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
  "url": "https://app.example.com",
  "username": "demo-user",
  "password": "demo-pass",
  "autofill": "[{\"url\":\"https://app.example.com\",\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}]",
  "allowed_domains": ["app.example.com"],
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
      "hostname": "internal-gw.example.internal",
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
  "url": "https://internal-app.example.internal:8443/dashboard",
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
| `server_layout` | string | RDP | Keyboard layout, a guacd keymap name such as `de-ch-qwertz` (see [keyboard layout](overview.md#keyboard-layout)). Default: guacd's, US English |
| `ignore_cert` | boolean | RDP | Ignore TLS certificate errors |
| `auth_pkg` | string | RDP | NLA auth package: `kerberos`, `ntlm`, or empty (negotiate) |
| `kdc_url` | string | RDP | Kerberos KDC or KDC Proxy URL |
| `kerberos_cache` | string | RDP | Path to Kerberos credential cache (advanced) |
| `color_depth` | integer | RDP | Color depth in bits (8, 16, 24, 32) |
| `vnc_resize` | boolean | VNC | Ask the VNC server to resize its screen to the browser window (default `false`: the screen is scaled to fit). Only for servers with their own virtual screen (TigerVNC, Xvnc); a physical console such as UltraVNC, RealVNC or x11vnc can't resize, and the session stalls if asked. |
| `vnc_network` | string | VNC | Network preset for the link between the VNC server and rustguac: `auto` (default), `lan`, `wan` or `slow`. See [VNC network presets](overview.md#vnc-network-presets). |
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
| `ssh_font_size` | integer | SSH | Terminal font size in points (default 12, 6 to 72) |
| `wol_send_packet` | boolean | SSH, RDP, VNC | Send a Wake-on-LAN magic packet before connecting |
| `wol_mac_addr` | string | SSH, RDP, VNC | MAC address to wake (required with `wol_send_packet`) |
| `wol_broadcast_addr` | string | SSH, RDP, VNC | Broadcast address for the packet (guacd default `255.255.255.255`) |
| `wol_udp_port` | integer | SSH, RDP, VNC | UDP port for the packet (guacd default 9) |
| `wol_wait_time` | integer | SSH, RDP, VNC | Seconds to wait for the host to boot before connecting (at most 600) |
| `owner` | string | All | Create the session on behalf of this user (their login email). Admin callers only, see [Creating a session for someone else](#creating-a-session-for-someone-else) |

`POST /api/sessions` takes literal values only: it does not resolve [credential variables](credential-variables.md). To connect with them, use [`POST /api/addressbook/adhoc/connect`](#post-apiaddressbookadhocconnect).

**Sessions created by non-admin users.** A request from a poweruser is held to a stricter policy than a connection entry or an admin; the same policy applies to the ad-hoc mode of `GET /api/connect` and to `POST /api/addressbook/adhoc/connect`:

- Every target is checked against the network allowlists, including the first jump host and the Proxmox VE API and SPICE proxy (see [Network allowlists](security.md#network-allowlists-ssrf-protection)).
- Fields that only a connection entry may set are ignored: `address_book_entry`, `address_book_folder`, `entry_display_name`, `max_recordings`, `record_typescript`, `container_username`, `container_password`, `kerberos_cache`, `allow_sharing` and the Wake-on-LAN fields (`wol_*`). A VDI session always uses the caller's own container.
- `enable_recording` can turn recording on, but not off while recording is enabled site-wide.
- `enable_drive` can turn the drive off, but not on while `[drive]` leaves it disabled.
- `container_cpu_limit`, `container_memory_limit` and `container_idle_timeout_mins` above the `[vdi]` defaults (`default_cpu_limit`, `default_memory_limit`, `idle_timeout_mins`) fall back to those defaults. A default of 0 means no limit and caps nothing.

Requests from admins, an admin API key included, are used as sent.

**SPICE fields** (`session_type: spice`, direct connection to a SPICE server):

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | string | SPICE server hostname or IP (required) |
| `port` | integer | SPICE port (default 5900) |
| `password` | string | SPICE password / ticket |
| `spice_tls` | boolean | Connect using TLS |
| `spice_tls_port` | integer | TLS port, when different from `port` (defaults to `port`) |
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

The token needs `VM.Console` (and `VM.Audit` for node auto-detect) on the target VM. rustguac calls the PVE `spiceproxy` API at connect to fetch a one-time SPICE ticket, so nothing sensitive is stored beyond the token. See [SPICE and Proxmox VE Sessions](spice-and-proxmox.md) for the connect flow, TLS options and troubleshooting.

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

List all recording files. Requires **poweruser** role or higher. When MP4 conversion is available on the server, each recording has an `mp4` field with the state of its MP4 (see below); without it, the field is left out.

### `GET /api/recordings/:name`

Serve a recording file for playback. Requires **poweruser** role or higher. Filename is validated against path traversal.

### `POST /api/recordings/:name/mp4`

Start converting a recording to MP4 with guacenc (see [MP4 downloads](configuration.md#mp4-downloads)). Same access as downloading the recording. Responses: `202` `{"state":"running"}` while it converts (asking again while it runs changes nothing); `200` `{"state":"ready","size_bytes":...}` when a converted copy is already there; `409` while the recording's session is still live; `404` for an unknown recording; `503` when conversion is not available on this server.

### `GET /api/recordings/:name/mp4/status`

Where a recording's MP4 stands: `{"state": "none" | "running" | "ready" | "failed" | "unavailable"}`, with `size_bytes` when ready and `error` when failed. A failed conversion is retried by the next `POST`.

### `GET /api/recordings/:name/mp4`

Download the converted MP4 (`video/mp4`, saved as `<recording>.mp4`). `404` until it is ready.

### `DELETE /api/recordings/:name`

Delete a recording file. Requires **admin** role.

## Users (admin only)

### `GET /api/users`

List all OIDC users.

### `POST /api/users`

Add a user ahead of their first OIDC login, which is how anyone gets in when `[oidc] auto_create_users = false`.

```json
{ "email": "jsmith@example.com", "role": "operator", "name": "J Smith" }
```

`role` is one of `admin`, `poweruser`, `operator`, `viewer`; `name` is optional and replaced by the provider's name on login. The email must contain `@`, be at most 254 characters and have no spaces or control characters; the name at most 200 characters. Responses: `201` with the user; `400` for an invalid email, name or role; `409` if a user with that email already exists, ignoring case. See [How a login is matched to a user](roles-and-access-control.md#how-a-login-is-matched-to-a-user).

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

Each entry lists its protocols ([multi-protocol entries](#multi-protocol-entries)); `GET /api/addressbook` and `GET /api/addressbook/search-index` do the same. The top-level fields (`session_type`, `hostname`, `port`, `username`, `has_credentials`, ...) describe the primary, so clients that know nothing of protocols see what they always did. In addition:

| Field | Description |
|-------|-------------|
| `protocol` | Name of the protocol the top-level fields describe |
| `protocols` | Every protocol, in order, each with the same fields as the entry (its effective values: host fields with the protocol's on top) and its `protocol` name |
| `settings` | Admins only: the fields set at that level as stored, for the editor (the host's own at the top level, the protocol's overrides in `protocols`). Secrets appear only as `has_password`, `has_private_key`, ... flags |

### `POST /api/addressbook/folders/:scope/:folder/entries/:entry/connect`

Create a session from an connections entry. Reads credentials (including jump host credentials) from Vault server-side and creates a session. Requires **operator** role and folder group access.

Optional body to override or supply credentials at connect time:

```json
{
  "protocol": "ssh",
  "username": "jdoe@CORP.EXAMPLE.COM",
  "password": "user-password",
  "domain": "CORP.EXAMPLE.COM",
  "banner": "Custom banner message",
  "width": 1920,
  "height": 1080,
  "dpi": 96,
  "keyboard_layout": "de-ch-qwertz"
}
```

`keyboard_layout` is the connecting user's own keyboard (**Settings > My keyboard layout** in the UI). It applies to RDP entries with no `server_layout` of their own, and to VDI desktops. A name guacd doesn't know is ignored.

`protocol` picks one of the entry's protocols by name (or by type, when no protocol has that name); without it the primary is used. A protocol the entry does not have answers `404`. The session records the protocol's name as `address_book_protocol`, and so does its recording (`protocol`).

Prompted credentials are used for the current session only and are never stored. Jump host credentials always come from the Vault entry and cannot be overridden at connect time.

### `POST /api/addressbook/adhoc/connect`

Connect to a host that is not a saved entry (an ad-hoc connection), described with every option an entry has. This is what **Connect to a host** (beside the search box on every page) sends. Requires **poweruser** role or higher. Works without Vault, and shares the session-creation rate limit with `POST /api/sessions`.

```json
{
  "entry": {
    "type": "ssh",
    "hostname": "10.0.0.5",
    "username": "deploy",
    "private_key": "$my_ssh_key",
    "ssh_font_size": 14,
    "jump_hosts": [{ "hostname": "bastion.example.com", "port": 22, "username": "jump" }]
  },
  "generate_keypair": false,
  "width": 1920,
  "height": 1080,
  "screen_width": 2560,
  "screen_height": 1440,
  "dpi": 96
}
```

- `entry` takes the same fields as [creating an entry](#post-apiaddressbookfoldersscopefolderentries-admin), in the same form, with a single `type`: a `protocols` list is refused with `400`. Its name, display name and folder are not used. Legacy single jump host fields are accepted, as on entries.
- `generate_keypair` (SSH): generate an ephemeral Ed25519 keypair, as with `POST /api/sessions`.
- `width`, `height`, `screen_width`, `screen_height`, `dpi`, `keyboard_layout`: as for the entry connect endpoint above.
- [Credential variables](credential-variables.md) (`$name` in `username`, `password`, `domain`, `private_key`) are resolved from the **caller's own** My Credentials, server side; values are never returned. A variable the caller has not set returns `412` with `{"error": "missing credential variables", "missing_variables": ["name"]}`. An API key has no credential variables, so a request from one that uses them returns `400`. Without Vault, references are not resolved.
- [Folder default credentials](credential-variables.md#folder-default-credentials) never apply: an ad-hoc connection belongs to no folder.
- Requests from non-admins get the [ad-hoc policy](#post-apisessions) (network allowlists on every target, including SPICE, Proxmox and jump hosts; entry-only options ignored; site recording, drive and VDI limits).

The response is the same as `POST /api/sessions` (`201`).

### `POST /api/addressbook/folders` (admin)

Create a folder.

```json
{
  "scope": "shared",
  "name": "production",
  "allowed_groups": ["engineering", "devops"],
  "allowed_users": ["oncall@example.com"],
  "description": "Production servers",
  "display_name": "Production",
  "inherit_from_parent": false
}
```

- `allowed_groups`: OIDC groups that can see the folder.
- `allowed_users` (optional): login emails of individual users who can see the folder. They need not have logged in yet. Up to 500 per folder; blanks and repeats (ignoring case) are dropped, and an entry containing spaces or control characters is refused with `400`.
- With both lists empty the folder is admin-only. See [Folder access control](roles-and-access-control.md#folder-access-control).
- `display_name` (optional): a title shown over the folder name in Connections and in search results, for example a customer's full name over a short folder key. The folder name stays the key used in paths and the API. Left out of the stored config when empty.

### `PUT /api/addressbook/folders/:scope/:folder` (admin)

Update folder configuration (`allowed_groups`, `allowed_users`, `description`, `display_name`, `inherit_from_parent`). If `allowed_users` or `display_name` is left out, the stored value is kept as it is; send `[]` or `""` to clear it.

### `GET /api/addressbook/folders/:scope/:folder/config` (admin)

The folder's access settings, including `allowed_users`. The folder listings that operators can read include `allowed_groups` but never `allowed_users`.

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
| `server_layout` | string | RDP | Keyboard layout, a guacd keymap name such as `de-ch-qwertz`. Empty uses the connecting user's own layout if they have set one, otherwise guacd's default (US English) |
| `ignore_cert` | boolean | RDP | Ignore certificate errors |
| `auth_pkg` | string | RDP | NLA auth package |
| `kdc_url` | string | RDP | Kerberos KDC URL |
| `color_depth` | integer | RDP | Color depth |
| `vnc_resize` | boolean | VNC | Resize the server's screen to the browser window (default `false`). See [`POST /api/sessions`](#post-apisessions). |
| `vnc_network` | string | VNC | Network preset: `auto` (default), `lan`, `wan` or `slow`. |
| `enable_drive` | boolean | RDP, SSH | Enable file transfer |
| `disable_copy` | boolean | All | Disable clipboard copy (server → client) |
| `disable_paste` | boolean | All | Disable clipboard paste (client → server) |
| `autofill` | string | Web | JSON array of autofill credentials |
| `allowed_domains` | array | Web | Domain allowlist for the browser session |
| `login_script` | string | Web | Login script filename |
| `display_name` | string | All | Friendly display name (shown as banner) |
| `prompt_credentials` | boolean | All | Prompt user for credentials at connect time |
| `jump_hosts` | array | All | Multi-hop SSH tunnel chain (same format as session creation) |
| `external_id` | string | All | Stable id of the record the entry is synced from (the [NetBox webhook](netbox.md#create-webhook-device-createdupdated) sends `netbox:device:<id>`). What `PUT ...?move=true` matches on; never used to connect. Preserved on update when omitted. |

| `protocols` | array | All | The ways to connect to the host, primary first, in place of `type` (see [Multi-protocol entries](#multi-protocol-entries)) |

For `spice` and `proxmox` entries, the `spice_*` and `proxmox_*` fields listed under [`POST /api/sessions`](#post-apisessions) apply here too. The `proxmox_token_secret` is write-only: it is never returned by the read endpoints (a `has_proxmox_token_secret` boolean indicates whether one is stored), and it is preserved on update when omitted. See [SPICE and Proxmox VE Sessions](spice-and-proxmox.md) for the editor fields and how the token is stored.

#### Multi-protocol entries

An entry can list several protocols for one host instead of a single `type`. The top-level fields are the host's defaults; each protocol has a `type`, an optional `name` and any entry field, which overrides the host's. An empty value (`""` or `[]`) clears the inherited one. The first protocol is the primary.

```json
{
  "name": "server01",
  "hostname": "10.0.0.10",
  "display_name": "server01.example.com",
  "username": "Administrator",
  "protocols": [
    { "type": "rdp", "port": 3389 },
    { "type": "ssh", "port": 22, "username": "admin" },
    { "type": "ssh", "name": "ssh-2222", "port": 2222 },
    { "type": "web", "url": "https://10.0.0.10/", "hostname": "" }
  ]
}
```

- `name` defaults to the type and must be unique in the entry (letters, digits, `-`, `_`, `.`). The connect endpoints, updates and sessions refer to a protocol by it.
- An update keeps each protocol's stored secrets by matching names, so renaming a protocol would leave it without them. To rename one, send its old name as `renamed_from` alongside the new `name` (`{"type": "ssh", "name": "ssh-mgmt", "renamed_from": "ssh-2222"}`) and its secrets move with it. `renamed_from` is used for that update only and is never stored.
- `port` is set per protocol and never inherited: a protocol without one connects on its type's standard port (SSH 22, RDP 3389, VNC 5900). A top-level `port` next to `protocols` is refused.
- Credentials resolve in this order: the protocol's own, the host's, the folder's [default credentials](credential-variables.md#folder-default-credentials) for the protocol's type, then `$variable` references are filled in.
- The single-protocol form (a top-level `type`) is still accepted everywhere and is the same as a one-item `protocols` list. A body with both `type` and `protocols` is refused with `400`, as is an unknown protocol type or two protocols with the same name.
- An entry that loses nothing by it is stored in the single-protocol form, so instances that predate this keep reading it. An entry with more than one protocol, a protocol name, or a host default the single form would put on the protocol (for example a host `username`) is stored with `protocols`; see [Migration](migration.md#multi-protocol-entries) before you create one.

### `PUT /api/addressbook/folders/:scope/:folder/entries/:entry` (admin)

Update a connection entry, or create it if there is none of that name in the folder. Uses read-modify-write: reads existing entry from Vault, merges incoming fields on top. Credentials (`password`, `private_key`, `container_password`, `proxmox_token_secret`) that are omitted from the request are preserved from the existing entry, and so is `external_id`. Jump host credentials are merged per-hop by index. If the existing entry cannot be read for any reason other than not existing, the response is `502` and nothing is written, so a request without secrets never replaces an entry that has them.

With [protocols](#multi-protocol-entries), the request's list is the entry's list of protocols, and secrets are kept per protocol: each protocol keeps the ones it omits from the stored protocol of the same name, and the host keeps its own. When the request and the stored entry each have one protocol, the two are matched whatever their names, so an old single-protocol body that changes an entry's `type` keeps its secrets as before. A single-protocol body (such as the original NetBox webhook) sent for an entry that has several protocols replaces them with that one.

**`?move=true`** is for sync sources such as the [NetBox webhook](netbox.md#create-webhook-device-createdupdated), where the folder or the name is computed from the device and can change. It needs `external_id` in the body and matches the device on that, never on its name:

1. If `:folder/:entry` exists with the same `external_id`, or with none (an entry made by hand before syncing began), it is updated in place.
2. Otherwise every entry in the scope is read, and the one carrying that `external_id` is moved to `:folder/:entry` by the server-side move below, credentials and credential variables included, and the update is then applied on top. The response says where it came from:

   ```json
   { "ok": true, "moved_from": { "folder": "customer-a", "name": "fw01" } }
   ```

3. If no entry carries it, the entry is created.

Entries in other folders that merely share the name are never touched. Responses: `400` without `external_id`; `409` if `:folder/:entry` belongs to a different `external_id`, if it has no `external_id` while another entry in the scope already carries this one (adopting it would put the id on two entries), or if the `external_id` is stored on more than one entry in the scope (nothing is changed in any of these); `502` with `"copied": true` if the move copied the entry but could not remove the original (it then exists in both folders, and the update is not applied). The scan in step 2 reads every entry in the scope, but it only happens when the entry is not already where the request says, that is on first sight of a device and when it moves.

### `GET /api/addressbook/folders/:scope/:folder/defaults` (admin)

The folder's default credentials, secrets stripped. These are lent to entries in the folder (and in subfolders without their own, per session type, but only subfolders that inherit access and grant no groups or users of their own) that have no password or private key of their own, so an entry created without secrets by a webhook or an import is connectable the moment it exists. An entry's own credentials always win, and an entry set to `prompt_credentials` still prompts. See [Folder default credentials](credential-variables.md#folder-default-credentials) for the storage layout, the inheritance rule and the note on web entries.

```json
{
  "defaults": {
    "ssh": { "username": "root", "domain": null, "has_password": false, "has_private_key": true },
    "web": { "username": null, "domain": null, "has_password": true, "has_private_key": false }
  }
}
```

Entries covered by folder defaults list with `has_credentials: true` and `inherited_credentials: true`.

### `PUT /api/addressbook/folders/:scope/:folder/defaults` (admin)

Set default credentials per session type. Types not mentioned keep what is stored; `null` removes a type. Within a type an omitted field keeps the stored value and `""` clears it, the same rule entry PUTs use for secrets.

```json
{
  "ssh": { "username": "root", "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..." },
  "web": { "password": "router-password" },
  "rdp": null
}
```

Returns the same summary as `GET`. A type left with nothing in it is dropped; a folder left with no types loses its defaults entirely. Audited as `update_folder_defaults`.

### `DELETE /api/addressbook/folders/:scope/:folder/defaults` (admin)

Remove the folder's default credentials. Returns `204`.


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

### `GET /api/addressbook/version?since=N`

The address book's change log, answered from memory: no Vault or disk read, so clients may poll it often. Requires **operator**. `version` counts every successful change made through this API to entries, folders and folder config (moves, copies and bulk operations included); `changed_at` is unix milliseconds, `0` before the first change since start. With `since`, `changes` lists what moved after that version, one row per folder: `kind` is `entries` (entries in the folder were written), `tree` (the folder itself was created, deleted or its config changed) or `all` (not attributable; refresh everything). It is `null` when `since` is omitted, or when the log no longer reaches back that far (it keeps the last few hundred changes), and the client should refresh what it shows once.

`epoch` identifies the server process the log belongs to. The version counter starts again at 0 when rustguac restarts, so a client should remember the `epoch` that came with its version and, when it changes, refresh what it shows once and ignore `changes`: after a restart they come from a different log, even when the numbers line up.

For callers below **admin**, rows only ever name folders the caller can open. An `entries` row for any other folder is left out, and every `tree` row is replaced by one without a path (`"scope": "*", "folder": ""`), since a folder that was created, deleted or had its access changed may be one the caller cannot see; a client should treat it like `all`. Admins get every row as logged. Filtering reads folder config only when there are changes to answer, so a poll with nothing new still costs no Vault read.

A user's own credential variables (`/api/me/credentials`) are not address-book changes and never appear here. The log is per process: with several rustguac instances on one Vault, each sees only its own changes.

The Connections page polls this every 3 seconds while visible and re-reads only the folder it shows, or the folder list when a folder came or went; its search index is rebuilt only when search is next used.

```json
{
  "version": 17,
  "changed_at": 1760155200000,
  "epoch": 3418867302915441,
  "changes": [
    { "scope": "shared", "folder": "customers/acme", "kind": "entries" },
    { "scope": "instance", "folder": "lab", "kind": "tree" }
  ]
}
```

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
