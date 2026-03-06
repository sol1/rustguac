# Security

rustguac is designed with a security-first approach. This document covers all security features and their implementation.

## TLS encryption

### Client-facing HTTPS

When a `[tls]` section is present in the config, rustguac serves HTTPS using rustls (a modern, memory-safe TLS implementation). The install script generates a self-signed certificate by default.

```toml
[tls]
cert_path = "/opt/rustguac/tls/cert.pem"
key_path = "/opt/rustguac/tls/key.pem"
```

Generate a certificate:

```bash
rustguac generate-cert --hostname your-hostname.example.com --out-dir /opt/rustguac/tls
```

### guacd TLS

The connection between rustguac and guacd can also be encrypted with TLS. When `guacd_cert_path` is set, rustguac connects to guacd over TLS, trusting the specified certificate. The same self-signed cert can serve both purposes.

```toml
[tls]
cert_path = "/opt/rustguac/tls/cert.pem"
key_path = "/opt/rustguac/tls/key.pem"
guacd_cert_path = "/opt/rustguac/tls/cert.pem"
```

guacd must be started with matching TLS flags:

```bash
guacd -b 127.0.0.1 -l 4822 -L info -f -C /opt/rustguac/tls/cert.pem -K /opt/rustguac/tls/key.pem
```

The install script configures both sides automatically.

## Network allowlists (SSRF protection)

All session targets are validated against CIDR allowlists before connections are made. Hostnames are resolved and every returned IP must match at least one allowed CIDR range.

```toml
ssh_allowed_networks = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]
rdp_allowed_networks = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]
vnc_allowed_networks = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]
web_allowed_networks = ["127.0.0.0/8", "::1/128"]
```

**Default: localhost only** — all four default to `["127.0.0.0/8", "::1/128"]`, preventing SSRF attacks out of the box.

## Authentication

rustguac supports two parallel authentication paths. See [Roles and Access Control](roles-and-access-control.md) for the full role system.

### API key authentication

- Keys are 256-bit random values (64 hex characters)
- Stored as SHA-256 hashes in SQLite — the plaintext key is only shown once at creation
- Supported in `Authorization: Bearer <key>`, `X-API-Key: <key>` headers, and `?key=<key>` query parameter (WebSocket fallback)
- Optional IP allowlist (comma-separated CIDR ranges)
- Optional expiry timestamp (ISO 8601)
- API key admins always have full admin-level access

### OIDC session authentication

- Session tokens are 256-bit random values, stored in SQLite with a TTL
- Cookie: `rustguac_session` with `HttpOnly`, `Secure` (when TLS enabled), `SameSite=Lax`
- Configurable TTL (default: 24 hours)
- PKCE and nonce validation on every login flow
- Works with any OIDC provider (Authentik, Keycloak, Okta, Azure AD, Google, etc.)

### User API token authentication

User API tokens provide OIDC users with long-lived API credentials for automation and scripting, without sharing their OIDC session or admin API keys.

**Token format and storage:**

- Tokens are 60 hex characters with a `rgu_` prefix (e.g., `rgu_a1b2c3...`)
- Stored as SHA-256 hashes in SQLite — the plaintext token is shown once at creation and cannot be retrieved
- The `rgu_` prefix allows secret scanners and log monitoring tools to identify leaked tokens
- Token validation uses constant-time hash comparison (SHA-256 matching via SQLite query) to prevent timing attacks

**Effective role computation:**

When a user API token authenticates, the effective role is computed as `min(user_current_role, token_max_role)`. This means:
- If an admin demotes a user from poweruser to operator, all their existing tokens are immediately restricted to operator-level access
- The `max_role` cap on a token cannot grant more access than the user currently has
- Role evaluation happens at authentication time, not at token creation time

**Token lifecycle security:**

| Control | Implementation |
|---------|---------------|
| Creation | poweruser+ self-service; admin can create for any user |
| Revocation | immediate; hash deleted from database |
| Expiry | optional ISO 8601 timestamp, checked at authentication time |
| Disabled users | tokens for disabled users are automatically rejected |
| User deletion | all tokens cascade-deleted when user is removed |
| Cleanup | expired tokens are purged hourly by background task |

**Attack surface and mitigations:**

| Threat | Mitigation |
|--------|-----------|
| Token theft / leakage | `rgu_` prefix enables automated secret scanning; short token lifetime recommended; tokens can be revoked immediately |
| Privilege escalation via token | effective role is always `min(user_role, max_role)` — demoting the user restricts all their tokens |
| Brute-force token guessing | 240 bits of entropy (60 hex chars); rate limiting at 2 req/sec per IP |
| Token abuse after user offboarding | user deletion cascade-deletes all tokens; disabling a user blocks all their tokens |
| Lateral movement from stolen token | tokens inherit the user's identity — all actions are logged with the user's email and client IP |
| Audit evasion | all token create/revoke/use events are logged in `token_audit_log` with IP addresses |

**Audit logging:**

All token operations are recorded in a dedicated `token_audit_log` table:
- **created** — token creation (by self-service or admin), with max_role and expiry details
- **revoked** — token revocation (by owner or admin), logged with revoker identity
- **admin_revoked** — admin revocation of another user's token

Audit logs are retained for 90 days and cleaned up hourly. Admins can view the log via the Admin UI or `GET /api/admin/token-audit`.

## Rate limiting

Per-IP rate limiting is applied to all endpoints using `tower_governor`:

| Endpoint group | Rate | Burst |
|---------------|------|-------|
| API routes | 2/sec | 10 |
| Session creation | 1/sec | 5 |
| WebSocket connections | 2/sec | 20 |

Rate limiting uses the resolved client IP (honoring `trusted_proxies` for X-Forwarded-For).

## Security headers

All responses include the following headers:

| Header | Value |
|--------|-------|
| Content-Security-Policy | `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'` |
| X-Frame-Options | `DENY` |
| X-Content-Type-Options | `nosniff` |
| Strict-Transport-Security | `max-age=31536000; includeSubDomains` (when TLS enabled) |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| Permissions-Policy | `camera=(), microphone=(), geolocation=()` |

## Audit logging

rustguac logs security-relevant events via the `tracing` framework:

- Authentication failures (API key, user token, and OIDC)
- Session creation, connection, and termination
- WebSocket connect/disconnect events
- Admin operations (user management, key rotation)
- Client IP addresses (resolved via trusted proxies)

Additionally, user API token operations are logged to a persistent `token_audit_log` database table (see [User API token authentication](#user-api-token-authentication) above). This provides a queryable audit trail for token creation, revocation, and usage — retained for 90 days.

## Session security

- **Pending timeout** — sessions that don't receive a WebSocket connection within 60 seconds (configurable) are automatically cleaned up
- **Maximum duration** — active sessions are terminated after 8 hours (configurable) to prevent abandoned sessions
- **Session ownership** — non-admin users can only terminate their own sessions
- **Share tokens** — read-only or collaborative access via time-limited share URLs

## Clipboard control

Clipboard copy (server → client) and paste (client → server) can be independently disabled per address book entry. This uses guacd's native `disable-copy` and `disable-paste` parameters, which work for all session types (SSH, RDP, VNC, and web browser sessions).

Use cases:
- **Disable copy** — prevents users from copying data out of sensitive sessions (data loss prevention)
- **Disable paste** — prevents users from pasting potentially malicious content into remote sessions
- **Disable both** — fully isolates the clipboard between the local browser and the remote session

## Web session hardening

Web browser sessions (headless Chromium on Xvnc) include several security layers:

### Chromium managed policy

A managed policy is installed at `/etc/chromium/policies/managed/rustguac.json` that restricts:

| Policy | Value | Effect |
|--------|-------|--------|
| `AllowFileSelectionDialogs` | `false` | Blocks file open/save dialogs (prevents filesystem browsing) |
| `PasswordManagerEnabled` | `true` | Allows autofill to work |
| `ImportSavedPasswords` | `false` | Blocks password import UI (which exposes a file browser) |
| `DeveloperToolsAvailability` | `2` | Disables DevTools completely (right-click inspect, F12, menu) |
| `DownloadRestrictions` | `3` | Blocks all downloads |
| `PrintingEnabled` | `false` | Disables printing |
| `EditBookmarksEnabled` | `false` | Prevents bookmark editing |
| `BrowserSignin` | `0` | Disables browser sign-in |
| `SyncDisabled` | `true` | Disables Chrome Sync |
| `ExtensionInstallBlocklist` | `["*"]` | Blocks all extension installation |
| `URLBlocklist` | `file://*`, `chrome://*`, etc. | Blocks dangerous URL schemes |

### Per-entry domain allowlisting

Address book entries can specify an `allowed_domains` list. When set, Chromium can only reach those domains (plus localhost). All other domains are blocked via Chromium's `--host-rules` flag, which prevents DNS resolution for non-allowed hosts.

Subdomains are automatically included — adding `example.com` allows `*.example.com` as well.

**Important:** The `allowed_domains` field restricts which domains the browser can reach. This is separate from the server-side `web_allowed_networks` CIDR allowlist, which controls which target hosts rustguac will connect to when creating sessions. Both can be active simultaneously:

- `web_allowed_networks` — server-side CIDR filter applied at session creation time (controls what the rustguac server is allowed to connect to)
- `allowed_domains` — client-side DNS restriction applied inside Chromium at runtime (controls what sites the user can navigate to within the browser session)

### Profile isolation

Each web session gets a unique Chromium profile directory (UUID-based path in `/tmp/`). The profile is created fresh before launch and deleted when the session ends. Credentials stored in the autofill database exist only for the duration of the session.

### Sandbox

Chromium runs with its normal sandbox enabled (via the SUID `chrome-sandbox` helper). The `--no-sandbox` flag is not used.

## File permissions

| Path | Mode | Owner |
|------|------|-------|
| Drive directories | 0750 (rwxr-x---) | rustguac:rustguac |
| LUKS device file | 0600 (rw-------) | rustguac:rustguac |
| Recording files | 0640 (rw-r-----) | rustguac:rustguac |
| Recording directory | 0750 (rwxr-x---) | rustguac:rustguac |
| TLS private key | 0600 (rw-------) | rustguac:rustguac |

## SQL injection protection

All database queries use parameterised statements via rusqlite's `params!` macro. No string concatenation is used in SQL queries.

## Path traversal protection

Recording file access validates filenames to block path traversal (`/`, `\`, `..`). The Vault address book also validates entry and folder names (alphanumeric, hyphens, underscores, dots only; length 1-64).

## XSS protection

The web UI uses DOM API methods (`createElement`, `textContent`, `appendChild`) instead of `innerHTML` for user-supplied content. Combined with the CSP header, this prevents cross-site scripting.

## Body size limits

HTTP request bodies are limited to 64KB to prevent memory exhaustion attacks.

## Trusted proxy support

When `trusted_proxies` is configured, rustguac extracts the real client IP from the `X-Forwarded-For` header for connections originating from trusted proxy CIDRs. This ensures correct IP-based rate limiting and audit logging behind reverse proxies.

```toml
trusted_proxies = ["127.0.0.1/32"]
```

## Credential handling

- **Vault credentials** — address book entries are read server-side from Vault. Connection passwords and private keys are never sent to the browser.
- **SSH tunnel credentials** — jump host passwords and private keys are stored in Vault alongside the address book entry. They are read server-side when establishing the tunnel chain and are never sent to the browser. For ad-hoc sessions, jump host credentials are provided in the session creation request and exist only in memory during tunnel setup.
- **API keys** — only the SHA-256 hash is stored. The plaintext key is shown once at creation and cannot be retrieved.
- **User API tokens** — same SHA-256 hash storage as admin API keys. The `rgu_` prefix enables secret scanning. Plaintext shown once at creation only.
- **OIDC client secret** — can be provided via `OIDC_CLIENT_SECRET` environment variable instead of the config file.
- **LUKS encryption key** — stored in Vault, passed to cryptsetup via stdin (never on the command line or on disk).
- **Ephemeral SSH keys** — the private key exists only in memory during the guacd handshake. It is never stored on disk or returned by the API.
