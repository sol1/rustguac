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
web_allowed_networks = ["127.0.0.0/8", "::1/128"]
```

**Default: localhost only** — all three default to `["127.0.0.0/8", "::1/128"]`, preventing SSRF attacks out of the box.

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

- Authentication failures (API key and OIDC)
- Session creation, connection, and termination
- WebSocket connect/disconnect events
- Admin operations (user management, key rotation)
- Client IP addresses (resolved via trusted proxies)

## Session security

- **Pending timeout** — sessions that don't receive a WebSocket connection within 60 seconds (configurable) are automatically cleaned up
- **Maximum duration** — active sessions are terminated after 8 hours (configurable) to prevent abandoned sessions
- **Session ownership** — non-admin users can only terminate their own sessions
- **Share tokens** — read-only or collaborative access via time-limited share URLs

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
- **API keys** — only the SHA-256 hash is stored. The plaintext key is shown once at creation and cannot be retrieved.
- **OIDC client secret** — can be provided via `OIDC_CLIENT_SECRET` environment variable instead of the config file.
- **LUKS encryption key** — stored in Vault, passed to cryptsetup via stdin (never on the command line or on disk).
- **Ephemeral SSH keys** — the private key exists only in memory during the guacd handshake. It is never stored on disk or returned by the API.
