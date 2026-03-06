# rustguac

A lightweight Rust replacement for the Apache Guacamole Java webapp. Provides browser-based SSH, RDP, VNC, and web browsing sessions through [guacd](https://github.com/apache/guacamole-server) (the Guacamole protocol daemon).

rustguac sits between web browsers and guacd, proxying the Guacamole protocol over WebSockets. It manages session lifecycle, authentication (API keys and OIDC SSO), session recording, and a Vault-backed address book.

## Features

- **SSH sessions** — browser-based SSH terminal via guacd, with password, private key, or ephemeral keypair auth
- **RDP sessions** — connect to Windows/RDP hosts with auto-fit display resize, Kerberos NLA, and RemoteApp/RAIL support
- **VNC sessions** — connect to any VNC server (KVM/IPMI consoles, remote desktops, VM displays)
- **Web browser sessions** — headless Chromium on Xvnc, streamed to the browser via VNC, with native autofill and per-entry domain allowlisting
- **Multi-hop SSH tunnels** — chain SSH jump hosts/bastions to reach isolated targets for any session type
- **OIDC single sign-on** — authenticate users via any OpenID Connect provider (Authentik, Google, Okta, etc.)
- **Role-based access** — admin, poweruser, operator, and viewer roles for both API key and OIDC users
- **Vault-backed address book** — connection credentials stored in HashiCorp Vault / OpenBao, never reach the browser
- **Per-entry clipboard control** — disable copy and/or paste per address book entry for data loss prevention
- **Kerberos NLA** — RDP Kerberos authentication via FreeRDP 3.x (no NTLM required)
- **Session recording** — all sessions recorded in Guacamole format with playback UI
- **Session sharing** — share tokens for read-only or collaborative access
- **Encrypted file transfer** — LUKS-encrypted per-session drive storage for RDP, SFTP for SSH
- **Themeable UI** — 8 built-in themes with CSS gradient backgrounds, or configure your own
- **TLS everywhere** — HTTPS for clients, TLS between rustguac and guacd
- **API key auth** — SHA-256 hashed keys with IP allowlists and expiry
- **SQLite storage** — no external database server needed
- **Single binary** — just rustguac + guacd, no Java stack

## Architecture

```
Browser (HTML/JS)
    |
    | WebSocket over HTTPS
    v
rustguac (Rust, axum)
    |
    | TLS (Guacamole protocol)
    v
guacd (C, from guacamole-server)
    |
    +---> SSH server (for SSH sessions)
    +---> RDP server (for RDP sessions)
    +---> VNC server (for VNC sessions)
    +---> Xvnc display (for web browser sessions)
              |
              +---> Chromium (kiosk mode)
```

## Quick start

**Debian 13 (.deb)** — download from [Releases](https://github.com/sol1/rustguac/releases):

```bash
sudo apt install ./rustguac_*.deb
```

**Docker:**

```bash
docker pull sol1/rustguac:latest
docker run -d -p 8089:8089 sol1/rustguac:latest
```

**RPM (Rocky/RHEL 9):**

```bash
sudo dnf install ./rustguac-*.rpm
```

After install, create an admin API key to get started:

```bash
/opt/rustguac/bin/rustguac --config /opt/rustguac/config.toml add-admin --name admin
```

API keys are intended for machine access and initial setup. Once you configure [OIDC authentication](docs/roles-and-access-control.md), you can delete the API key — no credentials are stored in the database.

See the [Installation guide](docs/installation.md) for full details including bare-metal install, Docker Compose, TLS setup, and development builds.

## Documentation

- [Installation](docs/installation.md) — packages, Docker, bare-metal, development
- [Configuration](docs/configuration.md) — TOML config reference, TLS, allowlists
- [Security](docs/security.md) — TLS, rate limiting, headers, credential handling
- [Roles & Access Control](docs/roles-and-access-control.md) — OIDC, roles, group mappings
- [Integrations](docs/integrations.md) — Vault address book, LUKS drives, HAProxy
- [API Reference](docs/api.md) — REST API endpoints, session creation, admin management

## Commercial support

Commercial support for rustguac is available from [Sol1](https://www.sol1.com.au).

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
