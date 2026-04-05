# rustguac

[![CI](https://github.com/sol1/rustguac/actions/workflows/ci.yml/badge.svg)](https://github.com/sol1/rustguac/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/sol1/rustguac)](https://github.com/sol1/rustguac/releases/latest)
[![License](https://img.shields.io/github/license/sol1/rustguac)](LICENSE)
[![Docker](https://img.shields.io/docker/pulls/sol1/rustguac)](https://hub.docker.com/r/sol1/rustguac)

A lightweight Rust replacement for the Apache Guacamole Java webapp. Browser-based SSH, RDP, VNC, web browsing, and VDI desktop containers through [guacd](https://github.com/apache/guacamole-server).

No Java. No Tomcat. Single binary + guacd.

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
    +---> SSH server
    +---> RDP server
    +---> VNC server
    +---> Xvnc + Chromium (web browser sessions)
    +---> Docker container + xrdp (VDI desktop sessions)
```

## Features

### Session types

| Type | Description |
|------|-------------|
| **SSH** | Browser-based terminal with password, private key, or ephemeral keypair auth. SFTP file transfer. |
| **RDP** | Windows/Linux RDP with auto-fit resize, Kerberos NLA, RemoteApp/RAIL, H.264 passthrough, GFX pipeline. |
| **VNC** | Connect to any VNC server (KVM/IPMI consoles, remote desktops, VM displays). |
| **Web** | Headless Chromium on Xvnc with native autofill, domain allowlisting, login script automation. |
| **VDI** | Ephemeral Docker desktop containers per user. Persist after disconnect, auto-cleanup on idle. |

### Security & authentication

- **OIDC single sign-on** — Authentik, Google, Okta, Keycloak, or any OpenID Connect provider
- **4-tier role system** — admin, poweruser, operator, viewer with OIDC group mapping
- **API key auth** — SHA-256 hashed keys with IP allowlists and expiry
- **Vault-backed address book** — credentials in HashiCorp Vault / OpenBao KV v2, never reach the browser
- **TLS everywhere** — HTTPS for clients, TLS between rustguac and guacd
- **CIDR allowlists** — per-protocol network restrictions for session targets
- **Per-entry clipboard control** — disable copy and/or paste for data loss prevention
- **Rate limiting** — per-IP, per-endpoint via tower_governor
- **Session recording** — Guacamole format with playback UI, disk rotation, per-entry limits

### Connectivity

- **Multi-hop SSH tunnels** — chain jump hosts/bastions to reach isolated networks (all session types)
- **Session sharing** — share tokens for read-only or collaborative access
- **Encrypted file transfer** — LUKS-encrypted per-session drive storage (RDP), SFTP (SSH)
- **Credential variables** — shared credentials across address book entries

### VDI desktop containers

- **Docker-based** — one container per user, deterministic naming, BYO image
- **Persist after disconnect** — reconnect to the same desktop within idle timeout
- **Logout detection** — desktop logout stops the container, tab close preserves it
- **Session thumbnails** — live preview in the address book, click to reconnect
- **Persistent home directories** — bind-mounted user data survives container restarts
- **Per-entry resource limits** — CPU, memory, idle timeout per address book entry
- **VdiDriver trait** — extensible for downstream forks (Nomad, Proxmox, cloud)

### UI

- **Address book** with folder-based organisation and OIDC group access control
- **Active Sessions** section with live thumbnail previews
- **Session ended overlay** with Reconnect/Close buttons
- **8 built-in themes** with CSS gradient backgrounds, or configure your own
- **Reports page** with session analytics, history, and CSV export

## Quick start

### Debian 13 (.deb)

Pre-built packages for amd64 and arm64 are available from [Releases](https://github.com/sol1/rustguac/releases):

```bash
sudo apt install ./rustguac_*.deb
/opt/rustguac/bin/rustguac --config /opt/rustguac/config.toml add-admin --name admin
sudo systemctl enable --now rustguac
```

### Docker

```bash
docker pull sol1/rustguac:latest
docker run -d -p 8089:8089 sol1/rustguac:latest
```

For VDI support, mount the Docker socket:

```bash
docker run -d -p 8089:8089 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --group-add $(getent group docker | cut -d: -f3) \
  sol1/rustguac:latest
```

### Other distributions

Pre-built packages are provided for Debian 13. For other distributions, build from source:

```bash
sudo ./install.sh
```

See the [Installation guide](docs/installation.md) for full details including Docker Compose, TLS setup, and development builds.

### VDI setup

VDI requires Docker on the host:

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker rustguac
sudo systemctl restart rustguac
```

Add `[vdi]` to your config and create a VDI entry in the address book. See [VDI Desktop Containers](docs/vdi.md) for image requirements and configuration.

## Documentation

### Getting started
- [Installation](docs/installation.md) — Debian packages, Docker, bare-metal, development builds
- [Configuration](docs/configuration.md) — TOML config reference with all sections
- [Deployment Guide](docs/deployment-guide.md) — step-by-step production setup

### Features
- [Roles & Access Control](docs/roles-and-access-control.md) — OIDC, roles, group mappings, API tokens
- [Web Browser Sessions](docs/web-sessions.md) — autofill, domain allowlisting, login scripts
- [VDI Desktop Containers](docs/vdi.md) — Docker desktops, image requirements, persistent homes
- [RDP Video Performance](docs/rdp-video-performance.md) — H.264 passthrough, GFX pipeline, xrdp tuning
- [Credential Variables](docs/credential-variables.md) — shared credentials across entries
- [Reports](docs/reports.md) — session analytics, history, CSV export

### Integration & reference
- [Integrations](docs/integrations.md) — Vault, LUKS drives, SSH tunnels, Kerberos, HAProxy, Knocknoc
- [NetBox](docs/netbox.md) — address book sync via custom fields and webhooks
- [Security](docs/security.md) — TLS, rate limiting, headers, audit logging, hardening
- [API Reference](docs/api.md) — REST API endpoints
- [Migration from Apache Guacamole](docs/migration.md) — MySQL/MariaDB to Vault

## Commercial support

Commercial support for rustguac is available from [Sol1](https://www.sol1.com.au).

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
