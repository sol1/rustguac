# Overview

## What is rustguac?

rustguac is a lightweight Rust replacement for the Apache Guacamole Java webapp. It provides browser-based remote access to SSH, RDP, VNC, web browser sessions, and VDI desktop containers through [guacd](https://github.com/apache/guacamole-server), the Guacamole protocol daemon.

rustguac sits between web browsers and guacd, proxying the Guacamole protocol over WebSockets. It manages session lifecycle, authentication, session recording, and an optional Vault-backed address book.

## Why not Apache Guacamole?

Apache Guacamole is a mature, feature-rich platform. rustguac is a purpose-built alternative for organisations that want:

- **No Java stack** — rustguac is a single Rust binary. No Tomcat, no WAR files, no JVM tuning.
- **Security-first design** — CIDR allowlists, TLS everywhere, LUKS-encrypted file transfer, Vault integration, rate limiting, audit logging.
- **Simpler deployment** — one binary + guacd. Install with a single script or Docker image.
- **Address book in Vault** — connection credentials stored in HashiCorp Vault / OpenBao KV v2. Credentials never reach the browser.
- **Zero-trust integration** — works with [Knocknoc](https://knocknoc.io) for identity-aware network access control at the HAProxy layer.

## Similarities to Apache Guacamole

rustguac and Apache Guacamole share the same foundation:

- **guacd** — both use guacd from [guacamole-server](https://github.com/apache/guacamole-server) for protocol translation. This is the same battle-tested C daemon.
- **Guacamole protocol** — the wire protocol between the webapp and guacd is identical. rustguac uses the same instruction format, the same JavaScript client library (`guac-common-js`), and the same WebSocket framing.
- **Session recording** — recordings are in the standard Guacamole format and can be played back with the bundled player.
- **SSH/RDP/VNC support** — the same protocol backends provided by guacd.

## Key differences from Apache Guacamole

| Feature | Apache Guacamole | rustguac |
|---------|-----------------|----------|
| **Runtime** | Java (Tomcat + Spring) | Rust (single binary) |
| **Database** | MySQL/PostgreSQL/LDAP | SQLite (embedded) |
| **Credential storage** | Database tables | Vault KV v2 (server-side only) |
| **Authentication** | LDAP, RADIUS, TOTP, SAML, database | OIDC SSO + API keys |
| **Web sessions** | Not supported | Headless Chromium on Xvnc |
| **Ephemeral SSH keys** | Not supported | Ed25519 keypair per session |
| **File transfer encryption** | Not supported | LUKS + Vault key management |
| **Multi-hop SSH tunnels** | Not supported | Chain multiple SSH bastion hops to reach isolated targets |
| **Network allowlists** | Not supported | CIDR allowlists per protocol |
| **Rate limiting** | Not built-in | Per-IP, per-endpoint (tower_governor) |
| **Reverse proxy integration** | Generic | HAProxy + Knocknoc examples |
| **Session sharing** | Connection sharing | Share tokens (read-only or collaborative) |
| **Clipboard control** | Not per-connection | Per-entry disable copy/paste |
| **Web session autofill** | Not supported | Native Chromium autofill from Vault credentials |
| **Web domain allowlist** | Not supported | Per-entry domain restriction via --host-rules |
| **VDI containers** | Not supported | Ephemeral Docker desktop containers per user |

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
    |         |
    |         +---> Chromium (kiosk mode)
    +---> Docker container :3389 (for VDI sessions)
              |
              +---> xrdp + desktop (xfce4, etc.)
```

For SSH, RDP, VNC, and web browser sessions, an optional multi-hop SSH tunnel chain can route the connection through one or more bastion hosts:

```
Browser -> rustguac -> SSH tunnel (hop 1) -> SSH tunnel (hop 2) -> ... -> guacd -> target
```

Both links are encrypted by default: HTTPS between browsers and rustguac, TLS between rustguac and guacd.

## Session types

### SSH

Connects guacd directly to a target SSH server. Supports password, private key, and ephemeral keypair authentication. Terminal rendering is handled by guacd's SSH plugin with `xterm-256color` terminal type.

SFTP file transfer is available directly between the browser and the target SSH server (no files stored on the rustguac server).

Supports optional [multi-hop SSH tunnel chains](#ssh-tunnel--jump-hosts) to reach targets through bastion hosts.

### RDP

Connects guacd to a target RDP server. Supports username/password, domain, and various RDP settings (security mode, certificate ignore, display resize). Drive redirection provides file transfer via a per-session directory on the rustguac server.

Supports optional [multi-hop SSH tunnel chains](#ssh-tunnel--jump-hosts) and [Kerberos NLA authentication](integrations.md#rdp-kerberos-nla-authentication).

### VNC

Connects guacd to a target VNC server. Supports password-based authentication. Useful for accessing existing VNC servers on the network (e.g., KVM/IPMI consoles, remote desktops, virtual machine displays).

Supports optional [multi-hop SSH tunnel chains](#ssh-tunnel--jump-hosts) to reach VNC targets through bastion hosts.

### Web browser

Spawns a headless Xvnc display and Chromium in kiosk mode, then connects guacd via VNC to the local display. The user sees a full browser session in their own browser. Each session gets an isolated Chromium profile directory.

Web sessions support native autofill, per-entry domain allowlisting, login scripts (CDP-based automation), clipboard control, and Chromium security hardening. See [Web Browser Sessions](web-sessions.md) for the full guide with examples.

Supports optional [multi-hop SSH tunnel chains](#ssh-tunnel--jump-hosts) to reach web targets through bastion hosts.

### VDI (Docker containers)

Spawns an ephemeral Docker container running xrdp and a Linux desktop, then connects guacd via RDP to the container. Each user gets a dedicated container named `rustguac-vdi-{username}`. Containers persist after disconnect for reconnection and are automatically cleaned up after an idle timeout.

VDI sessions support persistent home directories, per-entry resource limits and idle timeouts, session thumbnails, and active session previews in the address book. See [VDI Desktop Containers](vdi.md) for configuration and image requirements.

## SSH tunnel / jump hosts

All session types (SSH, RDP, VNC, and web browser) can be routed through one or more SSH bastion hosts using multi-hop SSH tunnel chains. This is useful when target machines are not directly reachable from the rustguac server.

Each hop in the chain establishes an SSH connection and creates a local TCP port forward (`direct-tcpip`). The hops are chained sequentially — each hop connects through the previous hop's local listener. The final hop forwards to the actual target (e.g., an RDP server on port 3389).

```
You -> bastion-1:22 -> bastion-2:22 -> target:3389 RDP
```

Jump hosts can be configured:
- **Per address book entry** — admins configure the tunnel chain in the entry editor
- **Per ad-hoc session** — powerusers add jump hosts when creating sessions from the Sessions page

Each hop supports independent credentials (username + password or private key). Jump host credentials are stored in Vault alongside the address book entry and are never sent to the browser.

## Ports

| Port | Service |
|------|---------|
| 443 | rustguac HTTPS (default with TLS) |
| 8089 | rustguac HTTP (when TLS is disabled) |
| 4822 | guacd (TLS, loopback only) |
| 6000-6099 | Xvnc displays (`:100`-`:199`, internal) |

## Project structure

```
src/
  main.rs          Entry point, CLI, server setup
  api.rs           REST API endpoints
  auth.rs          API key + OIDC session authentication middleware
  browser.rs       Xvnc + Chromium process manager
  config.rs        TOML config loading
  db.rs            SQLite database (admins, OIDC users, sessions)
  drive.rs         Drive / file transfer + LUKS lifecycle
  guacd.rs         guacd TLS/TCP connection & protocol handshake
  oidc.rs          OpenID Connect login flow
  protocol.rs      Guacamole wire format parser
  session.rs       Session state machine
  tunnel.rs        Multi-hop SSH tunnel chain
  vault.rs         Vault/OpenBao KV v2 client (AppRole auth)
  vdi/mod.rs       VDI driver trait and container types
  vdi/docker.rs    Docker-based VDI driver (bollard)
  websocket.rs     WebSocket <-> guacd proxy
static/
  *.html           Web UI pages
  guac/            Guacamole JS client library
docs/              This documentation
patches/           guacd patches for FreeRDP 3.x
contrib/           Target server setup scripts (xrdp, audio, Windows, VDI test image)
scripts/           Utility scripts (drive-setup.sh)
```

## Documentation

### Getting started
- [Deployment Guide](deployment-guide.md) -- step-by-step production setup (start here)
- [Installation](installation.md) -- all install options (Debian, Docker, bare-metal, dev, RPM from source)
- [Configuration](configuration.md) -- full config.toml reference

### Features
- [Roles and Access Control](roles-and-access-control.md) -- 4-tier role hierarchy, OIDC groups, user API tokens
- [Web Browser Sessions](web-sessions.md) -- autofill, domain allowlisting, login scripts
- [Credential Variables](credential-variables.md) -- shared credentials across entries
- [Reports](reports.md) -- session analytics, history, CSV export
- [RDP Video Performance](rdp-video-performance.md) -- H.264 passthrough, GFX pipeline, xrdp/Windows tuning
- [VDI Desktop Containers](vdi.md) -- ephemeral Docker desktops, image requirements, persistent homes

### Integrations
- [Integrations](integrations.md) -- OIDC, Vault, SSH tunnels, Kerberos, HAProxy, Knocknoc, drive/LUKS
- [NetBox](netbox.md) -- address book sync via custom fields and webhooks
- [Migration from Apache Guacamole](migration.md) -- MySQL/MariaDB to Vault

### Reference
- [Security](security.md) -- TLS, network allowlists, headers, audit logging, hardening
- [API Reference](api.md) -- complete REST API documentation
