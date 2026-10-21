# Overview

## What is rustguac?

rustguac is a lightweight Rust replacement for the Apache Guacamole Java webapp. It provides browser-based remote access to SSH, RDP, VNC, web browser sessions, and VDI desktop containers through [guacd](https://github.com/apache/guacamole-server), the Guacamole protocol daemon.

rustguac sits between web browsers and guacd, proxying the Guacamole protocol over WebSockets. It manages session lifecycle, authentication, session recording, VDI container orchestration, and Vault-backed connection storage.

The connections feature (the main user-facing UI) requires HashiCorp Vault or OpenBao for credential storage. Without one, rustguac falls back to ad-hoc connections only (**Connect to a host** beside the search box, or the API). See [Vault / OpenBao Connections](integrations.md#vault--openbao-connections) for setup, including the `contrib/vault-quickstart.sh` helper.

## Why not Apache Guacamole?

Apache Guacamole is a mature, feature-rich platform. rustguac is a purpose-built alternative for organisations that want:

- **No Java stack** — rustguac is a single Rust binary. No Tomcat, no WAR files, no JVM tuning.
- **Security-first design** — CIDR allowlists, TLS everywhere, LUKS-encrypted file transfer, Vault integration, rate limiting, audit logging.
- **Simpler deployment** — one binary + guacd. Install with a single script or Docker image.
- **VDI desktops** — ephemeral Docker containers give each user an isolated Linux desktop on demand. No VM infrastructure required.
- **Connections in Vault** — connection credentials stored in HashiCorp Vault / OpenBao KV v2. Credentials never reach the browser.
- **Zero-trust integration** — works with [Knocknoc](https://knocknoc.io) for identity-aware network access control at the HAProxy layer.

## Similarities to Apache Guacamole

rustguac and Apache Guacamole share the same foundation:

- **guacd** — both use guacd from [guacamole-server](https://github.com/apache/guacamole-server) for protocol translation. This is the same battle-tested C daemon.
- **Guacamole protocol** — the wire protocol between the webapp and guacd is identical. rustguac uses the same instruction format, the same JavaScript client library (`guac-common-js`), and the same WebSocket framing.
- **Session recording** — recordings are in the standard Guacamole format and can be played back with the bundled player.
- **SSH/RDP/VNC support** — the same protocol backends provided by guacd. rustguac adds web browser and VDI container session types on top.

## Key differences from Apache Guacamole

| Feature | Apache Guacamole | rustguac |
|---------|-----------------|----------|
| **Runtime** | Java (Tomcat + Guice + Jersey) | Rust (single binary) |
| **Database** | MySQL/PostgreSQL | SQLite (embedded) |
| **Credential storage** | Database tables | Vault KV v2 (server-side only) |
| **Authentication** | LDAP, RADIUS, TOTP, SAML, database | OIDC SSO + API keys |
| **Web sessions** | Not supported | Headless Chromium on Xvnc |
| **Ephemeral SSH keys** | Not supported | Ed25519 keypair per session |
| **File transfer encryption** | Not supported | LUKS + Vault key management |
| **Multi-hop SSH tunnels** | Not supported | Chain multiple SSH bastion hops to reach isolated targets |
| **Network allowlists** | Not supported | CIDR allowlists per protocol |
| **Rate limiting** | Not built-in | Per-IP, per-endpoint (tower_governor) |
| **Reverse proxy integration** | Generic | HAProxy + Knocknoc examples |
| **Session sharing** | Connection sharing | Share links (view-only or collaborative) |
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

For SSH, RDP, VNC, and web browser sessions, an optional multi-hop SSH tunnel chain can route the connection through one or more bastion hosts. VDI sessions connect to local Docker containers and do not use tunnels.

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

Connects guacd to a target RDP server. Supports username/password, domain, and various RDP settings (security mode, certificate ignore, display resize). Drive redirection provides file transfer via a per-session directory on the rustguac server. Optional printer redirection sends remote print jobs to the browser as PDF downloads by default. Set `rdp.printing_method = "trigger_print"` to open the browser's local print dialog without displaying the PDF. It uses a separate RDP device, does not require drive file transfer, and requires Ghostscript on the guacd host. An administrator must enable `rdp.allow_printing`.

Supports optional [multi-hop SSH tunnel chains](#ssh-tunnel--jump-hosts) and [Kerberos NLA authentication](integrations.md#rdp-kerberos-nla-authentication).

#### Keyboard layout

RDP sends key positions, not characters, so guacd turns what you type into the key positions of the remote desktop's keyboard layout, and needs to know that layout. Left at its US default, a desktop set up for Swiss German swaps Y and Z and loses its umlauts. There are two places to set it:

- **On the connection:** **Keyboard layout** in the entry's RDP settings, for a connection everyone uses with the same keyboard.
- **For yourself:** **Settings > My keyboard layout** on the Connections page, when the desktops you use are set up for the same layout as your keyboard. It's remembered in that browser and used for any RDP connection left at "Server default", and for VDI desktops.

A layout set on the connection wins. With neither set, guacd uses US English.

### VNC

Connects guacd to a target VNC server. Supports password-based authentication, plus username + password for servers that require it (VeNCrypt, RealVNC, macOS Screen Sharing). Useful for accessing existing VNC servers on the network (e.g., KVM/IPMI consoles, remote desktops, virtual machine displays).

Supports optional [multi-hop SSH tunnel chains](#ssh-tunnel--jump-hosts) to reach VNC targets through bastion hosts.

**Screen size.** By default the remote screen keeps its own size and is scaled to fit the browser window. Tick **Resize the remote desktop to fit the window** only for servers with their own virtual screen (TigerVNC, Xvnc). A physical console (UltraVNC, RealVNC, x11vnc) can't resize, and asking it to stalls the session.

A remote screen much bigger than the window, such as two monitors viewed from a laptop, is hard to read when scaled. In the session's **Controls** panel, **View** switches between **Fit to window** and **Actual size, with scroll bars**, which shows it at 100% and scrolls. The choice is remembered in that browser and applies to every session type.

#### VNC network presets

**Network** on a VNC connection chooses how the server encodes the screen for rustguac, like UltraVNC Viewer's quick options:

| Preset | Encodings (in order) | Compression | JPEG quality | Colour |
|---|---|---|---|---|
| Auto (default) | negotiated | default | default | as set |
| LAN | Ultra, ZRLE, Hextile, CopyRect, Raw | 1 | 9 | as set |
| WAN | Tight, ZRLE, CopyRect | 6 | 6 | as set |
| Slow link | Tight, CopyRect | 9 | 3 | 16-bit unless set |

This is the link between the VNC server and rustguac. The picture rustguac sends on to the browser is compressed separately, so a preset helps most when the VNC server is far from rustguac.

**Authentication.** These work: VNC password, VeNCrypt (including username and password over TLS, e.g. TigerVNC with PAM), macOS Screen Sharing, and UltraVNC's Windows login (MS-Logon II, "New MS-Logon"), which allows Active Directory accounts. These don't: RealVNC's or UltraVNC's RSA-AES encryption (security types 5, 6, 129, 130), UltraVNC's encryption plugins, and MS-Logon III. A server offering only those fails with "Unknown authentication scheme". MS-Logon II protects the password weakly and doesn't encrypt the session, so use it on a trusted network or through a jump host.

### SPICE and Proxmox VE

SPICE sessions connect guacd's SPICE plugin to a SPICE server, such as a libvirt/QEMU VM console, with optional TLS, CA verification, certificate-subject pinning and a SPICE proxy. Proxmox VE console sessions open a Proxmox VE VM's console: at connect time rustguac fetches a one-time SPICE ticket from the Proxmox API, so only the API token is stored.

Both support optional [multi-hop SSH tunnel chains](#ssh-tunnel--jump-hosts). See [SPICE and Proxmox VE Sessions](spice-and-proxmox.md) for entry fields, the API token, TLS and troubleshooting.

### Web browser

Spawns a headless Xvnc display and Chromium in kiosk mode, then connects guacd via VNC to the local display. The user sees a full browser session in their own browser. Each session gets an isolated Chromium profile directory.

Web sessions support native autofill, per-entry domain allowlisting, login scripts (CDP-based automation), clipboard control, and Chromium security hardening. See [Web Browser Sessions](web-sessions.md) for the full guide with examples.

Supports optional [multi-hop SSH tunnel chains](#ssh-tunnel--jump-hosts) to reach web targets through bastion hosts.

### VDI (Docker containers)

Spawns an ephemeral Docker container running xrdp and a Linux desktop, then connects guacd via RDP to the container. Each user gets a dedicated container named `rustguac-vdi-{username}`. Containers persist after disconnect for reconnection and are automatically cleaned up after an idle timeout.

VDI sessions support persistent home directories, per-entry resource limits and idle timeouts, session thumbnails, and active session previews in the connections. See [VDI Desktop Containers](vdi.md) for configuration and image requirements.

## SSH tunnel / jump hosts

SSH, RDP, VNC, SPICE, Proxmox VE, and web browser sessions can be routed through one or more SSH bastion hosts using multi-hop SSH tunnel chains. This is useful when target machines are not directly reachable from the rustguac server. VDI sessions do not support tunnels (containers run locally).

Each hop in the chain establishes an SSH connection and creates a local TCP port forward (`direct-tcpip`). The hops are chained sequentially — each hop connects through the previous hop's local listener. The final hop forwards to the actual target (e.g., an RDP server on port 3389).

```
You -> bastion-1:22 -> bastion-2:22 -> target:3389 RDP
```

Jump hosts can be configured:
- **Per connections entry** — admins configure the tunnel chain in the entry editor
- **Per ad-hoc connection** — powerusers add jump hosts in **Connect to a host** (beside the search box on every page)

Each hop supports independent credentials (username + password or private key). Jump host credentials are stored in Vault alongside the connections entry and are never sent to the browser.

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
- [SPICE and Proxmox VE Sessions](spice-and-proxmox.md) -- SPICE displays, Proxmox VE consoles, API tokens, TLS, troubleshooting
- [Credential Variables](credential-variables.md) -- shared credentials across entries
- [Reports](reports.md) -- session analytics, history, CSV export
- [RDP Video Performance](rdp-video-performance.md) -- H.264 passthrough, GFX pipeline, xrdp/Windows tuning
- [VDI Desktop Containers](vdi.md) -- ephemeral Docker desktops, image requirements, persistent homes

### Integrations
- [Integrations](integrations.md) -- OIDC, Vault, SSH tunnels, Kerberos, HAProxy, Knocknoc, drive/LUKS
- [NetBox](netbox.md) -- connections sync via custom fields and webhooks
- [Migration from Apache Guacamole](migration.md) -- MySQL/MariaDB to Vault

### Reference
- [Security](security.md) -- TLS, network allowlists, headers, audit logging, hardening
- [API Reference](api.md) -- complete REST API documentation
