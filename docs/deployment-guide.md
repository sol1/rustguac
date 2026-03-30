# Deployment Guide

A step-by-step guide for planning and deploying rustguac in production. Covers network architecture, server preparation, RDP target setup, security hardening, and ongoing operations.

## Architecture Overview

A typical deployment has three layers:

```
Internet
   |
[HAProxy] ── TLS termination, rate limiting, Knocknoc ACL
   |
[rustguac] ── session management, WebSocket proxy, address book
   |
[guacd] ── protocol translation (SSH, RDP, VNC)
   |
[targets] ── SSH servers, RDP desktops, VNC hosts
```

**All components can run on a single server** for small deployments (up to ~50 concurrent sessions). For larger deployments, guacd is the bottleneck (~158 MB per RDP session) and can be scaled separately.

### Port allocation

| Port | Service | Exposure |
|------|---------|----------|
| 443 | HAProxy (HTTPS) | Public / Knocknoc-gated |
| 8089 | rustguac (HTTPS) | Loopback only (behind HAProxy) |
| 4822 | guacd (TLS) | Loopback only |
| 6000-6099 | Xvnc displays | Loopback only (web sessions) |

## Step 1: Install rustguac

### Debian 13 (recommended)

```bash
# Download the latest .deb from GitHub releases
wget https://github.com/sol1/rustguac/releases/latest/download/rustguac_amd64.deb
sudo apt install ./rustguac_amd64.deb
```

This installs rustguac + guacd to `/opt/rustguac` with systemd services.

### Docker

```bash
docker pull ghcr.io/sol1/rustguac:latest
docker run -d \
  -p 443:8089 \
  -v rustguac-data:/opt/rustguac/data \
  -v rustguac-recordings:/opt/rustguac/recordings \
  -v ./config.toml:/opt/rustguac/config.toml \
  ghcr.io/sol1/rustguac:latest
```

See [installation.md](installation.md) for all options including bare-metal script and Docker.

## Step 2: Initial Configuration

### Create an admin API key

```bash
/opt/rustguac/bin/rustguac --config /opt/rustguac/config.toml add-admin --name admin
```

Save the printed key (`rgu_...`) — it is shown only once. Use it for initial setup, then **delete it once OIDC is configured** (see Step 5).

### Edit config.toml

```bash
sudo nano /opt/rustguac/config.toml
```

Key settings for a production deployment:

```toml
listen_addr = "127.0.0.1:8089"      # Loopback only — HAProxy handles public TLS
guacd_addr = "localhost:4822"

[tls]
cert_path = "/opt/rustguac/tls/cert.pem"
key_path = "/opt/rustguac/tls/key.pem"
guacd_cert_path = "/opt/rustguac/tls/cert.pem"

# Trust HAProxy's X-Forwarded-For header
trusted_proxies = ["127.0.0.1/32"]

# Network allowlists — restrict what targets guacd can connect to.
# Prevents SSRF via crafted session requests.
[network]
allowed_ssh_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
allowed_rdp_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
allowed_vnc_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
```

See [configuration.md](configuration.md) for the full reference.

### Start services

```bash
sudo systemctl enable --now rustguac
```

Verify: `curl -k https://localhost:8089/api/health`

## Step 3: Set Up HAProxy

HAProxy provides TLS termination, HTTP/2, WebSocket support, and Knocknoc integration.

### Install

```bash
sudo apt install haproxy
```

### Configure

Create `/etc/haproxy/haproxy.cfg`:

```
global
    log /dev/log local0
    maxconn 4096
    stats socket /run/haproxy/admin.sock mode 0660 level admin
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11

defaults
    log     global
    mode    http
    option  httplog
    timeout connect 5s
    timeout client  30s
    timeout server  30s
    timeout tunnel  8h              # Long-lived WebSocket sessions
    timeout http-request 10s        # Slowloris protection

frontend https
    bind *:443 ssl crt /etc/ssl/private/rustguac.pem alpn h2,http/1.1
    bind *:80
    http-request redirect scheme https unless { ssl_fc }
    http-request del-header X-Forwarded-For
    option forwardfor
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    default_backend rustguac

backend rustguac
    option httpchk GET /api/health
    server rustguac 127.0.0.1:8089 ssl verify none check inter 30s
```

### TLS certificate

Use Let's Encrypt or your organisation's CA:

```bash
# Let's Encrypt example (certbot + HAProxy)
sudo certbot certonly --standalone -d console.example.com
sudo cat /etc/letsencrypt/live/console.example.com/{fullchain,privkey}.pem \
    > /etc/ssl/private/rustguac.pem
sudo systemctl restart haproxy
```

## Step 4: Prepare RDP Targets

### Linux (xrdp with H.264)

For the best video experience with Linux desktops, use xrdp with x264 H.264 encoding. A single setup script handles everything — desktop environment, audio, xrdp rebuild with x264, and GFX configuration:

```bash
# On the RDP target machine (not the rustguac server):
wget -O setup-xrdp-gfx.sh https://raw.githubusercontent.com/sol1/rustguac/main/contrib/setup-xrdp-gfx.sh
sudo bash setup-xrdp-gfx.sh --desktop mate
```

The `--desktop` flag installs a desktop environment (default: `mate`). Options: `mate`, `xfce`, `kde`, `gnome`, `none`. MATE is recommended — it's lightweight, Windows-like, and works reliably over xrdp without GPU.

The script runs in three phases:
1. **Phase 1 (pure trixie):** Installs desktop, Firefox, Chromium, build tools, PulseAudio xrdp audio module, switches from PipeWire to real PulseAudio
2. **Phase 2 (temporary sid):** Adds Debian sid repo, installs matching xorgxrdp, rebuilds xrdp with `--enable-x264`, removes sid
3. **Phase 3 (configure):** Xorg backend, startwm.sh, gfx.toml with H.264 + x264 encoder

Run `bash setup-xrdp-gfx.sh --help` for all options, or `bash setup-xrdp-gfx.sh --diagnose` to troubleshoot after setup.

In the rustguac address book, enable these settings on the RDP entry:
- **Enable Graphics Pipeline (GFX)** -- checked
- **H.264 Passthrough** -- checked
- **Enable Desktop Composition** -- not needed for Linux (Windows-only DWM setting)

See [rdp-video-performance.md](rdp-video-performance.md) for manual setup and tuning.

### Windows

Windows RDP works out of the box. For video-heavy workloads:

```powershell
# On the Windows RDP server (as Administrator):
.\contrib\setup-rdp-performance.ps1

# With GPU hardware encoding:
.\contrib\setup-rdp-performance.ps1 -EnableGPU
```

This enables AVC 4:4:4, 60 FPS, desktop composition, and GPU encoding.

**Note:** Windows only sends H.264 when a GPU (physical or virtual) is available. Without GPU, it uses Planar/RemoteFX which guacd re-encodes as JPEG/WebP. This is still good quality — just not as low-latency as H.264 passthrough.

## Step 5: Configure Authentication

### OIDC Single Sign-On (recommended)

Add to `config.toml`:

```toml
[oidc]
issuer_url = "https://your-idp.example.com"
client_id = "rustguac"
redirect_uri = "https://console.example.com/auth/callback"
groups_claim = "groups"
session_ttl_secs = 28800    # 8 hours

[oidc.group_role_mappings]
"RemoteConsoleAdmins" = "admin"
"RemoteConsoleUsers" = "operator"
```

Set the client secret in `/opt/rustguac/env`:

```bash
echo 'OIDC_CLIENT_SECRET=your-secret-here' | sudo tee -a /opt/rustguac/env
sudo chmod 600 /opt/rustguac/env
sudo systemctl restart rustguac
```

See [integrations.md](integrations.md) for provider-specific guides (Authentik, JumpCloud, Entra ID, etc.).

### Delete the bootstrap API key

Once OIDC is working and you have an admin user, remove the initial API key:

```bash
# List admin keys
/opt/rustguac/bin/rustguac --config /opt/rustguac/config.toml list-admins

# Delete by name
/opt/rustguac/bin/rustguac --config /opt/rustguac/config.toml delete-admin --name admin
```

API keys are powerful (full admin, no MFA). For day-to-day use, OIDC with group-based roles is more secure. If you need programmatic API access, create scoped [user API tokens](roles-and-access-control.md) instead.

## Step 6: Set Up the Address Book (Vault)

The address book stores connection entries in HashiCorp Vault or OpenBao. Credentials stay server-side — they never reach the browser.

```toml
[vault]
addr = "https://vault.example.com:8200"
mount = "secret"
base_path = "rustguac"
role_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

```bash
echo 'VAULT_SECRET_ID=your-secret-id' | sudo tee -a /opt/rustguac/env
sudo systemctl restart rustguac
```

See [integrations.md](integrations.md) for Vault setup, AppRole configuration, and mTLS.

## Step 7: Lock It Down with Knocknoc

[Knocknoc](https://knocknoc.io) removes the attack surface entirely. Instead of exposing rustguac's login page to the internet, Knocknoc gates access at the network layer:

1. **Before Knocknoc:** the login page is visible to scanners, bots, and attackers
2. **After Knocknoc:** the login page returns 403 unless the user has authenticated through Knocknoc first (SSO + MFA)

Only the front page (`/`) is gated. API endpoints, OIDC callbacks, and share links pass through to rustguac's own auth.

### HAProxy + Knocknoc configuration

Add to your HAProxy config:

```
# Dynamic ACL managed by knocknoc-agent
acl knoc_rustguac src -u 600
acl is_root path /

# Gate only the login page
use_backend rustguac if is_root knoc_rustguac
use_backend denied   if is_root
use_backend rustguac
```

Install and configure [knocknoc-agent](https://docs.knocknoc.io) to manage ACL #600 via the HAProxy admin socket.

### Why this matters

rustguac gives users administrative access to servers. Even with OIDC and strong passwords, exposing the login page means:
- Brute-force and credential-stuffing attacks
- Zero-day exploits against the web layer
- Reconnaissance by scanners

Knocknoc ensures the login page is only reachable after identity-verified network authentication. The attack surface goes from "the entire internet" to "zero".

## Step 8: Enable Drive Mapping (optional)

Drive mapping lets users transfer files to/from remote sessions.

### Basic (unencrypted)

```toml
[drive]
enabled = true
drive_path = "/opt/rustguac/drives"
drive_name = "Shared Drive"
```

### Encrypted (LUKS + Vault)

For environments requiring at-rest encryption:

```bash
sudo /opt/rustguac/bin/drive-setup.sh
```

This creates a LUKS-encrypted volume with the encryption key stored in Vault. See [integrations.md](integrations.md) for details.

## Step 9: Session Recording (optional)

Session recordings are enabled by default and stored in `/opt/rustguac/recordings`.

```toml
recording_path = "/opt/rustguac/recordings"

[recording_rotation]
enabled = true
max_disk_percent = 80    # Auto-delete oldest when disk usage exceeds 80%
interval_secs = 300      # Check every 5 minutes
```

Recordings can be played back in the browser via the Sessions page, or exported for compliance.

## Ongoing Operations

### Monitoring

- **Health check:** `GET /api/health` returns 200 when rustguac and guacd are running
- **System status:** `GET /api/system/status` (admin only) shows version, uptime, active sessions
- **Reports:** Session history, top connections, top users available at `/reports.html` (poweruser+ role)

### Upgrading

```bash
# Debian package
sudo apt install ./rustguac_new-version.deb
sudo systemctl restart rustguac
```

Config files are preserved across upgrades (`--force-confold`). Database migrations run automatically on startup.

### Backup

Back up these paths:
- `/opt/rustguac/config.toml` — configuration
- `/opt/rustguac/data/rustguac.db` — users, tokens, session history
- `/opt/rustguac/env` — secrets (Vault secret ID, OIDC client secret)
- `/opt/rustguac/recordings/` — session recordings (if needed for compliance)

The address book is in Vault — back up Vault separately.

### Security checklist

- [ ] HAProxy terminates TLS with a valid certificate (not self-signed)
- [ ] rustguac listens on loopback only (`listen_addr = "127.0.0.1:8089"`)
- [ ] Network allowlists configured (prevent SSRF to unintended targets)
- [ ] OIDC configured with group-based role mappings
- [ ] Bootstrap API key deleted after OIDC setup
- [ ] Knocknoc gates the login page (optional but strongly recommended)
- [ ] Drive encryption enabled if file transfer is used in regulated environments
- [ ] Session recording enabled for audit compliance
- [ ] `/opt/rustguac/env` has `chmod 600` permissions
- [ ] Trusted proxies configured to match HAProxy IP
