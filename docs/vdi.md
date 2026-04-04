# VDI Desktop Containers

rustguac can spawn ephemeral Docker desktop containers on demand. Each user gets their own isolated Linux desktop accessible via the browser, with no client software required.

## How it works

1. An admin creates a VDI entry in the address book, specifying a Docker image
2. When a user clicks Connect, rustguac creates a Docker container from that image
3. The container runs xrdp on port 3389, and guacd connects to it via RDP
4. The user sees a full Linux desktop in their browser
5. On disconnect (tab close, network drop), the container keeps running for reconnection
6. On logout from the desktop, the container is stopped and removed
7. Idle containers (no active session) are automatically cleaned up after a configurable timeout

## Configuration

Add a `[vdi]` section to your config file:

```toml
[vdi]
enabled = true
# docker_socket = "/var/run/docker.sock"   # default
# default_cpu_limit = 2.0                   # cores, 0 = no limit
# default_memory_limit = 2048               # MB, 0 = no limit
# ready_timeout_secs = 30                   # wait for xrdp to start
# idle_timeout_mins = 60                    # container lifetime after disconnect
# home_base = "/vdi-homes"                  # persistent home directories
# allowed_images = ["myregistry/desktop:latest"]  # whitelist, empty = allow all
```

The `rustguac` system user must be in the `docker` group:

```bash
sudo usermod -aG docker rustguac
sudo systemctl restart rustguac
```

## Docker image requirements

Any Docker image that meets these requirements will work:

- **xrdp listening on port 3389** with TLS certificates configured
- **Accepts environment variables**: `VDI_USERNAME`, `VDI_PASSWORD`
- **Entrypoint** creates the Linux user, sets the password, and starts xrdp

A minimal test image is included at `contrib/vdi-test-image/` (Debian + xfce4).

### Example entrypoint

```bash
#!/bin/bash
set -e
USERNAME="${VDI_USERNAME:-user}"
PASSWORD="${VDI_PASSWORD:-password}"

if ! id "$USERNAME" &>/dev/null; then
    useradd -m -s /bin/bash "$USERNAME"
fi
echo "$USERNAME:$PASSWORD" | chpasswd
echo "xfce4-session" > /home/"$USERNAME"/.xsession
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.xsession

# Configure TLS for xrdp
sed -i \
    -e 's|^certificate=.*|certificate=/etc/ssl/certs/ssl-cert-snakeoil.pem|' \
    -e 's|^key_file=.*|key_file=/etc/ssl/private/ssl-cert-snakeoil.key|' \
    /etc/xrdp/xrdp.ini

mkdir -p /run/dbus
dbus-daemon --system --fork 2>/dev/null || true
xrdp-sesman --nodaemon &
exec xrdp --nodaemon
```

## Address book setup

1. Create a folder in the address book (or use an existing one)
2. Add a new entry with type **VDI (Docker)**
3. Set the **Container Image** (e.g. `rustguac-vdi-test:latest`)
4. Optionally set CPU limit, memory limit, environment variables, idle timeout
5. Click Save

Users in the folder's allowed groups can now click Connect to get a desktop.

## Container lifecycle

| Event | What happens |
|-------|-------------|
| User clicks Connect | Container created (or reused if already running) |
| User closes browser tab | Container keeps running |
| Network drops | Container keeps running (reconnect when back online) |
| User logs out of desktop | Container stopped and removed |
| Idle timeout expires | Container stopped and removed by background reaper |
| Admin terminates session | Session ends, container keeps running |

## Persistent home directories

Set `home_base` in the VDI config to enable persistent user data:

```toml
[vdi]
home_base = "/vdi-homes"
```

Each user gets `{home_base}/{username}` mounted as `/home/{username}` inside the container. Files persist across container restarts. The directory is created automatically on first use.

## Active Sessions

The address book shows an **Active Sessions** section with thumbnail previews of running sessions. Thumbnails are captured every 10 seconds from the browser display. Click a thumbnail to reconnect.

Dormant VDI containers (running but no active browser session) also appear with their last captured thumbnail.

## Per-entry settings

Each VDI address book entry can override:

- **CPU limit** (cores) — overrides `default_cpu_limit`
- **Memory limit** (MB) — overrides `default_memory_limit`
- **Idle timeout** (minutes) — overrides `idle_timeout_mins`
- **Environment variables** — custom `KEY=VALUE` pairs passed to the container
- **Banner** — message shown before session starts

## Security notes

- Container images must be pre-pulled on the Docker host (no automatic pull)
- Use `allowed_images` to restrict which images can be used
- Containers run with default Docker isolation (no `--privileged`)
- Credentials are auto-generated per session (users never see the RDP password)
- The `rustguac` user needs Docker socket access but no other elevated permissions
