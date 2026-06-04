# Installation

> **Target platform**: rustguac is built and tested against **Debian 13
> (Trixie)**. The pre-built `.deb` package and the `install.sh` script
> both assume FreeRDP 3.15+ (Debian 13's `freerdp3-dev`). On other Linux
> distributions, the recommended path is the Docker image (Option C),
> which avoids the FreeRDP ABI issue entirely. See
> [Other Linux distributions](#other-linux-distributions) below.

## Option A: Debian package (recommended)

Pre-built `.deb` packages are available from the [releases page](https://github.com/sol1/rustguac/releases) for Debian 13 (Trixie) and compatible distributions.

```bash
sudo apt install ./rustguac_*.deb
```

Using `apt install` (not `dpkg -i`) ensures all runtime dependencies are resolved automatically.

The package installs to `/opt/rustguac` and creates systemd services for both guacd and rustguac.

### Post-install

1. **Create an admin API key:**

```bash
/opt/rustguac/bin/rustguac --config /opt/rustguac/config.toml add-admin --name admin
```

Save the printed API key — it is only shown once.

2. **Configure** — edit `/opt/rustguac/config.toml` as needed (see [Configuration](configuration.md)).

3. **Start the services:**

```bash
sudo systemctl enable --now rustguac
```

This starts both `rustguac-guacd` (the protocol daemon) and `rustguac` (the web proxy).

4. **(Required for connections) Set up Vault or OpenBao:**

The connections page is rustguac's primary user-facing feature. It stores SSH, RDP, VNC, web session, and VDI entries in [HashiCorp Vault](https://www.vaultproject.io/) or [OpenBao](https://openbao.org/) KV v2 — credentials never reach the browser. **Without one of these, the Connections UI is unavailable** and users can only run ad-hoc sessions via the Sessions page or the API.

For a single-host install the fastest path is the bundled quickstart helper, which auto-detects vault or bao and provisions everything:

```bash
# Against an existing Vault or OpenBao:
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=hvs.xxxxxxxx
./contrib/vault-quickstart.sh

# Or install Vault locally on this box with on-disk auto-unseal:
sudo ./contrib/vault-quickstart.sh --local
```

See [Vault / OpenBao Connections](integrations.md#vault--openbao-connections) for the manual walkthrough, mTLS, multi-instance setup, and the security caveat for `--local` mode.

6. **(Optional) Set up encrypted drive storage:**

```bash
sudo /opt/rustguac/bin/drive-setup.sh
```

See [Drive / File Transfer](integrations.md#drive--file-transfer--luks-encryption) for details.

7. **(Optional) Enable VDI desktop containers:**

If you want to use VDI sessions (ephemeral Docker desktop containers), install Docker and grant rustguac access:

```bash
# Install Docker (if not already installed)
curl -fsSL https://get.docker.com | sh

# Allow rustguac to manage containers
sudo usermod -aG docker rustguac
sudo systemctl restart rustguac
```

Then add a `[vdi]` section to your config — see [VDI Desktop Containers](vdi.md) for full setup.

## Option B: Bare-metal install script

For fresh Debian 13 systems, the install script builds everything from source:

```bash
sudo ./install.sh
```

This performs the following steps:

1. Installs system packages (build tools, Xvnc, Chromium, cryptsetup, etc.)
2. Installs the Rust toolchain (if not present)
3. Clones and builds guacd from [guacamole-server](https://github.com/apache/guacamole-server) source, applying patches automatically
4. Builds rustguac with `cargo build --release`
5. Creates the `rustguac` system user (home: `/home/rustguac`)
6. Generates a self-signed TLS certificate
7. Installs binaries, static files, and config to `/opt/rustguac`
8. Sets up systemd services

### Install flags

| Flag | Description |
|------|-------------|
| `--no-tls` | Skip TLS certificate generation, listen on HTTP port 8089 |
| `--hostname=FQDN` | Hostname for the TLS certificate (default: system hostname) |
| `--deps-only` | Only install system packages, then exit |
| `--no-deps` | Skip apt package installation |

### Installed layout

```
/opt/rustguac/
  bin/rustguac           # Main binary
  bin/drive-setup.sh     # LUKS drive setup script
  sbin/guacd             # Guacamole protocol daemon
  lib/                   # guacd shared libraries
  static/                # Web UI files
  tls/                   # TLS certificates
  data/                  # SQLite database
  recordings/            # Session recordings
  config.toml            # Configuration file
  env                    # Environment variables (VAULT_SECRET_ID, etc.)
```

### Systemd services

| Service | Description |
|---------|-------------|
| `rustguac-guacd` | guacd protocol daemon (TLS, loopback only) |
| `rustguac` | rustguac web proxy (depends on guacd) |

Both services run as the `rustguac` user and restart on failure.

The `rustguac` service loads environment variables from `/opt/rustguac/env` via systemd's `EnvironmentFile` directive. Use this for secrets like `VAULT_SECRET_ID` and `OIDC_CLIENT_SECRET`.

## Option C: Docker

Pre-built images are available on [Docker Hub](https://hub.docker.com/r/sol1/rustguac):

```bash
docker pull sol1/rustguac:latest
docker run -d -p 8089:8089 sol1/rustguac:latest
```

To build from source instead:

```bash
docker build -t rustguac .
docker run -d -p 8089:8089 rustguac
```

The Docker image:
- Uses a multi-stage build (Debian 13 trixie-slim runtime)
- Builds guacd from source with patches applied
- Generates a self-signed TLS certificate at build time
- Enables TLS between rustguac and guacd by default
- Exposes HTTP on port 8089 (put a reverse proxy in front for HTTPS)

### API key setup

On first run (when no database exists), the container automatically generates an admin API key and prints it to the logs:

```bash
docker logs rustguac
```

Save the printed key — it is only shown once. To generate additional keys later:

```bash
docker exec rustguac /opt/rustguac/bin/rustguac \
    --config /opt/rustguac/config.toml add-admin --name my-admin
```

### Customizing the configuration

To persist config changes across container restarts, bind-mount a local `config.toml` into the container:

1. **Copy the default config** from the image:

```bash
docker run --rm --entrypoint cat sol1/rustguac:latest /opt/rustguac/config.toml.default > config.toml
```

2. **Edit** `config.toml` as needed (see [Configuration](configuration.md)):

```toml
# Example: allow SSH to private networks
ssh_allowed_networks = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
```

3. **Mount it** in your Docker Compose file or `docker run` command (see below).

If no config file is mounted, the container uses a built-in default on first start.

### Docker Compose example

```yaml
services:
  rustguac:
    image: sol1/rustguac:latest
    ports:
      - "8089:8089"
    volumes:
      - ./config.toml:/opt/rustguac/config.toml
      - rustguac-data:/opt/rustguac/data
      - rustguac-recordings:/opt/rustguac/recordings
    environment:
      - RUST_LOG=info

volumes:
  rustguac-data:
  rustguac-recordings:
```

## Option D: RPM package (build from source)

Pre-built RPM packages are not currently provided. An RPM spec file (`rustguac.spec`) and build script (`build-rpm.sh`) are included for Red Hat / Fedora / Rocky Linux based systems. You will need FreeRDP 3.x development headers installed.

```bash
# Install build dependencies (example for Rocky/RHEL 9)
sudo dnf install -y epel-release
sudo dnf config-manager --set-enabled crb
sudo dnf install -y gcc gcc-c++ make git autoconf automake libtool \
    freerdp-devel cairo-devel libjpeg-turbo-devel libpng-devel libwebp-devel \
    libssh2-devel openssl-devel libvncserver-devel pango-devel \
    pulseaudio-libs-devel rpm-build

# Build the RPM
bash build-rpm.sh
sudo rpm -i rustguac-*.rpm
```

RPM builds are untested — contributions and feedback are welcome.

## Option E: Development

```bash
# Clone guacamole-server alongside rustguac
git clone https://github.com/apache/guacamole-server.git ../guacamole-server

# Install build deps, build guacd, build + run rustguac
./dev.sh deps
./dev.sh build-guacd
./dev.sh start
```

For development with TLS:

```bash
./dev.sh generate-cert

cat > config.local.toml <<EOF
[tls]
cert_path = "cert.pem"
key_path = "key.pem"
guacd_cert_path = "cert.pem"
EOF

./dev.sh start
```

## Other Linux distributions

rustguac is built and tested against Debian 13 (Trixie). On other Linux
distributions the FreeRDP ABI is typically different, and the prebuilt
`.deb` will fail at runtime even if it installs cleanly. The most common
symptom is RDP sessions working visually but drive redirection and audio
failing with messages in the guacd log like:

```
Cannot create static channel "rdpdr": failed to load "guac-common-svc" plugin for FreeRDP.
Cannot create static channel "rdpsnd": failed to load "guac-common-svc" plugin for FreeRDP.
```

That is FreeRDP's plugin loader silently failing symbol resolution
against a different FreeRDP version than what guacd was compiled against.

### Recommended: Docker (Option C above)

The Docker image bundles guacd, FreeRDP, and all dependencies as a single
artifact and runs cleanly on any host that can run a recent Docker
daemon. This is the supported path for Ubuntu, RHEL/Rocky/Alma, Arch,
and any other non-Debian-13 distribution.

```bash
docker pull sol1/rustguac:latest
```

See [Option C: Docker](#option-c-docker) above for the full setup.

### Untested: building from source on Ubuntu 24.04 LTS

If you really need a bare-metal install on Ubuntu 24.04, you can build
locally, but be aware that **Ubuntu 24.04 ships FreeRDP 3.5.1**, which
is older than what our `patches/` directory targets (FreeRDP 3.15+ as
shipped by Debian 13). The patches will fail to apply or apply against
the wrong lines.

Two options:

**Option 1: skip the patches and build against system FreeRDP 3.5.**

```bash
# Build deps
sudo apt-get install -y \
    git build-essential autoconf automake libtool pkg-config cmake \
    libcairo2-dev libjpeg-dev libpng-dev libwebp-dev libssh2-1-dev \
    libssl-dev libvncserver-dev libpango1.0-dev libpulse-dev \
    libavcodec-dev libavformat-dev libavutil-dev libswscale-dev \
    libtelnet-dev libwebsockets-dev freerdp3-dev uuid-dev \
    chromium-browser tigervnc-standalone-server cryptsetup \
    curl ca-certificates

# Rust toolchain (1.96+ required for rusqlite 0.40 build)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Build guacd against system FreeRDP 3.5 (skip our 3.15+ patches)
git clone https://github.com/sol1/rustguac.git
git clone https://github.com/apache/guacamole-server.git
cd guacamole-server
git checkout 2980cf0   # same pin rustguac uses
autoreconf -fi
./configure --prefix=/opt/rustguac --with-rdp
make -j"$(nproc)"
sudo make install

# Build rustguac
cd ../rustguac
cargo build --release
bash build-deb.sh
sudo dpkg -i ../rustguac_*_amd64.deb
```

Drive redirection, audio, and clipboard should work. The 3.15-specific
bugs our patches address are not present in 3.5.x, so the unpatched
build is fine for that vintage of FreeRDP.

**Option 2: install FreeRDP 3.15+ from a third-party source** (e.g. a
PPA or build from source) and then run `install.sh` normally. Out of
scope for this guide.

Both paths are **untested by us**: we don't run CI against Ubuntu 24.04
and we don't ship `.deb`s for it. Issues experienced on Ubuntu will be
triaged as best-effort and will generally close with a pointer back to
the Docker image. If you do run rustguac on Ubuntu successfully (or
unsuccessfully), reports via GitHub issues are welcome and help inform
whether we eventually add a CI target.

### Other distributions

For RPM-based distros see [Option D: RPM package (build from source)](#option-d-rpm-package-build-from-source).
For everything else, the Docker image is the path of least resistance.

## System dependencies

For bare-metal installs, rustguac requires:

- **Rust toolchain** (1.75+)
- **guacd** (built from guacamole-server source)
- **Xvnc** (tigervnc-standalone-server) — for web browser sessions
- **Chromium** — for web browser sessions
- **cryptsetup** — for LUKS encrypted drive storage
- **Build libraries** for guacd: libcairo2, libjpeg, libpng, libwebp, libssh2, libssl, libvncserver, libpango, libpulse, ffmpeg, freerdp3

See `install.sh` for the full package list.

## guacamole-server patches

guacd requires patches to build and run correctly with FreeRDP 3.15+ as shipped in Debian 13. These patches are in the `patches/` directory and are applied automatically by all build scripts.

The patches fix:
1. **Autoconf `-Werror` vs deprecated FreeRDP headers** — FreeRDP 3.15 deprecates `codecs_free()`, breaking compile tests
2. **Deprecated function pointer API** — replaces `->input->MouseEvent()` etc. with safe FreeRDP 3.x functions
3. **NULL pointer dereference** — FreeRDP 3.x fires PubSub events before `guac_rdp_disp` is allocated
4. **Struct layout mismatch** — channel source files missing `config.h` see wrong field offsets when SSH support is enabled
