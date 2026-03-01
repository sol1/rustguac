# Installation

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

4. **(Optional) Set up encrypted drive storage:**

```bash
sudo /opt/rustguac/bin/drive-setup.sh
```

See [Drive / File Transfer](integrations.md#drive--file-transfer--luks-encryption) for details.

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

### Docker Compose example

```yaml
services:
  rustguac:
    image: sol1/rustguac:latest
    ports:
      - "8089:8089"
    volumes:
      - rustguac-data:/opt/rustguac/data
      - rustguac-recordings:/opt/rustguac/recordings
    environment:
      - RUST_LOG=info

volumes:
  rustguac-data:
  rustguac-recordings:
```

## Option D: RPM package

An RPM spec is available for Red Hat / Fedora / Rocky Linux based systems:

```bash
bash build-rpm.sh
sudo rpm -i rustguac-*.rpm
```

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
