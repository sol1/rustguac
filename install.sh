#!/usr/bin/env bash
#
# install.sh — Install rustguac + guacd on Debian 13 (Trixie).
#
# Installs everything to /opt/rustguac with a systemd service.
#
# Usage:
#   sudo ./install.sh              Full install (build deps, guacd, rustguac)
#   sudo ./install.sh --deps-only  Only install system packages
#   sudo ./install.sh --no-deps    Skip apt install (assume deps already present)
#
set -euo pipefail

PREFIX="/opt/rustguac"
GUACD_SRC_URL="https://github.com/apache/guacamole-server.git"
GUACD_BRANCH="main"
BUILD_DIR="/tmp/rustguac-build-$$"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[install]${NC} $*"; }
warn()  { echo -e "${YELLOW}[install]${NC} $*"; }
error() { echo -e "${RED}[install]${NC} $*" >&2; }

SKIP_DEPS=0
DEPS_ONLY=0
NO_TLS=0
TLS_HOSTNAME=""
for arg in "$@"; do
    case "$arg" in
        --no-deps)     SKIP_DEPS=1 ;;
        --deps-only)   DEPS_ONLY=1 ;;
        --no-tls)      NO_TLS=1 ;;
        --hostname=*)  TLS_HOSTNAME="${arg#--hostname=}" ;;
        -h|--help)
            echo "Usage: sudo $0 [--deps-only|--no-deps] [--no-tls] [--hostname=FQDN]"
            echo ""
            echo "Options:"
            echo "  --deps-only       Only install system packages, then exit"
            echo "  --no-deps         Skip apt install (assume packages already present)"
            echo "  --no-tls          Skip TLS certificate generation (plain HTTP only)"
            echo "  --hostname=FQDN   Hostname for TLS certificate (default: system hostname)"
            exit 0
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo ./install.sh)"
    exit 1
fi

# Detect the real user who invoked sudo (for Rust toolchain install)
REAL_USER="${SUDO_USER:-root}"
REAL_HOME=$(eval echo "~$REAL_USER")

# ---------------------------------------------------------------------------
# Step 1: System packages
# ---------------------------------------------------------------------------
install_deps() {
    info "Installing system packages..."
    apt-get update

    # guacd build dependencies
    apt-get install -y \
        autoconf automake libtool pkg-config make gcc g++ git \
        libcairo2-dev libjpeg-dev libpng-dev libwebp-dev \
        libssh2-1-dev libssl-dev libvncserver-dev \
        libpango1.0-dev libpulse-dev \
        libavcodec-dev libavformat-dev libavutil-dev libswscale-dev \
        libcunit1-dev libtelnet-dev libwebsockets-dev \
        freerdp3-dev

    # uuid-dev (Debian standard) or fallback
    apt-get install -y uuid-dev 2>/dev/null || apt-get install -y libossp-uuid-dev || true

    # Xvnc and Chromium for web browser sessions
    apt-get install -y \
        tigervnc-standalone-server \
        chromium \
        x11-utils

    # Runtime utilities
    apt-get install -y \
        curl ca-certificates

    info "System packages installed."
}

if [[ $SKIP_DEPS -eq 0 ]]; then
    install_deps
fi

if [[ $DEPS_ONLY -eq 1 ]]; then
    info "Dependencies installed. Exiting (--deps-only)."
    exit 0
fi

# ---------------------------------------------------------------------------
# Step 2: Install Rust toolchain (if not present)
# ---------------------------------------------------------------------------
install_rust() {
    if sudo -u "$REAL_USER" bash -c 'command -v cargo' >/dev/null 2>&1; then
        info "Rust toolchain already installed."
        return 0
    fi

    info "Installing Rust toolchain for user $REAL_USER..."
    sudo -u "$REAL_USER" bash -c \
        'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
    info "Rust installed."
}

install_rust

# Source cargo env for build steps
CARGO_BIN="$REAL_HOME/.cargo/bin/cargo"
if [[ ! -x "$CARGO_BIN" ]]; then
    CARGO_BIN="$(sudo -u "$REAL_USER" bash -c 'source $HOME/.cargo/env 2>/dev/null; which cargo')"
fi

# ---------------------------------------------------------------------------
# Step 3: Build guacd from source
# ---------------------------------------------------------------------------
apply_guacd_patches() {
    local src="$1"
    local patch_dir="${SCRIPT_DIR}/patches"

    if [[ ! -d "$patch_dir" ]]; then
        return 0
    fi

    for patch in "$patch_dir"/*.patch; do
        [[ -f "$patch" ]] || continue
        if git -C "$src" apply --check "$patch" 2>/dev/null; then
            info "Applying patch: $(basename "$patch")"
            git -C "$src" apply "$patch"
        else
            info "Patch already applied or N/A: $(basename "$patch")"
        fi
    done
}

build_guacd() {
    info "Building guacd from source..."
    mkdir -p "$BUILD_DIR"

    if [[ -d "$SCRIPT_DIR/../guacamole-server/.git" ]]; then
        info "Using existing guacamole-server source at $SCRIPT_DIR/../guacamole-server"
        GUACD_SRC="$SCRIPT_DIR/../guacamole-server"
    else
        info "Cloning guacamole-server..."
        git clone --depth 1 --branch "$GUACD_BRANCH" "$GUACD_SRC_URL" "$BUILD_DIR/guacamole-server"
        GUACD_SRC="$BUILD_DIR/guacamole-server"
    fi

    apply_guacd_patches "$GUACD_SRC"

    cd "$GUACD_SRC"
    if [[ ! -f configure ]]; then
        info "Running autoreconf..."
        autoreconf -fi
    fi

    mkdir -p "$BUILD_DIR/guacd-build"
    cd "$BUILD_DIR/guacd-build"

    info "Configuring guacd..."
    "$GUACD_SRC/configure" \
        --prefix="$PREFIX" \
        --with-ssh \
        --with-vnc \
        --with-rdp \
        --without-telnet \
        --without-kubernetes \
        --disable-guacenc \
        --disable-guaclog \
        --disable-static

    info "Compiling guacd..."
    make -j"$(nproc)"

    info "Installing guacd to $PREFIX..."
    make install

    info "guacd installed: $PREFIX/sbin/guacd"
}

build_guacd

# ---------------------------------------------------------------------------
# Step 4: Build rustguac
# ---------------------------------------------------------------------------
build_rustguac() {
    info "Building rustguac..."
    cd "$SCRIPT_DIR"
    sudo -u "$REAL_USER" "$CARGO_BIN" build --release
    info "rustguac built."
}

build_rustguac

# ---------------------------------------------------------------------------
# Step 5: Install rustguac files
# ---------------------------------------------------------------------------
install_rustguac() {
    info "Installing rustguac to $PREFIX..."

    mkdir -p "$PREFIX"/{bin,data,recordings,static}

    # Binary
    cp "$SCRIPT_DIR/target/release/rustguac" "$PREFIX/bin/rustguac"
    chmod 755 "$PREFIX/bin/rustguac"

    # Static web assets
    cp -r "$SCRIPT_DIR/static/"* "$PREFIX/static/"

    # Default config (don't overwrite existing)
    if [[ ! -f "$PREFIX/config.toml" ]]; then
        local LISTEN_PORT="8089"
        if [[ $NO_TLS -eq 0 ]]; then
            LISTEN_PORT="443"
        fi
        cat > "$PREFIX/config.toml" <<TOMLEOF
listen_addr = "0.0.0.0:${LISTEN_PORT}"
guacd_addr = "127.0.0.1:4822"
recording_path = "/opt/rustguac/recordings"
static_path = "/opt/rustguac/static"
db_path = "/opt/rustguac/data/rustguac.db"
session_pending_timeout_secs = 60
xvnc_path = "Xvnc"
chromium_path = "chromium"
display_range_start = 100
display_range_end = 199
TOMLEOF

        if [[ $NO_TLS -eq 0 ]]; then
            cat >> "$PREFIX/config.toml" <<'TOMLEOF'

[tls]
cert_path = "/opt/rustguac/tls/cert.pem"
key_path = "/opt/rustguac/tls/key.pem"
guacd_cert_path = "/opt/rustguac/tls/cert.pem"
TOMLEOF
        fi

        info "Created default config at $PREFIX/config.toml"
    else
        info "Config already exists at $PREFIX/config.toml (not overwritten)"
    fi

    # Create rustguac system user (if not exists)
    if ! id -u rustguac >/dev/null 2>&1; then
        useradd --system --create-home --home-dir /home/rustguac --shell /usr/sbin/nologin rustguac
        info "Created system user 'rustguac'"
    fi

    chown -R rustguac:rustguac "$PREFIX/data" "$PREFIX/recordings"

    # Chromium policy: block devtools, file dialogs, password import (web session hardening)
    mkdir -p /etc/chromium/policies/managed
    cat > /etc/chromium/policies/managed/rustguac.json <<'POLICY'
{"AllowFileSelectionDialogs": false, "PasswordManagerEnabled": true, "ImportSavedPasswords": false, "DeveloperToolsAvailability": 2, "DownloadRestrictions": 3, "PrintingEnabled": false, "EditBookmarksEnabled": false, "BrowserSignin": 0, "SyncDisabled": true, "ExtensionInstallBlocklist": ["*"], "URLBlocklist": ["file://*", "chrome://*", "chrome-extension://*", "view-source:*", "javascript:*"], "URLAllowlist": ["chrome://policy"]}
POLICY

    info "rustguac installed to $PREFIX"
}

install_rustguac

# ---------------------------------------------------------------------------
# Step 6: Generate TLS certificate (unless --no-tls)
# ---------------------------------------------------------------------------
setup_tls() {
    if [[ $NO_TLS -eq 1 ]]; then
        info "Skipping TLS setup (--no-tls)"
        return 0
    fi

    mkdir -p "$PREFIX/tls"

    if [[ -f "$PREFIX/tls/cert.pem" && -f "$PREFIX/tls/key.pem" ]]; then
        info "TLS certificates already exist at $PREFIX/tls/ (not overwritten)"
        return 0
    fi

    local CERT_HOSTNAME="${TLS_HOSTNAME:-$(hostname -f 2>/dev/null || hostname)}"

    info "Generating self-signed TLS certificate for: $CERT_HOSTNAME"
    "$PREFIX/bin/rustguac" generate-cert \
        --hostname "$CERT_HOSTNAME" \
        --out-dir "$PREFIX/tls"

    chown -R rustguac:rustguac "$PREFIX/tls"
    chmod 600 "$PREFIX/tls/key.pem"
    chmod 644 "$PREFIX/tls/cert.pem"

    info "TLS certificate generated at $PREFIX/tls/"
    warn "This is a self-signed certificate for dev/testing."
    warn "For production, replace with real certificates from your CA."
}

setup_tls

# ---------------------------------------------------------------------------
# Step 6b: Drive / LUKS setup (optional, interactive)
# ---------------------------------------------------------------------------
# Env vars for non-interactive / automation:
#   RUSTGUAC_DRIVE_SETUP=yes|no   — skip the prompt
#   RUSTGUAC_DRIVE_SIZE=4G        — LUKS container size
#   RUSTGUAC_DRIVE_MOUNT=/mnt/rustguac-drives
#   RUSTGUAC_LUKS_DEVICE=/opt/rustguac/drives.luks
#   RUSTGUAC_LUKS_NAME=rustguac-drives
setup_drive() {
    local SETUP="${RUSTGUAC_DRIVE_SETUP:-}"
    local DRIVE_SIZE="${RUSTGUAC_DRIVE_SIZE:-4G}"
    local MOUNT_POINT="${RUSTGUAC_DRIVE_MOUNT:-/mnt/rustguac-drives}"
    local LUKS_DEVICE="${RUSTGUAC_LUKS_DEVICE:-$PREFIX/drives.luks}"
    local LUKS_NAME="${RUSTGUAC_LUKS_NAME:-rustguac-drives}"

    # If already set up, skip
    if [[ -f "$LUKS_DEVICE" ]]; then
        info "LUKS container already exists at $LUKS_DEVICE (skipping drive setup)"
        return 0
    fi

    # Check if cryptsetup is available
    if ! command -v cryptsetup &>/dev/null; then
        warn "cryptsetup not found — install cryptsetup-bin for encrypted drive support"
        return 0
    fi

    if [[ -z "$SETUP" ]]; then
        echo ""
        local AVAIL
        AVAIL=$(df -h "$(dirname "$LUKS_DEVICE")" | tail -1 | awk '{print $4}')
        info "Drive / File Transfer Setup (optional)"
        info "  Enables encrypted file transfer storage for RDP sessions."
        info "  Available space on $(dirname "$LUKS_DEVICE"): $AVAIL"
        info "  Default container size: $DRIVE_SIZE"
        echo ""
        read -rp "Set up encrypted drive volume? [y/N] (size: $DRIVE_SIZE): " SETUP
        if [[ "$SETUP" =~ ^[yY] ]]; then
            read -rp "Container size [$DRIVE_SIZE]: " USER_SIZE
            if [[ -n "$USER_SIZE" ]]; then
                DRIVE_SIZE="$USER_SIZE"
            fi
        fi
    fi

    if [[ ! "$SETUP" =~ ^[yY] ]]; then
        info "Skipping drive setup. You can set this up later."
        return 0
    fi

    info "Creating LUKS container: $LUKS_DEVICE ($DRIVE_SIZE)"

    # Parse size to MB for dd
    local SIZE_MB
    if [[ "$DRIVE_SIZE" =~ ^([0-9]+)[gG]$ ]]; then
        SIZE_MB=$(( ${BASH_REMATCH[1]} * 1024 ))
    elif [[ "$DRIVE_SIZE" =~ ^([0-9]+)[mM]$ ]]; then
        SIZE_MB="${BASH_REMATCH[1]}"
    else
        error "Invalid size format: $DRIVE_SIZE (use e.g. 4G, 512M)"
        return 1
    fi

    # Generate random key
    local LUKS_KEY
    LUKS_KEY=$(openssl rand -base64 32)

    # Create the container file
    dd if=/dev/zero of="$LUKS_DEVICE" bs=1M count="$SIZE_MB" status=progress 2>&1

    # Format LUKS
    echo -n "$LUKS_KEY" | cryptsetup luksFormat --batch-mode "$LUKS_DEVICE" -

    # Open, format filesystem, close
    echo -n "$LUKS_KEY" | cryptsetup open --type luks --key-file=- "$LUKS_DEVICE" "$LUKS_NAME"
    mkfs.ext4 -q "/dev/mapper/$LUKS_NAME"
    cryptsetup close "$LUKS_NAME"

    # Create mount point
    mkdir -p "$MOUNT_POINT"
    chown rustguac:rustguac "$MOUNT_POINT"

    # Set ownership of LUKS file
    chown rustguac:rustguac "$LUKS_DEVICE"
    chmod 600 "$LUKS_DEVICE"

    # Install sudoers rules
    info "Installing sudoers rules for LUKS management..."
    cat > /etc/sudoers.d/rustguac-drive <<SUDOERS
# rustguac LUKS drive management
rustguac ALL=(root) NOPASSWD: /usr/sbin/cryptsetup open --type luks --key-file=- $LUKS_DEVICE $LUKS_NAME
rustguac ALL=(root) NOPASSWD: /usr/sbin/cryptsetup close $LUKS_NAME
rustguac ALL=(root) NOPASSWD: /bin/mount /dev/mapper/$LUKS_NAME $MOUNT_POINT
rustguac ALL=(root) NOPASSWD: /usr/bin/mount /dev/mapper/$LUKS_NAME $MOUNT_POINT
rustguac ALL=(root) NOPASSWD: /bin/umount $MOUNT_POINT
rustguac ALL=(root) NOPASSWD: /usr/bin/umount $MOUNT_POINT
rustguac ALL=(root) NOPASSWD: /bin/chown *\:* $MOUNT_POINT
rustguac ALL=(root) NOPASSWD: /usr/bin/chown *\:* $MOUNT_POINT
SUDOERS
    chmod 0440 /etc/sudoers.d/rustguac-drive

    info "LUKS container created and formatted."
    echo ""
    info "IMPORTANT: Store this LUKS key in Vault:"
    info "  vault kv put -mount=<mount> rustguac/luks-key key='$LUKS_KEY'"
    echo ""
    info "Then add to your config.toml:"
    info "  [drive]"
    info "  enabled = true"
    info "  drive_path = \"$MOUNT_POINT\""
    info "  luks_device = \"$LUKS_DEVICE\""
    info "  luks_name = \"$LUKS_NAME\""
    info "  luks_key_path = \"rustguac/luks-key\""
    echo ""
    warn "The LUKS key above is shown ONCE. Save it to Vault now."
}

setup_drive

# ---------------------------------------------------------------------------
# Step 7: ldconfig for guacd libraries
# ---------------------------------------------------------------------------
setup_ldconfig() {
    echo "$PREFIX/lib" > /etc/ld.so.conf.d/rustguac.conf
    ldconfig
    info "Library path configured."
}

setup_ldconfig

# ---------------------------------------------------------------------------
# Step 8: systemd services
# ---------------------------------------------------------------------------
install_systemd() {
    info "Installing systemd services..."

    # guacd service
    cat > /etc/systemd/system/rustguac-guacd.service <<EOF
[Unit]
Description=Guacamole proxy daemon (guacd) for rustguac
After=network.target

[Service]
Type=simple
User=rustguac
ExecStart=$PREFIX/sbin/guacd -b 127.0.0.1 -l 4822 -L info -f -C $PREFIX/tls/cert.pem -K $PREFIX/tls/key.pem
Restart=on-failure
RestartSec=5
Environment=LD_LIBRARY_PATH=$PREFIX/lib

[Install]
WantedBy=multi-user.target
EOF

    # rustguac service
    cat > /etc/systemd/system/rustguac.service <<EOF
[Unit]
Description=rustguac web session proxy
After=network.target rustguac-guacd.service
Requires=rustguac-guacd.service

[Service]
Type=simple
User=rustguac
WorkingDirectory=$PREFIX
ExecStart=$PREFIX/bin/rustguac --config $PREFIX/config.toml serve
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable rustguac-guacd.service
    systemctl enable rustguac.service

    info "Systemd services installed and enabled."
    info "  sudo systemctl start rustguac    (starts both guacd + rustguac)"
}

install_systemd

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
rm -rf "$BUILD_DIR"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
info "============================================"
info "  rustguac installed to $PREFIX"
info "============================================"
echo ""
info "Next steps:"
info "  1. Create an admin:"
info "     $PREFIX/bin/rustguac --config $PREFIX/config.toml add-admin --name admin"
info ""
info "  2. Start the services:"
info "     sudo systemctl start rustguac"
info ""
if [[ $NO_TLS -eq 0 ]]; then
    info "  3. Open in browser:"
    info "     https://$(hostname -f 2>/dev/null || hostname)"
    info ""
    info "  Note: Using self-signed cert — browser will show a warning."
    info "  Replace $PREFIX/tls/cert.pem and key.pem with real certs for production."
else
    info "  3. Open in browser:"
    info "     http://localhost:8089"
fi
echo ""
