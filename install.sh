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
GUACD_COMMIT="6719b20d"  # Pin to known-good commit
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
        # An alias for the environment variable rather than a second switch
        # reaching the same place, so there is one thing to read when the
        # answer looks wrong. Set here, it also wins over an inherited
        # RUSTGUAC_DRIVE_SETUP=yes, which is the precedence an explicit flag
        # should have.
        --no-drive)    RUSTGUAC_DRIVE_SETUP=no ;;
        -h|--help)
            echo "Usage: sudo $0 [--deps-only|--no-deps] [--no-tls] [--no-drive]"
            echo "                        [--hostname=FQDN]"
            echo ""
            echo "Options:"
            echo "  --deps-only       Only install system packages, then exit"
            echo "  --no-deps         Skip apt install (assume packages already present)"
            echo "  --no-tls          Skip TLS certificate generation (plain HTTP only)"
            echo "  --no-drive        Skip the encrypted drive prompt (same as"
            echo "                    RUSTGUAC_DRIVE_SETUP=no)"
            echo "  --hostname=FQDN   Hostname for TLS certificate (default: system hostname)"
            echo ""
            echo "Environment:"
            echo "  The encrypted drive for RDP file transfer is the only part of this"
            echo "  installer that asks a question. It is skipped on its own when the"
            echo "  container already exists, when cryptsetup is missing, or when stdin"
            echo "  is not a terminal; these answer it otherwise."
            echo ""
            echo "  RUSTGUAC_DRIVE_SETUP    yes|no — answer the prompt without a terminal"
            echo "  RUSTGUAC_DRIVE_SIZE     LUKS container size (default: 4G)"
            echo "  RUSTGUAC_DRIVE_MOUNT    Mount point (default: /mnt/rustguac-drives)"
            echo "  RUSTGUAC_LUKS_DEVICE    Container path (default: PREFIX/drives.luks)"
            echo "  RUSTGUAC_LUKS_NAME      dm-crypt mapper name (default: rustguac-drives)"
            echo ""
            echo "  Settings for guacd itself belong in PREFIX/guacd.env, which is"
            echo "  created once and never overwritten; the unit files are rewritten on"
            echo "  every run, so anything set in them directly is lost at the next"
            echo "  install."
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
        freerdp3-dev libspice-client-glib-2.0-dev

    # uuid-dev (Debian standard) or fallback
    apt-get install -y uuid-dev 2>/dev/null || apt-get install -y libossp-uuid-dev || true

    # Xvnc and Chromium for web browser sessions
    apt-get install -y \
        tigervnc-standalone-server \
        chromium chromium-sandbox \
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
        git clone "$GUACD_SRC_URL" "$BUILD_DIR/guacamole-server"
        git -C "$BUILD_DIR/guacamole-server" checkout "$GUACD_COMMIT"
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
        --with-spice \
        --without-telnet \
        --without-kubernetes \
        --disable-guacenc \
        --disable-guaclog \
        --disable-guacclip \
        --disable-static

    info "Compiling guacd..."
    make -j"$(nproc)"

    info "Installing guacd to $PREFIX..."
    make install

    # Verify FreeRDP plugins were installed (required for drive redirection + audio)
    local freerdp_plugin_dir
    freerdp_plugin_dir=$(pkg-config --variable=libdir freerdp3 2>/dev/null || pkg-config --variable=libdir freerdp2 2>/dev/null)/freerdp3
    if [[ -d "$freerdp_plugin_dir" ]]; then
        local plugin_count
        plugin_count=$(find "$freerdp_plugin_dir" -name "libguac*" 2>/dev/null | wc -l)
        if [[ "$plugin_count" -gt 0 ]]; then
            info "FreeRDP plugins installed to $freerdp_plugin_dir ($plugin_count plugins)"
        else
            warn "FreeRDP plugins NOT found in $freerdp_plugin_dir — drive redirection will not work"
            # Try to copy from the build
            if [[ -d "$BUILD_DIR/guacd-build/src/protocols/rdp/.libs" ]]; then
                info "Copying FreeRDP plugins manually..."
                cp -a "$BUILD_DIR/guacd-build/src/protocols/rdp/.libs"/libguac-common-svc-client*.so* "$freerdp_plugin_dir/" 2>/dev/null || true
                cp -a "$BUILD_DIR/guacd-build/src/protocols/rdp/.libs"/libguacai-client*.so* "$freerdp_plugin_dir/" 2>/dev/null || true
            fi
        fi
    fi

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

    # A running binary cannot be overwritten -- cp fails with "Text file busy"
    # and leaves the old one in place, after the script has already reported
    # building the new one. That failure reads exactly like a successful
    # upgrade that changed nothing, which is the worst shape a deploy problem
    # can take. Stop it here and restart it at the end, but only if it was
    # running: a first install should not be started behind the operator's
    # back before there is an admin account.
    WAS_RUNNING=0
    if systemctl is-active --quiet rustguac 2>/dev/null; then
        WAS_RUNNING=1
        info "Stopping rustguac for the upgrade..."
        systemctl stop rustguac
    fi

    # Binary
    cp "$SCRIPT_DIR/target/release/rustguac" "$PREFIX/bin/rustguac"
    chmod 755 "$PREFIX/bin/rustguac"

    # Static web assets, mirrored rather than copied over the top.
    #
    # An overlay copy never removes anything, so a file that leaves the repo
    # stays served for ever. That is not only clutter: ServeDir is rooted at
    # $PREFIX/static, so whatever is left there is reachable. A stray nested
    # copy of the whole tree sat at $PREFIX/static/static from July until
    # September 2026, serving two-month-old HTML and JavaScript at /static/...
    # to anyone who asked for it, and three files from an abandoned branch
    # outlived the branch the same way.
    #
    # `static/.` rather than `static/*` because the latter is one slip away
    # from `cp -r static "$PREFIX/static/"`, which nests the tree instead of
    # filling the directory -- which is how that copy got there.
    #
    # Operators are told to put their own files here too (a theme logo_url
    # such as /acme-logo.png, see docs/configuration.md), so a blind mirror
    # would delete them on every upgrade. Instead each install records what
    # it put there, and the next one removes only files from that record that
    # have since left the repo. Anything an operator added is never in the
    # record and is left alone.
    local manifest="$PREFIX/.static-installed-files"
    local new_manifest
    new_manifest="$(mktemp)"
    (cd "$SCRIPT_DIR/static" && find . -type f | sort) > "$new_manifest"
    if [[ -f "$manifest" ]]; then
        comm -23 <(sort "$manifest") "$new_manifest" | while IFS= read -r stale; do
            case "$stale" in
                ./*) ;;
                *) continue ;;
            esac
            [[ "$stale" == *..* ]] && continue
            rm -f -- "$PREFIX/static/${stale#./}"
            info "Removed stale static file ${stale#./}"
        done
    fi
    # The nested copy described above predates any record, so name it.
    if [[ -d "$PREFIX/static/static" && ! -e "$SCRIPT_DIR/static/static" ]]; then
        rm -rf -- "$PREFIX/static/static"
        info "Removed stray nested $PREFIX/static/static"
    fi
    cp -r "$SCRIPT_DIR/static/." "$PREFIX/static/"
    install -m 0644 "$new_manifest" "$manifest"
    rm -f "$new_manifest"

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

    # Chromium policy: web session hardening (block file dialogs, printing, extensions, etc.)
    # DeveloperToolsAvailability=0: DevTools/CDP allowed (needed for login scripts).
    # Users can't reach chrome://devtools anyway — chrome://* is in URLBlocklist.
    mkdir -p /etc/chromium/policies/managed
    cat > /etc/chromium/policies/managed/rustguac.json <<'POLICY'
{"AllowFileSelectionDialogs": false, "PasswordManagerEnabled": true, "ImportSavedPasswords": false, "DeveloperToolsAvailability": 0, "DownloadRestrictions": 3, "PrintingEnabled": false, "EditBookmarksEnabled": false, "BrowserSignin": 0, "SyncDisabled": true, "ExtensionInstallBlocklist": ["*"], "URLBlocklist": ["file://*", "chrome://*", "chrome-extension://*", "view-source:*", "javascript:*"], "URLAllowlist": ["chrome://policy"]}
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

    # Only ask if there is someone there to answer. Run from a pipe, a
    # nohup, CI or any other non-interactive context, `read` gets EOF
    # immediately under `set -e`... or worse, waits for ever holding a
    # terminal that no one is watching. This prompt sits *after* the binary
    # and the assets are installed, so a hang here looks like a deploy that
    # completed except for the service coming back -- which is exactly how it
    # presented, repeatedly, before this guard.
    #
    # RUSTGUAC_DRIVE_SETUP=yes|no answers it without a terminal.
    if [[ -z "$SETUP" && ! -t 0 ]]; then
        SETUP="no"
        info "Drive / File Transfer Setup skipped (not interactive)."
        info "  Set RUSTGUAC_DRIVE_SETUP=yes to enable it from a script."
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
rustguac ALL=(root) NOPASSWD: /bin/chown rustguac\:rustguac $MOUNT_POINT
rustguac ALL=(root) NOPASSWD: /usr/bin/chown rustguac\:rustguac $MOUNT_POINT
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

    # guacd environment file. Created only if absent -- the unit files below
    # are rewritten on every run, so anything set directly in them (or via
    # "systemctl edit") is lost on the next install. Local settings belong
    # here instead, and this file is never overwritten.
    if [[ ! -f "$PREFIX/guacd.env" ]]; then
        cat > "$PREFIX/guacd.env" <<'EOF'
# Environment for rustguac-guacd. Preserved across reinstalls.
# Uncomment to enable; restart rustguac-guacd after changing.

# guacd log level: trace, debug, info, warning, error. H.264 passthrough logs
# per-surface-command codec detail at trace and per-frame detail at debug.
#GUACD_LOG_LEVEL=debug
EOF
        chown rustguac:rustguac "$PREFIX/guacd.env" 2>/dev/null || true
        info "Created $PREFIX/guacd.env (edit to set guacd environment)."
    else
        info "Keeping existing $PREFIX/guacd.env"
    fi

    # guacd service
    cat > /etc/systemd/system/rustguac-guacd.service <<EOF
[Unit]
Description=Guacamole proxy daemon (guacd) for rustguac
After=network.target

[Service]
Type=simple
User=rustguac
ExecStart=/bin/sh -c 'exec $PREFIX/sbin/guacd -b 127.0.0.1 -l 4822 -L \${GUACD_LOG_LEVEL:-info} -f -C $PREFIX/tls/cert.pem -K $PREFIX/tls/key.pem'
Restart=on-failure
RestartSec=5
Environment=LD_LIBRARY_PATH=$PREFIX/lib
EnvironmentFile=-$PREFIX/guacd.env

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

    # Warn about systemd drop-ins. They merge with the unit written above and
    # win, but live in a separate directory this script never touches, so a
    # forgotten "systemctl edit" silently overrides everything here -- including
    # ExecStart, which discards the log-level wrapper and any flags set above.
    local dropin_dir="/etc/systemd/system/rustguac-guacd.service.d"
    if compgen -G "$dropin_dir/*.conf" > /dev/null; then
        warn "Systemd drop-in overrides exist and take precedence over the unit"
        warn "just written. They are NOT managed by this installer:"
        for f in "$dropin_dir"/*.conf; do
            warn "  $f"
            sed 's/^/      /' "$f" | while read -r line; do warn "$line"; done
        done
        warn "Review with: systemctl cat rustguac-guacd"
        warn "Settings belong in $PREFIX/guacd.env instead, which persists."
    fi

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
# Restart, if this was an upgrade of a running service
# ---------------------------------------------------------------------------
# guacd first, and whenever it is running. `make install` replaced its binary
# and libraries above, but a running guacd keeps executing the old ones, and
# restarting rustguac does not touch it: Requires= starts a stopped guacd and
# never restarts a running one. So an upgrade otherwise rebuilt guacd and then
# went on serving the previous build until someone restarted it by hand. Live
# sessions are not a concern here -- they go through rustguac, which is
# already stopped for the upgrade or was never running.
if systemctl is-active --quiet rustguac-guacd 2>/dev/null; then
    info "Restarting guacd..."
    systemctl restart rustguac-guacd
    sleep 1
    if ! systemctl is-active --quiet rustguac-guacd; then
        error "guacd did not come back up. Check: journalctl -u rustguac-guacd -n 50"
        exit 1
    fi
fi

# rustguac only when it was already running. A first install leaves it stopped
# so that an admin account can be created before anything is reachable.
if [[ "${WAS_RUNNING:-0}" -eq 1 ]]; then
    info "Restarting rustguac..."
    systemctl restart rustguac
    sleep 2
    if systemctl is-active --quiet rustguac; then
        info "rustguac is running."
    else
        error "rustguac did not come back up. Check: journalctl -u rustguac -n 50"
        exit 1
    fi
fi

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
if [[ "${WAS_RUNNING:-0}" -eq 1 ]]; then
    info "  2. Services were already running and have been restarted."
else
    info "  2. Start the services:"
    info "     sudo systemctl start rustguac"
fi
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
