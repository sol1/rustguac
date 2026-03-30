#!/bin/bash
# Setup GFX pipeline with H.264 encoding for xrdp on Debian 13 (trixie).
#
# This script installs a desktop environment, rebuilds xrdp from the Debian
# sid source package with x264 support, and configures the GFX pipeline.
#
# The stock Debian 13 xrdp package does NOT include x264 support.
# Sid is added temporarily for the xrdp rebuild, then removed.
#
# Run as root on the xrdp target machine (not the rustguac server).
# Requires: Debian 13 (trixie), ~15 minutes.
#
# Usage: sudo bash setup-xrdp-gfx.sh [--desktop mate|xfce|kde|gnome|none]
#
# Includes PulseAudio xrdp audio module (no separate audio script needed).

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo bash $0)"
    exit 1
fi

# ── Diagnostic function ──────────────────────────────────────────────
run_diagnose() {
    echo "============================================"
    echo "  xrdp Diagnostic Report"
    echo "============================================"
    echo ""

    echo "── System ──"
    echo "  OS:   $(lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2)"
    echo "  User: $(whoami) (uid $(id -u))"
    echo ""

    echo "── Packages ──"
    echo "  xrdp:      $(dpkg -l xrdp 2>/dev/null | awk '/^ii/{print $3}' || echo 'NOT INSTALLED')"
    echo "  xorgxrdp:  $(dpkg -l xorgxrdp 2>/dev/null | awk '/^ii/{print $3}' || echo 'NOT INSTALLED')"
    echo "  x264 link: $(ldd /usr/sbin/xrdp 2>/dev/null | grep -o 'libx264.*' || echo 'NOT LINKED')"
    echo ""

    echo "── Services ──"
    echo "  xrdp:         $(systemctl is-active xrdp 2>/dev/null)"
    echo "  xrdp-sesman:  $(systemctl is-active xrdp-sesman 2>/dev/null)"
    echo ""

    echo "── Config ──"
    echo "  autorun:   $(grep '^autorun=' /etc/xrdp/xrdp.ini 2>/dev/null || echo 'NOT SET')"
    echo "  Xwrapper:  $(cat /etc/X11/Xwrapper.config 2>/dev/null | grep allowed_users || echo 'NOT SET')"
    echo "  startwm:   $(grep '^exec ' /etc/xrdp/startwm.sh 2>/dev/null || echo 'NOT SET')"
    echo "  gfx.toml:  $([ -f /etc/xrdp/gfx.toml ] && echo 'exists' || echo 'MISSING')"
    CODEC=$(grep 'order' /etc/xrdp/gfx.toml 2>/dev/null)
    [ -n "$CODEC" ] && echo "  codecs:    $CODEC"
    echo ""

    echo "── Audio modules ──"
    SINK_SO=$(find /usr/lib -name "module-xrdp-sink.so" 2>/dev/null | head -1)
    echo "  module-xrdp-sink.so:   ${SINK_SO:-NOT FOUND}"
    echo "  module-xrdp-source.so: $(find /usr/lib -name 'module-xrdp-source.so' 2>/dev/null | head -1)"
    echo "  autostart:             $([ -f /etc/xdg/autostart/pulseaudio-xrdp.desktop ] && echo 'exists' || echo 'MISSING')"
    echo ""

    echo "── Audio processes (this user) ──"
    PA_PID=$(ps -u "$(whoami)" -o pid,comm 2>/dev/null | grep pulseaudio | awk '{print $1}' | head -1)
    PW_PID=$(ps -u "$(whoami)" -o pid,comm 2>/dev/null | grep pipewire-pulse | awk '{print $1}' | head -1)
    [ -n "$PA_PID" ] && echo "  pulseaudio:     running (pid $PA_PID)" || echo "  pulseaudio:     NOT RUNNING"
    [ -n "$PW_PID" ] && echo "  pipewire-pulse: running (pid $PW_PID) ← PROBLEM: blocks xrdp audio" || echo "  pipewire-pulse: not running (good)"
    echo ""

    echo "── Audio sinks (this user) ──"
    SINKS=$(pactl list sinks short 2>/dev/null)
    if [ -n "$SINKS" ]; then
        echo "$SINKS" | sed 's/^/  /'
        if echo "$SINKS" | grep -q xrdp; then
            echo "  ✓ xrdp-sink present"
        else
            echo "  ✗ xrdp-sink MISSING — try: pactl load-module module-xrdp-sink"
        fi
    else
        echo "  No sinks (pactl not reachable)"
    fi
    echo ""

    echo "── Audio server info ──"
    pactl info 2>/dev/null | grep -E "Server Name|Default Sink" | sed 's/^/  /' || echo "  pactl not reachable"
    echo ""

    echo "── PipeWire vs PulseAudio (systemd global) ──"
    echo "  pipewire-pulse.socket: $(systemctl --global is-enabled pipewire-pulse.socket 2>/dev/null || echo 'unknown') (should be masked)"
    echo "  pulseaudio.socket:     $(systemctl --global is-enabled pulseaudio.socket 2>/dev/null || echo 'unknown') (should be enabled)"
    echo ""

    echo "── User systemd audio units ──"
    echo "  pipewire-pulse: $(systemctl --user is-active pipewire-pulse.service 2>/dev/null || echo 'unknown')"
    echo "  pulseaudio:     $(systemctl --user is-active pulseaudio.service 2>/dev/null || echo 'unknown')"
    echo ""

    # Privileged checks (only if root)
    if [ "$(id -u)" -eq 0 ]; then
        echo "── Active xrdp sessions ──"
        SESSIONS=$(ps aux | grep xrdp-sesexec | grep -v grep)
        if [ -n "$SESSIONS" ]; then
            echo "$SESSIONS" | awk '{print "  pid " $2}'
            for USER_HOME in /home/*/; do
                USER=$(basename "$USER_HOME")
                USER_ID=$(id -u "$USER" 2>/dev/null) || continue
                if ps -u "$USER" 2>/dev/null | grep -q Xorg; then
                    echo "  $USER:"
                    sudo -u "$USER" XDG_RUNTIME_DIR="/run/user/$USER_ID" pactl list sinks short 2>/dev/null | sed 's/^/    /' || echo "    pactl not reachable"
                fi
            done
        else
            echo "  No active sessions"
        fi
        echo ""

        echo "── Recent xrdp log (errors/warnings) ──"
        grep -iE "error|warn|fail" /var/log/xrdp-sesman.log 2>/dev/null | tail -5 | sed 's/^/  /'
        echo ""

        echo "── Sid repo (should be removed) ──"
        if [ -f /etc/apt/sources.list.d/sid.list ]; then
            echo "  WARNING: sid.list still exists — run: rm /etc/apt/sources.list.d/sid.list"
        else
            echo "  Clean (no sid repo)"
        fi
    else
        echo "── Run as root for additional checks ──"
        echo "  sudo bash $0 --diagnose"
    fi

    exit 0
}

# ── Help ─────────────────────────────────────────────────────────────
show_help() {
    cat << 'HELPEOF'
Usage: sudo bash setup-xrdp-gfx.sh [OPTIONS]

Set up xrdp with H.264 encoding, GFX pipeline, desktop environment,
and audio redirection on Debian 13 (trixie).

Options:
  --desktop DESKTOP  Desktop environment to install (default: mate)
                     mate   - MATE desktop (recommended, Windows-like, no GPU needed)
                     xfce   - XFCE (lightweight, reliable)
                     kde    - KDE Plasma (requires GPU or software rendering)
                     gnome  - GNOME (may need GPU for Wayland)
                     none   - skip desktop install (bring your own)

  --diagnose         Run diagnostic checks and exit. Shows package versions,
                     service status, audio config, and active session state.
                     Can be run as regular user or root (root shows more).

  --help             Show this help and exit.

What this script does:
  Phase 1 (pure trixie):
    1. Install desktop environment
    2. Install build tools (build-essential, libx264-dev, etc.)
    3. Build PulseAudio xrdp audio module from source
    4. Switch from PipeWire-pulse to real PulseAudio

  Phase 2 (temporary sid):
    5. Add Debian sid repo with pinning
    6. Install xorgxrdp from sid
    7. Rebuild xrdp from sid source with --enable-x264
    8. Remove sid repo

  Phase 3 (configure):
    9. Set Xorg backend, Xwrapper, startwm.sh
   10. Create gfx.toml (H.264 + x264 encoder)
   11. Restart xrdp

Examples:
  sudo bash setup-xrdp-gfx.sh                    # MATE desktop (default)
  sudo bash setup-xrdp-gfx.sh --desktop kde      # KDE Plasma
  sudo bash setup-xrdp-gfx.sh --desktop none     # No desktop (headless)
  bash setup-xrdp-gfx.sh --diagnose              # Troubleshoot (no root needed)

For use with rustguac: https://github.com/sol1/rustguac
HELPEOF
    exit 0
}

# Parse arguments
DESKTOP="mate"
while [ $# -gt 0 ]; do
    case "$1" in
        --desktop) DESKTOP="$2"; shift 2 ;;
        --desktop=*) DESKTOP="${1#*=}"; shift ;;
        --diagnose|--diag) run_diagnose ;;
        --help|-h) show_help ;;
        *) echo "Unknown option: $1. Try --help"; exit 1 ;;
    esac
done

case "$DESKTOP" in
    xfce|kde|gnome|mate|none) ;;
    *) echo "Error: --desktop must be mate, xfce, kde, gnome, or none"; exit 1 ;;
esac

echo "============================================"
echo "  xrdp GFX + H.264 Setup for Debian 13"
echo "  Desktop: $DESKTOP"
echo "============================================"
echo ""

# ══════════════════════════════════════════════════════════════════════
# Phase 1: Install everything from trixie (before touching sid)
# ══════════════════════════════════════════════════════════════════════

echo "=== Step 1: Installing desktop environment ($DESKTOP) ==="
apt-get update -qq
case "$DESKTOP" in
    xfce)
        DEBIAN_FRONTEND=noninteractive apt-get install -y task-xfce-desktop
        STARTWM_CMD="exec startxfce4"
        ;;
    kde)
        DEBIAN_FRONTEND=noninteractive apt-get install -y task-kde-desktop
        STARTWM_CMD="exec startplasma-x11"
        ;;
    gnome)
        DEBIAN_FRONTEND=noninteractive apt-get install -y task-gnome-desktop
        STARTWM_CMD="exec gnome-session"
        ;;
    mate)
        DEBIAN_FRONTEND=noninteractive apt-get install -y mate-desktop-environment
        STARTWM_CMD="exec mate-session"
        ;;
    none)
        echo "  Skipping desktop install"
        STARTWM_CMD=""
        ;;
esac
echo ""

echo "=== Step 2: Installing build tools ==="
apt-get install -y build-essential devscripts libx264-dev libpulse-dev \
    git autoconf libtool m4 dpkg-dev pulseaudio
echo ""

echo "=== Step 3: Building PulseAudio xrdp audio module ==="
AUDIO_BUILD_DIR=$(mktemp -d /tmp/xrdp-audio-build.XXXXXX)
cd "$AUDIO_BUILD_DIR"
git clone --depth 1 https://github.com/neutrinolabs/pulseaudio-module-xrdp.git
cd pulseaudio-module-xrdp
scripts/install_pulseaudio_sources_apt.sh
./bootstrap
./configure PULSE_DIR=/root/pulseaudio.src
make
make install
SINK_SO=$(find /usr/lib -name "module-xrdp-sink.so" 2>/dev/null | head -1)
if [ -n "$SINK_SO" ]; then
    echo "  Audio module installed: $SINK_SO"
else
    echo "  WARNING: module-xrdp-sink.so not found after install"
fi
AUTOSTART="/etc/xdg/autostart/pulseaudio-xrdp.desktop"
if [ -f "$AUTOSTART" ]; then
    echo "  Autostart: $AUTOSTART"
else
    echo "  WARNING: autostart file not created by make install"
    echo "  Creating manually..."
    mkdir -p /etc/xdg/autostart
    cat > "$AUTOSTART" << 'ASEOF'
[Desktop Entry]
Type=Application
Name=PulseAudio xrdp modules
Exec=/usr/bin/pactl load-module module-xrdp-sink
NoDisplay=true
OnlyShowIn=XRDP;
ASEOF
    echo "  Created $AUTOSTART"
fi
rm -rf "$AUDIO_BUILD_DIR"

# Debian 13 defaults to PipeWire-pulse, but xrdp audio modules require
# real PulseAudio. Disable PipeWire-pulse and enable PulseAudio globally.
if systemctl --global is-enabled pipewire-pulse.socket >/dev/null 2>&1; then
    echo "  Switching from PipeWire-pulse to PulseAudio (required for xrdp audio)"
    systemctl --global disable pipewire-pulse.socket pipewire-pulse.service 2>/dev/null || true
    systemctl --global mask pipewire-pulse.socket pipewire-pulse.service 2>/dev/null || true
    systemctl --global enable pulseaudio.service pulseaudio.socket 2>/dev/null || true
fi
echo ""

# ══════════════════════════════════════════════════════════════════════
# Phase 2: Temporarily add sid, rebuild xrdp with x264, then remove sid
# ══════════════════════════════════════════════════════════════════════

echo "=== Step 4: Adding sid repo (temporary) ==="
SID_LIST="/etc/apt/sources.list.d/sid.list"
PIN_FILE="/etc/apt/preferences.d/pin-trixie"

printf "deb http://deb.debian.org/debian sid main\ndeb-src http://deb.debian.org/debian sid main\n" > "$SID_LIST"

if [ ! -f "$PIN_FILE" ]; then
    cat > "$PIN_FILE" << 'PINEOF'
Package: *
Pin: release a=trixie
Pin-Priority: 900

Package: *
Pin: release a=unstable
Pin-Priority: 100
PINEOF
fi

apt-get update -qq
echo ""

echo "=== Step 5: Installing xorgxrdp from sid ==="
apt-get install -y -t unstable xorgxrdp
XORGXRDP_VER=$(dpkg -l xorgxrdp | awk '/^ii/{print $3}')
echo "  xorgxrdp version: $XORGXRDP_VER"
echo ""

echo "=== Step 6: Rebuilding xrdp with x264 support ==="

# Install xrdp build dependencies
apt-get build-dep -y -t unstable xrdp

# Get xrdp source from sid
BUILD_DIR=$(mktemp -d /tmp/xrdp-build.XXXXXX)
echo "  Build directory: $BUILD_DIR"
cd "$BUILD_DIR"

# Find the latest version in sid
XRDP_SID_VER=$(apt-cache showsrc -t unstable xrdp 2>/dev/null | grep "^Version:" | awk '{print $2}' | sort -V | tail -1)
if [ -z "$XRDP_SID_VER" ]; then
    echo "Error: cannot find xrdp source in sid"
    exit 1
fi
echo "  Building xrdp $XRDP_SID_VER from sid source"

apt-get source -t unstable "xrdp=$XRDP_SID_VER"
XRDP_DIR=$(ls -d xrdp-* | head -1)
cd "$XRDP_DIR"

# Patch debian/rules to add --enable-x264
if grep -q -- '--enable-x264' debian/rules; then
    echo "  debian/rules already has --enable-x264"
elif grep -q -- '--enable-opus' debian/rules; then
    sed -i "s|--enable-opus|--enable-opus --enable-x264|" debian/rules
    echo "  Patched debian/rules: added --enable-x264 (after --enable-opus)"
else
    sed -i '0,/--\(enable\|with\)-/{s|$| --enable-x264|}' debian/rules
    echo "  Patched debian/rules: appended --enable-x264"
fi

# Ensure libx264-dev is in Build-Depends
if grep -q 'libx264-dev' debian/control; then
    echo "  debian/control already has libx264-dev"
else
    sed -i "s|^ autoconf,| libx264-dev,\n autoconf,|" debian/control
    echo "  Patched debian/control: added libx264-dev"
fi

# Build
echo "  Building (this takes a few minutes)..."
dpkg-buildpackage -b -uc -us -j"$(nproc)" > /tmp/xrdp-build.log 2>&1
if [ $? -ne 0 ]; then
    echo "  Build failed! See /tmp/xrdp-build.log"
    exit 1
fi

# Install (apt -f resolves any missing dependencies like ssl-cert)
DEB=$(ls "$BUILD_DIR"/xrdp_*.deb | head -1)
echo "  Installing $DEB"
dpkg -i "$DEB" || true
apt-get install -f -y

# Verify x264 is linked
if ldd /usr/sbin/xrdp 2>/dev/null | grep -q libx264; then
    echo "  Verified: xrdp linked to libx264"
else
    echo "  WARNING: xrdp does not appear to be linked to libx264"
fi

# Cleanup build
rm -rf "$BUILD_DIR"

# Remove sid repo to prevent dependency pollution
echo "  Removing sid repo (no longer needed)"
rm -f "$SID_LIST"
apt-get update -qq
echo ""

# ══════════════════════════════════════════════════════════════════════
# Phase 3: Configure xrdp
# ══════════════════════════════════════════════════════════════════════

echo "=== Step 7: Configuring Xorg backend ==="
XRDP_INI="/etc/xrdp/xrdp.ini"

if grep -q "^autorun=Xorg" "$XRDP_INI"; then
    echo "  Already set to Xorg"
elif grep -q "^autorun=" "$XRDP_INI"; then
    sed -i "s/^autorun=.*/autorun=Xorg/" "$XRDP_INI"
    echo "  Set autorun=Xorg"
else
    echo "autorun=Xorg" >> "$XRDP_INI"
    echo "  Added autorun=Xorg"
fi

# Allow non-root to start Xorg
XWRAPPER="/etc/X11/Xwrapper.config"
if [ -f "$XWRAPPER" ]; then
    if grep -q "allowed_users=anybody" "$XWRAPPER"; then
        echo "  Xwrapper already allows anybody"
    else
        sed -i "s/^allowed_users=.*/allowed_users=anybody/" "$XWRAPPER"
        echo "  Set Xwrapper allowed_users=anybody"
    fi
else
    echo "allowed_users=anybody" > "$XWRAPPER"
    echo "  Created Xwrapper with allowed_users=anybody"
fi

# Set startwm.sh
if [ -n "$STARTWM_CMD" ]; then
    cat > /etc/xrdp/startwm.sh << WMEOF
#!/bin/sh
if test -r /etc/profile; then
    . /etc/profile
fi
if test -r ~/.profile; then
    . ~/.profile
fi
$STARTWM_CMD
WMEOF
    chmod 755 /etc/xrdp/startwm.sh
    echo "  Set startwm.sh to: $STARTWM_CMD"
fi
echo ""

echo "=== Step 8: Creating GFX configuration ==="
GFX_CONF="/etc/xrdp/gfx.toml"
if [ -f "$GFX_CONF" ]; then
    cp "$GFX_CONF" "${GFX_CONF}.bak"
    echo "  Backed up existing $GFX_CONF"
fi

cat > "$GFX_CONF" << 'EOF'
# GFX Pipeline Configuration for xrdp
# Generated by rustguac contrib/setup-xrdp-gfx.sh

[codec]
order = ["H.264", "RFX"]
h264_encoder = "x264"

[x264.default]
preset = "ultrafast"
tune = "zerolatency"
profile = "main"
vbv_max_bitrate = 0
vbv_buffer_size = 0
fps_num = 60
fps_den = 1
threads = 1

[x264.lan]
# inherits default — uncapped bitrate, 60fps

[x264.wan]
vbv_max_bitrate = 15000
vbv_buffer_size = 1500

[x264.broadband_high]
preset = "superfast"
vbv_max_bitrate = 8000
vbv_buffer_size = 800

[x264.broadband_low]
preset = "veryfast"
vbv_max_bitrate = 1600
vbv_buffer_size = 66
EOF
echo "  Created $GFX_CONF"
echo ""

echo "=== Step 9: Restarting xrdp ==="
systemctl restart xrdp
echo "  xrdp restarted"

echo ""
echo "============================================"
echo "  Setup complete!"
echo "============================================"
echo ""
echo "xrdp is now configured with:"
echo "  - xrdp $(dpkg -l xrdp | awk '/^ii/{print $3}') rebuilt with x264 support"
echo "  - xorgxrdp $XORGXRDP_VER"
echo "  - Desktop: $DESKTOP"
echo "  - Xorg backend (required for GFX pipeline)"
echo "  - H.264 encoding via x264 (60fps LAN)"
echo "  - PulseAudio xrdp audio module installed"
echo "  - Sid repo removed (clean trixie state)"
echo ""
echo "Next steps:"
echo "  In rustguac, enable GFX + H.264 Passthrough on RDP entries"
echo ""
echo "To troubleshoot, run: sudo bash $(basename "$0") --diagnose"
