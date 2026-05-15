#!/bin/bash
# Setup GFX pipeline with H.264 encoding for xrdp on Debian 13 (trixie)
# or Linux Mint Debian Edition 7 (LMDE 7, based on trixie).
#
# This script installs a desktop environment, rebuilds xrdp from the Debian
# sid source package with x264 support, and configures the GFX pipeline.
#
# The stock Debian 13 xrdp package does NOT include x264 support.
# Sid is added temporarily for the xrdp rebuild, then removed.
#
# Run as root on the xrdp target machine (not the rustguac server).
# Requires: Debian 13 (trixie) or LMDE 7, ~15 minutes.
#
# Usage: sudo bash setup-xrdp-gfx.sh [--desktop mate|xfce|kde|gnome|none]
#
# Includes PulseAudio xrdp audio module (no separate audio script needed).

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo bash $0)"
    exit 1
fi

get_debian_base_codename() {
    # LMDE reports the Mint codename via lsb_release -cs, but Debian source
    # packages need the Debian base codename (for LMDE 7, trixie).
    if [ -r /etc/os-release ]; then
        . /etc/os-release
        if [ -n "${DEBIAN_CODENAME:-}" ]; then
            echo "$DEBIAN_CODENAME"
            return
        fi
        if [ "${ID:-}" = "debian" ] && [ -n "${VERSION_CODENAME:-}" ]; then
            echo "$VERSION_CODENAME"
            return
        fi
    fi

    lsb_release -cs
}

is_linux_mint() {
    if [ -r /etc/linuxmint/info ]; then
        return 0
    fi

    if [ -r /etc/os-release ]; then
        . /etc/os-release
        case "${ID:-} ${NAME:-} ${PRETTY_NAME:-}" in
            *linuxmint*|*Linux\ Mint*) return 0 ;;
        esac
    fi

    if command -v lsb_release >/dev/null 2>&1; then
        case "$(lsb_release -is 2>/dev/null)" in
            LinuxMint|linuxmint) return 0 ;;
        esac
    fi

    return 1
}

prepare_pulseaudio_sources() {
    PULSE_DIR="/root/pulseaudio.src"
    PULSE_SRC_TMP=""
    if [ -d "$PULSE_DIR" ]; then
        echo "  Reusing existing PulseAudio sources: $PULSE_DIR"
        return
    fi

    PA_SRC_PKG=$(dpkg-query -W -f='${source:Package}' pulseaudio 2>/dev/null || true)
    PA_BIN_VER=$(dpkg-query -W -f='${Version}' pulseaudio)
    PA_SRC_VER=$(dpkg-query -W -f='${source:Version}' pulseaudio 2>/dev/null || true)

    [ -n "$PA_SRC_PKG" ] || PA_SRC_PKG="pulseaudio"
    [ -n "$PA_SRC_VER" ] || PA_SRC_VER=$(echo "$PA_BIN_VER" | sed 's/+b[0-9]\+$//')

    echo "  PulseAudio binary version: $PA_BIN_VER"
    echo "  PulseAudio source version: $PA_SRC_VER"

    if ! apt-cache showsrc "$PA_SRC_PKG" 2>/dev/null | grep -qx "Version: $PA_SRC_VER"; then
        BASE_CODENAME=$(get_debian_base_codename)
        PULSE_SRC_LIST="/etc/apt/sources.list.d/debian-${BASE_CODENAME}-source.list"
        echo "  Adding Debian $BASE_CODENAME source repo for PulseAudio source package"
        printf "deb-src http://deb.debian.org/debian %s main\n" "$BASE_CODENAME" > "$PULSE_SRC_LIST"
        apt-get update -qq
    else
        PULSE_SRC_LIST=""
    fi

    apt-get build-dep -y "$PA_SRC_PKG=$PA_SRC_VER"
    apt-get install -y doxygen

    PULSE_SRC_TMP=$(mktemp -d /tmp/pulseaudio-src.XXXXXX)
    cd "$PULSE_SRC_TMP"
    apt-get source "$PA_SRC_PKG=$PA_SRC_VER"
    PA_BUILD_DIR=$(find . -maxdepth 1 -type d -name "${PA_SRC_PKG}-[0-9]*" | sort -V | tail -1)
    if [ -z "$PA_BUILD_DIR" ]; then
        echo "Error: cannot find extracted PulseAudio source directory"
        exit 1
    fi

    cd "$PA_BUILD_DIR"
    if [ -x ./configure ]; then
        ./configure
    elif [ -f ./meson.build ]; then
        rm -rf build
        meson setup build
    else
        echo "Error: cannot configure PulseAudio source in $(pwd)"
        exit 1
    fi

    echo "  Trimming PulseAudio source tree to module headers"
    find . -type f ! -name '*.h' -delete
    find . -mindepth 1 -maxdepth 1 \
        -name src -o -name build -o -name config.h \
        -o -exec rm -rf {} +
    cd ..
    mv "$PA_BUILD_DIR" "$PULSE_DIR"
    rm -rf "$PULSE_SRC_TMP"

    if [ -n "$PULSE_SRC_LIST" ]; then
        rm -f "$PULSE_SRC_LIST"
        apt-get update -qq
    fi
}

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
    if is_linux_mint; then
        echo "  mint:      detected"
    else
        echo "  mint:      not detected"
    fi
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

    echo "── Audio sink inputs (this user) ──"
    pactl list sink-inputs short 2>/dev/null | sed 's/^/  /' || echo "  pactl not reachable"
    echo ""

    echo "── xrdp audio sockets ──"
    find /run/xrdp/sockdir /tmp/.xrdp -type s -name '*audio*' 2>/dev/null | sort | sed 's/^/  /' || echo "  none found"
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
and audio redirection on Debian 13 (trixie) or LMDE 7.

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
       (and switch PipeWire-pulse to real PulseAudio)

  Phase 2 (temporary sid):
    4. Add Debian sid repo with pinning
    5. Install xorgxrdp from sid
    6. Rebuild xrdp from sid source with --enable-x264
       (and remove sid repo)

  Phase 3 (configure):
    7. Set Xorg backend, Xwrapper, startwm.sh
    8. Create gfx.toml (H.264 + x264 encoder)
    9. Fix TLS key permissions (ensure xrdp is in ssl-cert group)
   10. Restart xrdp

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
echo "  xrdp GFX + H.264 Setup for Debian 13 / LMDE 7"
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

# Install common desktop applications
if [ "$DESKTOP" != "none" ]; then
    apt-get install -y firefox-esr chromium
fi
echo ""

echo "=== Step 2: Installing build tools ==="
apt-get install -y build-essential devscripts libx264-dev libpulse-dev \
    git autoconf libtool m4 dpkg-dev pulseaudio pulseaudio-utils pavucontrol alsa-utils
if [ "$DESKTOP" = "mate" ]; then
    apt-get install -y mate-media
fi
echo ""

echo "=== Step 3: Building PulseAudio xrdp audio module ==="
AUDIO_BUILD_DIR=$(mktemp -d /tmp/xrdp-audio-build.XXXXXX)
cd "$AUDIO_BUILD_DIR"
git clone --depth 1 https://github.com/neutrinolabs/pulseaudio-module-xrdp.git
cd pulseaudio-module-xrdp
(prepare_pulseaudio_sources)
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
XRDP_AUDIO_LOADER="/usr/local/bin/load-pulseaudio-xrdp"
cat > "$XRDP_AUDIO_LOADER" << 'LAEOF'
#!/bin/sh
# Load xrdp PulseAudio modules inside an xrdp desktop session.
LOG_DIR="${HOME:-/tmp}/.cache"
LOG_FILE="$LOG_DIR/xrdp-pulseaudio.log"
mkdir -p "$LOG_DIR" 2>/dev/null || true
exec >> "$LOG_FILE" 2>&1

echo "[$(date)] load-pulseaudio-xrdp starting"

if [ "${XRDP_SESSION:-}" != "1" ]; then
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        pgrep -u "$(id -u)" -x xrdp-chansrv >/dev/null 2>&1 && break
        sleep 0.25
    done
fi

if [ "${XRDP_SESSION:-}" != "1" ] && ! pgrep -u "$(id -u)" -x xrdp-chansrv >/dev/null 2>&1; then
    echo "No xrdp session marker or xrdp-chansrv process found; exiting"
    exit 0
fi

USER_RUNTIME_DIR="/run/user/$(id -u)"
if [ -d "$USER_RUNTIME_DIR" ]; then
    if [ -z "${XDG_RUNTIME_DIR:-}" ] || [ "$XDG_RUNTIME_DIR" != "$USER_RUNTIME_DIR" ] || \
        [ "$(stat -c %u "$XDG_RUNTIME_DIR" 2>/dev/null || echo -1)" != "$(id -u)" ]; then
        export XDG_RUNTIME_DIR="$USER_RUNTIME_DIR"
        echo "Set XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR"
    fi
fi
if [ -n "${XDG_RUNTIME_DIR:-}" ]; then
    PULSE_NATIVE="unix:$XDG_RUNTIME_DIR/pulse/native"
else
    PULSE_NATIVE=""
fi

DISPLAY_NUM=$(printf "%s" "${DISPLAY:-}" | sed 's/^.*:\([0-9][0-9]*\).*$/\1/')
if [ -z "$DISPLAY_NUM" ] || [ "$DISPLAY_NUM" = "${DISPLAY:-}" ]; then
    DISPLAY_NUM=$(ps -u "$(id -u -n)" -o args= 2>/dev/null | sed -n 's/.*Xorg :\([0-9][0-9]*\).*/\1/p' | head -1)
fi

XRDP_SOCKET_PATH="${XRDP_SOCKET_PATH:-}"
if [ -z "$XRDP_SOCKET_PATH" ]; then
    if [ -d /run/xrdp/sockdir ]; then
        XRDP_SOCKET_PATH=/run/xrdp/sockdir
    else
        XRDP_SOCKET_PATH=/tmp/.xrdp
    fi
fi

XRDP_PULSE_SINK_SOCKET="${XRDP_PULSE_SINK_SOCKET:-xrdp_chansrv_audio_out_socket_${DISPLAY_NUM}}"
XRDP_PULSE_SOURCE_SOCKET="${XRDP_PULSE_SOURCE_SOCKET:-xrdp_chansrv_audio_in_socket_${DISPLAY_NUM}}"

FOUND_SINK_SOCKET=""
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if [ -n "$DISPLAY_NUM" ]; then
        FOUND_SINK_SOCKET=$(find /run/xrdp/sockdir /tmp/.xrdp "$XRDP_SOCKET_PATH" \
            -type s -name "xrdp_chansrv_audio_out_socket_${DISPLAY_NUM}" 2>/dev/null | head -1)
    fi
    if [ -z "$FOUND_SINK_SOCKET" ]; then
        FOUND_SINK_SOCKET=$(find /run/xrdp/sockdir /tmp/.xrdp "$XRDP_SOCKET_PATH" \
            -type s -name 'xrdp_chansrv_audio_out_socket_*' 2>/dev/null | head -1)
    fi
    [ -n "$FOUND_SINK_SOCKET" ] && break
    sleep 0.25
done

if [ -n "$FOUND_SINK_SOCKET" ]; then
    XRDP_SOCKET_PATH=$(dirname "$FOUND_SINK_SOCKET")
    XRDP_PULSE_SINK_SOCKET=$(basename "$FOUND_SINK_SOCKET")
    XRDP_PULSE_SOURCE_SOCKET=$(printf "%s" "$XRDP_PULSE_SINK_SOCKET" | sed 's/audio_out/audio_in/')
fi

echo "DISPLAY=${DISPLAY:-unset} display_num=${DISPLAY_NUM:-unknown}"
echo "socket_path=$XRDP_SOCKET_PATH"
echo "sink_socket=$XRDP_PULSE_SINK_SOCKET"
echo "source_socket=$XRDP_PULSE_SOURCE_SOCKET"

if [ ! -S "$XRDP_SOCKET_PATH/$XRDP_PULSE_SINK_SOCKET" ]; then
    echo "xrdp audio socket missing: $XRDP_SOCKET_PATH/$XRDP_PULSE_SINK_SOCKET"
    echo "This usually means the RDP client did not request audio redirection, or xrdp-chansrv is not running for this display."
    echo "Available xrdp sockets:"
    find /run/xrdp/sockdir /tmp/.xrdp "$XRDP_SOCKET_PATH" -type s 2>/dev/null | sort -u || true
fi

if pactl info 2>/dev/null | grep -q '^Server Name:.*PipeWire' || pgrep -u "$(id -u)" -x pipewire-pulse >/dev/null 2>&1; then
    echo "Stopping pipewire-pulse for this xrdp session"
    systemctl --user disable --now pipewire-pulse.socket pipewire-pulse.service >/dev/null 2>&1 || true
    systemctl --user mask pipewire-pulse.socket pipewire-pulse.service >/dev/null 2>&1 || true
    pkill -u "$(id -u)" -x pipewire-pulse >/dev/null 2>&1 || true
    sleep 0.5
fi

if [ -n "${XDG_RUNTIME_DIR:-}" ]; then
    mkdir -p "$XDG_RUNTIME_DIR/pulse" 2>/dev/null || true
    if ! env -u PULSE_SERVER pactl info >/dev/null 2>&1 && ! pgrep -u "$(id -u)" -x pulseaudio >/dev/null 2>&1 && [ -S "$XDG_RUNTIME_DIR/pulse/native" ]; then
        echo "Removing stale PulseAudio socket: $XDG_RUNTIME_DIR/pulse/native"
        rm -f "$XDG_RUNTIME_DIR/pulse/native"
    fi
fi

if ! env -u PULSE_SERVER pulseaudio --check >/dev/null 2>&1; then
    echo "Starting real PulseAudio"
    env -u PULSE_SERVER pulseaudio --start || true
fi

if [ -n "$PULSE_NATIVE" ]; then
    export PULSE_SERVER="$PULSE_NATIVE"
    echo "Set PULSE_SERVER=$PULSE_SERVER"
fi

for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    pactl info >/dev/null 2>&1 && break
    sleep 0.2
done

pactl info >/dev/null 2>&1 || {
    echo "pactl cannot connect to PulseAudio"
    env -u PULSE_SERVER pulseaudio --start --log-target=stderr || true
    exit 0
}

pactl info | grep -E '^Server Name:|^Default Sink:' || true

echo "Reloading xrdp PulseAudio modules for current xrdp socket"
pactl list short modules 2>/dev/null | awk '$2 == "module-xrdp-sink" || $2 == "module-xrdp-source" {print $1}' |
    while read -r MODULE_ID; do
        [ -n "$MODULE_ID" ] && pactl unload-module "$MODULE_ID" || true
    done

pactl load-module module-xrdp-sink \
    "xrdp_socket_path=$XRDP_SOCKET_PATH" \
    "xrdp_pulse_sink_socket=$XRDP_PULSE_SINK_SOCKET" || true

pactl load-module module-xrdp-source \
    "xrdp_socket_path=$XRDP_SOCKET_PATH" \
    "xrdp_pulse_source_socket=$XRDP_PULSE_SOURCE_SOCKET" || true

if pactl list short sinks 2>/dev/null | grep -q 'xrdp-sink'; then
    pactl set-default-sink xrdp-sink || true
    echo "xrdp-sink is present and set as default"
else
    echo "xrdp-sink is missing"
fi
LAEOF
chmod 755 "$XRDP_AUDIO_LOADER"
echo "  Installed audio loader: $XRDP_AUDIO_LOADER"

PA_MOD_DIR=$(pkg-config --variable=modlibexecdir libpulse 2>/dev/null || true)
if [ -n "$PA_MOD_DIR" ]; then
    mkdir -p "$PA_MOD_DIR"
    for MODULE in module-xrdp-sink.so module-xrdp-source.so; do
        if [ ! -f "$PA_MOD_DIR/$MODULE" ]; then
            FOUND_MODULE=$(find /usr /usr/local -name "$MODULE" 2>/dev/null | head -1)
            if [ -n "$FOUND_MODULE" ]; then
                cp "$FOUND_MODULE" "$PA_MOD_DIR/$MODULE"
                echo "  Copied $MODULE into PulseAudio module dir: $PA_MOD_DIR"
            fi
        fi
    done
fi

mkdir -p /etc/xdg/autostart
cat > "$AUTOSTART" << ASEOF
[Desktop Entry]
Type=Application
Name=PulseAudio xrdp modules
Exec=$XRDP_AUDIO_LOADER
NoDisplay=true
ASEOF
echo "  Autostart: $AUTOSTART"
rm -rf "$AUDIO_BUILD_DIR"

# Debian 13 defaults to PipeWire-pulse, but xrdp audio modules require
# real PulseAudio. Disable PipeWire-pulse and enable PulseAudio globally.
echo "  Switching from PipeWire-pulse to PulseAudio (required for xrdp audio)"
systemctl --global disable pipewire-pulse.socket pipewire-pulse.service 2>/dev/null || true
systemctl --global mask pipewire-pulse.socket pipewire-pulse.service 2>/dev/null || true
systemctl --global enable pulseaudio.service pulseaudio.socket 2>/dev/null || true
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

if grep -q '^\[Channels\]' "$XRDP_INI"; then
    if sed -n '/^\[Channels\]/,/^\[/p' "$XRDP_INI" | grep -q '^rdpsnd='; then
        sed -i '/^\[Channels\]/,/^\[/ s/^rdpsnd=.*/rdpsnd=true/' "$XRDP_INI"
    else
        sed -i '/^\[Channels\]/a rdpsnd=true' "$XRDP_INI"
    fi

    if sed -n '/^\[Channels\]/,/^\[/p' "$XRDP_INI" | grep -q '^drdynvc='; then
        sed -i '/^\[Channels\]/,/^\[/ s/^drdynvc=.*/drdynvc=true/' "$XRDP_INI"
    else
        sed -i '/^\[Channels\]/a drdynvc=true' "$XRDP_INI"
    fi
    echo "  Enabled xrdp audio channels (rdpsnd, drdynvc)"
else
    cat >> "$XRDP_INI" << 'CHANEOF'

[Channels]
rdpsnd=true
drdynvc=true
CHANEOF
    echo "  Added xrdp audio channels (rdpsnd, drdynvc)"
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
if is_linux_mint; then
    echo "  Detected Linux Mint/LMDE; installing Mint-safe startwm.sh"
    cat > /etc/xrdp/startwm.sh << 'WMEOF'
#!/bin/sh
# xrdp X session start script (c) 2015, 2017, 2021 mirabilos
# published under The MirOS Licence

# Rely on /etc/pam.d/xrdp-sesman using pam_env to load both
# /etc/environment and /etc/default/locale to initialise the
# locale and the user environment properly.

# xrdp X session start script

unset DBUS_SESSION_BUS_ADDRESS
unset XDG_RUNTIME_DIR

if [ -r /etc/profile ]; then
    . /etc/profile
fi

if [ -r "$HOME/.profile" ]; then
    . "$HOME/.profile"
fi

# Use user's ~/.xsession if present
if [ -r "$HOME/.xsession" ]; then
    exec /bin/sh "$HOME/.xsession"
fi

# Fallback to system Xsession
exec /etc/X11/Xsession
WMEOF
    chmod 755 /etc/xrdp/startwm.sh
    echo "  Set startwm.sh to Linux Mint Xsession launcher"
elif [ -n "$STARTWM_CMD" ]; then
    cat > /etc/xrdp/startwm.sh << 'WMEOF'
#!/bin/sh
export XRDP_SESSION=1
if [ -d "/run/user/$(id -u)" ]; then
    export XDG_RUNTIME_DIR="/run/user/$(id -u)"
fi
/usr/local/bin/load-pulseaudio-xrdp
if [ -n "${XDG_RUNTIME_DIR:-}" ]; then
    export PULSE_SERVER="unix:$XDG_RUNTIME_DIR/pulse/native"
fi
if test -r /etc/profile; then
    . /etc/profile
fi
if test -r ~/.profile; then
    . ~/.profile
fi
WMEOF
    printf '%s\n' "$STARTWM_CMD" >> /etc/xrdp/startwm.sh
    chmod 755 /etc/xrdp/startwm.sh
    echo "  Set startwm.sh to: $STARTWM_CMD"
fi
cat > /etc/X11/Xsession.d/95xrdp-pulseaudio-env << 'XSEOF'
# Ensure xrdp desktop applications inherit the PulseAudio runtime path.
DISPLAY_NUM=$(printf "%s" "${DISPLAY:-}" | sed 's/^.*:\([0-9][0-9]*\).*$/\1/')
if [ -n "$DISPLAY_NUM" ] && [ "$DISPLAY_NUM" -ge 10 ] 2>/dev/null; then
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        pgrep -u "$(id -u)" -x xrdp-chansrv >/dev/null 2>&1 && break
        sleep 0.25
    done
fi

if pgrep -u "$(id -u)" -x xrdp-chansrv >/dev/null 2>&1; then
    export XRDP_SESSION=1
    if [ -d "/run/user/$(id -u)" ]; then
        export XDG_RUNTIME_DIR="/run/user/$(id -u)"
    fi
    /usr/local/bin/load-pulseaudio-xrdp
    if [ -n "${XDG_RUNTIME_DIR:-}" ]; then
        export PULSE_SERVER="unix:$XDG_RUNTIME_DIR/pulse/native"
    fi
fi
XSEOF
chmod 644 /etc/X11/Xsession.d/95xrdp-pulseaudio-env
echo "  Installed Xsession PulseAudio environment hook"
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

echo "=== Step 9: Fix TLS key permissions ==="
# Debian's stock xrdp postinst runs `adduser xrdp ssl-cert` and sets the
# snakeoil private key readable by the ssl-cert group. The sid rebuild
# we install earlier doesn't always re-apply this cleanly, so xrdp ends
# up unable to read /etc/xrdp/key.pem, falls back to "classic RDP
# security", and FreeRDP clients die with a MAC checksum error during
# the pre-TLS handshake. Fix it explicitly here.
#
# Idempotent: if ssl-cert group doesn't exist (non-Debian?), skip.
if getent group ssl-cert > /dev/null 2>&1; then
    if id xrdp >/dev/null 2>&1; then
        if ! id -nG xrdp | tr ' ' '\n' | grep -qx ssl-cert; then
            usermod -aG ssl-cert xrdp
            echo "  Added xrdp user to ssl-cert group"
        else
            echo "  xrdp user already in ssl-cert group"
        fi
    fi
    if [ -f /etc/xrdp/key.pem ]; then
        chgrp ssl-cert /etc/xrdp/key.pem
        chmod 640 /etc/xrdp/key.pem
        echo "  Fixed /etc/xrdp/key.pem ownership/mode"
    fi
else
    echo "  ssl-cert group not present; skipping TLS perm fix"
fi
echo ""

echo "=== Step 10: Restarting xrdp ==="
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
