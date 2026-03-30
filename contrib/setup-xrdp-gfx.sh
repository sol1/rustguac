#!/bin/bash
# Setup GFX pipeline with H.264 encoding for xrdp on Debian 13 (trixie).
#
# This script rebuilds xrdp from the Debian sid source package with x264
# support enabled, installs matching xorgxrdp, configures the Xorg backend
# and GFX pipeline with H.264 encoding.
#
# The stock Debian 13 xrdp package does NOT include x264 support.
# This script adds the Debian sid (unstable) repo, rebuilds xrdp with
# --enable-x264, and pins trixie as the default to prevent accidental
# upgrades from sid.
#
# Run as root on the xrdp target machine (not the rustguac server).
# Requires: Debian 13 (trixie), ~10 minutes for the rebuild.
#
# Usage: sudo bash setup-xrdp-gfx.sh [--desktop xfce|kde|gnome|mate|none]
#
# After running, also run setup-xrdp-audio.sh for audio redirection.

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo bash $0)"
    exit 1
fi

# Parse --desktop flag (default: xfce)
DESKTOP="mate"
while [ $# -gt 0 ]; do
    case "$1" in
        --desktop) DESKTOP="$2"; shift 2 ;;
        --desktop=*) DESKTOP="${1#*=}"; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

case "$DESKTOP" in
    xfce|kde|gnome|mate|none) ;;
    *) echo "Error: --desktop must be xfce, kde, gnome, mate, or none"; exit 1 ;;
esac

echo "============================================"
echo "  xrdp GFX + H.264 Setup for Debian 13"
echo "  Desktop: $DESKTOP"
echo "============================================"
echo ""

# ---------- Step 1: Install build tools from trixie (before sid) ----------

echo "=== Step 1: Installing build tools ==="
apt-get update -qq
apt-get install -y build-essential devscripts libx264-dev
echo ""

# ---------- Step 2: Add sid repo with pinning ----------

echo "=== Step 2: Configuring apt repos ==="
SID_LIST="/etc/apt/sources.list.d/sid.list"
PIN_FILE="/etc/apt/preferences.d/pin-trixie"

if [ ! -f "$SID_LIST" ]; then
    printf "deb http://deb.debian.org/debian sid main\ndeb-src http://deb.debian.org/debian sid main\n" > "$SID_LIST"
    echo "  Added sid repo (deb + deb-src) to $SID_LIST"
else
    # Ensure deb-src line exists (needed for apt-get source)
    if ! grep -q "^deb-src.*sid" "$SID_LIST"; then
        echo "deb-src http://deb.debian.org/debian sid main" >> "$SID_LIST"
        echo "  Added deb-src line to $SID_LIST"
    fi
    echo "  Sid repo configured"
fi

if [ ! -f "$PIN_FILE" ]; then
    cat > "$PIN_FILE" << 'PINEOF'
Package: *
Pin: release a=trixie
Pin-Priority: 900

Package: *
Pin: release a=unstable
Pin-Priority: 100
PINEOF
    echo "  Created apt pinning (trixie=900, sid=100)"
else
    echo "  Apt pinning already configured"
fi

apt-get update -qq
echo ""

# ---------- Step 3: Install xorgxrdp from sid ----------

echo "=== Step 3: Installing xorgxrdp from sid ==="
apt-get install -y -t unstable xorgxrdp
XORGXRDP_VER=$(dpkg -l xorgxrdp | awk '/^ii/{print $3}')
echo "  xorgxrdp version: $XORGXRDP_VER"
echo ""

# ---------- Step 4: Rebuild xrdp with x264 ----------

echo "=== Step 4: Rebuilding xrdp with x264 support ==="

# Install xrdp build dependencies
apt-get build-dep -y xrdp 2>/dev/null || apt-get build-dep -y -t unstable xrdp

# Get xrdp source from sid
BUILD_DIR=$(mktemp -d /tmp/xrdp-build.XXXXXX)
echo "  Build directory: $BUILD_DIR"
cd "$BUILD_DIR"

# Find the latest version in sid (sort -V to get highest version)
XRDP_SID_VER=$(apt-cache showsrc -t unstable xrdp 2>/dev/null | grep "^Version:" | awk '{print $2}' | sort -V | tail -1)
if [ -z "$XRDP_SID_VER" ]; then
    echo "Error: cannot find xrdp source in sid"
    exit 1
fi
echo "  Building xrdp $XRDP_SID_VER from sid source"

# Explicitly use -t unstable to ensure we get the sid source
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
    # Fallback: append to the first configure line that has --with or --enable
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

# Cleanup
rm -rf "$BUILD_DIR"
echo ""

# ---------- Step 5: Install desktop environment ----------

echo "=== Step 5: Installing desktop environment ($DESKTOP) ==="
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

# ---------- Step 6: Configure Xorg backend ----------

echo "=== Step 6: Configuring Xorg backend ==="
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
echo ""

# ---------- Step 7: Configure GFX pipeline ----------

echo "=== Step 7: Creating GFX configuration ==="
GFX_CONF="/etc/xrdp/gfx.toml"
if [ -f "$GFX_CONF" ]; then
    cp "$GFX_CONF" "${GFX_CONF}.bak"
    echo "  Backed up existing $GFX_CONF"
fi

cat > "$GFX_CONF" << 'EOF'
# GFX Pipeline Configuration for xrdp
# Generated by rustguac contrib/setup-xrdp-gfx.sh
#
# H.264 encoding with x264 for best video performance.
# See: man 5 gfx.toml

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

# ---------- Step 8: Restart ----------

echo "=== Step 8: Restarting xrdp ==="
systemctl restart xrdp
echo "  xrdp restarted"

echo ""
echo "============================================"
echo "  Setup complete!"
echo "============================================"
echo ""
echo "xrdp is now configured with:"
echo "  - xrdp $(dpkg -l xrdp | awk '/^ii/{print $3}') rebuilt with x264 support"
echo "  - xorgxrdp $XORGXRDP_VER (from sid)"
echo "  - Xorg backend (required for GFX pipeline)"
echo "  - H.264 encoding via x264 (60fps LAN)"
echo "  - RemoteFX as fallback codec"
echo "  - Xwrapper allows non-root Xorg"
echo ""
echo "Next steps:"
echo "  1. Run contrib/setup-xrdp-audio.sh for audio support"
echo "  2. In rustguac, enable 'Graphics Pipeline (GFX)' on RDP entries"
echo ""
echo "When connecting from rustguac with H.264 passthrough enabled,"
echo "the browser's WebCodecs VideoDecoder will decode H.264 directly"
echo "for low-latency, high-quality video."
