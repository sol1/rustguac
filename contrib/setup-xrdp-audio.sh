#!/bin/bash
# Setup audio redirection for xrdp on Debian 13 (trixie).
#
# Builds and installs the PulseAudio module-xrdp, which creates a virtual
# audio sink that redirects sound through the RDP channel.
#
# Run as root on the xrdp target machine (not the rustguac server).
# Requires: xrdp, pulseaudio, build tools.
#
# After install, new RDP sessions will automatically load the audio module
# via XDG autostart. Existing sessions need to be disconnected and reconnected.
#
# Usage: sudo bash setup-xrdp-audio.sh
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo bash $0)"
    exit 1
fi

echo "=== Checking prerequisites ==="
if ! dpkg -l xrdp >/dev/null 2>&1; then
    echo "Error: xrdp is not installed"
    exit 1
fi

if ! dpkg -l pulseaudio >/dev/null 2>&1; then
    echo "Error: pulseaudio is not installed. Install with: apt install pulseaudio"
    exit 1
fi

XRDP_VERSION=$(dpkg -l xrdp | awk '/^ii/{print $3}')
echo "  xrdp version: $XRDP_VERSION"
echo "  pulseaudio version: $(pulseaudio --version 2>/dev/null || echo unknown)"

echo ""
echo "=== Installing build dependencies ==="
apt-get update -qq
apt-get install -y git build-essential dpkg-dev libpulse-dev autoconf libtool m4

echo ""
echo "=== Fetching PulseAudio source (for module API headers) ==="
BUILDDIR=$(mktemp -d)
cd "$BUILDDIR"
git clone --depth 1 https://github.com/neutrinolabs/pulseaudio-module-xrdp.git
cd pulseaudio-module-xrdp

# The install script fetches and configures pulseaudio sources
echo ""
echo "=== Building PulseAudio sources ==="
scripts/install_pulseaudio_sources_apt.sh

echo ""
echo "=== Configuring module-xrdp ==="
./bootstrap
./configure PULSE_DIR=/root/pulseaudio.src

echo ""
echo "=== Building ==="
make

echo ""
echo "=== Installing ==="
make install

echo ""
echo "=== Verifying installation ==="
SINK_SO=$(find /usr/lib -name "module-xrdp-sink.so" 2>/dev/null | head -1)
if [ -z "$SINK_SO" ]; then
    echo "Error: module-xrdp-sink.so not found after install"
    exit 1
fi
echo "  Installed: $SINK_SO"

SOURCE_SO=$(find /usr/lib -name "module-xrdp-source.so" 2>/dev/null | head -1)
echo "  Installed: $SOURCE_SO"

AUTOSTART="/etc/xdg/autostart/pulseaudio-xrdp.desktop"
if [ -f "$AUTOSTART" ]; then
    echo "  Autostart: $AUTOSTART"
else
    echo "  Warning: autostart desktop file not found"
fi

echo ""
echo "=== Cleaning up build directory ==="
rm -rf "$BUILDDIR"

echo ""
echo "=== Done ==="
echo ""
echo "Audio redirection is now installed. New RDP sessions will"
echo "automatically load the PulseAudio xrdp modules."
echo ""
echo "For existing sessions, disconnect and reconnect to pick up audio."
echo ""
echo "To verify audio is working in a session, run:"
echo "  pactl list sinks short"
echo "You should see 'xrdp-sink' in the output."
