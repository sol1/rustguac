#!/bin/bash
set -e

USERNAME="${VDI_USERNAME:-user}"
PASSWORD="${VDI_PASSWORD:-password}"
SUDO_ENABLED="${VDI_SUDO:-false}"

# Create user if it doesn't already exist (container reuse)
if ! id "$USERNAME" &>/dev/null; then
    useradd -m -s /bin/bash "$USERNAME"
fi
if [ "$SUDO_ENABLED" = "true" ]; then
    usermod -aG sudo "$USERNAME"
else
    deluser "$USERNAME" sudo >/dev/null 2>&1 || true
fi

USER_ID="$(id -u "$USERNAME")"
USER_GROUP="$(id -gn "$USERNAME")"
install -d -m 700 -o "$USERNAME" -g "$USER_GROUP" /run/user/"$USER_ID"

dbus-uuidgen --ensure=/etc/machine-id

# Always update password (may be regenerated on reconnect)
echo "$USERNAME:$PASSWORD" | chpasswd

# Set default session to MATE and preload the xrdp PulseAudio modules.
cat > /home/"$USERNAME"/.xsession <<'EOF'
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
export XDG_CURRENT_DESKTOP=MATE
export XDG_SESSION_DESKTOP=mate
export DESKTOP_SESSION=mate
export XDG_SESSION_TYPE=x11
export GDK_BACKEND=x11
/usr/local/bin/load-pulseaudio-xrdp &
exec dbus-run-session -- mate-session
EOF
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.xsession

# Ensure xrdp TLS certs are configured
sed -i \
    -e 's|^certificate=.*|certificate=/etc/ssl/certs/ssl-cert-snakeoil.pem|' \
    -e 's|^key_file=.*|key_file=/etc/ssl/private/ssl-cert-snakeoil.key|' \
    /etc/xrdp/xrdp.ini
chmod 644 /etc/ssl/private/ssl-cert-snakeoil.key 2>/dev/null || true

# Start dbus
mkdir -p /run/dbus
dbus-daemon --system --fork 2>/dev/null || true

# Start xrdp-sesman and xrdp
xrdp-sesman --nodaemon &
exec xrdp --nodaemon
