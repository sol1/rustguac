#!/bin/bash
set -e

USERNAME="${VDI_USERNAME:-user}"
PASSWORD="${VDI_PASSWORD:-password}"

# Create user if it doesn't already exist (container reuse)
if ! id "$USERNAME" &>/dev/null; then
    useradd -m -s /bin/bash "$USERNAME"
fi

# Always update password (may be regenerated on reconnect)
echo "$USERNAME:$PASSWORD" | chpasswd

# Set default session to xfce4
echo "xfce4-session" > /home/"$USERNAME"/.xsession
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
