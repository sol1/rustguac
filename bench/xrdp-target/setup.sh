#!/bin/bash
# Setup xrdp on a Debian 13 VM for benchmarking rustguac.
# Run as root on the target VM.
# Creates 100 bench users (bench01-bench100) with password "bench".
set -e

echo "=== Installing xrdp ==="
apt-get update
apt-get install -y xrdp xfce4 xfce4-terminal dbus-x11

echo "=== Configuring xrdp ==="
# Use Xvnc backend (lighter than Xorg)
sed -i 's/^port=3389/port=3389/' /etc/xrdp/xrdp.ini

# Allow multiple sessions per user
sed -i 's/^Policy=Default/Policy=Default/' /etc/xrdp/sesman.ini

# Set session defaults to Xfce (lightweight)
cat > /etc/xrdp/startwm.sh << 'STARTWM'
#!/bin/sh
if [ -r /etc/default/locale ]; then
  . /etc/default/locale
  export LANG LANGUAGE
fi
exec startxfce4
STARTWM
chmod +x /etc/xrdp/startwm.sh

echo "=== Creating bench users ==="
for i in $(seq -w 1 100); do
    USER="bench${i}"
    if ! id "$USER" &>/dev/null; then
        useradd -m -s /bin/bash "$USER"
        echo "${USER}:bench" | chpasswd
    fi
done

echo "=== Starting xrdp ==="
systemctl enable xrdp
systemctl restart xrdp

echo "=== Done ==="
echo "xrdp listening on port 3389"
echo "Users: bench01-bench100, password: bench"
echo "Test with: xfreerdp /v:$(hostname -I | awk '{print $1}'):3389 /u:bench01 /p:bench"
