#!/bin/bash
# Entrypoint script: starts guacd and rustguac in the background. tini (PID 1)
# passes stop signals to both. If either one exits, the other is stopped and
# the container exits with that status, so a restart policy can bring it back
# rather than leaving rustguac running without guacd.
set -e

# Copy default config on first run (if no config file is mounted/present)
CONFIG_PATH="/opt/rustguac/config.toml"
if [ ! -f "$CONFIG_PATH" ]; then
    echo "No config.toml found — copying default configuration."
    cp /opt/rustguac/config.toml.default "$CONFIG_PATH"
fi

# Create an admin API key on first run. rustguac decides what "first run"
# means: it opens the database named by db_path in the config and creates
# the admin only if there is none yet. Checking for a database file at a fixed
# path here broke any config that moved db_path: every restart then tried to
# create the admin again and failed on the existing one (#240).
ADMIN_OUT=$(/opt/rustguac/bin/rustguac --config "$CONFIG_PATH" add-admin --name docker-admin --if-none)
echo "$ADMIN_OUT"
case "$ADMIN_OUT" in
    *"API Key:"*)
        echo ""
        echo "==> SAVE THE API KEY ABOVE — it is only shown once! <=="
        echo ""
        ;;
esac

# TLS pair for the web UI and guacd: the one mounted at /opt/rustguac/tls or
# made on an earlier start, otherwise this container's own. Never one baked
# into the image (GHSA-j4r4-h9h8-fj4v).
TLS_DIR=/opt/rustguac/tls
if [ ! -s "$TLS_DIR/cert.pem" ] || [ ! -s "$TLS_DIR/key.pem" ]; then
    if [ -w "$TLS_DIR" ]; then
        echo "No TLS pair in $TLS_DIR: generating one for this container."
        /opt/rustguac/bin/rustguac --config "$CONFIG_PATH" generate-cert --hostname localhost --out-dir "$TLS_DIR" >/dev/null
        chmod 600 "$TLS_DIR/key.pem"
    else
        echo "ERROR: no TLS pair in $TLS_DIR (cert.pem, key.pem) and it is not writable."
        echo "Mount a pair there (e.g. -v ./tls:$TLS_DIR:ro) or make it writable."
        exit 1
    fi
elif [ -n "$(find "$TLS_DIR/key.pem" -perm /044 2>/dev/null)" ] \
    && openssl x509 -in "$TLS_DIR/cert.pem" -noout -subject 2>/dev/null | grep -q "rcgen self signed cert"; then
    # Images before 1.14.4 shipped a world-readable key, the same in every
    # container. A named volume on $TLS_DIR keeps that key across upgrades.
    # Only a pair rustguac generated is checked: a mounted certificate of
    # your own may well need a key others can read.
    echo "WARNING: $TLS_DIR/key.pem is readable by other users."
    echo "  If it came with a rustguac image before 1.14.4 (for example kept in a"
    echo "  volume on $TLS_DIR), it is public: delete cert.pem and key.pem there and"
    echo "  restart to get a new pair, or mount your own. See GHSA-j4r4-h9h8-fj4v."
fi

# Start guacd in background
echo "Starting guacd..."
LD_LIBRARY_PATH=/opt/rustguac/lib FREERDP_ADDIN_PATH=/opt/rustguac/lib/freerdp3 \
    /opt/rustguac/sbin/guacd \
    -b 127.0.0.1 -l 4822 -L "${GUACD_LOG_LEVEL:-info}" -f \
    -C /opt/rustguac/tls/cert.pem -K /opt/rustguac/tls/key.pem &
GUACD_PID=$!

# Wait briefly to confirm guacd started
sleep 0.5
if ! kill -0 "$GUACD_PID" 2>/dev/null; then
    echo "ERROR: guacd failed to start"
    exit 1
fi
echo "guacd started (pid=$GUACD_PID)"


echo "Starting rustguac..."
/opt/rustguac/bin/rustguac --config "$CONFIG_PATH" serve &
RUSTGUAC_PID=$!

# Wait for whichever exits first, then stop the other.
set +e
wait -n "$GUACD_PID" "$RUSTGUAC_PID"
STATUS=$?
if ! kill -0 "$GUACD_PID" 2>/dev/null; then
    echo "guacd exited (status $STATUS), stopping rustguac"
else
    echo "rustguac exited (status $STATUS), stopping guacd"
fi
kill "$GUACD_PID" "$RUSTGUAC_PID" 2>/dev/null
wait
exit "$STATUS"
