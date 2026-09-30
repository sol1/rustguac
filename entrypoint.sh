#!/bin/sh
# Entrypoint script: starts guacd in background, then rustguac in background, waiting on both to exit
set -e

# Copy default config on first run (if no config file is mounted/present)
CONFIG_PATH="/opt/rustguac/config.toml"
if [ ! -f "$CONFIG_PATH" ]; then
    echo "No config.toml found — copying default configuration."
    cp /opt/rustguac/config.toml.default "$CONFIG_PATH"
fi

# Create admin API key on first run (if no DB exists yet)
DB_PATH="/opt/rustguac/data/rustguac.db"
if [ ! -f "$DB_PATH" ]; then
    echo "First run detected — creating admin API key..."
    /opt/rustguac/bin/rustguac --config "$CONFIG_PATH" add-admin --name docker-admin
    echo ""
    echo "==> SAVE THE API KEY ABOVE — it is only shown once! <=="
    echo ""
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


# Run rustguac in foreground
echo "Starting rustguac..."
/opt/rustguac/bin/rustguac --config "$CONFIG_PATH" serve &
RUSTGUAC_PID=$!

wait $GUACD_PID $RUSTGUAC_PID
