# =============================================================================
# Multi-stage Dockerfile for rustguac
#
# Stages:
#   1. guacd-builder  — compile guacd from guacamole-server source
#   2. rust-builder   — compile rustguac binary
#   3. runtime        — minimal image with both binaries + runtime deps
#
# Build:
#   docker build -t rustguac .
#
# Run:
#   docker run -d -p 8089:8089 rustguac
#
# The image runs both guacd and rustguac under a simple entrypoint script.
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build guacd from source
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS guacd-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf automake libtool pkg-config make gcc g++ git ca-certificates \
    libcairo2-dev libjpeg-dev libpng-dev libwebp-dev \
    libssh2-1-dev libssl-dev libvncserver-dev \
    libpango1.0-dev libpulse-dev \
    libavcodec-dev libavformat-dev libavutil-dev libswscale-dev \
    libcunit1-dev libtelnet-dev libwebsockets-dev \
    uuid-dev freerdp3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --depth 1 https://github.com/apache/guacamole-server.git

# Apply patches for FreeRDP 3.x / Debian 13 compatibility
COPY patches/ /build/patches/
WORKDIR /build/guacamole-server
RUN for patch in /build/patches/*.patch; do \
        [ -f "$patch" ] || continue; \
        echo "Applying patch: $(basename "$patch")"; \
        git apply "$patch"; \
    done

RUN autoreconf -fi

WORKDIR /build/guacd-build
RUN /build/guacamole-server/configure \
        --prefix=/opt/rustguac \
        --with-ssh \
        --with-vnc \
        --with-rdp \
        --without-telnet \
        --without-kubernetes \
        --disable-guacenc \
        --disable-guaclog \
        --disable-static \
    && make -j"$(nproc)" \
    && make install

# ---------------------------------------------------------------------------
# Stage 2: Build rustguac
# ---------------------------------------------------------------------------
FROM rust:1-bookworm AS rust-builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY src/ src/
COPY docs/ docs/
COPY static/ static/

RUN cargo build --release

# ---------------------------------------------------------------------------
# Stage 3: Runtime image
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS runtime

# Runtime libraries for guacd
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 libjpeg62-turbo libpng16-16t64 libwebp7 \
    libssh2-1 libssl3t64 libvncclient1 \
    libpango-1.0-0 libpulse0 \
    libavcodec61 libavformat61 libavutil59 libswscale8 \
    libtelnet2 libwebsockets19t64 \
    libfreerdp3-3 libfreerdp-client3-3 libwinpr3-3 \
    # Xvnc + Chromium for web browser sessions
    tigervnc-standalone-server \
    chromium \
    x11-utils \
    # Minimal runtime utilities
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install guacd
COPY --from=guacd-builder /opt/rustguac/sbin/ /opt/rustguac/sbin/
COPY --from=guacd-builder /opt/rustguac/lib/ /opt/rustguac/lib/

# Install rustguac binary
COPY --from=rust-builder /build/target/release/rustguac /opt/rustguac/bin/rustguac

# Install static web assets
COPY static/ /opt/rustguac/static/

# Library path for guacd
RUN echo "/opt/rustguac/lib" > /etc/ld.so.conf.d/rustguac.conf && ldconfig

# Create data directories
RUN mkdir -p /opt/rustguac/data /opt/rustguac/recordings /opt/rustguac/tls

# Generate self-signed cert for guacd TLS (internal loopback encryption)
RUN /opt/rustguac/bin/rustguac generate-cert --hostname localhost --out-dir /opt/rustguac/tls

# Default config (guacd TLS enabled by default)
RUN cat > /opt/rustguac/config.toml <<'EOF'
listen_addr = "0.0.0.0:8089"
guacd_addr = "127.0.0.1:4822"
recording_path = "/opt/rustguac/recordings"
static_path = "/opt/rustguac/static"
db_path = "/opt/rustguac/data/rustguac.db"
session_pending_timeout_secs = 60
xvnc_path = "Xvnc"
chromium_path = "chromium"
display_range_start = 100
display_range_end = 199

[tls]
cert_path = "/opt/rustguac/tls/cert.pem"
key_path = "/opt/rustguac/tls/key.pem"
guacd_cert_path = "/opt/rustguac/tls/cert.pem"
EOF

# Entrypoint script: starts guacd in background, then rustguac in foreground
RUN cat > /opt/rustguac/entrypoint.sh <<'SCRIPT'
#!/bin/sh
set -e

# Create admin API key on first run (if no DB exists yet)
DB_PATH="/opt/rustguac/data/rustguac.db"
if [ ! -f "$DB_PATH" ]; then
    echo "First run detected — creating admin API key..."
    /opt/rustguac/bin/rustguac --config /opt/rustguac/config.toml add-admin --name docker-admin
    echo ""
    echo "==> SAVE THE API KEY ABOVE — it is only shown once! <=="
    echo ""
fi

# Start guacd in background
echo "Starting guacd..."
LD_LIBRARY_PATH=/opt/rustguac/lib /opt/rustguac/sbin/guacd \
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

# Trap signals to shut down both processes
trap 'kill $GUACD_PID 2>/dev/null; wait; exit 0' TERM INT

# Run rustguac in foreground
echo "Starting rustguac..."
exec /opt/rustguac/bin/rustguac --config /opt/rustguac/config.toml serve
SCRIPT
RUN chmod +x /opt/rustguac/entrypoint.sh

WORKDIR /opt/rustguac
EXPOSE 8089
VOLUME ["/opt/rustguac/data", "/opt/rustguac/recordings"]

ENV RUST_LOG=info
ENV GUACD_LOG_LEVEL=info

ENTRYPOINT ["/opt/rustguac/entrypoint.sh"]
