FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# Debian Trixie desktop image example with PulseAudio Support for rustguac VDI
#
# This follows the same broad shape as contrib/setup-xrdp-gfx.sh:
# install a desktop, install real PulseAudio, build the xrdp PulseAudio
# modules from source, and configure xrdp to use the Xorg backend.
RUN apt-get update && apt-get install -y --no-install-recommends \
    apt-utils \
    ca-certificates \
    curl \
    dbus-user-session \
    dbus-x11 \
    gpg \
    sudo \
    xrdp \
    xorgxrdp \
    xserver-xorg \
    xserver-xorg-core \
    x11-xserver-utils \
    mate-desktop-environment \
    mate-terminal \
    mate-media \
    firefox-esr \
    chromium \
    chromium-sandbox \
    libreoffice \
    mousepad \
    vim \
    xarchiver \
    pulseaudio \
    pulseaudio-utils \
    pavucontrol \
    alsa-utils \
    git \
    build-essential \
    dpkg-dev \
    autoconf \
    automake \
    libtool \
    lsb-release \
    m4 \
    pkg-config \
    libpulse-dev \
    meson \
    ninja-build \
    doxygen \
    && if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor --yes -o /usr/share/keyrings/microsoft-edge.gpg; \
        printf '%s\n' \
            'Types: deb' \
            'URIs: https://packages.microsoft.com/repos/edge-stable' \
            'Suites: stable' \
            'Components: main' \
            'Architectures: amd64' \
            'Signed-By: /usr/share/keyrings/microsoft-edge.gpg' \
            > /etc/apt/sources.list.d/microsoft-edge.sources; \
        apt-get update; \
        apt-get install -y --no-install-recommends microsoft-edge-stable; \
    fi \
    && printf 'deb-src http://deb.debian.org/debian trixie main\n' > /etc/apt/sources.list.d/debian-trixie-source.list \
    && apt-get update \
    && apt-get build-dep -y pulseaudio \
    && git clone --depth 1 https://github.com/neutrinolabs/pulseaudio-module-xrdp.git /tmp/pulseaudio-module-xrdp \
    && cd /tmp/pulseaudio-module-xrdp \
    && scripts/install_pulseaudio_sources_apt.sh \
    && ./bootstrap \
    && ./configure PULSE_DIR=/root/pulseaudio.src \
    && make -j"$(nproc)" \
    && make install \
    && PA_MOD_DIR="$(pkg-config --variable=modlibexecdir libpulse)" \
    && for module in module-xrdp-sink.so module-xrdp-source.so; do \
        found_module="$(find /usr /usr/local -name "$module" 2>/dev/null | head -1)"; \
        test -n "$found_module"; \
        mkdir -p "$PA_MOD_DIR"; \
        if [ "$found_module" != "$PA_MOD_DIR/$module" ]; then \
            cp "$found_module" "$PA_MOD_DIR/$module"; \
        fi; \
    done \
    && rm -rf /tmp/pulseaudio-module-xrdp /root/pulseaudio.src /etc/apt/sources.list.d/debian-trixie-source.list \
    && apt-get purge -y --auto-remove \
        git \
        build-essential \
        dpkg-dev \
        autoconf \
        automake \
        libtool \
        lsb-release \
        m4 \
        pkg-config \
        libpulse-dev \
        meson \
        ninja-build \
        doxygen \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN sed -i \
        -e 's/^new_cursors=.*/new_cursors=true/' \
        -e 's/^crypt_level=.*/crypt_level=high/' \
        /etc/xrdp/xrdp.ini \
    && if grep -q '^autorun=' /etc/xrdp/xrdp.ini; then \
        sed -i 's/^autorun=.*/autorun=Xorg/' /etc/xrdp/xrdp.ini; \
    else \
        printf '\nautorun=Xorg\n' >> /etc/xrdp/xrdp.ini; \
    fi \
    && if grep -q '^\[Channels\]' /etc/xrdp/xrdp.ini; then \
        sed -i '/^\[Channels\]/,/^\[/ s/^rdpsnd=.*/rdpsnd=true/' /etc/xrdp/xrdp.ini; \
        sed -i '/^\[Channels\]/,/^\[/ s/^drdynvc=.*/drdynvc=true/' /etc/xrdp/xrdp.ini; \
    else \
        printf '\n[Channels]\nrdpsnd=true\ndrdynvc=true\n' >> /etc/xrdp/xrdp.ini; \
    fi \
    && printf 'allowed_users=anybody\n' > /etc/X11/Xwrapper.config \
    && mkdir -p /etc/xdg/autostart \
    && printf '%s\n' \
        '[Desktop Entry]' \
        'Type=Application' \
        'Name=PulseAudio xrdp modules' \
        'Exec=/usr/local/bin/load-pulseaudio-xrdp' \
        'NoDisplay=true' \
        > /etc/xdg/autostart/pulseaudio-xrdp.desktop

RUN if [ -x /usr/bin/chromium ] && [ ! -x /usr/bin/chromium.real ]; then \
        mv /usr/bin/chromium /usr/bin/chromium.real; \
        printf '%s\n' \
            '#!/bin/sh' \
            'exec /usr/bin/chromium.real --no-sandbox --disable-dev-shm-usage --test-type "$@"' \
            > /usr/bin/chromium; \
        chmod 755 /usr/bin/chromium; \
    fi \
    && if [ -x /usr/bin/microsoft-edge-stable ] && [ ! -x /usr/bin/microsoft-edge-stable.real ]; then \
        mv /usr/bin/microsoft-edge-stable /usr/bin/microsoft-edge-stable.real; \
        printf '%s\n' \
            '#!/bin/sh' \
            'exec /usr/bin/microsoft-edge-stable.real --no-sandbox --disable-dev-shm-usage --test-type "$@"' \
            > /usr/bin/microsoft-edge-stable; \
        chmod 755 /usr/bin/microsoft-edge-stable; \
    fi

RUN printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'if [ -d "/run/user/$(id -u)" ]; then' \
    '    export XDG_RUNTIME_DIR="/run/user/$(id -u)"' \
    'fi' \
    'pulseaudio --start >/dev/null 2>&1 || true' \
    'for _ in 1 2 3 4 5 6 7 8 9 10; do' \
    '    pactl info >/dev/null 2>&1 && break' \
    '    sleep 0.2' \
    'done' \
    'DISPLAY_NUM=$(printf "%s" "${DISPLAY:-}" | sed "s/^.*:\\([0-9][0-9]*\\).*$/\\1/")' \
    '[ -n "$DISPLAY_NUM" ] || DISPLAY_NUM=10' \
    'SOCKET_PATH=/run/xrdp/sockdir' \
    '[ -d "$SOCKET_PATH" ] || SOCKET_PATH=/tmp/.xrdp' \
    'pactl load-module module-xrdp-sink "xrdp_socket_path=$SOCKET_PATH" "xrdp_pulse_sink_socket=xrdp_chansrv_audio_out_socket_$DISPLAY_NUM" >/dev/null 2>&1 || true' \
    'pactl load-module module-xrdp-source "xrdp_socket_path=$SOCKET_PATH" "xrdp_pulse_source_socket=xrdp_chansrv_audio_in_socket_$DISPLAY_NUM" >/dev/null 2>&1 || true' \
    'pactl set-default-sink xrdp-sink >/dev/null 2>&1 || true' \
    > /usr/local/bin/load-pulseaudio-xrdp \
    && chmod 755 /usr/local/bin/load-pulseaudio-xrdp

COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

EXPOSE 3389

ENTRYPOINT ["/opt/entrypoint.sh"]
