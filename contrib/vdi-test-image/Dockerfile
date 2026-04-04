FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# Minimal desktop: xrdp + xfce4
RUN apt-get update && apt-get install -y --no-install-recommends \
    xrdp \
    xorgxrdp \
    xserver-xorg \
    xfce4 \
    xfce4-terminal \
    xfdesktop4 \
    dbus-x11 \
    sudo \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

EXPOSE 3389

ENTRYPOINT ["/opt/entrypoint.sh"]
