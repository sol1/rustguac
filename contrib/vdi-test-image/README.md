# VDI Test Image

Minimal Docker image for testing rustguac VDI sessions. Provides a basic xfce4 desktop accessible via xrdp on port 3389.

## Build

```bash
docker build -t rustguac-vdi-test:latest .
```

## Usage

This image is designed to be launched by rustguac's VDI driver. Create an address book entry of type **VDI (Docker)** with the image name `rustguac-vdi-test:latest`.

The entrypoint accepts these environment variables (set automatically by rustguac):

| Variable | Description |
|----------|-------------|
| `VDI_USERNAME` | Linux username to create (default: `user`) |
| `VDI_PASSWORD` | Password for RDP login (default: `password`) |

## What's included

- Debian trixie-slim base
- xrdp + xorgxrdp (X server for RDP)
- xfce4 desktop with terminal
- TLS certificates (snakeoil, configured at runtime)

## Building your own image

Any Docker image that meets these requirements will work with rustguac VDI:

1. Run xrdp on port 3389
2. Accept `VDI_USERNAME` and `VDI_PASSWORD` environment variables
3. Create the user and set the password in the entrypoint
4. Start xrdp as the main process

For production use, consider adding: Firefox/Chromium, audio (PulseAudio + xrdp module), custom desktop environment, hardened security settings.
