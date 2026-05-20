# VDI Example Image with PulseAudio Support

Debian Trixie Docker image for Rustguac VDI sessions. Provides a MATE desktop, common desktop applications, and PulseAudio redirection over xrdp on port 3389.

## Build

```bash
docker build -t trixie-vdi-pulseaudio:latest .
```

## Usage

This image is designed to be launched by rustguac's VDI driver. Create an address book entry of type **VDI (Docker)** with the image name `trixie-vdi-pulseaudio:latest`.

The entrypoint accepts these environment variables (set automatically by rustguac):

| Variable | Description |
|----------|-------------|
| `VDI_USERNAME` | Linux username to create (default: `user`) |
| `VDI_PASSWORD` | Password for RDP login (default: `password`) |
| `VDI_SUDO` | Add the user to the `sudo` group when set to `true` (default: `false`) |

## What's included

- Debian Trixie slim base
- xrdp + xorgxrdp (X server for RDP)
- MATE desktop with terminal and media controls
- Microsoft Edge, Chromium, Firefox ESR, LibreOffice
- PulseAudio, pavucontrol, ALSA tools, and the xrdp PulseAudio sink/source modules
- TLS certificates (snakeoil, configured at runtime)