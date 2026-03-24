# RDP Video Performance

Guide to optimizing RDP video quality and frame rate through rustguac, particularly for video monitoring workloads.

## Address Book Settings

Three per-entry settings control RDP video behaviour:

- **Enable Graphics Pipeline (GFX)** — Activates the RDP Graphics Pipeline Extension (RDPGFX), which enables the RemoteFX codec for better video compression. Recommended for video monitoring and media-heavy sessions. Requires 32-bit colour depth (set automatically).

- **Enable Desktop Composition** — Enables Windows Desktop Window Manager (DWM) compositing in the remote session. Improves rendering of video overlays, transparency effects, and smooth scrolling. Increases bandwidth slightly.

- **Force Lossless** — Forces PNG-only encoding (no JPEG/WebP lossy compression). Better for text-heavy workloads where visual fidelity matters. Uses significantly more bandwidth — not recommended for video content.

These settings appear in the address book entry editor for RDP entries under "Video Performance".

## Windows RDP Server Tuning

For the best video experience, configure the Windows RDP server:

### Enable AVC 4:4:4 (H.264 full-colour)

Group Policy: `Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Remote Session Environment`

- **Prioritize H.264/AVC 444 Graphics mode for Remote Desktop Connections** → Enabled

Or via registry:
```
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
  AVC444ModePreferred = 1 (DWORD)
  AVCHardwareEncodePreferred = 1 (DWORD)
```

### Enable 60 FPS

Windows RDP defaults to 30 FPS. To enable 60 FPS:
```
HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations
  DWMFRAMEINTERVAL = 15 (DWORD)
```

### Enable GPU Hardware Encoding

Any DirectX 11+ GPU (NVIDIA, Intel iGPU, AMD) can offload H.264 encoding. Enable via the same Group Policy path:

- **Configure H.264/AVC hardware encoding for Remote Desktop connections** → Enabled
- **Use hardware graphics adapters for all Remote Desktop Services sessions** → Enabled

### Verify Settings

Check Windows Event Viewer at `Applications and Services Logs > Microsoft > Windows > RemoteDesktopServices-RdpCoreTS`:

- **Event ID 162** — AVC444 mode is active
- **Event ID 170** — Hardware encoding is active

## Linux xrdp Tuning (Debian 13)

Debian 13 (trixie) ships xrdp 0.10.1 with GFX pipeline and H.264 support.

### Quick Setup with Scripts

Helper scripts are provided in the `contrib/` directory of the rustguac repository. Run these **on the xrdp target machine** (not the rustguac server):

```bash
# 1. Install GFX pipeline with H.264 encoding
sudo bash contrib/setup-xrdp-gfx.sh

# 2. Install audio redirection (builds PulseAudio module from source)
sudo bash contrib/setup-xrdp-audio.sh
```

### Manual Setup

#### Prerequisites

```bash
apt install xrdp xorgxrdp libx264-164 libavcodec61 pulseaudio
```

#### GFX Pipeline (Video)

The GFX pipeline requires the Xorg backend (`libxup.so`), not Xvnc. Set in `/etc/xrdp/xrdp.ini`:

```ini
autorun=Xorg
```

Create `/etc/xrdp/gfx.toml`:

```toml
[codec]
order = ["H.264", "RFX"]
h264_encoder = "x264"

[x264]
preset = "ultrafast"
tune = "zerolatency"
profile = "main"
vbv_max_bitrate = 0
vbv_buffer_size = 0
fps_num = 60
fps_den = 1
threads = 0

[x264.connection.lan]
preset = "ultrafast"
tune = "zerolatency"
vbv_max_bitrate = 0
fps_num = 60
fps_den = 1

[x264.connection.broadband_high]
preset = "ultrafast"
tune = "zerolatency"
vbv_max_bitrate = 20000
fps_num = 30
fps_den = 1
```

#### Audio Redirection

Debian 13 does not package `pulseaudio-module-xrdp` — it must be built from source. The `contrib/setup-xrdp-audio.sh` script automates this, or manually:

```bash
# Install build deps
apt install git build-essential dpkg-dev libpulse-dev autoconf libtool m4

# Clone and build
git clone --depth 1 https://github.com/neutrinolabs/pulseaudio-module-xrdp.git
cd pulseaudio-module-xrdp
scripts/install_pulseaudio_sources_apt.sh
./bootstrap
./configure PULSE_DIR=/root/pulseaudio.src
make
sudo make install
```

This installs `module-xrdp-sink.so` and `module-xrdp-source.so` into the PulseAudio modules directory, plus an XDG autostart entry that loads them automatically when an RDP session starts.

**Verify audio in a session:**
```bash
pactl list sinks short
# Should show: xrdp-sink  module-xrdp-sink.c  s16le 2ch 44100Hz  RUNNING
```

#### NVIDIA GPU Acceleration

If the xrdp server has an NVIDIA GPU with NVENC support, set in `/etc/xrdp/sesman.ini`:

```ini
XRDP_USE_ACCEL_ASSIST=1
```

#### Restart

```bash
sudo systemctl restart xrdp
```

## Network Requirements

Estimated bandwidth per session at different quality levels:

| Resolution | FPS | Encoding | Bandwidth |
|-----------|-----|----------|-----------|
| 1080p | 30 | JPEG (default) | ~10 Mbps |
| 1080p | 30 | WebP | ~7 Mbps |
| 1080p | 60 | JPEG | ~18 Mbps |
| 4K | 30 | WebP | ~29 Mbps |

For video monitoring workloads, a minimum of 20 Mbps per session is recommended. Use GFX + Desktop Composition for the best results.

## How It Works

The video pipeline through rustguac:

1. **RDP Server** encodes screen updates (H.264/AVC444 if enabled)
2. **FreeRDP** (inside guacd) decodes to bitmaps
3. **guacd** re-encodes dirty regions as JPEG, WebP, or PNG based on content type and network conditions
4. **rustguac** relays over WebSocket to the browser
5. **Browser** decodes and renders to HTML Canvas

guacd automatically adapts encoding quality based on network lag:
- Low lag (<20ms): quality 90 (high detail)
- Medium lag (50ms): quality 70 (balanced)
- High lag (80ms): quality 30 (aggressive compression)

The GFX pipeline enables RemoteFX codec between the RDP server and FreeRDP, which provides better compression than legacy bitmap updates.
