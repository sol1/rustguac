# RDP Video Performance

Guide to optimizing RDP video quality and frame rate through rustguac, particularly for video monitoring workloads.

## Address Book Settings

Three per-entry settings control RDP video behaviour:

- **Enable Graphics Pipeline (GFX)** — Activates the RDP Graphics Pipeline Extension (RDPGFX), which enables the RemoteFX codec for better video compression. Recommended for video monitoring and media-heavy sessions. Requires 32-bit colour depth (set automatically).

- **Enable Desktop Composition** — Enables Windows Desktop Window Manager (DWM) compositing in the remote session. Improves rendering of video overlays, transparency effects, and smooth scrolling. Increases bandwidth slightly.

- **Force Lossless** — Forces PNG-only encoding (no JPEG/WebP lossy compression). Better for text-heavy workloads where visual fidelity matters. Uses significantly more bandwidth — not recommended for video content.

These settings appear in the address book entry editor for RDP entries under "Video Performance".

## Windows RDP Server Tuning

For the best video experience, configure the Windows RDP server (2022+).

### Quick Setup with Script

A PowerShell script is provided in `contrib/`. Run on the **Windows RDP target server** as Administrator:

```powershell
# Standard setup (software encoding, AVC444, 60fps)
.\setup-rdp-performance.ps1

# With GPU hardware encoding (requires DirectX 11+ GPU)
.\setup-rdp-performance.ps1 -EnableGPU
```

This configures: AVC 4:4:4, 60 FPS, desktop composition, RemoteFX, audio, and network tuning. A reboot is recommended after.

### Manual Setup

#### Enable AVC 4:4:4 (H.264 full-colour)

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

Debian 13 (trixie) ships xrdp 0.10.x, but the stock package does **not** include x264 H.264 encoding support. The `contrib/setup-xrdp-gfx.sh` script rebuilds xrdp from the Debian sid source package with `--enable-x264` and configures the GFX pipeline.

### Quick Setup with Scripts

Helper scripts are provided in the `contrib/` directory of the rustguac repository. Run these **on the xrdp target machine** (not the rustguac server):

```bash
# 1. Rebuild xrdp with x264 + configure GFX pipeline (~10 minutes)
sudo bash contrib/setup-xrdp-gfx.sh

# 2. Install audio redirection (builds PulseAudio module from source)
sudo bash contrib/setup-xrdp-audio.sh

# 3. Install a desktop environment
sudo apt install task-xfce-desktop
```

The GFX script:
1. Adds Debian sid repo with pinning (trixie stays default)
2. Installs matching `xorgxrdp` from sid
3. Rebuilds `xrdp` from sid source with `--enable-x264`
4. Configures Xorg backend (`autorun=Xorg`)
5. Allows non-root Xorg via Xwrapper
6. Creates `/etc/xrdp/gfx.toml` with H.264 + x264 encoder

### Manual Setup

#### Prerequisites

```bash
# Add sid repo for newer xrdp source
echo "deb http://deb.debian.org/debian sid main" > /etc/apt/sources.list.d/sid.list

# Pin trixie as default (prevent accidental sid upgrades)
cat > /etc/apt/preferences.d/pin-trixie << 'EOF'
Package: *
Pin: release a=trixie
Pin-Priority: 900

Package: *
Pin: release a=unstable
Pin-Priority: 100
EOF

apt-get update

# Install xorgxrdp from sid (must match xrdp version)
apt-get install -y -t unstable xorgxrdp

# Install x264 and build dependencies
apt-get install -y libx264-dev build-essential devscripts
apt-get build-dep -y xrdp
```

#### Rebuild xrdp with x264

The stock Debian xrdp package is built without `--enable-x264`. Rebuild from sid source:

```bash
cd /tmp
apt-get source xrdp=<sid-version>
cd xrdp-*
sed -i "s|--enable-opus|--enable-opus --enable-x264|" debian/rules
sed -i "s|^ autoconf,| libx264-dev,\n autoconf,|" debian/control
dpkg-buildpackage -b -uc -us -j$(nproc)
dpkg -i ../xrdp_*.deb
```

Verify x264 is linked: `ldd /usr/sbin/xrdp | grep libx264`

#### GFX Pipeline (Video)

The GFX pipeline requires the Xorg backend, not Xvnc. Set in `/etc/xrdp/xrdp.ini`:

```ini
autorun=Xorg
```

Allow non-root Xorg in `/etc/X11/Xwrapper.config`:
```
allowed_users=anybody
```

Create `/etc/xrdp/gfx.toml`:

```toml
[codec]
order = ["H.264", "RFX"]
h264_encoder = "x264"

[x264.default]
preset = "ultrafast"
tune = "zerolatency"
profile = "main"
vbv_max_bitrate = 0
vbv_buffer_size = 0
fps_num = 60
fps_den = 1
threads = 1

[x264.lan]
# inherits default — uncapped bitrate, 60fps

[x264.wan]
vbv_max_bitrate = 15000
vbv_buffer_size = 1500

[x264.broadband_high]
preset = "superfast"
vbv_max_bitrate = 8000
vbv_buffer_size = 800
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

### Standard Pipeline (non-H.264 servers)

1. **RDP Server** sends screen updates (Planar/RemoteFX codec)
2. **FreeRDP** (inside guacd) decodes to bitmaps
3. **guacd** re-encodes dirty regions as JPEG, WebP, or PNG based on content type and network conditions
4. **rustguac** relays over WebSocket to the browser
5. **Browser** decodes and renders to HTML Canvas

guacd automatically adapts encoding quality based on network lag:
- Low lag (<20ms): quality 90 (high detail)
- Medium lag (50ms): quality 70 (balanced)
- High lag (80ms): quality 30 (aggressive compression)

### H.264 Passthrough Pipeline (xrdp with x264)

When the RDP server sends H.264 (AVC420/AVC444), guacd passes the raw H.264 NAL units directly to the browser, bypassing the server-side decode and re-encode:

1. **xrdp** encodes the screen as H.264 via x264
2. **FreeRDP** (inside guacd) receives the H.264 SurfaceCommand
3. **guacd** copies the raw H.264 NAL data and also runs the normal GDI decode (for frame sync)
4. During frame flush, guacd sends the raw H.264 data as a custom `h264` instruction
5. **rustguac** relays over WebSocket to the browser
6. **Browser** decodes H.264 using the [WebCodecs VideoDecoder API](https://developer.mozilla.org/en-US/docs/Web/API/VideoDecoder) (hardware-accelerated)

Benefits:
- **Lower server CPU** — no decode + re-encode cycle on the server
- **Lower latency** — one fewer encoding pass
- **Consistent quality** — single lossy encoding pass (x264) instead of H.264 → bitmap → JPEG/WebP

H.264 passthrough activates automatically when the RDP server sends AVC420/AVC444 codec data. Servers that don't support H.264 (stock Debian xrdp, Windows without GPU) use the standard pipeline automatically.

Browser requirements: Chrome/Edge 94+, Firefox 130+ (WebCodecs support).
