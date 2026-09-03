#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Configure Windows Server 2022+ for maximum RDP video and audio performance.

.DESCRIPTION
    Applies registry settings and Group Policy overrides to enable:
    - AVC 4:4:4 (H.264 full-colour) encoding
    - 60 FPS frame rate (default is 30)
    - Hardware GPU encoding (optional, requires DirectX 11+ GPU)
    - Desktop composition (DWM) in remote sessions
    - Optimized audio settings

    Run on the Windows RDP target server (not the rustguac server).
    Requires administrator privileges. A reboot is recommended after.

.PARAMETER NoGPU
    Disable hardware GPU encoding. Hardware encoding is ON by default: without
    it Windows encodes H.264 in software regardless of the GPU present, which
    caps the source frame rate and degrades audio sync for every client.

.PARAMETER AVC444
    Enable AVC 4:4:4. Incompatible with rustguac's H.264 passthrough, which
    forwards a single bitstream -- use only for mstsc-only hosts.

.PARAMETER Report
    Print the current settings and detected GPUs, then exit without changing
    anything.

.PARAMETER SkipReboot
    Don't prompt for reboot after applying settings.

.EXAMPLE
    # Standard setup (hardware encoding enabled, AVC420 for rustguac)
    .\setup-rdp-performance.ps1

    # Show what is currently configured, change nothing
    .\setup-rdp-performance.ps1 -Report

    # Force software encoding
    .\setup-rdp-performance.ps1 -NoGPU

.NOTES
    For rustguac - see docs/rdp-video-performance.md
    Tested on: Windows Server 2022, Windows Server 2025, Windows 11

    If PowerShell refuses to run this ("not digitally signed"), the file is
    carrying the mark-of-the-web from being copied onto the host. Clear it:

        Unblock-File .\setup-rdp-performance.ps1

    Under an AllSigned policy, bypass for a single invocation instead of
    weakening the machine-wide policy:

        powershell -ExecutionPolicy Bypass -File .\setup-rdp-performance.ps1
#>

param(
    [switch]$NoGPU,
    [switch]$AVC444,
    [switch]$Report,
    [switch]$SkipReboot
)

$ErrorActionPreference = "Stop"

function Set-RegValue {
    param(
        [string]$Path,
        [string]$Name,
        [int]$Value,
        [string]$Type = "DWord"
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
    Write-Host "  Set $Name = $Value" -ForegroundColor Green
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $v.$Name
    } catch {
        return "<not set>"
    }
}

Write-Host "`n=== RDP Performance Configuration ===" -ForegroundColor Cyan
Write-Host "Target: $(hostname) ($((Get-CimInstance Win32_OperatingSystem).Caption))"
Write-Host ""

# ── Report mode: show what is actually configured, change nothing ──
if ($Report) {
    $ts = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $ws = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations"

    Write-Host "--- Current settings ---" -ForegroundColor Yellow
    foreach ($n in @("AVC444ModePreferred", "AVCHardwareEncodePreferred",
                     "bEnumerateHWBeforeSW", "SelectTransport",
                     "fClientDisableUDP", "MaxCompressionLevel",
                     "VisualExperiencePolicy", "ImageQuality")) {
        Write-Host ("  {0,-30} {1}" -f $n, (Get-RegValue $ts $n))
    }
    Write-Host ("  {0,-30} {1}" -f "DWMFRAMEINTERVAL", (Get-RegValue $ws "DWMFRAMEINTERVAL"))

    Write-Host "`n--- GPUs ---" -ForegroundColor Yellow
    Get-CimInstance Win32_VideoController | ForEach-Object {
        Write-Host "  - $($_.Name) [driver $($_.DriverVersion)]"
    }

    Write-Host "`nSelectTransport: 0 = both UDP and TCP, 1 = TCP only, 2 = UDP only" -ForegroundColor Gray
    Write-Host "Hardware encoding requires AVCHardwareEncodePreferred = 1 AND a reboot." -ForegroundColor Gray
    Write-Host "Confirm it is actually in use via Task Manager > Performance > GPU >" -ForegroundColor Gray
    Write-Host "Video Encode during an active session. 0% means software encoding." -ForegroundColor Gray
    return
}

# ── AVC 4:4:4 H.264 Encoding ──
Write-Host "--- Enabling AVC 4:4:4 (H.264 full-colour) ---" -ForegroundColor Yellow
$tsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# AVC444 splits the image across two H.264 bitstreams (luma/main plus an
# auxiliary chroma view). rustguac's passthrough forwards a single bitstream,
# so an AVC444 stream renders as a corrupted luma/chroma split. Windows only
# offers H.264 at all when guacd advertises the AVC444 capability
# (GUAC_RDP_H264_AVC444=1), but it must then decline the preference and send
# AVC420 -- which is what setting this to 0 does.
#
# Pass -AVC444 only for hosts used exclusively with mstsc, never with rustguac.
if ($AVC444) {
    Write-Host "  (AVC444 requested -- incompatible with rustguac H.264 passthrough)" -ForegroundColor Yellow
    Set-RegValue -Path $tsPath -Name "AVC444ModePreferred" -Value 1
} else {
    Set-RegValue -Path $tsPath -Name "AVC444ModePreferred" -Value 0
}

# 0 = both UDP and TCP, 1 = TCP only, 2 = UDP only. UDP carries video and audio
# far better for mstsc; forcing TCP here degrades exactly the frame rate and
# audio sync this script is meant to improve. guacd uses TCP regardless, so
# allowing both costs it nothing.
Set-RegValue -Path $tsPath -Name "SelectTransport" -Value 0
Set-RegValue -Path $tsPath -Name "MaxCompressionLevel" -Value 2  # Optimized compression

# ── 60 FPS Frame Rate ──
Write-Host "`n--- Enabling 60 FPS (default is 30) ---" -ForegroundColor Yellow
$wsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations"

# DWMFRAMEINTERVAL: 15 = 60fps, 10 = ~100fps (not recommended), 30 = 30fps (default)
Set-RegValue -Path $wsPath -Name "DWMFRAMEINTERVAL" -Value 15

# ── GPU Hardware Encoding ──
if (-not $NoGPU) {
    Write-Host "`n--- Enabling GPU hardware encoding ---" -ForegroundColor Yellow
    Set-RegValue -Path $tsPath -Name "AVCHardwareEncodePreferred" -Value 1
    Set-RegValue -Path $tsPath -Name "bEnumerateHWBeforeSW" -Value 1

    # Enable GPU for all RDS sessions
    $gpuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    Set-RegValue -Path $gpuPath -Name "bEnumerateHWBeforeSW" -Value 1

    # Check for available GPUs
    Write-Host "`n  Detected GPUs:" -ForegroundColor Gray
    Get-CimInstance Win32_VideoController | ForEach-Object {
        $status = if ($_.Status -eq "OK") { "OK" } else { $_.Status }
        Write-Host "    - $($_.Name) [$status]" -ForegroundColor Gray
    }
} else {
    Write-Host "`n--- GPU encoding: skipped (-NoGPU given) ---" -ForegroundColor Gray
}

# ── Desktop Composition (DWM) ──
Write-Host "`n--- Enabling desktop composition in remote sessions ---" -ForegroundColor Yellow
$dwmPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# Allow desktop composition for remote sessions
Set-RegValue -Path $dwmPath -Name "fEnableDesktopComposition" -Value 1

# ── RemoteFX / Graphics optimisation ──
Write-Host "`n--- Configuring RemoteFX and graphics ---" -ForegroundColor Yellow
$rfxPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# Enable RemoteFX for all sessions
Set-RegValue -Path $rfxPath -Name "fEnableRemoteFXAdvancedRemoteApp" -Value 1

# Configure visual experience to "Rich multimedia"
Set-RegValue -Path $rfxPath -Name "VisualExperiencePolicy" -Value 1

# Set image quality to highest
# 1=Low, 2=Medium, 3=High. Verify in gpedit under "Configure image quality
# for RemoteFX Adaptive Graphics" -- the policy shows the value in words.
Set-RegValue -Path $rfxPath -Name "ImageQuality" -Value 3

# ── Audio ──
Write-Host "`n--- Configuring audio ---" -ForegroundColor Yellow
$audioPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# Enable audio playback redirection
Set-RegValue -Path $audioPath -Name "fDisableCam" -Value 0  # Don't disable audio

# Audio quality: 0=Dynamic, 1=Medium, 2=High
Set-RegValue -Path $audioPath -Name "AudioQualityMode" -Value 0  # Dynamic adapts to bandwidth

# ── Network tuning ──
Write-Host "`n--- Network optimisation ---" -ForegroundColor Yellow
$netPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# Use RDP 8+ features
Set-RegValue -Path $netPath -Name "fClientDisableUDP" -Value 0  # Allow UDP transport
Set-RegValue -Path $netPath -Name "SelectNetworkDetect" -Value 1  # Auto-detect network quality

# ── Verify settings ──
Write-Host "`n=== Verification ===" -ForegroundColor Cyan

Write-Host "`nCheck Event Viewer after connecting to verify:" -ForegroundColor Gray
Write-Host "  Location: Applications and Services Logs > Microsoft > Windows >" -ForegroundColor Gray
Write-Host "            RemoteDesktopServices-RdpCoreTS > Operational" -ForegroundColor Gray
Write-Host "  Event ID 162 = AVC444 mode active" -ForegroundColor Gray
Write-Host "  Event ID 170 = Hardware encoding active" -ForegroundColor Gray

# Summary
Write-Host "`n=== Settings Applied ===" -ForegroundColor Cyan
Write-Host "  AVC 4:4:4 (H.264):     Enabled" -ForegroundColor Green
Write-Host "  Frame rate:             60 FPS" -ForegroundColor Green
Write-Host "  Desktop composition:    Enabled" -ForegroundColor Green
Write-Host "  RemoteFX:               Enabled" -ForegroundColor Green
Write-Host "  Audio:                  Dynamic quality" -ForegroundColor Green
if (-not $NoGPU) {
    Write-Host "  GPU hardware encoding:  Enabled" -ForegroundColor Green
    Write-Host "    Verify after reboot: Task Manager > Performance > GPU >" -ForegroundColor Gray
    Write-Host "    Video Encode during a session. 0% means it fell back to software." -ForegroundColor Gray
} else {
    Write-Host "  GPU hardware encoding:  Not enabled (-NoGPU)" -ForegroundColor Yellow
}
if ($AVC444) {
    Write-Host "  AVC 4:4:4:              Enabled (breaks rustguac passthrough)" -ForegroundColor Yellow
} else {
    Write-Host "  AVC 4:2:0:              Enabled (required for rustguac passthrough)" -ForegroundColor Green
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "A reboot is recommended for all settings to take effect." -ForegroundColor Yellow

if (-not $SkipReboot) {
    Write-Host ""
    $answer = Read-Host "Reboot now? (y/N)"
    if ($answer -eq "y" -or $answer -eq "Y") {
        Write-Host "Rebooting..."
        Restart-Computer -Force
    }
}
