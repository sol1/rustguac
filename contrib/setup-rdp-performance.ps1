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

.PARAMETER EnableGPU
    Enable hardware GPU encoding. Requires a DirectX 11+ GPU
    (NVIDIA, Intel iGPU, or AMD). If no compatible GPU is present,
    Windows falls back to software encoding automatically.

.PARAMETER SkipReboot
    Don't prompt for reboot after applying settings.

.EXAMPLE
    # Standard setup (software encoding)
    .\setup-rdp-performance.ps1

    # With GPU hardware encoding
    .\setup-rdp-performance.ps1 -EnableGPU

.NOTES
    For rustguac - see docs/rdp-video-performance.md
    Tested on: Windows Server 2022, Windows Server 2025, Windows 11
#>

param(
    [switch]$EnableGPU,
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

Write-Host "`n=== RDP Performance Configuration ===" -ForegroundColor Cyan
Write-Host "Target: $(hostname) ($((Get-CimInstance Win32_OperatingSystem).Caption))"
Write-Host ""

# ── AVC 4:4:4 H.264 Encoding ──
Write-Host "--- Enabling AVC 4:4:4 (H.264 full-colour) ---" -ForegroundColor Yellow
$tsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

Set-RegValue -Path $tsPath -Name "AVC444ModePreferred" -Value 1
Set-RegValue -Path $tsPath -Name "SelectTransport" -Value 1  # Prefer UDP for better video
Set-RegValue -Path $tsPath -Name "MaxCompressionLevel" -Value 2  # Optimized compression

# ── 60 FPS Frame Rate ──
Write-Host "`n--- Enabling 60 FPS (default is 30) ---" -ForegroundColor Yellow
$wsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations"

# DWMFRAMEINTERVAL: 15 = 60fps, 10 = ~100fps (not recommended), 30 = 30fps (default)
Set-RegValue -Path $wsPath -Name "DWMFRAMEINTERVAL" -Value 15

# ── GPU Hardware Encoding ──
if ($EnableGPU) {
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
    Write-Host "`n--- GPU encoding: skipped (use -EnableGPU to enable) ---" -ForegroundColor Gray
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
Set-RegValue -Path $rfxPath -Name "ImageQuality" -Value 1  # 1=Low, 2=Medium, 3=High

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
if ($EnableGPU) {
    Write-Host "  GPU hardware encoding:  Enabled" -ForegroundColor Green
} else {
    Write-Host "  GPU hardware encoding:  Not enabled (use -EnableGPU)" -ForegroundColor Yellow
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
