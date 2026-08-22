# Prove Windows sees the T-Display S3 the same way Light does. Does not flash.
# Close Light / Desktop / Studio first if you use -Ping (they hold the COM port).
#
#   powershell -ExecutionPolicy Bypass -File scripts\test-banshee-usb.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\test-banshee-usb.ps1 -Watch
#   powershell -ExecutionPolicy Bypass -File scripts\test-banshee-usb.ps1 -Ping

param(
    [switch]$Watch,
    [switch]$Ping,
    [int]$Seconds = 60
)

$ErrorActionPreference = "Stop"
$Espressif = "303A"
$BootPid = "1001"
$AppPid = "B05E"

function Get-BansheeUsb {
    $rows = @()
    $entities = Get-CimInstance Win32_PnPEntity | Where-Object {
        $_.PNPDeviceID -match "VID_$Espressif" -or ($_.Name -match "COM\d+")
    }
    foreach ($dev in $entities) {
        $id = [string]$dev.PNPDeviceID
        if ($id -notmatch "VID_$Espressif") { continue }
        $usbPid = if ($id -match "PID_([0-9A-Fa-f]{4})") { $Matches[1].ToUpper() } else { "?" }
        $com = ""
        if ($dev.Name -match "(COM\d+)") { $com = $Matches[1] }
        $rows += [pscustomobject]@{
            Com  = $com
            UsbPid = $usbPid
            Mode = switch ($usbPid) {
                $BootPid { "bootloader (hold LEFT / BOOT)" }
                $AppPid { "app firmware (Light can talk)" }
                default { "Espressif USB, not Banshee app/boot" }
            }
            Name = $dev.Name
            Id   = $id
        }
    }
    return $rows
}

function Show-BansheeUsb([object[]]$rows) {
    if (-not $rows -or $rows.Count -eq 0) {
        Write-Host "No Espressif USB (VID 303A). Hold LEFT, plug USB, wait 2s."
        return
    }
    $rows | Format-Table Com, UsbPid, Mode, Name -AutoSize | Out-String | Write-Host
    $boot = $rows | Where-Object { $_.UsbPid -eq $BootPid }
    $app = $rows | Where-Object { $_.UsbPid -eq $AppPid }
    if ($boot) { Write-Host "READY TO FLASH  port $($boot.Com)  PID $BootPid" }
    if ($app) { Write-Host "APP MODE        port $($app.Com)  PID $AppPid" }
}

function Ping-Banshee([string]$com) {
    if (-not $com) { throw "No app COM port (need PID $AppPid). Flash first, then unplug/replug." }
    Write-Host "PING $com (DTR/RTS off)..."
    $sp = New-Object System.IO.Ports.SerialPort $com, 115200, None, 8, One
    $sp.DtrEnable = $false
    $sp.RtsEnable = $false
    $sp.NewLine = "`n"
    $sp.ReadTimeout = 800
    $sp.WriteTimeout = 2000
    $sp.Open()
    Start-Sleep -Milliseconds 400
    try { [void]$sp.ReadExisting() } catch { }
    try {
        $sp.WriteLine("PING")
        $line = ""
        $deadline = [DateTime]::UtcNow.AddSeconds(3)
        while ([DateTime]::UtcNow -lt $deadline) {
            try { $line = $sp.ReadLine().Trim() } catch { continue }
            if (-not $line) { continue }
            Write-Host "  rx $line"
            if ($line.StartsWith("OK PONG")) { Write-Host "USB TALK OK"; return }
        }
        throw "No OK PONG from $com"
    } finally {
        $sp.Close()
        $sp.Dispose()
    }
}

$rows = @(Get-BansheeUsb)
Show-BansheeUsb $rows

if ($Watch) {
    Write-Host "Watching $Seconds s. Unplug, do NOT hold LEFT, then plug in. Looking for PID B05E..."
    $until = [DateTime]::UtcNow.AddSeconds($Seconds)
    $last = ($rows | ForEach-Object { "$($_.Com):$($_.UsbPid)" }) -join ","
    while ([DateTime]::UtcNow -lt $until) {
        Start-Sleep -Seconds 1
        $rows = @(Get-BansheeUsb)
        $now = ($rows | ForEach-Object { "$($_.Com):$($_.UsbPid)" }) -join ","
        if ($now -ne $last) {
            Write-Host ""
            Show-BansheeUsb $rows
            $last = $now
        }
        if ($rows | Where-Object { $_.UsbPid -eq $AppPid }) {
            Write-Host "APP BOOTED"
            break
        }
    }
    if (-not (@(Get-BansheeUsb) | Where-Object { $_.UsbPid -eq $AppPid })) {
        Write-Host "Still bootloader (1001). App did not start. Studio Update with the original .pem, LEFT only while flashing."
    }
}

if ($Ping) {
    $app = @(Get-BansheeUsb) | Where-Object { $_.UsbPid -eq $AppPid } | Select-Object -First 1
    Ping-Banshee $app.Com
}
