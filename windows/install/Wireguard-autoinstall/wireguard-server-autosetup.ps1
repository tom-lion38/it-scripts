# wireguard-server-autosetup.ps1 (v8)
# WireGuard SERVER auto-setup (Windows) - robust keygen + cleaner output (ASCII only)
#
# Fixes:
# - If "wg.exe genkey" hangs on some hosts: we add timeout + multiple fallbacks
# - No fake "WinNAT created" message if it fails
# - Output messages are ASCII (avoids mojibake like "Ã©", "â€¦")
#
# Run (PowerShell as Admin):
#   chcp 65001 | Out-Null
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\wireguard-server-autosetup.ps1
#
# Notes:
# - Full-tunnel (AllowedIPs=0.0.0.0/0) needs NAT. WinNAT may fail on some systems (0x80041013).
#   If WinNAT fails, script offers split-tunnel fallback.
# - Client configs are written to: C:\Users\Public\WireGuard-Clients\

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try { chcp 65001 | Out-Null } catch {}
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new() } catch {}

function Info($m){ Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Ok($m){   Write-Host "[OK]   $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Die($m){  Write-Host "[ERR]  $m" -ForegroundColor Red; exit 1 }

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-Default([string]$Prompt, [string]$Default = "") {
  if ([string]::IsNullOrWhiteSpace($Default)) { return (Read-Host $Prompt) }
  $v = Read-Host "$Prompt [$Default]"
  if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
  return $v
}

function Read-YesNo([string]$Prompt, [string]$Default = "y") {
  while ($true) {
    $v = Read-Host "$Prompt [y/n] (default: $Default)"
    if ([string]::IsNullOrWhiteSpace($v)) { $v = $Default }
    switch ($v.ToLowerInvariant()) {
      "y" { return $true }
      "n" { return $false }
      default { Write-Host "Answer y or n." }
    }
  }
}

function Get-ArchTag {
  switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    "x86"   { "x86" }
    default { "amd64" }
  }
}

function Invoke-ExeCapture {
  param(
    [Parameter(Mandatory=$true)][string]$File,
    [Parameter(Mandatory=$false)][string]$Args = "",
    [Parameter(Mandatory=$false)][int]$TimeoutMs = 15000
  )
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $File
  $psi.Arguments = $Args
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()

  if (-not $p.WaitForExit($TimeoutMs)) {
    try { $p.Kill() } catch {}
    return [pscustomobject]@{ ExitCode = 124; StdOut = ""; StdErr = "TIMEOUT" }
  }

  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  return [pscustomobject]@{ ExitCode = $p.ExitCode; StdOut = $out; StdErr = $err }
}

function Extract-WgKey([string]$Text) {
  # WireGuard key is base64 44 chars ending with "="
  $m = [regex]::Match($Text, '([A-Za-z0-9+/]{43}=)')
  if ($m.Success) { return $m.Groups[1].Value }
  return $null
}

function Install-WireGuard-WithWinget {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { return $false }
  Info "Install via winget (WireGuard.WireGuard)..."
  $p = Start-Process -FilePath "winget" -ArgumentList @(
    "install","-e","--id","WireGuard.WireGuard",
    "--accept-package-agreements","--accept-source-agreements"
  ) -Wait -PassThru -WindowStyle Hidden
  if ($p.ExitCode -eq 0) { Ok "WireGuard installed (winget)."; return $true }
  Warn "winget failed (code $($p.ExitCode)). MSI fallback..."
  return $false
}

function Install-WireGuard-WithMSI {
  $arch = Get-ArchTag
  $base = "https://download.wireguard.com/windows-client/"
  Info "Fetch official MSI list..."
  $html = (Invoke-WebRequest -Uri $base -UseBasicParsing).Content

  $regex = "wireguard-$arch-([0-9]+\.[0-9]+\.[0-9]+)\.msi"
  $matches = [regex]::Matches($html, $regex)
  if ($matches.Count -lt 1) { Die "No MSI found for arch=$arch" }

  $ver = $matches[$matches.Count - 1].Groups[1].Value
  $msiName = "wireguard-$arch-$ver.msi"
  $msiUrl  = $base + $msiName
  $msiPath = Join-Path $env:TEMP $msiName

  Info "Download MSI: $msiName"
  Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
  if (-not (Test-Path $msiPath)) { Die "Download failed: $msiPath" }
  Ok "MSI downloaded: $msiPath"

  Info "Silent install (msiexec)..."
  $args = "/i `"$msiPath`" /qn DO_NOT_LAUNCH=1"
  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
  if ($p.ExitCode -ne 0) { Die "msiexec failed (code $($p.ExitCode))" }
  Ok "WireGuard installed (MSI)."
  return $true
}

function Get-WireGuardPaths {
  $wgExe = Join-Path $env:ProgramFiles "WireGuard\wg.exe"
  $wgui  = Join-Path $env:ProgramFiles "WireGuard\wireguard.exe"
  return @{
    wg = $wgExe
    wireguard = $wgui
    present = ((Test-Path $wgExe) -and (Test-Path $wgui))
  }
}

function Get-WgPubKeyFromPriv_File([string]$wgExe, [string]$PrivKey) {
  $tmp = Join-Path $env:TEMP ("wg-priv-" + [guid]::NewGuid().ToString("N") + ".txt")
  try {
    $key = $PrivKey.Trim()
    [IO.File]::WriteAllText($tmp, $key + "`r`n", [Text.Encoding]::ASCII)

    $cmd = "/c type `"$tmp`" | `"$wgExe`" pubkey"
    $r = Invoke-ExeCapture -File "cmd.exe" -Args $cmd -TimeoutMs 8000
    if ($r.ExitCode -ne 0) { Die "wg pubkey failed. $($r.StdErr)" }

    $pub = Extract-WgKey ($r.StdOut + "`n" + $r.StdErr)
    if ([string]::IsNullOrWhiteSpace($pub)) { Die "wg pubkey produced no valid key." }
    return $pub
  } finally {
    if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
  }
}

function Get-GenKeyRobust([string]$wgExe) {
  # Try 1: direct call (can hang -> timeout via job is messy; use cmd capture first for timeout)
  # Try 2: cmd.exe /c "wg.exe genkey" with timeout
  # Try 3: direct PS call (no timeout, but usually works when cmd fails)
  # Return: private key (44 chars)

  # Try 1 (cmd with timeout)
  $r1 = Invoke-ExeCapture -File "cmd.exe" -Args "/c `"$wgExe`" genkey" -TimeoutMs 8000
  $k1 = Extract-WgKey ($r1.StdOut + "`n" + $r1.StdErr)
  if ($r1.ExitCode -eq 0 -and $k1) { return $k1 }

  # Try 2 (direct PS)
  try {
    $raw = (& $wgExe genkey 2>&1)
    $txt = ($raw | Out-String)
    $k2 = Extract-WgKey $txt
    if ($k2) { return $k2 }
  } catch {}

  # If we are here: something is really wrong
  Die "Stuck/failed at server key generation. wg genkey did not return a valid key."
}

function New-WgKeyPair([string]$wgExe) {
  $priv = Get-GenKeyRobust -wgExe $wgExe
  $pub  = Get-WgPubKeyFromPriv_File -wgExe $wgExe -PrivKey $priv
  return @{ Private=$priv; Public=$pub }
}

function Ensure-FirewallRuleUdp([int]$Port) {
  $name = "WireGuard UDP $Port"
  $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
  if ($existing) { Ok "Firewall rule exists: $name"; return }
  Info "Open Windows Firewall: $Port/udp..."
  New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol UDP -LocalPort $Port | Out-Null
  Ok "Firewall OK."
}

function Enable-IPForwarding {
  Info "Enable IPv4 routing (IPEnableRouter=1)..."
  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
    -Name "IPEnableRouter" -PropertyType DWord -Value 1 -Force | Out-Null
  Ok "IPv4 routing enabled (registry)."
}

function Try-Configure-WinNAT([string]$NatName, [string]$InternalPrefix) {
  if (-not (Get-Command New-NetNat -ErrorAction SilentlyContinue)) {
    Warn "New-NetNat not available. WinNAT disabled."
    return $false
  }
  try {
    $existing = Get-NetNat -Name $NatName -ErrorAction SilentlyContinue
    if ($existing) {
      Warn "NAT '$NatName' already exists."
      if (Read-YesNo "Remove and recreate NAT?" "n") {
        Remove-NetNat -Name $NatName -Confirm:$false
        Ok "NAT removed."
      } else {
        return $true
      }
    }
    Info "Create WinNAT: $NatName (Internal=$InternalPrefix)..."
    New-NetNat -Name $NatName -InternalIPInterfaceAddressPrefix $InternalPrefix | Out-Null
    Ok "WinNAT created."
    return $true
  } catch {
    Warn "WinNAT failed: $($_.Exception.Message)"
    return $false
  }
}

function Write-ServerConfig([string]$Path,[string]$Addr,[int]$Port,[string]$PrivKey) {
  $dir = Split-Path -Parent $Path
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
  $content = "[Interface]`r`nAddress = $Addr`r`nListenPort = $Port`r`nPrivateKey = $PrivKey`r`n"
  Set-Content -Path $Path -Value $content -Encoding ASCII
}

function Append-PeerToServer([string]$Path,[string]$ClientPub,[string]$ClientIP32) {
  $block = "`r`n[Peer]`r`nPublicKey = $ClientPub`r`nAllowedIPs = $ClientIP32`r`n"
  Add-Content -Path $Path -Value $block -Encoding ASCII
}

function Write-ClientConfig(
  [string]$Path,[string]$ClientPriv,[string]$ClientIP,[string]$Dns,
  [string]$ServerPub,[string]$Endpoint,[int]$Port,[string]$Allowed,[int]$Keepalive
) {
  $dir = Split-Path -Parent $Path
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
  $content =
"[Interface]`r`n" +
"PrivateKey = $ClientPriv`r`n" +
"Address = $ClientIP/32`r`n" +
"DNS = $Dns`r`n`r`n" +
"[Peer]`r`n" +
"PublicKey = $ServerPub`r`n" +
"Endpoint = ${Endpoint}:$Port`r`n" +
"AllowedIPs = $Allowed`r`n" +
"PersistentKeepalive = $Keepalive`r`n"
  Set-Content -Path $Path -Value $content -Encoding ASCII
}

function Install-TunnelService([string]$wireguardExe,[string]$ConfPath,[string]$TunnelName) {
  Info "Install tunnel service: $TunnelName"
  & $wireguardExe /installtunnelservice $ConfPath | Out-Null
  Start-Sleep -Milliseconds 300
  $svc = "WireGuardTunnel`$$TunnelName"
  try { Start-Service -Name $svc -ErrorAction SilentlyContinue } catch {}
  Ok "Service: $svc"
}

function Restart-TunnelService([string]$TunnelName) {
  $svc = "WireGuardTunnel`$$TunnelName"
  try { Restart-Service -Name $svc -Force; Ok "Service restarted: $svc" }
  catch { Warn "Cannot restart $svc automatically." }
}

function Next-ClientIP([string]$BasePrefix,[int]$Start,[string[]]$Used) {
  for ($i=$Start; $i -le 254; $i++) {
    $ip = "$BasePrefix.$i"
    if (-not ($Used -contains $ip)) { return $ip }
  }
  return $null
}

# ---------------- MAIN ----------------
if (-not (Test-Admin)) { Die "Run PowerShell as Administrator." }

Info "WireGuard SERVER auto-setup (Windows)"

$paths0 = Get-WireGuardPaths
if (-not $paths0.present) {
  $installed = Install-WireGuard-WithWinget
  if (-not $installed) { $installed = Install-WireGuard-WithMSI }
  if (-not $installed) { Die "WireGuard install failed." }
}

$paths = Get-WireGuardPaths
if (-not $paths.present) { Die "WireGuard binaries not found after install." }

$wgExe = $paths.wg
$wgui  = $paths.wireguard
Ok "WireGuard present: $wgui"

$ifcs = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq "Up" -and $_.IPv4Address }
$pick = if ($ifcs) {
  $arr = @($ifcs)
  Write-Host ""
  Write-Host "Select WAN interface:" -ForegroundColor Cyan
  for ($i=0; $i -lt $arr.Length; $i++) {
    Write-Host ("  {0}) {1} | {2}" -f ($i+1), $arr[$i].InterfaceAlias, $arr[$i].IPv4Address.IPAddress)
  }
  while ($true) {
    $raw = Read-Host "Choice (1-$($arr.Length))"
    if ($raw -match '^\d+$') {
      $n = [int]$raw
      if ($n -ge 1 -and $n -le $arr.Length) { $arr[$n-1]; break }
    }
    Write-Host "Invalid choice."
  }
} else { $null }

$defaultIP = if ($pick) { $pick.IPv4Address.IPAddress } else { "" }

$tunnelName = Read-Default "Tunnel name (service)" "wg0"
if ($tunnelName -notmatch '^[a-zA-Z0-9._-]+$') { Die "Invalid tunnel name." }

$endpoint = Read-Default "Endpoint IP/DNS (public or LAN)" $defaultIP
if ([string]::IsNullOrWhiteSpace($endpoint)) { Die "Endpoint empty." }

$portRaw = Read-Default "WireGuard UDP port" "51820"
if ($portRaw -notmatch '^\d+$') { Die "Invalid port." }
$listenPort = [int]$portRaw

$cidr = Read-Default "WireGuard network (CIDR /24 only)" "10.8.0.0/24"
if ($cidr -notmatch '^(\d{1,3}\.){3}\d{1,3}/24$') { Die "Only /24 supported (example: 10.8.0.0/24)." }

$baseIP = $cidr.Split('/')[0]
$basePrefix = ($baseIP -split '\.')[0..2] -join '.'
$serverIP = "$basePrefix.1"
$serverAddr = "$serverIP/24"

Write-Host ""
Write-Host "DNS to push to clients:" -ForegroundColor Cyan
Write-Host "  1) Cloudflare (1.1.1.1)"
Write-Host "  2) Google (8.8.8.8)"
Write-Host "  3) Quad9 (9.9.9.9)"
Write-Host "  4) Server DNS (auto)"
$dnsChoice = Read-Default "Choice" "1"
$dns = "1.1.1.1"
switch ($dnsChoice) {
  "1" { $dns="1.1.1.1" }
  "2" { $dns="8.8.8.8" }
  "3" { $dns="9.9.9.9" }
  "4" {
    $dns = (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | Select-Object -First 1).ServerAddresses[0]
    if ([string]::IsNullOrWhiteSpace($dns)) { $dns="1.1.1.1" }
  }
}

Write-Host ""
Write-Host "Client routing mode:" -ForegroundColor Cyan
Write-Host "  1) Full-tunnel (AllowedIPs=0.0.0.0/0)"
Write-Host "  2) Split-tunnel (choose networks)"
$routeMode = Read-Default "Choice" "1"

$clientAllowed = "0.0.0.0/0"
if ($routeMode -eq "2") {
  $clientAllowed = Read-Default "AllowedIPs (comma separated)" "$cidr,192.168.1.0/24"
}

$doNat = $false
if ($routeMode -eq "1") {
  $doNat = Read-YesNo "Enable WinNAT for full-tunnel internet (may fail on some Windows)?" "y"
}

Write-Host ""
Info "Summary:"
Write-Host "  Tunnel    : $tunnelName"
Write-Host "  Endpoint  : ${endpoint}:$listenPort/udp"
Write-Host "  WG net    : $cidr (server $serverIP)"
Write-Host "  DNS       : $dns"
Write-Host "  AllowedIPs: $clientAllowed"
Write-Host "  WinNAT    : $doNat"
Write-Host ""

if (-not (Read-YesNo "Start now?" "y")) { Die "Cancelled." }

Info "Generate server keys (robust)..."
$serverKP = New-WgKeyPair -wgExe $wgExe
Ok "Server PublicKey:"
Write-Host $serverKP.Public

$confDir = Join-Path $env:ProgramData "WireGuard\Tunnels"
$serverConf = Join-Path $confDir "$tunnelName.conf"

if (Test-Path $serverConf) {
  Warn "Server config already exists: $serverConf"
  if (-not (Read-YesNo "Overwrite?" "n")) { Die "Cancelled." }
}

Info "Write server config: $serverConf"
Write-ServerConfig -Path $serverConf -Addr $serverAddr -Port $listenPort -PrivKey $serverKP.Private
Ok "Server config written."

Ensure-FirewallRuleUdp -Port $listenPort
Enable-IPForwarding

if ($doNat) {
  $okNat = Try-Configure-WinNAT -NatName ("WireGuardNAT-$tunnelName") -InternalPrefix $cidr
  if (-not $okNat) {
    Warn "WinNAT not available on this machine."
    Warn "Simple fallback: switch clients to split-tunnel (no NAT needed)."
    if (Read-YesNo "Switch to split-tunnel now?" "y") {
      $clientAllowed = Read-Default "AllowedIPs (split-tunnel)" "$cidr,192.168.1.0/24"
      Warn "OK. Clients will NOT use this server for all internet traffic."
    } else {
      Warn "If you need full-tunnel on Windows Server: use RRAS NAT."
    }
  }
}

Install-TunnelService -wireguardExe $wgui -ConfPath $serverConf -TunnelName $tunnelName

Write-Host ""
Info "Client generation."
$clientsDir = Join-Path $env:Public "WireGuard-Clients"
$used = @($serverIP)
$startOctet = 2
$keepalive = 25

while ($true) {
  $clientName = Read-Host "Client name (example: phone1) or ENTER to finish"
  if ([string]::IsNullOrWhiteSpace($clientName)) { break }
  if ($clientName -notmatch '^[a-zA-Z0-9._-]+$') { Write-Host "Invalid name."; continue }

  $suggest = Next-ClientIP -BasePrefix $basePrefix -Start $startOctet -Used $used
  if (-not $suggest) { Die "No more IPs in /24." }

  $clientIP = Read-Default "Client IP (in $cidr)" $suggest
  if ($clientIP -notmatch '^(\d{1,3}\.){3}\d{1,3}$') { Write-Host "Invalid IP."; continue }
  if ($used -contains $clientIP) { Write-Host "IP already used."; continue }
  if (($clientIP -split '\.')[0..2] -join '.' -ne $basePrefix) { Write-Host "IP outside /24."; continue }

  Info "Generate client keys..."
  $ckp = New-WgKeyPair -wgExe $wgExe
  Ok "Client PublicKey:"
  Write-Host $ckp.Public

  Append-PeerToServer -Path $serverConf -ClientPub $ckp.Public -ClientIP32 "$clientIP/32"
  $used += $clientIP

  $clientConf = Join-Path $clientsDir "$clientName.conf"
  Write-ClientConfig -Path $clientConf -ClientPriv $ckp.Private -ClientIP $clientIP -Dns $dns `
    -ServerPub $serverKP.Public -Endpoint $endpoint -Port $listenPort -Allowed $clientAllowed -Keepalive $keepalive
  Ok "Client config: $clientConf"

  if (-not (Read-YesNo "Add another client?" "y")) { break }
}

Restart-TunnelService -TunnelName $tunnelName

Write-Host ""
Ok "Done."
Info "Server config : $serverConf"
Info "Client configs: $clientsDir\*.conf"
Info "Status       : `"$wgExe`" show"
Info "Service      : WireGuardTunnel`$$tunnelName"
Info "Logs         : `"$wgui`" /dumplog"
