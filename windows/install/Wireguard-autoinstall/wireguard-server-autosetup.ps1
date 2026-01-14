# wireguard-server-autosetup.ps1
# WireGuard SERVER auto-install + config on Windows (10/11/Server).
# - Installe WireGuard (winget -> MSI fallback)
# - Crée un tunnel serveur (wg0) en service Windows
# - Ouvre le port UDP
# - Active le routage IPv4
# - (Optionnel) Configure WinNAT (New-NetNat) pour full-tunnel (clients -> Internet via le serveur)
# - Génère 1+ configs clients et ajoute automatiquement les peers côté serveur
#
# Run (PowerShell Admin):
#   chcp 65001 | Out-Null
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\wireguard-server-autosetup.ps1

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# UTF-8 output to avoid mojibake (Ã© etc.)
try {
  chcp 65001 | Out-Null
  $OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
} catch {}

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
    $v = Read-Host "$Prompt [y/n] (défaut: $Default)"
    if ([string]::IsNullOrWhiteSpace($v)) { $v = $Default }
    switch ($v.ToLowerInvariant()) {
      "y" { return $true }
      "n" { return $false }
      default { Write-Host "Réponds y ou n." }
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

function Install-WireGuard-WithWinget {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { return $false }
  Info "Installation via winget (WireGuard.WireGuard)…"
  $p = Start-Process -FilePath "winget" -ArgumentList @(
    "install","-e","--id","WireGuard.WireGuard",
    "--accept-package-agreements","--accept-source-agreements"
  ) -Wait -PassThru -WindowStyle Hidden
  if ($p.ExitCode -eq 0) { Ok "WireGuard installé (winget)."; return $true }
  Warn "winget a échoué (code $($p.ExitCode)). Fallback MSI…"
  return $false
}

function Install-WireGuard-WithMSI {
  $arch = Get-ArchTag
  $base = "https://download.wireguard.com/windows-client/"
  Info "Récupération de la liste officielle des MSIs…"
  $html = (Invoke-WebRequest -Uri $base -UseBasicParsing).Content

  $regex = "wireguard-$arch-([0-9]+\.[0-9]+\.[0-9]+)\.msi"
  $matches = [regex]::Matches($html, $regex)
  if ($matches.Count -lt 1) { Die "Impossible de trouver un MSI WireGuard pour arch=$arch" }

  $ver = $matches[$matches.Count - 1].Groups[1].Value
  $msiName = "wireguard-$arch-$ver.msi"
  $msiUrl  = $base + $msiName
  $msiPath = Join-Path $env:TEMP $msiName

  Info "Téléchargement MSI: $msiName"
  Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
  if (-not (Test-Path $msiPath)) { Die "Téléchargement échoué: $msiPath" }
  Ok "MSI téléchargé: $msiPath"

  Info "Installation silencieuse (msiexec)…"
  $args = "/i `"$msiPath`" /qn DO_NOT_LAUNCH=1"
  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
  if ($p.ExitCode -ne 0) { Die "msiexec a échoué (code $($p.ExitCode))." }
  Ok "WireGuard installé (MSI)."
  return $true
}

function Get-WireGuardPaths {
  $wgExe = Join-Path $env:ProgramFiles "WireGuard\wg.exe"
  $wgui  = Join-Path $env:ProgramFiles "WireGuard\wireguard.exe"
  if (-not (Test-Path $wgExe)) { Die "wg.exe introuvable: $wgExe" }
  if (-not (Test-Path $wgui))  { Die "wireguard.exe introuvable: $wgui" }
  return @{ wg = $wgExe; wireguard = $wgui }
}

# Avoid PowerShell pipeline for pubkey conversion (fixes: "Trailing characters found after key")
function Get-WgPubKeyFromPriv([string]$wgExe, [string]$PrivKey) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $wgExe
  $psi.Arguments = "pubkey"
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()

  $p.StandardInput.WriteLine($PrivKey.Trim())
  $p.StandardInput.Close()

  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()

  if ($p.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($out)) {
    Die "wg pubkey a échoué. $err"
  }
  return $out.Trim()
}

function New-WgKeyPair([string]$wgExe) {
  $priv = (& $wgExe genkey 2>$null).Trim()
  if ([string]::IsNullOrWhiteSpace($priv)) { Die "Échec gen clé privée." }

  $pub = Get-WgPubKeyFromPriv -wgExe $wgExe -PrivKey $priv
  if ([string]::IsNullOrWhiteSpace($pub)) { Die "Échec gen clé publique." }

  return @{ Private=$priv; Public=$pub }
}

function Select-FromList([string]$Title, [object[]]$Items, [scriptblock]$Render) {
  $arr = @($Items)
  if ($arr.Length -eq 0) { return $null }
  Write-Host ""
  Write-Host $Title -ForegroundColor Cyan
  for ($i=0; $i -lt $arr.Length; $i++) {
    $line = & $Render $arr[$i]
    Write-Host ("  {0}) {1}" -f ($i+1), $line)
  }
  while ($true) {
    $raw = Read-Host "Choix (1-$($arr.Length))"
    if ($raw -match '^\d+$') {
      $n = [int]$raw
      if ($n -ge 1 -and $n -le $arr.Length) { return $arr[$n-1] }
    }
    Write-Host "Choix invalide."
  }
}

function Ensure-FirewallRuleUdp([int]$Port) {
  $name = "WireGuard UDP $Port"
  $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
  if ($existing) { Ok "Firewall rule déjà présente: $name"; return }
  Info "Ouverture firewall Windows: $Port/udp…"
  New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol UDP -LocalPort $Port | Out-Null
  Ok "Firewall OK."
}

function Enable-IPForwarding {
  Info "Activation routage IPv4 (IPEnableRouter=1)…"
  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
    -Name "IPEnableRouter" -PropertyType DWord -Value 1 -Force | Out-Null
  Ok "Routage IPv4 activé (registry)."
}

function Try-Configure-WinNAT([string]$NatName, [string]$InternalPrefix) {
  if (-not (Get-Command New-NetNat -ErrorAction SilentlyContinue)) {
    Warn "New-NetNat introuvable. Pas de NAT automatique (full-tunnel Internet)."
    return $false
  }
  $existing = Get-NetNat -Name $NatName -ErrorAction SilentlyContinue
  if ($existing) {
    Warn "NAT '$NatName' existe déjà."
    if (Read-YesNo "Le supprimer et le recréer ?" "n") {
      Remove-NetNat -Name $NatName -Confirm:$false
      Ok "NAT supprimé."
    } else {
      return $true
    }
  }
  Info "Création WinNAT: $NatName (Internal=$InternalPrefix)…"
  New-NetNat -Name $NatName -InternalIPInterfaceAddressPrefix $InternalPrefix | Out-Null
  Ok "WinNAT créé."
  return $true
}

function Write-ServerConfig([string]$Path,[string]$Addr,[int]$Port,[string]$PrivKey) {
  $dir = Split-Path -Parent $Path
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
  $content = @"
[Interface]
Address = $Addr
ListenPort = $Port
PrivateKey = $PrivKey
"@
  Set-Content -Path $Path -Value $content -Encoding ASCII
}

function Append-PeerToServer([string]$Path,[string]$ClientPub,[string]$ClientIP32) {
  Add-Content -Path $Path -Value "`r`n[Peer]`r`nPublicKey = $ClientPub`r`nAllowedIPs = $ClientIP32" -Encoding ASCII
}

function Write-ClientConfig(
  [string]$Path,[string]$ClientPriv,[string]$ClientIP,[string]$Dns,
  [string]$ServerPub,[string]$Endpoint,[int]$Port,[string]$Allowed,[int]$Keepalive
) {
  $dir = Split-Path -Parent $Path
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
  $content = @"
[Interface]
PrivateKey = $ClientPriv
Address = $ClientIP/32
DNS = $Dns

[Peer]
PublicKey = $ServerPub
Endpoint = ${Endpoint}:$Port
AllowedIPs = $Allowed
PersistentKeepalive = $Keepalive
"@
  Set-Content -Path $Path -Value $content -Encoding ASCII
}

function Install-TunnelService([string]$wireguardExe,[string]$ConfPath,[string]$TunnelName) {
  Info "Installation tunnel service: $TunnelName"
  & $wireguardExe /installtunnelservice $ConfPath | Out-Null
  Start-Sleep -Milliseconds 300
  $svc = "WireGuardTunnel`$$TunnelName"
  try { Start-Service -Name $svc -ErrorAction SilentlyContinue } catch {}
  Ok "Service tunnel: $svc"
}

function Restart-TunnelService([string]$TunnelName) {
  $svc = "WireGuardTunnel`$$TunnelName"
  try {
    Restart-Service -Name $svc -Force
    Ok "Service redémarré: $svc"
  } catch {
    Warn "Impossible de redémarrer $svc automatiquement."
  }
}

function Next-ClientIP([string]$BasePrefix,[int]$Start,[string[]]$Used) {
  for ($i=$Start; $i -le 254; $i++) {
    $ip = "$BasePrefix.$i"
    if (-not ($Used -contains $ip)) { return $ip }
  }
  return $null
}

# ---------------- MAIN ----------------
if (-not (Test-Admin)) { Die "Lance PowerShell en Administrateur." }

Info "WireGuard SERVER auto-setup (Windows)"

$installed = Install-WireGuard-WithWinget
if (-not $installed) { $installed = Install-WireGuard-WithMSI }
if (-not $installed) { Die "Installation WireGuard impossible." }

$paths = Get-WireGuardPaths
$wgExe = $paths.wg
$wgui  = $paths.wireguard
Ok "WireGuard présent: $wgui"

# Pick WAN interface (for default IP hint)
$ifcs = Get-NetIPConfiguration | Where-Object {
  $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq "Up" -and $_.IPv4Address
}
$pick = if ($ifcs) {
  Select-FromList "Choisis l'interface WAN (celle qui sort Internet/LAN principal)" $ifcs {
    param($x) "$($x.InterfaceAlias)  |  $($x.IPv4Address.IPAddress)"
  }
} else { $null }
$defaultIP = if ($pick) { $pick.IPv4Address.IPAddress } else { "" }

$tunnelName = Read-Default "Nom du tunnel serveur (service)" "wg0"
if ($tunnelName -notmatch '^[a-zA-Z0-9._-]+$') { Die "Nom invalide (lettres/chiffres/._-)." }

$endpoint = Read-Default "IP/DNS que les clients utiliseront (endpoint public ou LAN)" $defaultIP
if ([string]::IsNullOrWhiteSpace($endpoint)) { Die "Endpoint vide." }

$portRaw = Read-Default "Port WireGuard UDP" "51820"
if ($portRaw -notmatch '^\d+$') { Die "Port invalide." }
$listenPort = [int]$portRaw

$cidr = Read-Default "Réseau WireGuard (CIDR /24 recommandé)" "10.8.0.0/24"
if ($cidr -notmatch '^(\d{1,3}\.){3}\d{1,3}/24$') {
  Die "Ce script gère automatiquement /24 uniquement (ex: 10.8.0.0/24)."
}

$baseIP = $cidr.Split('/')[0]
$basePrefix = ($baseIP -split '\.')[0..2] -join '.'
$serverIP = "$basePrefix.1"
$serverAddr = "$serverIP/24"

# DNS clients
Write-Host ""
Write-Host "DNS à pousser aux clients :" -ForegroundColor Cyan
Write-Host "  1) Cloudflare (1.1.1.1)"
Write-Host "  2) Google (8.8.8.8)"
Write-Host "  3) Quad9 (9.9.9.9)"
Write-Host "  4) DNS du serveur (automatique)"
$dnsChoice = Read-Default "Ton choix" "1"
$dns = "1.1.1.1"
switch ($dnsChoice) {
  "1" { $dns="1.1.1.1" }
  "2" { $dns="8.8.8.8" }
  "3" { $dns="9.9.9.9" }
  "4" {
    $dns = (Get-DnsClientServerAddress -AddressFamily IPv4 |
      Where-Object { $_.ServerAddresses } |
      Select-Object -First 1).ServerAddresses[0]
    if ([string]::IsNullOrWhiteSpace($dns)) { $dns="1.1.1.1" }
  }
}

# Routing mode for clients
Write-Host ""
Write-Host "Mode de routage client :" -ForegroundColor Cyan
Write-Host "  1) Full-tunnel (tout passe dans le VPN)      AllowedIPs=0.0.0.0/0"
Write-Host "  2) Split-tunnel (réseaux choisis)           AllowedIPs=ex: 10.8.0.0/24,192.168.1.0/24"
$routeMode = Read-Default "Ton choix" "1"
$clientAllowed = "0.0.0.0/0"
if ($routeMode -eq "2") {
  $clientAllowed = Read-Default "AllowedIPs (séparés par virgules)" "$cidr"
}

# NAT option (for full-tunnel Internet)
$doNat = $false
if ($routeMode -eq "1") {
  $doNat = Read-YesNo "Configurer WinNAT pour que les clients aient Internet via ce serveur ?" "y"
} else {
  $doNat = Read-YesNo "Configurer WinNAT quand même ? (rarement utile en split)" "n"
}

Write-Host ""
Info "Résumé :"
Write-Host "  Tunnel     : $tunnelName"
Write-Host "  Endpoint   : ${endpoint}:$listenPort/udp"
Write-Host "  WG réseau  : $cidr (serveur: $serverIP)"
Write-Host "  DNS client : $dns"
Write-Host "  AllowedIPs : $clientAllowed"
Write-Host "  WinNAT     : $doNat"
Write-Host ""

if (-not (Read-YesNo "Lancer la configuration maintenant ?" "y")) { Die "Annulé." }

# Keys
Info "Génération clés serveur…"
$serverKP = New-WgKeyPair -wgExe $wgExe
Ok "Clé publique SERVEUR (à mettre chez les clients):"
Write-Host $serverKP.Public

# Write server conf
$confDir = Join-Path $env:ProgramData "WireGuard\Tunnels"
$serverConf = Join-Path $confDir "$tunnelName.conf"

if (Test-Path $serverConf) {
  Warn "Config existe déjà: $serverConf"
  if (-not (Read-YesNo "Écraser ?" "n")) { Die "Annulé." }
}

Info "Écriture config serveur: $serverConf"
Write-ServerConfig -Path $serverConf -Addr $serverAddr -Port $listenPort -PrivKey $serverKP.Private
Ok "Config serveur écrite."

# Firewall + routing
Ensure-FirewallRuleUdp -Port $listenPort
Enable-IPForwarding

# WinNAT (optional)
if ($doNat) {
  $natName = "WireGuardNAT-$tunnelName"
  [void](Try-Configure-WinNAT -NatName $natName -InternalPrefix $cidr)
}

# Install tunnel service
Install-TunnelService -wireguardExe $wgui -ConfPath $serverConf -TunnelName $tunnelName

# Clients
Write-Host ""
Info "Génération des clients (au moins 1)."
$clientsDir = Join-Path $env:Public "WireGuard-Clients"
$used = @($serverIP)
$startOctet = 2
$keepalive = 25

while ($true) {
  $clientName = Read-Host "Nom du client (ex: phone1) ou ENTER pour finir"
  if ([string]::IsNullOrWhiteSpace($clientName)) { break }
  if ($clientName -notmatch '^[a-zA-Z0-9._-]+$') { Write-Host "Nom invalide."; continue }

  $suggest = Next-ClientIP -BasePrefix $basePrefix -Start $startOctet -Used $used
  if (-not $suggest) { Die "Plus d'IP disponibles dans /24." }

  $clientIP = Read-Default "IP client (dans $cidr)" $suggest
  if ($clientIP -notmatch '^(\d{1,3}\.){3}\d{1,3}$') { Write-Host "IP invalide."; continue }
  if ($used -contains $clientIP) { Write-Host "IP déjà utilisée."; continue }
  if (($clientIP -split '\.')[0..2] -join '.' -ne $basePrefix) { Write-Host "IP hors du /24."; continue }

  Info "Génération clés client…"
  $ckp = New-WgKeyPair -wgExe $wgExe
  Ok "Clé publique CLIENT (peer côté serveur):"
  Write-Host $ckp.Public

  Append-PeerToServer -Path $serverConf -ClientPub $ckp.Public -ClientIP32 "$clientIP/32"
  $used += $clientIP

  $clientConf = Join-Path $clientsDir "$clientName.conf"
  Write-ClientConfig -Path $clientConf -ClientPriv $ckp.Private -ClientIP $clientIP -Dns $dns `
    -ServerPub $serverKP.Public -Endpoint $endpoint -Port $listenPort -Allowed $clientAllowed -Keepalive $keepalive
  Ok "Client généré: $clientConf"

  if (-not (Read-YesNo "Ajouter un autre client ?" "y")) { break }
}

# Reload peers
Restart-TunnelService -TunnelName $tunnelName

Write-Host ""
Ok "Terminé."
Info "Config serveur : $serverConf"
Info "Configs clients: $clientsDir\*.conf"
Info "Voir état      : `"$wgExe`" show"
Info "Service        : WireGuardTunnel`$$tunnelName"
Info "Logs WG        : `"$wgui`" /dumplog"
