# wireguard-autoinstall.ps1
# Installe WireGuard sur Windows (silencieux) puis (optionnel) crée/import un tunnel en service.
# - Méthode 1: winget si dispo
# - Méthode 2: télécharge le MSI officiel depuis download.wireguard.com et installe via msiexec
#
# Run (PowerShell admin):
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\wireguard-autoinstall.ps1
#
# Notes:
# - Ce script configure un "client" WireGuard (tunnel). Il ne configure pas un serveur WireGuard côté distant.
# - Aucune info perso codée en dur: tout est demandé au runtime.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[OK]   $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Die($msg)        { Write-Host "[ERR]  $msg" -ForegroundColor Red; exit 1 }

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-Default([string]$Prompt, [string]$Default = "") {
  if ([string]::IsNullOrWhiteSpace($Default)) {
    return (Read-Host $Prompt)
  }
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
  # WireGuard MSIs on download page: amd64 / arm64 / x86
  switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { return "amd64" }
    "ARM64" { return "arm64" }
    "x86"   { return "x86" }
    default { return "amd64" }
  }
}

function Install-WireGuard-WithWinget {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { return $false }
  Write-Info "Installation via winget (WireGuard.WireGuard)…"
  $p = Start-Process -FilePath "winget" -ArgumentList @(
    "install","-e","--id","WireGuard.WireGuard",
    "--accept-package-agreements","--accept-source-agreements"
  ) -Wait -PassThru -WindowStyle Hidden
  if ($p.ExitCode -eq 0) {
    Write-Ok "WireGuard installé (winget)."
    return $true
  }
  Write-Warn "winget a échoué (code $($p.ExitCode)). Fallback MSI…"
  return $false
}

function Install-WireGuard-WithMSI {
  $arch = Get-ArchTag
  $base = "https://download.wireguard.com/windows-client/"
  Write-Info "Récupération de la liste officielle des MSIs…"
  $html = (Invoke-WebRequest -Uri $base -UseBasicParsing).Content

  # Trouve le dernier MSI correspondant à l'arch: wireguard-amd64-0.x.y.msi
  $regex = "wireguard-$arch-([0-9]+\.[0-9]+\.[0-9]+)\.msi"
  $matches = [regex]::Matches($html, $regex)
  if ($matches.Count -lt 1) { Die "Impossible de trouver un MSI WireGuard pour arch=$arch sur $base" }

  # Sur la page, il n'y a normalement qu'une version "courante"; on prend la dernière matchée.
  $ver = $matches[$matches.Count - 1].Groups[1].Value
  $msiName = "wireguard-$arch-$ver.msi"
  $msiUrl  = $base + $msiName
  $msiPath = Join-Path $env:TEMP $msiName

  Write-Info "Téléchargement MSI: $msiName"
  Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
  if (-not (Test-Path $msiPath)) { Die "Téléchargement échoué: $msiPath" }
  Write-Ok "MSI téléchargé: $msiPath"

  Write-Info "Installation silencieuse (msiexec)…"
  # DO_NOT_LAUNCH=1 évite l'ouverture UI après install (propriété MSI WireGuard)
  $args = "/i `"$msiPath`" /qn DO_NOT_LAUNCH=1"
  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
  if ($p.ExitCode -ne 0) { Die "msiexec a échoué (code $($p.ExitCode))." }
  Write-Ok "WireGuard installé (MSI)."
  return $true
}

function Get-WireGuardPaths {
  $wgExe = Join-Path $env:ProgramFiles "WireGuard\wg.exe"
  $wgui  = Join-Path $env:ProgramFiles "WireGuard\wireguard.exe"
  if (-not (Test-Path $wgExe)) { Die "wg.exe introuvable: $wgExe (install WireGuard KO ?)" }
  if (-not (Test-Path $wgui))  { Die "wireguard.exe introuvable: $wgui (install WireGuard KO ?)" }
  return @{ wg = $wgExe; wireguard = $wgui }
}

function New-WgKeyPair([string]$wgExe) {
  # wg genkey | wg pubkey
  $priv = (& $wgExe genkey).Trim()
  if ([string]::IsNullOrWhiteSpace($priv)) { Die "Échec génération clé privée." }
  $pub  = ($priv | & $wgExe pubkey).Trim()
  if ([string]::IsNullOrWhiteSpace($pub)) { Die "Échec génération clé publique." }
  return @{ Private = $priv; Public = $pub }
}

function Write-ClientConfig {
  param(
    [string]$Path,
    [string]$ClientPriv,
    [string]$ClientAddress,
    [string]$Dns,
    [string]$ServerPub,
    [string]$EndpointHost,
    [string]$EndpointPort,
    [string]$AllowedIPs,
    [string]$Keepalive
  )
  $content = @"
[Interface]
PrivateKey = $ClientPriv
Address = $ClientAddress
DNS = $Dns

[Peer]
PublicKey = $ServerPub
Endpoint = $EndpointHost`:$EndpointPort
AllowedIPs = $AllowedIPs
PersistentKeepalive = $Keepalive
"@
  $dir = Split-Path -Parent $Path
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
  Set-Content -Path $Path -Value $content -Encoding ASCII
}

function Install-TunnelService([string]$wireguardExe, [string]$confPath, [string]$tunnelName) {
  Write-Info "Installation du tunnel service: $tunnelName"
  & $wireguardExe /installtunnelservice $confPath | Out-Null
  Start-Sleep -Milliseconds 300
  $svc = "WireGuardTunnel`$$tunnelName"
  try {
    Start-Service -Name $svc -ErrorAction SilentlyContinue
  } catch { }
  Write-Ok "Tunnel installé. Service: $svc"
}

# ------------------
# MAIN
# ------------------
if (-not (Test-Admin)) { Die "Lance PowerShell en Administrateur." }

Write-Info "WireGuard auto-install (Windows)"

$installed = Install-WireGuard-WithWinget
if (-not $installed) { $installed = Install-WireGuard-WithMSI }
if (-not $installed) { Die "Installation WireGuard impossible." }

$paths = Get-WireGuardPaths
$wgExe = $paths.wg
$wgui  = $paths.wireguard
Write-Ok "WireGuard présent: $wgui"

if (-not (Read-YesNo "Créer et installer un tunnel WireGuard maintenant ?" "y")) {
  Write-Ok "Fin (install uniquement)."
  exit 0
}

# Prompts tunnel
$tunnelName   = Read-Default "Nom du tunnel (service)" "wg0"
if ($tunnelName -notmatch '^[a-zA-Z0-9._-]+$') { Die "Nom tunnel invalide (lettres/chiffres/._-)." }

$endpointHost = Read-Default "Endpoint (IP publique ou domaine du serveur)" ""
if ([string]::IsNullOrWhiteSpace($endpointHost)) { Die "Endpoint vide." }

$endpointPort = Read-Default "Port WireGuard UDP" "51820"
if ($endpointPort -notmatch '^\d+$') { Die "Port invalide." }

$serverPubKey = Read-Default "Clé publique du serveur (PublicKey)" ""
if ([string]::IsNullOrWhiteSpace($serverPubKey)) { Die "Clé publique serveur vide." }

$clientAddr   = Read-Default "Adresse client (ex: 10.8.0.2/32)" "10.8.0.2/32"
$dns          = Read-Default "DNS pour le client (ex: 1.1.1.1)" "1.1.1.1"
$allowedIPs   = Read-Default "AllowedIPs (0.0.0.0/0 = full-tunnel, ou 10.8.0.0/24 = split)" "0.0.0.0/0"
$keepalive    = Read-Default "PersistentKeepalive (sec)" "25"

Write-Info "Génération clés client…"
$kp = New-WgKeyPair -wgExe $wgExe
Write-Ok "Clé publique CLIENT (à ajouter côté serveur):"
Write-Host $kp.Public

$outDir = Join-Path $env:ProgramData "WireGuard\Tunnels"
$conf   = Join-Path $outDir ("$tunnelName.conf")

Write-Info "Écriture config client: $conf"
Write-ClientConfig -Path $conf `
  -ClientPriv $kp.Private -ClientAddress $clientAddr -Dns $dns `
  -ServerPub $serverPubKey -EndpointHost $endpointHost -EndpointPort $endpointPort `
  -AllowedIPs $allowedIPs -Keepalive $keepalive
Write-Ok "Config écrite."

Install-TunnelService -wireguardExe $wgui -confPath $conf -tunnelName $tunnelName

Write-Host ""
Write-Ok "Terminé."
Write-Info "Config client: $conf"
Write-Info "Désinstaller tunnel: `"$wgui`" /uninstalltunnelservice $tunnelName"
Write-Info "Voir état: `"$wgExe`" show $tunnelName"
Write-Info "Logs WireGuard: `"$wgui`" /dumplog"
