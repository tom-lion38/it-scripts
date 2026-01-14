# wireguard-autoinstall.ps1 (v3 - fix Count/StrictMode)
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
  if ($p.ExitCode -eq 0) { Write-Ok "WireGuard installé (winget)."; return $true }
  Write-Warn "winget a échoué (code $($p.ExitCode)). Fallback MSI…"
  return $false
}

function Install-WireGuard-WithMSI {
  $arch = Get-ArchTag
  $base = "https://download.wireguard.com/windows-client/"
  Write-Info "Récupération de la liste officielle des MSIs…"
  $html = (Invoke-WebRequest -Uri $base -UseBasicParsing).Content

  $regex = "wireguard-$arch-([0-9]+\.[0-9]+\.[0-9]+)\.msi"
  $matches = [regex]::Matches($html, $regex)
  if ($matches.Count -lt 1) { Die "Impossible de trouver un MSI WireGuard pour arch=$arch sur $base" }

  $ver = $matches[$matches.Count - 1].Groups[1].Value
  $msiName = "wireguard-$arch-$ver.msi"
  $msiUrl  = $base + $msiName
  $msiPath = Join-Path $env:TEMP $msiName

  Write-Info "Téléchargement MSI: $msiName"
  Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
  if (-not (Test-Path $msiPath)) { Die "Téléchargement échoué: $msiPath" }
  Write-Ok "MSI téléchargé: $msiPath"

  Write-Info "Installation silencieuse (msiexec)…"
  $args = "/i `"$msiPath`" /qn DO_NOT_LAUNCH=1"
  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
  if ($p.ExitCode -ne 0) { Die "msiexec a échoué (code $($p.ExitCode))." }
  Write-Ok "WireGuard installé (MSI)."
  return $true
}

function Get-WireGuardPaths {
  $wgExe = Join-Path $env:ProgramFiles "WireGuard\wg.exe"
  $wgui  = Join-Path $env:ProgramFiles "WireGuard\wireguard.exe"
  if (-not (Test-Path $wgExe)) { Die "wg.exe introuvable: $wgExe" }
  if (-not (Test-Path $wgui))  { Die "wireguard.exe introuvable: $wgui" }
  return @{ wg = $wgExe; wireguard = $wgui }
}

function New-WgKeyPair([string]$wgExe) {
  $priv = (& $wgExe genkey).Trim()
  if ([string]::IsNullOrWhiteSpace($priv)) { Die "Échec génération clé privée." }
  $pub  = ($priv | & $wgExe pubkey).Trim()
  if ([string]::IsNullOrWhiteSpace($pub)) { Die "Échec génération clé publique." }
  return @{ Private = $priv; Public = $pub }
}

function Select-FromList([string]$Title, [string[]]$Items) {
  $arr = @($Items) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
  if ($arr.Length -eq 0) { return $null }

  Write-Host ""
  Write-Host $Title -ForegroundColor Cyan
  for ($i=0; $i -lt $arr.Length; $i++) { Write-Host ("  {0}) {1}" -f ($i+1), $arr[$i]) }

  while ($true) {
    $raw = Read-Host "Choix (1-$($arr.Length)) ou vide pour annuler"
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    if ($raw -match '^\d+$') {
      $n = [int]$raw
      if ($n -ge 1 -and $n -le $arr.Length) { return $arr[$n-1] }
    }
    Write-Host "Choix invalide."
  }
}

function Get-LocalWgInterfaces([string]$wgExe) {
  try {
    $out = (& $wgExe show interfaces 2>$null)
    if ([string]::IsNullOrWhiteSpace($out)) { return @() }
    # Force array
    return @($out -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  } catch {
    return @()
  }
}

function Try-GetServerPubKeyAuto([string]$wgExe) {
  # 1) Interface WireGuard locale -> public key
  $ifaces = @(Get-LocalWgInterfaces -wgExe $wgExe)
  if ($ifaces.Length -gt 0) {
    $picked = Select-FromList -Title "Interfaces WireGuard locales détectées (clé publique récupérable automatiquement)" -Items $ifaces
    if ($picked) {
      try {
        $pk = (& $wgExe show $picked public-key 2>$null).Trim()
        if (-not [string]::IsNullOrWhiteSpace($pk)) {
          Write-Ok "Clé publique récupérée depuis l'interface locale: $picked"
          return $pk
        }
      } catch { }
    }
  }

  # 2) URL texte brut
  $url = Read-Default "URL (optionnelle) clé publique serveur (texte brut) - vide pour passer" ""
  if (-not [string]::IsNullOrWhiteSpace($url)) {
    try {
      $pk = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content.Trim()
      if (-not [string]::IsNullOrWhiteSpace($pk)) { Write-Ok "Clé publique récupérée via URL."; return $pk }
    } catch { Write-Warn "URL KO: $($_.Exception.Message)" }
  }

  # 3) fichier local
  $path = Read-Default "Fichier (optionnel) contenant la clé publique serveur - vide pour passer" ""
  if (-not [string]::IsNullOrWhiteSpace($path)) {
    if (Test-Path $path) {
      $pk = (Get-Content -Path $path -Raw).Trim()
      if (-not [string]::IsNullOrWhiteSpace($pk)) { Write-Ok "Clé publique récupérée via fichier."; return $pk }
    } else { Write-Warn "Fichier introuvable: $path" }
  }

  return $null
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
  try { Start-Service -Name $svc -ErrorAction SilentlyContinue } catch { }
  Write-Ok "Tunnel installé. Service: $svc"
}

# MAIN
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

$tunnelName   = Read-Default "Nom du tunnel (service)" "wg0"
if ($tunnelName -notmatch '^[a-zA-Z0-9._-]+$') { Die "Nom tunnel invalide (lettres/chiffres/._-)." }

$endpointHost = Read-Default "Endpoint (IP publique ou domaine du serveur)" ""
if ([string]::IsNullOrWhiteSpace($endpointHost)) { Die "Endpoint vide." }

$endpointPort = Read-Default "Port WireGuard UDP" "51820"
if ($endpointPort -notmatch '^\d+$') { Die "Port invalide." }

Write-Info "Récupération de la clé publique serveur (auto si possible)…"
$serverPubKey = Try-GetServerPubKeyAuto -wgExe $wgExe
if ([string]::IsNullOrWhiteSpace($serverPubKey)) {
  $serverPubKey = Read-Default "Clé publique du serveur (PublicKey) à coller (fallback manuel)" ""
}
if ([string]::IsNullOrWhiteSpace($serverPubKey)) { Die "Clé publique serveur absente." }

$clientAddr   = Read-Default "Adresse client (ex: 10.8.0.2/32)" "10.8.0.2/32"
$dns          = Read-Default "DNS pour le client (ex: 1.1.1.1)" "1.1.1.1"
$allowedIPs   = Read-Default "AllowedIPs (0.0.0.0/0=full, ou 10.8.0.0/24=split)" "0.0.0.0/0"
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
