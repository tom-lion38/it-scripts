# WireGuard SERVER sur Windows — Auto-install + configuration (PowerShell)

Ce repo fournit un script PowerShell qui installe et configure **WireGuard en mode serveur** sur Windows, puis génère des **configs clients prêtes à importer**.

L’objectif : tu lances le script en admin → tu réponds à quelques prompts → tu repars avec :
- un serveur WireGuard actif (service Windows)
- un port UDP ouvert dans le firewall
- (optionnel) du NAT pour donner Internet aux clients (full-tunnel)
- des fichiers clients `.conf` générés automatiquement

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Compatibilité](#compatibilité)
- [Prérequis](#prérequis)
- [Installation rapide](#installation-rapide)
- [Ce que le script configure](#ce-que-le-script-configure)
- [Choix importants (endpoint, full/split, NAT)](#choix-importants-endpoint-fullsplit-nat)
- [Où sont les fichiers ?](#où-sont-les-fichiers-)
- [Importer un client](#importer-un-client)
- [Accès depuis Internet (port forwarding)](#accès-depuis-internet-port-forwarding)
- [Commandes utiles](#commandes-utiles)
- [Dépannage](#dépannage)
- [Sécurité / bonnes pratiques](#sécurité--bonnes-pratiques)
- [FAQ](#faq)

---

## Fonctionnalités

Le script :

- Installe WireGuard automatiquement :
  - **winget** si dispo
  - sinon téléchargement + installation silencieuse du **MSI officiel**
- Configure un tunnel serveur WireGuard (ex: `wg0`) et l’installe comme **service Windows**
- Ouvre le port WireGuard dans le **Firewall Windows** (`UDP <port>`)
- Active le routage IPv4 Windows (registry `IPEnableRouter=1`)
- (Optionnel) Configure **WinNAT** (`New-NetNat`) pour permettre un **full-tunnel** (Internet via le serveur)
- Génère un ou plusieurs clients :
  - clés client générées automatiquement
  - peer ajouté automatiquement dans la config serveur
  - fichier client `.conf` généré et sauvegardé

---

## Compatibilité

- Windows 10 / 11
- Windows Server récent (2019/2022/2025 en général OK)
- PowerShell 5.1+ (PowerShell intégré Windows)
- WinNAT : dépend de Windows/édition. Si absent, le script te le dira.

---

## Prérequis

- Lancer PowerShell en **Administrateur**
- Accès Internet (si WireGuard n’est pas déjà installé)
- Si connexion depuis l’extérieur : accès à ta box/routeur pour faire une **redirection de port UDP**

---

## Installation rapide

1) Clone / télécharge le repo
2) Ouvre PowerShell **en Administrateur**
3) Place-toi dans le dossier du script
4) Lance :

```powershell
chcp 65001 | Out-Null
Set-ExecutionPolicy Bypass -Scope Process -Force
.\wireguard-server-autosetup.ps1
