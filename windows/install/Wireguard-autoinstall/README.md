# WireGuard (Windows) — Auto-install + tunnel service (PowerShell)

Ce projet fournit un script PowerShell qui :
1) installe **WireGuard for Windows** automatiquement (silencieux)
2) (optionnel) crée une **configuration client** et l’installe en **tunnel service** Windows (démarrage auto, pas besoin d’UI)

Objectif : tu exécutes en admin, tu réponds aux prompts, et tu repars avec un tunnel WireGuard opérationnel.

---

## Prérequis

- Windows 10/11 ou Windows Server récent
- PowerShell
- Droits administrateur (obligatoire pour installer et créer le service)
- Une config côté serveur déjà prête (au minimum la **clé publique du serveur** et l’endpoint)

---

## Fichiers

- `wireguard-autoinstall.ps1` : le script PowerShell

---

## Installation / Exécution

1) Ouvre **PowerShell en Administrateur**
2) Dans le dossier du script :

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\wireguard-autoinstall.ps1
