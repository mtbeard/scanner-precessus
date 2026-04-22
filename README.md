# 🔍 Scanner d'intégrité des processus Windows

Script PowerShell d'analyse de sécurité des processus en cours d'exécution. Il calcule les hash SHA-256, vérifie les signatures Authenticode et interroge l'API VirusTotal pour attribuer un niveau de risque à chaque processus, puis génère un rapport HTML interactif et un export CSV.

---

## Fonctionnalités

- **Énumération des processus** : liste tous les processus actifs disposant d'un chemin d'exécutable accessible
- **Hash SHA-256** : calcul d'empreinte cryptographique pour chaque exécutable unique
- **Vérification de signature** : contrôle Authenticode (valid, untrusted, unsigned…)
- **Intégration VirusTotal** : interrogation de l'API v3 avec gestion de cache local (TTL 7 jours) et respect du quota (1 requête / 16 s)
- **Niveaux de risque** : classification en quatre niveaux — `critique`, `élevé`, `modéré`, `faible`
- **Rapport HTML interactif** : tableau filtrable et triable avec badges colorés et liens directs vers VirusTotal
- **Export CSV** : fichier délimité par `;` exploitable dans Excel ou tout SIEM

---

## Prérequis

- Windows 10 / 11 ou Windows Server 2016+
- PowerShell 5.1 ou PowerShell 7+
- Droits d'exécution de scripts PowerShell (`Set-ExecutionPolicy RemoteSigned` ou équivalent)
- *(Optionnel)* Clé API VirusTotal (gratuite sur [virustotal.com](https://www.virustotal.com))

---

## Installation

```powershell
# Cloner le dépôt
git clone https://github.com/mtbeard/scanner-processus.git
cd scanner-processus
```

---

## Utilisation

### Sans VirusTotal

```powershell
.\scanner-processus.ps1
```

Les colonnes VirusTotal seront indiquées comme désactivées. Le reste de l'analyse (hash + signature) fonctionne pleinement.

### Avec VirusTotal

Définis la variable d'environnement `VT_API_KEY` avant de lancer le script :

```powershell
$env:VT_API_KEY = "ta_cle_api_ici"
.\scanner-processus.ps1
```

Ou édite directement la variable `$ApiKey` en haut du fichier.

---

## Sorties

Les fichiers générés sont placés dans `%USERPROFILE%\Documents\ScannerEDR\` :

| Fichier | Description |
|---|---|
| `scan_YYYY-MM-DD_HH-mm.html` | Rapport interactif (s'ouvre automatiquement dans le navigateur) |
| `scan_YYYY-MM-DD_HH-mm.csv` | Export CSV pour traitement externe |
| `cache-vt.json` | Cache des résultats VirusTotal (évite de re-interroger les mêmes hash) |

---

## Niveaux de risque

| Niveau | Critères |
|---|---|
| 🔴 **Critique** | ≥ 3 détections malicieuses sur VirusTotal |
| 🟠 **Élevé** | ≥ 1 détection malicieuse, ≥ 2 suspects, ou hash inconnu de VT + non signé |
| 🟡 **Modéré** | ≥ 1 suspect, ou hash connu/VT absent mais non signé |
| 🟢 **Faible** | Aucune détection et signature Authenticode valide |

> ⚠️ Un niveau élevé ou critique n'implique pas forcément une menace réelle (faux positifs possibles). Vérifiez toujours manuellement avant toute action.

---

## Cache VirusTotal

Le script maintient un cache JSON local pour limiter les appels API :
- Durée de validité : **7 jours**
- Les hash en erreur (`ErreurApi`) sont réinterrogés au prochain lancement
- Le cache est mis à jour automatiquement à chaque exécution

---

## Licence

MIT — libre d'utilisation, de modification et de distribution.
