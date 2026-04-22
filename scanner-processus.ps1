$ApiKey = $env:VT_API_KEY
if (-not $ApiKey) {
    $ApiKey = ""
}

$DossierSortie = "$env:USERPROFILE\Documents\ScannerEDR"
if (-not (Test-Path $DossierSortie)) {
    New-Item -ItemType Directory -Path $DossierSortie -Force | Out-Null
}

$FichierCache = Join-Path $DossierSortie "cache-vt.json"
$Date = Get-Date
$Horodatage = $Date.ToString("yyyy-MM-dd_HH-mm")
$FichierCsv  = Join-Path $DossierSortie "scan_$Horodatage.csv"
$FichierHtml = Join-Path $DossierSortie "scan_$Horodatage.html"
$DateAffichee = $Date.ToString("dd/MM/yyyy HH:mm")

$DelaiEntreRequetes = 16
$AgeMaxCacheJours   = 7

$cache = @{}
if (Test-Path $FichierCache) {
    try {
        $data = Get-Content $FichierCache -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($p in $data.PSObject.Properties) {
            $cache[$p.Name] = $p.Value
        }
    } catch {
        $cache = @{}
    }
}

Write-Host "Enumeration des processus..." -ForegroundColor Cyan
$processus = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path }
Write-Host "  $($processus.Count) processus avec chemin accessible." -ForegroundColor Gray

$cheminsUniques = $processus | Select-Object -ExpandProperty Path -Unique
Write-Host "  $($cheminsUniques.Count) executables uniques a analyser." -ForegroundColor Gray

Write-Host "Calcul des hash et verification des signatures..." -ForegroundColor Cyan
$infosFichiers = @{}
$i = 0
foreach ($chemin in $cheminsUniques) {
    if (-not $chemin) { continue }
    $i++
    Write-Progress -Activity "Analyse fichiers" -Status "$i / $($cheminsUniques.Count)" -PercentComplete (($i / $cheminsUniques.Count) * 100)

    $hash = ""
    $sigStatut = "Inconnu"
    $signataire = ""

    try {
        $hash = (Get-FileHash -Path $chemin -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        $hash = "ERREUR"
    }

    try {
        $sig = Get-AuthenticodeSignature -FilePath $chemin -ErrorAction Stop
        $sigStatut = $sig.Status.ToString()
        if ($sig.SignerCertificate) {
            $subject = $sig.SignerCertificate.Subject
            if ($subject -match 'CN=([^,]+)') {
                $signataire = $Matches[1].Trim('"')
            } else {
                $signataire = $subject
            }
        }
    } catch {}

    $infosFichiers[$chemin] = @{
        Hash       = $hash
        SigStatut  = $sigStatut
        Signataire = $signataire
    }
}
Write-Progress -Activity "Analyse fichiers" -Completed

$hashesAInterroger = @()
foreach ($info in $infosFichiers.Values) {
    if ($info.Hash -eq "ERREUR") { continue }
    if ($cache.ContainsKey($info.Hash)) {
        $entree = $cache[$info.Hash]
        $ageJours = if ($entree.DateInterrogation) {
            ((Get-Date) - [datetime]$entree.DateInterrogation).TotalDays
        } else { 999 }
        if ($ageJours -lt $AgeMaxCacheJours -and $entree.Statut -ne "ErreurApi") { continue }
    }
    if ($info.Hash -notin $hashesAInterroger) {
        $hashesAInterroger += $info.Hash
    }
}

if (-not $ApiKey) {
    Write-Host "Pas de cle API VirusTotal configuree, etape VT ignoree." -ForegroundColor Yellow
    Write-Host "  Pour activer : definis la variable d'environnement VT_API_KEY" -ForegroundColor Yellow
    Write-Host "  ou edite la variable \$ApiKey en haut du script." -ForegroundColor Yellow
} elseif ($hashesAInterroger.Count -eq 0) {
    Write-Host "Tous les hash sont deja en cache, VirusTotal saute." -ForegroundColor Green
} else {
    $tempsEstime = [math]::Ceiling(($hashesAInterroger.Count * $DelaiEntreRequetes) / 60)
    Write-Host "Interrogation VirusTotal : $($hashesAInterroger.Count) hash(es) a verifier (~$tempsEstime min)" -ForegroundColor Cyan

    $j = 0
    foreach ($h in $hashesAInterroger) {
        $j++
        Write-Progress -Activity "VirusTotal" -Status "$j / $($hashesAInterroger.Count)" -PercentComplete (($j / $hashesAInterroger.Count) * 100)

        try {
            $resp = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$h" `
                -Headers @{ "x-apikey" = $ApiKey } `
                -Method Get -ErrorAction Stop

            $stats = $resp.data.attributes.last_analysis_stats
            $cache[$h] = [PSCustomObject]@{
                Statut            = "Connu"
                Malicieux         = [int]$stats.malicious
                Suspect           = [int]$stats.suspicious
                Sain              = [int]$stats.harmless
                NonDetecte        = [int]$stats.undetected
                TotalMoteurs      = [int]$stats.malicious + [int]$stats.suspicious + [int]$stats.harmless + [int]$stats.undetected
                NomAffiche        = $resp.data.attributes.meaningful_name
                DateInterrogation = (Get-Date).ToString("o")
            }
        } catch {
            $code = 0
            try { $code = [int]$_.Exception.Response.StatusCode } catch {}
            if ($code -eq 404) {
                $cache[$h] = [PSCustomObject]@{
                    Statut            = "Inconnu"
                    DateInterrogation = (Get-Date).ToString("o")
                }
            } elseif ($code -eq 429) {
                Write-Host "    Quota VirusTotal atteint, arret de l'interrogation." -ForegroundColor Yellow
                break
            } else {
                $cache[$h] = [PSCustomObject]@{
                    Statut            = "ErreurApi"
                    DateInterrogation = (Get-Date).ToString("o")
                }
            }
        }

        if ($j -lt $hashesAInterroger.Count) {
            Start-Sleep -Seconds $DelaiEntreRequetes
        }
    }
    Write-Progress -Activity "VirusTotal" -Completed
}

$cacheExport = @{}
foreach ($k in $cache.Keys) { $cacheExport[$k] = $cache[$k] }
$cacheExport | ConvertTo-Json -Depth 5 | Out-File -FilePath $FichierCache -Encoding UTF8

function Get-NiveauRisque {
    param($InfoFichier, $InfoVt)
    $sig = $InfoFichier.SigStatut
    $signe = ($sig -eq "Valid")

    if ($InfoVt) {
        if ($InfoVt.Statut -eq "Connu") {
            if ($InfoVt.Malicieux -ge 3) { return "critique" }
            if ($InfoVt.Malicieux -ge 1 -or $InfoVt.Suspect -ge 2) { return "eleve" }
            if ($InfoVt.Suspect -ge 1) { return "modere" }
            if ($signe) { return "faible" }
            return "modere"
        }
        if ($InfoVt.Statut -eq "Inconnu") {
            if ($signe) { return "faible" }
            return "eleve"
        }
    }

    if ($signe) { return "faible" }
    return "modere"
}

Write-Host "Construction du rapport..." -ForegroundColor Cyan

$lignes = @()
foreach ($p in $processus) {
    if (-not $p.Path) { continue }
    if (-not $infosFichiers.ContainsKey($p.Path)) { continue }
    $info = $infosFichiers[$p.Path]
    if (-not $info) { continue }
    $vt = $null
    if ($info.Hash -and $cache.ContainsKey($info.Hash)) {
        $vt = $cache[$info.Hash]
    }

    $niveau = Get-NiveauRisque -InfoFichier $info -InfoVt $vt

    $detections = ""
    $nbMoteurs  = ""
    if ($vt -and $vt.Statut -eq "Connu") {
        $detections = "$($vt.Malicieux + $vt.Suspect) / $($vt.TotalMoteurs)"
        $nbMoteurs  = [int]$vt.Malicieux + [int]$vt.Suspect
    } elseif ($vt -and $vt.Statut -eq "Inconnu") {
        $detections = "Inconnu VT"
    } elseif ($ApiKey) {
        $detections = "Non interroge"
    } else {
        $detections = "-"
    }

    $lignes += [PSCustomObject]@{
        PID         = $p.Id
        Nom         = $p.ProcessName
        Chemin      = $p.Path
        Hash        = $info.Hash
        Signature   = $info.SigStatut
        Signataire  = $info.Signataire
        VtResultat  = $detections
        NbDetec     = $nbMoteurs
        Niveau      = $niveau
    }
}

$lignes = $lignes | Sort-Object @{Expression={
    switch ($_.Niveau) { "critique" {0} "eleve" {1} "modere" {2} "faible" {3} default {4} }
}}, Nom

Write-Host "Export CSV..." -ForegroundColor Cyan
$lignes | Select-Object PID, Nom, Niveau, VtResultat, Signature, Signataire, Hash, Chemin |
    Export-Csv -Path $FichierCsv -Delimiter ';' -Encoding UTF8 -NoTypeInformation

Write-Host "Generation HTML..." -ForegroundColor Cyan

$stats = @{
    Total     = $lignes.Count
    Critique  = ($lignes | Where-Object { $_.Niveau -eq "critique" }).Count
    Eleve     = ($lignes | Where-Object { $_.Niveau -eq "eleve" }).Count
    Modere    = ($lignes | Where-Object { $_.Niveau -eq "modere" }).Count
    Faible    = ($lignes | Where-Object { $_.Niveau -eq "faible" }).Count
}

$lignesHtml = ""
foreach ($l in $lignes) {
    $nom        = ($l.Nom        -replace '<','&lt;' -replace '>','&gt;')
    $chemin     = ($l.Chemin     -replace '<','&lt;' -replace '>','&gt;')
    $signataire = ($l.Signataire -replace '<','&lt;' -replace '>','&gt;')
    $hash       = $l.Hash
    $sig        = $l.Signature
    $vtTxt      = $l.VtResultat
    $lienVt = if ($hash -and $hash -ne "ERREUR") {
        "<a href='https://www.virustotal.com/gui/file/$hash' target='_blank'>$vtTxt</a>"
    } else { $vtTxt }

    $lignesHtml += "<tr class='row-$($l.Niveau)' data-niveau='$($l.Niveau)'>"
    $lignesHtml += "<td><span class='badge badge-$($l.Niveau)'>$($l.Niveau)</span></td>"
    $lignesHtml += "<td class='num'>$($l.PID)</td>"
    $lignesHtml += "<td><strong>$nom</strong></td>"
    $lignesHtml += "<td>$sig</td>"
    $lignesHtml += "<td>$signataire</td>"
    $lignesHtml += "<td class='num'>$lienVt</td>"
    $lignesHtml += "<td class='mono small'>$chemin</td>"
    $lignesHtml += "<td class='mono small'>$hash</td>"
    $lignesHtml += "</tr>`n"
}

$pcNom = $env:COMPUTERNAME
$utilisateur = $env:USERNAME
$noteVt = if ($ApiKey) { "VirusTotal interroge" } else { "VirusTotal desactive (pas de cle API)" }

$html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Scanner processus - $pcNom</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f4f6f8; color: #222; margin: 0; padding: 32px; }
  .wrap { max-width: 1500px; margin: 0 auto; }
  header { background: linear-gradient(135deg, #1e293b, #334155); color: white; padding: 32px; border-radius: 16px; margin-bottom: 24px; box-shadow: 0 4px 20px rgba(30,41,59,0.3); }
  header h1 { margin: 0 0 8px 0; font-size: 28px; }
  header .meta { opacity: 0.85; font-size: 14px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .stat { background: white; border-radius: 12px; padding: 18px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); border-left: 4px solid #cbd5e1; }
  .stat.s-critique { border-left-color: #dc2626; }
  .stat.s-eleve    { border-left-color: #ea580c; }
  .stat.s-modere   { border-left-color: #d97706; }
  .stat.s-faible   { border-left-color: #16a34a; }
  .stat-label { font-size: 11px; text-transform: uppercase; color: #6b7280; letter-spacing: 0.5px; }
  .stat-value { font-size: 28px; font-weight: 700; margin-top: 4px; color: #111; }
  .toolbar { background: white; padding: 16px; border-radius: 12px; margin-bottom: 16px; display: flex; gap: 12px; align-items: center; box-shadow: 0 2px 8px rgba(0,0,0,0.05); flex-wrap: wrap; }
  .toolbar input { flex: 1; min-width: 240px; padding: 10px 14px; border: 1px solid #d1d5db; border-radius: 8px; font-size: 14px; }
  .toolbar select { padding: 10px 14px; border: 1px solid #d1d5db; border-radius: 8px; font-size: 14px; background: white; }
  .count { color: #6b7280; font-size: 13px; }
  .table-wrap { background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
  table { width: 100%; border-collapse: collapse; }
  th { background: #f3f4f6; padding: 12px 14px; text-align: left; font-size: 13px; color: #374151; border-bottom: 1px solid #e5e7eb; cursor: pointer; user-select: none; position: sticky; top: 0; }
  th:hover { background: #e5e7eb; }
  td { padding: 10px 14px; border-bottom: 1px solid #f3f4f6; font-size: 14px; vertical-align: top; }
  tr:hover td { background: #fafbfc; }
  tr.row-critique td { background: #fef2f2; }
  tr.row-eleve    td { background: #fff7ed; }
  .mono { font-family: 'Consolas', 'Courier New', monospace; color: #555; font-size: 12px; word-break: break-all; }
  .small { font-size: 12px; }
  .num { white-space: nowrap; font-variant-numeric: tabular-nums; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.3px; }
  .badge-critique { background: #fecaca; color: #991b1b; }
  .badge-eleve    { background: #fed7aa; color: #9a3412; }
  .badge-modere   { background: #fde68a; color: #92400e; }
  .badge-faible   { background: #bbf7d0; color: #166534; }
  a { color: #2563eb; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .note { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; font-size: 13px; color: #78350f; }
  footer { text-align: center; padding: 24px; color: #9ca3af; font-size: 12px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Scanner d'integrite des processus</h1>
    <div class="meta">$pcNom - $utilisateur - $DateAffichee - $noteVt</div>
  </header>

  <div class="note">
    Ce rapport est <strong>informatif</strong>. Un niveau eleve ou critique ne signifie pas forcement une menace reelle (faux positifs possibles). Verifie toujours manuellement avant toute action (Stop-Process, desinstallation, etc.).
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-label">Total</div><div class="stat-value">$($stats.Total)</div></div>
    <div class="stat s-critique"><div class="stat-label">Critique</div><div class="stat-value">$($stats.Critique)</div></div>
    <div class="stat s-eleve"><div class="stat-label">Eleve</div><div class="stat-value">$($stats.Eleve)</div></div>
    <div class="stat s-modere"><div class="stat-label">Modere</div><div class="stat-value">$($stats.Modere)</div></div>
    <div class="stat s-faible"><div class="stat-label">Faible</div><div class="stat-value">$($stats.Faible)</div></div>
  </div>

  <div class="toolbar">
    <input type="text" id="filtre" placeholder="Rechercher : nom, chemin, signataire, hash...">
    <select id="niveauFiltre">
      <option value="">Tous les niveaux</option>
      <option value="critique">Critique</option>
      <option value="eleve">Eleve</option>
      <option value="modere">Modere</option>
      <option value="faible">Faible</option>
    </select>
    <div class="count" id="compteur"></div>
  </div>

  <div class="table-wrap">
    <table id="tbl">
      <thead>
        <tr>
          <th data-col="0">Risque</th>
          <th data-col="1">PID</th>
          <th data-col="2">Processus</th>
          <th data-col="3">Signature</th>
          <th data-col="4">Signataire</th>
          <th data-col="5">VirusTotal</th>
          <th data-col="6">Chemin</th>
          <th data-col="7">SHA-256</th>
        </tr>
      </thead>
      <tbody>
$lignesHtml
      </tbody>
    </table>
  </div>

  <footer>Scan genere - $DateAffichee - CSV : $FichierCsv</footer>
</div>

<script>
  const input = document.getElementById('filtre');
  const niveauSel = document.getElementById('niveauFiltre');
  const compteur = document.getElementById('compteur');
  const lignes = Array.from(document.querySelectorAll('#tbl tbody tr'));

  function filtrer() {
    const q = input.value.toLowerCase();
    const n = niveauSel.value;
    let visibles = 0;
    for (const tr of lignes) {
      const txt = tr.innerText.toLowerCase();
      const niv = tr.dataset.niveau;
      const ok = (q === '' || txt.includes(q)) && (n === '' || niv === n);
      tr.style.display = ok ? '' : 'none';
      if (ok) visibles++;
    }
    compteur.textContent = visibles + ' / ' + lignes.length + ' processus affiches';
  }
  input.addEventListener('input', filtrer);
  niveauSel.addEventListener('change', filtrer);
  filtrer();

  document.querySelectorAll('th').forEach(th => {
    let asc = true;
    th.addEventListener('click', () => {
      const col = parseInt(th.dataset.col);
      const tbody = document.querySelector('#tbl tbody');
      const rows = Array.from(tbody.querySelectorAll('tr'));
      rows.sort((a, b) => {
        const av = a.children[col].innerText.trim().toLowerCase();
        const bv = b.children[col].innerText.trim().toLowerCase();
        const an = parseFloat(av);
        const bn = parseFloat(bv);
        if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
      });
      asc = !asc;
      rows.forEach(r => tbody.appendChild(r));
    });
  });
</script>
</body>
</html>
"@

$html | Out-File -FilePath $FichierHtml -Encoding UTF8

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "   Scan termine" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "   $($stats.Total) processus analyses" -ForegroundColor White
Write-Host "   Critique : $($stats.Critique)  |  Eleve : $($stats.Eleve)  |  Modere : $($stats.Modere)  |  Faible : $($stats.Faible)" -ForegroundColor White
Write-Host ""
Write-Host "   CSV  : $FichierCsv" -ForegroundColor Yellow
Write-Host "   HTML : $FichierHtml" -ForegroundColor Yellow
Write-Host ""

Start-Process $FichierHtml
