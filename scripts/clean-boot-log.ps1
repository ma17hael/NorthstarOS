
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot

$inputPath = Join-Path $root "run\northstar-boot.log"
$outputPath = Join-Path $root "run\northstar-boot-clean.log"

if (-not (Test-Path $inputPath)) {
    throw "Fichier de journalisation introuvable : $inputPath"
}

# Lire le log brut.
$content = Get-Content -LiteralPath $inputPath -Raw

# Supprimer les sequences d'echappement ANSI.
$content = $content -replace '\x1B\[[0-?]*[ -/]*[@-~]', ''

# Conserver uniquement les diagnostics Northstar.
$marker = "[SERIAL] Northstar Boot logging initialized"

$position = $content.IndexOf($marker)

if ($position -ge 0) {
    $content = $content.Substring($position)
}

# Enregistrer une version lisible.
Set-Content `
    -LiteralPath $outputPath `
    -Value $content.TrimEnd() `
    -Encoding UTF8

Write-Host "Journal nettoye : $outputPath"
