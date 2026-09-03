# Sync live api/ package from the monorepo root (keeps research project untouched).
# Run from repo root:  powershell -File api\sync_from_project.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "src\api\app.py"))) {
    $Root = $PSScriptRoot
    if (-not (Test-Path (Join-Path $Root "..\src\api\app.py"))) {
        throw "Run this script from the Prompt repo (api\sync_from_project.ps1)."
    }
    $Root = Resolve-Path (Join-Path $PSScriptRoot "..")
}
$Api = Join-Path $Root "api"

Write-Host "Syncing monorepo -> $Api"
New-Item -ItemType Directory -Force -Path $Api, "$Api\data\processed", "$Api\data\versions", "$Api\logs", "$Api\models\detector" | Out-Null

robocopy (Join-Path $Root "src") (Join-Path $Api "src") /E /XD __pycache__ .pytest_cache /NFL /NDL /NJH /NJS /nc /ns /np | Out-Null
robocopy (Join-Path $Root "configs") (Join-Path $Api "configs") /E /NFL /NDL /NJH /NJS /nc /ns /np | Out-Null
robocopy (Join-Path $Root "models\detector") (Join-Path $Api "models\detector") /E /NFL /NDL /NJH /NJS /nc /ns /np | Out-Null

Copy-Item (Join-Path $Root "requirements.txt") (Join-Path $Api "requirements.txt") -Force
Copy-Item (Join-Path $Root "main.py") (Join-Path $Api "main.py") -Force

$bank = Join-Path $Root "data\attack_bank.json"
if (Test-Path $bank) { Copy-Item $bank (Join-Path $Api "data\attack_bank.json") -Force }
foreach ($f in @("team_overrides.json", "malicious_inbox.json")) {
    $src = Join-Path $Root "data\$f"
    if (Test-Path $src) { Copy-Item $src (Join-Path $Api "data\$f") -Force }
}

$train = Join-Path $Root "data\processed\train.jsonl"
if (Test-Path $train) {
    Write-Host "Copying train.jsonl (needed for Lab retrain on live)..."
    Copy-Item $train (Join-Path $Api "data\processed\train.jsonl") -Force
}

Write-Host "Done. Deploy from: $Api"
Write-Host "  cd api; copy .env.example .env; python -m venv .venv; .\.venv\Scripts\pip install -r requirements.txt; python run_api.py"
