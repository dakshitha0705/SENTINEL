# SENTINEL setup (Windows PowerShell). Run from the repository root:  powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
# Creates .venv, installs pinned dependencies, checks Ollama + model, generates sample datasets.
param([string]$Python = "", [string]$Model = "qwen2.5:3b")
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

# Keep pip cache and temp files inside the project drive.
$env:PIP_CACHE_DIR = Join-Path (Get-Location) ".cache\pip"
$env:TEMP = Join-Path (Get-Location) ".cache\tmp"; $env:TMP = $env:TEMP
New-Item -ItemType Directory -Force $env:PIP_CACHE_DIR, $env:TEMP | Out-Null

if (-not $Python) {
  $cands = @("py -3.13", "py -3.12", "py -3.11", "python")
  foreach ($c in $cands) { try { $v = & cmd /c "$c --version" 2>$null; if ($LASTEXITCODE -eq 0) { $Python = $c; break } } catch {} }
}
Write-Host "Using Python: $Python"
if (-not (Test-Path .venv\Scripts\python.exe)) { & cmd /c "$Python -m venv .venv" }
.\.venv\Scripts\python.exe -m pip install --upgrade pip -q
if (Test-Path wheels) {
  Write-Host "Installing from local wheels/ (offline)"
  .\.venv\Scripts\python.exe -m pip install --no-index --find-links wheels -r requirements.txt -q
} else {
  .\.venv\Scripts\python.exe -m pip install -r requirements.txt -q
}

# Ollama + model check (never downloads silently).
$ollama = Get-Command ollama -ErrorAction SilentlyContinue
if (-not $ollama) { Write-Warning "Ollama not found. Install from https://ollama.com, then run: ollama pull $Model" }
else {
  $list = & ollama list 2>$null
  if ($list -match [regex]::Escape($Model)) { Write-Host "Model $Model is available locally." }
  else { Write-Warning "Model $Model not found. While online run: ollama pull $Model  (SENTINEL falls back to template explanations without it)" }
}

.\.venv\Scripts\python.exe data\generator.py
Write-Host "`nSetup complete. Start the app with: .\scripts\run.ps1   Run tests with: .\scripts\test.ps1"
