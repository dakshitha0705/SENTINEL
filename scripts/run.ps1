# Start the SENTINEL dashboard on http://127.0.0.1:8501 (local only, telemetry off).
# Optional: .\scripts\run.ps1 -Demo   opens the browser directly on the demo dataset.
param([switch]$Demo, [int]$Port = 8501)
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Test-Path .venv\Scripts\streamlit.exe)) { Write-Error "Run scripts\setup.ps1 first."; exit 1 }
try { Invoke-RestMethod http://127.0.0.1:11434/api/version -TimeoutSec 2 | Out-Null; Write-Host "Ollama: running" }
catch { Write-Warning "Ollama is not running - start it from the Start menu (explanations will use the template until then)." }
$url = "http://127.0.0.1:$Port/"
if ($Demo) { $url += "?sample=demo_unseen&corrected=1&page=0" }
Start-Job -ScriptBlock { param($u) Start-Sleep 4; Start-Process $u } -ArgumentList $url | Out-Null
.\.venv\Scripts\streamlit.exe run app.py --server.port $Port --server.address 127.0.0.1
