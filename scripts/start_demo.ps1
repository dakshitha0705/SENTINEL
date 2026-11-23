# Start the SENTINEL live demo: NEXUS (127.0.0.1:8502) + SENTINEL (127.0.0.1:8501). Works offline.
#   powershell -ExecutionPolicy Bypass -File scripts\start_demo.ps1
# Processes started here are recorded in demo_data\pids.json; scripts\stop_demo.ps1 stops only those.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Py = Join-Path $Root ".venv\Scripts\python.exe"
$St = Join-Path $Root ".venv\Scripts\streamlit.exe"
$DemoDir = Join-Path $Root "demo_data"
$PidFile = Join-Path $DemoDir "pids.json"
$LogDir = Join-Path $DemoDir "logs"
New-Item -ItemType Directory -Force $LogDir | Out-Null

function Test-Url($url) {
    try { $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 $url; return $r.StatusCode -eq 200 } catch { return $false }
}

Write-Host "1/6 Virtual environment" -ForegroundColor DarkYellow
if (-not (Test-Path $Py)) { throw "Missing .venv - run scripts\setup.ps1 first." }
& $Py -c "import flask, streamlit, pandas, evtx" 2>$null
if ($LASTEXITCODE -ne 0) { throw "Missing Python packages - run scripts\setup.ps1 (uses wheels\ offline)." }
Write-Host "    ok"

Write-Host "2/6 Local model server (Ollama)" -ForegroundColor DarkYellow
if (Test-Url "http://127.0.0.1:11434/api/version") { Write-Host "    Ollama reachable on 127.0.0.1:11434" }
else { Write-Host "    Ollama not reachable: detection still works; explanations fall back to the deterministic template." -ForegroundColor Yellow }

$pids = @{}
if (Test-Path $PidFile) { $pids = @{}; (Get-Content $PidFile -Raw | ConvertFrom-Json).psobject.Properties | ForEach-Object { $pids[$_.Name] = $_.Value } }

function Running($name) {
    if (-not $pids.ContainsKey($name)) { return $false }
    return $null -ne (Get-Process -Id $pids[$name] -ErrorAction SilentlyContinue)
}

Write-Host "3/6 NEXUS demo portal" -ForegroundColor DarkYellow
if ((Running "nexus") -or (Test-Url "http://127.0.0.1:8502/api/health")) { Write-Host "    already running" }
else {
    $p = Start-Process -FilePath $Py -ArgumentList "-m", "demo_target.app" -WorkingDirectory $Root -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $LogDir "nexus.out.log") -RedirectStandardError (Join-Path $LogDir "nexus.err.log")
    $pids["nexus"] = $p.Id
    $pids | ConvertTo-Json | Out-File -Encoding utf8 $PidFile
    Write-Host "    started (PID $($p.Id))"
}

Write-Host "    live detection worker (python -m sentinel.live)"
$hb = Join-Path $DemoDir "live_worker.json"
$fresh = $false
if (Test-Path $hb) {
    try {
        $h = Get-Content $hb -Raw | ConvertFrom-Json
        $fresh = (((Get-Date) - (Get-Item $hb).LastWriteTime).TotalSeconds -lt 5) -and ($null -ne (Get-Process -Id $h.pid -ErrorAction SilentlyContinue))
    } catch {}
}
if ((Running "live_worker") -or $fresh) { Write-Host "    already running" }
else {
    $p = Start-Process -FilePath $Py -ArgumentList "-m", "sentinel.live" -WorkingDirectory $Root -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $LogDir "live.out.log") -RedirectStandardError (Join-Path $LogDir "live.err.log")
    $pids["live_worker"] = $p.Id
    $pids | ConvertTo-Json | Out-File -Encoding utf8 $PidFile
    Write-Host "    started (PID $($p.Id))"
}

Write-Host "4/6 SENTINEL dashboard" -ForegroundColor DarkYellow
if ((Running "sentinel") -or (Test-Url "http://127.0.0.1:8501/_stcore/health")) { Write-Host "    already running" }
else {
    $p = Start-Process -FilePath $St -ArgumentList "run", "app.py", "--server.port", "8501" -WorkingDirectory $Root -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $LogDir "sentinel.out.log") -RedirectStandardError (Join-Path $LogDir "sentinel.err.log")
    $pids["sentinel"] = $p.Id
    Write-Host "    started (PID $($p.Id))"
}
$pids | ConvertTo-Json | Out-File -Encoding utf8 $PidFile

Write-Host "5/6 Health checks" -ForegroundColor DarkYellow
$ok1 = $false; $ok2 = $false
for ($i = 0; $i -lt 40 -and -not ($ok1 -and $ok2); $i++) {
    Start-Sleep -Milliseconds 750
    if (-not $ok1) { $ok1 = Test-Url "http://127.0.0.1:8502/api/health" }
    if (-not $ok2) { $ok2 = Test-Url "http://127.0.0.1:8501/_stcore/health" }
}
Write-Host ("    NEXUS    " + ($(if ($ok1) { "healthy" } else { "NOT responding - see demo_data\logs\nexus.err.log" })))
Write-Host ("    SENTINEL " + ($(if ($ok2) { "healthy" } else { "NOT responding - see demo_data\logs\sentinel.err.log" })))

Write-Host "6/6 Event pipeline" -ForegroundColor DarkYellow
if ($ok1) {
    try { $s = Invoke-RestMethod -TimeoutSec 5 "http://127.0.0.1:8502/api/demo/status"; Write-Host "    demo session $($s.session), $($s.events_emitted) events so far" } catch {}
    # warm the live engine (it starts inside the SENTINEL server on the first live page view)
    if ($ok2) { try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 "http://127.0.0.1:8501/?live=1" | Out-Null } catch {} }
}
Write-Host ""
Write-Host "SENTINEL (live monitoring):  http://127.0.0.1:8501/?live=1" -ForegroundColor Green
Write-Host "NEXUS portal:                http://127.0.0.1:8502/login" -ForegroundColor Green
Write-Host "NEXUS scenario controller:   http://127.0.0.1:8502/demo" -ForegroundColor Green
Write-Host "Stop with: powershell -ExecutionPolicy Bypass -File scripts\stop_demo.ps1"
