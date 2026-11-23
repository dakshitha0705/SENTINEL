# Stop ONLY the processes started by scripts\start_demo.ps1 (recorded in demo_data\pids.json).
# Unrelated Python / Streamlit processes are never touched. Demo data on disk is kept.
$Root = Split-Path -Parent $PSScriptRoot
$PidFile = Join-Path $Root "demo_data\pids.json"
if (-not (Test-Path $PidFile)) { Write-Host "No demo processes recorded."; exit 0 }
$pids = Get-Content $PidFile -Raw | ConvertFrom-Json
foreach ($prop in $pids.psobject.Properties) {
    $p = Get-Process -Id $prop.Value -ErrorAction SilentlyContinue
    if ($p) {
        # /T stops the recorded process and its own child processes only
        & taskkill.exe /PID $prop.Value /T /F | Out-Null
        Write-Host "stopped $($prop.Name) (PID $($prop.Value))"
    } else {
        Write-Host "$($prop.Name) (PID $($prop.Value)) was not running"
    }
}
Remove-Item $PidFile -Confirm:$false
