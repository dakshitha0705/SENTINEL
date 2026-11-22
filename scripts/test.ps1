# Run the automated test suite and the held-out evaluation.
#   .\scripts\test.ps1            tests + evaluation (deterministic, no SLM needed)
#   .\scripts\test.ps1 -Slm       also benchmark the local SLM's verification rate on the test seeds
param([switch]$Slm)
Set-Location (Split-Path $PSScriptRoot -Parent)
.\.venv\Scripts\python.exe -m pytest -q
if ($LASTEXITCODE -ne 0) { Write-Warning "Some tests failed." }
.\.venv\Scripts\python.exe scripts\evaluate.py
if ($Slm) { foreach ($s in "test_seed101", "test_seed202", "test_seed303") { .\.venv\Scripts\python.exe scripts\slm_benchmark.py --dataset $s } }
