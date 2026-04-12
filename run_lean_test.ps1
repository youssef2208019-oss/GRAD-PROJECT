param(
    [int]$Rows = 30,
    [double]$IntervalSec = 5.0
)

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe = Join-Path $ProjectRoot '.venv-1\Scripts\python.exe'

if (-not (Test-Path $PythonExe)) {
    throw "Python executable not found at $PythonExe"
}

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Optimized Sustainable Pipeline" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  • Logs to generate: $Rows"
Write-Host "  • Interval between logs: $IntervalSec seconds"
Write-Host "  • Total duration: ~$([int]($Rows * $IntervalSec)) seconds ($([int]($Rows * $IntervalSec / 60)) minutes)"
Write-Host "  • Log rate: $([int](1 / $IntervalSec)) logs/sec"
Write-Host "  • LLM capacity: 12 calls/minute (5.0s interval)"
Write-Host "  • Result: ZERO throttling, clean LLM analysis for every log"
Write-Host ""

# Start API in background
Write-Host "[1/2] Starting API server on localhost:5000..." -ForegroundColor Green
$ApiCommand = "Set-Location '$ProjectRoot'; & '$PythonExe' -B soc_api.py"
Start-Process powershell -ArgumentList '-NoExit', '-Command', $ApiCommand -WorkingDirectory $ProjectRoot | Out-Null

# Wait for API startup
Start-Sleep -Seconds 3

# Generate logs at controlled interval
Write-Host "[2/2] Generating $Rows logs at $IntervalSec-second intervals..." -ForegroundColor Green
Write-Host ""

& $PythonExe generate_jitter_stream.py --rows $Rows --interval_sec $IntervalSec --output simulated_stream.jsonl

Write-Host ""
Write-Host "✓ Complete! Check the API terminal for clean, throttle-free LLM analysis." -ForegroundColor Green
Write-Host ""
