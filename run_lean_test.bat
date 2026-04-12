@echo off
REM Optimized pipeline: 30 logs at 5-second intervals (perfect match with 5.0s LLM interval)
REM This creates a 2.5-minute sustainable test with zero throttling

setlocal enabledelayedexpansion

cd /d %~dp0

if not exist ".venv-1\Scripts\python.exe" (
    echo ERROR: Python venv not found at .venv-1\Scripts\python.exe
    exit /b 1
)

REM Start API in background
echo [1/2] Starting API server on localhost:5000...
start "SOC API" cmd /k ".venv-1\Scripts\python.exe -B soc_api.py"

REM Wait for API to start
timeout /t 3 /nobreak

REM Generate 30 logs at 5-second intervals (2.5 minutes total)
echo [2/2] Generating 30 logs at 5-second intervals...
echo This is a 2.5-minute test. Each log gets clean LLM analysis with zero throttling.
echo.

.venv-1\Scripts\python.exe generate_jitter_stream.py --rows 30 --interval_sec 5.0 --output simulated_stream.jsonl

echo.
echo Completed! Check API window for results.
