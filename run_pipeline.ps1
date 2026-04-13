param(
    [int]$Rows = 30,
    [double]$IntervalSec = 5.0,
    [string]$LogstashHome = "",
    [switch]$NoForever,
    [int]$WarmupSec = 15,
    [switch]$KeepExistingStream
)

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe = Join-Path $ProjectRoot '.venv-1\Scripts\python.exe'

$k = [Environment]::GetEnvironmentVariable("GROQ_API_KEY", "Process")
if (-not $k) { $k = [Environment]::GetEnvironmentVariable("GROQ_API_KEY", "User") }
if (-not $k) { $k = [Environment]::GetEnvironmentVariable("GROQ_API_KEY", "Machine") }
if ($k) { $env:GROQ_API_KEY = $k }

if (-not $LogstashHome) {
    if ($env:LOGSTASH_HOME) {
        $LogstashHome = $env:LOGSTASH_HOME
    } elseif (Test-Path 'D:\Logstash\logstash-9.3.3') {
        $LogstashHome = 'D:\Logstash\logstash-9.3.3'
    }
}

if (-not (Test-Path $PythonExe)) {
    throw "Python executable not found at $PythonExe"
}

$ApiCommand = "Set-Location '$ProjectRoot'; & '$PythonExe' soc_api.py"
$GeneratorArgs = "--rows $Rows --interval_sec $IntervalSec"
if (-not $NoForever) {
    $GeneratorArgs = "$GeneratorArgs --forever"
}
$GeneratorCommand = "Set-Location '$ProjectRoot'; & '$PythonExe' generate_jitter_stream.py $GeneratorArgs"

$StreamPath = Join-Path $ProjectRoot 'simulated_stream.jsonl'
if (-not $KeepExistingStream) {
    # Start from an empty stream file so Logstash does not ingest historical backlog on boot.
    # Set-Content -Path $StreamPath -Value '' -Encoding utf8
}

Start-Process powershell -ArgumentList '-NoExit', '-Command', $ApiCommand -WorkingDirectory $ProjectRoot | Out-Null

if ($LogstashHome) {
    $LogstashBat = Join-Path $LogstashHome 'bin\logstash.bat'
    if (-not (Test-Path $LogstashBat)) {
        throw "LOGSTASH_HOME is set, but logstash.bat was not found at $LogstashBat"
    }

    $LogstashCommand = "Set-Location '$ProjectRoot'; & '$LogstashBat' -f '$ProjectRoot\logstash.conf'"
    Start-Process powershell -ArgumentList '-NoExit', '-Command', $LogstashCommand -WorkingDirectory $ProjectRoot | Out-Null
} else {
    Write-Host "Logstash path not found. Set LOGSTASH_HOME or pass -LogstashHome when calling this script."
}

if ($WarmupSec -gt 0) {
    Write-Host "Warming up services for $WarmupSec seconds before starting generator..."
    Start-Sleep -Seconds $WarmupSec
}

Start-Process powershell -ArgumentList '-NoExit', '-Command', $GeneratorCommand -WorkingDirectory $ProjectRoot | Out-Null

Write-Host "Launched API and generator."
if ($LogstashHome) {
    Write-Host "Launched Logstash from: $LogstashHome"
} else {
    Write-Host "Logstash was not launched."
}