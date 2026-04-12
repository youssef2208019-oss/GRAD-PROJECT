param(
    [int]$Rows = 500,
    [double]$IntervalSec = 0.5,
    [string]$LogstashHome = "",
    [switch]$NoForever
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

Start-Process powershell -ArgumentList '-NoExit', '-Command', $GeneratorCommand -WorkingDirectory $ProjectRoot | Out-Null

Write-Host "Launched API and generator."
if ($LogstashHome) {
    Write-Host "Launched Logstash from: $LogstashHome"
} else {
    Write-Host "Logstash was not launched."
}