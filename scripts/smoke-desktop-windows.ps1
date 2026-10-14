param([string]$Binary = '')

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$binary = if ($Binary) { $Binary } else { Join-Path $root 'src-tauri\target\release\redtrace-desktop.exe' }
$data = Join-Path $env:TEMP ('redtrace-desktop-' + [guid]::NewGuid().ToString('N'))
$previous = $env:REDTRACE_DATA_DIR
$main = $null
$sidecar = $null

try {
    if (Get-NetTCPConnection -LocalPort 9710 -State Listen -ErrorAction SilentlyContinue) { throw 'Port 9710 already in use' }
    $env:REDTRACE_DATA_DIR = $data
    $main = Start-Process -FilePath $binary -PassThru
    for ($attempt = 0; $attempt -lt 80; $attempt++) {
        Start-Sleep -Milliseconds 250
        $main.Refresh()
        if ($main.HasExited) { throw 'Desktop exited during startup' }
        $sidecar = Get-CimInstance Win32_Process -Filter ('ParentProcessId = ' + $main.Id) | Where-Object { $_.Name -eq 'redtrace.exe' }
        if ($sidecar -and $main.MainWindowHandle -ne 0) { break }
    }
    if (-not $sidecar) { throw 'Sidecar did not start' }
    if ($main.MainWindowHandle -eq 0) { throw 'Desktop window did not open' }
    $unauthorized = $false
    try { Invoke-RestMethod 'http://127.0.0.1:9710/api/health' | Out-Null } catch { $unauthorized = [int]$_.Exception.Response.StatusCode -eq 401 }
    if (-not $unauthorized) { throw 'Desktop API accepted unauthenticated request' }
    $second = Start-Process -FilePath $binary -PassThru
    if (-not $second.WaitForExit(10000)) { Stop-Process -Id $second.Id -Force; throw 'Single-instance check failed' }
    $main.Refresh()
    if ($main.HasExited) { throw 'Original desktop process exited' }
    if (-not $main.CloseMainWindow()) { throw 'Could not close desktop window' }
    if (-not $main.WaitForExit(15000)) { throw 'Desktop did not exit after closing window' }
    Start-Sleep -Seconds 1
    if (Get-Process -Id $sidecar.ProcessId -ErrorAction SilentlyContinue) { throw 'Sidecar survived desktop exit' }
    'PASS: desktop window, session authentication, single-instance, sidecar lifecycle'
} finally {
    if ($main -and -not $main.HasExited) { Stop-Process -Id $main.Id -Force; $main.WaitForExit() }
    if ($sidecar -and (Get-Process -Id $sidecar.ProcessId -ErrorAction SilentlyContinue)) { Stop-Process -Id $sidecar.ProcessId -Force }
    $env:REDTRACE_DATA_DIR = $previous
    if (Test-Path -LiteralPath $data) { Remove-Item -LiteralPath $data -Recurse -Force }
}
