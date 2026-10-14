param([switch]$SkipBuild)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$temporaryRoot = Join-Path $env:TEMP ('redtrace-windows-' + [guid]::NewGuid().ToString('N'))
$core = $null
$agent = $null
$variables = @('REDTRACE_DATA_DIR', 'REDTRACE_INGEST_BIND', 'REDTRACE_API_TOKEN', 'REDTRACE_LOOKBACK', 'REDTRACE_AGENT_TOKEN')
$previous = @{}
foreach ($name in $variables) { $previous[$name] = [Environment]::GetEnvironmentVariable($name) }

function Wait-Core {
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try { return Invoke-RestMethod 'http://127.0.0.1:9710/api/health' -Headers $headers } catch { Start-Sleep -Milliseconds 500 }
    }
    throw 'Core startup timed out'
}

function Start-Core {
    Start-Process (Join-Path $root 'target\release\redtrace.exe') -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $temporaryRoot 'core.out') -RedirectStandardError (Join-Path $temporaryRoot 'core.err')
}

try {
    if (Get-NetTCPConnection -LocalPort 9710 -State Listen -ErrorAction SilentlyContinue) { throw 'Port 9710 already in use' }
    if (-not $SkipBuild) {
        & cargo build --release --bins
        if ($LASTEXITCODE -ne 0) { throw 'Release build failed' }
    }
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $env:REDTRACE_DATA_DIR = Join-Path $temporaryRoot 'core-data'
    $env:REDTRACE_INGEST_BIND = '127.0.0.1:9711'
    $env:REDTRACE_LOOKBACK = '24h'
    $env:REDTRACE_API_TOKEN = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
    $headers = @{ 'x-redtrace-token' = $env:REDTRACE_API_TOKEN }
    $core = Start-Core
    $health = Wait-Core
    $unauthorized = $false
    try { Invoke-RestMethod 'http://127.0.0.1:9710/api/health' | Out-Null } catch { $unauthorized = [int]$_.Exception.Response.StatusCode -eq 401 }
    if (-not $unauthorized) { throw 'Session authentication failed' }
    $registered = Invoke-RestMethod 'http://127.0.0.1:9710/api/agents' -Method Post -Headers $headers -ContentType 'application/json' -Body '{"name":"windows-smoke"}'
    $env:REDTRACE_AGENT_TOKEN = $registered.token
    $agentState = Join-Path $temporaryRoot 'agent-data'
    $arguments = '--server http://127.0.0.1:9711 --name windows-smoke --poll 1 --state-dir "' + $agentState + '"'
    $agent = Start-Process (Join-Path $root 'target\release\redtrace-agent.exe') -ArgumentList $arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $temporaryRoot 'agent.out') -RedirectStandardError (Join-Path $temporaryRoot 'agent.err')
    $url = 'http://127.0.0.1:9710/api/search?q=agent.id:' + $registered.id + '&limit=1000'
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        Start-Sleep -Milliseconds 500
        $results = Invoke-RestMethod $url -Headers $headers
        if ($results.total -gt 0) { break }
    }
    if ($results.total -eq 0) { throw 'No real Windows events reached server; check readable channels and lookback' }
    if (@($results.events | Where-Object { $_.fields.'collector.mode' -eq 'native' }).Count -eq 0) { throw 'Native collector did not supply events' }
    $uids = @($results.events.uid)
    Stop-Process -Id $core.Id -Force
    $core.WaitForExit()
    $core = $null
    Start-Sleep -Seconds 3
    $core = Start-Core
    $health = Wait-Core
    $recovered = Invoke-RestMethod $url -Headers $headers
    foreach ($uid in $uids) { if ($uid -notin $recovered.events.uid) { throw 'Acknowledged event missing after crash/restart' } }
    Start-Sleep -Seconds 3
    $after = Invoke-RestMethod $url -Headers $headers
    if (@($after.events.uid | Sort-Object -Unique).Count -ne @($after.events).Count) { throw 'Duplicate UIDs after restart' }
    $revoked = Invoke-RestMethod ('http://127.0.0.1:9710/api/agents/' + $registered.id) -Method Delete -Headers $headers
    if (-not $revoked.revoked) { throw 'Token revocation failed' }
    "PASS: native Windows events=$($results.total), crash recovery, agent retry, session authentication, token revocation"
    $health = Invoke-RestMethod 'http://127.0.0.1:9710/api/health' -Headers $headers
    "Collector state=$($health.source.state); diagnostic=$($health.source.last_error)"
} finally {
    foreach ($process in @($agent, $core)) {
        if ($null -ne $process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
    }
    foreach ($name in $variables) { [Environment]::SetEnvironmentVariable($name, $previous[$name]) }
    if (Test-Path -LiteralPath $temporaryRoot) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }
}
