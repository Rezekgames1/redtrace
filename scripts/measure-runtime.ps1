param([int]$Seconds = 10)
$ErrorActionPreference = 'Stop'
$all = @(Get-CimInstance Win32_Process)
$ids = @($all | Where-Object { $_.Name -in @('redtrace.exe', 'redtrace-desktop.exe') } | ForEach-Object { [int]$_.ProcessId })
do {
    $added = @($all | Where-Object { [int]$_.ParentProcessId -in $ids -and [int]$_.ProcessId -notin $ids } | ForEach-Object { [int]$_.ProcessId })
    $ids += $added
} while ($added.Count -gt 0)
$initial = @{}
foreach ($id in $ids) {
    $process = Get-Process -Id $id -ErrorAction SilentlyContinue
    if ($process) { $initial[$id] = $process.CPU }
}
$clock = [System.Diagnostics.Stopwatch]::StartNew()
Start-Sleep -Seconds $Seconds
$elapsed = $clock.Elapsed.TotalSeconds
$rows = @(foreach ($id in $ids) {
    $process = Get-Process -Id $id -ErrorAction SilentlyContinue
    if ($process -and $initial.ContainsKey($id)) {
        $oneCore = 100 * ($process.CPU - $initial[$id]) / $elapsed
        [pscustomobject]@{
            pid = $id
            name = $process.ProcessName
            working_set_mib = [Math]::Round($process.WorkingSet64 / 1MB, 2)
            private_commit_mib = [Math]::Round($process.PrivateMemorySize64 / 1MB, 2)
            cpu_one_core_percent = [Math]::Round($oneCore, 3)
            cpu_machine_percent = [Math]::Round($oneCore / [Environment]::ProcessorCount, 3)
        }
    }
})
[pscustomobject]@{
    generated_at = [DateTime]::UtcNow.ToString('o')
    sample_seconds = [Math]::Round($elapsed, 3)
    logical_processors = [Environment]::ProcessorCount
    processes = $rows
    total_working_set_mib = [Math]::Round(($rows | Measure-Object working_set_mib -Sum).Sum, 2)
    total_private_commit_mib = [Math]::Round(($rows | Measure-Object private_commit_mib -Sum).Sum, 2)
    total_cpu_machine_percent = [Math]::Round(($rows | Measure-Object cpu_machine_percent -Sum).Sum, 3)
} | ConvertTo-Json -Depth 4
