param([ValidateSet('open', 'close')][string]$Action)
$ErrorActionPreference = 'Stop'
$name = 'REDTRACE-MacBook-Isolated-Test-19711'
if ($Action -eq 'open') {
    if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) { throw 'Test rule already exists; preserve and inspect it' }
    $binary = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../target/debug/redtrace.exe'))
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw 'Test collector binary missing' }
    New-NetFirewallRule -Name $name -DisplayName $name -Direction Inbound -Action Allow -Protocol TCP -LocalAddress 192.168.31.96 -LocalPort 19711 -RemoteAddress 192.168.31.216 -Profile Private -Program $binary | Out-Null
} else {
    $rule = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
    if ($rule) { $rule | Remove-NetFirewallRule }
}
