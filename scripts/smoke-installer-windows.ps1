$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$parent = Join-Path $env:TEMP 'opencode'
if (-not (Test-Path -LiteralPath $parent)) { throw 'Approved temporary parent missing' }
$installed = Join-Path $parent ('redtrace-install-' + [guid]::NewGuid().ToString('N'))
$installer = Join-Path $root 'src-tauri\target\release\bundle\nsis\REDTRACE_0.1.0_x64-setup.exe'
$registry = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\REDTRACE'
$productRegistry = 'HKCU:\Software\redlabs\REDTRACE'
if (Test-Path -LiteralPath $productRegistry) { throw 'Existing installer metadata detected; use a clean VM' }
$manufacturerExisted = Test-Path -LiteralPath 'HKCU:\Software\redlabs'
if ((Test-Path -LiteralPath $registry) -or (Test-Path -LiteralPath 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\REDTRACE')) { throw 'Existing installation detected; use a clean VM for installer validation' }
if (Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name REDTRACE -ErrorAction SilentlyContinue) { throw 'Existing REDTRACE autostart detected' }
$shortcuts = @(
    (Join-Path ([Environment]::GetFolderPath('DesktopDirectory')) 'REDTRACE.lnk'),
    (Join-Path ([Environment]::GetFolderPath('Programs')) 'REDTRACE.lnk')
)
foreach ($shortcut in $shortcuts) { if (Test-Path -LiteralPath $shortcut) { throw 'Existing REDTRACE shortcut detected' } }

try {
    $process = Start-Process -FilePath $installer -ArgumentList @('/S', ('/D=' + $installed)) -PassThru -Wait
    if ($process.ExitCode -ne 0) { throw 'NSIS installation failed' }
    foreach ($file in @('redtrace-desktop.exe', 'redtrace.exe', 'redtrace-audit-helper.exe', 'uninstall.exe')) {
        if (-not (Test-Path -LiteralPath (Join-Path $installed $file))) { throw ('Missing installed binary: ' + $file) }
    }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'smoke-desktop-windows.ps1') -Binary (Join-Path $installed 'redtrace-desktop.exe')
    if ($LASTEXITCODE -ne 0) { throw 'Installed desktop lifecycle test failed' }
    'PASS: NSIS install and installed main/core/helper, session auth, single-instance, lifecycle'
} finally {
    $uninstaller = Join-Path $installed 'uninstall.exe'
    if (Test-Path -LiteralPath $uninstaller) {
        $process = Start-Process -FilePath $uninstaller -ArgumentList @('/S', ('_?=' + $installed)) -PassThru -Wait
        if ($process.ExitCode -ne 0) { throw 'NSIS uninstall failed' }
    }
    if (Test-Path -LiteralPath $productRegistry) { Remove-Item -LiteralPath $productRegistry -Recurse -Force }
    if (-not $manufacturerExisted -and (Test-Path -LiteralPath 'HKCU:\Software\redlabs') -and (Get-Item -LiteralPath 'HKCU:\Software\redlabs').SubKeyCount -eq 0) { Remove-Item -LiteralPath 'HKCU:\Software\redlabs' }
}
if (Test-Path -LiteralPath $registry) { throw 'Uninstall registration remained after removal' }
if (Test-Path -LiteralPath (Join-Path $installed 'redtrace-desktop.exe')) { throw 'Main binary remained after removal' }
if (Test-Path -LiteralPath $installed) { Remove-Item -LiteralPath $installed -Recurse -Force }
'PASS: NSIS uninstall'
