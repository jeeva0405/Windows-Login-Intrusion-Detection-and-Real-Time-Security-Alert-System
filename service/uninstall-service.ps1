#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error 'ERROR: Access Denied. You MUST run PowerShell as Administrator to uninstall Windows Services!'
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectDir = (Get-Item "$ScriptDir\..").FullName
$ServiceName = 'WindowsLoginSentinel'
$ServiceExe = "$ProjectDir\service\WindowsLoginSentinel.exe"

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $existing) {
    Write-Host "Service '$ServiceName' is not installed." -ForegroundColor Yellow
    exit 0
}

Write-Host "Stopping service '$ServiceName'..." -ForegroundColor Yellow
if (Test-Path $ServiceExe) {
    & $ServiceExe stop | Out-Null
} else {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

Write-Host "Uninstalling service '$ServiceName'..." -ForegroundColor Yellow
if (Test-Path $ServiceExe) {
    & $ServiceExe uninstall | Out-Null
} else {
    sc.exe delete $ServiceName | Out-Null
}
Start-Sleep -Seconds 2

$checkDeleted = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($checkDeleted) {
    Write-Error "ERROR: Failed to uninstall service '$ServiceName'."
    exit 1
}

Write-Host "SUCCESS: Service '$ServiceName' uninstalled successfully." -ForegroundColor Green
