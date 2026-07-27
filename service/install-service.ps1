#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error 'ERROR: Access Denied. You MUST run PowerShell as Administrator to install Windows Services!'
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectDir = (Get-Item "$ScriptDir\..").FullName
Set-Location $ProjectDir

$ServiceName = 'WindowsLoginSentinel'
$ServiceExe = "$ProjectDir\service\WindowsLoginSentinel.exe"
$ServiceXml = "$ProjectDir\service\WindowsLoginSentinel.xml"
$JarPath = "$ProjectDir\target\WindowsLoginSentinel-1.0.0.jar"
$LogsDir = "$ProjectDir\logs"

if (-not (Test-Path $JarPath)) {
    Write-Error "ERROR: Application JAR '$JarPath' not found! Run 'mvn package' first."
    exit 1
}

if (-not (Test-Path $LogsDir)) {
    New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
}

$JavaCmd = (Get-Command java.exe -ErrorAction SilentlyContinue).Source
if (-not $JavaCmd -and $env:JAVA_HOME) {
    $JavaCmd = "$env:JAVA_HOME\bin\java.exe"
}
if (-not $JavaCmd -or -not (Test-Path $JavaCmd)) {
    Write-Error 'ERROR: java.exe not found on system PATH or JAVA_HOME!'
    exit 1
}

if (-not (Test-Path $ServiceExe)) {
    Write-Host 'Downloading WinSW service wrapper executable...' -ForegroundColor Cyan
    $winSwUrl = 'https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        (New-Object System.Net.WebClient).DownloadFile($winSwUrl, $ServiceExe)
    } catch {
        Write-Error "Failed to download WinSW wrapper: $_"
        exit 1
    }
}

# Update executable and paths in XML dynamically while keeping credentials and structure valid
$EnvUser = $env:EMAIL_USERNAME
$EnvPass = $env:EMAIL_APP_PASSWORD
$EnvRecipient = $env:ALERT_RECIPIENT_EMAIL

if (-not $EnvUser -or -not $EnvPass) {
    $ConfigPath = "$ProjectDir\config\config.properties"
    if (Test-Path $ConfigPath) {
        Get-Content $ConfigPath | ForEach-Object {
            if ($_ -match '^\s*email\.username\s*=\s*(.+)$') { $EnvUser = $Matches[1].Trim() }
            if ($_ -match '^\s*email\.password\s*=\s*(.+)$') { $EnvPass = $Matches[1].Trim() }
            if ($_ -match '^\s*email\.recipient\s*=\s*(.+)$') { $EnvRecipient = $Matches[1].Trim() }
        }
    }
}
if (-not $EnvUser) { $EnvUser = 'YOUR_GMAIL_ADDRESS@gmail.com' }
if (-not $EnvPass) { $EnvPass = 'YOUR_GMAIL_APP_PASSWORD' }
if (-not $EnvRecipient) { $EnvRecipient = $EnvUser }

# Clean password string (strip spaces if any)
$EnvPassClean = $EnvPass.Replace(' ', '')

$XmlContent = @"
<service>
  <id>$ServiceName</id>
  <name>Windows Login Sentinel Security Service</name>
  <description>Monitors Windows Security Event Log for failed login attempts (Event ID 4625) and sends email alerts.</description>
  <executable>$JavaCmd</executable>
  <workingdirectory>$ProjectDir</workingdirectory>
  <arguments>-jar "$JarPath"</arguments>
  <env name="EMAIL_USERNAME" value="$EnvUser" />
  <env name="EMAIL_APP_PASSWORD" value="$EnvPassClean" />
  <env name="ALERT_RECIPIENT_EMAIL" value="$EnvRecipient" />
  <logpath>$LogsDir</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>10240</sizeThreshold>
    <keepFiles>8</keepFiles>
  </log>
  <onfailure action="restart" delay="10 sec" />
  <startmode>Automatic</startmode>
</service>
"@

Set-Content -Path $ServiceXml -Value $XmlContent -Encoding UTF8

Write-Host "[1/5] Removing existing '$ServiceName' service if present..." -ForegroundColor Cyan
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    & $ServiceExe stop | Out-Null
    Start-Sleep -Seconds 2
    & $ServiceExe uninstall | Out-Null
    Start-Sleep -Seconds 2
}

Write-Host "[2/5] Registering '$ServiceName' with Windows Service Manager via WinSW..." -ForegroundColor Cyan
& $ServiceExe install
Start-Sleep -Seconds 2

Write-Host "[3/5] Verifying service registration..." -ForegroundColor Cyan
$registered = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $registered) {
    Write-Error "ERROR: Service registration failed! 'Get-Service -Name $ServiceName' returns not found."
    exit 1
}
Write-Host "Service '$ServiceName' registered successfully." -ForegroundColor Green

Write-Host "[4/5] Starting '$ServiceName' service..." -ForegroundColor Cyan
& $ServiceExe start
Start-Sleep -Seconds 3

Write-Host "[5/5] Verifying service status..." -ForegroundColor Cyan
$statusCheck = Get-Service -Name $ServiceName
if ($statusCheck.Status -ne 'Running') {
    Write-Error "ERROR: Service started but status is '$($statusCheck.Status)' instead of 'Running'! Check logs at $LogsDir."
    exit 1
}

Write-Host "=============================================================" -ForegroundColor Green
Write-Host " SUCCESS: '$ServiceName' installed and is RUNNING! " -ForegroundColor Green
Write-Host "=============================================================" -ForegroundColor Green
