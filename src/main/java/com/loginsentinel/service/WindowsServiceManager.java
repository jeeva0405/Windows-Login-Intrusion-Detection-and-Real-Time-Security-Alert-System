package com.loginsentinel.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.Properties;

/**
 * WindowsServiceManager handles service state persistence (preventing duplicate email alerts)
 * and generates WinSW service wrapper configuration and PowerShell scripts for reliable background service execution.
 */
public class WindowsServiceManager {
    private static final Logger logger = LoggerFactory.getLogger(WindowsServiceManager.class);

    private final String stateFilePath;
    private long lastProcessedRecordId = -1;

    public WindowsServiceManager(String stateFilePath) {
        this.stateFilePath = stateFilePath;
        loadState();
    }

    /**
     * Loads the last processed EventRecordID from state.properties.
     */
    public synchronized void loadState() {
        File stateFile = new File(stateFilePath);
        if (stateFile.exists()) {
            Properties properties = new Properties();
            try (InputStream input = new FileInputStream(stateFile)) {
                properties.load(input);
                String idStr = properties.getProperty("last.processed.record.id", "-1").trim();
                this.lastProcessedRecordId = Long.parseLong(idStr);
                logger.info("Loaded state: last.processed.record.id = {}", lastProcessedRecordId);
            } catch (Exception e) {
                logger.error("Error reading state file {}: {}", stateFilePath, e.getMessage());
            }
        } else {
            logger.info("No prior state file found at {}. Initializing fresh state.", stateFilePath);
        }
    }

    /**
     * Updates and persists the last processed EventRecordID.
     */
    public synchronized void saveState(long recordId) {
        this.lastProcessedRecordId = recordId;
        File stateFile = new File(stateFilePath);
        File parentDir = stateFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }

        Properties properties = new Properties();
        properties.setProperty("last.processed.record.id", String.valueOf(recordId));
        properties.setProperty("last.processed.timestamp", LocalDateTime.now().toString());

        try (OutputStream output = new FileOutputStream(stateFile)) {
            properties.store(output, "Windows Login Sentinel State - DO NOT EDIT MANUALLY");
            logger.debug("State saved successfully. Last record ID = {}", recordId);
        } catch (Exception e) {
            logger.error("Failed to save state to {}: {}", stateFilePath, e.getMessage());
        }
    }

    public synchronized long getLastProcessedRecordId() {
        return lastProcessedRecordId;
    }

    public synchronized boolean isNewEvent(long recordId) {
        return recordId > lastProcessedRecordId;
    }

    /**
     * Generates WinSW service configuration and PowerShell scripts for background Windows Service installation.
     */
    public void generateWindowsServiceScripts(String jarPath) {
        try {
            Path targetDir = Paths.get("service");
            Files.createDirectories(targetDir);

            // 1. Generate install-service.ps1 with WinSW integration
            String installPs1 = "#Requires -RunAsAdministrator\n" +
                    "$ErrorActionPreference = 'Stop'\n\n" +
                    "$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)\n" +
                    "if (-not $isAdmin) {\n" +
                    "    Write-Error 'ERROR: Access Denied. You MUST run PowerShell as Administrator to install Windows Services!'\n" +
                    "    exit 1\n" +
                    "}\n\n" +
                    "$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition\n" +
                    "$ProjectDir = (Get-Item \"$ScriptDir\\..\").FullName\n" +
                    "Set-Location $ProjectDir\n\n" +
                    "$ServiceName = 'WindowsLoginSentinel'\n" +
                    "$ServiceExe = \"$ProjectDir\\service\\WindowsLoginSentinel.exe\"\n" +
                    "$ServiceXml = \"$ProjectDir\\service\\WindowsLoginSentinel.xml\"\n" +
                    "$JarPath = \"$ProjectDir\\target\\WindowsLoginSentinel-1.0.0.jar\"\n" +
                    "$LogsDir = \"$ProjectDir\\logs\"\n\n" +
                    "if (-not (Test-Path $JarPath)) {\n" +
                    "    Write-Error \"ERROR: Application JAR '$JarPath' not found! Run 'mvn package' first.\"\n" +
                    "    exit 1\n" +
                    "}\n\n" +
                    "if (-not (Test-Path $LogsDir)) {\n" +
                    "    New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null\n" +
                    "}\n\n" +
                    "$JavaCmd = (Get-Command java.exe -ErrorAction SilentlyContinue).Source\n" +
                    "if (-not $JavaCmd -and $env:JAVA_HOME) {\n" +
                    "    $JavaCmd = \"$env:JAVA_HOME\\bin\\java.exe\"\n" +
                    "}\n" +
                    "if (-not $JavaCmd -or -not (Test-Path $JavaCmd)) {\n" +
                    "    Write-Error 'ERROR: java.exe not found on system PATH or JAVA_HOME!'\n" +
                    "    exit 1\n" +
                    "}\n\n" +
                    "if (-not (Test-Path $ServiceExe)) {\n" +
                    "    Write-Host 'Downloading WinSW service wrapper executable...' -ForegroundColor Cyan\n" +
                    "    $winSwUrl = 'https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe'\n" +
                    "    try {\n" +
                    "        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\n" +
                    "        (New-Object System.Net.WebClient).DownloadFile($winSwUrl, $ServiceExe)\n" +
                    "    } catch {\n" +
                    "        Write-Error \"Failed to download WinSW wrapper: $_\"\n" +
                    "        exit 1\n" +
                    "    }\n" +
                    "}\n\n" +
                    "$EnvUser = $env:EMAIL_USERNAME\n" +
                    "$EnvPass = $env:EMAIL_APP_PASSWORD\n" +
                    "$EnvRecipient = $env:ALERT_RECIPIENT_EMAIL\n" +
                    "if (-not $EnvUser -or -not $EnvPass) {\n" +
                    "    $ConfigPath = \"$ProjectDir\\config\\config.properties\"\n" +
                    "    if (Test-Path $ConfigPath) {\n" +
                    "        Get-Content $ConfigPath | ForEach-Object {\n" +
                    "            if ($_ -match '^\\s*email\\.username\\s*=\\s*(.+)$') { $EnvUser = $Matches[1].Trim() }\n" +
                    "            if ($_ -match '^\\s*email\\.password\\s*=\\s*(.+)$') { $EnvPass = $Matches[1].Trim() }\n" +
                    "            if ($_ -match '^\\s*email\\.recipient\\s*=\\s*(.+)$') { $EnvRecipient = $Matches[1].Trim() }\n" +
                    "        }\n" +
                    "    }\n" +
                    "}\n" +
                    "if (-not $EnvRecipient) { $EnvRecipient = $EnvUser }\n\n" +
                    "$XmlContent = @\"\n" +
                    "<service>\n" +
                    "  <id>$ServiceName</id>\n" +
                    "  <name>Windows Login Sentinel Security Service</name>\n" +
                    "  <description>Monitors Windows Security Event Log for failed login attempts (Event ID 4625) and sends email alerts.</description>\n" +
                    "  <executable>$JavaCmd</executable>\n" +
                    "  <workingdirectory>$ProjectDir</workingdirectory>\n" +
                    "  <arguments>-jar \"$JarPath\"</arguments>\n" +
                    "  <env name=\"EMAIL_USERNAME\" value=\"$EnvUser\" />\n" +
                    "  <env name=\"EMAIL_APP_PASSWORD\" value=\"$EnvPass\" />\n" +
                    "  <env name=\"ALERT_RECIPIENT_EMAIL\" value=\"$EnvRecipient\" />\n" +
                    "  <logpath>$LogsDir</logpath>\n" +
                    "  <log mode=\"roll-by-size\">\n" +
                    "    <sizeThreshold>10240</sizeThreshold>\n" +
                    "    <keepFiles>8</keepFiles>\n" +
                    "  </log>\n" +
                    "  <onfailure action=\"restart\" delay=\"10 sec\" />\n" +
                    "  <startmode>Automatic</startmode>\n" +
                    "</service>\n" +
                    "\"@\n\n" +
                    "Set-Content -Path $ServiceXml -Value $XmlContent -Encoding UTF8\n\n" +
                    "Write-Host \"[1/5] Removing existing '$ServiceName' service if present...\" -ForegroundColor Cyan\n" +
                    "$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue\n" +
                    "if ($existing) {\n" +
                    "    & $ServiceExe stop | Out-Null\n" +
                    "    Start-Sleep -Seconds 2\n" +
                    "    & $ServiceExe uninstall | Out-Null\n" +
                    "    Start-Sleep -Seconds 2\n" +
                    "}\n\n" +
                    "Write-Host \"[2/5] Registering '$ServiceName' with Windows Service Manager via WinSW...\" -ForegroundColor Cyan\n" +
                    "& $ServiceExe install\n" +
                    "Start-Sleep -Seconds 2\n\n" +
                    "Write-Host \"[3/5] Verifying service registration...\" -ForegroundColor Cyan\n" +
                    "$registered = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue\n" +
                    "if (-not $registered) {\n" +
                    "    Write-Error \"ERROR: Service registration failed! 'Get-Service -Name $ServiceName' returns not found.\"\n" +
                    "    exit 1\n" +
                    "}\n" +
                    "Write-Host \"Service '$ServiceName' registered successfully.\" -ForegroundColor Green\n\n" +
                    "Write-Host \"[4/5] Starting '$ServiceName' service...\" -ForegroundColor Cyan\n" +
                    "& $ServiceExe start\n" +
                    "Start-Sleep -Seconds 3\n\n" +
                    "Write-Host \"[5/5] Verifying service status...\" -ForegroundColor Cyan\n" +
                    "$statusCheck = Get-Service -Name $ServiceName\n" +
                    "if ($statusCheck.Status -ne 'Running') {\n" +
                    "    Write-Error \"ERROR: Service started but status is '$($statusCheck.Status)' instead of 'Running'! Check logs at $LogsDir.\"\n" +
                    "    exit 1\n" +
                    "}\n\n" +
                    "Write-Host \"=============================================================\" -ForegroundColor Green\n" +
                    "Write-Host \" SUCCESS: '$ServiceName' installed and is RUNNING! \" -ForegroundColor Green\n" +
                    "Write-Host \"=============================================================\" -ForegroundColor Green\n";

            Files.writeString(targetDir.resolve("install-service.ps1"), installPs1);

            // 2. Generate uninstall-service.ps1
            String uninstallPs1 = "#Requires -RunAsAdministrator\n" +
                    "$ErrorActionPreference = 'Stop'\n\n" +
                    "$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)\n" +
                    "if (-not $isAdmin) {\n" +
                    "    Write-Error 'ERROR: Access Denied. You MUST run PowerShell as Administrator to uninstall Windows Services!'\n" +
                    "    exit 1\n" +
                    "}\n\n" +
                    "$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition\n" +
                    "$ProjectDir = (Get-Item \"$ScriptDir\\..\").FullName\n" +
                    "$ServiceName = 'WindowsLoginSentinel'\n" +
                    "$ServiceExe = \"$ProjectDir\\service\\WindowsLoginSentinel.exe\"\n\n" +
                    "$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue\n" +
                    "if (-not $existing) {\n" +
                    "    Write-Host \"Service '$ServiceName' is not installed.\" -ForegroundColor Yellow\n" +
                    "    exit 0\n" +
                    "}\n\n" +
                    "Write-Host \"Stopping service '$ServiceName'...\" -ForegroundColor Yellow\n" +
                    "if (Test-Path $ServiceExe) {\n" +
                    "    & $ServiceExe stop | Out-Null\n" +
                    "} else {\n" +
                    "    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue\n" +
                    "}\n" +
                    "Start-Sleep -Seconds 2\n\n" +
                    "Write-Host \"Uninstalling service '$ServiceName'...\" -ForegroundColor Yellow\n" +
                    "if (Test-Path $ServiceExe) {\n" +
                    "    & $ServiceExe uninstall | Out-Null\n" +
                    "} else {\n" +
                    "    sc.exe delete $ServiceName | Out-Null\n" +
                    "}\n" +
                    "Start-Sleep -Seconds 2\n\n" +
                    "$checkDeleted = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue\n" +
                    "if ($checkDeleted) {\n" +
                    "    Write-Error \"ERROR: Failed to uninstall service '$ServiceName'.\"\n" +
                    "    exit 1\n" +
                    "}\n\n" +
                    "Write-Host \"SUCCESS: Service '$ServiceName' uninstalled successfully.\" -ForegroundColor Green\n";

            Files.writeString(targetDir.resolve("uninstall-service.ps1"), uninstallPs1);

            logger.info("Generated WinSW service wrapper files in directory: {}", targetDir.toAbsolutePath());

        } catch (Exception e) {
            logger.error("Failed to generate service installation scripts: {}", e.getMessage());
        }
    }
}
