package com.loginsentinel.monitor;

import com.loginsentinel.email.EmailAlertService;
import com.loginsentinel.event.EventParser;
import com.loginsentinel.event.LoginEvent;
import com.loginsentinel.security.CredentialManager;
import com.loginsentinel.service.WindowsServiceManager;
import com.loginsentinel.webcam.WebcamCaptureResult;
import com.loginsentinel.webcam.WebcamCaptureService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * WindowsLoginMonitor continuously polls the Windows Security Event Log for failed login events (Event ID 4625),
 * parses new events, triggers single-frame webcam capture, updates persistent state, and dispatches email notifications.
 */
public class WindowsLoginMonitor {
    private static final Logger logger = LoggerFactory.getLogger(WindowsLoginMonitor.class);

    private final CredentialManager credentialManager;
    private final EventParser eventParser;
    private final EmailAlertService emailAlertService;
    private final WindowsServiceManager serviceManager;
    private final WebcamCaptureService webcamCaptureService;
    private final ScheduledExecutorService executorService;
    private volatile boolean isRunning = false;
    private boolean initializedBaseline = false;

    public WindowsLoginMonitor(CredentialManager credentialManager,
                               EventParser eventParser,
                               EmailAlertService emailAlertService,
                               WindowsServiceManager serviceManager) {
        this(credentialManager, eventParser, emailAlertService, serviceManager, new WebcamCaptureService(credentialManager));
    }

    public WindowsLoginMonitor(CredentialManager credentialManager,
                               EventParser eventParser,
                               EmailAlertService emailAlertService,
                               WindowsServiceManager serviceManager,
                               WebcamCaptureService webcamCaptureService) {
        this.credentialManager = credentialManager;
        this.eventParser = eventParser;
        this.emailAlertService = emailAlertService;
        this.serviceManager = serviceManager;
        this.webcamCaptureService = webcamCaptureService;
        this.executorService = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "WindowsLoginMonitor-Worker");
            thread.setDaemon(true);
            return thread;
        });
    }

    /**
     * Starts the continuous background monitoring loop.
     */
    public synchronized void startMonitoring() {
        if (isRunning) {
            logger.info("WindowsLoginMonitor is already running.");
            return;
        }

        isRunning = true;
        int intervalSeconds = credentialManager.getMonitorIntervalSeconds();
        logger.info("🚀 Starting Windows Login Sentinel Monitoring (Poll interval: {}s)...", intervalSeconds);

        executorService.scheduleWithFixedDelay(this::pollSecurityEvents, 0, intervalSeconds, TimeUnit.SECONDS);
    }

    /**
     * Stops the monitoring service gracefully.
     */
    public synchronized void stopMonitoring() {
        if (!isRunning) return;

        logger.info("Stopping Windows Login Sentinel Monitor...");
        isRunning = false;
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
        logger.info("Windows Login Sentinel Monitor stopped.");
    }

    /**
     * Performs a single poll cycle of the Windows Security Event Log.
     */
    public void pollSecurityEvents() {
        if (!isRunning) return;

        try {
            logger.debug("Polling Windows Security log for failed authentication events (4625, 4776, 4771)...");
            String xmlData = queryWindowsSecurityEvents();
            if (xmlData == null || xmlData.trim().isEmpty()) {
                logger.debug("No event data returned from Windows Event Log query.");
                return;
            }

            List<LoginEvent> parsedEvents = eventParser.parseXmlEvents(xmlData);
            if (parsedEvents.isEmpty()) {
                logger.debug("No failed authentication events (4625/4776/4771) found in returned XML.");
                return;
            }

            long currentLastRecordId = serviceManager.getLastProcessedRecordId();

            // First run initialization baseline setup to prevent alerting on historic events
            if (currentLastRecordId == -1 && !initializedBaseline) {
                long maxRecordId = parsedEvents.stream()
                        .mapToLong(LoginEvent::getRecordId)
                        .max()
                        .orElse(-1);
                if (maxRecordId > 0) {
                    serviceManager.saveState(maxRecordId);
                    logger.info("Initialized event record baseline to ID: {}. Historic events skipped.", maxRecordId);
                }
                initializedBaseline = true;
                return;
            }

            // Filter for only NEW events that have record ID > currentLastRecordId
            List<LoginEvent> newEvents = parsedEvents.stream()
                    .filter(e -> serviceManager.isNewEvent(e.getRecordId()))
                    .sorted(Comparator.comparingLong(LoginEvent::getRecordId))
                    .collect(Collectors.toList());

            if (newEvents.isEmpty()) {
                logger.debug("No new failed authentication events since record ID {}", currentLastRecordId);
                return;
            }

            logger.warn("🚨 Detected {} NEW failed authentication attempt(s)!", newEvents.size());

            for (LoginEvent event : newEvents) {
                logger.warn("🚨 [Event ID {}] User: '{}' | Workstation: '{}' | Type: '{}' | Status: '{}' | RecordID: {}",
                        event.getEventId(), event.getTargetUserName(), event.getWorkstationName(),
                        event.getLogonTypeDescription(), event.getStatusDescription(), event.getRecordId());

                WebcamCaptureResult webcamResult = null;
                try {
                    webcamResult = webcamCaptureService.captureSnapshot();
                    logger.info("Webcam capture status for Event ID {}: {}", event.getEventId(), webcamResult.getStatus());
                } catch (Exception e) {
                    logger.error("Webcam snapshot capture attempt threw exception: {}", e.getMessage());
                }

                try {
                    boolean sent = emailAlertService.sendAlertEmail(event, webcamResult);
                    if (sent) {
                        logger.info("Email alert successfully sent for Event ID {} (Record ID {})", event.getEventId(), event.getRecordId());
                    } else {
                        logger.warn("Failed to dispatch email alert for Event ID {} (Record ID {}), updating state to prevent retry loop.", event.getEventId(), event.getRecordId());
                    }
                } finally {
                    if (webcamResult != null) {
                        webcamCaptureService.cleanupResult(webcamResult);
                    }
                }

                // Update persistent state after processing event
                serviceManager.saveState(event.getRecordId());
            }

        } catch (Exception e) {
            logger.error("Error during security event poll: {}", e.getMessage(), e);
        }
    }

    /**
     * Executes native Windows Event Log query tool (wevtutil) or PowerShell fallback.
     */
    public String queryWindowsSecurityEvents() {
        String output = runWevtutilQuery();
        if (output == null || output.trim().isEmpty()) {
            logger.debug("wevtutil query produced no output or encountered error. Attempting PowerShell fallback...");
            output = runPowerShellQuery();
        }
        return output;
    }

    private String runWevtutilQuery() {
        // Query Security log for Event IDs 4625, 4776, 4771, format as XML, newest 15 events
        String[] command = {
                "wevtutil.exe", "qe", "Security",
                "/q:*[System[(EventID=4625 or EventID=4776 or EventID=4771)]]",
                "/f:xml", "/rd:true", "/c:15"
        };

        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append("\n");
                }
            }

            int exitCode = process.waitFor();
            if (exitCode == 0) {
                return sb.toString();
            } else {
                logger.debug("wevtutil exit code: {}. Output: {}", exitCode, sb.toString());
            }
        } catch (Exception e) {
            logger.debug("Failed to execute wevtutil command: {}", e.getMessage());
        }
        return null;
    }

    private String runPowerShellQuery() {
        String script = "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625,4776,4771} -MaxEvents 15 -ErrorAction SilentlyContinue | ForEach-Object { $_.ToXml() }";
        String[] command = {
                "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script
        };

        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append("\n");
                }
            }

            process.waitFor();
            return sb.toString();
        } catch (Exception e) {
            logger.error("Failed to execute PowerShell query fallback: {}", e.getMessage());
        }
        return null;
    }

    public boolean isRunning() {
        return isRunning;
    }
}
