package com.loginsentinel;

import com.loginsentinel.email.EmailAlertService;
import com.loginsentinel.event.EventParser;
import com.loginsentinel.monitor.WindowsLoginMonitor;
import com.loginsentinel.security.CredentialManager;
import com.loginsentinel.service.WindowsServiceManager;
import com.loginsentinel.webcam.WebcamCaptureService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.Arrays;

/**
 * Main application entry point for Windows Login Sentinel.
 * Manages CLI options, background service initialization, diagnostic checks, and shutdown hooks.
 */
public class Main {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);
    public static final String VERSION = "1.0.0";

    public static void main(String[] args) {
        printBanner();

        CredentialManager credentialManager = new CredentialManager();
        EventParser eventParser = new EventParser();
        EmailAlertService emailAlertService = new EmailAlertService(credentialManager);
        WindowsServiceManager serviceManager = new WindowsServiceManager(credentialManager.getStateFilePath());
        WebcamCaptureService webcamCaptureService = new WebcamCaptureService(credentialManager);
        WindowsLoginMonitor loginMonitor = new WindowsLoginMonitor(credentialManager, eventParser, emailAlertService, serviceManager, webcamCaptureService);

        if (args != null && args.length > 0) {
            String arg = args[0].toLowerCase();
            switch (arg) {
                case "--help":
                case "-h":
                    printHelp();
                    return;

                case "--version":
                case "-v":
                    System.out.println("Windows Login Sentinel v" + VERSION);
                    return;

                case "--test-email":
                    logger.info("Executing test email dispatch...");
                    boolean success = emailAlertService.sendTestEmail();
                    if (success) {
                        logger.info("✅ Test email sent successfully to {}", credentialManager.getRecipientEmail());
                    } else {
                        logger.error("❌ Test email failed. Check SMTP configuration or credentials.");
                    }
                    return;

                case "--install-service":
                    String jarPath = getJarLocation();
                    logger.info("Generating Windows Service configuration scripts for JAR: {}", jarPath);
                    serviceManager.generateWindowsServiceScripts(jarPath);
                    logger.info("✅ Service configuration files created in the 'service/' directory.");
                    return;

                case "--status":
                    printStatus(credentialManager, serviceManager, loginMonitor);
                    return;

                default:
                    logger.warn("Unknown argument: {}. Use --help for usage information.", Arrays.toString(args));
                    printHelp();
                    return;
            }
        }

        // Default run mode: Start background monitoring service
        logger.info("Initializing Windows Login Sentinel Background Service...");
        logger.info("Email Username: {}", credentialManager.getMaskedUsername());
        logger.info("Alert Recipient: {}", credentialManager.getRecipientEmail());
        logger.info("SMTP Host: {}:{}", credentialManager.getSmtpHost(), credentialManager.getSmtpPort());
        logger.info("Last Processed Record ID: {}", serviceManager.getLastProcessedRecordId());

        // Register Graceful Shutdown Hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutdown signal received. Terminating monitor gracefully...");
            loginMonitor.stopMonitoring();
        }, "Shutdown-Hook"));

        // Start monitoring loop
        loginMonitor.startMonitoring();

        // Keep main thread alive while monitoring
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            logger.info("Main thread interrupted. Exiting Sentinel.");
            Thread.currentThread().interrupt();
        }
    }

    private static void printBanner() {
        System.out.println("===================================================================");
        System.out.println("   🛡️  WINDOWS LOGIN SENTINEL v" + VERSION + "  🛡️");
        System.out.println("   Real-Time Failed Login Detection & Email Alert System");
        System.out.println("===================================================================");
    }

    private static void printHelp() {
        System.out.println("\nUsage: java -jar WindowsLoginSentinel.jar [options]\n");
        System.out.println("Options:");
        System.out.println("  (none)             Run Sentinel in background monitoring mode");
        System.out.println("  --test-email       Send a test email alert to verify SMTP settings");
        System.out.println("  --install-service  Generate Windows Service configuration and installation scripts");
        System.out.println("  --status           Run system diagnostic checks and print current configuration");
        System.out.println("  --version, -v      Display version information");
        System.out.println("  --help, -h         Display this help message\n");
        System.out.println("Environment Variables:");
        System.out.println("  EMAIL_USERNAME        Sender email address (e.g. user@gmail.com)");
        System.out.println("  EMAIL_APP_PASSWORD    Sender App Password / SMTP Password");
        System.out.println("  ALERT_RECIPIENT_EMAIL Destination email for security alerts");
        System.out.println("===================================================================\n");
    }

    private static void printStatus(CredentialManager credentialManager, WindowsServiceManager serviceManager, WindowsLoginMonitor monitor) {
        System.out.println("\n--- Windows Login Sentinel Diagnostics ---");
        System.out.println("OS: " + System.getProperty("os.name") + " (" + System.getProperty("os.arch") + ")");
        System.out.println("Java Version: " + System.getProperty("java.version"));
        System.out.println("Computer Name: " + System.getenv("COMPUTERNAME"));
        System.out.println("Credentials Valid: " + (credentialManager.hasValidCredentials() ? "YES" : "NO (Incomplete)"));
        System.out.println("Email Username: " + credentialManager.getMaskedUsername());
        System.out.println("Alert Recipient: " + credentialManager.getRecipientEmail());
        System.out.println("SMTP Host: " + credentialManager.getSmtpHost() + ":" + credentialManager.getSmtpPort());
        System.out.println("Last Record ID: " + serviceManager.getLastProcessedRecordId());
        System.out.println("Webcam Feature Enabled: " + (credentialManager.isWebcamEnabled() ? "YES" : "NO"));
        System.out.println("Webcam Resolution: " + credentialManager.getWebcamWidth() + "x" + credentialManager.getWebcamHeight());

        System.out.print("Testing Windows Security Log Query Access... ");
        String testXml = monitor.queryWindowsSecurityEvents();
        if (testXml != null && !testXml.isEmpty()) {
            System.out.println("SUCCESS (Security log readable)");
        } else {
            System.out.println("WARNING (Security log empty or requires Administrator elevation)");
        }
        System.out.println("-------------------------------------------\n");
    }

    private static String getJarLocation() {
        try {
            File file = new File(Main.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            return file.getAbsolutePath();
        } catch (Exception e) {
            return "WindowsLoginSentinel.jar";
        }
    }
}
