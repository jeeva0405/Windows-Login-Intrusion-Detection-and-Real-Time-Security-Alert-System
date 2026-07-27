package com.loginsentinel.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Properties;

/**
 * CredentialManager securely handles configuration loading and retrieval of email credentials.
 * Prioritizes Environment Variables (EMAIL_USERNAME, EMAIL_APP_PASSWORD, ALERT_RECIPIENT_EMAIL)
 * and falls back to config/config.properties.
 */
public class CredentialManager {
    private static final Logger logger = LoggerFactory.getLogger(CredentialManager.class);

    public static final String ENV_EMAIL_USERNAME = "EMAIL_USERNAME";
    public static final String ENV_EMAIL_APP_PASSWORD = "EMAIL_APP_PASSWORD";
    public static final String ENV_ALERT_RECIPIENT = "ALERT_RECIPIENT_EMAIL";

    private final Properties properties = new Properties();
    private String emailUsername;
    private String emailPassword;
    private String recipientEmail;

    public CredentialManager() {
        this("config/config.properties");
    }

    public CredentialManager(String configFilePath) {
        loadProperties(configFilePath);
        loadCredentials();
    }

    private void loadProperties(String configFilePath) {
        File configFile = new File(configFilePath);
        if (configFile.exists()) {
            try (InputStream input = new FileInputStream(configFile)) {
                properties.load(input);
                logger.info("Loaded configuration properties from {}", configFile.getAbsolutePath());
            } catch (Exception e) {
                logger.error("Failed to read configuration file: {}", e.getMessage());
            }
        } else {
            logger.warn("Configuration file {} not found. Relying on defaults and environment variables.", configFilePath);
        }
    }

    private void loadCredentials() {
        // 1. Username
        String envUser = System.getenv(ENV_EMAIL_USERNAME);
        String propUser = properties.getProperty("email.username", "").trim();
        if (envUser != null && !envUser.trim().isEmpty() && !envUser.contains("YOUR_GMAIL") && (propUser.isEmpty() || envUser.equalsIgnoreCase(propUser))) {
            this.emailUsername = envUser.trim();
            logger.info("Loaded email username from environment variable [{}]", ENV_EMAIL_USERNAME);
        } else if (!propUser.isEmpty()) {
            this.emailUsername = propUser;
            logger.info("Loaded email username from configuration properties file [{}]", getMaskedUsername());
        } else if (envUser != null && !envUser.trim().isEmpty()) {
            this.emailUsername = envUser.trim();
        }

        // 2. Password / App Password
        String envPass = System.getenv(ENV_EMAIL_APP_PASSWORD);
        String propPass = properties.getProperty("email.password", "").replaceAll("\\s+", "").trim();
        if (envPass != null && !envPass.trim().isEmpty() && !envPass.contains("MySecurePassword") && !envPass.contains("YOUR_GMAIL") && (propPass.isEmpty() || envPass.equalsIgnoreCase(propPass))) {
            this.emailPassword = envPass.replaceAll("\\s+", "").trim();
            logger.info("Loaded email password from environment variable [{}]", ENV_EMAIL_APP_PASSWORD);
        } else if (!propPass.isEmpty()) {
            this.emailPassword = propPass;
            logger.info("Loaded email password from configuration properties file");
        } else if (envPass != null && !envPass.trim().isEmpty()) {
            this.emailPassword = envPass.replaceAll("\\s+", "").trim();
        }

        // 3. Recipient Email
        String envRecipient = System.getenv(ENV_ALERT_RECIPIENT);
        String propRecipient = properties.getProperty("email.recipient", "").trim();
        if (envRecipient != null && !envRecipient.trim().isEmpty() && !envRecipient.contains("YOUR_GMAIL")) {
            this.recipientEmail = envRecipient.trim();
            logger.info("Loaded recipient email from environment variable [{}]", ENV_ALERT_RECIPIENT);
        } else if (!propRecipient.isEmpty()) {
            this.recipientEmail = propRecipient;
            logger.info("Loaded recipient email from configuration properties file");
        } else {
            this.recipientEmail = this.emailUsername;
        }

        if (!hasValidCredentials()) {
            logger.warn("⚠️ Email credentials incomplete! Set EMAIL_USERNAME and EMAIL_APP_PASSWORD environment variables or update config/config.properties");
        }
    }

    public boolean hasValidCredentials() {
        return emailUsername != null && !emailUsername.isEmpty()
                && emailPassword != null && !emailPassword.isEmpty()
                && recipientEmail != null && !recipientEmail.isEmpty();
    }

    public String getEmailUsername() {
        return emailUsername;
    }

    public String getEmailPassword() {
        return emailPassword;
    }

    public String getRecipientEmail() {
        return recipientEmail;
    }

    public String getSmtpHost() {
        return properties.getProperty("smtp.host", "smtp.gmail.com").trim();
    }

    public int getSmtpPort() {
        try {
            return Integer.parseInt(properties.getProperty("smtp.port", "587").trim());
        } catch (NumberFormatException e) {
            return 587;
        }
    }

    public boolean isSmtpAuth() {
        return Boolean.parseBoolean(properties.getProperty("smtp.auth", "true").trim());
    }

    public boolean isStartTls() {
        return Boolean.parseBoolean(properties.getProperty("smtp.starttls.enable", "true").trim());
    }

    public int getMonitorIntervalSeconds() {
        try {
            return Integer.parseInt(properties.getProperty("monitor.interval.seconds", "5").trim());
        } catch (NumberFormatException e) {
            return 5;
        }
    }

    public String getStateFilePath() {
        return properties.getProperty("state.file.path", "config/state.properties").trim();
    }

    public boolean isWebcamEnabled() {
        return Boolean.parseBoolean(properties.getProperty("webcam.enabled", "true").trim());
    }

    public int getWebcamWidth() {
        try {
            return Integer.parseInt(properties.getProperty("webcam.width", "640").trim());
        } catch (NumberFormatException e) {
            return 640;
        }
    }

    public int getWebcamHeight() {
        try {
            return Integer.parseInt(properties.getProperty("webcam.height", "480").trim());
        } catch (NumberFormatException e) {
            return 480;
        }
    }

    public int getWebcamTimeoutMs() {
        try {
            return Integer.parseInt(properties.getProperty("webcam.timeout.ms", "3000").trim());
        } catch (NumberFormatException e) {
            return 3000;
        }
    }

    public String getMaskedUsername() {
        if (emailUsername == null || emailUsername.isEmpty()) {
            return "<NOT SET>";
        }
        int atIdx = emailUsername.indexOf('@');
        if (atIdx > 2) {
            return emailUsername.substring(0, 2) + "***" + emailUsername.substring(atIdx);
        }
        return "***" + emailUsername.substring(Math.max(0, atIdx));
    }
}
