package com.loginsentinel.email;

import com.loginsentinel.event.LoginEvent;
import com.loginsentinel.security.CredentialManager;
import com.loginsentinel.webcam.WebcamCaptureResult;
import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.Properties;

/**
 * EmailAlertService constructs and dispatches secure HTML and plain text email alerts
 * when a failed Windows login event is detected, including webcam snapshot attachments.
 */
public class EmailAlertService {
    private static final Logger logger = LoggerFactory.getLogger(EmailAlertService.class);

    private final CredentialManager credentialManager;

    public EmailAlertService(CredentialManager credentialManager) {
        this.credentialManager = credentialManager;
    }

    /**
     * Sends an email security alert for a specific failed LoginEvent without webcam snapshot.
     */
    public boolean sendAlertEmail(LoginEvent event) {
        return sendAlertEmail(event, null);
    }

    /**
     * Sends an email security alert for a specific failed LoginEvent including webcam snapshot results.
     */
    public boolean sendAlertEmail(LoginEvent event, WebcamCaptureResult webcamResult) {
        if (!credentialManager.hasValidCredentials()) {
            logger.error("Cannot send email alert: Missing email credentials in CredentialManager.");
            return false;
        }

        String subject = "⚠️ Unauthorized Login Attempt Detected on " + event.getWorkstationName();
        String plainTextContent = buildPlainTextContent(event, webcamResult);
        String htmlContent = buildHtmlContent(event, webcamResult);

        File attachment = (webcamResult != null && webcamResult.isSuccess()) ? webcamResult.getImageFile() : null;
        return sendEmail(subject, plainTextContent, htmlContent, attachment);
    }

    /**
     * Sends a test email to verify SMTP connection and configuration settings.
     */
    public boolean sendTestEmail() {
        if (!credentialManager.hasValidCredentials()) {
            logger.error("Test email failed: Missing credentials in CredentialManager.");
            return false;
        }

        String subject = "✅ Windows Login Sentinel - SMTP Configuration Test";
        String plainTextContent = "Windows Login Sentinel is successfully configured and active on " +
                System.getenv("COMPUTERNAME") + ". Real-time security alerts will be sent to this email address.";
        String htmlContent = buildTestEmailHtmlContent();

        logger.info("Sending test email to {}...", credentialManager.getRecipientEmail());
        return sendEmail(subject, plainTextContent, htmlContent, null);
    }

    private boolean sendEmail(String subject, String plainTextContent, String htmlContent, File attachment) {
        try {
            Properties props = new Properties();
            props.put("mail.smtp.host", credentialManager.getSmtpHost());
            props.put("mail.smtp.port", String.valueOf(credentialManager.getSmtpPort()));
            props.put("mail.smtp.auth", String.valueOf(credentialManager.isSmtpAuth()));
            props.put("mail.smtp.starttls.enable", String.valueOf(credentialManager.isStartTls()));
            props.put("mail.smtp.ssl.protocols", "TLSv1.2 TLSv1.3");
            props.put("mail.smtp.connectiontimeout", "10000");
            props.put("mail.smtp.timeout", "10000");

            Session session = Session.getInstance(props, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(
                            credentialManager.getEmailUsername(),
                            credentialManager.getEmailPassword()
                    );
                }
            });

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(credentialManager.getEmailUsername(), "Windows Login Sentinel"));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(credentialManager.getRecipientEmail()));
            message.setSubject(subject);

            // Multipart message (Plain text + HTML)
            MimeBodyPart textPart = new MimeBodyPart();
            textPart.setText(plainTextContent, "utf-8");

            MimeBodyPart htmlPart = new MimeBodyPart();
            htmlPart.setContent(htmlContent, "text/html; charset=utf-8");

            MimeMultipart contentAlternative = new MimeMultipart("alternative");
            contentAlternative.addBodyPart(textPart);
            contentAlternative.addBodyPart(htmlPart);

            MimeMultipart rootMultipart;
            if (attachment != null && attachment.exists() && attachment.length() > 0) {
                MimeBodyPart bodyWrapper = new MimeBodyPart();
                bodyWrapper.setContent(contentAlternative);

                rootMultipart = new MimeMultipart("related");
                rootMultipart.addBodyPart(bodyWrapper);

                MimeBodyPart imagePart = new MimeBodyPart();
                imagePart.attachFile(attachment);
                imagePart.setContentID("<webcamImage>");
                imagePart.setDisposition(MimeBodyPart.INLINE);
                imagePart.setFileName("webcam_snapshot.jpg");
                rootMultipart.addBodyPart(imagePart);
            } else {
                rootMultipart = contentAlternative;
            }

            message.setContent(rootMultipart);

            Transport.send(message);
            logger.info("Email alert successfully sent to {}", credentialManager.getRecipientEmail());
            return true;

        } catch (Exception e) {
            logger.error("Failed to send email alert: {}", e.getMessage(), e);
            return false;
        }
    }

    private String buildPlainTextContent(LoginEvent event, WebcamCaptureResult webcamResult) {
        StringBuilder sb = new StringBuilder();
        sb.append("⚠️ UNAUTHORIZED AUTHENTICATION ATTEMPT DETECTED\n\n");
        sb.append("A failed authentication attempt was detected on your Windows computer.\n\n");
        sb.append("Computer Name: ").append(event.getWorkstationName()).append("\n");
        sb.append("Username: ").append(event.getTargetUserName()).append("\n");
        sb.append("Domain: ").append(event.getTargetDomainName()).append("\n");
        sb.append("Event: Failed Windows Logon / Auth (Event ID ").append(event.getEventId()).append(")\n");
        sb.append("Date & Time: ").append(event.getTimeCreated()).append("\n");
        sb.append("Logon Type: ").append(event.getLogonTypeDescription()).append("\n");
        sb.append("Status: ").append(event.getStatusDescription()).append(" (").append(event.getStatus()).append(")\n");
        sb.append("IP Address: ").append(event.getIpAddress()).append("\n");
        sb.append("Process / Package: ").append(event.getProcessName()).append("\n\n");

        if (webcamResult != null) {
            if (webcamResult.isSuccess()) {
                sb.append("📷 Webcam Capture: Snapshot successfully attached to this email.\n\n");
            } else {
                sb.append("📷 Webcam Capture Status: ").append(webcamResult.getMessage()).append("\n\n");
            }
        }

        sb.append("Please verify whether this authentication attempt was authorized.");
        return sb.toString();
    }

    private String buildHtmlContent(LoginEvent event, WebcamCaptureResult webcamResult) {
        StringBuilder webcamHtml = new StringBuilder();
        if (webcamResult != null) {
            if (webcamResult.isSuccess()) {
                webcamHtml.append("      <div style=\"margin-top: 24px; padding: 16px; background-color: #1a252f; border-radius: 6px; text-align: center;\">\n")
                          .append("        <h4 style=\"color: #ffffff; margin: 0 0 12px 0; font-size: 15px;\">📷 Intruder Webcam Snapshot</h4>\n")
                          .append("        <img src=\"cid:webcamImage\" alt=\"Captured Webcam Snapshot\" style=\"max-width: 100%; height: auto; border: 2px solid #d9534f; border-radius: 4px;\">\n")
                          .append("        <p style=\"color: #a0aec0; font-size: 11px; margin: 8px 0 0 0;\">Snapshot automatically captured upon failed login event.</p>\n")
                          .append("      </div>\n");
            } else {
                webcamHtml.append("      <div style=\"margin-top: 20px; background-color: #fff3cd; color: #856404; border-left: 4px solid #ffeba8; padding: 12px 16px; border-radius: 3px; font-size: 13px;\">\n")
                          .append("        📷 <strong>Webcam Status:</strong> ").append(escapeHtml(webcamResult.getMessage())).append("\n")
                          .append("      </div>\n");
            }
        }

        return "<!DOCTYPE html>\n" +
                "<html>\n" +
                "<head>\n" +
                "  <meta charset=\"UTF-8\">\n" +
                "  <style>\n" +
                "    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; margin: 0; padding: 20px; color: #333333; }\n" +
                "    .container { max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); border-top: 5px solid #d9534f; }\n" +
                "    .header { background-color: #1a252f; padding: 24px; text-align: center; color: #ffffff; }\n" +
                "    .header h2 { margin: 0; font-size: 20px; letter-spacing: 0.5px; display: flex; align-items: center; justify-content: center; gap: 10px; }\n" +
                "    .badge { background-color: #d9534f; color: white; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; text-transform: uppercase; display: inline-block; margin-top: 8px; }\n" +
                "    .content { padding: 30px 25px; }\n" +
                "    .alert-banner { background-color: #fdf2f2; border-left: 4px solid #d9534f; padding: 12px 16px; margin-bottom: 24px; border-radius: 2px; font-size: 14px; color: #a94442; }\n" +
                "    .detail-table { width: 100%; border-collapse: collapse; margin-bottom: 25px; }\n" +
                "    .detail-table th, .detail-table td { padding: 12px 14px; text-align: left; border-bottom: 1px solid #eeeeee; font-size: 14px; }\n" +
                "    .detail-table th { background-color: #f8f9fa; color: #555555; width: 35%; font-weight: 600; }\n" +
                "    .detail-table td { color: #222222; font-weight: 500; }\n" +
                "    .highlight { color: #d9534f; font-weight: bold; }\n" +
                "    .footer { background-color: #f8f9fa; padding: 16px; text-align: center; font-size: 12px; color: #777777; border-top: 1px solid #eeeeee; }\n" +
                "  </style>\n" +
                "</head>\n" +
                "<body>\n" +
                "  <div class=\"container\">\n" +
                "    <div class=\"header\">\n" +
                "      <h2>⚠️ Windows Security Alert</h2>\n" +
                "      <div class=\"badge\">Failed Authentication Event ID " + event.getEventId() + "</div>\n" +
                "    </div>\n" +
                "    <div class=\"content\">\n" +
                "      <div class=\"alert-banner\">\n" +
                "        A failed authentication attempt was detected on your Windows computer.\n" +
                "      </div>\n" +
                "      <table class=\"detail-table\">\n" +
                "        <tr><th>Computer Name</th><td><strong>" + escapeHtml(event.getWorkstationName()) + "</strong></td></tr>\n" +
                "        <tr><th>Username</th><td><span class=\"highlight\">" + escapeHtml(event.getTargetUserName()) + "</span></td></tr>\n" +
                "        <tr><th>Domain / Workgroup</th><td>" + escapeHtml(event.getTargetDomainName()) + "</td></tr>\n" +
                "        <tr><th>Event Type</th><td>Failed Authentication (ID " + event.getEventId() + ")</td></tr>\n" +
                "        <tr><th>Timestamp</th><td>" + escapeHtml(event.getTimeCreated()) + "</td></tr>\n" +
                "        <tr><th>Logon Type / Mode</th><td>" + escapeHtml(event.getLogonTypeDescription()) + "</td></tr>\n" +
                "        <tr><th>Failure Status</th><td>" + escapeHtml(event.getStatusDescription()) + " (" + escapeHtml(event.getStatus()) + ")</td></tr>\n" +
                "        <tr><th>IP / Source</th><td>" + escapeHtml(event.getIpAddress()) + "</td></tr>\n" +
                "        <tr><th>Process / Package</th><td>" + escapeHtml(event.getProcessName()) + "</td></tr>\n" +
                "      </table>\n" +
                webcamHtml.toString() +
                "      <p style=\"font-size: 13px; color: #666666; margin-top: 20px;\">🔒 <strong>Note:</strong> Windows Login Sentinel detected this attempt via the Windows Security Log. Temporary image captures are securely deleted after alert dispatch.</p>\n" +
                "    </div>\n" +
                "    <div class=\"footer\">\n" +
                "      Windows Login Sentinel Security System • Protecting " + escapeHtml(event.getWorkstationName()) + "\n" +
                "    </div>\n" +
                "  </div>\n" +
                "</body>\n" +
                "</html>";
    }

    private String buildTestEmailHtmlContent() {
        return "<!DOCTYPE html>\n" +
                "<html>\n" +
                "<head>\n" +
                "  <meta charset=\"UTF-8\">\n" +
                "  <style>\n" +
                "    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; margin: 0; padding: 20px; color: #333333; }\n" +
                "    .container { max-width: 550px; margin: 0 auto; background: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); border-top: 5px solid #28a745; }\n" +
                "    .header { background-color: #1a252f; padding: 20px; text-align: center; color: #ffffff; }\n" +
                "    .content { padding: 25px; text-align: center; }\n" +
                "    .footer { background-color: #f8f9fa; padding: 14px; text-align: center; font-size: 12px; color: #777777; }\n" +
                "  </style>\n" +
                "</head>\n" +
                "<body>\n" +
                "  <div class=\"container\">\n" +
                "    <div class=\"header\">\n" +
                "      <h2>✅ System Configuration Test</h2>\n" +
                "    </div>\n" +
                "    <div class=\"content\">\n" +
                "      <p><strong>Windows Login Sentinel</strong> is successfully connected to your SMTP email server.</p>\n" +
                "      <p>Real-time notifications for failed Windows authentication attempts (Event IDs 4625, 4776, 4771) will be dispatched to this address.</p>\n" +
                "    </div>\n" +
                "    <div class=\"footer\">\n" +
                "      Windows Login Sentinel System Test • " + System.getenv("COMPUTERNAME") + "\n" +
                "    </div>\n" +
                "  </div>\n" +
                "</body>\n" +
                "</html>";
    }

    private String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
