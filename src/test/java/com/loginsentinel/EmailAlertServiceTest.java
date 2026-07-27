package com.loginsentinel;

import com.loginsentinel.email.EmailAlertService;
import com.loginsentinel.event.LoginEvent;
import com.loginsentinel.security.CredentialManager;
import com.loginsentinel.webcam.WebcamCaptureResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class EmailAlertServiceTest {

    static class InvalidCredentialManager extends CredentialManager {
        public InvalidCredentialManager() {
            super("non-existent-file.properties");
        }

        @Override
        public boolean hasValidCredentials() {
            return false;
        }
    }

    @Test
    void testSendAlertEmailWithMissingCredentials() {
        CredentialManager credentialManager = new InvalidCredentialManager();
        EmailAlertService service = new EmailAlertService(credentialManager);
        LoginEvent event = new LoginEvent(1001, "2026-07-26 23:00:00", "Admin", "WORKGROUP",
                "DESKTOP-TEST", 2, "Interactive", "0xc000006d", "Incorrect Password", "127.0.0.1", "winlogon.exe");

        boolean result = service.sendAlertEmail(event);
        assertFalse(result);
    }

    @Test
    void testSendAlertEmailWithWebcamResult(@TempDir Path tempDir) throws Exception {
        CredentialManager credentialManager = new InvalidCredentialManager();
        EmailAlertService service = new EmailAlertService(credentialManager);
        LoginEvent event = new LoginEvent(1002, "2026-07-26 23:05:00", "John", "DOMAIN",
                "LAPTOP-01", 2, "Interactive", "0xc000006d", "Bad Password", "192.168.1.10", "winlogon.exe");

        File dummyImg = tempDir.resolve("snap.jpg").toFile();
        try (FileWriter writer = new FileWriter(dummyImg)) {
            writer.write("fake-image-bytes");
        }

        WebcamCaptureResult successResult = WebcamCaptureResult.success(dummyImg);
        assertFalse(service.sendAlertEmail(event, successResult));

        WebcamCaptureResult failedResult = WebcamCaptureResult.noCameraFound();
        assertFalse(service.sendAlertEmail(event, failedResult));
    }
}
