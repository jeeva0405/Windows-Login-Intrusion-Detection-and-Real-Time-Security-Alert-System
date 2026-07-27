package com.loginsentinel;

import com.loginsentinel.email.EmailAlertService;
import com.loginsentinel.event.EventParser;
import com.loginsentinel.event.LoginEvent;
import com.loginsentinel.monitor.WindowsLoginMonitor;
import com.loginsentinel.security.CredentialManager;
import com.loginsentinel.service.WindowsServiceManager;
import com.loginsentinel.webcam.WebcamCaptureResult;
import com.loginsentinel.webcam.WebcamCaptureService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class WindowsLoginMonitorTest {

    static class TestCredentialManager extends CredentialManager {
        public TestCredentialManager() {
            super("non-existent-file.properties");
        }
        @Override
        public int getMonitorIntervalSeconds() {
            return 5;
        }
        @Override
        public boolean hasValidCredentials() {
            return false;
        }
    }

    static class TestWebcamService extends WebcamCaptureService {
        final AtomicInteger captureCount = new AtomicInteger(0);
        final AtomicInteger cleanupCount = new AtomicInteger(0);

        public TestWebcamService(CredentialManager cm) {
            super(cm);
        }

        @Override
        public WebcamCaptureResult captureSnapshot() {
            captureCount.incrementAndGet();
            return WebcamCaptureResult.noCameraFound();
        }

        @Override
        public void cleanupResult(WebcamCaptureResult result) {
            cleanupCount.incrementAndGet();
        }
    }

    static class TestEmailService extends EmailAlertService {
        final AtomicInteger sendCount = new AtomicInteger(0);

        public TestEmailService(CredentialManager cm) {
            super(cm);
        }

        @Override
        public boolean sendAlertEmail(LoginEvent event, WebcamCaptureResult webcamResult) {
            sendCount.incrementAndGet();
            return true;
        }
    }

    @Test
    void testPollTriggersWebcamCaptureOnNewEvent(@TempDir Path tempDir) {
        String statePath = tempDir.resolve("test_state.properties").toString();
        CredentialManager cm = new TestCredentialManager();
        EventParser parser = new EventParser();
        TestEmailService emailService = new TestEmailService(cm);
        WindowsServiceManager serviceManager = new WindowsServiceManager(statePath);
        serviceManager.saveState(9000L);

        TestWebcamService webcamService = new TestWebcamService(cm);

        String sampleXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<Events>\n" +
                "  <Event>\n" +
                "    <System>\n" +
                "      <EventID>4625</EventID>\n" +
                "      <EventRecordID>9999</EventRecordID>\n" +
                "      <TimeCreated SystemTime=\"2026-07-26T23:00:00.000Z\"/>\n" +
                "      <Computer>DESKTOP-TEST</Computer>\n" +
                "    </System>\n" +
                "    <EventData>\n" +
                "      <Data Name=\"TargetUserName\">IntruderUser</Data>\n" +
                "      <Data Name=\"TargetDomainName\">WORKGROUP</Data>\n" +
                "      <Data Name=\"WorkstationName\">DESKTOP-TEST</Data>\n" +
                "      <Data Name=\"LogonType\">2</Data>\n" +
                "      <Data Name=\"Status\">0xc000006d</Data>\n" +
                "    </EventData>\n" +
                "  </Event>\n" +
                "</Events>";

        WindowsLoginMonitor monitor = new WindowsLoginMonitor(cm, parser, emailService, serviceManager, webcamService) {
            @Override
            public String queryWindowsSecurityEvents() {
                return sampleXml;
            }
        };

        monitor.startMonitoring();
        try {
            Thread.sleep(100);
        } catch (InterruptedException ignored) {}
        monitor.stopMonitoring();

        assertEquals(1, webcamService.captureCount.get());
        assertEquals(1, emailService.sendCount.get());
        assertEquals(1, webcamService.cleanupCount.get());
        assertEquals(9999L, serviceManager.getLastProcessedRecordId());
    }

    @Test
    void testPollSkipsWebcamWhenNoNewEvents(@TempDir Path tempDir) {
        String statePath = tempDir.resolve("test_state.properties").toString();
        CredentialManager cm = new TestCredentialManager();
        EventParser parser = new EventParser();
        TestEmailService emailService = new TestEmailService(cm);
        WindowsServiceManager serviceManager = new WindowsServiceManager(statePath);
        serviceManager.saveState(9999L); // Same as incoming record ID

        TestWebcamService webcamService = new TestWebcamService(cm);

        String sampleXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<Events>\n" +
                "  <Event>\n" +
                "    <System>\n" +
                "      <EventID>4625</EventID>\n" +
                "      <EventRecordID>9999</EventRecordID>\n" +
                "      <TimeCreated SystemTime=\"2026-07-26T23:00:00.000Z\"/>\n" +
                "      <Computer>DESKTOP-TEST</Computer>\n" +
                "    </System>\n" +
                "  </Event>\n" +
                "</Events>";

        WindowsLoginMonitor monitor = new WindowsLoginMonitor(cm, parser, emailService, serviceManager, webcamService) {
            @Override
            public String queryWindowsSecurityEvents() {
                return sampleXml;
            }
        };

        monitor.startMonitoring();
        try {
            Thread.sleep(100);
        } catch (InterruptedException ignored) {}
        monitor.stopMonitoring();

        assertEquals(0, webcamService.captureCount.get());
        assertEquals(0, emailService.sendCount.get());
    }
}
