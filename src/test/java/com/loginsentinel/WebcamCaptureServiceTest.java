package com.loginsentinel;

import com.loginsentinel.security.CredentialManager;
import com.loginsentinel.security.CredentialManager;
import com.loginsentinel.webcam.WebcamCaptureResult;
import com.loginsentinel.webcam.WebcamCaptureService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class WebcamCaptureServiceTest {

    static class DisabledCredentialManager extends CredentialManager {
        public DisabledCredentialManager() {
            super("non-existent-file.properties");
        }

        @Override
        public boolean isWebcamEnabled() {
            return false;
        }
    }

    @Test
    void testDisabledWebcamCapture() {
        CredentialManager credentialManager = new DisabledCredentialManager();
        WebcamCaptureService service = new WebcamCaptureService(credentialManager);
        WebcamCaptureResult result = service.captureSnapshot();

        assertNotNull(result);
        assertEquals(WebcamCaptureResult.Status.DISABLED, result.getStatus());
        assertFalse(result.isSuccess());
    }

    @Test
    void testWebcamResultDTO() {
        WebcamCaptureResult noCam = WebcamCaptureResult.noCameraFound();
        assertEquals(WebcamCaptureResult.Status.NO_CAMERA_FOUND, noCam.getStatus());
        assertFalse(noCam.isSuccess());
        assertNull(noCam.getImageFile());

        WebcamCaptureResult permDenied = WebcamCaptureResult.permissionDenied("Access Denied");
        assertEquals(WebcamCaptureResult.Status.PERMISSION_DENIED, permDenied.getStatus());
        assertFalse(permDenied.isSuccess());
        assertTrue(permDenied.getMessage().contains("Access Denied"));
    }

    @Test
    void testSecureTemporaryFileDeletion(@TempDir Path tempDir) throws Exception {
        CredentialManager credentialManager = new CredentialManager("config/config.properties");
        WebcamCaptureService service = new WebcamCaptureService(credentialManager);

        File dummyFile = tempDir.resolve("test_image.jpg").toFile();
        try (FileWriter writer = new FileWriter(dummyFile)) {
            writer.write("dummy-image-data-header-bytes");
        }

        assertTrue(dummyFile.exists());
        assertTrue(dummyFile.length() > 0);

        service.deleteTemporaryFile(dummyFile);

        assertFalse(dummyFile.exists());
    }
}
