package com.loginsentinel.webcam;

import java.io.File;

/**
 * WebcamCaptureResult encapsulates the outcome of a single webcam snapshot attempt.
 */
public class WebcamCaptureResult {

    public enum Status {
        SUCCESS,
        NO_CAMERA_FOUND,
        PERMISSION_DENIED,
        CAPTURE_FAILED,
        DISABLED
    }

    private final Status status;
    private final File imageFile;
    private final String message;

    public WebcamCaptureResult(Status status, File imageFile, String message) {
        this.status = status;
        this.imageFile = imageFile;
        this.message = message != null ? message : "";
    }

    public static WebcamCaptureResult success(File imageFile) {
        return new WebcamCaptureResult(Status.SUCCESS, imageFile, "Webcam snapshot captured successfully.");
    }

    public static WebcamCaptureResult noCameraFound() {
        return new WebcamCaptureResult(Status.NO_CAMERA_FOUND, null, "No webcam hardware detected on system.");
    }

    public static WebcamCaptureResult permissionDenied(String details) {
        return new WebcamCaptureResult(Status.PERMISSION_DENIED, null, "Camera access permission denied or blocked: " + details);
    }

    public static WebcamCaptureResult failure(String reason) {
        return new WebcamCaptureResult(Status.CAPTURE_FAILED, null, "Webcam capture failed: " + reason);
    }

    public static WebcamCaptureResult disabled() {
        return new WebcamCaptureResult(Status.DISABLED, null, "Webcam capture feature is disabled in configuration.");
    }

    public Status getStatus() {
        return status;
    }

    public boolean isSuccess() {
        return status == Status.SUCCESS && imageFile != null && imageFile.exists() && imageFile.length() > 0;
    }

    public File getImageFile() {
        return imageFile;
    }

    public String getMessage() {
        return message;
    }

    @Override
    public String toString() {
        return "WebcamCaptureResult{" +
                "status=" + status +
                ", hasImage=" + (imageFile != null && imageFile.exists()) +
                ", message='" + message + '\'' +
                '}';
    }
}
