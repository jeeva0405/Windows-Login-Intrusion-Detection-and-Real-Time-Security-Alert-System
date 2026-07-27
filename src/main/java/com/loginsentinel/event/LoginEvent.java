package com.loginsentinel.event;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Objects;

/**
 * LoginEvent represents a parsed failed authentication event (Windows Event ID 4625).
 * Contains computer details, targeted account, logon type, timestamp, and failure status.
 */
public class LoginEvent {
    private final int eventId;
    private final long recordId;
    private final String timeCreated;
    private final String targetUserName;
    private final String targetDomainName;
    private final String workstationName;
    private final int logonType;
    private final String logonTypeDescription;
    private final String status;
    private final String statusDescription;
    private final String ipAddress;
    private final String processName;

    public LoginEvent(long recordId, String timeCreated, String targetUserName, String targetDomainName,
                      String workstationName, int logonType, String logonTypeDescription,
                      String status, String statusDescription, String ipAddress, String processName) {
        this(4625, recordId, timeCreated, targetUserName, targetDomainName,
             workstationName, logonType, logonTypeDescription, status, statusDescription, ipAddress, processName);
    }

    public LoginEvent(int eventId, long recordId, String timeCreated, String targetUserName, String targetDomainName,
                      String workstationName, int logonType, String logonTypeDescription,
                      String status, String statusDescription, String ipAddress, String processName) {
        this.eventId = eventId;
        this.recordId = recordId;
        this.timeCreated = timeCreated != null ? timeCreated : LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        this.targetUserName = (targetUserName != null && !targetUserName.isEmpty()) ? targetUserName : "Unknown";
        this.targetDomainName = (targetDomainName != null && !targetDomainName.isEmpty()) ? targetDomainName : "N/A";
        this.workstationName = (workstationName != null && !workstationName.isEmpty()) ? workstationName : getComputerNameFallback();
        this.logonType = logonType;
        this.logonTypeDescription = logonTypeDescription != null ? logonTypeDescription : "Type " + logonType;
        this.status = status != null ? status : "0xC000006D";
        this.statusDescription = statusDescription != null ? statusDescription : "Incorrect Password / Account Error";
        this.ipAddress = (ipAddress != null && !ipAddress.equals("-")) ? ipAddress : "Localhost / Lock Screen";
        this.processName = (processName != null && !processName.equals("-")) ? processName : "Windows Logon System";
    }

    private String getComputerNameFallback() {
        String envComputer = System.getenv("COMPUTERNAME");
        return envComputer != null ? envComputer : "Windows-PC";
    }

    public int getEventId() {
        return eventId;
    }

    public long getRecordId() {
        return recordId;
    }

    public String getTimeCreated() {
        return timeCreated;
    }

    public String getTargetUserName() {
        return targetUserName;
    }

    public String getTargetDomainName() {
        return targetDomainName;
    }

    public String getWorkstationName() {
        return workstationName;
    }

    public int getLogonType() {
        return logonType;
    }

    public String getLogonTypeDescription() {
        return logonTypeDescription;
    }

    public String getStatus() {
        return status;
    }

    public String getStatusDescription() {
        return statusDescription;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getProcessName() {
        return processName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LoginEvent that = (LoginEvent) o;
        return recordId == that.recordId;
    }

    @Override
    public int hashCode() {
        return Objects.hash(recordId);
    }

    @Override
    public String toString() {
        return "LoginEvent{" +
                "eventId=" + eventId +
                ", recordId=" + recordId +
                ", timeCreated='" + timeCreated + '\'' +
                ", targetUserName='" + targetUserName + '\'' +
                ", workstationName='" + workstationName + '\'' +
                ", logonType=" + logonTypeDescription +
                ", status='" + statusDescription + '\'' +
                '}';
    }
}
