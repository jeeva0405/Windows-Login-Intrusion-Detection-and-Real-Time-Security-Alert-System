package com.loginsentinel.event;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * EventParser converts raw Windows Event Log XML representations (Event IDs 4625, 4776, 4771)
 * into LoginEvent instances with enriched human-readable metadata.
 */
public class EventParser {
    private static final Logger logger = LoggerFactory.getLogger(EventParser.class);

    private static final Set<String> SUPPORTED_EVENT_IDS = Set.of("4625", "4776", "4771");

    private static final Map<Integer, String> LOGON_TYPE_MAP = Map.of(
            2, "Interactive (Keyboard / Lock Screen)",
            3, "Network (Shared Folder / Service)",
            4, "Batch (Scheduled Task)",
            5, "Service (Background Service Startup)",
            7, "Unlock (Screen Unlock Attempt)",
            8, "Network Cleartext",
            9, "New Credentials",
            10, "Remote Interactive (Remote Desktop RDP)",
            11, "Cached Interactive"
    );

    private static final Map<String, String> STATUS_CODE_MAP = Map.of(
            "0xc000006d", "Incorrect Password / Unknown Username",
            "0xc000006a", "Valid Username but Incorrect Password",
            "0xc000006e", "Account Logon Time / Workstation Restriction",
            "0xc0000072", "Account is Currently Disabled",
            "0xc0000193", "User Account Has Expired",
            "0xc0000234", "Account is Locked Out",
            "0xc000006f", "User Logon Outside Permitted Hours",
            "0x18", "Pre-authentication Failed (Bad Password)",
            "0x14", "Client Key Expired / Account Error"
    );

    /**
     * Parses an XML string containing one or more <Event> elements into a list of LoginEvent objects.
     */
    public List<LoginEvent> parseXmlEvents(String xmlContent) {
        List<LoginEvent> events = new ArrayList<>();
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return events;
        }

        // Handle multiple XML event blocks by wrapping in a root element if necessary
        String formattedXml = xmlContent.trim();
        if (!formattedXml.startsWith("<?xml") && !formattedXml.startsWith("<Events>")) {
            formattedXml = "<Events>" + formattedXml + "</Events>";
        }

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(formattedXml)));

            NodeList eventNodes = doc.getElementsByTagName("Event");
            for (int i = 0; i < eventNodes.getLength(); i++) {
                Element eventElem = (Element) eventNodes.item(i);
                LoginEvent loginEvent = parseSingleEventElement(eventElem);
                if (loginEvent != null) {
                    events.add(loginEvent);
                }
            }
        } catch (Exception e) {
            logger.error("Failed to parse Windows Event XML: {}", e.getMessage());
        }

        return events;
    }

    private LoginEvent parseSingleEventElement(Element eventElem) {
        try {
            // Parse <System> node
            Element systemElem = (Element) eventElem.getElementsByTagName("System").item(0);
            if (systemElem == null) return null;

            String eventIdStr = getElementText(systemElem, "EventID");
            if (!SUPPORTED_EVENT_IDS.contains(eventIdStr)) {
                // Ignore unsupported event IDs
                return null;
            }
            int eventId = Integer.parseInt(eventIdStr);

            String recordIdStr = getElementText(systemElem, "EventRecordID");
            long recordId = recordIdStr.isEmpty() ? System.currentTimeMillis() : Long.parseLong(recordIdStr);

            String rawTime = "";
            NodeList timeList = systemElem.getElementsByTagName("TimeCreated");
            if (timeList.getLength() > 0) {
                Element timeElem = (Element) timeList.item(0);
                rawTime = timeElem.getAttribute("SystemTime");
            }
            String formattedTime = formatTimestamp(rawTime);

            String computerName = getElementText(systemElem, "Computer");

            // Parse <EventData> node
            Map<String, String> dataMap = new HashMap<>();
            NodeList dataNodes = eventElem.getElementsByTagName("Data");
            for (int j = 0; j < dataNodes.getLength(); j++) {
                Element dataElem = (Element) dataNodes.item(j);
                String name = dataElem.getAttribute("Name");
                String value = dataElem.getTextContent();
                if (name != null && !name.isEmpty()) {
                    dataMap.put(name, value);
                }
            }

            // Handle Event ID 4776 (Credential Validation Failure)
            if (eventId == 4776) {
                String statusCode = dataMap.getOrDefault("Status", "0x0").toLowerCase();
                if ("0x0".equals(statusCode) || "0x00000000".equals(statusCode) || statusCode.isEmpty()) {
                    // Success event - ignore
                    return null;
                }
                String targetUserName = dataMap.getOrDefault("TargetUserName", "Unknown");
                String workstationName = dataMap.getOrDefault("Workstation", computerName);
                String packageName = dataMap.getOrDefault("PackageName", "NTLM / LSA");
                String statusDesc = STATUS_CODE_MAP.getOrDefault(statusCode, "Credential Validation Failed (" + statusCode + ")");

                return new LoginEvent(4776, recordId, formattedTime, targetUserName, "Local Account",
                        workstationName, 2, "Credential Validation Attempt", statusCode, statusDesc, "Localhost", packageName);
            }

            // Handle Event ID 4771 (Kerberos Pre-Authentication Failure)
            if (eventId == 4771) {
                String failureCode = dataMap.getOrDefault("FailureCode", "0x0").toLowerCase();
                if ("0x0".equals(failureCode) || failureCode.isEmpty()) {
                    return null;
                }
                String targetUserName = dataMap.getOrDefault("TargetUserName", "Unknown");
                String clientAddress = dataMap.getOrDefault("IpAddress", dataMap.getOrDefault("ClientAddress", "-"));
                String statusDesc = STATUS_CODE_MAP.getOrDefault(failureCode, "Kerberos Pre-authentication Failed (" + failureCode + ")");

                return new LoginEvent(4771, recordId, formattedTime, targetUserName, "Kerberos Domain",
                        computerName, 3, "Kerberos Pre-Authentication", failureCode, statusDesc, clientAddress, "Kerberos Key Distribution Center");
            }

            // Standard Event ID 4625
            String targetUserName = dataMap.getOrDefault("TargetUserName", "Unknown");
            String targetDomainName = dataMap.getOrDefault("TargetDomainName", computerName);
            String workstationName = dataMap.getOrDefault("WorkstationName", computerName);

            int logonType = 2; // Default to interactive
            try {
                if (dataMap.containsKey("LogonType")) {
                    logonType = Integer.parseInt(dataMap.get("LogonType"));
                }
            } catch (NumberFormatException ignored) {}

            String logonTypeDesc = LOGON_TYPE_MAP.getOrDefault(logonType, "Type " + logonType);

            String rawSubStatus = dataMap.getOrDefault("SubStatus", "").toLowerCase();
            String rawStatus = dataMap.getOrDefault("Status", "0xc000006d").toLowerCase();
            String status = (!rawSubStatus.isEmpty() && !"0x0".equals(rawSubStatus)) ? rawSubStatus : rawStatus;

            String statusDesc = STATUS_CODE_MAP.getOrDefault(status,
                    STATUS_CODE_MAP.getOrDefault(rawStatus, "Incorrect Password / Authentication Failed"));

            String ipAddress = dataMap.getOrDefault("IpAddress", "-");
            String processName = dataMap.getOrDefault("ProcessName", dataMap.getOrDefault("LogonProcessName", "-"));

            return new LoginEvent(4625, recordId, formattedTime, targetUserName, targetDomainName,
                    workstationName, logonType, logonTypeDesc, status, statusDesc, ipAddress, processName);

        } catch (Exception e) {
            logger.error("Error extracting LoginEvent from XML element: {}", e.getMessage());
            return null;
        }
    }

    private String getElementText(Element parent, String tagName) {
        NodeList list = parent.getElementsByTagName(tagName);
        if (list.getLength() > 0) {
            return list.item(0).getTextContent().trim();
        }
        return "";
    }

    private String formatTimestamp(String isoTimestamp) {
        if (isoTimestamp == null || isoTimestamp.isEmpty()) {
            return ZonedDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd hh:mm:ss a z"));
        }
        try {
            ZonedDateTime zdt = ZonedDateTime.parse(isoTimestamp);
            return zdt.format(DateTimeFormatter.ofPattern("yyyy-MM-dd hh:mm:ss a z"));
        } catch (Exception e) {
            return isoTimestamp;
        }
    }
}
