package com.loginsentinel;

import com.loginsentinel.event.EventParser;
import com.loginsentinel.event.LoginEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class EventParserTest {

    private EventParser parser;

    @BeforeEach
    public void setUp() {
        parser = new EventParser();
    }

    @Test
    public void testParseValidEvent4625Xml() {
        String sampleXml = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n" +
                "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\n" +
                "  <System>\n" +
                "    <Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"{5484fe62-44a4-42b5-b740-357764ed8131}\"/>\n" +
                "    <EventID>4625</EventID>\n" +
                "    <Version>0</Version>\n" +
                "    <Level>0</Level>\n" +
                "    <Task>12544</Task>\n" +
                "    <Opcode>0</Opcode>\n" +
                "    <Keywords>0x8010000000000000</Keywords>\n" +
                "    <TimeCreated SystemTime=\"2026-07-26T13:30:45.1234567Z\"/>\n" +
                "    <EventRecordID>5002</EventRecordID>\n" +
                "    <Correlation/>\n" +
                "    <Execution ProcessID=\"724\" ThreadID=\"1288\"/>\n" +
                "    <Channel>Security</Channel>\n" +
                "    <Computer>JEEVA-PC</Computer>\n" +
                "    <Security/>\n" +
                "  </System>\n" +
                "  <EventData>\n" +
                "    <Data Name=\"SubjectUserSid\">S-1-5-18</Data>\n" +
                "    <Data Name=\"SubjectUserName\">JEEVA-PC$</Data>\n" +
                "    <Data Name=\"TargetUserName\">Jeeva</Data>\n" +
                "    <Data Name=\"TargetDomainName\">JEEVA-PC</Data>\n" +
                "    <Data Name=\"Status\">0xc000006d</Data>\n" +
                "    <Data Name=\"SubStatus\">0xc000006a</Data>\n" +
                "    <Data Name=\"LogonType\">2</Data>\n" +
                "    <Data Name=\"LogonProcessName\">User32</Data>\n" +
                "    <Data Name=\"WorkstationName\">JEEVA-PC</Data>\n" +
                "    <Data Name=\"IpAddress\">127.0.0.1</Data>\n" +
                "    <Data Name=\"ProcessName\">C:\\Windows\\System32\\winlogon.exe</Data>\n" +
                "  </EventData>\n" +
                "</Event>";

        List<LoginEvent> events = parser.parseXmlEvents(sampleXml);
        assertEquals(1, events.size());

        LoginEvent event = events.get(0);
        assertEquals(4625, event.getEventId());
        assertEquals(5002L, event.getRecordId());
        assertEquals("Jeeva", event.getTargetUserName());
        assertEquals("JEEVA-PC", event.getWorkstationName());
        assertEquals(2, event.getLogonType());
        assertTrue(event.getLogonTypeDescription().contains("Interactive"));
        assertEquals("0xc000006a", event.getStatus());
        assertTrue(event.getStatusDescription().contains("Valid Username but Incorrect Password"));
        assertEquals("127.0.0.1", event.getIpAddress());
    }

    @Test
    public void testParseValidEvent4776Xml() {
        String sampleXml = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n" +
                "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\n" +
                "  <System>\n" +
                "    <EventID>4776</EventID>\n" +
                "    <TimeCreated SystemTime=\"2026-07-26T14:10:00.0000000Z\"/>\n" +
                "    <EventRecordID>6003</EventRecordID>\n" +
                "    <Computer>LAPTOP-TEST</Computer>\n" +
                "  </System>\n" +
                "  <EventData>\n" +
                "    <Data Name=\"PackageName\">MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data>\n" +
                "    <Data Name=\"TargetUserName\">asus</Data>\n" +
                "    <Data Name=\"Workstation\">LAPTOP-TEST</Data>\n" +
                "    <Data Name=\"Status\">0xc000006a</Data>\n" +
                "  </EventData>\n" +
                "</Event>";

        List<LoginEvent> events = parser.parseXmlEvents(sampleXml);
        assertEquals(1, events.size());

        LoginEvent event = events.get(0);
        assertEquals(4776, event.getEventId());
        assertEquals(6003L, event.getRecordId());
        assertEquals("asus", event.getTargetUserName());
        assertEquals("0xc000006a", event.getStatus());
        assertTrue(event.getStatusDescription().contains("Valid Username but Incorrect Password"));
    }

    @Test
    public void testParseValidEvent4771Xml() {
        String sampleXml = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n" +
                "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\n" +
                "  <System>\n" +
                "    <EventID>4771</EventID>\n" +
                "    <TimeCreated SystemTime=\"2026-07-26T14:15:00.0000000Z\"/>\n" +
                "    <EventRecordID>7004</EventRecordID>\n" +
                "    <Computer>DOMAIN-DC</Computer>\n" +
                "  </System>\n" +
                "  <EventData>\n" +
                "    <Data Name=\"TargetUserName\">admin</Data>\n" +
                "    <Data Name=\"FailureCode\">0x18</Data>\n" +
                "    <Data Name=\"ClientAddress\">192.168.1.50</Data>\n" +
                "  </EventData>\n" +
                "</Event>";

        List<LoginEvent> events = parser.parseXmlEvents(sampleXml);
        assertEquals(1, events.size());

        LoginEvent event = events.get(0);
        assertEquals(4771, event.getEventId());
        assertEquals(7004L, event.getRecordId());
        assertEquals("admin", event.getTargetUserName());
        assertEquals("0x18", event.getStatus());
        assertTrue(event.getStatusDescription().contains("Pre-authentication Failed"));
    }

    @Test
    public void testIgnoreUnsupportedEvents() {
        String sampleXml = "<Event><System><EventID>4624</EventID><EventRecordID>100</EventRecordID></System></Event>";
        List<LoginEvent> events = parser.parseXmlEvents(sampleXml);
        assertTrue(events.isEmpty());
    }

    @Test
    public void testParseEmptyOrMalformedXml() {
        List<LoginEvent> events = parser.parseXmlEvents("invalid xml string");
        assertTrue(events.isEmpty());
    }
}
