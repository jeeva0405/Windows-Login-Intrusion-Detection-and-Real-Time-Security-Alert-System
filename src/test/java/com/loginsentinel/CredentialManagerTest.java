package com.loginsentinel;

import com.loginsentinel.security.CredentialManager;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class CredentialManagerTest {

    @Test
    public void testDefaultConfigLoading() {
        CredentialManager manager = new CredentialManager("config/config.properties");

        assertEquals("smtp.gmail.com", manager.getSmtpHost());
        assertEquals(587, manager.getSmtpPort());
        assertTrue(manager.isSmtpAuth());
        assertTrue(manager.isStartTls());
        assertEquals(5, manager.getMonitorIntervalSeconds());
    }

    @Test
    public void testUsernameMasking() {
        CredentialManager manager = new CredentialManager("config/config.properties");
        String masked = manager.getMaskedUsername();
        assertNotNull(masked);
    }
}
