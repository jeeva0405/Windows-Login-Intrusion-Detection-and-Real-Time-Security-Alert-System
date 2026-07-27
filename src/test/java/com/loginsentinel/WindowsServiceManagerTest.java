package com.loginsentinel;

import com.loginsentinel.service.WindowsServiceManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class WindowsServiceManagerTest {

    @Test
    public void testStatePersistenceAndDuplicateDetection(@TempDir Path tempDir) {
        Path stateFile = tempDir.resolve("test-state.properties");
        WindowsServiceManager manager = new WindowsServiceManager(stateFile.toAbsolutePath().toString());

        assertEquals(-1, manager.getLastProcessedRecordId());

        // First event
        long eventId1 = 5001L;
        assertTrue(manager.isNewEvent(eventId1));
        manager.saveState(eventId1);
        assertEquals(5001L, manager.getLastProcessedRecordId());

        // Same event again (Duplicate)
        assertFalse(manager.isNewEvent(eventId1));

        // Older event
        assertFalse(manager.isNewEvent(5000L));

        // Newer event
        long eventId2 = 5002L;
        assertTrue(manager.isNewEvent(eventId2));
        manager.saveState(eventId2);
        assertEquals(5002L, manager.getLastProcessedRecordId());

        // Verify state reloads correctly from disk
        WindowsServiceManager newManager = new WindowsServiceManager(stateFile.toAbsolutePath().toString());
        assertEquals(5002L, newManager.getLastProcessedRecordId());
    }
}
