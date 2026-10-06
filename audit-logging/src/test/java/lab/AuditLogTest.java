package lab;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import lab.AuditLog.Entry;
import org.junit.jupiter.api.Test;

class AuditLogTest {
    private static AuditLog sample() {
        AuditLog log = new AuditLog("test-key-test-key-test-key-12345".getBytes(StandardCharsets.UTF_8));
        log.append("created");
        log.append("paid");
        log.append("shipped");
        return log;
    }

    @Test
    void intactChainVerifies() {
        assertEquals(-1, sample().firstInvalid());
    }

    @Test
    void editedEntryIsDetectedAtItsPosition() {
        AuditLog log = sample();
        Entry e = log.entries().get(1);
        log.entries().set(1, new Entry(e.seq(), "refunded", e.prevMac(), e.mac()));
        assertEquals(1, log.firstInvalid());
    }

    @Test
    void deletedEntryIsDetected() {
        AuditLog log = sample();
        log.entries().remove(1);
        assertEquals(1, log.firstInvalid());
    }

    @Test
    void attackerWithoutKeyCannotRecomputeChain() {
        AuditLog log = sample();
        AuditLog forged = new AuditLog("wrong-key-wrong-key-wrong-key-12".getBytes(StandardCharsets.UTF_8));
        forged.append("created");
        forged.append("refunded");
        log.entries().set(1, forged.entries().get(1));
        assertEquals(1, log.firstInvalid());
    }
}
