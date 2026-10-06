package lab;

import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;
import lab.FieldCrypto.OrderRow;
import org.junit.jupiter.api.Test;

class FieldCryptoTest {
    private static FieldCrypto newCrypto() {
        byte[] a = new byte[32], b = new byte[32];
        new SecureRandom().nextBytes(a);
        new SecureRandom().nextBytes(b);
        return new FieldCrypto(a, b);
    }

    @Test
    void roundTripKeepsOtherColumnsPlain() throws Exception {
        FieldCrypto fc = newCrypto();
        OrderRow row = fc.protect("o-1", "PAID", "ana@example.com");
        assertEquals("PAID", row.status());
        assertFalse(row.emailEnc().contains("ana"));
        assertEquals("ana@example.com", fc.reveal(row));
    }

    @Test
    void ciphertextIsRandomizedButBlindIndexIsStable() throws Exception {
        FieldCrypto fc = newCrypto();
        OrderRow a = fc.protect("o-1", "PAID", "ana@example.com");
        OrderRow b = fc.protect("o-1", "PAID", "ana@example.com");
        assertNotEquals(a.emailEnc(), b.emailEnc());
        assertEquals(a.emailIndex(), b.emailIndex());
        assertEquals(a.emailIndex(), fc.blindIndex(" ANA@example.com "));
    }

    @Test
    void ciphertextMovedToAnotherRowFails() throws Exception {
        FieldCrypto fc = newCrypto();
        OrderRow a = fc.protect("o-1", "PAID", "ana@example.com");
        OrderRow moved = new OrderRow("o-2", "PAID", a.emailEnc(), a.emailIndex());
        assertThrows(Exception.class, () -> fc.reveal(moved));
    }
}
