package lab;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class PasswordHasherTest {
    @Test
    void roundTripAndWrongPassword() {
        String h = PasswordHasher.hash("s3cret");
        assertTrue(PasswordHasher.verify("s3cret", h));
        assertFalse(PasswordHasher.verify("S3cret", h));
    }

    @Test
    void saltMakesHashesDiffer() {
        assertNotEquals(PasswordHasher.hash("same"), PasswordHasher.hash("same"));
    }

    @Test
    void weakParametersNeedRehash() {
        assertFalse(PasswordHasher.needsRehash(PasswordHasher.hash("x")));
        assertTrue(PasswordHasher.needsRehash("$argon2id$v=19$m=1024,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA==$AAAA"));
    }
}
