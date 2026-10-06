package lab;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Field-level encryption for an Orders row: only the sensitive column (customer email) is encrypted,
 * the rest stays queryable. Two independent keys: one for AES-GCM, one for an HMAC "blind index"
 * that allows equality lookups without decrypting. Each ciphertext is bound to its row id via AAD,
 * so a ciphertext copied to another row fails to decrypt.
 */
public final class FieldCrypto {
    public record OrderRow(String id, String status, String emailEnc, String emailIndex) {}

    private static final SecureRandom RANDOM = new SecureRandom();
    private final SecretKeySpec encKey;
    private final SecretKeySpec indexKey;

    public FieldCrypto(byte[] encKey32, byte[] indexKey32) {
        this.encKey = new SecretKeySpec(encKey32, "AES");
        this.indexKey = new SecretKeySpec(indexKey32, "HmacSHA256");
    }

    public OrderRow protect(String id, String status, String email) throws Exception {
        return new OrderRow(id, status, encrypt(id, email), blindIndex(email));
    }

    public String reveal(OrderRow row) throws Exception {
        return decrypt(row.id(), row.emailEnc());
    }

    /** Normalised so "A@x.io" and "a@x.io" find the same row; leaks equality, nothing else. */
    public String blindIndex(String email) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(indexKey);
        return Base64.getEncoder().encodeToString(mac.doFinal(email.trim().toLowerCase().getBytes(StandardCharsets.UTF_8)));
    }

    private String encrypt(String rowId, String value) throws Exception {
        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, encKey, new GCMParameterSpec(128, iv));
        c.updateAAD(rowId.getBytes(StandardCharsets.UTF_8));
        byte[] ct = c.doFinal(value.getBytes(StandardCharsets.UTF_8));
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return Base64.getEncoder().encodeToString(out);
    }

    private String decrypt(String rowId, String encoded) throws Exception {
        byte[] in = Base64.getDecoder().decode(encoded);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, encKey, new GCMParameterSpec(128, in, 0, 12));
        c.updateAAD(rowId.getBytes(StandardCharsets.UTF_8));
        return new String(c.doFinal(in, 12, in.length - 12), StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        byte[] k1 = new byte[32], k2 = new byte[32];
        RANDOM.nextBytes(k1);
        RANDOM.nextBytes(k2);
        FieldCrypto fc = new FieldCrypto(k1, k2);
        OrderRow row = fc.protect("o-1", "PAID", "Ana@example.com");
        System.out.println(row);
        System.out.println("revealed=" + fc.reveal(row));
    }
}
