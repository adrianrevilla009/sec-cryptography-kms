package lab;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;

/**
 * Envelope encryption: KMS only ever wraps a small per-message data key; the bulk data is
 * encrypted locally with AES-256-GCM. Blob layout: [4B wrappedKeyLen][wrappedKey][12B iv][ciphertext+tag].
 */
public final class EnvelopeCrypto {
    private static final SecureRandom RANDOM = new SecureRandom();
    private final KmsClient kms;
    private final String keyId;

    public EnvelopeCrypto(KmsClient kms, String keyId) {
        this.kms = kms;
        this.keyId = keyId;
    }

    public byte[] encrypt(byte[] plaintext, String context) throws Exception {
        GenerateDataKeyResponse dk = kms.generateDataKey(GenerateDataKeyRequest.builder()
                .keyId(keyId).keySpec(DataKeySpec.AES_256).encryptionContext(Map.of("purpose", context)).build());
        byte[] key = dk.plaintext().asByteArray();
        byte[] wrapped = dk.ciphertextBlob().asByteArray();
        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);
        try {
            byte[] ct = cipher(Cipher.ENCRYPT_MODE, key, iv, context).doFinal(plaintext);
            return ByteBuffer.allocate(4 + wrapped.length + iv.length + ct.length)
                    .putInt(wrapped.length).put(wrapped).put(iv).put(ct).array();
        } finally {
            Arrays.fill(key, (byte) 0); // keep the plaintext key in memory as briefly as possible
        }
    }

    public byte[] decrypt(byte[] blob, String context) throws Exception {
        ByteBuffer b = ByteBuffer.wrap(blob);
        byte[] wrapped = new byte[b.getInt()];
        b.get(wrapped);
        byte[] iv = new byte[12];
        b.get(iv);
        byte[] ct = new byte[b.remaining()];
        b.get(ct);
        byte[] key = kms.decrypt(DecryptRequest.builder().ciphertextBlob(SdkBytes.fromByteArray(wrapped))
                .keyId(keyId).encryptionContext(Map.of("purpose", context)).build()).plaintext().asByteArray();
        try {
            return cipher(Cipher.DECRYPT_MODE, key, iv, context).doFinal(ct);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static Cipher cipher(int mode, byte[] key, byte[] iv, String context) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        c.updateAAD(context.getBytes(StandardCharsets.UTF_8));
        return c;
    }
}
