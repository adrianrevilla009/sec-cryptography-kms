package lab;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/** Argon2id with explicit, justified parameters; output is a PHC-style string so parameters can be raised later. */
public final class PasswordHasher {
    // OWASP minimum profile for Argon2id: 19 MiB memory, 2 iterations, 1 lane.
    // Memory is the cost that hurts GPU/ASIC attackers, so it is the one to raise first.
    public static final int MEMORY_KIB = 19 * 1024;
    public static final int ITERATIONS = 2;
    public static final int PARALLELISM = 1;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordHasher() {}

    public static String hash(String password) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        return encode(MEMORY_KIB, ITERATIONS, PARALLELISM, salt, derive(password, salt, MEMORY_KIB, ITERATIONS, PARALLELISM));
    }

    public static boolean verify(String password, String encoded) {
        String[] p = encoded.split("\\$"); // "", argon2id, v=19, m=..,t=..,p=.., salt, hash
        String[] cost = p[3].split(",");
        int m = Integer.parseInt(cost[0].substring(2));
        int t = Integer.parseInt(cost[1].substring(2));
        int par = Integer.parseInt(cost[2].substring(2));
        byte[] salt = Base64.getDecoder().decode(p[4]);
        byte[] expected = Base64.getDecoder().decode(p[5]);
        return MessageDigest.isEqual(expected, derive(password, salt, m, t, par));
    }

    /** True when stored parameters are weaker than the current policy, so the hash should be upgraded on next login. */
    public static boolean needsRehash(String encoded) {
        String[] cost = encoded.split("\\$")[3].split(",");
        return Integer.parseInt(cost[0].substring(2)) < MEMORY_KIB || Integer.parseInt(cost[1].substring(2)) < ITERATIONS
                || Integer.parseInt(cost[2].substring(2)) < PARALLELISM;
    }

    private static byte[] derive(String password, byte[] salt, int m, int t, int par) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(m).withIterations(t).withParallelism(par).withSalt(salt).build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] out = new byte[HASH_BYTES];
        gen.generateBytes(password.getBytes(StandardCharsets.UTF_8), out);
        return out;
    }

    private static String encode(int m, int t, int par, byte[] salt, byte[] hash) {
        Base64.Encoder b = Base64.getEncoder();
        return "$argon2id$v=19$m=" + m + ",t=" + t + ",p=" + par + "$" + b.encodeToString(salt) + "$" + b.encodeToString(hash);
    }

    public static void main(String[] args) {
        long start = System.nanoTime();
        String h = hash("correct horse battery staple");
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println(h);
        System.out.println("hash took " + ms + " ms; verify ok=" + verify("correct horse battery staple", h)
                + "; wrong=" + verify("wrong", h));
    }
}
