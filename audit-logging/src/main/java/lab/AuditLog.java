package lab;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Tamper-evident audit log. Each entry's MAC covers its sequence number, payload and the previous
 * entry's MAC, so editing, deleting, reordering or inserting any entry breaks every MAC after it.
 * Using HMAC (not a bare hash) means an attacker who can rewrite the store but lacks the key
 * cannot recompute a consistent chain.
 */
public final class AuditLog {
    public record Entry(long seq, String event, String prevMac, String mac) {}

    private static final String GENESIS = "0".repeat(64);
    private final byte[] key;
    private final List<Entry> entries = new ArrayList<>();

    public AuditLog(byte[] key) {
        this.key = key.clone();
    }

    public Entry append(String event) {
        String prev = entries.isEmpty() ? GENESIS : entries.get(entries.size() - 1).mac();
        long seq = entries.size();
        Entry e = new Entry(seq, event, prev, mac(seq, event, prev));
        entries.add(e);
        return e;
    }

    public List<Entry> entries() {
        return entries; // exposed mutable on purpose: tests simulate an attacker editing the store
    }

    /** Returns the seq of the first bad entry, or -1 when the whole chain is intact. */
    public long firstInvalid() {
        String prev = GENESIS;
        for (int i = 0; i < entries.size(); i++) {
            Entry e = entries.get(i);
            boolean ok = e.seq() == i && e.prevMac().equals(prev)
                    && MessageDigest.isEqual(e.mac().getBytes(StandardCharsets.UTF_8),
                            mac(i, e.event(), prev).getBytes(StandardCharsets.UTF_8));
            if (!ok) return i;
            prev = e.mac();
        }
        return -1;
    }

    private String mac(long seq, String event, String prev) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            // length-prefix the event so field boundaries cannot be shifted
            String data = seq + "|" + prev + "|" + event.length() + "|" + event;
            return HexFormat.of().formatHex(m.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    public static void main(String[] args) {
        AuditLog log = new AuditLog("demo-only-key-demo-only-key-1234".getBytes(StandardCharsets.UTF_8));
        log.append("order o-1 created");
        log.append("order o-1 paid");
        log.append("order o-1 shipped");
        System.out.println("intact -> firstInvalid=" + log.firstInvalid());
        log.entries().set(1, new Entry(1, "order o-1 refunded", log.entries().get(1).prevMac(), log.entries().get(1).mac()));
        System.out.println("edited -> firstInvalid=" + log.firstInvalid());
    }
}
