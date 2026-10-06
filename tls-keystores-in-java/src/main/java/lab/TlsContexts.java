package lab;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

/**
 * Explicit TLS configuration: PKCS12 keystore (own key + cert) for the server, a separate
 * PKCS12 truststore (only the certs we trust) for the client, and protocol versions pinned
 * to TLS 1.3/1.2 instead of relying on JVM defaults.
 */
public final class TlsContexts {
    public static final String[] PROTOCOLS = {"TLSv1.3", "TLSv1.2"};

    private TlsContexts() {}

    public static KeyStore load(Path file, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(file)) {
            ks.load(in, password);
        }
        return ks;
    }

    public static SSLContext server(KeyStore keyStore, char[] keyPassword) throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keyPassword);
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx;
    }

    public static SSLContext client(KeyStore trustStore) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(null, tmf.getTrustManagers(), null);
        return ctx;
    }

    /** Pins protocols and turns on hostname verification (off by default for raw SSLSockets). */
    public static SSLParameters hardened(SSLParameters p) {
        p.setProtocols(PROTOCOLS);
        p.setEndpointIdentificationAlgorithm("HTTPS");
        return p;
    }
}
