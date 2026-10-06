package lab;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TlsContextsTest {
    static final char[] PW = "changeit-lab".toCharArray();
    static Path dir;
    static Path keystore;

    private static void keytool(String... args) throws Exception {
        String[] cmd = new String[args.length + 1];
        cmd[0] = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        System.arraycopy(args, 0, cmd, 1, args.length);
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        p.getInputStream().readAllBytes();
        assertEquals(0, p.waitFor(), "keytool failed");
    }

    @BeforeAll
    static void generateKeys(@TempDir Path tmp) throws Exception {
        // Keys are generated at test time into a temp dir: nothing secret is committed.
        dir = Files.createTempDirectory(tmp, "tls");
        keystore = dir.resolve("server.p12");
        keytool("-genkeypair", "-alias", "server", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=localhost",
                "-ext", "san=dns:localhost", "-validity", "2", "-storetype", "PKCS12",
                "-keystore", keystore.toString(), "-storepass", new String(PW));
        Path cert = dir.resolve("server.crt");
        keytool("-exportcert", "-alias", "server", "-keystore", keystore.toString(), "-storepass", new String(PW),
                "-file", cert.toString());
        keytool("-importcert", "-noprompt", "-alias", "server", "-file", cert.toString(), "-storetype", "PKCS12",
                "-keystore", dir.resolve("trust.p12").toString(), "-storepass", new String(PW));
    }

    private String roundTrip(KeyStore trust) throws Exception {
        SSLContext server = TlsContexts.server(TlsContexts.load(keystore, PW), PW);
        try (SSLServerSocket ss = (SSLServerSocket) server.getServerSocketFactory().createServerSocket(0, 1,
                java.net.InetAddress.getLoopbackAddress())) {
            ss.setSSLParameters(TlsContexts.hardened(ss.getSSLParameters()));
            Thread t = new Thread(() -> {
                try (SSLSocket s = (SSLSocket) ss.accept()) {
                    OutputStream o = s.getOutputStream();
                    o.write('k');
                    o.flush();
                    s.getInputStream().read();
                } catch (Exception ignored) {
                    // handshake failure is asserted on the client side
                }
            });
            t.start();
            SSLContext client = TlsContexts.client(trust);
            try (SSLSocket c = (SSLSocket) client.getSocketFactory().createSocket("localhost", ss.getLocalPort())) {
                c.setSSLParameters(TlsContexts.hardened(c.getSSLParameters()));
                c.startHandshake();
                InputStream in = c.getInputStream();
                int b = in.read();
                c.getOutputStream().write(1);
                return c.getSession().getProtocol() + ":" + (char) b;
            } finally {
                t.join(5000);
            }
        }
    }

    @Test
    void trustedServerHandshakesOverTls13() throws Exception {
        assertEquals("TLSv1.3:k", roundTrip(TlsContexts.load(dir.resolve("trust.p12"), PW)));
    }

    @Test
    void emptyTruststoreRejectsServer() throws Exception {
        KeyStore empty = KeyStore.getInstance("PKCS12");
        empty.load(null, null);
        assertThrows(javax.net.ssl.SSLException.class, () -> roundTrip(empty));
    }

    @Test
    void truststoreHoldsOnlyTheCertificateNotThePrivateKey() throws Exception {
        KeyStore trust = TlsContexts.load(dir.resolve("trust.p12"), PW);
        assertTrue(trust.isCertificateEntry("server"));
        assertFalse(trust.isKeyEntry("server"));
        Certificate c = trust.getCertificate("server");
        assertNotNull(c);
    }
}
