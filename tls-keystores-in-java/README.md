# tls-keystores-in-java

`TlsContexts.java`: helpers that build server and client `SSLContext`s from PKCS12 files, with `TlsContextsTest.java` running a loopback handshake.

## Goal

Configure Java TLS explicitly: a PKCS12 keystore for the server identity, a separate PKCS12 truststore for the client, pinned protocol versions (TLS 1.3 and 1.2) and hostname verification on a raw `SSLSocket`.

## Run it

```
mvn -q -B test
```

Expected: `Tests run: 3, Failures: 0, Errors: 0` and `BUILD SUCCESS` (without `-q`). The test calls the JDK's `keytool` to generate a throwaway EC key pair, keystore and truststore in a temp directory, so a JDK (not just a JRE) is required and no key material is committed.

## What it proves

- A client that trusts the server certificate completes a handshake on loopback with hostname verification (`CN=localhost`, SAN `localhost`); the test asserts the negotiated protocol is `TLSv1.3`.
- A client with an empty truststore fails against the same server with an `SSLException`.
- The truststore holds the certificate as a certificate entry and has no private key entry.

## Trade-offs

- The certificate is self-signed and valid for 2 days. Production uses a CA-issued certificate with automated renewal.
- The keystore password `changeit-lab` is a literal in the test only. Real passwords come from a secret store.
- On a raw `SSLSocket`, hostname verification must be switched on by hand (`setEndpointIdentificationAlgorithm("HTTPS")` in `hardened`); `java.net.http.HttpClient` does it for you.
- No mutual TLS. Adding it needs a client keystore and `setNeedClientAuth(true)` on the server.

## When not to use it

- When TLS ends at a proxy, ingress or service mesh and the application never handles keys.
- When the platform's default trust store and defaults already do what you need.
