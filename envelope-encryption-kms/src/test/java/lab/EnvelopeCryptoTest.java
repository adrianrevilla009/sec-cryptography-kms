package lab;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

class EnvelopeCryptoTest {
    static LocalStackContainer ls = new LocalStackContainer(DockerImageName.parse("localstack/localstack:3.4.0"))
            .withServices(LocalStackContainer.Service.KMS);
    static EnvelopeCrypto crypto;

    @BeforeAll
    static void start() {
        ls.start();
        KmsClient kms = KmsClient.builder().endpointOverride(ls.getEndpoint())
                .region(Region.of(ls.getRegion()))
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test"))).build();
        String keyId = kms.createKey(b -> b.description("lab")).keyMetadata().keyId();
        crypto = new EnvelopeCrypto(kms, keyId);
    }

    @AfterAll
    static void stop() {
        ls.stop();
    }

    @Test
    void roundTrip() throws Exception {
        byte[] blob = crypto.encrypt("order #42".getBytes(), "orders");
        assertArrayEquals("order #42".getBytes(), crypto.decrypt(blob, "orders"));
    }

    @Test
    void eachMessageGetsItsOwnDataKey() throws Exception {
        assertFalse(Arrays.equals(crypto.encrypt("x".getBytes(), "orders"), crypto.encrypt("x".getBytes(), "orders")));
    }

    @Test
    void wrongContextIsRejected() throws Exception {
        byte[] blob = crypto.encrypt("x".getBytes(), "orders");
        assertThrows(Exception.class, () -> crypto.decrypt(blob, "invoices"));
    }

    @Test
    void tamperedCiphertextIsRejected() throws Exception {
        byte[] blob = crypto.encrypt("x".getBytes(), "orders");
        blob[blob.length - 1] ^= 1;
        assertThrows(Exception.class, () -> crypto.decrypt(blob, "orders"));
    }
}
