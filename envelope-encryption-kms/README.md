# envelope-encryption-kms

`EnvelopeCrypto.java`: envelope encryption with the AWS KMS client, tested against LocalStack 3.4.0 started by Testcontainers in `EnvelopeCryptoTest.java`.

## Goal

Encrypt each message locally with AES-256-GCM under a fresh data key, where KMS only generates and unwraps that key. The wrapped key is stored in front of the ciphertext.

## Run it

```
mvn -q -B test
```

Docker must be running. The first run pulls `localstack/localstack:3.4.0`, which can take minutes. Expected: `Tests run: 4, Failures: 0, Errors: 0` and `BUILD SUCCESS` (without `-q`); the test class took about 20 s here. No real AWS account is used and nothing costs money. Testcontainers removes the container when the test ends; `docker image rm localstack/localstack:3.4.0` frees the disk.

## What it proves

- `encrypt` then `decrypt` returns the original bytes, through `GenerateDataKey` and `Decrypt`.
- Two encryptions of the same plaintext give different blobs, because each call gets its own data key and IV.
- The context string is sent as the KMS encryption context and as GCM associated data, so decrypting with `invoices` instead of `orders` throws.
- Flipping the last bit of the blob fails the GCM tag check.

## Trade-offs

- One KMS call per message isolates keys but adds latency and uses KMS quota. High-volume systems cache data keys with limits.
- LocalStack's KMS mimics the API only. It does not model IAM key policies, rotation or quotas.
- The key array is zeroed after use, but the JVM may have copied it.
- The blob layout (`[4B wrapped-key length][wrapped key][12B IV][ciphertext+tag]`) is custom. The AWS Encryption SDK or Tink are the production-grade formats.

## When not to use it

- For payloads under 4 KB, where KMS `Encrypt` can be called directly.
- When you need an audited, ready-made message format.
