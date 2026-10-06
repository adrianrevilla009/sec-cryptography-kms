# sec-cryptography-kms

Five small Java 21 examples of everyday application cryptography (password hashing, envelope encryption with KMS, field-level encryption, a tamper-evident audit log and TLS keystores), each runnable on its own and each built around a tiny Orders domain.

## What is inside

| Folder | What it shows | Run |
| --- | --- | --- |
| [`password-hashing-argon2`](./password-hashing-argon2) | Argon2id with explicit parameters, random salt, constant-time verify and a rehash check | `mvn -q -B test` |
| [`envelope-encryption-kms`](./envelope-encryption-kms) | AES-256-GCM with a per-message data key generated and unwrapped by AWS KMS (LocalStack) | `mvn -q -B test` |
| [`field-level-encryption`](./field-level-encryption) | Encrypting one column of an Orders row, plus an HMAC blind index for equality lookups | `mvn -q -B test` |
| [`audit-logging`](./audit-logging) | HMAC-chained audit log that detects edits and deletions | `mvn -q -B test` |
| [`tls-keystores-in-java`](./tls-keystores-in-java) | PKCS12 keystore and truststore, pinned TLS versions and hostname verification | `mvn -q -B test` |

## Prerequisites

- Java 21 (JDK, because the TLS test calls `keytool`)
- Maven 3.8 or newer (no wrapper is included)
- Docker, only for `envelope-encryption-kms` (it starts `localstack/localstack:3.4.0` through Testcontainers)

## How to read it

Start with `password-hashing-argon2` or `audit-logging`: both are one class and need no Docker. Then read `envelope-encryption-kms` followed by `field-level-encryption`, which uses the same AES-GCM idea with keys passed in as bytes. Run every command from inside its folder.
