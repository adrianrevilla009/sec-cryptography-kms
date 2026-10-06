# field-level-encryption

`FieldCrypto.java`: encrypts the customer email of an Orders row and builds a blind index for it, with `FieldCryptoTest.java`.

## Goal

Encrypt only the sensitive column with AES-256-GCM and keep it searchable by equality through an HMAC-SHA256 blind index under a separate key. No Docker or network is needed.

## Run it

```
mvn -q -B test
java -cp target/classes lab.FieldCrypto
```

Expected: the test run passes (`Tests run: 3, Failures: 0, Errors: 0`, `BUILD SUCCESS` without `-q`). The `main` demo prints an `OrderRow[id=o-1, status=PAID, emailEnc=..., emailIndex=...]` line with random Base64 values, then `revealed=Ana@example.com`.

## What it proves

- The stored `emailEnc` does not contain the address, while `status` stays plain and `reveal` returns the original email.
- Two protections of the same row give different `emailEnc` values but the same `emailIndex`, and `" ANA@example.com "` hashes to that same index (trimmed and lower-cased).
- The row id is GCM associated data, so an `emailEnc` copied into a row with id `o-2` fails to decrypt.

## Trade-offs

- A blind index leaks which rows share an email and is open to dictionary attacks on guessable values. Keep its key separate and secret.
- Only equality lookups work: no range, prefix or `LIKE` search.
- Keys come in as raw 32-byte arrays. In real use they would come from KMS, as in `envelope-encryption-kms`; KMS is left out here so the folder runs without Docker.
- The stored value has no key id or version prefix, so rotating keys would need a format change first.

## When not to use it

- When disk or database encryption already covers your threat model.
- When you need rich queries over encrypted data; a database with native client-side field encryption fits better.
