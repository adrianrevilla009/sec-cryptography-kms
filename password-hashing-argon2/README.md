# password-hashing-argon2

`PasswordHasher.java`: Argon2id password hashing with BouncyCastle 1.78.1, plus `PasswordHasherTest.java`.

## Goal

Hash passwords with Argon2id using explicit, documented parameters and a random salt per password. Show how the parameters travel inside the hash so they can be raised later.

## Run it

```
mvn -q -B test
```

Expected: no output with `-q`; without it Maven reports `Tests run: 3, Failures: 0, Errors: 0` and `BUILD SUCCESS`. This was run for this README and passed. The `main` method that prints a hash and its timing was not run.

## What it proves

- `hash` then `verify` succeeds for the same password and fails for `S3cret` against `s3cret`.
- Hashing the same password twice gives different strings, because each call draws a 16-byte salt.
- The output is `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`. `needsRehash` reads those numbers and returns true for a stored `m=1024,t=1,p=1` hash and false for a fresh one.

## Trade-offs

- The parameters (19 MiB, 2 iterations, 1 lane) are the OWASP minimum for Argon2id. Raise memory until a login costs roughly 100-500 ms on your hardware.
- BouncyCastle's Argon2 is pure Java and slower than a native library; measure before copying the numbers.
- There is no pepper. A secret held in KMS or an HSM would be a further step.
- Argon2id was chosen over bcrypt: it is memory-hard and has no 72-byte input limit.

## When not to use it

- When you must use FIPS-validated algorithms: PBKDF2 is the usual choice there.
- When passwords can be avoided altogether, for example with passkeys or OIDC.
