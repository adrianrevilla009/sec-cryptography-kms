# audit-logging

`AuditLog.java`: an in-memory, HMAC-chained audit log, with `AuditLogTest.java`.

## Goal

Make an audit log tamper-evident: each entry carries an HMAC-SHA256 over its sequence number, its event text and the previous entry's MAC, so the entries form a chain.

## Run it

```
mvn -q -B test
java -cp target/classes lab.AuditLog
```

Expected: the tests pass (`Tests run: 4, Failures: 0, Errors: 0`, `BUILD SUCCESS` without `-q`). The demo prints `intact -> firstInvalid=-1` and then `edited -> firstInvalid=1`.

## What it proves

- An untouched three-entry log verifies: `firstInvalid()` returns -1.
- Editing entry 1 or removing it makes `firstInvalid()` return 1, the position where the chain breaks.
- An entry forged under a different key is rejected at its position, so rewriting the store without the HMAC key does not produce a consistent chain.

## Trade-offs

- It detects tampering but does not prevent it. Dropping entries from the end is invisible unless the latest MAC is stored elsewhere (an external witness, write-once storage or a signed checkpoint).
- Anyone holding the HMAC key can forge the whole log. For non-repudiation use asymmetric signatures with the key in KMS or an HSM.
- The store is a plain list with one writer: no concurrency, persistence or key rotation. `entries()` is deliberately mutable so tests can play the attacker.

## When not to use it

- When a managed append-only service (CloudTrail log file validation, immutable object storage, a ledger database) already gives you this.
- When you need legal-grade non-repudiation.
