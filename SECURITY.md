# Security Policy

## Reporting Vulnerabilities

Report security vulnerabilities to **security@sacredvote.org**.

Expected response time: 48 hours for initial acknowledgment, 7 days for assessment.

## Scope

This policy covers the plausiden-identity crate and its cryptographic primitives:
- Identity commitment scheme (BLAKE3 + SHA-512)
- Fraud detection engine
- Recovery code generation and verification (argon2id)
- Similarity matching algorithms

## Cryptographic Guarantees

- All hashing uses audited crates: sha2, blake3, argon2
- No custom cryptography
- All secret material zeroized after use
- Constant-time comparison for all secret values
