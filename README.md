# plausiden-identity

A zero-knowledge identity verification engine that proves a person IS who they claim to be — without storing any personally identifiable information. Designed for voting systems, civic technology, and any application where one-person-one-identity must be cryptographically enforced while preserving privacy.

## The Problem

Identity verification in digital systems faces an impossible-seeming tradeoff: you need to prove someone is who they claim to be, prevent duplicate registrations, and detect impersonation — all without creating a honeypot of personally identifiable information that could be stolen, subpoenaed, or misused.

Existing systems either store PII in cleartext (creating attack targets), use weak verification that can be gamed (record lookups anyone can pass), or require centralized identity providers that become surveillance infrastructure. Vulnerable populations — voters, activists, whistleblowers — need identity verification that works without trusting any single party with their data.

## How It Works

plausiden-identity uses cryptographic commitment schemes and hash-based fingerprinting to verify identities without storing PII:

1. **Identity Commitments**: When a person verifies their identity, their attributes (name, DOB, document ID) are hashed through a BLAKE3 keyed commitment scheme with per-user salt. The commitment is unique to that person but reveals nothing about them. PII is zeroized from memory immediately after commitment generation.

2. **Nullifiers**: For each context (election, poll, etc.), the commitment generates a unique nullifier that prevents double-action without revealing which identity produced it. Different contexts produce different nullifiers — no cross-context correlation.

3. **Fraud Detection**: A multi-signal engine detects impersonation (document reuse), duplicate registration (fingerprint collision), evasion attempts (similarity matching), bulk fraud (IP clustering), and attribute drift (changing details between attempts).

4. **Graduated Lockdown**: When conflicts are detected, both parties are locked at an appropriate severity level (Soft → Hard → Permanent). Each level has specific resolution paths — from additional verification questions to photo ID upload to in-person appearance.

5. **Account Recovery**: Recovery codes (argon2id hashed, single-use) generated at verification time. Re-verification through commitment matching for "lost everything" scenarios. Admin-assisted recovery with full audit trail.

```
Identity Attributes (PII) ──→ Commitment (stored) ──→ Nullifier (per-context)
         │                          │
         │ zeroized                 │ compared against
         │ immediately              │ existing records
         ▼                          ▼
    Never stored              Fraud Detection
                              ├─ Document collision → HARD LOCK
                              ├─ Identity collision → HARD LOCK
                              ├─ Similar identity   → SOFT LOCK
                              ├─ IP clustering      → ALERT
                              └─ Attribute drift    → SOFT LOCK
```

## Current Status

| Component | Status | Tests |
|-----------|--------|-------|
| Identity commitments (BLAKE3 + SHA-512) | Working | 16 tests |
| Nullifiers (context-separated) | Working | 2 tests |
| Fraud detection engine | Working | 8 tests |
| Name similarity (Jaro-Winkler + phonetic) | Working | 12 tests |
| Lockdown protocol (graduated severity) | Working | 8 tests |
| Account recovery (argon2id codes) | Working | 11 tests |
| Property-based tests (proptest) | Planned | - |
| HTTP API (axum server) | Planned | - |
| Sacred.Vote integration | In progress | - |

## Quick Start

```bash
# Clone
git clone https://github.com/PlausiDen/plausiden-identity.git
cd plausiden-identity

# Run tests (60 tests)
cargo test

# Run with all warnings
cargo clippy -- -D warnings

# Build release
cargo build --release
```

## Usage

```rust
use plausiden_identity::*;

// Generate commitment from identity attributes
let attrs = IdentityAttributes {
    given_name: "John".into(),
    family_name: "Smith".into(),
    date_of_birth: "1990-01-15".into(),
    document_id: Some("DL123456".into()),
    document_type: Some("drivers_license".into()),
    extra_claims: vec![],
};
let salt = generate_salt();
let commitment = generate_commitment(&attrs, &salt);
let fingerprint = generate_fingerprint(&attrs);

// Generate nullifier for a specific election
let nullifier = generate_nullifier(&commitment, "election-2026");

// Run fraud detection
let engine = FraudEngine::new(FraudConfig::default());
let result = engine.check_conflicts(&store, "voter-hash", &attrs, Some("ip-hash"))?;
if !result.allow_verification {
    // Identity locked — show resolution instructions
    println!("{}", result.explanation);
}

// Generate recovery codes (show to user ONCE)
let (cleartext_codes, code_set) = generate_recovery_codes("voter-hash");
for code in &cleartext_codes {
    println!("Recovery code: {}", format_code_for_display(code));
}
// Store code_set in database (hashes only)
```

## The PlausiDen Ecosystem

plausiden-identity is part of the [PlausiDen](https://github.com/PlausiDen) ecosystem of privacy-preserving tools. It provides the identity layer for:

- **[Sacred.Vote](https://sacred.vote)** — Zero-trust cryptographic polling platform
- **PlausiDenOS** — Privacy-focused operating system
- Any application requiring one-person-one-identity without PII storage

## Security Model

Designed for state-level adversaries with source code access (AVP-2 methodology):

- **No PII stored**: Only cryptographic commitments and fingerprints persist
- **Memory safety**: All secrets zeroized after use (zeroize crate)
- **Timing resistance**: Constant-time comparison for all secret comparisons
- **Domain separation**: BLAKE3 keyed mode prevents cross-context correlation
- **Audited crypto**: Only SHA-512, BLAKE3, and argon2id — no custom cryptography
- **Multi-signal fraud**: No single detection bypass compromises the system

## License

BSL 1.1 with 4-year Apache 2.0 change date.
