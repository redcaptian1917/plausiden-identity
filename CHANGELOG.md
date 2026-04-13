# Changelog

## [0.1.0] - 2026-04-13

### Added
- Identity commitment scheme (BLAKE3 keyed + SHA-512 field pre-hashing)
- Nullifier generation (context-separated, per-identity)
- Identity fingerprinting (normalized, unsalted, for duplicate detection)
- Document fingerprinting (exact-match deduplication)
- Fraud detection engine with 6 independent signal checks
- Name similarity engine (Jaro-Winkler + Levenshtein + phonetic + part reordering)
- Graduated lockdown protocol (None → Soft → Hard → Permanent)
- Resolution request system (KBA, photo ID, in-person, admin review)
- Account recovery codes (argon2id hashed, single-use, 8 codes per registration)
- Re-verification through commitment matching
- IdentityStore trait for storage-agnostic integration
- 60 unit tests across all modules
- Criterion benchmarks for commitment generation
