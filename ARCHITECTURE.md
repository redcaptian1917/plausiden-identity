# Architecture

## System Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                     plausiden-identity                        │
│                                                              │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────┐  │
│  │ commitment   │   │  similarity   │   │    recovery      │  │
│  │              │   │              │   │                  │  │
│  │ BLAKE3 keyed │   │ Jaro-Winkler │   │ Argon2id codes   │  │
│  │ SHA-512 pre  │   │ Levenshtein  │   │ Re-verification  │  │
│  │ Nullifiers   │   │ Phonetic     │   │ Admin-assisted   │  │
│  └──────┬───────┘   └──────┬───────┘   └────────┬─────────┘  │
│         │                  │                     │            │
│  ┌──────▼──────────────────▼─────────────────────▼─────────┐  │
│  │                    fraud engine                          │  │
│  │                                                         │  │
│  │  Check 1: Existing lockdown status                      │  │
│  │  Check 2: Document fingerprint collision                │  │
│  │  Check 3: Identity fingerprint collision                │  │
│  │  Check 4: Near-duplicate similarity                     │  │
│  │  Check 5: Attribute drift (re-verification)             │  │
│  │  Check 6: IP clustering (bulk fraud)                    │  │
│  └──────┬──────────────────────────────────────────────────┘  │
│         │                                                     │
│  ┌──────▼──────────────────────────────────────────────────┐  │
│  │                   lockdown protocol                     │  │
│  │                                                         │  │
│  │  None → Soft → Hard → Permanent                         │  │
│  │  Resolution: KBA | Photo ID | In-person | Admin         │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │              IdentityStore trait (you implement)         │  │
│  │                                                         │  │
│  │  PostgreSQL, SQLite, in-memory, etc.                    │  │
│  └─────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## Data Flow

```
User submits identity attributes (PII)
    │
    ▼
commitment.rs: generate_commitment(attrs, salt) → IdentityCommitment
commitment.rs: generate_fingerprint(attrs) → IdentityFingerprint
commitment.rs: generate_document_fingerprint() → DocumentFingerprint
    │
    │  PII zeroized here — never stored
    ▼
fraud.rs: check_conflicts(store, voter_hash, attrs, ip_hash)
    │
    ├─► Check existing lockdown → BLOCKED if Hard/Permanent
    ├─► Check document fingerprint → CRITICAL if collision
    ├─► Check identity fingerprint → HIGH if collision
    ├─► Check similarity → MEDIUM if near-match
    ├─► Check attribute drift → MEDIUM if changed
    └─► Check IP clustering → HIGH if bulk
    │
    ▼
ConflictCheckResult { allow_verification, signals, recommended_lockdown }
    │
    ├─ allow=true → proceed with verification, store record
    │                generate recovery codes, return to user
    │
    └─ allow=false → apply lockdown to BOTH parties
                     return resolution instructions
                     admin notified
```

## Threat Model

### In Scope

- **Identity theft**: Attacker uses victim's real identity to register
- **Duplicate registration**: Same person creates multiple accounts
- **Evasion**: Deliberate name/DOB variations to avoid detection
- **Bulk fraud**: Automated mass registration from single source
- **Credential sharing**: Multiple people using the same identity proof
- **Account takeover**: Attacker gains control of victim's voter code

### Out of Scope

- **Physical coercion**: Forcing someone to verify at gunpoint
- **Nation-state device compromise**: Keylogger capturing PII before hashing
- **Database compromise**: If the store is breached, only hashes are exposed

### Key Design Decisions

1. **BLAKE3 over SHA-256 for commitments**: BLAKE3 provides native keyed hashing (domain separation without HMAC overhead) and is faster on modern hardware.

2. **SHA-512 field-level pre-hashing**: Each attribute is individually SHA-512 hashed before BLAKE3 commitment. Prevents length-extension and field-boundary confusion attacks.

3. **Fingerprints are intentionally collision-prone**: Unlike commitments (salted, unique), fingerprints use normalized, unsalted inputs. This is by design — higher collision rates enable duplicate detection.

4. **Multiple similarity algorithms**: No single distance metric catches all evasion strategies. Jaro-Winkler handles typos, Levenshtein handles insertions, phonetic encoding handles sound-alikes, part reordering handles first/last swaps.

5. **Argon2id for recovery codes**: Memory-hard hashing prevents GPU/ASIC brute-force of the limited keyspace (31^8 ≈ 8.5×10^11 possibilities).

6. **Storage-agnostic trait**: The `IdentityStore` trait keeps the engine independent of any database. This enables use in PostgreSQL (Sacred.Vote), SQLite (PlausiDenOS), or in-memory (testing).
