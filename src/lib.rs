//! # plausiden-identity — Zero-Knowledge Identity Verification Engine
//!
//! Cryptographic identity verification with fraud detection, conflict resolution,
//! and account recovery. Designed for civic technology and voting systems where
//! one-person-one-identity must be enforced while preserving privacy.
//!
//! ## Core Capabilities
//!
//! - **Identity Commitments:** Bind a person to a unique cryptographic value
//!   without storing PII. Uses BLAKE3 keyed hashing with SHA-512 field-level
//!   pre-hashing for domain separation.
//!
//! - **Nullifiers:** Prevent double-action (e.g., double-voting) within a
//!   specific context without revealing the identity. Each identity produces
//!   a unique nullifier per context (election, poll, etc.).
//!
//! - **Fraud Detection:** Multi-signal engine that detects impersonation,
//!   duplicate registration, near-duplicate evasion, bulk fraud, attribute
//!   drift, and multi-state claims.
//!
//! - **Lockdown Protocol:** Graduated response (None → Soft → Hard → Permanent)
//!   with resolution paths (KBA, photo ID, in-person, admin review).
//!
//! - **Account Recovery:** Recovery codes (argon2id hashed, single-use),
//!   re-verification (commitment matching), and admin-assisted recovery.
//!
//! ## Architecture
//!
//! The engine is storage-agnostic: it operates on an `IdentityStore` trait.
//! Integrators implement this trait to connect their database (PostgreSQL,
//! SQLite, in-memory, etc.). This makes the engine portable across:
//! - Sacred.Vote (civic polling platform)
//! - PlausiDenOS (privacy-focused operating system)
//! - Any application requiring one-person-one-identity
//!
//! ## Security Model (AVP-2)
//!
//! Designed for state-level adversaries with source code access:
//! - Multiple independent fraud signals (no single point of evasion)
//! - Similarity matching catches name-variation evasion
//! - All secrets zeroized after use (zeroize crate)
//! - Constant-time comparison prevents timing attacks
//! - Argon2id for all stored secrets (recovery codes)
//! - BLAKE3 keyed mode for domain-separated hashing
//! - No PII persists — only commitments and fingerprints

pub mod commitment;
pub mod fraud;
pub mod lockdown;
pub mod recovery;
pub mod similarity;
pub mod types;

// Re-export primary types and functions for convenience
pub use commitment::{
    generate_commitment, generate_document_fingerprint, generate_fingerprint, generate_nullifier,
    generate_salt, verify_commitment,
};
pub use fraud::{FraudConfig, FraudEngine, IdentityRecord, IdentityStore};
pub use lockdown::{
    can_resolve, create_resolution_request, escalate_lockdown, resolution_instructions,
    resolve_lockdown, ResolutionMethod, ResolutionRequest, ResolutionStatus,
};
pub use recovery::{
    format_code_for_display, generate_recovery_codes, mark_code_used, remaining_codes,
    verify_recovery_code, verify_re_verification,
};
pub use similarity::{compare_identities, compare_names, SimilarityInterpretation, SimilarityResult};
pub use types::*;
