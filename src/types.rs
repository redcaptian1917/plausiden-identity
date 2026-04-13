//! Core types for the plausiden-identity engine.
//!
//! All types are designed to be ZK-friendly: identity data flows through
//! hash functions before storage, ensuring PII never persists in cleartext.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

/// A 64-byte identity commitment — the cryptographic binding of a person
/// to a unique value without revealing who they are.
///
/// Computed as: `BLAKE3(SHA-512(given_name) || SHA-512(family_name) || SHA-512(dob) || SHA-512(document_hash) || salt)`
///
/// This is a one-way function: knowing the commitment reveals nothing
/// about the person. But the same person always produces the same commitment
/// (given the same salt), enabling duplicate detection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityCommitment(pub String);

impl IdentityCommitment {
    /// Returns the hex-encoded commitment string.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// A nullifier — a value unique per identity per context that prevents
/// double-action (e.g., double-voting) without revealing the identity.
///
/// Computed as: `BLAKE3(commitment || domain_separator || context_id)`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nullifier(pub String);

impl Nullifier {
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// An identity fingerprint — a less-salted hash used for fuzzy duplicate
/// detection. Intentionally has higher collision probability than commitments
/// to catch near-duplicates.
///
/// Computed as: `BLAKE3(normalize(given_name) || normalize(family_name) || dob)`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityFingerprint(pub String);

impl IdentityFingerprint {
    /// Returns the hex-encoded fingerprint string.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// A document fingerprint — hash of the identifying document (DL number, etc.).
/// Exact match only; no fuzzy matching.
///
/// Computed as: `BLAKE3(document_type || document_id)`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DocumentFingerprint(pub String);

impl DocumentFingerprint {
    /// Returns the hex-encoded fingerprint string.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// Raw identity attributes used as input to commitment generation.
/// MUST be zeroized after commitment is computed — never stored.
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct IdentityAttributes {
    pub given_name: String,
    pub family_name: String,
    /// Format: YYYY-MM-DD
    pub date_of_birth: String,
    /// Optional document ID (DL number, passport number, etc.)
    /// If provided, generates a DocumentFingerprint for exact-match dedup.
    pub document_id: Option<String>,
    /// Optional document type (e.g., "drivers_license", "passport")
    pub document_type: Option<String>,
    /// Additional verified attributes (party, county, etc.) for KBA
    pub extra_claims: Vec<(String, String)>,
}

/// Lockdown severity levels. Once escalated, can only be de-escalated
/// by a higher authority (admin > automated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockdownLevel {
    /// Normal operation — no restrictions.
    None = 0,
    /// Suspicious activity detected — requires additional verification step.
    /// Example: similar name+DOB to existing identity.
    Soft = 1,
    /// Confirmed conflict — account frozen until resolution.
    /// Example: same document used by different voter codes.
    Hard = 2,
    /// Confirmed fraud — permanent ban. Only admin can lift.
    Permanent = 3,
}

/// Reasons an identity can be locked down.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockdownReason {
    /// Same document fingerprint used by a different voter code.
    DocumentCollision {
        existing_voter_hash: String,
        new_voter_hash: String,
    },
    /// Same identity fingerprint (name + DOB) used by a different voter code.
    IdentityCollision {
        existing_voter_hash: String,
        new_voter_hash: String,
        similarity_score: f64,
    },
    /// Multiple different identities verified from the same IP in a short window.
    IpClustering {
        ip_hash: String,
        identity_count: u32,
        window_minutes: u32,
    },
    /// KBA challenge failed 3 times — likely not the real person.
    KbaExhausted {
        voter_hash: String,
        attempts: u32,
    },
    /// Same voter code attempted with different identity attributes.
    AttributeMismatch {
        voter_hash: String,
        field: String,
    },
    /// Multi-state claim within 12 months.
    MultiStateClaim {
        voter_hash: String,
        states: Vec<String>,
    },
    /// Admin-initiated lockdown.
    AdminAction {
        admin_id: String,
        reason: String,
    },
}

/// The status of an identity in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityStatus {
    pub voter_hash: String,
    pub commitment: IdentityCommitment,
    pub fingerprint: IdentityFingerprint,
    pub document_fingerprint: Option<DocumentFingerprint>,
    pub lockdown_level: LockdownLevel,
    pub lockdown_reason: Option<LockdownReason>,
    pub verification_method: VerificationMethod,
    pub verification_strength: VerificationStrength,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub recovery_codes_generated: bool,
}

/// How the identity was verified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    /// Mobile Driver's License (ISO 18013-5) — cryptographic
    Mdl,
    /// Government portal login via zkTLS — cryptographic
    GovPortalZktls,
    /// Voter registration lookup + KBA challenge — knowledge-based
    RegistrationKba,
    /// Voter registration lookup only — record check
    RegistrationOnly,
    /// Photo ID upload + liveness check — visual
    PhotoId,
    /// In-person verification — physical
    InPerson,
    /// Recovery re-verification
    Recovery,
}

/// Strength tiers for verification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStrength {
    /// Record check only — weakest. Anyone who knows the details can pass.
    RecordCheck = 0,
    /// Knowledge-based — medium. Must know details not provided as input.
    KnowledgeBased = 1,
    /// Visual — strong. Photo ID + liveness check.
    Visual = 2,
    /// Cryptographic — strongest. mDL, gov portal login, hardware credential.
    Cryptographic = 3,
}

/// Fraud signal detected during verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudSignal {
    pub id: Uuid,
    pub signal_type: FraudSignalType,
    pub severity: FraudSeverity,
    pub voter_hash: String,
    pub related_voter_hash: Option<String>,
    pub details: serde_json::Value,
    pub detected_at: DateTime<Utc>,
    /// Whether this signal triggered a lockdown.
    pub triggered_lockdown: bool,
}

/// Types of fraud signals the engine can detect.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FraudSignalType {
    /// Same document, different person
    DocumentReuse,
    /// Same person, different voter codes (duplicate registration)
    DuplicateIdentity,
    /// Similar identity attributes (near-duplicate)
    SimilarIdentity,
    /// Multiple identities from same source (IP, device)
    BulkVerification,
    /// Attributes changed between verification attempts
    AttributeDrift,
    /// KBA challenge failed repeatedly
    KbaFailure,
    /// Multiple states claimed in short period
    MultiState,
    /// Verification attempt on locked identity
    LockedIdentityAccess,
}

/// Severity levels for fraud signals.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FraudSeverity {
    /// Informational — logged but no action taken.
    Info = 0,
    /// Low — soft lock, require additional step.
    Low = 1,
    /// Medium — hard lock one or both identities.
    Medium = 2,
    /// High — hard lock both + immediate admin alert.
    High = 3,
    /// Critical — permanent lock + law enforcement referral.
    Critical = 4,
}

/// A recovery code — generated at verification time, stored as argon2 hash.
/// The user sees the cleartext once and must store it securely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodeSet {
    pub voter_hash: String,
    /// Argon2 hashes of the recovery codes (NOT the codes themselves).
    pub code_hashes: Vec<String>,
    /// How many codes have been used.
    pub used_count: u32,
    pub generated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Result of a conflict check — what the fraud engine found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictCheckResult {
    /// Whether any conflicts were detected.
    pub has_conflicts: bool,
    /// Fraud signals detected.
    pub signals: Vec<FraudSignal>,
    /// Recommended lockdown level.
    pub recommended_lockdown: LockdownLevel,
    /// Whether verification should proceed.
    pub allow_verification: bool,
    /// Human-readable explanation.
    pub explanation: String,
}
