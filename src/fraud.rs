//! Fraud detection engine for identity verification.
//!
//! Detects and prevents:
//! - **Impersonation:** Someone using another person's identity (document reuse)
//! - **Duplicate registration:** Same person registering under multiple voter codes
//! - **Near-duplicate:** Subtle name variations to evade duplicate detection
//! - **Bulk fraud:** Multiple identities verified from same source (IP/device)
//! - **Attribute drift:** Identity details changing between verification attempts
//! - **Multi-state claims:** Claiming residency in multiple states
//!
//! # Architecture
//!
//! The engine operates on an `IdentityStore` trait — it doesn't know about
//! databases or HTTP. Integrators implement the trait to connect their storage.
//! This keeps the engine portable across Sacred.Vote, PlausiDenOS, and any
//! future project.
//!
//! # Adversarial Perspective (AVP-2)
//!
//! An attacker with source code access knows every detection rule. Defense-in-depth:
//! - Multiple independent signals (fingerprint, document, IP, behavioral)
//! - Similarity matching catches evasion attempts (typos, name variations)
//! - IP clustering catches proxy/VPN bulk attacks
//! - Attribute drift catches credential sharing/swapping
//! - All signals logged for post-hoc forensic analysis even if not auto-locked

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::commitment::{generate_document_fingerprint, generate_fingerprint};
use crate::similarity::{compare_identities, SimilarityInterpretation};
use crate::types::*;

/// Trait for identity storage. Implementors connect the fraud engine to their
/// database, in-memory store, or any other persistence layer.
///
/// All methods return `Result` to allow for I/O errors from the backing store.
pub trait IdentityStore {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Look up an existing identity by voter hash.
    fn get_identity(&self, voter_hash: &str) -> Result<Option<IdentityRecord>, Self::Error>;

    /// Find all identities with a matching fingerprint (name + DOB hash).
    fn find_by_fingerprint(
        &self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<Vec<IdentityRecord>, Self::Error>;

    /// Find all identities with a matching document fingerprint.
    fn find_by_document(
        &self,
        doc_fingerprint: &DocumentFingerprint,
    ) -> Result<Vec<IdentityRecord>, Self::Error>;

    /// Count verification attempts from a given IP hash within a time window.
    fn count_verifications_from_ip(
        &self,
        ip_hash: &str,
        since: DateTime<Utc>,
    ) -> Result<u32, Self::Error>;

    /// Get the list of distinct voter hashes verified from an IP hash in a window.
    fn get_voter_hashes_from_ip(
        &self,
        ip_hash: &str,
        since: DateTime<Utc>,
    ) -> Result<Vec<String>, Self::Error>;

    /// Store a new identity record.
    fn store_identity(&mut self, record: IdentityRecord) -> Result<(), Self::Error>;

    /// Store a fraud signal.
    fn store_fraud_signal(&mut self, signal: FraudSignal) -> Result<(), Self::Error>;

    /// Apply a lockdown to a voter hash.
    fn apply_lockdown(
        &mut self,
        voter_hash: &str,
        level: LockdownLevel,
        reason: LockdownReason,
    ) -> Result<(), Self::Error>;

    /// Get the current lockdown level for a voter hash.
    fn get_lockdown_level(&self, voter_hash: &str) -> Result<LockdownLevel, Self::Error>;

    /// Store recovery codes for a voter.
    fn store_recovery_codes(&mut self, codes: RecoveryCodeSet) -> Result<(), Self::Error>;

    /// Get recovery codes for a voter.
    fn get_recovery_codes(&self, voter_hash: &str) -> Result<Option<RecoveryCodeSet>, Self::Error>;
}

/// An identity record as stored in the backing store.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IdentityRecord {
    pub voter_hash: String,
    pub commitment: IdentityCommitment,
    pub fingerprint: IdentityFingerprint,
    pub document_fingerprint: Option<DocumentFingerprint>,
    pub salt: Vec<u8>,
    pub lockdown_level: LockdownLevel,
    pub verification_method: VerificationMethod,
    pub verification_strength: VerificationStrength,
    pub ip_hash: Option<String>,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Normalized name (for similarity comparison in near-duplicate detection).
    /// This is a lossy normalization — cannot recover the original name.
    pub normalized_name: String,
    /// Date of birth (needed for similarity comparison).
    pub date_of_birth: String,
}

/// Configuration for the fraud detection engine.
#[derive(Debug, Clone)]
pub struct FraudConfig {
    /// Maximum number of distinct identities from one IP in a time window.
    pub max_identities_per_ip: u32,
    /// Time window for IP clustering detection (minutes).
    pub ip_window_minutes: u32,
    /// Similarity threshold for triggering a near-duplicate alert.
    pub similarity_threshold: f64,
    /// Whether to auto-lock on document fingerprint collision.
    pub auto_lock_document_collision: bool,
    /// Whether to auto-lock on identity fingerprint collision.
    pub auto_lock_identity_collision: bool,
    /// Whether to auto-lock on IP clustering.
    pub auto_lock_ip_clustering: bool,
}

impl Default for FraudConfig {
    fn default() -> Self {
        Self {
            max_identities_per_ip: 3,
            ip_window_minutes: 60,
            similarity_threshold: 0.85,
            auto_lock_document_collision: true,
            auto_lock_identity_collision: true,
            auto_lock_ip_clustering: false, // Alert only — could be shared network
        }
    }
}

/// The fraud detection engine. Stateless — all state is in the IdentityStore.
pub struct FraudEngine {
    pub config: FraudConfig,
}

impl FraudEngine {
    pub fn new(config: FraudConfig) -> Self {
        Self { config }
    }

    /// Run a comprehensive conflict check before allowing a verification to proceed.
    ///
    /// This is the main entry point. Call it with the attributes of the person
    /// being verified and the context (voter hash, IP, etc.). It returns a
    /// `ConflictCheckResult` that tells you whether to proceed, lock, or alert.
    ///
    /// # Arguments
    /// * `store` - The identity store implementation
    /// * `voter_hash` - The voter code hash of the person being verified
    /// * `attrs` - The identity attributes (will NOT be stored — only hashes)
    /// * `ip_hash` - Hash of the verifier's IP address
    ///
    /// # Returns
    /// A `ConflictCheckResult` with signals, recommended lockdown, and whether
    /// to allow the verification to proceed.
    pub fn check_conflicts<S: IdentityStore>(
        &self,
        store: &S,
        voter_hash: &str,
        attrs: &IdentityAttributes,
        ip_hash: Option<&str>,
    ) -> Result<ConflictCheckResult, S::Error> {
        let mut signals: Vec<FraudSignal> = Vec::new();
        let mut max_lockdown = LockdownLevel::None;
        let now = Utc::now();

        // ── Check 1: Is this voter already locked? ──────────────────────
        let current_lockdown = store.get_lockdown_level(voter_hash)?;
        if current_lockdown >= LockdownLevel::Hard {
            return Ok(ConflictCheckResult {
                has_conflicts: true,
                signals: vec![FraudSignal {
                    id: Uuid::new_v4(),
                    signal_type: FraudSignalType::LockedIdentityAccess,
                    severity: FraudSeverity::High,
                    voter_hash: voter_hash.to_string(),
                    related_voter_hash: None,
                    details: serde_json::json!({
                        "current_lockdown": format!("{:?}", current_lockdown),
                    }),
                    detected_at: now,
                    triggered_lockdown: false,
                }],
                recommended_lockdown: current_lockdown,
                allow_verification: false,
                explanation: "This identity is currently locked due to a security concern. Please contact support.".to_string(),
            });
        }

        // ── Check 2: Document fingerprint collision ─────────────────────
        if let (Some(doc_type), Some(doc_id)) = (&attrs.document_type, &attrs.document_id) {
            let doc_fp = generate_document_fingerprint(doc_type, doc_id);
            let existing = store.find_by_document(&doc_fp)?;

            for record in &existing {
                if record.voter_hash != voter_hash {
                    // CRITICAL: Same document used by different voter code
                    // This is either identity theft or someone sharing credentials
                    let signal = FraudSignal {
                        id: Uuid::new_v4(),
                        signal_type: FraudSignalType::DocumentReuse,
                        severity: FraudSeverity::Critical,
                        voter_hash: voter_hash.to_string(),
                        related_voter_hash: Some(record.voter_hash.clone()),
                        details: serde_json::json!({
                            "document_type": doc_type,
                            "existing_verified_at": record.verified_at.to_rfc3339(),
                        }),
                        detected_at: now,
                        triggered_lockdown: self.config.auto_lock_document_collision,
                    };
                    signals.push(signal);

                    if self.config.auto_lock_document_collision {
                        max_lockdown = max_lockdown.max(LockdownLevel::Hard);
                    }
                }
            }
        }

        // ── Check 3: Identity fingerprint collision ─────────────────────
        let fingerprint = generate_fingerprint(attrs);
        let fp_matches = store.find_by_fingerprint(&fingerprint)?;

        for record in &fp_matches {
            if record.voter_hash != voter_hash {
                // Same name + DOB hash, different voter code
                let signal = FraudSignal {
                    id: Uuid::new_v4(),
                    signal_type: FraudSignalType::DuplicateIdentity,
                    severity: FraudSeverity::High,
                    voter_hash: voter_hash.to_string(),
                    related_voter_hash: Some(record.voter_hash.clone()),
                    details: serde_json::json!({
                        "fingerprint_match": true,
                        "existing_verified_at": record.verified_at.to_rfc3339(),
                        "existing_method": record.verification_method,
                    }),
                    detected_at: now,
                    triggered_lockdown: self.config.auto_lock_identity_collision,
                };
                signals.push(signal);

                if self.config.auto_lock_identity_collision {
                    max_lockdown = max_lockdown.max(LockdownLevel::Hard);
                }
            }
        }

        // ── Check 4: Near-duplicate similarity check ────────────────────
        // This catches evasion: "Jon" vs "John", "SMITH" vs "Smyth", etc.
        // We check against ALL records from fingerprint matches AND a broader
        // set from the same DOB.
        {
            let full_name = format!("{} {}", attrs.given_name, attrs.family_name);
            for record in &fp_matches {
                if record.voter_hash == voter_hash {
                    continue;
                }
                let result = compare_identities(
                    &full_name,
                    &attrs.date_of_birth,
                    &record.normalized_name,
                    &record.date_of_birth,
                );

                if result.interpretation == SimilarityInterpretation::Suspicious
                    || result.interpretation == SimilarityInterpretation::SamePerson
                {
                    let signal = FraudSignal {
                        id: Uuid::new_v4(),
                        signal_type: FraudSignalType::SimilarIdentity,
                        severity: FraudSeverity::Medium,
                        voter_hash: voter_hash.to_string(),
                        related_voter_hash: Some(record.voter_hash.clone()),
                        details: serde_json::json!({
                            "name_score": result.name_score,
                            "overall_score": result.overall_score,
                            "dob_match": result.dob_match,
                            "interpretation": format!("{:?}", result.interpretation),
                        }),
                        detected_at: now,
                        triggered_lockdown: false,
                    };
                    signals.push(signal);

                    if result.interpretation == SimilarityInterpretation::SamePerson {
                        max_lockdown = max_lockdown.max(LockdownLevel::Soft);
                    }
                }
            }
        }

        // ── Check 5: Attribute drift (re-verification with different details) ──
        if let Some(existing) = store.get_identity(voter_hash)? {
            // Same voter hash is re-verifying — check if attributes changed
            let new_fp = generate_fingerprint(attrs);
            if existing.fingerprint != new_fp {
                let signal = FraudSignal {
                    id: Uuid::new_v4(),
                    signal_type: FraudSignalType::AttributeDrift,
                    severity: FraudSeverity::Medium,
                    voter_hash: voter_hash.to_string(),
                    related_voter_hash: None,
                    details: serde_json::json!({
                        "previous_verified_at": existing.verified_at.to_rfc3339(),
                        "fingerprint_changed": true,
                    }),
                    detected_at: now,
                    triggered_lockdown: false,
                };
                signals.push(signal);
                max_lockdown = max_lockdown.max(LockdownLevel::Soft);
            }
        }

        // ── Check 6: IP clustering ─────────────────────────────────────
        if let Some(ip) = ip_hash {
            let window_start =
                now - Duration::minutes(self.config.ip_window_minutes as i64);
            let voter_hashes = store.get_voter_hashes_from_ip(ip, window_start)?;

            // Count distinct voter hashes (excluding current)
            let distinct_others: Vec<_> = voter_hashes
                .iter()
                .filter(|h| h.as_str() != voter_hash)
                .collect();

            if distinct_others.len() as u32 >= self.config.max_identities_per_ip {
                let signal = FraudSignal {
                    id: Uuid::new_v4(),
                    signal_type: FraudSignalType::BulkVerification,
                    severity: FraudSeverity::High,
                    voter_hash: voter_hash.to_string(),
                    related_voter_hash: None,
                    details: serde_json::json!({
                        "ip_hash": ip,
                        "distinct_identities": distinct_others.len() + 1,
                        "window_minutes": self.config.ip_window_minutes,
                    }),
                    detected_at: now,
                    triggered_lockdown: self.config.auto_lock_ip_clustering,
                };
                signals.push(signal);

                if self.config.auto_lock_ip_clustering {
                    max_lockdown = max_lockdown.max(LockdownLevel::Soft);
                }
            }
        }

        // ── Compile result ─────────────────────────────────────────────
        let has_conflicts = !signals.is_empty();
        let allow_verification = max_lockdown < LockdownLevel::Hard;

        let explanation = if !has_conflicts {
            "No conflicts detected.".to_string()
        } else if !allow_verification {
            format!(
                "Identity verification blocked: {} conflict(s) detected. Both identities have been locked pending resolution.",
                signals.len()
            )
        } else {
            format!(
                "{} potential issue(s) detected. Verification may proceed with additional scrutiny.",
                signals.len()
            )
        };

        Ok(ConflictCheckResult {
            has_conflicts,
            signals,
            recommended_lockdown: max_lockdown,
            allow_verification,
            explanation,
        })
    }

    /// Record a KBA failure and potentially trigger a lockdown.
    pub fn record_kba_failure<S: IdentityStore>(
        &self,
        store: &mut S,
        voter_hash: &str,
        attempts: u32,
        max_attempts: u32,
    ) -> Result<Option<FraudSignal>, S::Error> {
        if attempts >= max_attempts {
            let signal = FraudSignal {
                id: Uuid::new_v4(),
                signal_type: FraudSignalType::KbaFailure,
                severity: FraudSeverity::Medium,
                voter_hash: voter_hash.to_string(),
                related_voter_hash: None,
                details: serde_json::json!({
                    "attempts": attempts,
                    "max_attempts": max_attempts,
                }),
                detected_at: Utc::now(),
                triggered_lockdown: true,
            };
            store.store_fraud_signal(signal.clone())?;
            store.apply_lockdown(
                voter_hash,
                LockdownLevel::Soft,
                LockdownReason::KbaExhausted {
                    voter_hash: voter_hash.to_string(),
                    attempts,
                },
            )?;
            Ok(Some(signal))
        } else {
            Ok(None)
        }
    }

    /// Lock down both parties in a document collision.
    /// Both voter hashes are hard-locked until resolution.
    pub fn lockdown_document_collision<S: IdentityStore>(
        &self,
        store: &mut S,
        existing_voter_hash: &str,
        new_voter_hash: &str,
    ) -> Result<(), S::Error> {
        let reason = LockdownReason::DocumentCollision {
            existing_voter_hash: existing_voter_hash.to_string(),
            new_voter_hash: new_voter_hash.to_string(),
        };
        store.apply_lockdown(existing_voter_hash, LockdownLevel::Hard, reason.clone())?;
        store.apply_lockdown(new_voter_hash, LockdownLevel::Hard, reason)?;
        Ok(())
    }

    /// Lock down both parties in an identity fingerprint collision.
    pub fn lockdown_identity_collision<S: IdentityStore>(
        &self,
        store: &mut S,
        existing_voter_hash: &str,
        new_voter_hash: &str,
        similarity_score: f64,
    ) -> Result<(), S::Error> {
        let reason = LockdownReason::IdentityCollision {
            existing_voter_hash: existing_voter_hash.to_string(),
            new_voter_hash: new_voter_hash.to_string(),
            similarity_score,
        };
        store.apply_lockdown(existing_voter_hash, LockdownLevel::Hard, reason.clone())?;
        store.apply_lockdown(new_voter_hash, LockdownLevel::Hard, reason)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::{generate_commitment, generate_salt};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory identity store for testing.
    struct MockStore {
        identities: HashMap<String, IdentityRecord>,
        fraud_signals: Vec<FraudSignal>,
        lockdowns: HashMap<String, (LockdownLevel, LockdownReason)>,
        ip_verifications: Vec<(String, String, DateTime<Utc>)>, // (ip_hash, voter_hash, time)
        recovery_codes: HashMap<String, RecoveryCodeSet>,
    }

    #[derive(Debug)]
    struct MockError(String);
    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "MockError: {}", self.0)
        }
    }
    impl std::error::Error for MockError {}

    impl MockStore {
        fn new() -> Self {
            Self {
                identities: HashMap::new(),
                fraud_signals: Vec::new(),
                lockdowns: HashMap::new(),
                ip_verifications: Vec::new(),
                recovery_codes: HashMap::new(),
            }
        }

        fn add_identity(&mut self, record: IdentityRecord) {
            self.identities.insert(record.voter_hash.clone(), record);
        }

        fn add_ip_verification(&mut self, ip_hash: &str, voter_hash: &str) {
            self.ip_verifications.push((
                ip_hash.to_string(),
                voter_hash.to_string(),
                Utc::now(),
            ));
        }
    }

    impl IdentityStore for MockStore {
        type Error = MockError;

        fn get_identity(&self, voter_hash: &str) -> Result<Option<IdentityRecord>, MockError> {
            Ok(self.identities.get(voter_hash).cloned())
        }

        fn find_by_fingerprint(
            &self,
            fingerprint: &IdentityFingerprint,
        ) -> Result<Vec<IdentityRecord>, MockError> {
            Ok(self
                .identities
                .values()
                .filter(|r| r.fingerprint == *fingerprint)
                .cloned()
                .collect())
        }

        fn find_by_document(
            &self,
            doc_fp: &DocumentFingerprint,
        ) -> Result<Vec<IdentityRecord>, MockError> {
            Ok(self
                .identities
                .values()
                .filter(|r| r.document_fingerprint.as_ref() == Some(doc_fp))
                .cloned()
                .collect())
        }

        fn count_verifications_from_ip(
            &self,
            ip_hash: &str,
            since: DateTime<Utc>,
        ) -> Result<u32, MockError> {
            Ok(self
                .ip_verifications
                .iter()
                .filter(|(ip, _, t)| ip == ip_hash && *t >= since)
                .count() as u32)
        }

        fn get_voter_hashes_from_ip(
            &self,
            ip_hash: &str,
            since: DateTime<Utc>,
        ) -> Result<Vec<String>, MockError> {
            Ok(self
                .ip_verifications
                .iter()
                .filter(|(ip, _, t)| ip == ip_hash && *t >= since)
                .map(|(_, vh, _)| vh.clone())
                .collect())
        }

        fn store_identity(&mut self, record: IdentityRecord) -> Result<(), MockError> {
            self.identities.insert(record.voter_hash.clone(), record);
            Ok(())
        }

        fn store_fraud_signal(&mut self, signal: FraudSignal) -> Result<(), MockError> {
            self.fraud_signals.push(signal);
            Ok(())
        }

        fn apply_lockdown(
            &mut self,
            voter_hash: &str,
            level: LockdownLevel,
            reason: LockdownReason,
        ) -> Result<(), MockError> {
            self.lockdowns
                .insert(voter_hash.to_string(), (level, reason));
            Ok(())
        }

        fn get_lockdown_level(&self, voter_hash: &str) -> Result<LockdownLevel, MockError> {
            Ok(self
                .lockdowns
                .get(voter_hash)
                .map(|(l, _)| *l)
                .unwrap_or(LockdownLevel::None))
        }

        fn store_recovery_codes(&mut self, codes: RecoveryCodeSet) -> Result<(), MockError> {
            self.recovery_codes
                .insert(codes.voter_hash.clone(), codes);
            Ok(())
        }

        fn get_recovery_codes(
            &self,
            voter_hash: &str,
        ) -> Result<Option<RecoveryCodeSet>, MockError> {
            Ok(self.recovery_codes.get(voter_hash).cloned())
        }
    }

    fn make_attrs(given: &str, family: &str, dob: &str) -> IdentityAttributes {
        IdentityAttributes {
            given_name: given.to_string(),
            family_name: family.to_string(),
            date_of_birth: dob.to_string(),
            document_id: None,
            document_type: None,
            extra_claims: vec![],
        }
    }

    fn make_record(
        voter_hash: &str,
        attrs: &IdentityAttributes,
    ) -> IdentityRecord {
        let salt = generate_salt();
        let commitment = generate_commitment(attrs, &salt);
        let fingerprint = crate::commitment::generate_fingerprint(attrs);
        IdentityRecord {
            voter_hash: voter_hash.to_string(),
            commitment,
            fingerprint,
            document_fingerprint: None,
            salt: salt.to_vec(),
            lockdown_level: LockdownLevel::None,
            verification_method: VerificationMethod::RegistrationKba,
            verification_strength: VerificationStrength::KnowledgeBased,
            ip_hash: None,
            verified_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(365),
            normalized_name: format!("{} {}", attrs.given_name.to_lowercase(), attrs.family_name.to_lowercase()),
            date_of_birth: attrs.date_of_birth.clone(),
        }
    }

    #[test]
    fn no_conflicts_for_new_identity() {
        let store = MockStore::new();
        let engine = FraudEngine::new(FraudConfig::default());
        let attrs = make_attrs("John", "Smith", "1990-01-15");

        let result = engine
            .check_conflicts(&store, "voter-abc", &attrs, None)
            .unwrap();

        assert!(!result.has_conflicts);
        assert!(result.allow_verification);
        assert_eq!(result.recommended_lockdown, LockdownLevel::None);
    }

    #[test]
    fn detects_identity_fingerprint_collision() {
        let mut store = MockStore::new();
        let engine = FraudEngine::new(FraudConfig::default());

        // First person verifies
        let attrs = make_attrs("John", "Smith", "1990-01-15");
        let record = make_record("voter-aaa", &attrs);
        store.add_identity(record);

        // Second person tries with same name + DOB but different voter code
        let result = engine
            .check_conflicts(&store, "voter-bbb", &attrs, None)
            .unwrap();

        assert!(result.has_conflicts);
        assert!(!result.allow_verification); // Hard lock
        assert!(result.signals.iter().any(|s| s.signal_type == FraudSignalType::DuplicateIdentity));
    }

    #[test]
    fn allows_re_verification_by_same_voter() {
        let mut store = MockStore::new();
        let engine = FraudEngine::new(FraudConfig::default());

        let attrs = make_attrs("John", "Smith", "1990-01-15");
        let record = make_record("voter-aaa", &attrs);
        store.add_identity(record);

        // Same voter re-verifies — should be fine
        let result = engine
            .check_conflicts(&store, "voter-aaa", &attrs, None)
            .unwrap();

        assert!(!result.has_conflicts);
        assert!(result.allow_verification);
    }

    #[test]
    fn detects_document_reuse() {
        let mut store = MockStore::new();
        let engine = FraudEngine::new(FraudConfig::default());

        let mut attrs1 = make_attrs("John", "Smith", "1990-01-15");
        attrs1.document_id = Some("DL123456".to_string());
        attrs1.document_type = Some("drivers_license".to_string());
        let mut record = make_record("voter-aaa", &attrs1);
        record.document_fingerprint =
            Some(generate_document_fingerprint("drivers_license", "DL123456"));
        store.add_identity(record);

        // Different person uses same DL number
        let mut attrs2 = make_attrs("Jane", "Doe", "1985-03-20");
        attrs2.document_id = Some("DL123456".to_string());
        attrs2.document_type = Some("drivers_license".to_string());

        let result = engine
            .check_conflicts(&store, "voter-bbb", &attrs2, None)
            .unwrap();

        assert!(result.has_conflicts);
        assert!(!result.allow_verification);
        assert!(result.signals.iter().any(|s| s.signal_type == FraudSignalType::DocumentReuse));
        assert!(result.signals.iter().any(|s| s.severity == FraudSeverity::Critical));
    }

    #[test]
    fn detects_ip_clustering() {
        let mut store = MockStore::new();
        let mut config = FraudConfig::default();
        config.max_identities_per_ip = 2;
        config.auto_lock_ip_clustering = true;
        let engine = FraudEngine::new(config);

        // Three different voters from same IP
        store.add_ip_verification("ip-hash-1", "voter-aaa");
        store.add_ip_verification("ip-hash-1", "voter-bbb");
        store.add_ip_verification("ip-hash-1", "voter-ccc");

        let attrs = make_attrs("New", "Person", "2000-01-01");
        let result = engine
            .check_conflicts(&store, "voter-ddd", &attrs, Some("ip-hash-1"))
            .unwrap();

        assert!(result.has_conflicts);
        assert!(result.signals.iter().any(|s| s.signal_type == FraudSignalType::BulkVerification));
    }

    #[test]
    fn detects_attribute_drift() {
        let mut store = MockStore::new();
        let engine = FraudEngine::new(FraudConfig::default());

        // Voter verified with one name
        let attrs1 = make_attrs("John", "Smith", "1990-01-15");
        let record = make_record("voter-aaa", &attrs1);
        store.add_identity(record);

        // Same voter tries to verify with different name
        let attrs2 = make_attrs("Jonathan", "Smith", "1990-01-15");
        let result = engine
            .check_conflicts(&store, "voter-aaa", &attrs2, None)
            .unwrap();

        assert!(result.has_conflicts);
        assert!(result.signals.iter().any(|s| s.signal_type == FraudSignalType::AttributeDrift));
    }

    #[test]
    fn locked_identity_cannot_verify() {
        let mut store = MockStore::new();
        let engine = FraudEngine::new(FraudConfig::default());

        store.apply_lockdown(
            "voter-aaa",
            LockdownLevel::Hard,
            LockdownReason::AdminAction {
                admin_id: "admin".to_string(),
                reason: "test".to_string(),
            },
        ).unwrap();

        let attrs = make_attrs("John", "Smith", "1990-01-15");
        let result = engine
            .check_conflicts(&store, "voter-aaa", &attrs, None)
            .unwrap();

        assert!(!result.allow_verification);
        assert!(result.signals.iter().any(|s| s.signal_type == FraudSignalType::LockedIdentityAccess));
    }

    #[test]
    fn kba_failure_triggers_soft_lock() {
        let mut store = MockStore::new();
        let engine = FraudEngine::new(FraudConfig::default());

        let signal = engine
            .record_kba_failure(&mut store, "voter-aaa", 3, 3)
            .unwrap();

        assert!(signal.is_some());
        assert_eq!(
            store.get_lockdown_level("voter-aaa").unwrap(),
            LockdownLevel::Soft
        );
    }

    #[test]
    fn different_people_no_conflict() {
        let mut store = MockStore::new();
        let engine = FraudEngine::new(FraudConfig::default());

        let attrs1 = make_attrs("John", "Smith", "1990-01-15");
        let record = make_record("voter-aaa", &attrs1);
        store.add_identity(record);

        let attrs2 = make_attrs("Maria", "Garcia", "1985-07-22");
        let result = engine
            .check_conflicts(&store, "voter-bbb", &attrs2, None)
            .unwrap();

        assert!(!result.has_conflicts);
        assert!(result.allow_verification);
    }
}
