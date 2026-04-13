//! Adversarial tests — simulating specific attack scenarios.
//!
//! Each test represents a real attack an adversary might try against the
//! identity system. The tests verify that the engine detects and blocks
//! each attack vector.

use plausiden_identity::*;

fn make_attrs(given: &str, family: &str, dob: &str) -> types::IdentityAttributes {
    types::IdentityAttributes {
        given_name: given.to_string(),
        family_name: family.to_string(),
        date_of_birth: dob.to_string(),
        document_id: None,
        document_type: None,
        extra_claims: vec![],
    }
}

// ── Attack: Name variation evasion ─────────────────────────────────────

#[test]
fn attack_typo_evasion() {
    // Attacker tries "Jon" instead of "John" to evade duplicate detection.
    // The similarity engine should catch this.
    let result = compare_identities(
        "John Smith", "1990-01-15",
        "Jon Smith", "1990-01-15",
    );
    assert_ne!(
        result.interpretation,
        SimilarityInterpretation::Different,
        "Typo evasion 'Jon' vs 'John' should be detected"
    );
}

#[test]
fn attack_case_evasion() {
    // Attacker tries different capitalization.
    // Fingerprints are case-insensitive by design.
    let a1 = make_attrs("JOHN", "SMITH", "1990-01-15");
    let a2 = make_attrs("john", "smith", "1990-01-15");
    let fp1 = generate_fingerprint(&a1);
    let fp2 = generate_fingerprint(&a2);
    assert_eq!(fp1, fp2, "Case variation should produce same fingerprint");
}

#[test]
fn attack_suffix_evasion() {
    // Attacker adds "Jr" to their name.
    let a1 = make_attrs("John", "Smith", "1990-01-15");
    let a2 = make_attrs("John", "Smith Jr", "1990-01-15");
    let fp1 = generate_fingerprint(&a1);
    let fp2 = generate_fingerprint(&a2);
    assert_eq!(fp1, fp2, "Name suffix 'Jr' should be stripped in fingerprint");
}

#[test]
fn attack_middle_name_evasion() {
    // Attacker adds a middle name to differentiate.
    // Similarity engine should still catch this.
    let result = compare_identities(
        "John Smith", "1990-01-15",
        "John Michael Smith", "1990-01-15",
    );
    assert!(
        result.name_score >= 0.70,
        "Middle name addition should still have high similarity: {}",
        result.name_score
    );
}

#[test]
fn attack_name_reorder_evasion() {
    // Attacker puts last name first.
    let result = compare_identities(
        "John Smith", "1990-01-15",
        "Smith John", "1990-01-15",
    );
    assert!(
        result.name_score >= 0.80,
        "Name reordering should be detected: {}",
        result.name_score
    );
}

// ── Attack: Document sharing ───────────────────────────────────────────

#[test]
fn attack_shared_document() {
    // Two people share the same DL number (one real, one fake/stolen).
    let doc_fp1 = generate_document_fingerprint("drivers_license", "DL999999");
    let doc_fp2 = generate_document_fingerprint("drivers_license", "DL999999");
    assert_eq!(doc_fp1, doc_fp2, "Same document must produce same fingerprint");

    // Different document number = different fingerprint
    let doc_fp3 = generate_document_fingerprint("drivers_license", "DL000001");
    assert_ne!(doc_fp1, doc_fp3, "Different document must produce different fingerprint");
}

// ── Attack: Commitment forgery ─────────────────────────────────────────

#[test]
fn attack_commitment_without_salt() {
    // Attacker doesn't know the salt and tries to forge a commitment.
    let attrs = make_attrs("John", "Smith", "1990-01-15");
    let real_salt = generate_salt();
    let real_commitment = generate_commitment(&attrs, &real_salt);

    // Attacker tries with a different salt
    let fake_salt = [0u8; 32];
    let fake_commitment = generate_commitment(&attrs, &fake_salt);

    assert_ne!(
        real_commitment, fake_commitment,
        "Different salt must produce different commitment"
    );
    assert!(
        !verify_commitment(&attrs, &fake_salt, &real_commitment),
        "Wrong salt must fail verification"
    );
}

// ── Attack: Cross-context correlation ──────────────────────────────────

#[test]
fn attack_cross_election_correlation() {
    // Two elections should produce different nullifiers for the same person,
    // preventing correlation of votes across elections.
    let attrs = make_attrs("John", "Smith", "1990-01-15");
    let salt = generate_salt();
    let commitment = generate_commitment(&attrs, &salt);

    let n1 = generate_nullifier(&commitment, "election-2026-primary");
    let n2 = generate_nullifier(&commitment, "election-2026-general");

    assert_ne!(n1, n2, "Nullifiers must differ across elections");
}

// ── Attack: Recovery code brute force ──────────────────────────────────

#[test]
fn attack_recovery_code_keyspace() {
    // Recovery codes use 31 characters (unambiguous set) at 8 chars = 31^8 ≈ 8.5×10^11
    // Verify that the charset is actually restricted
    let (codes, _) = generate_recovery_codes("voter-test");
    let charset: Vec<char> = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ".chars().collect();

    for code in &codes {
        for c in code.chars() {
            assert!(
                charset.contains(&c),
                "Recovery code contains forbidden character: '{}' in code '{}'",
                c, code
            );
        }
        // No 0, O, 1, I, l (ambiguous characters)
        assert!(!code.contains('0'), "Code contains ambiguous '0'");
        assert!(!code.contains('O'), "Code contains ambiguous 'O'");
        assert!(!code.contains('1'), "Code contains ambiguous '1'");
        assert!(!code.contains('I'), "Code contains ambiguous 'I'");
    }
}

// ── Attack: Nullifier reuse detection ──────────────────────────────────

#[test]
fn attack_double_voting_detected() {
    // If the same person votes twice in the same election, their nullifiers
    // will be identical. The system stores nullifiers and rejects duplicates.
    let attrs = make_attrs("John", "Smith", "1990-01-15");
    let salt = generate_salt();
    let commitment = generate_commitment(&attrs, &salt);

    let n1 = generate_nullifier(&commitment, "election-2026");
    let n2 = generate_nullifier(&commitment, "election-2026");

    assert_eq!(n1, n2, "Same person + same election = same nullifier (detectable)");
}

// ── Attack: Phonetic evasion ───────────────────────────────────────────

#[test]
fn attack_phonetic_evasion() {
    // Attacker tries "Stephen" vs "Steven" — should still be caught.
    let result = compare_identities(
        "Steven Jones", "1990-01-15",
        "Stephen Jones", "1990-01-15",
    );
    assert!(
        result.name_score >= 0.85,
        "Phonetic evasion 'Steven' vs 'Stephen' should be caught: {}",
        result.name_score
    );
}

// ── Attack: Empty/minimal input ────────────────────────────────────────

#[test]
fn attack_empty_name() {
    // Attacker submits empty name fields.
    let a1 = make_attrs("", "", "1990-01-15");
    let a2 = make_attrs("John", "Smith", "1990-01-15");
    let fp1 = generate_fingerprint(&a1);
    let fp2 = generate_fingerprint(&a2);
    assert_ne!(fp1, fp2, "Empty name must not match real name");
}

#[test]
fn attack_single_char_name() {
    // Attacker submits single-character names.
    let a1 = make_attrs("J", "S", "1990-01-15");
    let a2 = make_attrs("John", "Smith", "1990-01-15");
    let fp1 = generate_fingerprint(&a1);
    let fp2 = generate_fingerprint(&a2);
    assert_ne!(fp1, fp2, "Single-char name must not match full name");
}

// ── Attack: Unicode/encoding tricks ────────────────────────────────────

#[test]
fn attack_unicode_homograph() {
    // Attacker uses unicode characters that look like ASCII.
    // The normalize function strips non-ASCII, so these should differ.
    let a1 = make_attrs("John", "Smith", "1990-01-15");
    // Using regular ASCII since the fingerprint strips non-alpha
    let a2 = make_attrs("J0hn", "Sm1th", "1990-01-15"); // 0 and 1 instead of o and i
    let fp1 = generate_fingerprint(&a1);
    let fp2 = generate_fingerprint(&a2);
    // After stripping non-alpha: "jhn" vs "john" — different
    assert_ne!(fp1, fp2, "Homograph attack should not produce matching fingerprint");
}

// ── Lockdown ordering invariants ───────────────────────────────────────

#[test]
fn lockdown_ordering_invariant() {
    // Verify the lockdown ordering is strictly monotonic
    let levels = [
        types::LockdownLevel::None,
        types::LockdownLevel::Soft,
        types::LockdownLevel::Hard,
        types::LockdownLevel::Permanent,
    ];
    for i in 0..levels.len() - 1 {
        assert!(
            levels[i] < levels[i + 1],
            "{:?} should be less than {:?}",
            levels[i],
            levels[i + 1]
        );
    }
}

#[test]
fn resolution_strength_matches_lockdown() {
    // KBA can only resolve Soft (weakest lock, weakest resolution)
    assert!(can_resolve(&ResolutionMethod::AdditionalKba, types::LockdownLevel::Soft));
    assert!(!can_resolve(&ResolutionMethod::AdditionalKba, types::LockdownLevel::Hard));

    // Photo ID can resolve up to Hard
    assert!(can_resolve(&ResolutionMethod::PhotoId, types::LockdownLevel::Hard));
    assert!(!can_resolve(&ResolutionMethod::PhotoId, types::LockdownLevel::Permanent));

    // Only in-person and admin can resolve Permanent
    assert!(can_resolve(&ResolutionMethod::InPerson, types::LockdownLevel::Permanent));
    assert!(can_resolve(&ResolutionMethod::AdminReview, types::LockdownLevel::Permanent));
}

// ══════════════════════════════════════════════════════════════════════
// WAVE 2: Deeper adversarial tests — state-level, sophisticated, integrity
// ══════════════════════════════════════════════════════════════════════

// ── Attack: Field boundary confusion ──────────────────────────────────

#[test]
fn attack_field_boundary_confusion() {
    // Adversary tries to exploit field concatenation to create collisions.
    // E.g., given="John|Smith" family="" should NOT collide with given="John" family="Smith"
    // The SHA-512 per-field pre-hashing prevents this.
    let a1 = types::IdentityAttributes {
        given_name: "John".to_string(),
        family_name: "Smith".to_string(),
        date_of_birth: "1990-01-15".to_string(),
        document_id: None,
        document_type: None,
        extra_claims: vec![],
    };
    let a2 = types::IdentityAttributes {
        given_name: "JohnSmith".to_string(),
        family_name: "".to_string(),
        date_of_birth: "1990-01-15".to_string(),
        document_id: None,
        document_type: None,
        extra_claims: vec![],
    };
    let salt = [42u8; 32];
    let c1 = generate_commitment(&a1, &salt);
    let c2 = generate_commitment(&a2, &salt);
    assert_ne!(c1, c2, "Field boundary confusion must not create collision");
}

#[test]
fn attack_field_boundary_confusion_with_separator() {
    // Another variant: adversary puts the pipe separator in the name itself
    let a1 = make_attrs("John", "Smith", "1990-01-15");
    let a2 = types::IdentityAttributes {
        given_name: "John|".to_string(),
        family_name: "|Smith".to_string(),
        date_of_birth: "1990-01-15".to_string(),
        document_id: None,
        document_type: None,
        extra_claims: vec![],
    };
    let salt = [42u8; 32];
    let c1 = generate_commitment(&a1, &salt);
    let c2 = generate_commitment(&a2, &salt);
    assert_ne!(c1, c2, "Pipe char in name must not collide with field separator");
}

// ── Attack: Extra claims ordering ─────────────────────────────────────

#[test]
fn attack_extra_claims_ordering() {
    // If extra_claims are processed in order, different orderings produce
    // different commitments. This is correct behavior — the commitment is
    // bound to the exact attribute set as presented.
    let salt = [42u8; 32];
    let a1 = types::IdentityAttributes {
        given_name: "John".to_string(),
        family_name: "Smith".to_string(),
        date_of_birth: "1990-01-15".to_string(),
        document_id: None,
        document_type: None,
        extra_claims: vec![
            ("party".to_string(), "Republican".to_string()),
            ("county".to_string(), "Salt Lake".to_string()),
        ],
    };
    let a2 = types::IdentityAttributes {
        given_name: "John".to_string(),
        family_name: "Smith".to_string(),
        date_of_birth: "1990-01-15".to_string(),
        document_id: None,
        document_type: None,
        extra_claims: vec![
            ("county".to_string(), "Salt Lake".to_string()),
            ("party".to_string(), "Republican".to_string()),
        ],
    };
    let c1 = generate_commitment(&a1, &salt);
    let c2 = generate_commitment(&a2, &salt);
    // Different ordering SHOULD produce different commitments
    // (the caller must canonicalize before committing)
    assert_ne!(c1, c2, "Different claim ordering must produce different commitments");
}

// ── Attack: Salt reuse detection ──────────────────────────────────────

#[test]
fn attack_salt_reuse_reveals_same_identity() {
    // If an attacker can force salt reuse (e.g., compromised RNG),
    // they can detect if two commitments are for the same person.
    // This is a known limitation — salt MUST be unique per registration.
    let attrs = make_attrs("John", "Smith", "1990-01-15");
    let salt = [42u8; 32]; // Reused salt
    let c1 = generate_commitment(&attrs, &salt);
    let c2 = generate_commitment(&attrs, &salt);
    assert_eq!(c1, c2, "Same attrs + same salt = same commitment (salt reuse is dangerous)");

    // But different people with same salt still differ
    let attrs2 = make_attrs("Jane", "Doe", "1985-03-20");
    let c3 = generate_commitment(&attrs2, &salt);
    assert_ne!(c1, c3, "Different attrs + same salt still differ");
}

#[test]
fn attack_salt_uniqueness() {
    // Verify that generate_salt produces unique values
    let s1 = generate_salt();
    let s2 = generate_salt();
    let s3 = generate_salt();
    assert_ne!(s1, s2, "Salts must be unique");
    assert_ne!(s2, s3, "Salts must be unique");
    assert_ne!(s1, s3, "Salts must be unique");
}

// ── Attack: Document type case confusion ──────────────────────────────

#[test]
fn attack_document_type_case_sensitivity() {
    // Adversary submits "DRIVERS_LICENSE" instead of "drivers_license"
    // Document fingerprints are currently case-sensitive — this is correct
    // because the caller (Express server) normalizes before calling.
    let d1 = generate_document_fingerprint("drivers_license", "DL123456");
    let d2 = generate_document_fingerprint("DRIVERS_LICENSE", "DL123456");
    // These SHOULD differ — the engine trusts the caller to normalize.
    // If they don't normalize, the adversary could evade detection.
    // This test documents that behavior for callers to be aware.
    assert_ne!(d1, d2, "Document type is case-sensitive (caller must normalize)");
}

// ── Attack: Whitespace injection ──────────────────────────────────────

#[test]
fn attack_whitespace_injection_fingerprint() {
    // Adversary tries leading/trailing/internal whitespace to evade fingerprint matching
    let a1 = make_attrs("John", "Smith", "1990-01-15");
    let a2 = make_attrs("  John  ", "  Smith  ", "1990-01-15");
    let fp1 = generate_fingerprint(&a1);
    let fp2 = generate_fingerprint(&a2);
    assert_eq!(fp1, fp2, "Whitespace padding must not evade fingerprint matching");
}

#[test]
fn attack_tab_and_newline_injection() {
    // Adversary uses tabs or newlines in name fields
    let a1 = make_attrs("John", "Smith", "1990-01-15");
    let a2 = types::IdentityAttributes {
        given_name: "John\t".to_string(),
        family_name: "Smith\n".to_string(),
        date_of_birth: "1990-01-15".to_string(),
        document_id: None,
        document_type: None,
        extra_claims: vec![],
    };
    let fp1 = generate_fingerprint(&a1);
    let fp2 = generate_fingerprint(&a2);
    // Tab and newline are non-alphabetic → stripped by normalize_name
    assert_eq!(fp1, fp2, "Tab/newline must be stripped in fingerprint");
}

// ── Attack: All-prefix name ───────────────────────────────────────────

#[test]
fn attack_all_prefix_name() {
    // Adversary registers with a name that's entirely prefixes/suffixes
    // After stripping, the name should be empty or near-empty
    let a1 = make_attrs("Dr", "Jr", "1990-01-15");
    let a2 = make_attrs("Mr", "Sr", "1990-01-15");
    let fp1 = generate_fingerprint(&a1);
    let fp2 = generate_fingerprint(&a2);
    // Both reduce to near-empty after prefix stripping — should still differ
    // because "dr" != "mr" after normalization
    // The key point: the system doesn't crash on edge-case names
    assert!(fp1.as_hex().len() == 64, "Fingerprint must still be valid");
    assert!(fp2.as_hex().len() == 64, "Fingerprint must still be valid");
}

// ── Attack: Very long name buffer ─────────────────────────────────────

#[test]
fn attack_very_long_name() {
    // Adversary submits an extremely long name to test buffer handling
    let long_name = "A".repeat(10_000);
    let a1 = types::IdentityAttributes {
        given_name: long_name.clone(),
        family_name: "Smith".to_string(),
        date_of_birth: "1990-01-15".to_string(),
        document_id: None,
        document_type: None,
        extra_claims: vec![],
    };
    let salt = generate_salt();
    let commitment = generate_commitment(&a1, &salt);
    assert_eq!(commitment.as_hex().len(), 64, "Long name must produce valid commitment");

    let fp = generate_fingerprint(&a1);
    assert_eq!(fp.as_hex().len(), 64, "Long name must produce valid fingerprint");
}

// ── Attack: DOB format variation ──────────────────────────────────────

#[test]
fn attack_dob_format_variation() {
    // Adversary submits "1990-1-15" vs "1990-01-15" to evade matching
    // The fingerprint uses the DOB as-is (caller must canonicalize)
    let a1 = make_attrs("John", "Smith", "1990-01-15");
    let a2 = make_attrs("John", "Smith", "1990-1-15");
    let fp1 = generate_fingerprint(&a1);
    let fp2 = generate_fingerprint(&a2);
    // These SHOULD differ — this documents that the caller must normalize DOB format
    assert_ne!(fp1, fp2, "DOB format variation produces different fingerprint (caller must normalize)");
}

// ── Attack: Empty document ID vs None ─────────────────────────────────

#[test]
fn attack_empty_vs_none_document_id() {
    // Adversary submits empty string vs None for document_id
    // These should produce different commitments
    let salt = [42u8; 32];
    let a1 = types::IdentityAttributes {
        given_name: "John".to_string(),
        family_name: "Smith".to_string(),
        date_of_birth: "1990-01-15".to_string(),
        document_id: None,
        document_type: None,
        extra_claims: vec![],
    };
    let a2 = types::IdentityAttributes {
        given_name: "John".to_string(),
        family_name: "Smith".to_string(),
        date_of_birth: "1990-01-15".to_string(),
        document_id: Some("".to_string()),
        document_type: Some("".to_string()),
        extra_claims: vec![],
    };
    let c1 = generate_commitment(&a1, &salt);
    let c2 = generate_commitment(&a2, &salt);
    // None hashes sentinel "none", empty string hashes ""
    assert_ne!(c1, c2, "Empty document ID must differ from None");
}

// ── Attack: Recovery code exhaustion ──────────────────────────────────

#[test]
fn attack_recovery_code_exhaustion() {
    // After all 8 codes are used, no more recovery is possible via codes
    let (codes, mut code_set) = generate_recovery_codes("voter-test");
    assert_eq!(codes.len(), 8);

    // Use all 8 codes
    for (i, code) in codes.iter().enumerate() {
        let idx = verify_recovery_code(code, &code_set).unwrap();
        assert_eq!(idx, i);
        mark_code_used(&mut code_set, idx);
    }

    // All codes exhausted — none should work now
    for code in &codes {
        assert!(
            verify_recovery_code(code, &code_set).is_none(),
            "Exhausted code must not verify"
        );
    }
    assert_eq!(remaining_codes(&code_set), 0);
}

// ── Attack: Recovery code with whitespace ─────────────────────────────

#[test]
fn attack_recovery_code_whitespace_tolerance() {
    // User might copy-paste with extra whitespace
    let (codes, code_set) = generate_recovery_codes("voter-test");
    let padded = format!("  {}  ", codes[0]);
    let result = verify_recovery_code(&padded, &code_set);
    assert_eq!(result, Some(0), "Whitespace-padded code should still verify");
}

// ── Attack: Recovery code case tolerance ──────────────────────────────

#[test]
fn attack_recovery_code_mixed_case() {
    let (codes, code_set) = generate_recovery_codes("voter-test");
    // Mix case randomly
    let mixed: String = codes[0]
        .chars()
        .enumerate()
        .map(|(i, c)| if i % 2 == 0 { c.to_lowercase().next().unwrap() } else { c })
        .collect();
    let result = verify_recovery_code(&mixed, &code_set);
    assert_eq!(result, Some(0), "Mixed-case code should still verify");
}

// ── Attack: Nullifier cannot reveal commitment ────────────────────────

#[test]
fn attack_nullifier_preimage_resistance() {
    // Two different commitments with the same context produce different nullifiers.
    // This means you can't reverse-engineer a commitment from its nullifier.
    let a1 = make_attrs("John", "Smith", "1990-01-15");
    let a2 = make_attrs("Jane", "Doe", "1985-03-20");
    let salt1 = generate_salt();
    let salt2 = generate_salt();
    let c1 = generate_commitment(&a1, &salt1);
    let c2 = generate_commitment(&a2, &salt2);

    let n1 = generate_nullifier(&c1, "election-2026");
    let n2 = generate_nullifier(&c2, "election-2026");

    assert_ne!(n1, n2, "Different commitments must produce different nullifiers");
    // Also verify nullifiers don't contain commitment material
    assert!(!n1.as_hex().contains(&c1.as_hex()[..16]),
        "Nullifier should not contain commitment prefix");
}

// ── Attack: Commitment output length invariant ────────────────────────

#[test]
fn attack_commitment_output_length_invariant() {
    // No matter the input size, output is always 64 hex chars (256 bits)
    let salt = generate_salt();
    let long_a = "A".repeat(1000);
    let long_b = "B".repeat(1000);
    let long_c = "C".repeat(1000);
    let inputs: Vec<(&str, &str, &str)> = vec![
        ("", "", ""),
        ("J", "S", "1"),
        ("John", "Smith", "1990-01-15"),
        (&long_a, &long_b, &long_c),
    ];

    for (given, family, dob) in inputs {
        let a = types::IdentityAttributes {
            given_name: given.to_string(),
            family_name: family.to_string(),
            date_of_birth: dob.to_string(),
            document_id: None,
            document_type: None,
            extra_claims: vec![],
        };
        let c = generate_commitment(&a, &salt);
        assert_eq!(
            c.as_hex().len(), 64,
            "Commitment must be 64 hex chars regardless of input size"
        );
    }
}

// ── Attack: Fingerprint is NOT commitment ─────────────────────────────

#[test]
fn attack_fingerprint_commitment_domain_separation() {
    // Even with the same input, fingerprint != commitment
    // Because they use different BLAKE3 domain keys
    let attrs = make_attrs("John", "Smith", "1990-01-15");
    let salt = [0u8; 32];
    let commitment = generate_commitment(&attrs, &salt);
    let fingerprint = generate_fingerprint(&attrs);
    assert_ne!(
        commitment.as_hex(), fingerprint.as_hex(),
        "Commitment and fingerprint must use different domains"
    );
}

// ── Attack: Recovery code doesn't resolve identity locks ──────────────

#[test]
fn attack_recovery_code_cannot_resolve_hard_lock() {
    // Recovery codes prove ownership, not identity. They must NOT resolve
    // identity conflicts (Hard/Permanent locks).
    assert!(!can_resolve(&ResolutionMethod::RecoveryCode, types::LockdownLevel::Hard));
    assert!(!can_resolve(&ResolutionMethod::RecoveryCode, types::LockdownLevel::Permanent));
    assert!(!can_resolve(&ResolutionMethod::RecoveryCode, types::LockdownLevel::Soft));
    assert!(can_resolve(&ResolutionMethod::RecoveryCode, types::LockdownLevel::None));
}

// ── Attack: Lockdown cannot be de-escalated via escalate ──────────────

#[test]
fn attack_lockdown_escalation_monotonic() {
    // Verify that escalate_lockdown only goes up, never down.
    // An attacker who gains partial system access shouldn't be able to
    // de-escalate a permanent lock by calling escalate with a lower level.
    use std::collections::HashMap;
    use chrono::{DateTime, Utc};

    struct TestStore {
        lockdowns: HashMap<String, (types::LockdownLevel, types::LockdownReason)>,
    }

    #[derive(Debug)]
    struct TestErr;
    impl std::fmt::Display for TestErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "test error")
        }
    }
    impl std::error::Error for TestErr {}

    impl plausiden_identity::fraud::IdentityStore for TestStore {
        type Error = TestErr;
        fn get_identity(&self, _: &str) -> Result<Option<plausiden_identity::fraud::IdentityRecord>, TestErr> { Ok(None) }
        fn find_by_fingerprint(&self, _: &types::IdentityFingerprint) -> Result<Vec<plausiden_identity::fraud::IdentityRecord>, TestErr> { Ok(vec![]) }
        fn find_by_document(&self, _: &types::DocumentFingerprint) -> Result<Vec<plausiden_identity::fraud::IdentityRecord>, TestErr> { Ok(vec![]) }
        fn count_verifications_from_ip(&self, _: &str, _: DateTime<Utc>) -> Result<u32, TestErr> { Ok(0) }
        fn get_voter_hashes_from_ip(&self, _: &str, _: DateTime<Utc>) -> Result<Vec<String>, TestErr> { Ok(vec![]) }
        fn store_identity(&mut self, _: plausiden_identity::fraud::IdentityRecord) -> Result<(), TestErr> { Ok(()) }
        fn store_fraud_signal(&mut self, _: types::FraudSignal) -> Result<(), TestErr> { Ok(()) }
        fn apply_lockdown(&mut self, vh: &str, level: types::LockdownLevel, reason: types::LockdownReason) -> Result<(), TestErr> {
            self.lockdowns.insert(vh.to_string(), (level, reason));
            Ok(())
        }
        fn get_lockdown_level(&self, vh: &str) -> Result<types::LockdownLevel, TestErr> {
            Ok(self.lockdowns.get(vh).map(|(l, _)| *l).unwrap_or(types::LockdownLevel::None))
        }
        fn store_recovery_codes(&mut self, _: types::RecoveryCodeSet) -> Result<(), TestErr> { Ok(()) }
        fn get_recovery_codes(&self, _: &str) -> Result<Option<types::RecoveryCodeSet>, TestErr> { Ok(None) }
    }

    let mut store = TestStore {
        lockdowns: HashMap::new(),
    };

    // Set to Permanent
    let reason = types::LockdownReason::AdminAction {
        admin_id: "admin".to_string(),
        reason: "confirmed fraud".to_string(),
    };
    store.apply_lockdown("voter-x", types::LockdownLevel::Permanent, reason).unwrap();

    // Try to de-escalate via escalate_lockdown — should be no-op
    let soft_reason = types::LockdownReason::AdminAction {
        admin_id: "attacker".to_string(),
        reason: "trying to de-escalate".to_string(),
    };
    escalate_lockdown(&mut store, "voter-x", types::LockdownLevel::Soft, soft_reason).unwrap();

    // Lockdown should still be Permanent
    assert_eq!(
        store.get_lockdown_level("voter-x").unwrap(),
        types::LockdownLevel::Permanent,
        "escalate_lockdown must not de-escalate"
    );
}

// ── Attack: Hyphenated vs unhyphenated names ──────────────────────────

#[test]
fn attack_hyphenated_name_evasion() {
    // "Smith-Jones" vs "Smithjones" vs "Smith Jones"
    // Fingerprint strips hyphens (non-alpha) so these should match
    let a1 = make_attrs("John", "Smith-Jones", "1990-01-15");
    let a2 = make_attrs("John", "SmithJones", "1990-01-15");
    let fp1 = generate_fingerprint(&a1);
    let fp2 = generate_fingerprint(&a2);
    // After normalize: "smithjones" in both cases
    assert_eq!(fp1, fp2, "Hyphenated name must match unhyphenated in fingerprint");
}

#[test]
fn attack_apostrophe_name_evasion() {
    // "O'Brien" vs "OBrien" vs "Obrien"
    let a1 = make_attrs("John", "O'Brien", "1990-01-15");
    let a2 = make_attrs("John", "OBrien", "1990-01-15");
    let fp1 = generate_fingerprint(&a1);
    let fp2 = generate_fingerprint(&a2);
    assert_eq!(fp1, fp2, "Apostrophe must be stripped in fingerprint");
}

// ── Attack: Name normalization word-boundary safety ───────────────────

#[test]
fn attack_suffix_in_name_body() {
    // "hawaii" ends in "ii" but "ii" is NOT a suffix here — it's part of the name.
    // The normalizer must only strip " ii" (preceded by space), not bare "ii".
    let a1 = make_attrs("John", "Hawaii", "1990-01-15");
    let fp1 = generate_fingerprint(&a1);
    // If the bug existed, "hawaii" → "hawa" which would be wrong
    // The fingerprint for "hawaii" should be different from "hawa"
    let a2 = make_attrs("John", "Hawa", "1990-01-15");
    let fp2 = generate_fingerprint(&a2);
    assert_ne!(fp1, fp2, "Suffix 'ii' in body of name must not be stripped");
}

#[test]
fn attack_prefix_in_name_body() {
    // "jrsmith" starts with "jr" but it's not a prefix — it's the name.
    let a1 = make_attrs("Jrsmith", "Jones", "1990-01-15");
    let a2 = make_attrs("Smith", "Jones", "1990-01-15");
    let fp1 = generate_fingerprint(&a1);
    let fp2 = generate_fingerprint(&a2);
    assert_ne!(fp1, fp2, "Prefix 'jr' as part of name body must not be stripped");
}

// ── Attack: Similarity engine edge cases ──────────────────────────────

#[test]
fn attack_identical_first_different_last() {
    // Same first name, completely different last — should NOT be flagged as same person
    let result = compare_identities(
        "John Smith", "1990-01-15",
        "John Okafor", "1990-01-15",
    );
    assert!(
        result.interpretation != SimilarityInterpretation::SamePerson,
        "Same first name + different last should not be SamePerson: score={}",
        result.name_score
    );
}

#[test]
fn attack_completely_identical_names_different_dob() {
    // Twins or parent-child with same name, different DOB
    let result = compare_identities(
        "John Smith", "1990-01-15",
        "John Smith", "1960-03-22",
    );
    assert!(
        result.interpretation == SimilarityInterpretation::Investigate,
        "Same name + different DOB should be Investigate: {:?}",
        result.interpretation
    );
    assert!(!result.dob_match);
}

// ── Attack: Commitment hex is valid hex ───────────────────────────────

#[test]
fn attack_commitment_is_valid_hex() {
    let attrs = make_attrs("John", "Smith", "1990-01-15");
    let salt = generate_salt();
    let c = generate_commitment(&attrs, &salt);
    // Verify it's valid lowercase hex
    assert!(
        c.as_hex().chars().all(|ch| ch.is_ascii_hexdigit()),
        "Commitment must be valid hex"
    );
    assert!(
        c.as_hex().chars().all(|ch| !ch.is_ascii_uppercase()),
        "Commitment hex must be lowercase"
    );
}

// ── Attack: Verify rejects tampered commitment ────────────────────────

#[test]
fn attack_tampered_commitment_rejected() {
    let attrs = make_attrs("John", "Smith", "1990-01-15");
    let salt = [42u8; 32];
    let c = generate_commitment(&attrs, &salt);

    // Tamper with one byte of the commitment
    let mut tampered = c.as_hex().to_string();
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'a' { 'b' } else { 'a' });
    let tampered_commitment = types::IdentityCommitment(tampered);

    assert!(
        !verify_commitment(&attrs, &salt, &tampered_commitment),
        "Tampered commitment must fail verification"
    );
}

// ── Attack: Multiple simultaneous registrations ───────────────────────

#[test]
fn attack_parallel_registration_fingerprint_collision() {
    // Two separate registrations for the same person should produce
    // the same fingerprint (enabling collision detection),
    // but different commitments (different salts).
    let attrs = make_attrs("John", "Smith", "1990-01-15");
    let salt1 = generate_salt();
    let salt2 = generate_salt();

    let c1 = generate_commitment(&attrs, &salt1);
    let c2 = generate_commitment(&attrs, &salt2);
    let fp1 = generate_fingerprint(&attrs);
    let fp2 = generate_fingerprint(&attrs);

    assert_ne!(c1, c2, "Different salts must produce different commitments");
    assert_eq!(fp1, fp2, "Same person must produce same fingerprint");
}

// ── Attack: Null byte injection ───────────────────────────────────────

#[test]
fn attack_null_byte_injection() {
    // Adversary injects null bytes to truncate or confuse hash input
    let a1 = make_attrs("John", "Smith", "1990-01-15");
    let a2 = types::IdentityAttributes {
        given_name: "John\0Extra".to_string(),
        family_name: "Smith".to_string(),
        date_of_birth: "1990-01-15".to_string(),
        document_id: None,
        document_type: None,
        extra_claims: vec![],
    };
    let salt = [42u8; 32];
    let c1 = generate_commitment(&a1, &salt);
    let c2 = generate_commitment(&a2, &salt);
    // BLAKE3/SHA-512 process all bytes including null — they should differ
    assert_ne!(c1, c2, "Null byte in name must produce different commitment");
}

// ── Verification strength ordering ────────────────────────────────────

#[test]
fn verification_strength_ordering() {
    assert!(types::VerificationStrength::RecordCheck < types::VerificationStrength::KnowledgeBased);
    assert!(types::VerificationStrength::KnowledgeBased < types::VerificationStrength::Visual);
    assert!(types::VerificationStrength::Visual < types::VerificationStrength::Cryptographic);
}

// ── Fraud severity ordering ───────────────────────────────────────────

#[test]
fn fraud_severity_ordering() {
    assert!(types::FraudSeverity::Info < types::FraudSeverity::Low);
    assert!(types::FraudSeverity::Low < types::FraudSeverity::Medium);
    assert!(types::FraudSeverity::Medium < types::FraudSeverity::High);
    assert!(types::FraudSeverity::High < types::FraudSeverity::Critical);
}
