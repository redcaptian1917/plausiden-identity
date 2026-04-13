//! Property-based tests for plausiden-identity.
//!
//! These tests use proptest to generate random inputs and verify that
//! the identity engine's invariants hold across all possible inputs.
//! This is critical for crypto code — edge cases in name handling,
//! encoding, and hash computation must not create exploitable patterns.

use plausiden_identity::*;
use proptest::prelude::*;

// ── Commitment Properties ──────────────────────────────────────────────

proptest! {
    /// The same attributes + salt always produce the same commitment.
    #[test]
    fn commitment_is_deterministic(
        given in "[a-zA-Z ]{1,50}",
        family in "[a-zA-Z ]{1,50}",
        dob in "[0-9]{4}-[0-9]{2}-[0-9]{2}",
        salt_byte in 0u8..=255u8,
    ) {
        let attrs = types::IdentityAttributes {
            given_name: given.clone(),
            family_name: family.clone(),
            date_of_birth: dob.clone(),
            document_id: None,
            document_type: None,
            extra_claims: vec![],
        };
        let salt = [salt_byte; 32];
        let c1 = generate_commitment(&attrs, &salt);
        let c2 = generate_commitment(&attrs, &salt);
        prop_assert_eq!(c1, c2);
    }

    /// Different salts produce different commitments (with overwhelming probability).
    #[test]
    fn different_salt_different_commitment(
        given in "[a-zA-Z]{2,20}",
        family in "[a-zA-Z]{2,20}",
        dob in "1[0-9]{3}-[0-1][0-9]-[0-3][0-9]",
        salt1_byte in 0u8..=127u8,
        salt2_byte in 128u8..=255u8,
    ) {
        let attrs = types::IdentityAttributes {
            given_name: given,
            family_name: family,
            date_of_birth: dob,
            document_id: None,
            document_type: None,
            extra_claims: vec![],
        };
        let s1 = [salt1_byte; 32];
        let s2 = [salt2_byte; 32];
        let c1 = generate_commitment(&attrs, &s1);
        let c2 = generate_commitment(&attrs, &s2);
        prop_assert_ne!(c1, c2);
    }

    /// Commitments are always 64 hex characters (BLAKE3 output).
    #[test]
    fn commitment_length(
        given in "[a-zA-Z]{1,50}",
        family in "[a-zA-Z]{1,50}",
        dob in "[0-9]{4}-[0-9]{2}-[0-9]{2}",
    ) {
        let attrs = types::IdentityAttributes {
            given_name: given,
            family_name: family,
            date_of_birth: dob,
            document_id: None,
            document_type: None,
            extra_claims: vec![],
        };
        let salt = generate_salt();
        let c = generate_commitment(&attrs, &salt);
        prop_assert_eq!(c.as_hex().len(), 64);
        // Must be valid hex
        prop_assert!(hex::decode(c.as_hex()).is_ok());
    }

    /// verify_commitment returns true for correct attrs and false for wrong attrs.
    #[test]
    fn verify_commitment_property(
        given in "[a-zA-Z]{2,20}",
        family in "[a-zA-Z]{2,20}",
        dob in "199[0-9]-0[1-9]-[0-2][0-9]",
        wrong_given in "[a-zA-Z]{2,20}",
    ) {
        let attrs = types::IdentityAttributes {
            given_name: given.clone(),
            family_name: family.clone(),
            date_of_birth: dob.clone(),
            document_id: None,
            document_type: None,
            extra_claims: vec![],
        };
        let salt = generate_salt();
        let commitment = generate_commitment(&attrs, &salt);

        // Correct attrs verify
        prop_assert!(verify_commitment(&attrs, &salt, &commitment));

        // Wrong attrs don't verify (unless names happen to be identical)
        if wrong_given != given {
            let wrong_attrs = types::IdentityAttributes {
                given_name: wrong_given,
                family_name: family,
                date_of_birth: dob,
                document_id: None,
                document_type: None,
                extra_claims: vec![],
            };
            prop_assert!(!verify_commitment(&wrong_attrs, &salt, &commitment));
        }
    }
}

// ── Nullifier Properties ──────────────────────────────────────────────

proptest! {
    /// Same commitment + context = same nullifier.
    #[test]
    fn nullifier_deterministic(
        commitment_hex in "[0-9a-f]{64}",
        context in "[a-zA-Z0-9-]{1,50}",
    ) {
        let commitment = types::IdentityCommitment(commitment_hex);
        let n1 = generate_nullifier(&commitment, &context);
        let n2 = generate_nullifier(&commitment, &context);
        prop_assert_eq!(n1, n2);
    }

    /// Different contexts produce different nullifiers.
    #[test]
    fn nullifier_context_isolated(
        commitment_hex in "[0-9a-f]{64}",
        ctx1 in "[a-z]{3,20}",
        ctx2 in "[A-Z]{3,20}",
    ) {
        let commitment = types::IdentityCommitment(commitment_hex);
        let n1 = generate_nullifier(&commitment, &ctx1);
        let n2 = generate_nullifier(&commitment, &ctx2);
        // Different contexts (one lowercase, one uppercase) = different nullifiers
        prop_assert_ne!(n1, n2);
    }

    /// Nullifiers are always 64 hex characters.
    #[test]
    fn nullifier_length(
        commitment_hex in "[0-9a-f]{64}",
        context in "[a-zA-Z0-9]{1,30}",
    ) {
        let commitment = types::IdentityCommitment(commitment_hex);
        let n = generate_nullifier(&commitment, &context);
        prop_assert_eq!(n.as_hex().len(), 64);
    }
}

// ── Fingerprint Properties ──────────────────────────────────────────────

proptest! {
    /// Fingerprints are case-insensitive.
    #[test]
    fn fingerprint_case_insensitive(
        name in "[a-zA-Z]{2,20}",
        family in "[a-zA-Z]{2,20}",
        dob in "199[0-9]-0[1-9]-[0-2][0-9]",
    ) {
        let attrs_upper = types::IdentityAttributes {
            given_name: name.to_uppercase(),
            family_name: family.to_uppercase(),
            date_of_birth: dob.clone(),
            document_id: None,
            document_type: None,
            extra_claims: vec![],
        };
        let attrs_lower = types::IdentityAttributes {
            given_name: name.to_lowercase(),
            family_name: family.to_lowercase(),
            date_of_birth: dob,
            document_id: None,
            document_type: None,
            extra_claims: vec![],
        };
        let fp1 = generate_fingerprint(&attrs_upper);
        let fp2 = generate_fingerprint(&attrs_lower);
        prop_assert_eq!(fp1, fp2);
    }

    /// Document fingerprints are deterministic.
    #[test]
    fn document_fingerprint_deterministic(
        doc_type in "[a-z_]{3,20}",
        doc_id in "[A-Z0-9]{5,20}",
    ) {
        let d1 = generate_document_fingerprint(&doc_type, &doc_id);
        let d2 = generate_document_fingerprint(&doc_type, &doc_id);
        prop_assert_eq!(d1, d2);
    }
}

// ── Similarity Properties ──────────────────────────────────────────────

proptest! {
    /// Comparing a name to itself always returns 1.0.
    #[test]
    fn self_similarity_is_one(
        name in "[a-zA-Z ]{2,30}",
    ) {
        let score = compare_names(&name, &name);
        prop_assert!((score - 1.0).abs() < f64::EPSILON, "Self-similarity was {} not 1.0", score);
    }

    /// Comparing identical identities returns SamePerson.
    #[test]
    fn identical_identities_same_person(
        name in "[a-zA-Z]{3,15} [a-zA-Z]{3,15}",
        dob in "199[0-9]-0[1-9]-[0-2][0-9]",
    ) {
        let result = compare_identities(&name, &dob, &name, &dob);
        prop_assert_eq!(result.interpretation, SimilarityInterpretation::SamePerson);
    }

    /// Similarity score is always between 0.0 and 1.0.
    #[test]
    fn similarity_bounded(
        a in "[a-zA-Z ]{1,30}",
        b in "[a-zA-Z ]{1,30}",
    ) {
        let score = compare_names(&a, &b);
        prop_assert!(score >= 0.0 && score <= 1.0, "Score {} out of bounds", score);
    }
}

// ── Recovery Code Properties ──────────────────────────────────────────

#[test]
fn recovery_codes_all_unique_across_sets() {
    // Generate multiple sets and verify no code appears in more than one set
    let mut all_codes = std::collections::HashSet::new();
    for i in 0..10 {
        let (codes, _) = generate_recovery_codes(&format!("voter-{}", i));
        for code in codes {
            assert!(all_codes.insert(code), "Duplicate code across sets");
        }
    }
}

#[test]
fn recovery_code_verify_is_position_correct() {
    let (codes, code_set) = generate_recovery_codes("voter-test");
    for (i, code) in codes.iter().enumerate() {
        let result = verify_recovery_code(code, &code_set);
        assert_eq!(result, Some(i), "Code {} should match at index {}", code, i);
    }
}

#[test]
fn recovery_code_mark_used_prevents_reuse() {
    let (codes, mut code_set) = generate_recovery_codes("voter-test");

    // Use code 0
    let idx = verify_recovery_code(&codes[0], &code_set).unwrap();
    mark_code_used(&mut code_set, idx);

    // Code 0 is now invalid
    assert!(verify_recovery_code(&codes[0], &code_set).is_none());

    // Code 1 still works
    assert!(verify_recovery_code(&codes[1], &code_set).is_some());
}

// ── Lockdown Properties ──────────────────────────────────────────────

#[test]
fn lockdown_escalation_only() {
    // Lockdown levels are ordered: None < Soft < Hard < Permanent
    assert!(types::LockdownLevel::None < types::LockdownLevel::Soft);
    assert!(types::LockdownLevel::Soft < types::LockdownLevel::Hard);
    assert!(types::LockdownLevel::Hard < types::LockdownLevel::Permanent);
}

#[test]
fn resolution_methods_cover_all_lockdowns() {
    // Every lockdown level has at least one resolution method
    for level in [
        types::LockdownLevel::None,
        types::LockdownLevel::Soft,
        types::LockdownLevel::Hard,
        types::LockdownLevel::Permanent,
    ] {
        let methods = [
            ResolutionMethod::AdditionalKba,
            ResolutionMethod::PhotoId,
            ResolutionMethod::InPerson,
            ResolutionMethod::AdminReview,
            ResolutionMethod::RecoveryCode,
        ];
        let resolvable = methods.iter().any(|m| can_resolve(m, level));
        assert!(
            resolvable,
            "No resolution method for lockdown level {:?}",
            level
        );
    }
}
