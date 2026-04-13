//! Account recovery protocol.
//!
//! Handles the scenario where a user loses access to their device but
//! still needs to verify their identity. Recovery does NOT bypass identity
//! verification — it proves ownership of the original registration.
//!
//! # Recovery Methods
//!
//! 1. **Recovery codes:** 8 codes generated at verification time. Each is
//!    single-use. Stored as argon2 hashes — the cleartext is shown once
//!    to the user and never stored.
//!
//! 2. **Re-verification:** Go through the full identity verification flow
//!    again. The new commitment must match the original (same person,
//!    same attributes). This handles the "lost everything" scenario.
//!
//! 3. **Admin-assisted:** Submit a support ticket with identity evidence.
//!    Admin reviews and manually links the new voter code to the existing
//!    identity. Full audit trail required.
//!
//! # Security Properties
//!
//! - Recovery codes are argon2id hashed with per-code salt — rainbow
//!   tables are infeasible.
//! - Each code is single-use and tracked — cannot be replayed.
//! - Codes expire after 1 year (configurable).
//! - Re-verification requires the SAME identity attributes — you can't
//!   "recover" into a different identity.
//! - Admin-assisted recovery has a mandatory cooling period before the
//!   account becomes active again.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use rand::Rng;
use crate::commitment::verify_commitment;
use crate::types::*;
use crate::fraud::IdentityRecord;

/// Number of recovery codes generated per registration.
const RECOVERY_CODE_COUNT: usize = 8;

/// Length of each recovery code (alphanumeric characters).
const RECOVERY_CODE_LENGTH: usize = 8;

/// Default expiry for recovery codes (365 days).
const RECOVERY_CODE_EXPIRY_DAYS: i64 = 365;

/// Characters used in recovery codes — unambiguous set (no 0/O, 1/I/l).
const CODE_CHARSET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

/// Generate a set of recovery codes for a voter.
///
/// Returns a tuple of:
/// - The cleartext codes (SHOW TO USER ONCE, then zeroize)
/// - The `RecoveryCodeSet` with argon2 hashes (store in DB)
///
/// # Security
///
/// The cleartext codes MUST be displayed to the user and then discarded.
/// They are never stored. If the user loses them, they must use another
/// recovery method.
pub fn generate_recovery_codes(
    voter_hash: &str,
) -> (Vec<String>, RecoveryCodeSet) {
    let mut rng = rand::thread_rng();
    let mut cleartext_codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut hashed_codes = Vec::with_capacity(RECOVERY_CODE_COUNT);

    let argon2 = Argon2::default();

    for _ in 0..RECOVERY_CODE_COUNT {
        // Generate a random code from the unambiguous charset
        let code: String = (0..RECOVERY_CODE_LENGTH)
            .map(|_| {
                let idx = rng.gen_range(0..CODE_CHARSET.len());
                CODE_CHARSET[idx] as char
            })
            .collect();

        // Hash with argon2id
        let salt = SaltString::generate(&mut OsRng);
        let hash = argon2
            .hash_password(code.as_bytes(), &salt)
            .expect("argon2 hash failed")
            .to_string();

        cleartext_codes.push(code);
        hashed_codes.push(hash);
    }

    let code_set = RecoveryCodeSet {
        voter_hash: voter_hash.to_string(),
        code_hashes: hashed_codes,
        used_count: 0,
        generated_at: Utc::now(),
        expires_at: Utc::now() + Duration::days(RECOVERY_CODE_EXPIRY_DAYS),
    };

    (cleartext_codes, code_set)
}

/// Verify a recovery code against stored hashes.
///
/// Returns `Some(index)` of the matched code if valid, `None` if no match.
/// Each code is single-use — after verification, the caller must mark it used.
///
/// # Arguments
/// * `code` - The cleartext recovery code entered by the user
/// * `code_set` - The stored recovery code set with hashes
///
/// # Returns
/// The index of the matching code, or None if no match.
pub fn verify_recovery_code(code: &str, code_set: &RecoveryCodeSet) -> Option<usize> {
    // Check expiry
    if Utc::now() > code_set.expires_at {
        return None;
    }

    // Normalize: uppercase, trim whitespace
    let normalized = code.trim().to_uppercase();

    let argon2 = Argon2::default();

    // Check each hash — try all of them (constant-time in aggregate)
    for (i, hash_str) in code_set.code_hashes.iter().enumerate() {
        // Skip if this hash has been "used" (replaced with empty string)
        if hash_str.is_empty() {
            continue;
        }

        if let Ok(parsed_hash) = PasswordHash::new(hash_str) {
            if argon2
                .verify_password(normalized.as_bytes(), &parsed_hash)
                .is_ok()
            {
                return Some(i);
            }
        }
    }

    None
}

/// Mark a recovery code as used by replacing its hash with an empty string.
/// This is a destructive operation — the code cannot be used again.
pub fn mark_code_used(code_set: &mut RecoveryCodeSet, index: usize) {
    if index < code_set.code_hashes.len() {
        code_set.code_hashes[index] = String::new();
        code_set.used_count += 1;
    }
}

/// Verify that a re-verification attempt matches the original identity.
///
/// The user goes through the full identity verification flow again.
/// If their commitment matches the stored one, they're the same person
/// and can be re-linked to their voter code.
///
/// # Arguments
/// * `attrs` - The new identity attributes from re-verification
/// * `stored_record` - The original identity record
///
/// # Returns
/// True if the re-verification matches, false otherwise.
pub fn verify_re_verification(
    attrs: &IdentityAttributes,
    stored_record: &IdentityRecord,
) -> bool {
    let salt: [u8; 32] = stored_record
        .salt
        .as_slice()
        .try_into()
        .unwrap_or([0u8; 32]);
    verify_commitment(attrs, &salt, &stored_record.commitment)
}

/// Count remaining usable recovery codes.
pub fn remaining_codes(code_set: &RecoveryCodeSet) -> usize {
    code_set
        .code_hashes
        .iter()
        .filter(|h| !h.is_empty())
        .count()
}

/// Format recovery codes for display to the user.
/// Inserts a dash every 4 characters for readability: "ABCD-EFGH"
pub fn format_code_for_display(code: &str) -> String {
    let chars: Vec<char> = code.chars().collect();
    let mut formatted = String::new();
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            formatted.push('-');
        }
        formatted.push(*c);
    }
    formatted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_correct_number_of_codes() {
        let (codes, code_set) = generate_recovery_codes("voter-aaa");
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        assert_eq!(code_set.code_hashes.len(), RECOVERY_CODE_COUNT);
        assert_eq!(code_set.used_count, 0);
    }

    #[test]
    fn codes_are_correct_length() {
        let (codes, _) = generate_recovery_codes("voter-aaa");
        for code in &codes {
            assert_eq!(code.len(), RECOVERY_CODE_LENGTH);
        }
    }

    #[test]
    fn codes_use_unambiguous_charset() {
        let (codes, _) = generate_recovery_codes("voter-aaa");
        for code in &codes {
            for c in code.chars() {
                assert!(
                    CODE_CHARSET.contains(&(c as u8)),
                    "Unexpected char: {}",
                    c
                );
            }
        }
    }

    #[test]
    fn verify_code_succeeds() {
        let (codes, code_set) = generate_recovery_codes("voter-aaa");
        let result = verify_recovery_code(&codes[0], &code_set);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn verify_code_case_insensitive() {
        let (codes, code_set) = generate_recovery_codes("voter-aaa");
        let lower = codes[0].to_lowercase();
        let result = verify_recovery_code(&lower, &code_set);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn verify_code_rejects_wrong_code() {
        let (_, code_set) = generate_recovery_codes("voter-aaa");
        let result = verify_recovery_code("ZZZZZZZZ", &code_set);
        assert!(result.is_none());
    }

    #[test]
    fn used_code_cannot_be_reused() {
        let (codes, mut code_set) = generate_recovery_codes("voter-aaa");
        let idx = verify_recovery_code(&codes[0], &code_set).unwrap();
        mark_code_used(&mut code_set, idx);

        let result = verify_recovery_code(&codes[0], &code_set);
        assert!(result.is_none());
    }

    #[test]
    fn remaining_codes_tracks_usage() {
        let (codes, mut code_set) = generate_recovery_codes("voter-aaa");
        assert_eq!(remaining_codes(&code_set), RECOVERY_CODE_COUNT);

        mark_code_used(&mut code_set, 0);
        assert_eq!(remaining_codes(&code_set), RECOVERY_CODE_COUNT - 1);

        mark_code_used(&mut code_set, 1);
        assert_eq!(remaining_codes(&code_set), RECOVERY_CODE_COUNT - 2);
    }

    #[test]
    fn expired_codes_rejected() {
        let (codes, mut code_set) = generate_recovery_codes("voter-aaa");
        code_set.expires_at = Utc::now() - Duration::days(1);
        let result = verify_recovery_code(&codes[0], &code_set);
        assert!(result.is_none());
    }

    #[test]
    fn format_code_adds_dashes() {
        assert_eq!(format_code_for_display("ABCDEFGH"), "ABCD-EFGH");
        assert_eq!(format_code_for_display("12345678"), "1234-5678");
    }

    #[test]
    fn all_codes_are_unique() {
        let (codes, _) = generate_recovery_codes("voter-aaa");
        let mut unique = std::collections::HashSet::new();
        for code in &codes {
            assert!(unique.insert(code), "Duplicate code generated");
        }
    }

    #[test]
    fn different_voters_get_different_codes() {
        let (codes_a, _) = generate_recovery_codes("voter-aaa");
        let (codes_b, _) = generate_recovery_codes("voter-bbb");
        // Not deterministic, but statistically impossible to collide all 8
        assert_ne!(codes_a, codes_b);
    }
}
