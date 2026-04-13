//! Identity commitment and nullifier generation.
//!
//! The commitment scheme binds a person to a unique cryptographic value
//! without revealing any PII. The nullifier extends this to prevent
//! double-action (e.g., double-voting) within a specific context.
//!
//! # Security Properties
//!
//! - **Binding:** Given a commitment, it is computationally infeasible to
//!   find different attributes that produce the same commitment.
//! - **Hiding:** Given a commitment, it is computationally infeasible to
//!   recover the original attributes.
//! - **Uniqueness:** The same person always produces the same commitment
//!   (given the same salt), enabling duplicate detection.
//! - **Context isolation:** Nullifiers are domain-separated, so commitments
//!   from one context cannot be correlated with another.
//!
//! # Adversarial Considerations (AVP-2)
//!
//! - Field-level hashing prevents length-extension attacks on concatenated inputs
//! - BLAKE3 keyed mode provides domain separation between commitment types
//! - Salt prevents rainbow table attacks against the commitment
//! - Nullifier domain separation prevents cross-election voter correlation
//! - Zeroization ensures attributes don't linger in memory after commitment

use blake3::Hasher;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use crate::types::{
    DocumentFingerprint, IdentityAttributes, IdentityCommitment, IdentityFingerprint, Nullifier,
};

/// Domain separation constants for BLAKE3 keyed hashing.
/// Each constant is exactly 32 bytes (BLAKE3 key size).
const COMMITMENT_DOMAIN: &[u8; 32] = b"plausiden-identity-commitment-v1";
const NULLIFIER_DOMAIN: &[u8; 32] = b"plausiden-identity-nullifier-v1!";
const FINGERPRINT_DOMAIN: &[u8; 32] = b"plausiden-identity-fingerprnt-v1";
const DOCUMENT_DOMAIN: &[u8; 32] = b"plausiden-identity-document--v1!";

/// Generate an identity commitment from raw attributes.
///
/// The commitment is computed as:
/// ```text
/// BLAKE3_keyed(COMMITMENT_DOMAIN,
///     SHA-512(given_name) ||
///     SHA-512(family_name) ||
///     SHA-512(date_of_birth) ||
///     SHA-512(document_id | "none") ||
///     salt
/// )
/// ```
///
/// Each field is individually SHA-512 hashed before concatenation to prevent
/// length-extension and field-boundary confusion attacks.
///
/// # Arguments
/// * `attrs` - Identity attributes (will NOT be modified; caller must zeroize)
/// * `salt` - Random 32-byte salt (unique per identity registration)
///
/// # Returns
/// A hex-encoded BLAKE3 commitment string (64 hex chars).
pub fn generate_commitment(attrs: &IdentityAttributes, salt: &[u8; 32]) -> IdentityCommitment {
    let mut hasher = Hasher::new_keyed(COMMITMENT_DOMAIN);

    // Hash each field individually with SHA-512 (prevents length-extension)
    hasher.update(&sha512_field(&attrs.given_name));
    hasher.update(&sha512_field(&attrs.family_name));
    hasher.update(&sha512_field(&attrs.date_of_birth));

    // Document ID: hash "none" sentinel if not provided
    match &attrs.document_id {
        Some(doc_id) => { hasher.update(&sha512_field(doc_id)); },
        None => { hasher.update(&sha512_field("none")); },
    }

    // Salt prevents rainbow table attacks
    hasher.update(salt);

    // Extra claims contribute to commitment uniqueness
    for (key, value) in &attrs.extra_claims {
        hasher.update(&sha512_field(key));
        hasher.update(&sha512_field(value));
    }

    let hash = hasher.finalize();
    IdentityCommitment(hex::encode(hash.as_bytes()))
}

/// Generate a nullifier for a specific context.
///
/// The nullifier is unique per (identity, context) pair. It prevents
/// the same identity from performing an action twice in the same context
/// (e.g., voting twice in the same election) without revealing which
/// identity produced it.
///
/// ```text
/// BLAKE3_keyed(NULLIFIER_DOMAIN, commitment || context_id)
/// ```
///
/// # Arguments
/// * `commitment` - The identity commitment
/// * `context_id` - Context identifier (e.g., election ID, poll ID)
///
/// # Returns
/// A hex-encoded nullifier string (64 hex chars).
pub fn generate_nullifier(commitment: &IdentityCommitment, context_id: &str) -> Nullifier {
    let mut hasher = Hasher::new_keyed(NULLIFIER_DOMAIN);
    hasher.update(commitment.as_hex().as_bytes());
    hasher.update(b"|");
    hasher.update(context_id.as_bytes());
    let hash = hasher.finalize();
    Nullifier(hex::encode(hash.as_bytes()))
}

/// Generate an identity fingerprint for fuzzy duplicate detection.
///
/// Unlike commitments, fingerprints are NOT salted and use normalized
/// (lowercased, trimmed) inputs. This intentionally increases collision
/// probability so that near-duplicates can be detected.
///
/// ```text
/// BLAKE3_keyed(FINGERPRINT_DOMAIN, normalize(given_name) || "|" || normalize(family_name) || "|" || dob)
/// ```
///
/// Two people with the same name and date of birth WILL produce the same
/// fingerprint. This is by design — it's a signal, not proof.
///
/// # Arguments
/// * `attrs` - Identity attributes
///
/// # Returns
/// A hex-encoded fingerprint string (64 hex chars).
pub fn generate_fingerprint(attrs: &IdentityAttributes) -> IdentityFingerprint {
    let mut hasher = Hasher::new_keyed(FINGERPRINT_DOMAIN);
    hasher.update(normalize_name(&attrs.given_name).as_bytes());
    hasher.update(b"|");
    hasher.update(normalize_name(&attrs.family_name).as_bytes());
    hasher.update(b"|");
    hasher.update(attrs.date_of_birth.trim().as_bytes());
    let hash = hasher.finalize();
    IdentityFingerprint(hex::encode(hash.as_bytes()))
}

/// Generate a document fingerprint for exact-match deduplication.
///
/// If a document ID is provided, this creates a hash that will exactly
/// match if the same document is used again — even by a different person.
/// This is the strongest duplicate detection signal.
///
/// # Arguments
/// * `document_type` - Type of document (e.g., "drivers_license")
/// * `document_id` - The document identifier
///
/// # Returns
/// A hex-encoded document fingerprint, or None if no document ID.
pub fn generate_document_fingerprint(
    document_type: &str,
    document_id: &str,
) -> DocumentFingerprint {
    let mut hasher = Hasher::new_keyed(DOCUMENT_DOMAIN);
    hasher.update(document_type.as_bytes());
    hasher.update(b"|");
    hasher.update(document_id.as_bytes());
    let hash = hasher.finalize();
    DocumentFingerprint(hex::encode(hash.as_bytes()))
}

/// Generate a random 32-byte salt for commitment generation.
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    getrandom::getrandom(&mut salt).expect("getrandom failed");
    salt
}

/// Normalize a name for fingerprint comparison.
/// Lowercases, trims whitespace, removes common prefixes/suffixes,
/// collapses multiple spaces.
fn normalize_name(name: &str) -> String {
    let mut n = name.to_lowercase().trim().to_string();

    // Remove common name prefixes (must be followed by space).
    // "mr ", "mrs ", etc. already include trailing space.
    for prefix in &["mr ", "mrs ", "ms ", "dr "] {
        if n.starts_with(prefix) {
            n = n[prefix.len()..].trim().to_string();
        }
    }

    // Remove common name suffixes (must be preceded by space to avoid
    // stripping from names like "hawaii" or matching "hajr").
    for suffix in &[" jr", " sr", " iii", " ii", " iv"] {
        if n.ends_with(suffix) {
            n = n[..n.len() - suffix.len()].trim().to_string();
        }
    }

    // Collapse multiple spaces
    while n.contains("  ") {
        n = n.replace("  ", " ");
    }

    // Remove non-alphabetic characters (hyphens, apostrophes vary by system).
    // Preserve Unicode alphabetic characters (e.g., Chinese, Arabic, Cyrillic)
    // so non-English names don't all collapse to empty strings.
    n.retain(|c| c.is_alphabetic() || c == ' ');

    n
}

/// SHA-512 hash a single field. Used as the inner hash in commitment generation.
fn sha512_field(value: &str) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(value.as_bytes());
    hasher.finalize().to_vec()
}

/// Verify that a set of attributes matches a known commitment.
/// Used during re-verification and account recovery.
pub fn verify_commitment(
    attrs: &IdentityAttributes,
    salt: &[u8; 32],
    expected: &IdentityCommitment,
) -> bool {
    let computed = generate_commitment(attrs, salt);
    // Constant-time comparison via the `subtle` crate to prevent timing attacks.
    // Using the audited `subtle::ConstantTimeEq` instead of hand-rolled comparison.
    let a = computed.as_hex().as_bytes();
    let b = expected.as_hex().as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_attrs() -> IdentityAttributes {
        IdentityAttributes {
            given_name: "John".to_string(),
            family_name: "Smith".to_string(),
            date_of_birth: "1990-01-15".to_string(),
            document_id: Some("DL123456".to_string()),
            document_type: Some("drivers_license".to_string()),
            extra_claims: vec![],
        }
    }

    #[test]
    fn commitment_is_deterministic() {
        let attrs = test_attrs();
        let salt = [42u8; 32];
        let c1 = generate_commitment(&attrs, &salt);
        let c2 = generate_commitment(&attrs, &salt);
        assert_eq!(c1, c2);
    }

    #[test]
    fn commitment_differs_with_different_salt() {
        let attrs = test_attrs();
        let salt1 = [1u8; 32];
        let salt2 = [2u8; 32];
        let c1 = generate_commitment(&attrs, &salt1);
        let c2 = generate_commitment(&attrs, &salt2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn commitment_differs_with_different_name() {
        let salt = [42u8; 32];
        let a1 = test_attrs();
        let mut a2 = test_attrs();
        a2.given_name = "Jane".to_string();
        let c1 = generate_commitment(&a1, &salt);
        let c2 = generate_commitment(&a2, &salt);
        assert_ne!(c1, c2);
    }

    #[test]
    fn commitment_differs_with_different_dob() {
        let salt = [42u8; 32];
        let a1 = test_attrs();
        let mut a2 = test_attrs();
        a2.date_of_birth = "1990-01-16".to_string();
        let c1 = generate_commitment(&a1, &salt);
        let c2 = generate_commitment(&a2, &salt);
        assert_ne!(c1, c2);
    }

    #[test]
    fn verify_commitment_works() {
        let attrs = test_attrs();
        let salt = [42u8; 32];
        let commitment = generate_commitment(&attrs, &salt);
        assert!(verify_commitment(&attrs, &salt, &commitment));
    }

    #[test]
    fn verify_commitment_rejects_wrong_attrs() {
        let attrs = test_attrs();
        let salt = [42u8; 32];
        let commitment = generate_commitment(&attrs, &salt);
        let mut wrong = test_attrs();
        wrong.given_name = "Jane".to_string();
        assert!(!verify_commitment(&wrong, &salt, &commitment));
    }

    #[test]
    fn nullifier_is_deterministic() {
        let attrs = test_attrs();
        let salt = [42u8; 32];
        let commitment = generate_commitment(&attrs, &salt);
        let n1 = generate_nullifier(&commitment, "election-2026");
        let n2 = generate_nullifier(&commitment, "election-2026");
        assert_eq!(n1, n2);
    }

    #[test]
    fn nullifier_differs_per_context() {
        let attrs = test_attrs();
        let salt = [42u8; 32];
        let commitment = generate_commitment(&attrs, &salt);
        let n1 = generate_nullifier(&commitment, "election-2026");
        let n2 = generate_nullifier(&commitment, "election-2027");
        assert_ne!(n1, n2);
    }

    #[test]
    fn fingerprint_ignores_case() {
        let mut a1 = test_attrs();
        a1.given_name = "JOHN".to_string();
        let mut a2 = test_attrs();
        a2.given_name = "john".to_string();
        let f1 = generate_fingerprint(&a1);
        let f2 = generate_fingerprint(&a2);
        assert_eq!(f1, f2);
    }

    #[test]
    fn fingerprint_ignores_name_suffixes() {
        let mut a1 = test_attrs();
        a1.family_name = "Smith Jr".to_string();
        let mut a2 = test_attrs();
        a2.family_name = "Smith".to_string();
        let f1 = generate_fingerprint(&a1);
        let f2 = generate_fingerprint(&a2);
        assert_eq!(f1, f2);
    }

    #[test]
    fn document_fingerprint_exact_match() {
        let d1 = generate_document_fingerprint("drivers_license", "DL123456");
        let d2 = generate_document_fingerprint("drivers_license", "DL123456");
        assert_eq!(d1, d2);
    }

    #[test]
    fn document_fingerprint_differs_for_different_docs() {
        let d1 = generate_document_fingerprint("drivers_license", "DL123456");
        let d2 = generate_document_fingerprint("drivers_license", "DL789012");
        assert_ne!(d1, d2);
    }

    #[test]
    fn commitment_length_is_64_hex() {
        let attrs = test_attrs();
        let salt = generate_salt();
        let c = generate_commitment(&attrs, &salt);
        assert_eq!(c.as_hex().len(), 64);
    }

    #[test]
    fn normalize_collapses_whitespace() {
        assert_eq!(normalize_name("  John   Doe  "), "john doe");
    }

    #[test]
    fn normalize_removes_titles() {
        assert_eq!(normalize_name("Dr John"), "john");
    }

    #[test]
    fn constant_time_verify_works() {
        // Verify the subtle::ConstantTimeEq-based comparison works correctly
        let attrs = test_attrs();
        let salt = [42u8; 32];
        let commitment = generate_commitment(&attrs, &salt);
        assert!(verify_commitment(&attrs, &salt, &commitment));

        // Tampered commitment must fail
        let tampered = IdentityCommitment("0".repeat(64));
        assert!(!verify_commitment(&attrs, &salt, &tampered));
    }

    #[test]
    fn extra_claims_change_commitment() {
        let salt = [42u8; 32];
        let a1 = test_attrs();
        let mut a2 = test_attrs();
        a2.extra_claims = vec![("party".to_string(), "Republican".to_string())];
        let c1 = generate_commitment(&a1, &salt);
        let c2 = generate_commitment(&a2, &salt);
        assert_ne!(c1, c2);
    }
}
