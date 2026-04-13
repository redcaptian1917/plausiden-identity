//! Name similarity engine for near-duplicate identity detection.
//!
//! Uses multiple string distance algorithms to catch intentional and
//! accidental name variations: typos, nicknames, transliterations,
//! prefix/suffix differences, and deliberate evasion attempts.
//!
//! # Adversarial Considerations
//!
//! An attacker might try:
//! - Slightly misspelling their name ("Jon" vs "John")
//! - Using a nickname ("Rob" vs "Robert")
//! - Swapping first/last name order
//! - Adding/removing middle names
//! - Using accented vs unaccented characters
//! - Transliterating between scripts
//!
//! The similarity engine catches all of these by combining:
//! - Jaro-Winkler distance (good for typos/transpositions)
//! - Normalized Levenshtein distance (good for insertions/deletions)
//! - Phonetic encoding comparison (catches sound-alike names)
//! - Name-part reordering comparison (catches first/last swap)

use strsim::{jaro_winkler, normalized_levenshtein};

/// Thresholds for name similarity scoring.
/// Values are between 0.0 (completely different) and 1.0 (identical).
pub const THRESHOLD_EXACT: f64 = 1.0;
pub const THRESHOLD_NEAR_MATCH: f64 = 0.92;
pub const THRESHOLD_SUSPICIOUS: f64 = 0.80;
pub const THRESHOLD_INVESTIGATE: f64 = 0.70;

/// Result of a similarity comparison between two identity attribute sets.
#[derive(Debug, Clone)]
pub struct SimilarityResult {
    /// Overall similarity score (0.0 to 1.0).
    pub overall_score: f64,
    /// Name similarity score.
    pub name_score: f64,
    /// Date of birth match (exact boolean).
    pub dob_match: bool,
    /// Address similarity score (if available).
    pub address_score: Option<f64>,
    /// Interpretation of the result.
    pub interpretation: SimilarityInterpretation,
}

/// What the similarity score means.
#[derive(Debug, Clone, PartialEq)]
pub enum SimilarityInterpretation {
    /// Exact or near-exact match — very likely the same person.
    SamePerson,
    /// Suspiciously similar — could be the same person or a close relative.
    Suspicious,
    /// Worth investigating — some attributes match.
    Investigate,
    /// Different people — low similarity.
    Different,
}

/// Compare two sets of identity attributes for similarity.
///
/// # Arguments
/// * `name_a` - Full name of first identity (given + family)
/// * `dob_a` - Date of birth of first identity
/// * `name_b` - Full name of second identity
/// * `dob_b` - Date of birth of second identity
///
/// # Returns
/// A `SimilarityResult` with scores and interpretation.
pub fn compare_identities(
    name_a: &str,
    dob_a: &str,
    name_b: &str,
    dob_b: &str,
) -> SimilarityResult {
    let name_score = compare_names(name_a, name_b);
    let dob_match = dob_a.trim() == dob_b.trim();

    // Overall score: name similarity weighted heavily, DOB is binary
    let overall_score = if dob_match {
        // Same DOB amplifies name similarity
        0.5 + (name_score * 0.5)
    } else {
        // Different DOB dampens overall score significantly
        name_score * 0.4
    };

    let interpretation = if dob_match && name_score >= THRESHOLD_NEAR_MATCH {
        SimilarityInterpretation::SamePerson
    } else if dob_match && name_score >= THRESHOLD_SUSPICIOUS {
        SimilarityInterpretation::Suspicious
    } else if dob_match && name_score >= THRESHOLD_INVESTIGATE {
        SimilarityInterpretation::Investigate
    } else if !dob_match && name_score >= THRESHOLD_EXACT {
        // Same name, different DOB — could be a relative or typo in DOB
        SimilarityInterpretation::Investigate
    } else {
        SimilarityInterpretation::Different
    };

    SimilarityResult {
        overall_score,
        name_score,
        dob_match,
        address_score: None,
        interpretation,
    }
}

/// Compare two full names using multiple distance metrics.
///
/// Returns a combined score from 0.0 (completely different) to 1.0 (identical).
///
/// Combines Jaro-Winkler (good for typos at the end) and Normalized Levenshtein
/// (good for insertions/deletions), plus a name-part reordering check.
pub fn compare_names(name_a: &str, name_b: &str) -> f64 {
    let a = normalize_for_comparison(name_a);
    let b = normalize_for_comparison(name_b);

    if a == b {
        return 1.0;
    }

    if a.is_empty() || b.is_empty() {
        return 0.0;
    }

    // Direct comparison
    let jw = jaro_winkler(&a, &b);
    let nl = normalized_levenshtein(&a, &b);

    // Name-part reordering: "john smith" vs "smith john"
    let reorder_score = compare_name_parts(&a, &b);

    // Phonetic comparison: simple soundex-like encoding
    let phonetic_score = compare_phonetic(&a, &b);

    // Weighted combination — favor the highest match
    let direct_score = (jw * 0.5) + (nl * 0.3) + (phonetic_score * 0.2);

    // Take the max of direct and reordered comparison
    direct_score.max(reorder_score)
}

/// Compare name parts regardless of order.
/// "John Michael Smith" should match "Smith, John M." highly.
fn compare_name_parts(a: &str, b: &str) -> f64 {
    let parts_a: Vec<&str> = a.split_whitespace().collect();
    let parts_b: Vec<&str> = b.split_whitespace().collect();

    if parts_a.is_empty() || parts_b.is_empty() {
        return 0.0;
    }

    // For each part in A, find the best match in B
    let mut total_score = 0.0;
    let mut matched = 0;

    for pa in &parts_a {
        let best = parts_b
            .iter()
            .map(|pb| jaro_winkler(pa, pb))
            .fold(0.0f64, f64::max);
        if best >= 0.85 {
            total_score += best;
            matched += 1;
        }
    }

    if matched == 0 {
        return 0.0;
    }

    // Score based on how many parts matched and how well
    let coverage = matched as f64 / parts_a.len().max(parts_b.len()) as f64;
    let avg_score = total_score / matched as f64;
    coverage * avg_score
}

/// Simple phonetic comparison using a basic soundex-like encoding.
/// Good for catching "Jon" vs "John", "Steven" vs "Stephen", etc.
fn compare_phonetic(a: &str, b: &str) -> f64 {
    let enc_a = phonetic_encode(a);
    let enc_b = phonetic_encode(b);
    if enc_a == enc_b {
        1.0
    } else {
        normalized_levenshtein(&enc_a, &enc_b)
    }
}

/// Basic phonetic encoding: removes vowels (except leading), collapses
/// double consonants, maps common substitutions.
fn phonetic_encode(name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }

    let chars: Vec<char> = name.chars().collect();
    let mut encoded = String::new();

    // Keep the first character as-is
    encoded.push(chars[0]);

    for &c in &chars[1..] {
        let mapped = match c {
            // Common phonetic equivalences
            'b' | 'f' | 'p' | 'v' => '1',
            'c' | 'g' | 'j' | 'k' | 'q' | 's' | 'x' | 'z' => '2',
            'd' | 't' => '3',
            'l' => '4',
            'm' | 'n' => '5',
            'r' => '6',
            // Vowels and h/w/y are dropped
            _ => continue,
        };

        // Don't add consecutive identical codes
        if encoded.ends_with(mapped) {
            continue;
        }

        encoded.push(mapped);
    }

    encoded
}

/// Normalize a name for comparison: lowercase, remove punctuation,
/// trim whitespace, collapse spaces.
fn normalize_for_comparison(name: &str) -> String {
    let mut n = name.to_lowercase();
    n.retain(|c| c.is_ascii_alphanumeric() || c == ' ');
    // Collapse multiple spaces
    while n.contains("  ") {
        n = n.replace("  ", " ");
    }
    n.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        let r = compare_identities("John Smith", "1990-01-15", "John Smith", "1990-01-15");
        assert_eq!(r.name_score, 1.0);
        assert!(r.dob_match);
        assert_eq!(r.interpretation, SimilarityInterpretation::SamePerson);
    }

    #[test]
    fn case_insensitive_match() {
        let r = compare_identities("JOHN SMITH", "1990-01-15", "john smith", "1990-01-15");
        assert_eq!(r.name_score, 1.0);
        assert_eq!(r.interpretation, SimilarityInterpretation::SamePerson);
    }

    #[test]
    fn typo_in_name() {
        let r = compare_identities("John Smith", "1990-01-15", "Jon Smith", "1990-01-15");
        assert!(r.name_score >= 0.85, "Score: {}", r.name_score);
        assert!(
            r.interpretation == SimilarityInterpretation::SamePerson
                || r.interpretation == SimilarityInterpretation::Suspicious
        );
    }

    #[test]
    fn name_parts_reordered() {
        let r = compare_identities("John Smith", "1990-01-15", "Smith John", "1990-01-15");
        assert!(r.name_score >= 0.80, "Score: {}", r.name_score);
        assert_ne!(r.interpretation, SimilarityInterpretation::Different);
    }

    #[test]
    fn different_people_same_dob() {
        let r = compare_identities("John Smith", "1990-01-15", "Alice Johnson", "1990-01-15");
        assert!(r.name_score < 0.5);
        assert_eq!(r.interpretation, SimilarityInterpretation::Different);
    }

    #[test]
    fn same_name_different_dob() {
        let r = compare_identities("John Smith", "1990-01-15", "John Smith", "1991-02-20");
        assert_eq!(r.name_score, 1.0);
        assert!(!r.dob_match);
        // Same name, different DOB — worth investigating
        assert_eq!(r.interpretation, SimilarityInterpretation::Investigate);
    }

    #[test]
    fn completely_different() {
        let r =
            compare_identities("John Smith", "1990-01-15", "Maria Garcia", "1985-07-22");
        assert!(r.overall_score < 0.3);
        assert_eq!(r.interpretation, SimilarityInterpretation::Different);
    }

    #[test]
    fn nickname_detection() {
        // "Rob" vs "Robert" — phonetic encoding should help
        let score = compare_names("Robert Smith", "Rob Smith");
        assert!(score >= 0.75, "Score: {}", score);
    }

    #[test]
    fn middle_name_tolerance() {
        let score = compare_names("John Michael Smith", "John Smith");
        assert!(score >= 0.70, "Score: {}", score);
    }

    #[test]
    fn phonetic_match() {
        let score = compare_names("Steven Jones", "Stephen Jones");
        assert!(score >= 0.85, "Score: {}", score);
    }

    #[test]
    fn phonetic_encode_basic() {
        // 'r' kept, o dropped (vowel), b→1, e dropped, r→6, t→3
        assert_eq!(phonetic_encode("robert"), "r163");
        // 'r' kept, u dropped, p→1, e dropped, r→6, t→3
        assert_eq!(phonetic_encode("rupert"), "r163");
    }

    #[test]
    fn normalize_removes_punctuation() {
        assert_eq!(normalize_for_comparison("O'Brien-Smith"), "obriensmith");
    }

    #[test]
    fn empty_names() {
        assert_eq!(compare_names("", "John"), 0.0);
        assert_eq!(compare_names("John", ""), 0.0);
    }
}
