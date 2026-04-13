//! Identity lockdown and conflict resolution protocol.
//!
//! When the fraud engine detects a conflict (duplicate identity, document
//! reuse, etc.), both parties are locked out until the conflict is resolved.
//! Resolution requires escalation to a higher verification tier.
//!
//! # Lockdown Levels
//!
//! - **None:** Normal operation.
//! - **Soft:** Additional verification step required (e.g., KBA, CAPTCHA).
//!   Can self-resolve by completing the extra step.
//! - **Hard:** Account frozen. Must escalate (photo ID, in-person, admin).
//!   Cannot self-resolve — requires evidence of identity.
//! - **Permanent:** Confirmed fraud. Only admin with audit trail can lift.
//!
//! # Resolution Methods (in order of strength)
//!
//! 1. **Additional KBA:** Soft locks only. Deeper questions (address history, etc.)
//! 2. **Photo ID + Liveness:** Upload government ID + selfie for comparison.
//!    Resolves hard locks. Checked by admin or automated face-match.
//! 3. **In-person verification:** Physical appearance at designated location.
//!    Resolves any lock level including permanent.
//! 4. **Admin override:** Administrator reviews evidence and decides.
//!    Required for permanent lock resolution. Full audit trail.
//! 5. **Recovery code:** Proves ownership of the original registration.
//!    Only resolves account access, NOT identity conflicts.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::*;
use crate::fraud::IdentityStore;

/// A resolution request — submitted by a locked-out user to regain access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionRequest {
    pub id: Uuid,
    pub voter_hash: String,
    pub method: ResolutionMethod,
    pub status: ResolutionStatus,
    pub evidence: Option<serde_json::Value>,
    pub submitted_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<String>,
    pub notes: Option<String>,
}

/// How the user is trying to resolve the lockdown.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionMethod {
    /// Additional KBA challenge (soft locks only).
    AdditionalKba,
    /// Photo ID upload + selfie (hard locks).
    PhotoId,
    /// In-person verification (any lock level).
    InPerson,
    /// Admin review of submitted evidence.
    AdminReview,
    /// Recovery code verification (access recovery only).
    RecoveryCode,
}

/// Status of a resolution request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStatus {
    /// Submitted, awaiting processing.
    Pending,
    /// Under review by admin.
    UnderReview,
    /// Approved — lockdown will be lifted.
    Approved,
    /// Denied — lockdown remains.
    Denied,
    /// Expired — took too long.
    Expired,
}

/// Check whether a resolution method is sufficient for a given lockdown level.
pub fn can_resolve(method: &ResolutionMethod, level: LockdownLevel) -> bool {
    match level {
        LockdownLevel::None => true, // Nothing to resolve
        LockdownLevel::Soft => matches!(
            method,
            ResolutionMethod::AdditionalKba
                | ResolutionMethod::PhotoId
                | ResolutionMethod::InPerson
                | ResolutionMethod::AdminReview
        ),
        LockdownLevel::Hard => matches!(
            method,
            ResolutionMethod::PhotoId
                | ResolutionMethod::InPerson
                | ResolutionMethod::AdminReview
        ),
        LockdownLevel::Permanent => matches!(
            method,
            ResolutionMethod::InPerson | ResolutionMethod::AdminReview
        ),
    }
}

/// Create a resolution request. Returns None if the method is insufficient
/// for the current lockdown level.
pub fn create_resolution_request(
    voter_hash: &str,
    method: ResolutionMethod,
    lockdown_level: LockdownLevel,
    evidence: Option<serde_json::Value>,
) -> Option<ResolutionRequest> {
    if !can_resolve(&method, lockdown_level) {
        return None;
    }

    Some(ResolutionRequest {
        id: Uuid::new_v4(),
        voter_hash: voter_hash.to_string(),
        method,
        status: ResolutionStatus::Pending,
        evidence,
        submitted_at: Utc::now(),
        resolved_at: None,
        resolved_by: None,
        notes: None,
    })
}

/// Resolve a lockdown after admin approval.
/// Lifts the lock on the voter hash and records the resolution.
///
/// Returns the updated lockdown level (should be None if fully resolved).
pub fn resolve_lockdown<S: IdentityStore>(
    store: &mut S,
    voter_hash: &str,
    approved_by: &str,
    notes: &str,
) -> Result<LockdownLevel, S::Error> {
    // Lift the lockdown by setting it to None
    store.apply_lockdown(
        voter_hash,
        LockdownLevel::None,
        LockdownReason::AdminAction {
            admin_id: approved_by.to_string(),
            reason: format!("Lockdown resolved: {}", notes),
        },
    )?;
    Ok(LockdownLevel::None)
}

/// Escalate a lockdown to a higher level.
/// Only escalates — never de-escalates (use resolve_lockdown for that).
pub fn escalate_lockdown<S: IdentityStore>(
    store: &mut S,
    voter_hash: &str,
    new_level: LockdownLevel,
    reason: LockdownReason,
) -> Result<(), S::Error> {
    let current = store.get_lockdown_level(voter_hash)?;
    if new_level > current {
        store.apply_lockdown(voter_hash, new_level, reason)?;
    }
    Ok(())
}

/// Get a human-readable description of what the user needs to do to resolve.
pub fn resolution_instructions(level: LockdownLevel) -> &'static str {
    match level {
        LockdownLevel::None => "No action needed.",
        LockdownLevel::Soft => {
            "Your identity requires additional verification. Please answer \
             the security questions or upload a photo of your government-issued ID."
        }
        LockdownLevel::Hard => {
            "Your identity has been flagged for review due to a potential conflict. \
             To resolve this, please upload a clear photo of your government-issued ID \
             along with a selfie. Alternatively, you may verify in person."
        }
        LockdownLevel::Permanent => {
            "Your account has been permanently locked due to a confirmed identity \
             conflict. Please contact support to arrange in-person verification. \
             You will need to present your government-issued photo ID in person."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soft_lock_resolvable_by_kba() {
        assert!(can_resolve(&ResolutionMethod::AdditionalKba, LockdownLevel::Soft));
    }

    #[test]
    fn soft_lock_resolvable_by_photo_id() {
        assert!(can_resolve(&ResolutionMethod::PhotoId, LockdownLevel::Soft));
    }

    #[test]
    fn hard_lock_not_resolvable_by_kba() {
        assert!(!can_resolve(&ResolutionMethod::AdditionalKba, LockdownLevel::Hard));
    }

    #[test]
    fn hard_lock_resolvable_by_photo_id() {
        assert!(can_resolve(&ResolutionMethod::PhotoId, LockdownLevel::Hard));
    }

    #[test]
    fn permanent_lock_only_resolvable_in_person_or_admin() {
        assert!(!can_resolve(&ResolutionMethod::PhotoId, LockdownLevel::Permanent));
        assert!(can_resolve(&ResolutionMethod::InPerson, LockdownLevel::Permanent));
        assert!(can_resolve(&ResolutionMethod::AdminReview, LockdownLevel::Permanent));
    }

    #[test]
    fn create_resolution_rejects_insufficient_method() {
        let req = create_resolution_request(
            "voter-aaa",
            ResolutionMethod::AdditionalKba,
            LockdownLevel::Hard,
            None,
        );
        assert!(req.is_none());
    }

    #[test]
    fn create_resolution_accepts_sufficient_method() {
        let req = create_resolution_request(
            "voter-aaa",
            ResolutionMethod::PhotoId,
            LockdownLevel::Hard,
            None,
        );
        assert!(req.is_some());
        assert_eq!(req.unwrap().status, ResolutionStatus::Pending);
    }

    #[test]
    fn recovery_code_does_not_resolve_identity_locks() {
        assert!(!can_resolve(&ResolutionMethod::RecoveryCode, LockdownLevel::Soft));
        assert!(!can_resolve(&ResolutionMethod::RecoveryCode, LockdownLevel::Hard));
    }

    #[test]
    fn instructions_vary_by_level() {
        let soft = resolution_instructions(LockdownLevel::Soft);
        let hard = resolution_instructions(LockdownLevel::Hard);
        let perm = resolution_instructions(LockdownLevel::Permanent);
        assert_ne!(soft, hard);
        assert_ne!(hard, perm);
        assert!(perm.contains("in person"));
    }
}
