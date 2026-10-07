//! Explicit authority for one finite commissioning session (ADR 0016).
//!
//! A permit is deliberately outside the qualification record/index types.
//! It proves no provider behavior and never derives production readiness.
//! This pure verifier checks signed authority only. Its runtime consumer must
//! additionally reserve the immutable lease budget in durable shared state
//! before custody access, and keep this authority off the application socket.

use crate::canonical::{self, Artifact, Canonical, Sealed};
use crate::verify::verifies;
use crate::{
    BoundedText, GitCommit, LifecycleStoreKind, ProviderEnvironmentClass,
    QualificationArtifactKind, QualificationFormatError, QualificationRevocationList,
    QualificationSignatureSuite, QualificationSignerCertificate, QualificationSignerId,
    QualificationTrustRoot, QualificationTuple, Sha256Digest, SignatureB64, VerifierState,
};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

/// The separate signature domain of a commissioning permit.
pub const COMMISSIONING_PERMIT_SCHEMA: &str = "auths.qualification-commissioning-permit/1";
/// Public file within a protected commissioning artifact directory.
pub const COMMISSIONING_PERMIT_FILE: &str = "commissioning-permit.json";
/// The domain of the stable run/family budget key.
pub const COMMISSIONING_BUDGET_KEY_DOMAIN: &str = "auths.qualification-commissioning-budget-key/1";
/// The domain of the immutable budget binding, including its ceiling.
pub const COMMISSIONING_BUDGET_BINDING_DOMAIN: &str =
    "auths.qualification-commissioning-budget-binding/1";
/// The largest commissioning permit accepted before parsing.
pub const MAX_COMMISSIONING_PERMIT_BYTES: usize = 32 * 1024;
/// The maximum distinct exact actions one permit may authorize.
pub const MAX_COMMISSIONING_ACTIONS: usize = 256;
/// The maximum custody acquisitions one permit may authorize.
pub const MAX_COMMISSIONING_LEASES: u64 = 1024;
/// A commissioning permit lasts at most two hours.
pub const MAX_COMMISSIONING_SECONDS: u64 = 2 * 60 * 60;

/// The two closed offline artifacts a protected signer must re-verify.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommissioningOfflineEvidence {
    /// Source, recipe digest, compiler/interpreter and closed-enumeration cases.
    pub conformance_sha256: Sha256Digest,
    /// The independently reviewed oracle's acceptance/rejection corpus.
    pub differential_sha256: Sha256Digest,
}

/// Everything fixed for a run, excluding signer rotation and time renewal.
///
/// Runtime identities come from the installed candidate and sealed verifier,
/// never from application assertions. Resource and action bindings are
/// expanded by the protected, reviewed reference before permit issuance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommissioningBinding {
    /// Exact protected workflow run identity, including its attempt.
    pub protected_run: BoundedText<256>,
    /// The installed candidate's immutable source revision.
    pub source_commit: GitCommit,
    /// Exact production recipe, contract, semantic closure, binary and target.
    pub tuple: QualificationTuple,
    /// Commitment to the ephemeral proof-authoring principal's canonical bytes.
    pub principal_sha256: Sha256Digest,
    /// Commitment to the operator-approved canonical trusted context.
    pub trusted_context_sha256: Sha256Digest,
    /// Commitment to the reviewed disposable provider resource bindings.
    pub resources_sha256: Sha256Digest,
    /// What kind of disposable provider environment is actually exercised.
    pub provider_environment_class: ProviderEnvironmentClass,
    /// Offline evidence which the issuing signer checked for this candidate.
    pub offline_evidence: CommissioningOfflineEvidence,
    /// Exact canonical action commitments, strictly ascending and unique.
    pub allowed_actions: Vec<Sha256Digest>,
    /// Lifetime custody-acquisition ceiling for this run and family.
    pub maximum_credential_leases: u64,
}

impl CommissioningBinding {
    /// The durable budget's key, stable across renewals and signer rotation.
    ///
    /// Changing any other binding member must conflict with the original
    /// durable registration at this key. It must never open a fresh counter.
    ///
    /// # Errors
    ///
    /// Returns [`QualificationFormatError::Malformed`] if canonical encoding
    /// fails. No I/O or counter allocation occurs here.
    pub fn budget_key(&self) -> Result<Sha256Digest, QualificationFormatError> {
        #[derive(Serialize)]
        struct Key<'a> {
            protected_run: &'a BoundedText<256>,
            recipe_family: &'a crate::RecipeFamilyId,
        }
        Ok(canonical::domain_digest(
            COMMISSIONING_BUDGET_KEY_DOMAIN,
            &canonical::canonical_bytes(&Key {
                protected_run: &self.protected_run,
                recipe_family: &self.tuple.recipe_family,
            })?,
        ))
    }

    /// Commitment the durable store must bind immutably at [`Self::budget_key`].
    ///
    /// # Errors
    ///
    /// Returns [`QualificationFormatError::Malformed`] if encoding fails.
    pub fn budget_binding(&self) -> Result<Sha256Digest, QualificationFormatError> {
        Ok(canonical::domain_digest(
            COMMISSIONING_BUDGET_BINDING_DOMAIN,
            &canonical::canonical_bytes(self)?,
        ))
    }

    /// Checks the production-only target, finite lease ceiling and exact list.
    ///
    /// # Errors
    ///
    /// Returns a format refusal for a development target or a broken hard
    /// bound/order. This check authenticates neither evidence nor signatures.
    pub fn validate(&self) -> Result<(), QualificationFormatError> {
        if self.tuple.target.store_kind != LifecycleStoreKind::PostgresqlV1
            || !self.tuple.target.credential_store_kind.is_production()
        {
            return Err(QualificationFormatError::Malformed);
        }
        if self.allowed_actions.is_empty()
            || self.allowed_actions.len() > MAX_COMMISSIONING_ACTIONS
            || !(1..=MAX_COMMISSIONING_LEASES).contains(&self.maximum_credential_leases)
        {
            return Err(QualificationFormatError::ListBound);
        }
        canonical::strictly_ascending(&self.allowed_actions)
    }
}

/// The exact statement a purpose-certified commissioning signer signs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommissioningPermitStatement {
    /// Exactly [`COMMISSIONING_PERMIT_SCHEMA`].
    pub schema: String,
    /// Run bindings which renewal cannot change or reset.
    pub binding: CommissioningBinding,
    /// The commissioning signer, distinct in purpose from a release signer.
    pub signer_id: QualificationSignerId,
    /// The signature suite.
    pub signature_suite: QualificationSignatureSuite,
    /// The actual issue time, no later than the start of the window.
    pub issued_at: u64,
    /// Start of the finite session.
    pub not_before: u64,
    /// End of the finite session, at most two hours after issue.
    pub not_after: u64,
}

/// The closed commissioning artifact: a statement and its purpose-bound signature.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommissioningPermitBody {
    /// All signed bindings, signer and times.
    pub statement: CommissioningPermitStatement,
    /// Ed25519 signature over [`Self::signing_preimage`].
    pub signature_b64: SignatureB64,
}

impl CommissioningPermitBody {
    /// Exact signature preimage; no record, index or proof has this domain.
    ///
    /// # Errors
    ///
    /// Returns [`QualificationFormatError::Malformed`] if encoding fails.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, QualificationFormatError> {
        Ok(canonical::preimage(
            COMMISSIONING_PERMIT_SCHEMA,
            &canonical::canonical_bytes(&self.statement)?,
        ))
    }
}

impl Sealed for CommissioningPermitBody {}

impl Artifact for CommissioningPermitBody {
    const SCHEMA: &'static str = COMMISSIONING_PERMIT_SCHEMA;
    const MAX_BYTES: usize = MAX_COMMISSIONING_PERMIT_BYTES;

    fn schema(&self) -> &str {
        &self.statement.schema
    }

    fn validate(&self) -> Result<(), QualificationFormatError> {
        let statement = &self.statement;
        canonical::valid_window(
            statement.issued_at,
            statement.not_before,
            statement.not_after,
            MAX_COMMISSIONING_SECONDS,
        )?;
        // Counting from issue prevents a long-dated dormant permit from
        // reserving a future two-hour window beyond the maximum lifetime.
        if statement.issued_at > statement.not_before
            || statement.not_after - statement.issued_at > MAX_COMMISSIONING_SECONDS
        {
            return Err(QualificationFormatError::InvalidTimeWindow);
        }
        statement.binding.validate()
    }
}

/// Structurally validated bytes, without any claim of trusted authority.
pub type QualificationCommissioningPermit = Canonical<CommissioningPermitBody>;

/// Untrusted canonical bytes the commissioning verifier authenticates.
#[derive(Clone, Copy, Debug)]
pub struct CommissioningInputs<'a> {
    /// Root-issued, commissioning-purpose signer certificate.
    pub signer_certificate: &'a [u8],
    /// Root-issued revocation list.
    pub revocation_list: &'a [u8],
    /// Separately signed commissioning permit.
    pub permit: &'a [u8],
}

/// Runtime bindings derived independently of the supplied permit.
#[derive(Clone, Copy, Debug)]
pub struct CommissioningRequest<'a> {
    /// Installed source revision.
    pub source_commit: &'a GitCommit,
    /// Current deployment tuple, never the caller's reported tuple.
    pub tuple: &'a QualificationTuple,
    /// Authenticated operator session's protected run identity.
    pub protected_run: &'a BoundedText<256>,
    /// Sealed verifier's exact proof-authoring principal commitment.
    pub principal_sha256: Sha256Digest,
    /// Operator-approved context actually executed by the verifier.
    pub trusted_context_sha256: Sha256Digest,
    /// Operator-approved disposable resource binding.
    pub resources_sha256: Sha256Digest,
    /// Native commitment of the verified canonical action.
    pub canonical_action_sha256: Sha256Digest,
}

/// A commissioning check's closed first refusal; never a qualification state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommissioningRefusal {
    /// Missing, malformed, forged, wrong-root or wrong-purpose signed inputs.
    Unavailable,
    /// A currently or previously authenticated list revoked this signer.
    Revoked,
    /// The revocation sequence went backwards.
    RevocationRollback,
    /// Untrusted clock or time before signed issue/window start.
    ClockUntrusted,
    /// Root revocations are past their signed refresh deadline.
    RevocationStale,
    /// The permit or signer window ended.
    Expired,
    /// An exact session, principal, action, context, resource or target differs.
    BindingMismatch,
}

impl CommissioningRefusal {
    /// Closed reason token, distinct from the qualification code family.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Revoked => "revoked",
            Self::RevocationRollback => "revocation-rollback",
            Self::ClockUntrusted => "clock-untrusted",
            Self::RevocationStale => "revocation-stale",
            Self::Expired => "expired",
            Self::BindingMismatch => "binding-mismatch",
        }
    }
}

/// Signature-checked commissioning authority, with no lease or readiness grant.
///
/// Holding this sealed value authenticates bytes only. [`Self::evaluate`]
/// checks current time, remembered revocations and each runtime binding before
/// every lease. Only a private operator session may consume a successful
/// check, after an atomic durable budget claim.
#[derive(Clone, Debug)]
pub struct VerifiedCommissioningPermit {
    certificate: QualificationSignerCertificate,
    revocations: QualificationRevocationList,
    permit: QualificationCommissioningPermit,
}

impl VerifiedCommissioningPermit {
    /// Authenticates all three closed artifacts under the pinned root.
    ///
    /// # Errors
    ///
    /// Returns [`CommissioningRefusal::Unavailable`] for any structural,
    /// signature, root, signer, permission or certificate-window fault. No
    /// supplied root or permit can upgrade ordinary application qualification.
    pub fn verify(
        root: &QualificationTrustRoot,
        inputs: &CommissioningInputs<'_>,
    ) -> Result<Self, CommissioningRefusal> {
        let unavailable = CommissioningRefusal::Unavailable;
        let certificate =
            QualificationSignerCertificate::from_canonical_json(inputs.signer_certificate)
                .map_err(|_| unavailable)?;
        let revocations = QualificationRevocationList::from_canonical_json(inputs.revocation_list)
            .map_err(|_| unavailable)?;
        let permit = QualificationCommissioningPermit::from_canonical_json(inputs.permit)
            .map_err(|_| unavailable)?;
        let cert = certificate.body();
        let signer = &cert.statement;
        let list = revocations.body();
        let permit_body = permit.body();
        let statement = &permit_body.statement;
        let root_key = root.body().public_key_b64.to_bytes();
        let root_signature = |preimage: Result<Vec<u8>, QualificationFormatError>,
                              signature: &SignatureB64| {
            preimage.is_ok_and(|bytes| verifies(&root_key, &bytes, &signature.to_bytes()))
        };
        if signer.root_id != root.body().root_id
            || list.statement.root_id != root.body().root_id
            || !root_signature(cert.signing_preimage(), &cert.root_signature_b64)
            || !root_signature(list.signing_preimage(), &list.root_signature_b64)
            || signer.permitted_artifact_kinds
                != [QualificationArtifactKind::QualificationCommissioningPermit]
            || statement.signer_id != signer.signer_id
            || statement.issued_at < signer.issued_at
            || statement.not_before < signer.not_before
            || statement.not_after > signer.not_after
            || !permit_body.signing_preimage().is_ok_and(|bytes| {
                verifies(
                    &signer.public_key_b64.to_bytes(),
                    &bytes,
                    &permit_body.signature_b64.to_bytes(),
                )
            })
        {
            return Err(unavailable);
        }
        Ok(Self {
            certificate,
            revocations,
            permit,
        })
    }

    /// Authenticated permit bytes; not proof of current validity or consumption.
    #[must_use]
    pub const fn permit(&self) -> &QualificationCommissioningPermit {
        &self.permit
    }

    /// Permanently remembers authenticated revocations and the largest sequence.
    ///
    /// A stale list still revokes what it names. The runtime must durably
    /// persist this state before acknowledging an operator import.
    pub fn remember(&self, state: &mut VerifierState) {
        let list = &self.revocations.body().statement;
        state
            .revoked_signers
            .extend(list.revoked_signers.iter().cloned());
        state
            .revoked_qualifications
            .extend(list.revoked_qualifications.iter().cloned());
        state.accepted_revocation_sequence = state.accepted_revocation_sequence.max(list.sequence);
    }

    /// Checks signed freshness and exact runtime bindings for one lease attempt.
    ///
    /// A successful result is a necessary condition only: the runtime must
    /// atomically claim one unit from the immutably registered shared budget
    /// before credentials, and still execute ordinary proof/recipe/attempt
    /// checks. This method cannot mint a [`crate::QualificationVerdict`].
    ///
    /// # Errors
    ///
    /// Returns the first closed refusal. Earlier authenticated revocations
    /// dominate time faults; rolled-back lists never restore authority.
    pub fn evaluate(
        &self,
        request: &CommissioningRequest<'_>,
        now: u64,
        clock_trusted: bool,
        state: &VerifierState,
    ) -> Result<(), CommissioningRefusal> {
        let signer = &self.certificate.body().statement;
        let list = &self.revocations.body().statement;
        let statement = &self.permit.body().statement;
        let binding = &statement.binding;
        if state.revoked_signers.contains(&signer.signer_id)
            || list.revoked_signers.contains(&signer.signer_id)
        {
            return Err(CommissioningRefusal::Revoked);
        }
        if list.sequence < state.accepted_revocation_sequence {
            return Err(CommissioningRefusal::RevocationRollback);
        }
        if !clock_trusted
            || now < signer.issued_at
            || now < signer.not_before
            || now < list.issued_at
            || now < statement.issued_at
            || now < statement.not_before
        {
            return Err(CommissioningRefusal::ClockUntrusted);
        }
        // Windows are half-open. At the deadline, no lease can start.
        if now >= list.next_update {
            return Err(CommissioningRefusal::RevocationStale);
        }
        if now >= signer.not_after || now >= statement.not_after {
            return Err(CommissioningRefusal::Expired);
        }
        if binding.source_commit != *request.source_commit
            || binding.tuple != *request.tuple
            || binding.protected_run != *request.protected_run
            || binding.principal_sha256 != request.principal_sha256
            || binding.trusted_context_sha256 != request.trusted_context_sha256
            || binding.resources_sha256 != request.resources_sha256
            || binding
                .allowed_actions
                .binary_search(&request.canonical_action_sha256)
                .is_err()
        {
            return Err(CommissioningRefusal::BindingMismatch);
        }
        Ok(())
    }
}
