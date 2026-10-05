//! The release verifier: what signed inputs let a gateway conclude about one
//! deployment.
//!
//! Verification has two steps. [`VerifiedQualifications::verify`] checks
//! every signature once and keeps the result; it reads no clock. Then
//! [`VerifiedQualifications::evaluate`] decides, for one deployment tuple at
//! one time, the qualification state and the first reason it is not
//! qualified. Evaluation is pure and cheap, so a gateway runs it before
//! every lease.
//!
//! Nothing here is told a provider's name. A tuple's provider contract is
//! compared as a digest.

use crate::{
    Canonical, QualificationArtifactKind, QualificationId, QualificationReleaseIndex,
    QualificationRevocationList, QualificationSignerCertificate, QualificationSignerId,
    QualificationTrustRoot, QualificationTuple, RecipeQualificationAttestation,
    RecipeQualificationRecord, RecipeQualificationState, Sha256Digest,
};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::BTreeSet;

/// The first reason a deployment is not qualified.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum QualificationRefusal {
    /// The signer certificate, the release index, or the revocation list
    /// cannot be used.
    Unavailable,
    /// A verified revocation list, now or earlier, names the qualification
    /// or its signer.
    Revoked,
    /// The clock is untrusted, or local time is before a signed issue time.
    ClockUntrusted,
    /// The revocation list is past its next update.
    RevocationStale,
    /// No usable attestation exists for the recipe family.
    Missing,
    /// The attestation's or the signer certificate's window has ended.
    Expired,
    /// A digest member of the tuple differs.
    DigestMismatch,
    /// A target member of the tuple differs.
    TargetMismatch,
}

impl QualificationRefusal {
    /// Returns the reason token, which a gateway appends to its own code
    /// family.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Revoked => "revoked",
            Self::ClockUntrusted => "clock-untrusted",
            Self::RevocationStale => "revocation-stale",
            Self::Missing => "missing",
            Self::Expired => "expired",
            Self::DigestMismatch => "digest-mismatch",
            Self::TargetMismatch => "target-mismatch",
        }
    }
}

/// The derived state of one deployment and, unless it is qualified, the
/// first reason why not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationVerdict {
    /// The derived state.
    pub state: RecipeQualificationState,
    /// The first reason the deployment is not qualified; `None` exactly when
    /// the state is qualified.
    pub refusal: Option<QualificationRefusal>,
}

impl QualificationVerdict {
    const QUALIFIED: Self = Self {
        state: RecipeQualificationState::Qualified,
        refusal: None,
    };

    const fn refused(state: RecipeQualificationState, refusal: QualificationRefusal) -> Self {
        Self {
            state,
            refusal: Some(refusal),
        }
    }

    /// Whether a credential may be leased for the deployment.
    #[must_use]
    pub const fn permits_lease(&self) -> bool {
        self.state.permits_lease() && self.refusal.is_none()
    }
}

/// What a verifier remembers between inputs. Revocation is permanent: once a
/// verified list has named a signer or a qualification, a later list that
/// omits it does not restore it. A list older than one already accepted is
/// refused.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VerifierState {
    /// The highest revocation-list sequence accepted so far.
    pub accepted_revocation_sequence: u64,
    /// The latest issue time of a release index accepted so far. An index
    /// issued earlier is refused, so a qualification a later index dropped
    /// cannot be brought back by presenting the older index again.
    pub accepted_index_issued_at: u64,
    /// Every signer a verified list has named.
    pub revoked_signers: BTreeSet<QualificationSignerId>,
    /// Every qualification a verified list has named.
    pub revoked_qualifications: BTreeSet<QualificationId>,
}

/// The local inputs of one verification, each as the exact bytes it was
/// distributed as. All are bounded by their decoders.
#[derive(Clone, Copy, Debug)]
pub struct QualificationInputs<'input> {
    /// The signer certificate.
    pub signer_certificate: &'input [u8],
    /// The revocation list.
    pub revocation_list: &'input [u8],
    /// The release index.
    pub release_index: &'input [u8],
    /// The records the index may reference.
    pub records: &'input [&'input [u8]],
    /// The attestations the index may reference.
    pub attestations: &'input [&'input [u8]],
}

fn verifies(key: &[u8; 32], preimage: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(key).is_ok_and(|key| {
        key.verify_strict(preimage, &Signature::from_bytes(signature))
            .is_ok()
    })
}

/// A listed record with the attestation the index names for it, when that
/// attestation's own signature and bindings hold.
struct Listed {
    record: RecipeQualificationRecord,
    /// The attestation, present only when the index lists exactly these
    /// bytes, it names this record and the certified signer, the certificate
    /// permits attestations, its signature verifies, and its window lies
    /// within the record's.
    attestation: Option<RecipeQualificationAttestation>,
}

/// Inputs whose signatures have been checked once. Holding this value says
/// nothing about time: [`Self::evaluate`] judges every signed time bound.
pub struct VerifiedQualifications {
    /// The certificate, when the pinned root signed it.
    certificate: Option<QualificationSignerCertificate>,
    /// Whether the certified signer signed the index and may sign indexes.
    index: Option<QualificationReleaseIndex>,
    /// The revocation list, when the pinned root signed it.
    revocations: Option<QualificationRevocationList>,
    listed: Vec<Listed>,
}

impl VerifiedQualifications {
    /// Checks every signature under the pinned `root`. An input that does
    /// not decode or verify is kept as absent; nothing is trusted from it.
    #[must_use]
    pub fn verify(root: &QualificationTrustRoot, inputs: &QualificationInputs<'_>) -> Self {
        let root_key = root.body().public_key_b64.to_bytes();
        let certificate = Canonical::from_canonical_json(inputs.signer_certificate)
            .ok()
            .filter(|certificate: &QualificationSignerCertificate| {
                let body = certificate.body();
                body.statement.root_id == root.body().root_id
                    && body.signing_preimage().is_ok_and(|preimage| {
                        verifies(&root_key, &preimage, &body.root_signature_b64.to_bytes())
                    })
            });
        let revocations = Canonical::from_canonical_json(inputs.revocation_list)
            .ok()
            .filter(|list: &QualificationRevocationList| {
                let body = list.body();
                body.statement.root_id == root.body().root_id
                    && body.signing_preimage().is_ok_and(|preimage| {
                        verifies(&root_key, &preimage, &body.root_signature_b64.to_bytes())
                    })
            });
        let signer = certificate
            .as_ref()
            .map(|certificate| &certificate.body().statement);
        let permits = |kind: QualificationArtifactKind| {
            signer.is_some_and(|signer| signer.permitted_artifact_kinds.contains(&kind))
        };
        let signer_key = signer.map(|signer| signer.public_key_b64.to_bytes());
        let index = Canonical::from_canonical_json(inputs.release_index)
            .ok()
            .filter(|index: &QualificationReleaseIndex| {
                let body = index.body();
                permits(QualificationArtifactKind::QualificationReleaseIndex)
                    && signer.is_some_and(|signer| signer.signer_id == body.statement.signer_id)
                    && signer_key.is_some_and(|key| {
                        body.signing_preimage().is_ok_and(|preimage| {
                            verifies(&key, &preimage, &body.signature_b64.to_bytes())
                        })
                    })
            });
        let records: Vec<RecipeQualificationRecord> = inputs
            .records
            .iter()
            .filter_map(|bytes| Canonical::from_canonical_json(bytes).ok())
            .collect();
        let attestations: Vec<RecipeQualificationAttestation> = inputs
            .attestations
            .iter()
            .filter_map(|bytes| Canonical::from_canonical_json(bytes).ok())
            .collect();
        let attested = |record: &RecipeQualificationRecord, digest: &Sha256Digest| {
            let signer = signer?;
            let key = signer_key?;
            if !permits(QualificationArtifactKind::RecipeQualificationAttestation) {
                return None;
            }
            attestations
                .iter()
                .find(|attestation| attestation.digest() == *digest)
                .filter(|attestation| {
                    let body = attestation.body();
                    let statement = &body.statement;
                    statement.qualification_id == record.body().qualification_id
                        && statement.record_sha256 == record.digest()
                        && statement.signer_id == signer.signer_id
                        && statement.not_before >= record.body().not_before
                        && statement.not_after <= record.body().not_after
                        && body.signing_preimage().is_ok_and(|preimage| {
                            verifies(&key, &preimage, &body.signature_b64.to_bytes())
                        })
                })
                .cloned()
        };
        let listed = index.as_ref().map_or_else(Vec::new, |index| {
            index
                .body()
                .statement
                .entries
                .iter()
                .filter_map(|entry| {
                    let record = records
                        .iter()
                        .find(|record| record.digest() == entry.record_sha256)
                        .filter(|record| {
                            record.body().qualification_id == entry.qualification_id
                        })?;
                    Some(Listed {
                        attestation: attested(record, &entry.attestation_sha256),
                        record: record.clone(),
                    })
                })
                .collect()
        });
        Self {
            certificate,
            index,
            revocations,
            listed,
        }
    }

    /// Whether the certificate, the release index, and the revocation list
    /// each verified, and the list is no older than the one `state` records
    /// as accepted. Inputs that fail this authenticate nothing, whatever
    /// else they contain.
    #[must_use]
    pub fn inputs_usable(&self, state: &VerifierState) -> bool {
        self.certificate.is_some()
            && self.current_index(state).is_some()
            && self.revocations.as_ref().is_some_and(|list| {
                list.body().statement.sequence >= state.accepted_revocation_sequence
            })
    }

    /// The verified index, unless `state` has accepted a later one.
    fn current_index(&self, state: &VerifierState) -> Option<&QualificationReleaseIndex> {
        self.index
            .as_ref()
            .filter(|index| index.body().statement.issued_at >= state.accepted_index_issued_at)
    }

    /// Adds what the verified revocation list names to `state`, and raises
    /// the accepted list sequence and index issue time. A list older than
    /// the accepted one lowers nothing; what it names is still remembered.
    pub fn remember(&self, state: &mut VerifierState) {
        if let (Some(_), Some(index)) = (&self.certificate, &self.index) {
            state.accepted_index_issued_at = state
                .accepted_index_issued_at
                .max(index.body().statement.issued_at);
        }
        let Some(list) = &self.revocations else {
            return;
        };
        let statement = &list.body().statement;
        state
            .revoked_signers
            .extend(statement.revoked_signers.iter().cloned());
        state
            .revoked_qualifications
            .extend(statement.revoked_qualifications.iter().cloned());
        state.accepted_revocation_sequence =
            state.accepted_revocation_sequence.max(statement.sequence);
    }

    /// Derives the state of `deployment` at `now`.
    ///
    /// `clock_trusted` comes from the deployment's clock adapter and from
    /// nowhere else. `state` is what earlier verified inputs established.
    /// When several faults hold, the first of these is reported: the
    /// certificate or index is unusable; a revocation applies; the
    /// revocation list is unusable or rolled back; the clock is untrusted or
    /// behind a signed issue time; the revocation list is stale; no usable
    /// attestation exists; a window has ended; a digest differs; the target
    /// differs.
    #[must_use]
    pub fn evaluate(
        &self,
        deployment: &QualificationTuple,
        now: u64,
        clock_trusted: bool,
        state: &VerifierState,
    ) -> QualificationVerdict {
        use QualificationRefusal as Refusal;
        use RecipeQualificationState as State;
        let (Some(certificate), Some(index)) = (&self.certificate, self.current_index(state))
        else {
            return QualificationVerdict::refused(State::Unqualified, Refusal::Unavailable);
        };
        let signer = &certificate.body().statement;
        let family: Vec<&Listed> = self
            .listed
            .iter()
            .filter(|listed| listed.record.body().tuple.recipe_family == deployment.recipe_family)
            .collect();
        // A list the root signed revokes what it names whatever its age or
        // sequence; only its freshness needs the clock.
        let named = self.revocations.as_ref().map(|list| &list.body().statement);
        let signer_revoked = state.revoked_signers.contains(&signer.signer_id)
            || named.is_some_and(|named| named.revoked_signers.contains(&signer.signer_id));
        let revoked = |listed: &Listed| {
            let id = &listed.record.body().qualification_id;
            state.revoked_qualifications.contains(id)
                || named.is_some_and(|named| named.revoked_qualifications.contains(id))
        };
        let standing: Vec<&Listed> = family
            .iter()
            .copied()
            .filter(|listed| !revoked(listed))
            .collect();
        if !family.is_empty() && (signer_revoked || standing.is_empty()) {
            return QualificationVerdict::refused(State::Revoked, Refusal::Revoked);
        }
        // An attestation is usable once its window and its signer's have
        // started. Whether they have ended is judged after.
        let usable: Vec<(&Listed, &RecipeQualificationAttestation)> = standing
            .iter()
            .filter_map(|listed| Some((*listed, listed.attestation.as_ref()?)))
            .filter(|(_, attestation)| {
                now >= attestation.body().statement.not_before && now >= signer.not_before
            })
            .collect();
        let short_of_usable = if !usable.is_empty() {
            State::Stale
        } else if family.is_empty() {
            State::Unqualified
        } else {
            State::Candidate
        };
        let current_list = self
            .revocations
            .as_ref()
            .map(|list| &list.body().statement)
            .filter(|list| list.sequence >= state.accepted_revocation_sequence);
        let Some(list) = current_list else {
            return QualificationVerdict::refused(short_of_usable, Refusal::Unavailable);
        };
        let behind = now < signer.issued_at
            || now < list.issued_at
            || now < index.body().statement.issued_at
            || usable
                .iter()
                .any(|(_, attestation)| now < attestation.body().statement.issued_at);
        if !clock_trusted || behind {
            return QualificationVerdict::refused(short_of_usable, Refusal::ClockUntrusted);
        }
        if now > list.next_update {
            return QualificationVerdict::refused(short_of_usable, Refusal::RevocationStale);
        }
        if usable.is_empty() {
            return QualificationVerdict::refused(short_of_usable, Refusal::Missing);
        }
        // The attestation nearest to qualified decides: another target's
        // attestation never hides the one that fits.
        usable
            .iter()
            .map(|(listed, attestation)| {
                let tuple = &listed.record.body().tuple;
                let digests_equal = tuple.compiled_recipe_sha256
                    == deployment.compiled_recipe_sha256
                    && tuple.profile_lock_sha256 == deployment.profile_lock_sha256
                    && tuple.provider_contract_id == deployment.provider_contract_id
                    && tuple.gateway_semantic_closure_sha256
                        == deployment.gateway_semantic_closure_sha256;
                if now > attestation.body().statement.not_after || now > signer.not_after {
                    Refusal::Expired
                } else if !digests_equal {
                    Refusal::DigestMismatch
                } else if tuple.target != deployment.target {
                    Refusal::TargetMismatch
                } else {
                    return None;
                }
                .into()
            })
            .max_by_key(|refusal: &Option<Refusal>| {
                refusal.map_or(u8::MAX, |refusal| refusal as u8)
            })
            .flatten()
            .map_or(QualificationVerdict::QUALIFIED, |refusal| {
                QualificationVerdict::refused(State::Stale, refusal)
            })
    }
}
