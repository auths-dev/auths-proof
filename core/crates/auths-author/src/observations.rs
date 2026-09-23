//! Signed observations carried as detached attachments of a prepared action.

use crate::PreparedAction;
use alloc::vec::Vec;
use auths_codec::{attachment_digest, body_digest};
use auths_model::CanonicalAction;
use auths_model::{
    ActionEnvelope, AttachmentDescriptor, Confidentiality, DetachedAttachment, DispositionId,
    MAX_OBSERVATION_ATTACHMENTS, MAX_OBSERVATION_BYTES, MediaType, ModelError,
    OBSERVATION_MEDIA_TYPE, Opacity, Presence,
};
use core::fmt;

/// Disposition of an attachment the verifier consumes as authorization input.
const AUTHORIZATION_INPUT: &str = "authorization-input";

/// Failure to attach signed observations to a prepared action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationAttachmentError {
    /// The prepared action already carries attachments; attach once.
    AlreadyAttached,
    /// A supplied media type is not the signed-observation media type.
    MediaType,
    /// An observation is empty or exceeds the per-observation byte bound.
    Size,
    /// More observations than one action may carry.
    Count,
    /// The same observation bytes were supplied more than once.
    Duplicate,
    /// A model invariant rejected the attachment set.
    Model(ModelError),
}

impl From<ModelError> for ObservationAttachmentError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl fmt::Display for ObservationAttachmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyAttached => "prepared action already carries attachments",
            Self::MediaType => "attachment is not a signed observation",
            Self::Size => "signed observation size is outside bounds",
            Self::Count => "too many signed observations for one action",
            Self::Duplicate => "signed observation supplied more than once",
            Self::Model(_) => "invalid observation attachment",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ObservationAttachmentError {}

/// An unsigned action envelope does not bind the canonical action it was
/// paired with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnboundActionEnvelope;

impl fmt::Display for UnboundActionEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("action envelope does not bind the canonical action")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnboundActionEnvelope {}

impl PreparedAction {
    /// Re-pairs a canonical action with the unsigned envelope prepared for
    /// it, for callers that carried the two separately.
    ///
    /// # Errors
    ///
    /// Returns [`UnboundActionEnvelope`] unless the envelope binds exactly
    /// this action's profile, body media type, body digest, permission, and
    /// budget request, and describes exactly its detached attachments.
    pub fn bind(
        canonical: CanonicalAction,
        envelope: ActionEnvelope,
    ) -> Result<Self, UnboundActionEnvelope> {
        let attachments_described = envelope.attachments().len()
            == canonical.detached_attachments().len()
            && canonical.detached_attachments().iter().all(|attachment| {
                envelope
                    .attachments()
                    .iter()
                    .any(|descriptor| descriptor.digest() == attachment.digest())
            });
        if envelope.profile() != canonical.profile()
            || envelope.body_media_type() != canonical.media_type()
            || envelope.canonical_body_digest() != body_digest(canonical.body())
            || envelope.permission() != canonical.permission()
            || envelope.requested_budget() != canonical.requested_budget()
            || !attachments_described
        {
            return Err(UnboundActionEnvelope);
        }
        Ok(Self {
            canonical,
            envelope,
        })
    }
}

/// Carries each signed observation as a required, plain, inspectable
/// detached attachment of `prepared`, and binds its descriptor into the
/// unsigned action statement so the action signature covers it.
///
/// Each entry is the declared media type and the exact observation bytes.
/// Only media type, size, count, and distinctness are checked: the
/// observation's signature, observer, subject, freshness, and facts are the
/// verifier's to judge, and an attachment it cannot use never widens
/// authority. Descriptors are ordered by content digest, the order the proof
/// bundle and verifier require. Zero observations return `prepared`
/// unchanged.
///
/// # Errors
///
/// Returns [`ObservationAttachmentError`] when `prepared` already carries
/// attachments, a media type is not the signed-observation media type, an
/// observation is empty or larger than [`MAX_OBSERVATION_BYTES`], more than
/// [`MAX_OBSERVATION_ATTACHMENTS`] are supplied, or bytes repeat.
pub fn attach_observations(
    prepared: PreparedAction,
    observations: &[(&str, &[u8])],
) -> Result<PreparedAction, ObservationAttachmentError> {
    let (canonical, envelope) = prepared.into_parts();
    if !envelope.attachments().is_empty() || !canonical.detached_attachments().is_empty() {
        return Err(ObservationAttachmentError::AlreadyAttached);
    }
    if observations.is_empty() {
        return Ok(PreparedAction {
            canonical,
            envelope,
        });
    }
    if observations.len() > MAX_OBSERVATION_ATTACHMENTS {
        return Err(ObservationAttachmentError::Count);
    }
    let media_type = MediaType::parse(OBSERVATION_MEDIA_TYPE)?;
    let disposition = DispositionId::parse(AUTHORIZATION_INPUT)?;
    let mut descriptors: Vec<AttachmentDescriptor> = Vec::with_capacity(observations.len());
    let mut detached = Vec::with_capacity(observations.len());
    for (declared, bytes) in observations {
        if *declared != OBSERVATION_MEDIA_TYPE {
            return Err(ObservationAttachmentError::MediaType);
        }
        if bytes.is_empty() || bytes.len() > MAX_OBSERVATION_BYTES {
            return Err(ObservationAttachmentError::Size);
        }
        let digest = attachment_digest(bytes);
        if descriptors
            .iter()
            .any(|descriptor| descriptor.digest() == digest)
        {
            return Err(ObservationAttachmentError::Duplicate);
        }
        let length = u64::try_from(bytes.len()).map_err(|_| ObservationAttachmentError::Size)?;
        descriptors.push(AttachmentDescriptor::new(
            digest,
            media_type.clone(),
            length,
            disposition.clone(),
            Confidentiality::Plain,
            Presence::Required,
            Opacity::MustBeInspectable,
        ));
        detached.push(DetachedAttachment::new(digest, bytes.to_vec())?);
    }
    descriptors.sort_by_key(AttachmentDescriptor::digest);
    let canonical = canonical.with_detached_attachments(detached)?;
    let envelope = ActionEnvelope::new(
        envelope.profile().clone(),
        envelope.body_media_type().clone(),
        envelope.canonical_body_digest(),
        envelope.permission().clone(),
        envelope.requested_budget().cloned(),
        envelope.audience().clone(),
        envelope.challenge(),
        envelope.validity(),
        envelope.actor().clone(),
        envelope.terminal_grant(),
        envelope.authorization_plan(),
        envelope.channel_binding().clone(),
        envelope.proof_ref(),
        descriptors,
        envelope.extensions().clone(),
    );
    Ok(PreparedAction {
        canonical,
        envelope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WorkflowAssemblyError, WorkflowProofBuilder, prepare_profile_action};
    use auths_model::{
        ActionConstraint, AssurancePolicyId, Audience, AudienceSet, CanonicalAction, CapabilityId,
        CriticalExtensions, GrantStatement, Permission, PermissionSet, PrincipalId,
        PrincipalMethodId, ProfileId, ProfileRef, ResourceId, SignatureBytes, SignatureDescriptor,
        SignatureEnvelope, SignatureSuiteId, SignedAction, SignedGrant, StatusPolicy, Timestamp,
        ValidityWindow, VerificationMethod,
    };

    type Offered<'a> = (&'a str, &'a [u8]);

    fn descriptor() -> SignatureDescriptor {
        SignatureDescriptor::new(
            PrincipalMethodId::parse("raw-key-v1").unwrap(),
            VerificationMethod::parse("did:key:root").unwrap(),
            SignatureSuiteId::parse("ed25519-v1").unwrap(),
        )
    }

    fn grant() -> SignedGrant {
        SignedGrant::new(
            GrantStatement::new(
                PrincipalId::parse("did:key:root").unwrap(),
                PrincipalId::parse("did:key:agent").unwrap(),
                ProfileRef::new(ProfileId::parse("auths.records").unwrap(), 1).unwrap(),
                PermissionSet::new(vec![permission()]).unwrap(),
                ValidityWindow::new(Timestamp::new(10), Timestamp::new(200_000)).unwrap(),
                AudienceSet::new(vec![Audience::parse("records://service").unwrap()]).unwrap(),
                ActionConstraint::AnyBody,
                None,
                0,
                None,
                StatusPolicy::ExpiryOnly,
                AssurancePolicyId::parse("records-v1").unwrap(),
                CriticalExtensions::empty(),
            ),
            SignatureEnvelope::new(descriptor(), SignatureBytes::new(vec![1; 64]).unwrap()),
        )
    }

    fn permission() -> Permission {
        Permission::new(
            CapabilityId::parse("records/update").unwrap(),
            ResourceId::parse("records://one").unwrap(),
        )
    }

    fn prepared() -> PreparedAction {
        let grant = grant();
        let canonical = CanonicalAction::new(
            grant.statement().profile().clone(),
            MediaType::parse("application/json").unwrap(),
            br#"{"value":1}"#.to_vec(),
            permission(),
            None,
        )
        .unwrap();
        prepare_profile_action(
            canonical,
            Audience::parse("records://service").unwrap(),
            grant.statement().subject().clone(),
            &grant,
            [7; 32],
            42,
        )
        .unwrap()
    }

    #[test]
    fn observations_are_bound_by_the_statement_in_digest_order() {
        let first = [0xa1_u8; 12];
        let second = [0x07_u8; 40];
        let before = prepared();
        let attached = attach_observations(
            before.clone(),
            &[
                (OBSERVATION_MEDIA_TYPE, &first[..]),
                (OBSERVATION_MEDIA_TYPE, &second[..]),
            ],
        )
        .unwrap();
        let descriptors = attached.envelope().attachments();
        assert_eq!(descriptors.len(), 2);
        assert!(descriptors[0].digest() < descriptors[1].digest());
        for descriptor in descriptors {
            assert_eq!(descriptor.media_type().as_str(), OBSERVATION_MEDIA_TYPE);
            assert_eq!(descriptor.presence(), Presence::Required);
            assert_eq!(descriptor.confidentiality(), Confidentiality::Plain);
            assert_eq!(descriptor.opacity(), Opacity::MustBeInspectable);
            let detached = attached
                .canonical()
                .detached_attachments()
                .iter()
                .find(|item| item.digest() == descriptor.digest())
                .expect("detached bytes for every descriptor");
            assert_eq!(attachment_digest(detached.bytes()), descriptor.digest());
            assert_eq!(descriptor.byte_length(), detached.bytes().len() as u64);
        }
        let unsigned = |prepared: &PreparedAction| {
            crate::prepare_action(prepared.envelope().clone(), descriptor())
                .unwrap()
                .signing_preimage()
                .to_vec()
        };
        assert_ne!(unsigned(&before), unsigned(&attached));
        assert_eq!(attached.canonical().body(), before.canonical().body());
        assert_eq!(
            attached.envelope().canonical_body_digest(),
            before.envelope().canonical_body_digest()
        );
    }

    #[test]
    fn zero_observations_leave_the_action_unchanged() {
        let before = prepared();
        assert_eq!(attach_observations(before.clone(), &[]).unwrap(), before);
    }

    #[test]
    fn media_type_size_count_and_repetition_are_refused() {
        let good = [1_u8; 8];
        let oversized = vec![2_u8; MAX_OBSERVATION_BYTES + 1];
        let exact = vec![3_u8; MAX_OBSERVATION_BYTES];
        let cases: [(&[Offered<'_>], ObservationAttachmentError); 4] = [
            (
                &[("application/cbor", &good[..])],
                ObservationAttachmentError::MediaType,
            ),
            (
                &[(OBSERVATION_MEDIA_TYPE, &[][..])],
                ObservationAttachmentError::Size,
            ),
            (
                &[(OBSERVATION_MEDIA_TYPE, &oversized[..])],
                ObservationAttachmentError::Size,
            ),
            (
                &[
                    (OBSERVATION_MEDIA_TYPE, &good[..]),
                    (OBSERVATION_MEDIA_TYPE, &good[..]),
                ],
                ObservationAttachmentError::Duplicate,
            ),
        ];
        for (observations, expected) in &cases {
            assert_eq!(
                attach_observations(prepared(), observations),
                Err(*expected)
            );
        }
        attach_observations(prepared(), &[(OBSERVATION_MEDIA_TYPE, &exact[..])])
            .expect("an observation at the byte bound attaches");

        let distinct: Vec<[u8; 2]> = (0..=MAX_OBSERVATION_ATTACHMENTS)
            .map(|index| [0xee, u8::try_from(index).unwrap()])
            .collect();
        let over: Vec<(&str, &[u8])> = distinct
            .iter()
            .map(|bytes| (OBSERVATION_MEDIA_TYPE, &bytes[..]))
            .collect();
        assert_eq!(
            attach_observations(prepared(), &over),
            Err(ObservationAttachmentError::Count)
        );
        attach_observations(prepared(), &over[..MAX_OBSERVATION_ATTACHMENTS])
            .expect("the attachment count bound is inclusive");
    }

    #[test]
    fn attaching_twice_is_refused() {
        let bytes = [9_u8; 16];
        let once =
            attach_observations(prepared(), &[(OBSERVATION_MEDIA_TYPE, &bytes[..])]).unwrap();
        assert_eq!(
            attach_observations(once, &[]),
            Err(ObservationAttachmentError::AlreadyAttached)
        );
    }

    #[test]
    fn proof_bundle_carries_the_signed_descriptors() -> Result<(), WorkflowAssemblyError> {
        let bytes = [5_u8; 24];
        let attached = attach_observations(prepared(), &[(OBSERVATION_MEDIA_TYPE, &bytes[..])])
            .expect("attached");
        let action = SignedAction::new(
            attached.envelope().clone(),
            SignatureEnvelope::new(descriptor(), SignatureBytes::new(vec![2; 64]).unwrap()),
        );
        let mut builder = WorkflowProofBuilder::new();
        builder.push_grant(grant())?;
        let context = auths_codec::decode_verifier_context(include_bytes!(
            "../../../fixtures/v1/denied/untrusted-root.context.cbor"
        ))
        .expect("canonical fixture context");
        let artifacts = builder.finish(&action, attached.canonical(), &context)?;
        assert_eq!(
            artifacts.proof().attachments(),
            attached.envelope().attachments()
        );
        Ok(())
    }

    #[test]
    fn rebinding_accepts_only_the_envelope_prepared_for_the_action() {
        let bytes = [4_u8; 20];
        let attached = attach_observations(prepared(), &[(OBSERVATION_MEDIA_TYPE, &bytes[..])])
            .expect("attached");
        let (canonical, envelope) = attached.clone().into_parts();
        assert_eq!(
            PreparedAction::bind(canonical.clone(), envelope.clone()),
            Ok(attached)
        );
        let (bare, bare_envelope) = prepared().into_parts();
        assert_eq!(
            PreparedAction::bind(bare.clone(), envelope),
            Err(UnboundActionEnvelope),
            "descriptors without detached bytes"
        );
        assert_eq!(
            PreparedAction::bind(canonical, bare_envelope.clone()),
            Err(UnboundActionEnvelope),
            "detached bytes without descriptors"
        );
        let other = CanonicalAction::new(
            bare.profile().clone(),
            bare.media_type().clone(),
            br#"{"value":2}"#.to_vec(),
            bare.permission().clone(),
            None,
        )
        .unwrap();
        assert_eq!(
            PreparedAction::bind(other, bare_envelope),
            Err(UnboundActionEnvelope),
            "another body"
        );
    }
}
