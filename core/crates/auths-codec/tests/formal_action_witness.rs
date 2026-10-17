//! Native parity for the complete-action witnesses in `Auths.Codec.Examples`.
//! These exercise codec acceptance, not authorization of an application profile.

use auths_codec::{CodecError, decode_canonical_action, encode_canonical_action};
use auths_model::{
    CanonicalAction, CapabilityId, LimitKind, MediaType, Permission, ProfileId, ProfileRef,
    ResourceId, VerifierLimits,
};

const INPUT: [u8; 26] = [
    166, 0, 162, 0, 97, 116, 1, 1, 1, 97, 109, 2, 65, 1, 3, 162, 0, 97, 114, 1, 97, 114, 4, 246, 5,
    128,
];

fn limits() -> Result<VerifierLimits, auths_model::ModelError> {
    let mut limits = VerifierLimits::default_deployment().with_work_units(1)?;
    for kind in [
        LimitKind::BundleBytes,
        LimitKind::ContextBytes,
        LimitKind::Grants,
        LimitKind::Actions,
        LimitKind::PlanLeaves,
        LimitKind::PlanDepth,
        LimitKind::PlanBranching,
        LimitKind::EvidenceObjects,
        LimitKind::EvidenceBytes,
        LimitKind::ControlBindings,
        LimitKind::PrincipalStatusStatements,
        LimitKind::GrantStatusStatements,
        LimitKind::Attachments,
        LimitKind::AttachmentBytes,
        LimitKind::Signatures,
        LimitKind::SignatureBytes,
        LimitKind::Permissions,
        LimitKind::Audiences,
        LimitKind::CriticalExtensions,
        LimitKind::CriticalExtensionBytes,
        LimitKind::AllowedBodyDigests,
        LimitKind::BindingEvidence,
        LimitKind::CanonicalBodyBytes,
        LimitKind::RegistryEntries,
        LimitKind::TrustAnchors,
        LimitKind::Approvals,
        LimitKind::ApproverAnchors,
        LimitKind::ApprovalRequirements,
    ] {
        limits = limits.with_limit(kind, 1)?;
    }
    limits.with_limit(LimitKind::ActionBytes, 128)
}

#[test]
fn complete_action_matches_proved_acceptance_and_exact_byte_boundary()
-> Result<(), auths_model::ModelError> {
    let limits = limits()?;
    let expected = CanonicalAction::new(
        ProfileRef::new(ProfileId::parse("t")?, 1)?,
        MediaType::parse("m")?,
        vec![1],
        Permission::new(CapabilityId::parse("r")?, ResourceId::parse("r")?),
        None,
    )?;
    assert_eq!(
        decode_canonical_action(&INPUT, &limits),
        Ok(expected.clone())
    );
    assert_eq!(encode_canonical_action(&expected), Ok(INPUT.to_vec()));
    let exact = limits.clone().with_limit(LimitKind::ActionBytes, 26)?;
    assert_eq!(decode_canonical_action(&INPUT, &exact), Ok(expected));
    let below = limits.with_limit(LimitKind::ActionBytes, 25)?;
    assert_eq!(
        decode_canonical_action(&INPUT, &below),
        Err(CodecError::LimitExceeded)
    );
    Ok(())
}

#[test]
fn complete_action_matches_proved_adversarial_refusals() -> Result<(), auths_model::ModelError> {
    let limits = limits()?;
    let mut duplicate_key = INPUT.to_vec();
    duplicate_key[6] = 0;
    let mut nonminimal_integer = INPUT.to_vec();
    nonminimal_integer.insert(7, 24);
    let mut invalid_utf8 = INPUT.to_vec();
    invalid_utf8[5] = 255;
    let truncated = INPUT[..INPUT.len() - 1].to_vec();
    let mut trailing = INPUT.to_vec();
    trailing.push(0);
    for (input, expected) in [
        (duplicate_key, CodecError::NonCanonical),
        (nonminimal_integer, CodecError::NonCanonical),
        (invalid_utf8, CodecError::Malformed),
        (truncated, CodecError::Malformed),
        (trailing, CodecError::Malformed),
    ] {
        assert_eq!(decode_canonical_action(&input, &limits), Err(expected));
    }
    Ok(())
}
