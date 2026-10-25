//! Canonical action and attachment binding.
use super::*;

fn same_shared_action(
    left: &auths_model::ActionEnvelope,
    right: &auths_model::ActionEnvelope,
) -> bool {
    left.profile() == right.profile()
        && left.body_media_type() == right.body_media_type()
        && left.canonical_body_digest() == right.canonical_body_digest()
        && left.permission() == right.permission()
        && left.requested_budget() == right.requested_budget()
        && left.audience() == right.audience()
        && left.challenge() == right.challenge()
        && left.validity() == right.validity()
        && left.authorization_plan() == right.authorization_plan()
        && left.channel_binding() == right.channel_binding()
        && left.attachments() == right.attachments()
        && left.extensions() == right.extensions()
}

use crate::collections::try_fold_items;
use auths_model::{ActionEnvelope, AttachmentDescriptor, AttachmentDigest, DetachedAttachment};

struct Binding<'a, R: RegistryAccess + ?Sized> {
    canonical: &'a CanonicalAction,
    context: &'a TrustedContext,
    registries: &'a R,
    first: &'a ActionEnvelope,
    expected_digest: Digest,
}

pub(super) fn validate_action_binding<R: RegistryAccess + ?Sized>(
    controlled: &ControlVerifiedProof, canonical: &CanonicalAction, context: &TrustedContext,
    registries: &R, meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    let bundle = controlled.resolved.decoded.bundle();
    if let Some(body) = bundle.canonical_body()
        && body != canonical.body()
    { return Err(VerificationFailure::Denied(DenialReason::ActionBodyMismatch)); }
    let expected_digest = body_digest(canonical.body());
    let first = bundle.actions().first()
        .ok_or(VerificationFailure::Denied(DenialReason::AuthorizationPlanInvalid))?.envelope();
    let binding = Binding { canonical, context, registries, first, expected_digest };
    let _ = try_fold_items!(bundle.actions(), (), _checked, _position, signed =>
        check_envelope(signed, &binding, meter))?;
    validate_attachments(bundle, canonical, context)?;
    let policy = registries.profile_policy(context.accepted_registries(), context.profile_policy())
        .ok_or(VerificationFailure::Indeterminate(Requirement::UnsupportedProfilePolicy))?;
    meter.reserve(policy.maximum_work_units(canonical))?;
    match policy.evaluate(canonical).map_err(|error| registry_operation_failure(error))? {
        ProfileDecision::Accept => Ok(()),
        ProfileDecision::Deny => Err(VerificationFailure::Denied(DenialReason::LocalPolicyDenied)),
    }
}

fn check_envelope<R: RegistryAccess + ?Sized>(signed: &SignedAction, binding: &Binding<'_, R>, meter: &mut WorkMeter)
-> Result<(), VerificationFailure> {
    let action = signed.envelope();
    let canonical = binding.canonical;
    let context = binding.context;
    if action.profile() != canonical.profile()
        || action.body_media_type() != canonical.media_type()
        || action.canonical_body_digest() != binding.expected_digest
        || action.permission() != canonical.permission()
        || action.requested_budget() != canonical.requested_budget()
    { return Err(VerificationFailure::Denied(DenialReason::ActionBodyMismatch)); }
    if !context.accepted_registries().accepts_profile(action.profile()) {
        return Err(VerificationFailure::Indeterminate(Requirement::UnsupportedProfile));
    }
    if action.audience() != context.expected_audience() {
        return Err(VerificationFailure::Denied(DenialReason::AudienceMismatch));
    }
    // Retain the actual constant-time Challenge comparison.
    if action.challenge() != context.expected_challenge() {
        return Err(VerificationFailure::Denied(DenialReason::ChallengeMismatch));
    }
    if !action.validity().contains(context.evaluation_time()) {
        return Err(VerificationFailure::Denied(DenialReason::ActionOutsideValidity));
    }
    if action.channel_binding() != context.channel_policy() {
        return Err(VerificationFailure::Denied(DenialReason::LocalPolicyDenied));
    }
    if !same_shared_action(binding.first, action) {
        return Err(VerificationFailure::Denied(DenialReason::PlanActionMismatch));
    }
    evaluate_extensions(action.extensions(), context, binding.registries, meter)?;
    observation::validate_observation_attachments(signed)
}

fn descriptors_duplicate(values: &[AttachmentDescriptor]) -> bool {
    let mut position = 1;
    let mut duplicate = false;
    while position < values.len() && !duplicate {
        duplicate = values[position - 1].digest() == values[position].digest();
        position += 1;
    }
    duplicate
}
fn payloads_duplicate(values: &[DetachedAttachment]) -> bool {
    let mut position = 1;
    let mut duplicate = false;
    while position < values.len() && !duplicate {
        duplicate = values[position - 1].digest() == values[position].digest();
        position += 1;
    }
    duplicate
}
fn attachment_total(values: &[DetachedAttachment]) -> Option<usize> {
    let mut total = Some(0usize);
    let mut position = 0;
    while position < values.len() && total.is_some() {
        total = match total {
            Some(used) => used.checked_add(values[position].bytes().len()),
            None => None,
        };
        position += 1;
    }
    total
}
fn payload_for(values: &[DetachedAttachment], digest: AttachmentDigest) -> Option<&DetachedAttachment> {
    let mut position = 0;
    while position < values.len() {
        if values[position].digest() == digest { return Some(&values[position]); }
        position += 1;
    }
    None
}
fn descriptor_present(values: &[AttachmentDescriptor], digest: AttachmentDigest) -> bool {
    let mut position = 0;
    let mut found = false;
    while position < values.len() && !found {
        found = values[position].digest() == digest;
        position += 1;
    }
    found
}
fn has_unused_payload(values: &[DetachedAttachment], descriptors: &[AttachmentDescriptor]) -> bool {
    let mut position = 0;
    let mut unused = false;
    while position < values.len() && !unused {
        unused = !descriptor_present(descriptors, values[position].digest());
        position += 1;
    }
    unused
}
fn check_descriptor(descriptor: &AttachmentDescriptor, payloads: &[DetachedAttachment]) -> Result<(), VerificationFailure> {
    let detached = payload_for(payloads, descriptor.digest());
    let Some(detached) = detached else {
        return if matches!(descriptor.presence(), auths_model::Presence::Required) {
            Err(VerificationFailure::Denied(DenialReason::AttachmentMissing))
        } else { Ok(()) };
    };
    let length = u64::try_from(detached.bytes().len())
        .map_err(|_| VerificationFailure::Denied(DenialReason::AttachmentLengthMismatch))?;
    if length != descriptor.byte_length() {
        return Err(VerificationFailure::Denied(DenialReason::AttachmentLengthMismatch));
    }
    if attachment_digest(detached.bytes()) != descriptor.digest() {
        return Err(VerificationFailure::Denied(DenialReason::AttachmentDigestMismatch));
    }
    if matches!(descriptor.confidentiality(), auths_model::Confidentiality::Encrypted)
        && matches!(descriptor.opacity(), auths_model::Opacity::MustBeInspectable)
    { return Err(VerificationFailure::Denied(DenialReason::OpaqueAttachmentNotAllowed)); }
    Ok(())
}
fn validate_attachments(bundle: &ProofBundle, canonical: &CanonicalAction, context: &TrustedContext)
-> Result<(), VerificationFailure> {
    let descriptors = match bundle.actions().first() {
        Some(action) => action.envelope().attachments(),
        None => &[],
    };
    if descriptors != bundle.attachments() {
        return Err(VerificationFailure::Denied(DenialReason::UnusedCriticalAttachment));
    }
    let payloads = canonical.detached_attachments();
    if descriptors_duplicate(descriptors) || payloads_duplicate(payloads) {
        return Err(VerificationFailure::Denied(DenialReason::DuplicateAttachment));
    }
    let total = attachment_total(payloads)
        .ok_or(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded))?;
    if total > context.limits().get(auths_model::LimitKind::AttachmentBytes) {
        return Err(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded));
    }
    let _ = try_fold_items!(descriptors, (), _checked, _position, descriptor =>
        check_descriptor(descriptor, payloads))?;
    if has_unused_payload(payloads, descriptors) {
        return Err(VerificationFailure::Denied(DenialReason::UnusedCriticalAttachment));
    }
    Ok(())
}
