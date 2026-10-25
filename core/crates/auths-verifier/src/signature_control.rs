//! Signature/control stage for the authoritative verifier. Registry selection,
//! evidence lookup, reservations, primitive calls and exact consumed-evidence
//! checks remain on this source path; the fold never receives an assumed result.

use super::*;
use crate::collections::try_fold_items;
use auths_model::{ControlBinding, EvidenceId};

struct ControlState {
    controls: Vec<VerifiedControl>,
    meter: WorkMeter,
}

pub(crate) fn verify_principal_control<R: RegistryAccess + ?Sized>(
    resolved: ResolvedProof,
    context: &TrustedContext,
    registries: &R,
) -> Result<ControlVerifiedProof, VerificationFailure> {
    if context.accepted_registries().manifest_id() != registries.manifest_id() {
        return Err(VerificationFailure::Denied(DenialReason::RegistryManifestMismatch));
    }
    if context.configuration() != registries.configuration_id() {
        return Err(VerificationFailure::Denied(DenialReason::VerifierConfigurationMismatch));
    }
    let bundle = resolved.decoded.bundle();
    let initial = ControlState { controls: Vec::new(), meter: WorkMeter::new(context.limits().max_work_units()) };
    let state = try_fold_items!(&resolved.grants, initial, state, _position, record =>
        verify_grant_record(state, record, bundle, context, registries))?;
    let state = try_fold_items!(&resolved.actions, state, state, _position, record =>
        verify_action_record(state, record, bundle, context, registries))?;
    let state = verify_status_controls(state, bundle, context, registries)?;
    let _ = try_fold_items!(&state.controls, (), _checked, _position, control =>
        check_consumed_binding(control, bundle))?;
    let consumed = declared_evidence(bundle, context);
    if has_unused_evidence(bundle.evidence(), &consumed) {
        return Err(VerificationFailure::Denied(DenialReason::UnusedCriticalEvidence));
    }
    Ok(ControlVerifiedProof { resolved, controls: state.controls, work_units: state.meter.used })
}

fn verify_grant_record<R: RegistryAccess + ?Sized>(
    mut state: ControlState, record: &GrantRecord, bundle: &ProofBundle, context: &TrustedContext, registries: &R,
) -> Result<ControlState, VerificationFailure> {
    let grant = &bundle.grants()[record.index];
    let preimage = grant_signing_preimage(grant.statement(), grant.signature().descriptor())
        .map_err(|error| codec_failure(error))?;
    let control = verify_signed(StatementRef::Grant(record.id), grant.statement().issuer(), grant.signature(),
        &preimage, ControlPurpose::CapabilityDelegation, grant.statement().validity().not_before(),
        bundle, context, registries, &mut state.meter)?;
    state.controls.push(control);
    Ok(state)
}
fn verify_action_record<R: RegistryAccess + ?Sized>(
    mut state: ControlState, record: &ActionRecord, bundle: &ProofBundle, context: &TrustedContext, registries: &R,
) -> Result<ControlState, VerificationFailure> {
    let action = &bundle.actions()[record.index];
    let preimage = action_signing_preimage(action.envelope(), action.signature().descriptor())
        .map_err(|error| codec_failure(error))?;
    let control = verify_signed(StatementRef::Action(record.id), action.envelope().actor(), action.signature(),
        &preimage, ControlPurpose::CapabilityInvocation, action.envelope().validity().not_before(),
        bundle, context, registries, &mut state.meter)?;
    state.controls.push(control);
    Ok(state)
}
fn verify_principal_status<R: RegistryAccess + ?Sized>(
    mut state: ControlState, status: &SignedPrincipalStatus, bundle: &ProofBundle, context: &TrustedContext, registries: &R,
) -> Result<ControlState, VerificationFailure> {
    let id = principal_status_id(status.statement()).map_err(|error| codec_failure(error))?;
    let preimage = principal_status_signing_preimage(status.statement(), status.signature().descriptor())
        .map_err(|error| codec_failure(error))?;
    let control = verify_signed(StatementRef::PrincipalStatus(id), status.statement().issuer(), status.signature(),
        &preimage, ControlPurpose::Assertion, status.statement().observed_at(),
        bundle, context, registries, &mut state.meter)?;
    state.controls.push(control);
    Ok(state)
}
fn verify_grant_status<R: RegistryAccess + ?Sized>(
    mut state: ControlState, status: &SignedGrantStatus, bundle: &ProofBundle, context: &TrustedContext, registries: &R,
) -> Result<ControlState, VerificationFailure> {
    let id = grant_status_id(status.statement()).map_err(|error| codec_failure(error))?;
    let preimage = grant_status_signing_preimage(status.statement(), status.signature().descriptor())
        .map_err(|error| codec_failure(error))?;
    let control = verify_signed(StatementRef::GrantStatus(id), status.statement().issuer(), status.signature(),
        &preimage, ControlPurpose::Assertion, status.statement().observed_at(),
        bundle, context, registries, &mut state.meter)?;
    state.controls.push(control);
    Ok(state)
}
fn verify_status_controls<R: RegistryAccess + ?Sized>(
    state: ControlState, bundle: &ProofBundle, context: &TrustedContext, registries: &R,
) -> Result<ControlState, VerificationFailure> {
    let state = try_fold_items!(context.principal_status_snapshot().statements(), state, state, _position, status =>
        verify_principal_status(state, status, bundle, context, registries))?;
    try_fold_items!(context.grant_status_snapshot().statements(), state, state, _position, status =>
        verify_grant_status(state, status, bundle, context, registries))
}

fn binding_for(bindings: &[ControlBinding], statement: StatementRef) -> Option<&ControlBinding> {
    let mut position = 0;
    while position < bindings.len() {
        if bindings[position].statement() == statement { return Some(&bindings[position]); }
        position += 1;
    }
    None
}
fn insert_identifiers(mut output: OrderedSet<EvidenceId>, values: &[EvidenceId]) -> OrderedSet<EvidenceId> {
    let mut position = 0;
    while position < values.len() { output.insert(values[position]); position += 1; }
    output
}
fn check_consumed_binding(control: &VerifiedControl, bundle: &ProofBundle) -> Result<(), VerificationFailure> {
    if let Ok(evidence) = &control.result {
        let bound_ids = match binding_for(bundle.bindings(), control.statement) {
            Some(binding) => binding.evidence(),
            None => &[],
        };
        let bound = insert_identifiers(OrderedSet::new(), bound_ids);
        let consumed = insert_identifiers(OrderedSet::new(), evidence.consumed_evidence());
        if bound != consumed {
            return Err(VerificationFailure::Denied(DenialReason::UnusedCriticalEvidence));
        }
    }
    Ok(())
}
fn declared_evidence(bundle: &ProofBundle, context: &TrustedContext) -> OrderedSet<EvidenceId> {
    let mut output = OrderedSet::new();
    let mut position = 0;
    while position < bundle.bindings().len() {
        output = insert_identifiers(output, bundle.bindings()[position].evidence());
        position += 1;
    }
    output = insert_identifiers(output, context.principal_status_snapshot().checkpoints());
    insert_identifiers(output, context.grant_status_snapshot().checkpoints())
}
fn has_unused_evidence(objects: &[EvidenceObject], consumed: &OrderedSet<EvidenceId>) -> bool {
    let mut position = 0;
    let mut unused = false;
    while position < objects.len() && !unused { unused = !consumed.contains(&objects[position].id()); position += 1; }
    unused
}

#[allow(clippy::too_many_arguments)]
fn verify_signed<R: RegistryAccess + ?Sized>(
    statement: StatementRef, principal: &PrincipalId, signature: &SignatureEnvelope,
    signing_preimage: &[u8], purpose: ControlPurpose, asserted_signing_time: Timestamp,
    bundle: &ProofBundle, context: &TrustedContext, registries: &R, meter: &mut WorkMeter,
) -> Result<VerifiedControl, VerificationFailure> {
    let result = evaluate_signature(principal, signature, signing_preimage, purpose, asserted_signing_time,
        || bound_evidence(bundle, statement), context, registries, meter);
    if result == Err(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded)) {
        return Err(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded));
    }
    Ok(VerifiedControl { statement, principal: principal.clone(), result })
}

fn evidence_accepted(evidence: &[&EvidenceObject], accepted: &auths_model::AcceptedRegistries) -> bool {
    let mut position = 0;
    let mut valid = true;
    while position < evidence.len() && valid {
        valid = accepted.accepts_evidence_type(evidence[position].evidence_type());
        position += 1;
    }
    valid
}

// The selected registry, actual descriptor, exact preimage and actual evidence
// reach the primitive calls. Optional signature-message replacement is supplied
// only by the selected principal method and keeps its existing port contract.
#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate_signature<'e, R: RegistryAccess + ?Sized>(
    principal: &PrincipalId, signature: &SignatureEnvelope, signing_preimage: &[u8],
    purpose: ControlPurpose, asserted_signing_time: Timestamp,
    evidence: impl FnOnce() -> Result<Vec<&'e EvidenceObject>, VerificationFailure>,
    context: &TrustedContext, registries: &R, meter: &mut WorkMeter,
) -> Result<ControlEvidence, VerificationFailure> {
    let descriptor = signature.descriptor();
    let method = registries.principal_method(context.accepted_registries(), descriptor.principal_method())
        .ok_or(VerificationFailure::Indeterminate(Requirement::UnsupportedPrincipalMethod))?;
    let suite = registries.signature_suite(context.accepted_registries(), descriptor.suite())
        .ok_or(VerificationFailure::Indeterminate(Requirement::UnsupportedSignatureSuite))?;
    let evidence = evidence()?;
    if !evidence_accepted(&evidence, context.accepted_registries()) {
        return Err(VerificationFailure::Indeterminate(Requirement::UnsupportedEvidenceType));
    }
    let method_reservation = method.maximum_work_units();
    meter.reserve(method_reservation)?;
    meter.reserve(suite.work_units())?;
    let control = method.evaluate_control(PrincipalControlInput {
        principal, verification_method: descriptor.verification_method(), signature_suite: descriptor.suite(),
        purpose, signing_preimage, signature: signature.signature().as_slice(), asserted_signing_time,
        evidence: &evidence, evaluation_time: context.evaluation_time(),
    }, DiagnosticMode::Discard).into_result().map_err(|error| control_failure(error))?;
    if control.work_units() > method_reservation {
        return Err(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded));
    }
    suite.verify(SignatureInput {
        verification_key: control.verification_key(),
        signing_preimage: control.signature_message().unwrap_or(signing_preimage),
        signature: signature.signature().as_slice(),
    }).map_err(|error| signature_failure(error))?;
    Ok(control)
}

fn evidence_for(objects: &[EvidenceObject], id: EvidenceId) -> Option<&EvidenceObject> {
    let mut position = 0;
    while position < objects.len() {
        if objects[position].id() == id { return Some(&objects[position]); }
        position += 1;
    }
    None
}
fn append_bound_evidence<'a>(mut output: Vec<&'a EvidenceObject>, id: EvidenceId, objects: &'a [EvidenceObject])
-> Result<Vec<&'a EvidenceObject>, VerificationFailure> {
    output.push(evidence_for(objects, id).ok_or(VerificationFailure::Denied(DenialReason::MissingReference))?);
    Ok(output)
}
fn bound_evidence(bundle: &ProofBundle, statement: StatementRef) -> Result<Vec<&EvidenceObject>, VerificationFailure> {
    let binding = binding_for(bundle.bindings(), statement)
        .ok_or(VerificationFailure::Indeterminate(Requirement::MissingPrincipalEvidence))?;
    try_fold_items!(binding.evidence(), Vec::with_capacity(binding.evidence().len()), output, _position, id =>
        append_bound_evidence(output, *id, bundle.evidence()))
}
