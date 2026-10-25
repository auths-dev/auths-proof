//! Effect-free extension and assurance dispatch in the authoritative verifier.
//! Every selected handler receives its actual typed object after its declared
//! work reservation; missing or unacceptable handlers retain typed refusals.

use super::*;
use crate::collections::try_fold_items;
use auths_model::{AssuranceClaim, AssuranceClaimId, CriticalExtension, CriticalExtensions};

pub(super) fn evaluate_extensions<R: RegistryAccess + ?Sized>(
    extensions: &CriticalExtensions, context: &TrustedContext, registries: &R, meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    try_fold_items!(extensions.as_slice(), (), _checked, _position, extension =>
        evaluate_extension(extension, context, registries, meter))
}
fn evaluate_extension<R: RegistryAccess + ?Sized>(
    extension: &CriticalExtension, context: &TrustedContext, registries: &R, meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    if !context.accepted_registries().accepts_critical_extension(extension.id()) {
        return Err(VerificationFailure::Denied(DenialReason::CriticalExtensionUnknown));
    }
    let handler = registries.extension_handler(context.accepted_registries(), extension.id())
        .ok_or(VerificationFailure::Indeterminate(Requirement::UnsupportedCriticalExtension))?;
    meter.reserve(handler.maximum_work_units(extension))?;
    handler.evaluate(extension).map_err(|error| registry_operation_failure(error))
}

fn validate_claim<R: RegistryAccess + ?Sized>(
    claim: &AssuranceClaim, context: &TrustedContext, registries: &R, meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    let rule = registries.assurance_claim(context.accepted_registries(), claim.kind())
        .ok_or(VerificationFailure::Indeterminate(Requirement::UnsupportedAssuranceClaim))?;
    meter.reserve(rule.maximum_work_units(claim))?;
    rule.validate(claim).map_err(|error| registry_operation_failure(error))
}
fn validate_report<R: RegistryAccess + ?Sized>(
    report: &ParticipantAssurance, context: &TrustedContext, registries: &R, meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    try_fold_items!(report.claims(), (), _checked, _position, claim => validate_claim(claim, context, registries, meter))
}
fn validate_assurance_claims<R: RegistryAccess + ?Sized>(
    reports: &[ParticipantAssurance], context: &TrustedContext, registries: &R, meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    try_fold_items!(reports, (), _checked, _position, report => validate_report(report, context, registries, meter))
}
fn reserve_implication<I: auths_ports::AssuranceImplication + ?Sized>(implication: &I, meter: &mut WorkMeter)
-> Result<(), VerificationFailure> { meter.reserve(implication.maximum_work_units()) }
fn implication_holds<I: auths_ports::AssuranceImplication + ?Sized>(
    implications: &[&I], claim: &AssuranceClaim, target: &AssuranceClaimId,
) -> bool {
    let mut position = 0;
    let mut accepted = false;
    while position < implications.len() && !accepted {
        let implication = implications[position];
        accepted = implication.source() == claim.kind() && implication.target() == target
            && implication.implies(claim).unwrap_or(false);
        position += 1;
    }
    accepted
}

pub(super) fn evaluate_branch_assurance<R: RegistryAccess + ?Sized>(
    reports: &[ParticipantAssurance], context: &TrustedContext, registries: &R, meter: &mut WorkMeter,
) -> Result<Vec<AssuranceSatisfaction>, VerificationFailure> {
    validate_assurance_claims(reports, context, registries, meter)?;
    let implications = registries.assurance_implications(context.accepted_registries());
    let _ = try_fold_items!(&implications, (), _checked, _position, implication => reserve_implication(*implication, meter))?;
    evaluate_with_implications(context.assurance_policy(), reports, context.evaluation_time(),
        |claim, target| implication_holds(&implications, claim, target))
        .map_err(|requirement| VerificationFailure::Indeterminate(requirement))
}
