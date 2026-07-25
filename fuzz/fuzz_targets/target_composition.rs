#![no_main]

use auths_composition::{evaluate, BranchOutcome};
use auths_model::{AuthorizationPlan, DenialReason, ProofRef, Requirement, VerifierLimits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let count = data.len().clamp(1, 32);
    let leaves: Vec<_> = (0..count)
        .map(|index| {
            let mut identifier = [0_u8; 32];
            identifier[0] = u8::try_from(index).unwrap_or(u8::MAX);
            AuthorizationPlan::proof(ProofRef::new(identifier))
        })
        .collect();
    let plan = match data[0] % 3 {
        0 => AuthorizationPlan::all_of(leaves),
        1 => AuthorizationPlan::any_of(leaves),
        _ => AuthorizationPlan::k_of_n(u16::try_from(count / 2 + 1).unwrap_or(u16::MAX), leaves),
    };
    let Ok(plan) = plan else {
        return;
    };
    let mut branch =
        |reference: ProofRef| match data[usize::from(reference.as_bytes()[0]) % data.len()] % 4 {
            0 => BranchOutcome::Authorized,
            1 => BranchOutcome::Denied(DenialReason::InvalidSignature),
            2 => BranchOutcome::Indeterminate(Requirement::StaleStatus),
            _ => BranchOutcome::StructurallyInvalid(DenialReason::MissingReference),
        };
    let first = evaluate(&plan, &VerifierLimits::default_deployment(), &mut branch);
    let second = evaluate(&plan, &VerifierLimits::default_deployment(), &mut branch);
    assert_eq!(first, second);
});
