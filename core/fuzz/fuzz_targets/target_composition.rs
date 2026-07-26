#![no_main]

use auths_composition::{BranchOutcome, evaluate};
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
    let operator = data[0] % 3;
    let threshold = count / 2 + 1;
    let plan = match operator {
        0 => AuthorizationPlan::all_of(leaves),
        1 => AuthorizationPlan::any_of(leaves),
        _ => AuthorizationPlan::k_of_n(u16::try_from(threshold).unwrap_or(u16::MAX), leaves),
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
    let first = evaluate(&plan, &VerifierLimits::hard(), &mut branch);
    let second = evaluate(&plan, &VerifierLimits::hard(), &mut branch);
    assert_eq!(first, second);

    let outcomes: Vec<_> = (0..count)
        .map(|index| data[index % data.len()] % 4)
        .collect();
    let authorized = outcomes.iter().filter(|tag| **tag == 0).count();
    let indeterminate = outcomes.iter().filter(|tag| **tag == 2).count();
    let denied = outcomes.contains(&1);
    let structural = outcomes.contains(&3);
    let canonical_denial = match (denied, structural) {
        (true, true) => {
            if DenialReason::InvalidSignature.code() < DenialReason::MissingReference.code() {
                DenialReason::InvalidSignature
            } else {
                DenialReason::MissingReference
            }
        }
        (true, false) => DenialReason::InvalidSignature,
        (false, true) => DenialReason::MissingReference,
        (false, false) => DenialReason::AuthorizationPlanInvalid,
    };
    let expected = match operator {
        0 if denied || structural => BranchOutcome::Denied(canonical_denial),
        0 if indeterminate > 0 => BranchOutcome::Indeterminate(Requirement::StaleStatus),
        0 => BranchOutcome::Authorized,
        1 if authorized > 0 => BranchOutcome::Authorized,
        1 if indeterminate > 0 => BranchOutcome::Indeterminate(Requirement::StaleStatus),
        1 => BranchOutcome::Denied(canonical_denial),
        _ if authorized >= threshold => BranchOutcome::Authorized,
        _ if authorized + indeterminate >= threshold => {
            BranchOutcome::Indeterminate(Requirement::StaleStatus)
        }
        _ => BranchOutcome::Denied(canonical_denial),
    };
    assert_eq!(first, Ok(expected));
});
