//! Registry-bound error transport for the Python boundary.
//!
//! Rust owns what an error *means*. This module owns only how that meaning
//! survives the pyo3 call boundary, and it may not invent any of it:
//!
//! * The stable code is one of the codes `auths_errors::registry()` defines.
//!   The boundary never mints a code of its own.
//! * `effect`, `retry`, and `recommended_action` are **read out of the
//!   registry** for that code. They are never written here by hand.
//! * A code the registry does not define fails closed to
//!   `effect = "possible"` / `retry = "unknown"` /
//!   `recommended_action = "resume-and-reconcile"`, so a newer Rust code can
//!   never be silently downgraded to "nothing happened" by an older binding
//!   (contract 4.1, the fail-closed rule).
//!
//! `EffectState` has exactly three members, and this module can only ever
//! produce those three, because it projects `auths_errors::EffectState`.

use auths_errors::{EffectState, ErrorDefinition, RecommendedAction, RetryClass, registry};
use pyo3::{create_exception, exceptions::PyValueError, prelude::*};

create_exception!(
    auths._native,
    NativeAuthsError,
    PyValueError,
    "A boundary failure carrying its registry classification."
);

/// The classifications the pyo3 boundary is allowed to assert.
///
/// This set is deliberately tiny. Every member names a registry code and
/// carries the justification for why that code — and therefore that effect
/// state — is true of the code path that raises it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Boundary {
    /// Bytes or identifiers the caller supplied that the canonical Rust model
    /// rejected. Every such entry point is a pure decoder, canonicaliser, or
    /// authoring step: it performs no effect, so `not-applied` is provable
    /// rather than assumed.
    MalformedInput,
    /// The attenuation algebra refused what the caller asked for. Planning is
    /// pure, so nothing was applied.
    AuthorizationDenied,
    /// A facility the native layer requires was unavailable (for example the
    /// operating system's randomness). Nothing was attempted.
    RuntimeUnavailable,
    /// The boundary could not classify the failure. Fails closed to
    /// `possible`: the caller must reconcile, never blindly retry.
    Unclassified,
}

impl Boundary {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::MalformedInput => "core.malformed-input",
            Self::AuthorizationDenied => "core.authorization-denied",
            Self::RuntimeUnavailable => "core.native-runtime-unavailable",
            Self::Unclassified => "core.outcome-unknown",
        }
    }
}

/// The registry's answer for one stable code, or the fail-closed answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Classification {
    pub(crate) effect: EffectState,
    pub(crate) retry: RetryClass,
    pub(crate) recommended_action: RecommendedAction,
    pub(crate) operation: &'static str,
    pub(crate) stage: &'static str,
    pub(crate) registered: bool,
}

const UNCLASSIFIED: Classification = Classification {
    effect: EffectState::Possible,
    retry: RetryClass::Unknown,
    recommended_action: RecommendedAction::ResumeAndReconcile,
    operation: "execute",
    stage: "unknown",
    registered: false,
};

fn definition(code: &str) -> Option<&'static ErrorDefinition> {
    registry().find(|candidate| candidate.code == code)
}

/// Reads the registry's classification of `code`.
///
/// An unrecognised code fails closed to `possible` / `unknown` /
/// `resume-and-reconcile`. A recognised code whose outcomes disagree about the
/// effect also fails closed, because in that case the boundary genuinely does
/// not know which outcome occurred.
pub(crate) fn classify(code: &str) -> Classification {
    let Some(definition) = definition(code) else {
        return UNCLASSIFIED;
    };
    let Some(first) = definition.outcomes.first() else {
        return UNCLASSIFIED;
    };
    let effect = if definition
        .outcomes
        .iter()
        .all(|outcome| outcome.effect == first.effect)
    {
        first.effect
    } else {
        EffectState::Possible
    };
    let retry = if definition
        .outcomes
        .iter()
        .all(|outcome| outcome.retry == first.retry)
    {
        first.retry
    } else {
        RetryClass::Unknown
    };
    Classification {
        effect,
        retry,
        recommended_action: definition.recommended_action,
        operation: definition.operation,
        stage: definition.stages.first().copied().unwrap_or("unknown"),
        registered: true,
    }
}

pub(crate) const fn effect_wire(value: EffectState) -> &'static str {
    match value {
        EffectState::NotApplied => "not-applied",
        EffectState::Possible => "possible",
        EffectState::Applied => "applied",
    }
}

pub(crate) const fn retry_wire(value: RetryClass) -> &'static str {
    match value {
        RetryClass::Never => "never",
        RetryClass::Safe => "safe",
        RetryClass::Conditional => "conditional",
        RetryClass::Unknown => "unknown",
    }
}

pub(crate) const fn action_wire(value: RecommendedAction) -> &'static str {
    match value {
        RecommendedAction::CorrectInput => "correct-input",
        RecommendedAction::CorrectConfiguration => "correct-configuration",
        RecommendedAction::InstallCompatibleRuntime => "install-compatible-runtime",
        RecommendedAction::RetryExecution => "retry-execution",
        RecommendedAction::SatisfyCondition => "satisfy-condition",
        RecommendedAction::ResumeAndReconcile => "resume-and-reconcile",
        RecommendedAction::InspectReceipt => "inspect-receipt",
        RecommendedAction::ContactSupport => "contact-support",
    }
}

/// Builds the structured exception for `code`, attaching the registry's own
/// classification. Every attribute is always present, so a caller never has to
/// test for its existence before branching on the effect axis.
pub(crate) fn structured_as<T>(code: &str, summary: &str) -> PyErr
where
    T: pyo3::type_object::PyTypeInfo,
{
    let classification = classify(code);
    let error = PyErr::new::<T, _>(summary.to_owned());
    let attach = Python::attach(|py| -> PyResult<()> {
        let value = error.value(py);
        value.setattr("code", code)?;
        value.setattr("effect", effect_wire(classification.effect))?;
        value.setattr("retry", retry_wire(classification.retry))?;
        value.setattr(
            "recommended_action",
            action_wire(classification.recommended_action),
        )?;
        value.setattr("operation", classification.operation)?;
        value.setattr("stage", classification.stage)?;
        value.setattr("summary", summary)?;
        value.setattr("registered", classification.registered)?;
        Ok(())
    });
    match attach {
        Ok(()) => error,
        Err(failure) => failure,
    }
}

/// Converts a Rust failure into the structured Python exception for `boundary`.
pub(crate) fn boundary_error(boundary: Boundary, error: impl core::fmt::Display) -> PyErr {
    structured_as::<NativeAuthsError>(boundary.code(), &error.to_string())
}

/// The boundary's answer to "the caller handed us something the canonical Rust
/// model rejects". Pure entry point, so the effect axis is provably
/// `not-applied`.
pub(crate) fn malformed_input(error: impl core::fmt::Display) -> PyErr {
    boundary_error(Boundary::MalformedInput, error)
}

/// The classification `code` carries, as `(code, effect, retry,
/// recommended_action, registered)`.
///
/// This is the only way a projection is allowed to learn what a code means:
/// it reads Rust's registry rather than keeping a copy of it.
#[pyfunction]
fn error_classification_v1(code: &str) -> (String, &'static str, &'static str, &'static str, bool) {
    let classification = classify(code);
    (
        code.to_owned(),
        effect_wire(classification.effect),
        retry_wire(classification.retry),
        action_wire(classification.recommended_action),
        classification.registered,
    )
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add(
        "NativeAuthsError",
        module.py().get_type::<NativeAuthsError>(),
    )?;
    module.add_function(wrap_pyfunction!(error_classification_v1, module)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Boundary, EffectState, RetryClass, classify};

    #[test]
    fn an_unregistered_code_fails_closed_to_possible() {
        let classification = classify("not.a.registry.code");
        assert_eq!(classification.effect, EffectState::Possible);
        assert_eq!(classification.retry, RetryClass::Unknown);
        assert!(!classification.registered);
    }

    #[test]
    fn every_boundary_classification_names_a_registry_code() {
        for boundary in [
            Boundary::MalformedInput,
            Boundary::RuntimeUnavailable,
            Boundary::Unclassified,
        ] {
            assert!(
                classify(boundary.code()).registered,
                "{} is not in the Rust registry",
                boundary.code()
            );
        }
    }

    #[test]
    fn the_unclassified_boundary_is_the_fail_closed_one() {
        assert_eq!(
            classify(Boundary::Unclassified.code()).effect,
            EffectState::Possible
        );
        assert_eq!(
            classify(Boundary::MalformedInput.code()).effect,
            EffectState::NotApplied
        );
    }
}
