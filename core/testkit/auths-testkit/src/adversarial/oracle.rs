use auths_model::{AdapterId, EvidenceId};
use auths_ports::{PrincipalControlError, PrincipalControlInput, PrincipalMethod};
use sha2::{Digest as _, Sha256};

/// Privacy-preserving projection of successful adapter output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlProjection {
    /// Digest of the suite-specific public key.
    pub verification_key_sha256: [u8; 32],
    /// Sorted exact consumed evidence identifiers.
    pub consumed_evidence: Vec<EvidenceId>,
    /// Adapter implementation identifier.
    pub adapter: AdapterId,
    /// Adapter semantic version.
    pub adapter_version: u16,
    /// Deterministic charged work.
    pub work_units: u64,
    /// Whether a method-specific signature message was emitted.
    pub has_signature_message: bool,
}

/// Exact boundary oracle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlOracle {
    /// Expected successful output projection.
    Control(ControlProjection),
    /// Expected typed adapter failure.
    Error(PrincipalControlError),
}

/// Borrowed method case with exact input and oracle.
pub struct MethodCase<'a> {
    /// Input consumed once by the method.
    pub input: PrincipalControlInput<'a>,
    /// Exact expected result.
    pub oracle: ControlOracle,
}

/// Shared principal-method contract failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConformanceFailure {
    /// The adapter returned a different semantic value.
    Mismatch,
    /// The adapter exceeded its declared conservative work reservation.
    WorkLimitExceeded,
    /// Successful provenance was empty, unsorted, or duplicated.
    InvalidProvenance,
}

/// Runs the common contract against one exact adapter case.
///
/// # Errors
///
/// Returns a typed conformance failure for any oracle or output-invariant
/// mismatch.
pub fn assert_method_contract(
    method: &dyn PrincipalMethod,
    case: MethodCase<'_>,
) -> Result<(), ConformanceFailure> {
    let reserved = method.maximum_work_units();
    match (&case.oracle, method.verify_control(case.input)) {
        (ControlOracle::Error(expected), Err(actual)) if expected == &actual => Ok(()),
        (ControlOracle::Control(expected), Ok(actual)) => {
            if actual.work_units() > reserved {
                return Err(ConformanceFailure::WorkLimitExceeded);
            }
            if actual.consumed_evidence().is_empty()
                || actual
                    .consumed_evidence()
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(ConformanceFailure::InvalidProvenance);
            }
            let actual = ControlProjection {
                verification_key_sha256: Sha256::digest(actual.verification_key()).into(),
                consumed_evidence: actual.consumed_evidence().to_vec(),
                adapter: actual.adapter().clone(),
                adapter_version: actual.adapter_version(),
                work_units: actual.work_units(),
                has_signature_message: actual.signature_message().is_some(),
            };
            if &actual == expected {
                Ok(())
            } else {
                Err(ConformanceFailure::Mismatch)
            }
        }
        _ => Err(ConformanceFailure::Mismatch),
    }
}
