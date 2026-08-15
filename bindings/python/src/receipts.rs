use auths_model::{
    Digest, PrincipalId, ProfileId, ProfileRef, ReceiptId, SignatureBytes, SignatureSuiteId,
    Timestamp, VerificationMethod,
};
use auths_profile_domains::DomainReceiptInspector;
use auths_raw_key::RawKeyDescriptor;
use auths_receipts::{
    AttestedDecisionReceipt, AttestedExecutionReceipt, ConfiguredReceiptVerifier, DecisionClass,
    ExecutionOutcome, ReceiptDisclosure, ReceiptInspection, ReceiptSigner, ReceiptViewMode,
    VerifiedReceiptMetadata, application_execution_lease_digest, decode_attested_decision,
    decode_attested_execution, decode_decision, decode_execution, encode_attested_decision,
    encode_attested_execution, encode_receipt_disclosure, inspect_attested_execution_receipt,
    prepare_decision_receipt, prepare_execution_receipt, verify_attested_decision_bytes,
    verify_attested_execution_bytes, verify_decision_attestation, verify_execution_attestation,
};
use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};
use serde_json::{Value, json};

#[derive(Clone)]
#[pyclass(
    name = "ReceiptPreparation",
    frozen,
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyReceiptPreparation {
    id: ReceiptId,
    canonical: Vec<u8>,
    signing_preimage: Vec<u8>,
}

#[pymethods]
impl PyReceiptPreparation {
    #[getter]
    fn receipt_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.id.as_bytes())
    }

    #[getter]
    fn canonical<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.canonical)
    }

    #[getter]
    fn signing_preimage<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.signing_preimage)
    }
}

pub(crate) fn prepare_decision(
    proof_cbor: &[u8],
    canonical_action_cbor: &[u8],
    trusted_context_cbor: &[u8],
    decided_at: u64,
    verifier: &str,
    verification_method: &str,
    suite: &str,
) -> PyResult<PyReceiptPreparation> {
    let limits = auths_model::VerifierLimits::default_deployment();
    let proof = auths_codec::decode_bundle(proof_cbor, &limits).map_err(value_error)?;
    if auths_codec::encode_bundle(&proof)
        .map_err(value_error)?
        .as_slice()
        != proof_cbor
    {
        return Err(PyValueError::new_err("proof is not canonical"));
    }
    let action = auths_codec::decode_canonical_action(canonical_action_cbor, &limits)
        .map_err(value_error)?;
    if auths_codec::encode_canonical_action(&action)
        .map_err(value_error)?
        .as_slice()
        != canonical_action_cbor
    {
        return Err(PyValueError::new_err("action is not canonical"));
    }
    let context =
        auths_codec::decode_verifier_context(trusted_context_cbor).map_err(value_error)?;
    if auths_codec::encode_verifier_context(&context)
        .map_err(value_error)?
        .as_slice()
        != trusted_context_cbor
    {
        return Err(PyValueError::new_err("trusted context is not canonical"));
    }
    let signer = receipt_signer(verifier, verification_method, suite)?;
    let authority_commitment = auths_codec::proof_digest(&proof).map_err(value_error)?;
    let prepared = prepare_decision_receipt(
        authority_commitment,
        &action,
        &context,
        DecisionClass::Authorized,
        vec!["authorized".to_owned()],
        Timestamp::new(decided_at),
        &signer,
    )
    .map_err(value_error)?;
    Ok(PyReceiptPreparation {
        id: prepared.id(),
        canonical: prepared.canonical().to_vec(),
        signing_preimage: prepared.signing_preimage().to_vec(),
    })
}

#[pyfunction]
fn prepare_authorized_decision_receipt_v1(
    proof_cbor: &[u8],
    canonical_action_cbor: &[u8],
    trusted_context_cbor: &[u8],
    decided_at: u64,
    verifier: &str,
    verification_method: &str,
    suite: &str,
) -> PyResult<PyReceiptPreparation> {
    prepare_decision(
        proof_cbor,
        canonical_action_cbor,
        trusted_context_cbor,
        decided_at,
        verifier,
        verification_method,
        suite,
    )
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn prepare_application_execution_receipt_v1(
    decision_receipt_id_bytes: &[u8],
    idempotency_key: &str,
    plan_commitment: Option<&[u8]>,
    member_index: Option<u16>,
    member_count: Option<u16>,
    command_bytes: &[u8],
    outcome: &str,
    result: Option<&[u8]>,
    completed_at: u64,
    verifier: &str,
    verification_method: &str,
    suite: &str,
) -> PyResult<PyReceiptPreparation> {
    if command_bytes.is_empty() || command_bytes.len() > auths_model::HARD_MAX_ACTION_BYTES {
        return Err(PyValueError::new_err("command bytes are outside bounds"));
    }
    let decision = ReceiptId::new(array32(decision_receipt_id_bytes, "decision receipt id")?);
    let plan = plan_commitment
        .map(|value| array32(value, "plan commitment").map(Digest::new))
        .transpose()?;
    let member = match (member_index, member_count) {
        (Some(index), Some(count)) => Some((index, count)),
        (None, None) => None,
        _ => return Err(PyValueError::new_err("plan member position is incomplete")),
    };
    application_execution_lease_digest(idempotency_key, plan, member).map_err(value_error)?;
    let signer = receipt_signer(verifier, verification_method, suite)?;
    let prepared = prepare_execution_receipt(
        decision,
        idempotency_key,
        plan,
        member,
        command_bytes,
        match outcome {
            "succeeded" => ExecutionOutcome::Succeeded,
            "failed" => ExecutionOutcome::Failed,
            "indeterminate" => ExecutionOutcome::Indeterminate,
            _ => {
                return Err(PyValueError::new_err(
                    "execution outcome cannot be attested",
                ));
            }
        },
        result,
        Timestamp::new(completed_at),
        &signer,
    )
    .map_err(value_error)?;
    Ok(PyReceiptPreparation {
        id: prepared.id(),
        canonical: prepared.canonical().to_vec(),
        signing_preimage: prepared.signing_preimage().to_vec(),
    })
}

#[pyfunction]
fn attest_decision_receipt_v1<'py>(
    py: Python<'py>,
    canonical: &[u8],
    verifier: &str,
    verification_method: &str,
    suite: &str,
    signature: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let receipt = decode_decision(canonical).map_err(value_error)?;
    let signer = receipt_signer(verifier, verification_method, suite)?;
    let attested = AttestedDecisionReceipt::new(
        receipt,
        signer,
        SignatureBytes::new(signature.to_vec()).map_err(value_error)?,
    );
    let bytes = encode_attested_decision(&attested).map_err(value_error)?;
    Ok(PyBytes::new(py, &bytes))
}

#[pyfunction]
fn attest_execution_receipt_v1<'py>(
    py: Python<'py>,
    canonical: &[u8],
    verifier: &str,
    verification_method: &str,
    suite: &str,
    signature: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let receipt = decode_execution(canonical).map_err(value_error)?;
    let signer = receipt_signer(verifier, verification_method, suite)?;
    let attested = AttestedExecutionReceipt::new(
        receipt,
        signer,
        SignatureBytes::new(signature.to_vec()).map_err(value_error)?,
    );
    let bytes = encode_attested_execution(&attested).map_err(value_error)?;
    Ok(PyBytes::new(py, &bytes))
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn verify_raw_key_receipt_v1(
    kind: &str,
    attested: &[u8],
    expected_id: &[u8],
    verifier: &str,
    verification_method: &str,
    suite: &str,
    raw_key_evidence: &[u8],
) -> PyResult<()> {
    let expected_verifier = PrincipalId::parse(verifier).map_err(value_error)?;
    let signer = ReceiptSigner::new(
        expected_verifier.clone(),
        VerificationMethod::parse(verification_method).map_err(value_error)?,
        SignatureSuiteId::parse(suite).map_err(value_error)?,
    );
    let descriptor = RawKeyDescriptor::decode(raw_key_evidence)
        .map_err(|_| PyValueError::new_err("invalid raw-key receipt evidence"))?;
    if descriptor.principal().map_err(value_error)?.as_str() != verifier
        || descriptor.suite() != suite
    {
        return Err(PyValueError::new_err("receipt key does not match signer"));
    }
    let expected = ReceiptId::new(array32(expected_id, "receipt id")?);
    let suite = auths_signature::Ed25519Suite::new().map_err(value_error)?;
    let configured = ConfiguredReceiptVerifier::new(signer, descriptor.public_key(), &suite);
    match kind {
        "decision" => {
            verify_decision_attestation(attested, expected, &expected_verifier, &configured)
                .map_err(value_error)?;
        }
        "execution" => {
            verify_execution_attestation(attested, expected, &expected_verifier, &configured)
                .map_err(value_error)?;
        }
        _ => return Err(PyValueError::new_err("unsupported receipt kind")),
    }
    Ok(())
}

#[pyfunction]
fn verify_receipt_link_v1(
    decision: &[u8],
    decision_id: &[u8],
    execution: &[u8],
    execution_id: &[u8],
) -> PyResult<()> {
    let decision_id = ReceiptId::new(array32(decision_id, "decision receipt id")?);
    verify_attested_decision_bytes(decision, decision_id).map_err(value_error)?;
    let execution_id = ReceiptId::new(array32(execution_id, "execution receipt id")?);
    let execution =
        verify_attested_execution_bytes(execution, execution_id).map_err(value_error)?;
    if execution.receipt().decision_receipt() != decision_id {
        return Err(PyValueError::new_err("receipt linkage mismatch"));
    }
    Ok(())
}

#[pyfunction]
fn prepare_receipt_disclosure_v1<'py>(
    py: Python<'py>,
    execution_id: &[u8],
    profile_id: &str,
    profile_version: u16,
    command: &[u8],
    result: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    let disclosure = ReceiptDisclosure::new(
        ReceiptId::new(array32(execution_id, "execution receipt id")?),
        ProfileRef::new(
            ProfileId::parse(profile_id).map_err(value_error)?,
            profile_version,
        )
        .map_err(value_error)?,
        command.to_vec(),
        result.map(<[u8]>::to_vec),
    )
    .map_err(value_error)?;
    let encoded = encode_receipt_disclosure(&disclosure).map_err(value_error)?;
    Ok(PyBytes::new(py, &encoded))
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn inspect_raw_key_receipt_v1<'py>(
    py: Python<'py>,
    decision_id: &[u8],
    decision_bytes: &[u8],
    decision_evidence: &[u8],
    execution_id: &[u8],
    execution_bytes: &[u8],
    execution_evidence: &[u8],
    mode: &str,
    disclosure: Option<&[u8]>,
) -> Bound<'py, PyBytes> {
    let output = inspect_raw_key_receipt(
        decision_id,
        decision_bytes,
        decision_evidence,
        execution_id,
        execution_bytes,
        execution_evidence,
        mode,
        disclosure,
    )
    .unwrap_or_else(|code| json!({ "kind": "invalid", "mode": mode, "code": code }));
    let encoded = serde_json::to_vec(&output).unwrap_or_else(|_| {
        br#"{"kind":"invalid","mode":"opaque","code":"inspection-output-failed"}"#.to_vec()
    });
    PyBytes::new(py, &encoded)
}

#[allow(clippy::too_many_arguments)]
fn inspect_raw_key_receipt(
    decision_id: &[u8],
    decision_bytes: &[u8],
    decision_evidence: &[u8],
    execution_id: &[u8],
    execution_bytes: &[u8],
    execution_evidence: &[u8],
    mode: &str,
    disclosure: Option<&[u8]>,
) -> Result<Value, String> {
    let mode = match mode {
        "opaque" => ReceiptViewMode::Opaque,
        "summary" => ReceiptViewMode::Summary,
        "full" => ReceiptViewMode::Full,
        _ => return Err("inspection-mode-unsupported".into()),
    };
    let decision_id = ReceiptId::new(
        decision_id
            .try_into()
            .map_err(|_| "receipt-id-outside-bounds")?,
    );
    let execution_id = ReceiptId::new(
        execution_id
            .try_into()
            .map_err(|_| "receipt-id-outside-bounds")?,
    );
    let decision_attested = decode_attested_decision(decision_bytes)
        .map_err(|error| inspection_receipt_error(error).to_owned())?;
    let execution_attested = decode_attested_execution(execution_bytes)
        .map_err(|error| inspection_receipt_error(error).to_owned())?;
    let decision_descriptor = RawKeyDescriptor::decode(decision_evidence)
        .map_err(|_| "receipt-invalid-evidence".to_owned())?;
    let execution_descriptor = RawKeyDescriptor::decode(execution_evidence)
        .map_err(|_| "receipt-invalid-evidence".to_owned())?;
    let decision_principal = decision_descriptor
        .principal()
        .map_err(|_| "receipt-invalid-evidence".to_owned())?;
    let execution_principal = execution_descriptor
        .principal()
        .map_err(|_| "receipt-invalid-evidence".to_owned())?;
    if decision_attested.signer().verifier() != &decision_principal
        || decision_attested.signer().suite().as_str() != decision_descriptor.suite()
        || execution_attested.signer().verifier() != &execution_principal
        || execution_attested.signer().suite().as_str() != execution_descriptor.suite()
    {
        return Err("receipt-key-does-not-match-signer".into());
    }
    let decision_suite =
        auths_signature::Ed25519Suite::new().map_err(|_| "receipt-suite-unavailable".to_owned())?;
    let execution_suite =
        auths_signature::Ed25519Suite::new().map_err(|_| "receipt-suite-unavailable".to_owned())?;
    let decision_policy = ConfiguredReceiptVerifier::new(
        decision_attested.signer().clone(),
        decision_descriptor.public_key(),
        &decision_suite,
    );
    let execution_policy = ConfiguredReceiptVerifier::new(
        execution_attested.signer().clone(),
        execution_descriptor.public_key(),
        &execution_suite,
    );
    let inspection = inspect_attested_execution_receipt(
        decision_bytes,
        decision_id,
        &decision_principal,
        &decision_policy,
        execution_bytes,
        execution_id,
        &execution_principal,
        &execution_policy,
        mode,
        disclosure,
        (mode != ReceiptViewMode::Opaque)
            .then_some(&DomainReceiptInspector as &dyn auths_receipts::ReceiptProfileInspector),
    )
    .map_err(|error| error.code().to_owned())?;
    Ok(inspection_json(&inspection))
}

fn inspection_json(inspection: &ReceiptInspection) -> Value {
    match inspection {
        ReceiptInspection::VerifiedOpaque { metadata } => json!({
            "kind": "verified-opaque",
            "mode": "opaque",
            "receipt": metadata_json(metadata),
        }),
        ReceiptInspection::VerifiedDisclosed {
            metadata,
            mode,
            projection,
            disclosure,
        } => json!({
            "kind": "verified-disclosed",
            "mode": match mode { ReceiptViewMode::Summary => "summary", ReceiptViewMode::Full => "full", ReceiptViewMode::Opaque => "opaque" },
            "receipt": metadata_json(metadata),
            "summary": {
                "title": projection.title(),
                "fields": projection.fields().iter().map(|(label, value)| json!({ "label": label, "value": value })).collect::<Vec<_>>(),
            },
            "disclosure": disclosure.as_ref().map(|value| json!({
                "commandHex": hex::encode(value.command()),
                "resultHex": value.result().map(hex::encode),
            })),
        }),
    }
}

fn metadata_json(metadata: &VerifiedReceiptMetadata) -> Value {
    json!({
        "decisionReceiptId": hex::encode(metadata.decision_id().as_bytes()),
        "executionReceiptId": hex::encode(metadata.execution_id().as_bytes()),
        "profile": { "id": metadata.profile().id().as_str(), "version": metadata.profile().version() },
        "decision": match metadata.decision() { DecisionClass::Authorized => "authorized", DecisionClass::Denied => "denied", DecisionClass::Indeterminate => "indeterminate" },
        "reasons": metadata.reasons(),
        "outcome": match metadata.outcome() { ExecutionOutcome::Succeeded => "succeeded", ExecutionOutcome::Failed => "failed", ExecutionOutcome::Indeterminate => "indeterminate" },
        "decidedAt": metadata.decided_at().get().to_string(),
        "completedAt": metadata.completed_at().get().to_string(),
        "decisionSigner": signer_json(metadata.decision_signer()),
        "executionSigner": signer_json(metadata.execution_signer()),
        "commitments": {
            "proof": hex::encode(metadata.proof_digest().as_bytes()),
            "action": hex::encode(metadata.action_digest().as_bytes()),
            "context": hex::encode(metadata.context_digest().as_bytes()),
            "principalStatus": hex::encode(metadata.principal_status().as_bytes()),
            "grantStatus": hex::encode(metadata.grant_status().as_bytes()),
            "executionLease": hex::encode(metadata.execution_lease().as_bytes()),
            "command": hex::encode(metadata.command_digest().as_bytes()),
            "result": metadata.result_digest().map(|value| hex::encode(value.as_bytes())),
        },
    })
}

fn signer_json(signer: &ReceiptSigner) -> Value {
    json!({
        "principal": signer.verifier().as_str(),
        "verificationMethod": signer.verification_method().as_str(),
        "suite": signer.suite().as_str(),
    })
}

fn inspection_receipt_error(error: auths_receipts::ReceiptError) -> &'static str {
    match error {
        auths_receipts::ReceiptError::Malformed | auths_receipts::ReceiptError::InvalidReason => {
            "receipt-malformed"
        }
        auths_receipts::ReceiptError::NonCanonical => "receipt-non-canonical",
        auths_receipts::ReceiptError::UnsupportedProtocol => "receipt-unsupported",
        auths_receipts::ReceiptError::LimitExceeded => "receipt-limit-exceeded",
        auths_receipts::ReceiptError::DigestMismatch => "receipt-id-mismatch",
        auths_receipts::ReceiptError::LinkageMismatch | auths_receipts::ReceiptError::Duplicate => {
            "receipt-linkage-mismatch"
        }
        auths_receipts::ReceiptError::UnexpectedSigner => "receipt-unexpected-signer",
        auths_receipts::ReceiptError::InvalidSignature
        | auths_receipts::ReceiptError::SigningUnavailable => "receipt-invalid-signature",
    }
}

fn receipt_signer(
    verifier: &str,
    verification_method: &str,
    suite: &str,
) -> PyResult<ReceiptSigner> {
    Ok(ReceiptSigner::new(
        PrincipalId::parse(verifier).map_err(value_error)?,
        VerificationMethod::parse(verification_method).map_err(value_error)?,
        SignatureSuiteId::parse(suite).map_err(value_error)?,
    ))
}

fn array32(value: &[u8], label: &str) -> PyResult<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{label} must contain 32 bytes")))
}

fn value_error(error: impl core::fmt::Display) -> PyErr {
    PyValueError::new_err(error.to_string())
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyReceiptPreparation>()?;
    module.add_function(wrap_pyfunction!(
        prepare_authorized_decision_receipt_v1,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        prepare_application_execution_receipt_v1,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(attest_decision_receipt_v1, module)?)?;
    module.add_function(wrap_pyfunction!(attest_execution_receipt_v1, module)?)?;
    module.add_function(wrap_pyfunction!(verify_raw_key_receipt_v1, module)?)?;
    module.add_function(wrap_pyfunction!(verify_receipt_link_v1, module)?)?;
    module.add_function(wrap_pyfunction!(prepare_receipt_disclosure_v1, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_raw_key_receipt_v1, module)?)?;
    Ok(())
}
