//! Frozen pre-cutover native algorithms exercise complete valid records and
//! result fields independently of the new translated policy guards.
use super::*;

fn original_authorize_recovery_lease(
    record: &ConnectionRecord,
    generation: NonZeroU64,
) -> Result<(), ConnectionRecordError> {
    if record.state == ConnectionState::Revoked {
        return Err(ConnectionRecordError::Revoked);
    }
    if generation > record.generation {
        return Err(ConnectionRecordError::InvalidGeneration);
    }
    Ok(())
}

fn original_binding_for_recovery(
    record: &ConnectionRecord,
    generation: NonZeroU64,
    credential_generation: NonZeroU64,
    credential_reference_commitment: CredentialReferenceCommitment,
) -> Result<ConnectionBinding, ConnectionRecordError> {
    original_authorize_recovery_lease(record, generation)?;
    if credential_generation > generation {
        return Err(ConnectionRecordError::InvalidGeneration);
    }
    if generation >= record.credential_generation
        && (credential_generation != record.credential_generation
            || !credential_reference_commitment.matches(&record.credential_reference_commitment))
    {
        return Err(ConnectionRecordError::InvalidGeneration);
    }
    Ok(ConnectionBinding {
        provider_kind: record.provider_kind.clone(),
        alias: record.alias.clone(),
        connection_id: record.connection_id.clone(),
        contract: record.contract.clone(),
        descriptor_schema: record.descriptor_schema.clone(),
        descriptor: record.descriptor.clone(),
        generation,
        credential_generation,
        descriptor_commitment: record.descriptor_commitment,
        account_commitment: record.account_commitment,
        credential_reference_commitment: *credential_reference_commitment.as_bytes(),
    })
}

fn original_transition_state(
    record: &ConnectionRecord,
    state: ConnectionState,
    updated_at_unix_seconds: u64,
) -> Result<ConnectionRecord, ConnectionRecordError> {
    if state == record.state
        || record.state == ConnectionState::Revoked
        || updated_at_unix_seconds < record.updated_at_unix_seconds
    {
        return Err(ConnectionRecordError::InvalidState);
    }
    let generations = kernel::state_change(record.generations())
        .ok_or(ConnectionRecordError::InvalidGeneration)?;
    ConnectionRecord::assemble(
        record.provider_kind.clone(),
        record.alias.clone(),
        record.connection_id.clone(),
        record.contract.clone(),
        record.descriptor_schema.clone(),
        record.descriptor.clone(),
        record.account_commitment,
        record.credential_reference_commitment,
        generations,
        state,
        record.allowed_workloads.clone(),
        record.allowed_profiles.clone(),
        record.created_at_unix_seconds,
        updated_at_unix_seconds,
        (state == ConnectionState::Revoked).then_some(updated_at_unix_seconds),
    )
}

fn record_for(state: ConnectionState, generation: u64, credential: u64) -> ConnectionRecord {
    let mut record = super::tests::record();
    record.state = state;
    record.generation = NonZeroU64::new(generation).unwrap();
    record.credential_generation = NonZeroU64::new(credential).unwrap();
    record.revoked_at_unix_seconds = (state == ConnectionState::Revoked).then_some(10);
    ConnectionRecord::from_canonical_cbor(&record.to_canonical_cbor().unwrap()).unwrap()
}

#[test]
fn recovery_policy_preserves_full_native_records_and_commitments() {
    let values = [1, 2, 3, u64::MAX - 1, u64::MAX];
    let mut accepted = 0;
    let mut refused = 0;
    for state in [
        ConnectionState::Active,
        ConnectionState::Disabled,
        ConnectionState::Revoked,
    ] {
        for generation in values {
            for current_credential in values {
                if current_credential > generation {
                    continue;
                }
                let record = record_for(state, generation, current_credential);
                for operation in values {
                    let operation = NonZeroU64::new(operation).unwrap();
                    assert_eq!(
                        record.authorize_recovery_lease(operation),
                        original_authorize_recovery_lease(&record, operation)
                    );
                    for credential in values {
                        for bytes in [[3; 32], [4; 32]] {
                            let credential = NonZeroU64::new(credential).unwrap();
                            let reference = CredentialReferenceCommitment::for_tests(bytes);
                            let expected = original_binding_for_recovery(
                                &record, operation, credential, reference,
                            );
                            let actual =
                                record.binding_for_recovery(operation, credential, reference);
                            if actual.is_ok() {
                                accepted += 1;
                            } else {
                                refused += 1;
                            }
                            assert_eq!(actual, expected);
                        }
                    }
                }
            }
        }
    }
    // Two non-revoked states. For record index i and current credential index j,
    // older operations contribute j*(j+1) pairs, current ones contribute i-j+1.
    // Summing 2*sum(i=0..4, j=0..i) gives 210 accepts among 2250 bindings.
    assert_eq!((accepted, refused), (210, 2040));
}

#[test]
fn administrative_transitions_preserve_the_full_frozen_record() {
    let states = [
        ConnectionState::Active,
        ConnectionState::Disabled,
        ConnectionState::Revoked,
    ];
    let times = [0, 1, 2, u64::MAX - 1, u64::MAX];
    let mut checked = 0;
    for current in states {
        for next in states {
            for generation in [1, u64::MAX] {
                for previous in times {
                    let mut record = record_for(current, generation, 1);
                    record.created_at_unix_seconds = 0;
                    record.updated_at_unix_seconds = previous;
                    record.revoked_at_unix_seconds =
                        (current == ConnectionState::Revoked).then_some(previous);
                    record =
                        ConnectionRecord::from_canonical_cbor(&record.to_canonical_cbor().unwrap())
                            .unwrap();
                    for proposed in times {
                        let actual = record.transition_state(next, proposed);
                        let expected = original_transition_state(&record, next, proposed);
                        assert_eq!(actual, expected);
                        checked += 1;
                    }
                }
            }
        }
    }
    assert_eq!(checked, 450);
}

fn original_rotated(
    record: &ConnectionRecord,
    descriptor: Vec<u8>,
    account_commitment: [u8; 32],
    credential_reference_commitment: [u8; 32],
    updated_at_unix_seconds: u64,
) -> Result<ConnectionRecord, ConnectionRecordError> {
    if record.state == ConnectionState::Revoked
        || updated_at_unix_seconds < record.updated_at_unix_seconds
    {
        return Err(ConnectionRecordError::InvalidState);
    }
    let generations =
        kernel::rotation(record.generations()).ok_or(ConnectionRecordError::InvalidGeneration)?;
    ConnectionRecord::assemble(
        record.provider_kind.clone(),
        record.alias.clone(),
        record.connection_id.clone(),
        record.contract.clone(),
        record.descriptor_schema.clone(),
        descriptor,
        account_commitment,
        credential_reference_commitment,
        generations,
        record.state,
        record.allowed_workloads.clone(),
        record.allowed_profiles.clone(),
        record.created_at_unix_seconds,
        updated_at_unix_seconds,
        None,
    )
}

fn original_with_authorization(
    record: &ConnectionRecord,
    allowed_workloads: Vec<String>,
    allowed_profiles: Vec<ConnectionProfile>,
    updated_at_unix_seconds: u64,
) -> Result<ConnectionRecord, ConnectionRecordError> {
    if record.state == ConnectionState::Revoked
        || updated_at_unix_seconds < record.updated_at_unix_seconds
    {
        return Err(ConnectionRecordError::InvalidState);
    }
    let generations = kernel::state_change(record.generations())
        .ok_or(ConnectionRecordError::InvalidGeneration)?;
    ConnectionRecord::assemble(
        record.provider_kind.clone(),
        record.alias.clone(),
        record.connection_id.clone(),
        record.contract.clone(),
        record.descriptor_schema.clone(),
        record.descriptor.clone(),
        record.account_commitment,
        record.credential_reference_commitment,
        generations,
        record.state,
        allowed_workloads,
        allowed_profiles,
        record.created_at_unix_seconds,
        updated_at_unix_seconds,
        None,
    )
}

#[test]
fn rotation_and_authorization_replacement_preserve_frozen_order_and_fields() {
    let mut rotations = (0, 0);
    let mut replacements = (0, 0);
    for state in [
        ConnectionState::Active,
        ConnectionState::Disabled,
        ConnectionState::Revoked,
    ] {
        for generation in [1, u64::MAX] {
            for previous in [0, 1, 2, u64::MAX - 1, u64::MAX] {
                let mut record = record_for(state, generation, 1);
                record.created_at_unix_seconds = 0;
                record.updated_at_unix_seconds = previous;
                record.revoked_at_unix_seconds =
                    (state == ConnectionState::Revoked).then_some(previous);
                record =
                    ConnectionRecord::from_canonical_cbor(&record.to_canonical_cbor().unwrap())
                        .unwrap();
                for proposed in [0, 1, 2, u64::MAX - 1, u64::MAX] {
                    for descriptor in [vec![], vec![1], vec![0; MAX_DESCRIPTOR_BYTES + 1]] {
                        let expected = original_rotated(
                            &record,
                            descriptor.clone(),
                            [7; 32],
                            [8; 32],
                            proposed,
                        );
                        let actual = record.rotated(descriptor, [7; 32], [8; 32], proposed);
                        rotations.0 += 1;
                        rotations.1 += usize::from(actual.is_ok());
                        assert_eq!(actual, expected);
                    }
                    for workloads in [vec![], record.allowed_workloads.clone()] {
                        for profiles in [vec![], record.allowed_profiles.clone()] {
                            let expected = original_with_authorization(
                                &record,
                                workloads.clone(),
                                profiles.clone(),
                                proposed,
                            );
                            let actual =
                                record.with_authorization(workloads.clone(), profiles, proposed);
                            replacements.0 += 1;
                            replacements.1 += usize::from(actual.is_ok());
                            assert_eq!(actual, expected);
                        }
                    }
                }
            }
        }
    }
    // Two eligible states, one non-overflowing generation and fifteen
    // nondecreasing timestamp pairs, with one valid payload per pair.
    assert_eq!(rotations, (450, 30));
    assert_eq!(replacements, (600, 30));
}
