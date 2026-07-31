//! Profile-specific commands sealed by Auths authorization and durable
//! lifecycle call-entry authority.

use auths_lifecycle::{ExecutionAuthorizationV1, ProviderCallAuthorizationV1};
use auths_sdk::Authorized;

use crate::{
    BoundedRecordApiPolicyV1, CREATE_PROVIDER_CONTRACT_ID, CreateRecordV1,
    READ_PROVIDER_CONTRACT_ID, ReadRecordV1, VerifiedCreateRecordCommand,
    VerifiedReadRecordCommand,
};

/// Exact create command accepted by the protected records provider.
pub struct SealedCreateRecordCommand {
    authorized: Authorized<VerifiedCreateRecordCommand>,
    execution_authorization: ExecutionAuthorizationV1,
    provider_call_authorization: ProviderCallAuthorizationV1,
    decision_digest: String,
    executed_at: u64,
}

impl SealedCreateRecordCommand {
    pub(crate) const fn new(
        authorized: Authorized<VerifiedCreateRecordCommand>,
        execution_authorization: ExecutionAuthorizationV1,
        provider_call_authorization: ProviderCallAuthorizationV1,
        decision_digest: String,
        executed_at: u64,
    ) -> Self {
        Self {
            authorized,
            execution_authorization,
            provider_call_authorization,
            decision_digest,
            executed_at,
        }
    }

    #[must_use]
    pub fn action(&self) -> &CreateRecordV1 {
        self.authorized.command().action()
    }

    #[must_use]
    pub fn lifecycle_authorization_matches(&self) -> bool {
        lifecycle_authorization_matches(
            self.action().digest().ok().as_deref(),
            CREATE_PROVIDER_CONTRACT_ID,
            &self.execution_authorization,
            &self.provider_call_authorization,
        )
    }

    #[must_use]
    pub fn decision_digest(&self) -> &str {
        &self.decision_digest
    }

    #[must_use]
    pub const fn executed_at(&self) -> u64 {
        self.executed_at
    }
}

/// Exact disclosure command accepted by the protected records provider.
pub struct SealedReadRecordCommand {
    authorized: Authorized<VerifiedReadRecordCommand>,
    policy: BoundedRecordApiPolicyV1,
    execution_authorization: ExecutionAuthorizationV1,
    provider_call_authorization: ProviderCallAuthorizationV1,
    decision_digest: String,
    disclosed_at: u64,
}

impl SealedReadRecordCommand {
    pub(crate) const fn new(
        authorized: Authorized<VerifiedReadRecordCommand>,
        policy: BoundedRecordApiPolicyV1,
        execution_authorization: ExecutionAuthorizationV1,
        provider_call_authorization: ProviderCallAuthorizationV1,
        decision_digest: String,
        disclosed_at: u64,
    ) -> Self {
        Self {
            authorized,
            policy,
            execution_authorization,
            provider_call_authorization,
            decision_digest,
            disclosed_at,
        }
    }

    #[must_use]
    pub fn action(&self) -> &ReadRecordV1 {
        self.authorized.command().action()
    }

    #[must_use]
    pub const fn policy(&self) -> &BoundedRecordApiPolicyV1 {
        &self.policy
    }

    #[must_use]
    pub fn lifecycle_authorization_matches(&self) -> bool {
        self.policy.digest().ok().as_deref() == Some(&self.action().policy_digest)
            && lifecycle_authorization_matches(
                self.action().digest().ok().as_deref(),
                READ_PROVIDER_CONTRACT_ID,
                &self.execution_authorization,
                &self.provider_call_authorization,
            )
    }

    #[must_use]
    pub fn decision_digest(&self) -> &str {
        &self.decision_digest
    }

    #[must_use]
    pub const fn disclosed_at(&self) -> u64 {
        self.disclosed_at
    }
}

fn lifecycle_authorization_matches(
    action_digest: Option<&str>,
    provider_contract_id: &str,
    execution: &ExecutionAuthorizationV1,
    call: &ProviderCallAuthorizationV1,
) -> bool {
    let Some(action_digest) = action_digest else {
        return false;
    };
    let Some(action_bytes) = hex::decode(action_digest)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
    else {
        return false;
    };
    execution.provider_contract_id().as_str() == provider_contract_id
        && execution.workflow_id() == call.workflow_id()
        && execution.execution_id() == call.execution_id()
        && execution.provider_request_digest() == call.provider_request_digest()
        && execution.provider_request_digest().bytes() == &action_bytes
        && call.revision() > execution.revision()
}
