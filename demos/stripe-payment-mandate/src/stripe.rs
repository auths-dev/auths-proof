use std::{
    collections::BTreeSet,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use auths_stripe::{
    CredentialProvider, CustomerId, MandateConnectAccount, MandateId,
    PaymentMandateCapabilityRecord, PaymentMandateCredential, PaymentMandateCredentialScope,
    PaymentMandateEffect, PaymentMandateEvidenceInput, PaymentMandateEvidenceV1,
    PaymentMandateGateway, PaymentMandateProviderProjection, PaymentMandateReconciliationOutcome,
    PaymentMethodId, PortError, SetupAttemptId, SetupIntentId, StripeAccountId,
    VerifiedPaymentMandateCommand,
    canonical::{canonical_json, sha256},
    merchant::MerchantConnectAccount,
};
use auths_stripe_payment_demo_common::StripeHttp;
use serde::Serialize;
use serde_json::Value;

/// Repository-owned Customer and attached test `PaymentMethod`.
pub struct MandateFixture {
    pub customer_id: CustomerId,
    pub payment_method_id: PaymentMethodId,
    pub evidence: PaymentMandateEvidenceV1,
}

/// Public, secret-free adapter counters.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct EnvironmentDiagnostics {
    pub credential_requests: u64,
    pub provider_calls: u64,
}

/// Complete demo environment boundary.
pub trait DemoPaymentMandateEnvironment:
    PaymentMandateGateway + CredentialProvider<PaymentMandateCredentialScope> + Send + Sync
{
    /// Creates repository-owned synthetic evidence.
    ///
    /// # Errors
    ///
    /// Returns a closed provider/configuration error.
    fn seed_fixture(&self, workflow_id: &str, now: u64) -> Result<MandateFixture, PortError>;
    /// Makes one successful provider delivery appear ambiguous to the service.
    ///
    /// # Errors
    ///
    /// Returns a closed persistence error.
    fn arm_ambiguous_once(&self, workflow_id: &str) -> Result<(), PortError>;
    fn account_id(&self) -> &StripeAccountId;
    fn api_version(&self) -> &str;
    fn diagnostics(&self) -> EnvironmentDiagnostics;
}

/// Real Stripe test-mode `SetupIntent` adapter.
pub struct LivePaymentMandateEnvironment {
    http: StripeHttp<PaymentMandateCredentialScope>,
    credential_requests: AtomicU64,
    provider_calls: AtomicU64,
    ambiguous_once: Mutex<BTreeSet<String>>,
}

impl LivePaymentMandateEnvironment {
    /// Loads test-only fixture and mandate-scoped credentials.
    ///
    /// # Errors
    ///
    /// Rejects missing or unsafe environment/provider configuration.
    pub fn from_environment() -> Result<Self, PortError> {
        Ok(Self {
            http: StripeHttp::from_environment("AUTHS_STRIPE_MANDATE_SECRET_KEY")?,
            credential_requests: AtomicU64::new(0),
            provider_calls: AtomicU64::new(0),
            ambiguous_once: Mutex::new(BTreeSet::new()),
        })
    }

    fn evidence(
        &self,
        customer_id: &CustomerId,
        payment_method_id: &PaymentMethodId,
        credential: Option<&PaymentMandateCredential>,
        now: u64,
    ) -> Result<PaymentMandateEvidenceV1, PortError> {
        let connect = MerchantConnectAccount::Platform;
        let customer_path = format!("/v1/customers/{customer_id}");
        let method_path = format!("/v1/payment_methods/{payment_method_id}");
        let (customer, method) = if let Some(secret) = credential {
            (
                self.http.protected_get(&customer_path, secret, &connect)?,
                self.http.protected_get(&method_path, secret, &connect)?,
            )
        } else {
            (
                self.http.fixture_get(&customer_path, &connect)?,
                self.http.fixture_get(&method_path, &connect)?,
            )
        };
        let observed_customer =
            CustomerId::parse(string(&customer.value, "id")?).map_err(|_| PortError::Malformed)?;
        let method_id = PaymentMethodId::parse(string(&method.value, "id")?)
            .map_err(|_| PortError::Malformed)?;
        let owner = PaymentMethodId::parse(method_id.to_string())
            .map_err(|_| PortError::Malformed)
            .and_then(|_| {
                CustomerId::parse(string(&method.value, "customer")?)
                    .map_err(|_| PortError::Malformed)
            })?;
        let method_type = string(&method.value, "type")?.to_owned();
        let response_commitment = sha256(
            [
                canonical_json(&customer.value).map_err(|_| PortError::Malformed)?,
                canonical_json(&method.value).map_err(|_| PortError::Malformed)?,
            ]
            .concat()
            .as_slice(),
        );
        PaymentMandateEvidenceV1::new(PaymentMandateEvidenceInput {
            stripe_account_id: self.http.account_id().clone(),
            connect_account: MandateConnectAccount::Platform,
            customer_id: observed_customer,
            customer_exists: !bool_field(&customer.value, "deleted").unwrap_or(false),
            payment_method_id: method_id,
            payment_method_type: method_type,
            payment_method_customer_id: owner,
            existing_setup_intent_ids: Vec::new(),
            active_mandate_count: 0,
            duplicate_scope_exists: false,
            ambiguous_setup_exists: false,
            stripe_api_version: self.http.api_version().into(),
            livemode: bool_field(&method.value, "livemode").ok_or(PortError::Malformed)?,
            observed_at: now,
            source: "stripe-customer-payment-method-read".into(),
            response_commitment,
        })
        .map_err(|_| PortError::Malformed)
    }

    fn retrieve(
        &self,
        id: &SetupIntentId,
        credential: &PaymentMandateCredential,
        now: u64,
    ) -> Result<PaymentMandateProviderProjection, PortError> {
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        let response = self.http.protected_get(
            &format!("/v1/setup_intents/{id}?expand[]=latest_attempt"),
            credential,
            &MerchantConnectAccount::Platform,
        )?;
        projection(&response.value, response.request_id, now, "retrieve")
    }
}

impl CredentialProvider<PaymentMandateCredentialScope> for LivePaymentMandateEnvironment {
    fn credential(&self, account: &StripeAccountId) -> Result<PaymentMandateCredential, PortError> {
        self.credential_requests.fetch_add(1, Ordering::Relaxed);
        self.http.credential(account)
    }
}

impl DemoPaymentMandateEnvironment for LivePaymentMandateEnvironment {
    fn seed_fixture(&self, workflow_id: &str, now: u64) -> Result<MandateFixture, PortError> {
        let connect = MerchantConnectAccount::Platform;
        let customer = self.http.fixture_post(
            "/v1/customers",
            &[
                ("description".into(), "Auths bounded mandate demo".into()),
                ("metadata[auths_fixture]".into(), workflow_id.into()),
            ],
            &format!("auths-mandate-customer-{workflow_id}"),
            &connect,
        )?;
        let customer_id =
            CustomerId::parse(string(&customer.value, "id")?).map_err(|_| PortError::Malformed)?;
        let method = self.http.fixture_post(
            "/v1/payment_methods",
            &[
                ("type".into(), "card".into()),
                ("card[token]".into(), "tok_visa".into()),
            ],
            &format!("auths-mandate-method-{workflow_id}"),
            &connect,
        )?;
        let payment_method_id = PaymentMethodId::parse(string(&method.value, "id")?)
            .map_err(|_| PortError::Malformed)?;
        self.http.fixture_post(
            &format!("/v1/payment_methods/{payment_method_id}/attach"),
            &[("customer".into(), customer_id.to_string())],
            &format!("auths-mandate-attach-{workflow_id}"),
            &connect,
        )?;
        let evidence = self.evidence(&customer_id, &payment_method_id, None, now)?;
        Ok(MandateFixture {
            customer_id,
            payment_method_id,
            evidence,
        })
    }

    fn arm_ambiguous_once(&self, workflow_id: &str) -> Result<(), PortError> {
        self.ambiguous_once
            .lock()
            .map_err(|_| PortError::Persistence)?
            .insert(workflow_id.into());
        Ok(())
    }

    fn account_id(&self) -> &StripeAccountId {
        self.http.account_id()
    }
    fn api_version(&self) -> &str {
        self.http.api_version()
    }

    fn diagnostics(&self) -> EnvironmentDiagnostics {
        EnvironmentDiagnostics {
            credential_requests: self.credential_requests.load(Ordering::Relaxed),
            provider_calls: self.provider_calls.load(Ordering::Relaxed),
        }
    }
}

impl PaymentMandateGateway for LivePaymentMandateEnvironment {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedPaymentMandateCommand,
        credential: &PaymentMandateCredential,
        now: u64,
    ) -> Result<PaymentMandateEvidenceV1, PortError> {
        self.evidence(
            command.action().customer_id(),
            command.action().payment_method_id(),
            Some(credential),
            now,
        )
    }

    fn create_and_confirm(
        &self,
        command: &VerifiedPaymentMandateCommand,
        credential: &PaymentMandateCredential,
        now: u64,
    ) -> Result<PaymentMandateEffect, PortError> {
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        let usage = match command.action().usage() {
            auths_stripe::MandateUsage::OnSession => "on_session",
            auths_stripe::MandateUsage::OffSession => "off_session",
        };
        let parameters = vec![
            (
                "customer".into(),
                command.action().customer_id().to_string(),
            ),
            (
                "payment_method".into(),
                command.action().payment_method_id().to_string(),
            ),
            ("payment_method_types[]".into(), "card".into()),
            ("usage".into(), usage.into()),
            ("confirm".into(), "true".into()),
            ("expand[]".into(), "latest_attempt".into()),
            (
                "metadata[auths_profile]".into(),
                command.action().profile().into(),
            ),
            (
                "metadata[auths_workflow_id]".into(),
                command.workflow_id().into(),
            ),
            (
                "metadata[auths_capability_id]".into(),
                command.capability().capability_id().to_string(),
            ),
        ];
        let response = match self.http.protected_post(
            "/v1/setup_intents",
            &parameters,
            command.idempotency_key(),
            credential,
            &MerchantConnectAccount::Platform,
        ) {
            Ok(response) => response,
            Err(PortError::Execution) => {
                return Ok(PaymentMandateEffect::KnownFailure {
                    code: "payment-mandate-provider-failed".into(),
                    projection: None,
                });
            }
            Err(PortError::OutcomeUnknown) => {
                return Ok(PaymentMandateEffect::OutcomeUnknown(None));
            }
            Err(error) => return Err(error),
        };
        let projection = projection(&response.value, response.request_id, now, "create-confirm")?;
        let ambiguous = self
            .ambiguous_once
            .lock()
            .map_err(|_| PortError::Persistence)?
            .remove(command.workflow_id());
        if ambiguous {
            return Ok(PaymentMandateEffect::OutcomeUnknown(None));
        }
        Ok(classify(projection))
    }

    fn reconcile(
        &self,
        capability: &PaymentMandateCapabilityRecord,
        credential: &PaymentMandateCredential,
        now: u64,
    ) -> Result<PaymentMandateReconciliationOutcome, PortError> {
        let projection = if let Some(provider) = capability.provider() {
            self.retrieve(&provider.setup_intent_id, credential, now)?
        } else {
            self.provider_calls.fetch_add(1, Ordering::Relaxed);
            let response = self.http.protected_get(
                &format!(
                    "/v1/setup_intents?customer={}&limit=100&expand[]=data.latest_attempt",
                    capability.customer_id()
                ),
                credential,
                &MerchantConnectAccount::Platform,
            )?;
            let value = setup_intent_for_workflow(&response.value, capability.workflow_id())?;
            projection(value, response.request_id, now, "reconcile-workflow-search")?
        };
        Ok(match projection.status.as_str() {
            "succeeded" => PaymentMandateReconciliationOutcome::Succeeded(projection),
            "requires_action" | "requires_confirmation" => {
                PaymentMandateReconciliationOutcome::CustomerActionRequired(projection)
            }
            "canceled" | "requires_payment_method" => {
                PaymentMandateReconciliationOutcome::KnownFailure(projection)
            }
            _ => PaymentMandateReconciliationOutcome::StillUnknown(Some(projection)),
        })
    }
}

fn classify(projection: PaymentMandateProviderProjection) -> PaymentMandateEffect {
    match projection.status.as_str() {
        "succeeded" => PaymentMandateEffect::Succeeded(projection),
        "requires_action" | "requires_confirmation" => {
            PaymentMandateEffect::CustomerActionRequired(projection)
        }
        "processing" => PaymentMandateEffect::Processing(projection),
        _ => PaymentMandateEffect::KnownFailure {
            code: "payment-mandate-provider-failed".into(),
            projection: Some(projection),
        },
    }
}

fn projection(
    value: &Value,
    request_id: Option<String>,
    now: u64,
    source: &str,
) -> Result<PaymentMandateProviderProjection, PortError> {
    let setup_intent_id =
        SetupIntentId::parse(string(value, "id")?).map_err(|_| PortError::Malformed)?;
    let customer_id =
        CustomerId::parse(id_string(value, "customer")?).map_err(|_| PortError::Malformed)?;
    let payment_method_id = PaymentMethodId::parse(id_string(value, "payment_method")?)
        .map_err(|_| PortError::Malformed)?;
    let latest_setup_attempt_id = optional_id_string(value, "latest_attempt")
        .map(SetupAttemptId::parse)
        .transpose()
        .map_err(|_| PortError::Malformed)?;
    let mandate_id = optional_id_string(value, "mandate")
        .map(MandateId::parse)
        .transpose()
        .map_err(|_| PortError::Malformed)?;
    Ok(PaymentMandateProviderProjection {
        setup_intent_id,
        latest_setup_attempt_id,
        mandate_id,
        customer_id,
        payment_method_id,
        usage: string(value, "usage")?.into(),
        status: string(value, "status")?.into(),
        livemode: bool_field(value, "livemode").ok_or(PortError::Malformed)?,
        stripe_request_id: request_id,
        response_digest: sha256(&canonical_json(value).map_err(|_| PortError::Malformed)?),
        observed_at: now,
        source: source.into(),
    })
}

fn setup_intent_for_workflow<'a>(
    response: &'a Value,
    workflow_id: &str,
) -> Result<&'a Value, PortError> {
    let matches = response
        .get("data")
        .and_then(Value::as_array)
        .ok_or(PortError::Malformed)?
        .iter()
        .filter(|setup_intent| {
            setup_intent
                .get("metadata")
                .and_then(|metadata| metadata.get("auths_workflow_id"))
                .and_then(Value::as_str)
                == Some(workflow_id)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [only] => Ok(*only),
        [] => Err(PortError::EvidenceUnavailable),
        _ => Err(PortError::Malformed),
    }
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, PortError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(PortError::Malformed)
}

fn bool_field(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn id_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, PortError> {
    optional_id_string(value, key).ok_or(PortError::Malformed)
}

fn optional_id_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(|field| {
        field
            .as_str()
            .or_else(|| field.get("id").and_then(Value::as_str))
    })
}

#[cfg(test)]
mod tests {
    use super::setup_intent_for_workflow;
    use auths_stripe::PortError;
    use serde_json::json;

    #[test]
    fn workflow_search_requires_exactly_one_setup_intent() {
        let response = json!({
            "data": [
                {"id": "seti_other", "metadata": {"auths_workflow_id": "other"}},
                {"id": "seti_match", "metadata": {"auths_workflow_id": "wanted"}}
            ]
        });
        assert_eq!(
            setup_intent_for_workflow(&response, "wanted").unwrap()["id"],
            "seti_match"
        );
        assert!(matches!(
            setup_intent_for_workflow(&response, "missing"),
            Err(PortError::EvidenceUnavailable)
        ));

        let duplicate = json!({
            "data": [
                {"id": "seti_one", "metadata": {"auths_workflow_id": "wanted"}},
                {"id": "seti_two", "metadata": {"auths_workflow_id": "wanted"}}
            ]
        });
        assert!(matches!(
            setup_intent_for_workflow(&duplicate, "wanted"),
            Err(PortError::Malformed)
        ));
    }
}
