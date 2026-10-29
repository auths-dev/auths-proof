//! Native side of the retained, independently implemented recipe comparison.
//! This produces verified compilation/observation facts, never provider evidence.

use super::*;
use crate::harness::authoring::tool_fixture_in_window;
use crate::recipe::ReadBack;
use crate::{ArgumentCeilingPolicy, ListedValues};

const RUN: &str = "ap074-independent-differential";

#[derive(Clone, Copy)]
enum Family {
    Airtable,
    Stripe,
}

impl Family {
    fn recipe(self) -> CompiledRecipe {
        let (source, lock) = match self {
            Self::Airtable => (
                include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json")
                    .as_slice(),
                include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json")
                    .as_slice(),
            ),
            Self::Stripe => (
                include_bytes!(
                    "../../../../qualification/simulation/live/stripe-platform/recipe.json"
                )
                .as_slice(),
                include_bytes!(
                    "../../../../qualification/simulation/live/stripe-platform/profile.lock.json"
                )
                .as_slice(),
            ),
        };
        let mut source: Value = serde_json::from_slice(source).expect("recipe");
        if matches!(self, Self::Airtable) {
            // Pure construction only: the independent reference pins this reviewed
            // base/table. These bytes never reach a provider or a credential port.
            for kind in ["write", "observation"] {
                source[kind]["path"][1]["value"] = json!("appQD3Qf0YFBCW9bV");
                source[kind]["path"][2]["value"] = json!("tblBx2jwe0IsPYRKT");
            }
        }
        CompiledRecipe::compile(&serde_json::to_vec(&source).expect("source"), lock)
            .expect("reviewed recipe")
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Airtable => "airtable-record-update-v1",
            Self::Stripe => "stripe-platform-refund-v1",
        }
    }

    fn arguments(self, recipe: &CompiledRecipe) -> Value {
        let mut arguments = json!({
            "operator_namespace": recipe.namespace().as_str(),
            "recipe_digest": recipe.digest_hex(), "operation_id": "differential-1",
        });
        match self {
            Self::Airtable => {
                arguments["record_id"] = json!("recTEST0000000001");
                arguments["replacement"] = json!("Approved");
            }
            Self::Stripe => {
                arguments["payment_intent"] = json!("pi_TEST123");
                arguments["amount"] = json!(1000);
                arguments["currency"] = json!("usd");
            }
        }
        arguments
    }

    fn resources(self) -> Value {
        match self {
            Self::Airtable => json!({
                "schema":"auths.airtable-record-qualification-resources/1", "protected_run":RUN,
                "base":"appQD3Qf0YFBCW9bV", "table":"tblBx2jwe0IsPYRKT",
                "records":[{"id":"recTEST0000000001", "run_metadata":RUN}],
            }),
            Self::Stripe => json!({
                "schema":"auths.stripe-platform-qualification-resources/1", "protected_run":RUN,
                "platform":"acct_TEST123", "payments":[{"id":"pi_TEST123",
                    "amount_received":2000, "currency":"usd", "livemode":false,
                    "run_metadata":RUN}],
            }),
        }
    }

    fn policy(self) -> Option<ArgumentCeilingPolicy> {
        matches!(self, Self::Stripe).then(|| {
            ArgumentCeilingPolicy::new("amount", 10_000, 3600, 16)
                .expect("bounded grant")
                .with_sum(
                    160_000,
                    Some(ListedValues::new("currency", &["usd", "eur"]).expect("partition")),
                )
                .expect("sum")
        })
    }
}

fn mutations(family: Family, base: &Value) -> Vec<(&'static str, &'static str, Value)> {
    let mut cases = vec![("baseline", "equal-request", base.clone())];
    let mut add = |name, contract, field: &str, value| {
        let mut arguments = base.clone();
        arguments[field] = value;
        cases.push((name, contract, arguments));
    };
    add(
        "other-operation",
        "equal-request",
        "operation_id",
        json!("differential-2"),
    );
    add(
        "wrong-namespace",
        "both-refuse",
        "operator_namespace",
        json!("other"),
    );
    add(
        "wrong-recipe",
        "both-refuse",
        "recipe_digest",
        json!("0".repeat(64)),
    );
    add("extra-field", "both-refuse", "unreviewed", json!(true));
    add("empty-operation", "both-refuse", "operation_id", json!(""));
    add(
        "long-operation",
        "both-refuse",
        "operation_id",
        json!("x".repeat(129)),
    );
    match family {
        Family::Airtable => {
            add(
                "other-value",
                "equal-request",
                "replacement",
                json!("Pending"),
            );
            add(
                "invalid-value",
                "both-refuse",
                "replacement",
                json!("Deleted"),
            );
            add(
                "wrong-value-type",
                "both-refuse",
                "replacement",
                json!(true),
            );
            add(
                "unowned-resource",
                "reference-pool-refuses",
                "record_id",
                json!("recOTHER000000001"),
            );
        }
        Family::Stripe => {
            add("minimum-amount", "equal-request", "amount", json!(1));
            add("maximum-amount", "equal-request", "amount", json!(10_000));
            add("other-currency", "equal-request", "currency", json!("eur"));
            add("zero-amount", "both-refuse", "amount", json!(0));
            add("negative-amount", "both-refuse", "amount", json!(-1));
            add("boolean-amount", "both-refuse", "amount", json!(true));
            add("over-grant-ceiling", "both-refuse", "amount", json!(10_001));
            add(
                "unowned-resource",
                "reference-pool-refuses",
                "payment_intent",
                json!("pi_OTHER"),
            );
        }
    }
    let mut missing = base.clone();
    missing
        .as_object_mut()
        .expect("object")
        .remove("operation_id");
    cases.push(("missing-operation", "both-refuse", missing));
    cases
}

fn request_json(request: &crate::ClosedProviderRequest) -> Value {
    json!({"method":request.method().as_str(), "url":request.url(),
        "content_type":request.content_type(),
        "body":std::str::from_utf8(request.body()).expect("body"),
        "headers":request.headers().iter().map(|h| [h.name(), h.value()]).collect::<Vec<_>>(),
        "idempotency_key":request.idempotency_key()})
}

fn recovery_json(recipe: &CompiledRecipe) -> Value {
    use crate::{LostClaimReentry, RecoveryClass, StateObservation, UnknownResolution};
    let capability = recipe.recovery().expect("mutation capability");
    let locator = |value| match value {
        StateObservation::None => "none",
        StateObservation::VerifiedLocator => "verified",
        StateObservation::ResponseLocator => "response",
    };
    let class = match capability.class {
        RecoveryClass::Linked => "linked",
        RecoveryClass::LinkedAfterResponse => "linked-after-response",
        RecoveryClass::Observed => "observed",
        RecoveryClass::Recorded => "recorded",
    };
    let retention = match capability.lost_claim_reentry {
        LostClaimReentry::None => None,
        LostClaimReentry::Declared {
            retention_seconds, ..
        } => Some(retention_seconds),
    };
    json!({"class":class, "state_locator":locator(capability.state_observation),
        "provider_link":locator(capability.provider_link),
        "unknown_reobservation":matches!(capability.unknown_resolution, UnknownResolution::GatewayReobservation),
        "declared_idempotency_retention_seconds":retention,
        "pre_entry_reread":capability.pre_entry_reread,
        "write_is_conditional":capability.write_is_conditional})
}

fn response_cases(family: Family, request: &crate::ClosedProviderRequest) -> Vec<Value> {
    let echo = request.echo_token().expect("declared echo");
    let original = match family {
        Family::Airtable => json!({"id":"recTEST0000000001", "fields":{
            "DemoStatus":"Approved", "auths_echo":echo}}),
        Family::Stripe => json!({"id":"re_TEST123", "object":"refund", "livemode":false,
            "payment_intent":"pi_TEST123", "amount":1000, "currency":"usd",
            "status":"succeeded", "metadata":{"auths_echo":echo}}),
    };
    let template = request.observation_template().expect("template");
    let raw = serde_json::to_vec(&original).expect("response");
    let locator = template.extract_locator(&raw);
    let observation = template
        .request(locator.as_ref())
        .expect("closed observation");
    let mut inputs = vec![("exact", original.clone())];
    let (value_pointer, echo_pointer) = match family {
        Family::Airtable => ("/fields/DemoStatus", "/fields/auths_echo"),
        Family::Stripe => ("/amount", "/metadata/auths_echo"),
    };
    for (name, pointer, replacement) in [
        ("wrong-value", value_pointer, json!(0)),
        ("wrong-echo", echo_pointer, json!("unrelated")),
        ("null-echo", echo_pointer, Value::Null),
        ("different-resource", "/id", json!("re_OTHER123")),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).expect("field") = replacement;
        inputs.push((name, changed));
    }
    if matches!(family, Family::Stripe) {
        for (name, field, value) in [
            ("pending-refund", "status", json!("pending")),
            ("other-payment", "payment_intent", json!("pi_OTHER")),
            ("other-currency", "currency", json!("eur")),
            ("live-refund", "livemode", json!(true)),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            inputs.push((name, changed));
        }
    }
    let mut inputs: Vec<_> = inputs
        .into_iter()
        .map(|(name, value)| (name, serde_json::to_string(&value).expect("response JSON")))
        .collect();
    inputs.extend([
        (
            "duplicate-member",
            "{\"id\":\"one\",\"id\":\"two\"}".to_owned(),
        ),
        ("malformed", "{".to_owned()),
        ("nonfinite", "{\"amount\":NaN}".to_owned()),
    ]);
    // Vary only trailing whitespace on a complete valid response, so the
    // negative boundary cannot also be explained by malformed JSON.
    let exact = serde_json::to_string(&original).expect("complete response");
    for (name, length) in [
        ("at-limit", observation.maximum_response_bytes()),
        ("over-limit", observation.maximum_response_bytes() + 1),
        ("over-reference-limit", 65_537),
    ] {
        assert!(exact.len() < length);
        let mut response = exact.clone();
        response.extend(std::iter::repeat_n(' ', length - exact.len()));
        inputs.push((name, response));
    }
    inputs
        .into_iter()
        .map(|(name, raw)| {
            let native = match observation.read_back(Some(echo), raw.as_bytes()) {
                Some(ReadBack::EchoMatched) => "echo-linked",
                Some(ReadBack::EchoMismatch) => "echo-mismatch",
                Some(ReadBack::Value { matched: true }) => "state-match",
                Some(ReadBack::Value { matched: false }) => "state-mismatch",
                None => "unavailable",
            };
            let response = raw.trim_end_matches(' ');
            json!({"name":name, "response":response,
                "trailing_space_bytes":raw.len() - response.len(),
                "native_maximum_response_bytes":observation.maximum_response_bytes(),
                "native":native})
        })
        .collect()
}

fn family_corpus(family: Family) -> Value {
    let recipe = family.recipe();
    let key = SigningKey::from_bytes(&[29; 32]);
    let policy = EffectPolicy::new("differential".to_owned(), 1, key.verifying_key().to_bytes())
        .expect("effect policy");
    let connection = connection(&recipe);
    let ceiling = family.policy();
    let mut cases = Vec::new();
    let mut observations = Value::Null;
    let mut recovery = Value::Null;
    for (name, contract, arguments) in mutations(family, &family.arguments(&recipe)) {
        let call = McpToolCall::new(
            recipe.review().service(),
            recipe.review().tool(),
            arguments.as_object().expect("arguments").clone(),
        )
        .expect("call");
        let signed = tool_fixture_in_window(&call, NOW, NOW - 3600, NOW + 3600, ceiling.as_ref())
            .expect("real signed native input");
        let context = auths_codec::decode_verifier_context(&signed.context).expect("trust");
        let installed = policy.installation(
            &recipe,
            &context,
            &connection,
            crate::QualificationPolicy::Optional,
            [12; 32],
        );
        let result = compile_mutation_effect(&installed, NOW, &signed.proof, &signed.action);
        assert_eq!(
            result.is_ok(),
            contract != "both-refuse",
            "{} {name}",
            family.name()
        );
        let mut row = json!({"name":name, "contract":contract, "arguments":arguments,
            "native_accepted":result.is_ok()});
        match result {
            Ok(effect) => {
                let request = effect.private_request().expect("mutation request");
                row["action_commitment"] = json!(hex::encode(request.action_commitment()));
                row["effect_id"] = json!(hex::encode(effect.binding().id().as_bytes()));
                row["request"] = request_json(request);
                // Approval signs the same immutable binding; no admission,
                // credential or transport exists in this corpus.
                let approval = effect.approval_request(NOW, NOW + 300).expect("request");
                let signature = key
                    .sign(&approval.signing_message().expect("message"))
                    .to_bytes();
                if name == "baseline" {
                    observations = json!(response_cases(family, request));
                    let template = request.observation_template().expect("observation");
                    let locator = template.extract_locator(b"{\"id\":\"re_TEST123\"}");
                    let separator = template.extract_locator(b"{\"id\":\"../other\"}");
                    recovery = json!({
                        "without_write_response_url":template.request(None).map(|r| r.url().to_owned()),
                        "with_write_response_url":template.request(locator.as_ref()).map(|r| r.url().to_owned()),
                        "dot_segment_response_locator_refused":template.extract_locator(b"{\"id\":\"..\"}").is_none(),
                        "separator_response_locator_url":separator.as_ref().and_then(|value| template.request(Some(value))).map(|r| r.url().to_owned()),
                        "capability":recovery_json(&recipe),
                    });
                }
                effect
                    .approve(
                        approval.with_signature(signature),
                        &key.verifying_key().to_bytes(),
                        NOW,
                    )
                    .expect("native exact approval")
                    .validate_for_entry(&installed, NOW)
                    .expect("same verified effect");
            }
            Err(error) => {
                row["native_result"] = serde_json::to_value(error).expect("native refusal")
            }
        }
        cases.push(row);
    }
    json!({"family":family.name(), "recipe_digest":recipe.digest_hex(),
        "resources":family.resources(), "cases":cases, "observations":observations,
        "recovery":recovery})
}

#[test]
fn native_independent_mutation_differential_fixture_is_current() {
    let corpus = json!({"schema":"auths.ap074-native-mutation-differential/1",
        "scope":"native signed authorization, bound effect, approval, closed request and response classification; no admission or I/O",
        "families":[family_corpus(Family::Airtable), family_corpus(Family::Stripe)]});
    let mut bytes = serde_json::to_vec_pretty(&corpus).expect("corpus");
    bytes.push(b'\n');
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/native-independent-mutation-differential.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("write corpus");
    }
    assert_eq!(std::fs::read(path).expect("retained corpus"), bytes);
}
