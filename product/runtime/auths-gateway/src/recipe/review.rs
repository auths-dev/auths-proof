//! Operator review of a compiled recipe: `auths.gateway-recipe-review/2`.
//!
//! The review keeps every field of `/1` and adds each declaration of
//! recipe source `/2` with the disclosure that says what the gateway can and
//! cannot establish about it, plus the derived recovery capability.

use super::recovery::{
    IdempotencyKind, LostClaimReentry, RecoveryCapability, RecoveryClass, StateObservation,
    UnknownResolution,
};
use super::source::{EchoPlacement, IdempotencySource, PathSegment};
use super::{CompiledRecipe, CredentialRequirement, MAX_BODY_BYTES, WriteMethod, provider_header};
use serde_json::{Value, json};

/// The review schema both review commands print.
pub const RECIPE_REVIEW_SCHEMA: &str = "auths.gateway-recipe-review/2";
/// The schema of the derived recovery capability.
pub const RECOVERY_CAPABILITY_SCHEMA: &str = "auths.gateway-recovery-capability/1";

const ECHO_DISCLOSURE: &str = "the gateway writes a token derived from the authorized action into this provider field; the provider stores it and anyone who can read the record can read it; do not declare echo when the observation response may contain secrets";
const PRECONDITION_DISCLOSURE: &str = "these arguments are never sent to the provider; only observation requirements in the proof's grants compare them, so a grant without such a requirement leaves them unchecked; the read-back subject argument must name exactly the record this request observes";
const IDEMPOTENCY_DISCLOSURE: &str =
    "declared by the recipe author; the gateway cannot verify that the provider honors it";
const PRE_ENTRY_DISCLOSURE: &str =
    "read after the credential lease and before the write; the write is not conditional";
const GUARD_DISCLOSURE: &str =
    "run at onboarding and at every lease; a denied read shows only the refusals observed";
const ACCOUNT_SCOPE_DISCLOSURE: &str = "sent only with a value the grant lists";

/// Operator review facts that are safe to show without a credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipeReview {
    service: String,
    tool: String,
    origin: String,
    method: WriteMethod,
    path: Vec<String>,
    credential: CredentialRequirement,
    maximum_body_bytes: usize,
    has_observation: bool,
    sends_idempotency_key: bool,
    echo: Option<RecipeEchoReview>,
    preconditions: Option<RecipePreconditionReview>,
    recovery: RecoveryCapability,
}

/// Operator review of the verified arguments the request never renders.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipePreconditionReview {
    read_back_subject: Option<String>,
    verified: Vec<String>,
}

impl RecipePreconditionReview {
    /// Returns the argument that must name the observed record, if declared.
    #[must_use]
    pub fn read_back_subject(&self) -> Option<&str> {
        self.read_back_subject.as_deref()
    }
    /// Returns the arguments compared only by observation requirements.
    #[must_use]
    pub fn verified(&self) -> &[String] {
        &self.verified
    }
    /// States that these arguments reach no provider and who checks them.
    #[must_use]
    pub const fn disclosure(&self) -> &'static str {
        PRECONDITION_DISCLOSURE
    }
}

/// Operator review of the provider field that will carry the echo token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipeEchoReview {
    kind: &'static str,
    write: String,
    observe: String,
}

impl RecipeEchoReview {
    /// Returns `json-pointer` or `form-field`.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        self.kind
    }
    /// Returns the JSON pointer or form field name that receives the token.
    #[must_use]
    pub fn write(&self) -> &str {
        &self.write
    }
    /// Returns the JSON pointer read back from the observation response.
    #[must_use]
    pub fn observe(&self) -> &str {
        &self.observe
    }
    /// States where the token is stored and who can read it.
    #[must_use]
    pub const fn disclosure(&self) -> &'static str {
        ECHO_DISCLOSURE
    }
}

impl RecipeReview {
    /// Returns the exact MCP service.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }
    /// Returns the versioned MCP tool.
    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }
    /// Returns the pinned public HTTPS origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
    /// Returns the fixed write method.
    #[must_use]
    pub const fn method(&self) -> WriteMethod {
        self.method
    }
    /// Returns fixed and typed path segments for operator review.
    #[must_use]
    pub fn path(&self) -> &[String] {
        &self.path
    }
    /// Returns the credential-header requirement, never the secret.
    #[must_use]
    pub const fn credential(&self) -> &CredentialRequirement {
        &self.credential
    }
    /// Returns the maximum body bytes enforced by the compiler.
    #[must_use]
    pub const fn maximum_body_bytes(&self) -> usize {
        self.maximum_body_bytes
    }
    /// Reports whether a separate read-only observation is declared.
    #[must_use]
    pub const fn has_observation(&self) -> bool {
        self.has_observation
    }
    /// Reports whether the write sends the `Idempotency-Key` the gateway
    /// derives from the verified namespace and logical operation ID. No read
    /// sends it.
    #[must_use]
    pub const fn sends_idempotency_key(&self) -> bool {
        self.sends_idempotency_key
    }
    /// Returns the declared echo field, if any.
    #[must_use]
    pub const fn echo(&self) -> Option<&RecipeEchoReview> {
        self.echo.as_ref()
    }
    /// Returns the declared precondition arguments, if any.
    #[must_use]
    pub const fn preconditions(&self) -> Option<&RecipePreconditionReview> {
        self.preconditions.as_ref()
    }
    /// Returns what the recipe can prove after an ambiguous write.
    #[must_use]
    pub const fn recovery(&self) -> RecoveryCapability {
        self.recovery
    }
}

fn segment_review(segment: &PathSegment) -> Value {
    match segment {
        PathSegment::Fixed { value } => json!(value),
        PathSegment::Field { name } => json!(format!("<{name}>")),
        PathSegment::ResponseField { pointer, max_bytes } => {
            json!(format!("<response:{pointer}:{max_bytes}>"))
        }
        PathSegment::Echo => json!("<echo>"),
    }
}

fn path_review(path: &[PathSegment]) -> Value {
    Value::Array(path.iter().map(segment_review).collect())
}

const fn observation_name(observation: StateObservation) -> &'static str {
    match observation {
        StateObservation::None => "none",
        StateObservation::VerifiedLocator => "verified-locator",
        StateObservation::ResponseLocator => "response-locator",
    }
}

const fn class_name(class: RecoveryClass) -> &'static str {
    match class {
        RecoveryClass::Linked => "linked",
        RecoveryClass::LinkedAfterResponse => "linked-after-response",
        RecoveryClass::Observed => "observed",
        RecoveryClass::Recorded => "recorded",
    }
}

const fn idempotency_kind_name(kind: IdempotencyKind) -> &'static str {
    match kind {
        IdempotencyKind::DerivedHeader => "derived-header",
        IdempotencyKind::OperationIdField => "operation-id-field",
    }
}

/// Renders `auths.gateway-recovery-capability/1`.
#[must_use]
pub(crate) fn recovery_document(capability: &RecoveryCapability) -> Value {
    let reentry = match capability.lost_claim_reentry {
        LostClaimReentry::None => json!({"deduplication": "none"}),
        LostClaimReentry::Declared {
            kind,
            retention_seconds,
        } => json!({
            "deduplication": "declared",
            "kind": idempotency_kind_name(kind),
            "retention_seconds": retention_seconds,
        }),
    };
    json!({
        "schema": RECOVERY_CAPABILITY_SCHEMA,
        "class": class_name(capability.class),
        "state_observation": observation_name(capability.state_observation),
        "provider_link": observation_name(capability.provider_link),
        "unknown_resolution": match capability.unknown_resolution {
            UnknownResolution::GatewayReobservation => "gateway-reobservation",
            UnknownResolution::None => "none",
        },
        "lost_claim_reentry": reentry,
        "pre_entry_reread": capability.pre_entry_reread,
        "write_is_conditional": capability.write_is_conditional,
    })
}

impl CompiledRecipe {
    /// Returns a bounded, secret-free operator review projection.
    #[must_use]
    pub fn review(&self) -> RecipeReview {
        let source = &self.source;
        RecipeReview {
            service: source.service.clone(),
            tool: source.tool.clone(),
            origin: source.origin.clone(),
            method: source.write.method,
            path: source
                .write
                .path
                .iter()
                .map(|segment| match segment_review(segment) {
                    Value::String(text) => text,
                    _ => String::new(),
                })
                .collect(),
            credential: super::credential_requirement(&source.credential),
            maximum_body_bytes: MAX_BODY_BYTES,
            has_observation: source.observation.is_some(),
            sends_idempotency_key: matches!(
                source.write.idempotency,
                Some(IdempotencySource::DerivedHeader { .. })
            ),
            echo: source.echo.as_ref().map(|echo| {
                let (kind, write) = match &echo.write {
                    EchoPlacement::JsonPointer { pointer } => ("json-pointer", pointer.clone()),
                    EchoPlacement::FormField { name } => ("form-field", name.clone()),
                };
                RecipeEchoReview {
                    kind,
                    write,
                    observe: echo.observe.clone(),
                }
            }),
            preconditions: source.preconditions.as_ref().map(|preconditions| {
                RecipePreconditionReview {
                    read_back_subject: preconditions.read_back_subject.clone(),
                    verified: preconditions.verified.clone(),
                }
            }),
            recovery: self.recovery(),
        }
    }

    /// Renders `auths.gateway-recipe-review/2`, the document both
    /// `auths-gateway review` and `auths-node gateway recipe check` print.
    /// Optional declarations the recipe omits are `null`.
    #[must_use]
    pub fn review_document(&self) -> Value {
        let review = self.review();
        let source = &self.source;
        let mut document = json!({
            "schema": RECIPE_REVIEW_SCHEMA,
            "digest": self.digest_hex(),
            "operator_namespace": self.namespace.as_str(),
            "service": review.service(),
            "tool": review.tool(),
            "origin": review.origin(),
            "method": review.method().as_str(),
            "path": review.path(),
            "credential": review.credential(),
            "maximum_body_bytes": review.maximum_body_bytes(),
            "has_observation": review.has_observation(),
            "sends_idempotency_key": review.sends_idempotency_key(),
            "echo": review.echo().map(|echo| json!({
                "kind": echo.kind(),
                "write": echo.write(),
                "observe": echo.observe(),
                "disclosure": echo.disclosure(),
            })),
            "preconditions": review.preconditions().map(|preconditions| json!({
                "read_back_subject": preconditions.read_back_subject(),
                "verified": preconditions.verified(),
                "disclosure": preconditions.disclosure(),
            })),
            "recovery": recovery_document(&review.recovery()),
            "write_is_conditional": false,
        });
        document["provider_headers"] =
            source
                .provider_headers
                .as_ref()
                .map_or(Value::Null, |headers| {
                    Value::Object(
                        headers
                            .iter()
                            .map(|(name, value)| {
                                let response = provider_header(name)
                                    .map_or("not-checked", |entry| entry.response.as_str());
                                (name.clone(), json!({"value": value, "response": response}))
                            })
                            .collect(),
                    )
                });
        document["credential_guard"] = self.guard_review();
        document["idempotency"] =
            source
                .write
                .idempotency
                .as_ref()
                .map_or(Value::Null, |idempotency| {
                    let mut value = json!({
                        "kind": match idempotency {
                            IdempotencySource::DerivedHeader { .. } => "derived-header",
                            IdempotencySource::OperationIdField { .. } => "operation-id-field",
                        },
                        "retention_seconds": idempotency.retention_seconds(),
                        "disclosure": IDEMPOTENCY_DISCLOSURE,
                    });
                    if let IdempotencySource::OperationIdField { location, .. } = idempotency {
                        value["location"] = serde_json::to_value(location).unwrap_or(Value::Null);
                    }
                    value
                });
        document["observation"] = source
            .observation
            .as_ref()
            .map_or(Value::Null, |observation| {
                json!({
                    "locator": observation_name(review.recovery().state_observation),
                    "path": path_review(&observation.path),
                    "json_pointer": observation.json_pointer,
                    "expected_field": observation.expected_field,
                    "maximum_response_bytes": observation.maximum_response_bytes,
                })
            });
        document["pre_entry"] = source.pre_entry.as_ref().map_or(Value::Null, |pre_entry| {
            json!({
                "path": path_review(&pre_entry.path),
                "pointers": pre_entry.pointers,
                "maximum_response_bytes": pre_entry.maximum_response_bytes,
                "disclosure": PRE_ENTRY_DISCLOSURE,
            })
        });
        document["account_scope"] = source.account_scope.as_ref().map_or(Value::Null, |scope| {
            json!({
                "header": scope.header,
                "field": scope.field,
                "disclosure": ACCOUNT_SCOPE_DISCLOSURE,
            })
        });
        document["relative_ceiling"] = self.relative_ceiling_review();
        document["bounds"] = source.bounds.as_ref().map_or(Value::Null, |bounds| {
            json!({"sum": bounds.sum.as_ref().map(|sum| json!({
                "argument": sum.argument,
                "partition": sum.partition,
            }))})
        });
        document
    }

    fn guard_review(&self) -> Value {
        let Some(guard) = self.source.credential.guard() else {
            return Value::Null;
        };
        json!({
            "prefixes": guard.prefixes,
            "probe": guard.probe.as_ref().map(|probe| json!({
                "path": path_review(&probe.path),
                "json_pointer": probe.json_pointer,
                "equals": probe.equals,
                "maximum_response_bytes": probe.maximum_response_bytes,
            })),
            "account": guard.account.as_ref().map(|account| json!({
                "path": path_review(&account.path),
                "json_pointer": account.json_pointer,
                "maximum_response_bytes": account.maximum_response_bytes,
            })),
            "denied_reads": guard.denied_reads.as_ref().map(|reads| reads.iter().map(|read| json!({
                "method": read.method,
                "path": path_review(&read.path),
                "refused_status": read.refused_status,
            })).collect::<Vec<_>>()),
            "disclosure": GUARD_DISCLOSURE,
        })
    }

    fn relative_ceiling_review(&self) -> Value {
        let Some(ceiling) = &self.source.relative_ceiling else {
            return Value::Null;
        };
        json!({
            "rule": format!(
                "{} ≤ floor(basis × {} / 10000)",
                ceiling.argument, ceiling.basis_points
            ),
            "argument": ceiling.argument,
            "basis_points": ceiling.basis_points,
            "path": path_review(&ceiling.path),
            "json_pointer": ceiling.json_pointer,
            "subtract_pointer": ceiling.subtract_pointer,
            "bind": ceiling.bind.as_ref().map(|binds| binds.iter().map(|bind| json!({
                "pointer": bind.pointer,
                "field": bind.field,
            })).collect::<Vec<_>>()),
            "maximum_response_bytes": ceiling.maximum_response_bytes,
        })
    }
}
