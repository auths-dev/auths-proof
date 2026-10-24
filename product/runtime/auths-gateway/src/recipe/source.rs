//! The typed AST of `auths.gateway-recipe-source/2`.
//!
//! Every struct refuses unknown members, and every optional member is omitted
//! when absent, so re-serializing a parsed source under RFC 8785 gives the
//! canonical bytes the digest covers. Values whose JSON type a compile rule
//! checks (a probe literal, a method, a count) are parsed loosely here so the
//! rule, not the parser, reports the stable code.

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

mod value_decode;

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecipeSource {
    pub(super) schema: String,
    pub(super) profile_schema_digest: String,
    pub(super) service: String,
    pub(super) tool: String,
    pub(super) operator_namespace: String,
    pub(super) credential: CredentialSource,
    pub(super) origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) provider_headers: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) account_scope: Option<AccountScopeSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) bounds: Option<BoundsSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) relative_ceiling: Option<RelativeCeilingSource>,
    pub(super) write: WriteSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) observation: Option<ObservationSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) echo: Option<EchoSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) pre_entry: Option<PreEntrySource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) preconditions: Option<PreconditionSource>,
}

/// The credential requirement plus the author's optional credential guard.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum CredentialSource {
    Bearer {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        guard: Option<GuardSource>,
    },
    HeaderApiKey {
        header: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        guard: Option<GuardSource>,
    },
}

impl CredentialSource {
    pub(super) const fn guard(&self) -> Option<&GuardSource> {
        match self {
            Self::Bearer { guard } | Self::HeaderApiKey { guard, .. } => guard.as_ref(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GuardSource {
    pub(super) prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) probe: Option<ProbeSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) account: Option<AccountReadSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) denied_reads: Option<Vec<DeniedReadSource>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProbeSource {
    pub(super) path: Vec<PathSegment>,
    pub(super) json_pointer: String,
    pub(super) equals: Value,
    pub(super) maximum_response_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccountReadSource {
    pub(super) path: Vec<PathSegment>,
    pub(super) json_pointer: String,
    pub(super) maximum_response_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeniedReadSource {
    pub(super) method: String,
    pub(super) path: Vec<PathSegment>,
    pub(super) refused_status: Vec<u64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccountScopeSource {
    pub(super) header: String,
    pub(super) field: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BoundsSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) sum: Option<SumBoundSource>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SumBoundSource {
    pub(super) argument: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) partition: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RelativeCeilingSource {
    pub(super) argument: String,
    pub(super) basis_points: u64,
    pub(super) path: Vec<PathSegment>,
    pub(super) json_pointer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) subtract_pointer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) bind: Option<Vec<BindSource>>,
    pub(super) maximum_response_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BindSource {
    pub(super) pointer: String,
    pub(super) field: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WriteSource {
    pub(super) method: super::WriteMethod,
    pub(super) path: Vec<PathSegment>,
    pub(super) body: BodySource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) idempotency: Option<IdempotencySource>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum IdempotencySource {
    DerivedHeader {
        retention_seconds: u64,
    },
    OperationIdField {
        location: IdempotencyLocation,
        retention_seconds: u64,
    },
}

impl IdempotencySource {
    pub(super) const fn retention_seconds(&self) -> u64 {
        match self {
            Self::DerivedHeader { retention_seconds }
            | Self::OperationIdField {
                retention_seconds, ..
            } => *retention_seconds,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IdempotencyLocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) json_pointer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) form_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) pointer: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum PathSegment {
    Fixed {
        value: String,
    },
    Field {
        name: String,
    },
    ResponseField {
        pointer: String,
        max_bytes: u64,
    },
    /// Parsed only so that an author-placed echo fails with a stable code.
    Echo,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum BodySource {
    Json { value: ValueExpr },
    Form { fields: BTreeMap<String, FormExpr> },
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum FormExpr {
    String {
        value: String,
    },
    Field {
        name: String,
    },
    Json {
        value: ValueExpr,
    },
    /// Parsed only so that an author-placed echo fails with a stable code.
    Echo,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum ValueExpr {
    String {
        value: String,
    },
    Integer {
        value: i64,
    },
    Boolean {
        value: bool,
    },
    Field {
        name: String,
    },
    Object {
        fields: BTreeMap<String, ValueExpr>,
    },
    Array {
        items: Vec<ValueExpr>,
    },
    /// Parsed only so that an author-placed echo fails with a stable code.
    Echo,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObservationSource {
    pub(super) path: Vec<PathSegment>,
    pub(super) json_pointer: String,
    pub(super) expected_field: String,
    pub(super) maximum_response_bytes: usize,
}

/// Where the compiler places the echo token: a new key of a fixed JSON
/// object, or one new form field.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum EchoPlacement {
    JsonPointer { pointer: String },
    FormField { name: String },
}

/// Recipe-declared provider field that carries the gateway echo token. The
/// application never supplies the token; the compiler alone places it.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EchoSource {
    pub(super) write: EchoPlacement,
    pub(super) observe: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreEntrySource {
    pub(super) path: Vec<PathSegment>,
    pub(super) pointers: Vec<String>,
    pub(super) maximum_response_bytes: u64,
}

/// Verified arguments the request never renders. They exist so that a grant's
/// observation requirements can name them as action facts: the read-back
/// subject names the observed record, and each verified argument is compared
/// only by those requirements.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreconditionSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) read_back_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) verified: Vec<String>,
}

// Exact production field/default and variant-order tables.

recipe_record_decode!(RecipeSource {
    schema: String => required,
    profile_schema_digest: String => required,
    service: String => required,
    tool: String => required,
    operator_namespace: String => required,
    credential: CredentialSource => required,
    origin: String => required,
    provider_headers: Option<BTreeMap<String, String>> => default,
    account_scope: Option<AccountScopeSource> => default,
    bounds: Option<BoundsSource> => default,
    relative_ceiling: Option<RelativeCeilingSource> => default,
    write: WriteSource => required,
    observation: Option<ObservationSource> => default,
    echo: Option<EchoSource> => default,
    pre_entry: Option<PreEntrySource> => default,
    preconditions: Option<PreconditionSource> => default,
});
recipe_record_decode!(GuardSource {
    prefixes: Vec<String> => required,
    probe: Option<ProbeSource> => default,
    account: Option<AccountReadSource> => default,
    denied_reads: Option<Vec<DeniedReadSource>> => default,
});
recipe_record_decode!(ProbeSource {
    path: Vec<PathSegment> => required,
    json_pointer: String => required,
    equals: Value => required,
    maximum_response_bytes: u64 => required,
});
recipe_record_decode!(AccountReadSource {
    path: Vec<PathSegment> => required,
    json_pointer: String => required,
    maximum_response_bytes: u64 => required,
});
recipe_record_decode!(DeniedReadSource {
    method: String => required,
    path: Vec<PathSegment> => required,
    refused_status: Vec<u64> => required,
});
recipe_record_decode!(AccountScopeSource { header: String => required, field: String => required });
recipe_record_decode!(BoundsSource { sum: Option<SumBoundSource> => default });
recipe_record_decode!(SumBoundSource { argument: String => required, partition: Option<String> => default });
recipe_record_decode!(RelativeCeilingSource {
    argument: String => required,
    basis_points: u64 => required,
    path: Vec<PathSegment> => required,
    json_pointer: String => required,
    subtract_pointer: Option<String> => default,
    bind: Option<Vec<BindSource>> => default,
    maximum_response_bytes: u64 => required,
});
recipe_record_decode!(BindSource { pointer: String => required, field: String => required });
recipe_record_decode!(WriteSource {
    method: super::WriteMethod => required,
    path: Vec<PathSegment> => required,
    body: BodySource => required,
    idempotency: Option<IdempotencySource> => default,
});
recipe_record_decode!(IdempotencyLocation {
    json_pointer: Option<String> => default,
    form_field: Option<String> => default,
    pointer: Option<String> => default,
});
recipe_record_decode!(ObservationSource {
    path: Vec<PathSegment> => required,
    json_pointer: String => required,
    expected_field: String => required,
    maximum_response_bytes: usize => required,
});
recipe_record_decode!(EchoSource { write: EchoPlacement => required, observe: String => required });
recipe_record_decode!(PreEntrySource {
    path: Vec<PathSegment> => required,
    pointers: Vec<String> => required,
    maximum_response_bytes: u64 => required,
});
recipe_record_decode!(PreconditionSource {
    read_back_subject: Option<String> => default,
    verified: Vec<String> => default,
});

recipe_internal_enum_decode!(CredentialSource {
    0 => "bearer" => Bearer [BearerFields { guard: Option<GuardSource> => default }],
    1 => "header-api-key" => HeaderApiKey [HeaderKeyFields {
        header: String => required, guard: Option<GuardSource> => default,
    }],
});
recipe_internal_enum_decode!(IdempotencySource {
    0 => "derived-header" => DerivedHeader [DerivedHeaderFields { retention_seconds: u64 => required }],
    1 => "operation-id-field" => OperationIdField [OperationIdFields {
        location: IdempotencyLocation => required, retention_seconds: u64 => required,
    }],
});
recipe_internal_enum_decode!(PathSegment {
    0 => "fixed" => Fixed [FixedPathFields { value: String => required }],
    1 => "field" => Field [FieldPathFields { name: String => required }],
    2 => "response-field" => ResponseField [ResponsePathFields { pointer: String => required, max_bytes: u64 => required }],
    3 => "echo" => Echo [],
});
recipe_internal_enum_decode!(BodySource {
    0 => "json" => Json [JsonBodyFields { value: ValueExpr => required }],
    1 => "form" => Form [FormBodyFields { fields: BTreeMap<String, FormExpr> => required }],
});
recipe_internal_enum_decode!(FormExpr {
    0 => "string" => String [StringFormFields { value: String => required }],
    1 => "field" => Field [FieldFormFields { name: String => required }],
    2 => "json" => Json [JsonFormFields { value: ValueExpr => required }],
    3 => "echo" => Echo [],
});
recipe_internal_enum_decode!(EchoPlacement {
    0 => "json-pointer" => JsonPointer [JsonEchoFields { pointer: String => required }],
    1 => "form-field" => FormField [FormEchoFields { name: String => required }],
});
