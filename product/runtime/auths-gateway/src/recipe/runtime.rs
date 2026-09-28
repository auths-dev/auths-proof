//! What the engine reads from a compiled recipe at run time: the lease-time
//! credential checks, the relative ceiling, the pre-entry pointers, the
//! version response rule, and the observation template fixed at each claim.
//!
//! Everything here is recipe data the author declared and the operator
//! approved by digest; the gateway compares bytes, integers, and statuses
//! and interprets no provider field.

use super::construct::{self, ArgumentValue, SegmentPlan};
use super::source::{IdempotencySource, PathSegment};
use super::{
    ClosedObservationRequest, CompiledRecipe, GatewayRecipeError, ProviderResponseRule,
    RequestHeader, provider_header,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// The largest integer a basis, locator, or bind may carry: 2^53 − 1.
pub(crate) const MAX_JSON_INTEGER: u64 = (1 << 53) - 1;
/// The largest account identifier the account read accepts.
pub(crate) const MAX_ACCOUNT_BYTES: usize = 256;
/// Seconds between native verification and the last moment of entry.
pub(crate) const ENTRY_DEADLINE_SECONDS: u64 = 60;
/// The largest number of stored locator values.
const MAX_LOCATOR_VALUES: usize = 2;
/// The largest stored observation template, in encoded path bytes.
const MAX_TEMPLATE_PATH_BYTES: usize = construct::MAX_PATH_BYTES;

/// The lease-time credential checks a recipe declares.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GuardChecks {
    /// Byte prefixes a permitted secret starts with.
    pub(crate) prefixes: Vec<Vec<u8>>,
    /// The onboarding probe's pointer and required value.
    pub(crate) probe: Option<(String, Value)>,
    /// The account read's pointer.
    pub(crate) account_pointer: Option<String>,
    /// Each denied read's refused statuses, in declaration order.
    pub(crate) denied_refused: Vec<Vec<u16>>,
}

impl GuardChecks {
    /// Whether `secret` starts with a declared prefix.
    pub(crate) fn admits_secret(&self, secret: &[u8]) -> bool {
        self.prefixes
            .iter()
            .any(|prefix| secret.starts_with(prefix))
    }
}

/// The relative ceiling a recipe declares.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CeilingCheck {
    /// The verified integer argument the ceiling bounds.
    pub(crate) argument: String,
    /// The declared ratio, 1–10 000.
    pub(crate) basis_points: u16,
    /// The pointer of the basis value.
    pub(crate) json_pointer: String,
    /// The pointer subtracted from the basis value, when declared.
    pub(crate) subtract_pointer: Option<String>,
    /// Each bind pointer and the verified field it must equal.
    pub(crate) binds: Vec<(String, String)>,
}

/// What one relative-ceiling read shows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CeilingReading {
    /// A valid basis, and whether every bind equals its verified field.
    Read { basis: u64, binds_equal: bool },
    /// A value outside the rules, an absent pointer, or a negative
    /// difference.
    Unavailable,
}

impl CeilingCheck {
    /// Reads the basis and binds from a complete 2xx JSON response body.
    pub(crate) fn read(&self, body: &[u8], arguments: &Map<String, Value>) -> CeilingReading {
        let Ok(document) = serde_json::from_slice::<Value>(body) else {
            return CeilingReading::Unavailable;
        };
        let Some(value) = json_integer(&document, &self.json_pointer) else {
            return CeilingReading::Unavailable;
        };
        let subtrahend = match &self.subtract_pointer {
            None => None,
            Some(pointer) => match json_integer(&document, pointer) {
                Some(second) => Some(second),
                None => return CeilingReading::Unavailable,
            },
        };
        let Some(basis) = auths_gateway_kernel::ratio::relative_basis(value, subtrahend) else {
            return CeilingReading::Unavailable;
        };
        let binds_equal = self.binds.iter().all(|(pointer, field)| {
            match (document.pointer(pointer), arguments.get(field)) {
                (Some(Value::String(found)), Some(Value::String(verified))) => {
                    found.as_bytes() == verified.as_bytes()
                }
                (Some(found @ Value::Number(_)), Some(Value::Number(verified))) => found
                    .as_u64()
                    .zip(verified.as_u64())
                    .is_some_and(|(found, verified)| found == verified),
                _ => false,
            }
        });
        CeilingReading::Read { basis, binds_equal }
    }

    /// The verified argument, which the compiler requires to be a top-level
    /// integer field of at most 2^53 − 1; anything else is refused.
    pub(crate) fn argument_value(&self, arguments: &Map<String, Value>) -> Option<u64> {
        arguments
            .get(&self.argument)
            .and_then(Value::as_u64)
            .filter(|value| *value <= MAX_JSON_INTEGER)
    }
}

/// A JSON integer in 0..=2^53 − 1 at `pointer`, with no fraction or
/// exponent.
fn json_integer(document: &Value, pointer: &str) -> Option<u64> {
    match document.pointer(pointer) {
        Some(Value::Number(number)) => number.as_u64().filter(|value| *value <= MAX_JSON_INTEGER),
        _ => None,
    }
}

/// One segment of a stored observation path.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum TemplateSegment {
    /// A fixed segment or the encoded value of a verified field.
    Resolved { value: String },
    /// A value read from the recorded write response.
    ResponseField { pointer: String, max_bytes: u64 },
}

/// One non-credential header of the observation.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TemplateHeader {
    pub(crate) name: String,
    pub(crate) value: String,
}

/// The observation of one claim, fixed from verified fields at the claim: the
/// resolved segments, any response-field pointers still to be read from the
/// recorded response, the headers, and the canonical expected value.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObservationTemplate {
    pub(crate) origin: String,
    pub(crate) segments: Vec<TemplateSegment>,
    pub(crate) headers: Vec<TemplateHeader>,
    pub(crate) json_pointer: String,
    pub(crate) expected: String,
    pub(crate) maximum_response_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) echo_pointer: Option<String>,
}

impl ObservationTemplate {
    /// Whether any segment comes from the recorded response.
    pub(crate) fn has_response_fields(&self) -> bool {
        self.segments
            .iter()
            .any(|segment| matches!(segment, TemplateSegment::ResponseField { .. }))
    }

    /// The stored plan's provider link.
    pub(crate) fn link(&self) -> auths_gateway_kernel::transition::Link {
        use auths_gateway_kernel::transition::Link;
        match (self.echo_pointer.is_some(), self.has_response_fields()) {
            (false, _) => Link::None,
            (true, false) => Link::Verified,
            (true, true) => Link::AfterResponse,
        }
    }

    /// Whether the template is within its bounds.
    pub(crate) fn valid(&self) -> bool {
        let fields = self
            .segments
            .iter()
            .filter(|segment| matches!(segment, TemplateSegment::ResponseField { .. }))
            .count();
        !self.origin.is_empty()
            && !self.segments.is_empty()
            && self.segments.len() <= 16
            && fields <= MAX_LOCATOR_VALUES
            && self
                .segments
                .iter()
                .map(|segment| match segment {
                    TemplateSegment::Resolved { value } => value.len() + 1,
                    TemplateSegment::ResponseField { max_bytes, .. } => {
                        usize::try_from(*max_bytes).unwrap_or(usize::MAX)
                    }
                })
                .fold(0_usize, usize::saturating_add)
                <= MAX_TEMPLATE_PATH_BYTES * 3
            && self.headers.len() <= 4
            && !self.expected.is_empty()
            && self.expected.len() <= 8_192
            && self.maximum_response_bytes > 0
            && self.maximum_response_bytes <= 65_536
    }

    /// Reads every response-field value from a complete 2xx JSON write
    /// response with no version mismatch: a JSON string of 1 to `max_bytes`
    /// bytes that is a safe path value, or a non-negative integer of at most
    /// 2^53 − 1 written in decimal. Only the values are kept.
    pub(crate) fn extract_locator(&self, body: &[u8]) -> Option<BTreeMap<String, String>> {
        let document: Value = serde_json::from_slice(body).ok()?;
        let mut locator = BTreeMap::new();
        for segment in &self.segments {
            let TemplateSegment::ResponseField { pointer, max_bytes } = segment else {
                continue;
            };
            let value = match document.pointer(pointer)? {
                Value::String(text) => {
                    let bound = usize::try_from(*max_bytes).ok()?;
                    (text.len() <= bound && construct::segment_value_valid(text.as_bytes()))
                        .then(|| text.clone())?
                }
                Value::Number(number) => number
                    .as_u64()
                    .filter(|value| *value <= MAX_JSON_INTEGER)?
                    .to_string(),
                _ => return None,
            };
            locator.insert(pointer.clone(), value);
        }
        (!locator.is_empty()).then_some(locator)
    }

    /// Whether `locator` supplies exactly this template's response fields.
    pub(crate) fn locator_fits(&self, locator: &BTreeMap<String, String>) -> bool {
        let pointers: Vec<&str> = self
            .segments
            .iter()
            .filter_map(|segment| match segment {
                TemplateSegment::ResponseField { pointer, .. } => Some(pointer.as_str()),
                TemplateSegment::Resolved { .. } => None,
            })
            .collect();
        locator.len() == pointers.len()
            && pointers
                .iter()
                .all(|pointer| locator.contains_key(*pointer))
            && locator
                .values()
                .all(|value| construct::segment_value_valid(value.as_bytes()))
    }

    /// The read-back request: each response-field segment is the stored
    /// locator value, percent-encoded exactly as a verified field is, so it
    /// cannot add a segment, query, or fragment. `None` when a value is
    /// missing or the path is over its bound.
    pub(crate) fn request(
        &self,
        locator: Option<&BTreeMap<String, String>>,
    ) -> Option<ClosedObservationRequest> {
        let mut path = Vec::new();
        for segment in &self.segments {
            path.push(b'/');
            match segment {
                TemplateSegment::Resolved { value } => path.extend_from_slice(value.as_bytes()),
                TemplateSegment::ResponseField { pointer, .. } => {
                    let value = locator?.get(pointer)?;
                    if !construct::segment_value_valid(value.as_bytes()) {
                        return None;
                    }
                    path = construct::append_path_encoded(path, value.as_bytes());
                }
            }
        }
        if path.len() > MAX_TEMPLATE_PATH_BYTES {
            return None;
        }
        let url = format!("{}{}", self.origin, String::from_utf8(path).ok()?);
        let expected = serde_json::from_str(&self.expected).ok()?;
        Some(ClosedObservationRequest {
            url,
            headers: self
                .headers
                .iter()
                .map(|header| RequestHeader {
                    name: header.name.clone(),
                    value: header.value.clone(),
                })
                .collect(),
            json_pointer: self.json_pointer.clone(),
            expected,
            maximum_response_bytes: self.maximum_response_bytes,
            echo_pointer: self.echo_pointer.clone(),
        })
    }
}

impl CompiledRecipe {
    /// The declared lease-time credential checks, if any.
    pub(crate) fn guard_checks(&self) -> Option<GuardChecks> {
        let guard = self.source.credential.guard()?;
        Some(GuardChecks {
            prefixes: guard
                .prefixes
                .iter()
                .map(|prefix| prefix.as_bytes().to_vec())
                .collect(),
            probe: guard
                .probe
                .as_ref()
                .map(|probe| (probe.json_pointer.clone(), probe.equals.clone())),
            account_pointer: guard
                .account
                .as_ref()
                .map(|account| account.json_pointer.clone()),
            denied_refused: guard
                .denied_reads
                .iter()
                .flatten()
                .map(|read| {
                    read.refused_status
                        .iter()
                        .filter_map(|status| u16::try_from(*status).ok())
                        .collect()
                })
                .collect(),
        })
    }

    /// The declared relative ceiling, if any.
    pub(crate) fn ceiling_check(&self) -> Option<CeilingCheck> {
        let source = self.source.relative_ceiling.as_ref()?;
        Some(CeilingCheck {
            argument: source.argument.clone(),
            basis_points: u16::try_from(source.basis_points).ok()?,
            json_pointer: source.json_pointer.clone(),
            subtract_pointer: source.subtract_pointer.clone(),
            binds: source
                .bind
                .iter()
                .flatten()
                .map(|bind| (bind.pointer.clone(), bind.field.clone()))
                .collect(),
        })
    }

    /// The declared pre-entry pointers, in declaration order.
    pub(crate) fn pre_entry_pointers(&self) -> Option<&[String]> {
        self.source
            .pre_entry
            .as_ref()
            .map(|source| source.pointers.as_slice())
    }

    /// Every version header whose response rule requires the provider to
    /// echo it, with its fixed value.
    pub(crate) fn required_response_versions(&self) -> Vec<(String, String)> {
        self.source
            .provider_headers
            .iter()
            .flatten()
            .filter(|(name, _)| {
                provider_header(name)
                    .is_some_and(|entry| entry.response == ProviderResponseRule::Required)
            })
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }

    /// The declared provider retention of a recipe that declares
    /// `write.idempotency`.
    pub(crate) fn idempotency_retention(&self) -> Option<u64> {
        self.source
            .write
            .idempotency
            .as_ref()
            .map(IdempotencySource::retention_seconds)
    }

    /// Whether the recipe declares an account-scope header.
    pub(crate) fn declares_account_scope(&self) -> bool {
        self.source.account_scope.is_some()
    }

    /// The observation template of a request built from `values`, or `None`
    /// without an observation.
    pub(crate) fn observation_template(
        &self,
        values: &[ArgumentValue],
        headers: &[RequestHeader],
        expected: &Value,
    ) -> Result<Option<ObservationTemplate>, GatewayRecipeError> {
        let Some(source) = &self.source.observation else {
            return Ok(None);
        };
        let mut segments = Vec::with_capacity(source.path.len());
        for segment in &source.path {
            let plan = match segment {
                PathSegment::Fixed { value } => SegmentPlan::Fixed(value.as_bytes().to_vec()),
                PathSegment::Field { name } => SegmentPlan::Field(
                    self.fields
                        .keys()
                        .position(|field| field == name)
                        .ok_or(GatewayRecipeError::ActionMismatch)?,
                ),
                PathSegment::ResponseField { pointer, max_bytes } => {
                    segments.push(TemplateSegment::ResponseField {
                        pointer: pointer.clone(),
                        max_bytes: *max_bytes,
                    });
                    continue;
                }
                PathSegment::Echo => return Err(GatewayRecipeError::EchoConflict),
            };
            if construct::segment_error(&plan, values).is_some() {
                return Err(GatewayRecipeError::UnsafePath);
            }
            let encoded = construct::append_segment(Vec::new(), &plan, values);
            let value = String::from_utf8(encoded.get(1..).unwrap_or_default().to_vec())
                .map_err(|_| GatewayRecipeError::UnsafePath)?;
            segments.push(TemplateSegment::Resolved { value });
        }
        let expected = serde_json_canonicalizer::to_string(expected)
            .map_err(|_| GatewayRecipeError::ActionMismatch)?;
        let template = ObservationTemplate {
            origin: self.source.origin.clone(),
            segments,
            headers: headers
                .iter()
                .filter(|header| header.name != super::IDEMPOTENCY_HEADER)
                .map(|header| TemplateHeader {
                    name: header.name.clone(),
                    value: header.value.clone(),
                })
                .collect(),
            json_pointer: source.json_pointer.clone(),
            expected,
            maximum_response_bytes: source.maximum_response_bytes,
            echo_pointer: self.source.echo.as_ref().map(|echo| echo.observe.clone()),
        };
        if template.valid() {
            Ok(Some(template))
        } else {
            Err(GatewayRecipeError::UnsafePath)
        }
    }
}
