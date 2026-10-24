//! Complete lowering of the native compiler's borrowed write-source view.
//! This view has no serialized format and adds no recipe capability. Native
//! JSON/AST validation supplies the named templates and parsed host; this
//! module couples every lowered request component to one field specification.

use alloc::vec::Vec;
use crate::body_compiler::{self, NamedFormPiece, NamedJsonPiece};
use crate::construct::{BodyPlan, ConstructError, RequestMethod, WritePlan, copy_bytes};
use crate::field_projection::{FieldSpec, field_names};
use crate::header_compiler::{HeaderCompileError, NamedHeader, NamedScope, lower_headers};
use crate::path_compiler::{NamedSegment, lower_path, origin_matches_host};

/// The only derived idempotency header name admitted by the source language.
pub const IDEMPOTENCY_HEADER: &str = "Idempotency-Key";

/// Borrowed choice between the two existing named body-template forms.
#[derive(Clone, Copy, Debug)]
pub enum NamedBody<'a> {
    /// Existing canonical JSON pieces before names become indices.
    Json(&'a [NamedJsonPiece]),
    /// Existing form pieces, including named nested JSON.
    Form(&'a [NamedFormPiece]),
}

/// Exact byte view of one native validated write declaration. The parsed host
/// is supplied by the origin validator, rather than derived from URL suffixes.
#[derive(Clone, Copy, Debug)]
pub struct WriteSource<'a> {
    /// The source's closed HTTP method.
    pub method: RequestMethod,
    /// Exact approved origin bytes.
    pub origin: &'a [u8],
    /// Host returned by the native HTTPS/DNS origin validator.
    pub parsed_host: &'a [u8],
    /// Exact fixed/named source path.
    pub path: &'a [NamedSegment],
    /// Absence differs from an explicitly empty fixed map.
    pub versions: Option<&'a [NamedHeader]>,
    /// Exact optional named account-scope reference.
    pub scope: Option<&'a NamedScope>,
    /// Whether the existing derived-header idempotency form is declared.
    pub idempotency_header: bool,
    /// Exact pre-rendered source literals, named values and echo markers.
    pub body: NamedBody<'a>,
}

/// Component-preserving compile refusal; the native caller maps these to its
/// existing public source/profile/origin/header error families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompileWriteError {
    /// Invalid lexical/unique field layout.
    Fields,
    /// Approved origin disagrees with the parsed host or exceeds its envelope.
    Origin,
    /// A read method cannot become a write declaration.
    Method,
    /// Complete header compilation refused.
    Headers(HeaderCompileError),
    /// Complete path compilation refused.
    Path(ConstructError),
    /// Complete body compilation refused.
    Body(ConstructError),
}

/// One immutable source-produced layout and its complete write plan. Native
/// read-plan lowering consumes this same temporary layout/origin/header data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledWrite {
    /// Exact lexical/unique names copied from the supplied field pairs.
    pub field_names: Vec<Vec<u8>>,
    /// Complete approved request plan; compilation grants no execution right.
    pub plan: WritePlan,
}

/// Only the four existing source write methods are admitted.
#[must_use]
pub const fn write_method_allowed(method: RequestMethod) -> bool {
    match method {
        RequestMethod::Post | RequestMethod::Put | RequestMethod::Patch | RequestMethod::Delete => true,
        RequestMethod::Get | RequestMethod::Head => false,
    }
}

/// Lowers the complete body choice through the actual aggregate/name checks.
///
/// # Errors
/// Forwards the exact JSON/form compilation error without a partial plan.
pub fn lower_body(names: &[Vec<u8>], body: NamedBody<'_>) -> Result<BodyPlan, ConstructError> {
    match body {
        NamedBody::Json(source) => {
            let lowered = body_compiler::lower_json(names, source);
            match &lowered {
                Ok(pieces) => Ok(BodyPlan::Json(pieces.clone())),
                Err(error) => Err(*error),
            }
        }
        NamedBody::Form(source) => {
            let lowered = body_compiler::lower_form(names, source);
            match &lowered {
                Ok(pieces) => Ok(BodyPlan::Form(pieces.clone())),
                Err(error) => Err(*error),
            }
        }
    }
}

/// Compiles every write component against names earned from one field layout.
/// Origin framing, method, complete headers, complete path and complete body
/// checks all precede the returned plan. Origin bytes and idempotency name are
/// copied only after their domains are established. This does not validate
/// DNS/TLS, native JSON/AST canonical order/echo placement or authorization.
///
/// # Errors
/// Preserves field/origin/method/header/path/body refusal in that order and
/// returns no partially compiled plan on any error branch.
pub fn compile_write(fields: &[FieldSpec], source: WriteSource<'_>) -> Result<CompiledWrite, CompileWriteError> {
    let WriteSource {
        method, origin, parsed_host, path: source_path, versions,
        scope, idempotency_header: uses_idempotency_header, body: source_body,
    } = source;
    let named = field_names(fields);
    let names = match &named {
        Ok(names) => names.clone(),
        Err(_) => return Err(CompileWriteError::Fields),
    };
    if !origin_matches_host(origin, parsed_host) {
        return Err(CompileWriteError::Origin);
    }
    if !write_method_allowed(method) {
        return Err(CompileWriteError::Method);
    }
    let lowered_headers = lower_headers(&names, versions, scope);
    let headers = match &lowered_headers {
        Ok(headers) => headers.clone(),
        Err(error) => return Err(CompileWriteError::Headers(*error)),
    };
    let lowered_path = lower_path(&names, source_path);
    let path = match &lowered_path {
        Ok(path) => path.clone(),
        Err(error) => return Err(CompileWriteError::Path(*error)),
    };
    let lowered_body = lower_body(&names, source_body);
    let body = match &lowered_body {
        Ok(body) => body.clone(),
        Err(error) => return Err(CompileWriteError::Body(*error)),
    };
    let idempotency_header = if uses_idempotency_header {
        Some(copy_bytes(b"Idempotency-Key"))
    } else {
        None
    };
    let plan = WritePlan {
        method, origin: copy_bytes(origin), path, headers,
        idempotency_header, body,
    };
    Ok(CompiledWrite { field_names: names, plan })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::construct::{Header, construct_write};
    use crate::field_projection::{NamedInput, project_object};
    use crate::scalars::{ScalarInput, ScalarSchema};
    use alloc::vec;

    #[test]
    fn complete_source_projection_and_writer_preserve_every_request_component() {
        let fields = [
            FieldSpec { name: b"record".to_vec(), schema: ScalarSchema::String { minimum: 1, maximum: 64 } },
            FieldSpec { name: b"account".to_vec(), schema: ScalarSchema::String { minimum: 13, maximum: 64 } },
        ];
        let path = [NamedSegment::Fixed(b"v1".to_vec()), NamedSegment::Field(b"record".to_vec())];
        let versions = [NamedHeader { name: b"Stripe-Version".to_vec(), value: b"2026-10-18".to_vec() }];
        let scope = NamedScope { name: b"Stripe-Account".to_vec(), field: b"account".to_vec() };
        let body = [NamedJsonPiece::Raw(b"{\"record\":".to_vec()), NamedJsonPiece::Field(b"record".to_vec()), NamedJsonPiece::Raw(b",\"token\":".to_vec()), NamedJsonPiece::Echo, NamedJsonPiece::Raw(b"}".to_vec())];
        let source = WriteSource {
            method: RequestMethod::Patch, origin: b"https://api.example.com", parsed_host: b"api.example.com",
            path: &path, versions: Some(&versions), scope: Some(&scope),
            idempotency_header: true, body: NamedBody::Json(&body),
        };
        let compiled = compile_write(&fields, source).unwrap();
        assert_eq!(compiled.field_names, vec![b"record".to_vec(), b"account".to_vec()]);
        let inputs = [
            NamedInput { name: b"account", value: ScalarInput::Text(b"acct_12345678") },
            NamedInput { name: b"record", value: ScalarInput::Text("x/é".as_bytes()) },
        ];
        let values = project_object(&fields, &inputs).unwrap();
        let request = construct_write(&compiled.plan, &values, b"echo-token", b"operation-key").unwrap();
        assert_eq!(request.method, RequestMethod::Patch);
        assert_eq!(request.url, b"https://api.example.com/v1/x%2F%C3%A9");
        assert_eq!(request.headers, vec![
            Header { name: b"Stripe-Version".to_vec(), value: b"2026-10-18".to_vec() },
            Header { name: b"Stripe-Account".to_vec(), value: b"acct_12345678".to_vec() },
            Header { name: b"Idempotency-Key".to_vec(), value: b"operation-key".to_vec() },
        ]);
        assert_eq!(request.body, "{\"record\":\"x/é\",\"token\":\"echo-token\"}".as_bytes());
        assert_eq!(compile_write(&fields, WriteSource { parsed_host: b"other.example.com", ..source }), Err(CompileWriteError::Origin));
        assert_eq!(compile_write(&fields, WriteSource { method: RequestMethod::Get, ..source }), Err(CompileWriteError::Method));
    }

    #[test]
    fn refused_components_preserve_order_without_returning_partial_plans() {
        let fields = [FieldSpec { name: b"a".to_vec(), schema: ScalarSchema::Boolean }];
        let bad_path = [NamedSegment::Unsupported];
        let bad_body = [NamedJsonPiece::Field(b"missing".to_vec())];
        let source = WriteSource {
            method: RequestMethod::Post, origin: b"https://a.b", parsed_host: b"a.b", path: &bad_path,
            versions: Some(&[]), scope: None, idempotency_header: false, body: NamedBody::Json(&bad_body),
        };
        let malformed = [FieldSpec { name: vec![], schema: ScalarSchema::Boolean }];
        assert_eq!(compile_write(&malformed, WriteSource { origin: b"wrong", ..source }), Err(CompileWriteError::Fields));
        assert_eq!(compile_write(&[], WriteSource { origin: b"wrong", ..source }).unwrap_err(), CompileWriteError::Origin);
        assert_eq!(compile_write(&fields, source), Err(CompileWriteError::Headers(HeaderCompileError::ProviderHeader)));
        assert_eq!(compile_write(&fields, WriteSource { versions: None, ..source }), Err(CompileWriteError::Path(ConstructError::ArgumentMismatch)));
        let path = [NamedSegment::Fixed(b"v1".to_vec())];
        assert_eq!(compile_write(&fields, WriteSource { versions: None, path: &path, ..source }), Err(CompileWriteError::Body(ConstructError::ArgumentMismatch)));
    }
}
