//! Lowers a validated recipe source into the closed plans that the
//! construction leaf executes.
//!
//! JSON bodies are pre-rendered in RFC 8785 order: object keys sorted by
//! byte (every key is an ASCII field name, so byte order is UTF-16 order),
//! the echo key inserted at its sorted position, and literals rendered with
//! the leaf's own string escaper. Form bodies list their fields, echo
//! included, in sorted name order with every separator pre-encoded. Only
//! argument values and the echo token are left for the leaf.

use super::construct::{
    ActionReadPlan, CredentialReadPlan, HeaderPlan,
    RequestMethod, SegmentPlan, WritePlan,
};
use super::source::{
    BodySource, CredentialSource, DeniedReadSource, EchoPlacement, FormExpr, IdempotencySource, PathSegment, RecipeSource, ValueExpr,
};
use super::{
    GatewayRecipeError, WriteMethod,
};
use super::validate::ValidatedSource;
use auths_gateway_kernel::field_projection::FieldSpec;
use auths_gateway_kernel::path_compiler::{self, NamedSegment};
use auths_gateway_kernel::header_compiler::{HeaderCompileError, NamedHeader, NamedScope};
use auths_gateway_kernel::request_compiler::{self, CompileWriteError};
use auths_gateway_kernel::template_ast::{self, TemplateError};

/// Every plan of one compiled recipe.
#[derive(Clone, Debug)]
pub(super) struct Plans {
    /// Complete immutable field/name pairs used by runtime object projection.
    pub(super) field_schemas: Vec<FieldSpec>,
    pub(super) write: WritePlan,
    /// Present only for a verified-locator observation.
    pub(super) observation: Option<ActionReadPlan>,
    pub(super) pre_entry: Option<ActionReadPlan>,
    pub(super) relative_ceiling: Option<ActionReadPlan>,
    pub(super) probe: Option<CredentialReadPlan>,
    pub(super) account: Option<CredentialReadPlan>,
    pub(super) denied: Vec<CredentialReadPlan>,
}

struct Lowering {
    field_names: Vec<Vec<u8>>,
    origin: Vec<u8>,
    headers: HeaderPlan,
}

/// Copies decoded values and original name/child pairs without rendering
/// syntax or resolving argument indices. The kernel checks and emits the body.
fn source_value(value: &ValueExpr) -> template_ast::Value {
    match value {
        ValueExpr::String { value } => template_ast::Value::String(value.as_bytes().to_vec()),
        ValueExpr::Integer { value } => template_ast::Value::Integer(*value),
        ValueExpr::Boolean { value } => template_ast::Value::Boolean(*value),
        ValueExpr::Field { name } => template_ast::Value::Field(name.as_bytes().to_vec()),
        ValueExpr::Object { fields } => template_ast::Value::Object(source_members(fields)),
        ValueExpr::Array { items } => template_ast::Value::Array(source_values(items)),
        ValueExpr::Echo => template_ast::Value::AuthorEcho,
    }
}

fn source_values(items: &[ValueExpr]) -> Vec<template_ast::Value> {
    let mut output = Vec::new();
    let mut position = 0;
    while position < items.len() {
        output.push(source_value(&items[position]));
        position += 1;
    }
    output
}

fn source_members(fields: &std::collections::BTreeMap<String, ValueExpr>) -> Vec<template_ast::JsonMember> {
    let mut output = Vec::new();
    for (name, value) in fields {
        output.push(template_ast::JsonMember { name: name.as_bytes().to_vec(), value: source_value(value) });
    }
    output
}

fn source_form_value(value: &FormExpr) -> template_ast::FormValue {
    match value {
        FormExpr::String { value } => template_ast::FormValue::String(value.as_bytes().to_vec()),
        FormExpr::Field { name } => template_ast::FormValue::Field(name.as_bytes().to_vec()),
        FormExpr::Json { value } => template_ast::FormValue::Json(source_value(value)),
        FormExpr::Echo => template_ast::FormValue::AuthorEcho,
    }
}

fn source_body(body: &BodySource) -> template_ast::Body {
    match body {
        BodySource::Json { value } => template_ast::Body::Json(source_value(value)),
        BodySource::Form { fields } => template_ast::Body::Form(source_form_members(fields)),
    }
}

fn source_form_members(fields: &std::collections::BTreeMap<String, FormExpr>) -> Vec<template_ast::FormMember> {
    let mut output = Vec::new();
    for (name, value) in fields {
        output.push(template_ast::FormMember { name: name.as_bytes().to_vec(), value: source_form_value(value) });
    }
    output
}

fn source_echo(echo: &EchoPlacement) -> Result<template_ast::Echo, GatewayRecipeError> {
    match echo {
        EchoPlacement::JsonPointer { pointer } => {
            let tokens = match auths_gateway_kernel::template_members::echo_pointer_tokens(pointer.as_bytes()) {
                Ok(tokens) => tokens,
                Err(_) => return Err(GatewayRecipeError::EchoConflict),
            };
            Ok(template_ast::Echo::Json(tokens))
        }
        EchoPlacement::FormField { name } => Ok(template_ast::Echo::Form(name.as_bytes().to_vec())),
    }
}

const fn method(method: WriteMethod) -> RequestMethod {
    match method {
        WriteMethod::Post => RequestMethod::Post,
        WriteMethod::Put => RequestMethod::Put,
        WriteMethod::Patch => RequestMethod::Patch,
        WriteMethod::Delete => RequestMethod::Delete,
    }
}

fn named_path(path: &[PathSegment]) -> Vec<NamedSegment> {
    let mut output = Vec::new();
    for segment in path {
        output.push(match segment {
            PathSegment::Fixed { value } => NamedSegment::Fixed(value.as_bytes().to_vec()),
            PathSegment::Field { name } => NamedSegment::Field(name.as_bytes().to_vec()),
            PathSegment::ResponseField { .. } | PathSegment::Echo => NamedSegment::Unsupported,
        });
    }
    output
}

pub(super) fn contains_response_field(path: &[PathSegment]) -> bool {
    for segment in path {
        if matches!(segment, PathSegment::ResponseField { .. }) {
            return true;
        }
    }
    false
}

impl Lowering {
    fn path(&self, path: &[PathSegment]) -> Result<Vec<SegmentPlan>, GatewayRecipeError> {
        path_compiler::lower_path(&self.field_names, &named_path(path))
            .map_err(|_| GatewayRecipeError::InvalidSource)
    }

    fn action_read(&self, path: &[PathSegment]) -> Result<ActionReadPlan, GatewayRecipeError> {
        Ok(ActionReadPlan {
            origin: self.origin.clone(),
            path: self.path(path)?,
            headers: self.headers.clone(),
        })
    }

    fn credential_read(
        &self,
        method: RequestMethod,
        path: &[PathSegment],
    ) -> Result<CredentialReadPlan, GatewayRecipeError> {
        let path = path_compiler::lower_fixed_path(&named_path(path))
            .map_err(|_| GatewayRecipeError::InvalidSource)?;
        Ok(CredentialReadPlan {
            method,
            origin: self.origin.clone(),
            path,
            versions: self.headers.versions.clone(),
        })
    }

    fn named_body(body: &BodySource, echo: Option<&EchoPlacement>) -> Result<template_ast::NamedTemplate, GatewayRecipeError> {
        let body = source_body(body);
        let echo = match echo { Some(echo) => Some(source_echo(echo)?), None => None };
        template_ast::compile_body(&body, echo.as_ref()).map_err(|error| match error {
            TemplateError::Shape => GatewayRecipeError::UnsafeTemplate,
            TemplateError::EchoConflict => GatewayRecipeError::EchoConflict,
            TemplateError::Resources => GatewayRecipeError::InvalidSource,
        })
    }

    fn probe(&self, credential: &CredentialSource) -> Result<Option<CredentialReadPlan>, GatewayRecipeError> {
        let Some(guard) = credential.guard() else { return Ok(None); };
        match &guard.probe {
            Some(probe) => {
                let lowered = self.credential_read(RequestMethod::Get, &probe.path);
                match &lowered {
                    Ok(plan) => Ok(Some(plan.clone())),
                    Err(error) => Err(*error),
                }
            }
            None => Ok(None),
        }
    }

    fn account(&self, credential: &CredentialSource) -> Result<Option<CredentialReadPlan>, GatewayRecipeError> {
        let Some(guard) = credential.guard() else { return Ok(None); };
        match &guard.account {
            Some(account) => {
                let lowered = self.credential_read(RequestMethod::Get, &account.path);
                match &lowered {
                    Ok(plan) => Ok(Some(plan.clone())),
                    Err(error) => Err(*error),
                }
            }
            None => Ok(None),
        }
    }

    fn denied(&self, credential: &CredentialSource) -> Result<Vec<CredentialReadPlan>, GatewayRecipeError> {
        let Some(guard) = credential.guard() else { return Ok(Vec::new()); };
        match &guard.denied_reads {
            Some(reads) => self.denied_reads(reads),
            None => Ok(Vec::new()),
        }
    }

    fn denied_reads(&self, reads: &[DeniedReadSource]) -> Result<Vec<CredentialReadPlan>, GatewayRecipeError> {
        let mut output = Vec::new();
        for read in reads {
            let lowered = self.credential_read(denied_read_method(read), &read.path);
            match &lowered {
                Ok(plan) => output.push(plan.clone()),
                Err(error) => return Err(*error),
            }
        }
        Ok(output)
    }

}

fn header_source(source: &RecipeSource) -> (Option<Vec<NamedHeader>>, Option<NamedScope>) {
    let versions = match &source.provider_headers {
        Some(headers) => {
            let mut output = Vec::new();
            for (name, value) in headers {
                output.push(NamedHeader { name: name.as_bytes().to_vec(), value: value.as_bytes().to_vec() });
            }
            Some(output)
        }
        None => None,
    };
    let account_scope = match &source.account_scope {
        Some(scope) => Some(NamedScope { name: scope.header.as_bytes().to_vec(), field: scope.field.as_bytes().to_vec() }),
        None => None,
    };
    (versions, account_scope)
}

fn named_write_body(source: &RecipeSource) -> Result<template_ast::NamedTemplate, GatewayRecipeError> {
    match &source.echo {
        Some(echo) => Lowering::named_body(&source.write.body, Some(&echo.write)),
        None => Lowering::named_body(&source.write.body, None),
    }
}

fn has_idempotency_header(source: &RecipeSource) -> bool {
    match &source.write.idempotency {
        Some(IdempotencySource::DerivedHeader { .. }) => true,
        Some(IdempotencySource::OperationIdField { .. }) | None => false,
    }
}

fn denied_read_method(read: &DeniedReadSource) -> RequestMethod {
    if auths_gateway_kernel::construct::field_name_equal(read.method.as_bytes(), b"HEAD") {
        RequestMethod::Head
    } else {
        RequestMethod::Get
    }
}

/// Lowers a source the compile rules accepted.
pub(super) fn plans(
    checked: &ValidatedSource<'_>,
) -> Result<Plans, GatewayRecipeError> {
    let source = checked.source();
    let parsed_host = checked.parsed_host();
    let field_schemas = checked.field_specs().to_vec();
    let body_result = named_write_body(source);
    let body = match &body_result {
        Ok(body) => body.clone(),
        Err(error) => return Err(*error),
    };
    let path = named_path(&source.write.path);
    let (versions, account_scope) = header_source(source);
    let write_source = request_compiler::WriteSource {
        method: method(source.write.method),
        origin: source.origin.as_bytes(),
        parsed_host: parsed_host.as_bytes(),
        path: &path,
        versions: versions.as_deref(),
        scope: account_scope.as_ref(),
        idempotency_header: has_idempotency_header(source),
        body: body.source(),
    };
    let compilation = request_compiler::compile_write(&field_schemas, write_source);
    let compiled = match &compilation {
        Ok(compiled) => compiled,
        Err(error) => return Err(match error {
            CompileWriteError::Fields => GatewayRecipeError::InvalidProfileLock,
            CompileWriteError::Origin => GatewayRecipeError::UnsafeOrigin,
            CompileWriteError::Method | CompileWriteError::Path(_) | CompileWriteError::Body(_) => GatewayRecipeError::InvalidSource,
            CompileWriteError::Headers(HeaderCompileError::ProviderHeader) => GatewayRecipeError::InvalidProviderHeader,
            CompileWriteError::Headers(HeaderCompileError::AccountScope) => GatewayRecipeError::InvalidAccountScope,
        }),
    };
    let write = compiled.plan.clone();
    let lowering = Lowering {
        field_names: compiled.field_names.clone(),
        origin: write.origin.clone(),
        headers: write.headers.clone(),
    };
    let observation = match &source.observation {
        Some(observation) => {
            if contains_response_field(&observation.path) {
                None
            } else {
                Some(lowering.action_read(&observation.path)?)
            }
        }
        None => None,
    };
    let pre_entry = match &source.pre_entry {
        Some(pre_entry) => Some(lowering.action_read(&pre_entry.path)?),
        None => None,
    };
    let relative_ceiling = match &source.relative_ceiling {
        Some(ceiling) => Some(lowering.action_read(&ceiling.path)?),
        None => None,
    };
    let probe = lowering.probe(&source.credential)?;
    let account = lowering.account(&source.credential)?;
    let denied = lowering.denied(&source.credential)?;
    Ok(Plans {
        field_schemas,
        write,
        observation,
        pre_entry,
        relative_ceiling,
        probe,
        account,
        denied,
    })
}
