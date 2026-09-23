//! Request mapping: server, security, parameters, path, and body.

use crate::diagnostic::{DeriveCode, Diagnostic};
use crate::document::{Dialect, Selected, resolve};
use crate::json::{Json, escape_token};
use crate::model::{
    ArgSchema, Argument, BINDING_FIELDS, Credential, CredentialKind, Mapping, Media,
    OPERATION_ID_MAX_BYTES, Omitted, Segment, Server, Template, Unenforced,
};
use crate::request::{Literal, Overrides, Request, SchemeOverride};
use crate::schema::{Kind, valid_argument_name, valid_fixed_segment};

/// Most fields the gateway compiler accepts in one profile.
const MAX_FIELDS: usize = 32;
/// Largest worst-case canonical argument JSON the profile generator accepts.
pub(crate) const MAX_ARGUMENT_JSON_BYTES: usize = 4096;
const MAX_PATH_SEGMENTS: usize = 16;
const MAX_TEMPLATE_NODES: usize = 64;
const MAX_FORM_FIELDS: usize = 16;

/// Mutable mapping state; diagnostics accumulate so one run reports the
/// whole rejection wall.
pub(crate) struct Mapper<'a> {
    pub(crate) document: &'a Json,
    pub(crate) dialect: Dialect,
    pub(crate) overrides: Overrides,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) omitted: Vec<Omitted>,
    pub(crate) unenforced: Vec<Unenforced>,
    pub(crate) arguments: Vec<Argument>,
}

struct Parameter<'a> {
    name: String,
    location: String,
    node: &'a Json,
    pointer: String,
}

impl<'a> Mapper<'a> {
    pub(crate) fn push(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }

    /// Maps the selected operation; returns every rejection on failure.
    pub(crate) fn map(
        mut self,
        request: &Request,
        selected: &Selected<'a>,
    ) -> Result<Mapping, Vec<Diagnostic>> {
        let tool = self.tool(request, selected);
        let server = self.server(request, selected);
        let credential = self.security(request, selected);
        let parameters = self.parameters(selected);
        let path = self.path(selected, &parameters, server.as_ref());
        let body = self.body(selected);
        self.limits(request, body.as_ref());
        if self.diagnostics.is_empty() {
            for unused in self.overrides.unused() {
                self.push(Diagnostic::new(
                    DeriveCode::UnusedOverride,
                    "",
                    format!("{unused} does not apply to any construct of this operation"),
                ));
            }
        }
        match (tool, server, credential, path, body) {
            (Some(tool), Some(server), Some(credential), Some(path), Some((media, body)))
                if self.diagnostics.is_empty() =>
            {
                Ok(Mapping {
                    tool,
                    server,
                    credential,
                    arguments: self.arguments,
                    path,
                    media,
                    body,
                    omitted: self.omitted,
                    unenforced: self.unenforced,
                })
            }
            _ => Err(self.diagnostics),
        }
    }

    fn tool(&mut self, request: &Request, selected: &Selected<'a>) -> Option<String> {
        let valid = |name: &str| {
            name.len() <= 112
                && name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
                && format!("{name}_v{}", request.version).len() <= 128
        };
        if let Some(tool) = &request.tool {
            if valid(tool) {
                return Some(tool.clone());
            }
            self.push(Diagnostic::new(
                DeriveCode::InvalidOverride,
                "",
                format!("--tool {tool:?} is not a 1-112 byte tool name starting with a letter"),
            ));
            return None;
        }
        if valid(&request.operation) {
            return Some(request.operation.clone());
        }
        let suggestion: String = request
            .operation
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                    character
                } else {
                    '_'
                }
            })
            .take(112)
            .collect();
        let suggestion =
            if suggestion.starts_with(|character: char| character.is_ascii_alphabetic()) {
                suggestion
            } else {
                format!("op_{suggestion}")
            };
        self.push(
            Diagnostic::new(
                DeriveCode::ToolName,
                format!("{}/operationId", selected.pointer),
                format!(
                    "operationId {:?} is not a valid tool name",
                    request.operation
                ),
            )
            .resolved_by([format!("--tool {suggestion}")]),
        );
        None
    }

    fn server(&mut self, request: &Request, selected: &Selected<'a>) -> Option<Server> {
        let (servers, pointer) = [
            (
                selected.operation.get("servers"),
                format!("{}/servers", selected.pointer),
            ),
            (
                selected.item.get("servers"),
                format!("{}/servers", selected.item_pointer),
            ),
            (self.document.get("servers"), "#/servers".to_owned()),
        ]
        .into_iter()
        .find(|(servers, _)| servers.is_some())
        .map_or((None, "#/servers".to_owned()), |(servers, pointer)| {
            (servers, pointer)
        });
        let entries: Vec<(usize, &Json, &str)> = servers
            .and_then(Json::as_array)
            .unwrap_or_default()
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                entry
                    .get("url")
                    .and_then(Json::as_str)
                    .map(|url| (index, entry, url))
            })
            .collect();
        let chosen = if let Some(wanted) = &request.server {
            entries.iter().find(|(_, _, url)| url == wanted)
        } else if entries.len() == 1 {
            entries.first()
        } else {
            None
        };
        let Some((index, entry, url)) = chosen else {
            let message = match (&request.server, entries.len()) {
                (Some(wanted), _) => {
                    format!("--server {wanted:?} is not listed byte-for-byte in the document")
                }
                (None, 0) => {
                    "the document lists no server; a listed https server is required".to_owned()
                }
                (None, count) => format!("{count} servers apply; one must be selected"),
            };
            self.push(
                Diagnostic::new(DeriveCode::AmbiguousServer, pointer, message).resolved_by(
                    entries
                        .iter()
                        .take(8)
                        .map(|(_, _, url)| format!("--server {url}")),
                ),
            );
            return None;
        };
        let at = format!("{pointer}/{index}");
        if entry.get("variables").is_some() || url.contains('{') {
            self.push(Diagnostic::new(
                DeriveCode::UnsafeServer,
                at,
                "server variables are not derived",
            ));
            return None;
        }
        match parse_server(url) {
            Ok((origin, base_path)) => Some(Server {
                listed: (*url).to_owned(),
                origin,
                base_path,
            }),
            Err(reason) => {
                self.push(Diagnostic::new(DeriveCode::UnsafeServer, at, reason));
                None
            }
        }
    }

    fn security(&mut self, request: &Request, selected: &Selected<'a>) -> Option<Credential> {
        let (declared, pointer) = match selected.operation.get("security") {
            Some(list) => (Some(list), format!("{}/security", selected.pointer)),
            None => (self.document.get("security"), "#/security".to_owned()),
        };
        let requirements: Vec<(usize, &[(String, Json)])> = declared
            .and_then(Json::as_array)
            .unwrap_or_default()
            .iter()
            .enumerate()
            .filter_map(|(index, requirement)| {
                requirement.as_object().map(|entries| (index, entries))
            })
            .filter(|(_, entries)| !entries.is_empty())
            .collect();
        if declared.is_some_and(|value| value.as_array().is_none()) {
            self.push(Diagnostic::new(
                DeriveCode::UnsupportedConstruct,
                pointer,
                "security is not an array",
            ));
            return None;
        }
        if requirements.is_empty() {
            return self.security_override(request, &pointer);
        }
        if request.security_scheme.is_some() {
            self.push(Diagnostic::new(
                DeriveCode::InvalidOverride,
                pointer,
                "--security-scheme cannot replace a security requirement the document declares",
            ));
            return None;
        }
        let chosen = match &request.security {
            Some(name) => requirements
                .iter()
                .find(|(_, entries)| entries.len() == 1 && entries[0].0 == *name),
            None if requirements.len() == 1 => requirements.first(),
            None => None,
        };
        let Some((index, entries)) = chosen else {
            let options = requirements
                .iter()
                .filter(|(_, entries)| entries.len() == 1)
                .map(|(_, entries)| format!("--security {}", entries[0].0));
            let message = match &request.security {
                Some(name) => format!(
                    "--security {name:?} does not name one declared single-scheme requirement"
                ),
                None => format!(
                    "{} security requirements apply; one must be selected",
                    requirements.len()
                ),
            };
            self.push(
                Diagnostic::new(DeriveCode::AmbiguousSecurity, pointer, message)
                    .resolved_by(options),
            );
            return None;
        };
        let at = format!("{pointer}/{index}");
        if entries.len() != 1 {
            self.push(Diagnostic::new(
                DeriveCode::CredentialSchemeOutOfScope,
                at,
                "a requirement combining several schemes needs more than one static header credential",
            ));
            return None;
        }
        self.scheme(&entries[0].0, &at)
    }

    fn security_override(&mut self, request: &Request, pointer: &str) -> Option<Credential> {
        match &request.security_scheme {
            Some(SchemeOverride::Bearer) => Some(Credential {
                kind: CredentialKind::Bearer,
                scheme_name: None,
                scheme_type: "http/bearer".to_owned(),
                from_override: true,
                application_owned_acquisition: false,
            }),
            Some(SchemeOverride::ApiKey(header)) => {
                if header_allowed(header) {
                    Some(Credential {
                        kind: CredentialKind::HeaderApiKey(header.clone()),
                        scheme_name: None,
                        scheme_type: "apiKey/header".to_owned(),
                        from_override: true,
                        application_owned_acquisition: false,
                    })
                } else {
                    self.push(Diagnostic::new(
                        DeriveCode::InvalidOverride,
                        pointer,
                        format!("header {header:?} is reserved and cannot carry an API key"),
                    ));
                    None
                }
            }
            None => {
                self.push(
                    Diagnostic::new(
                        DeriveCode::MissingSecurity,
                        pointer,
                        "the document declares no security requirement for this operation",
                    )
                    .resolved_by([
                        "--security-scheme bearer".to_owned(),
                        "--security-scheme apikey:<Header-Name>".to_owned(),
                    ]),
                );
                None
            }
        }
    }

    fn scheme(&mut self, name: &str, at: &str) -> Option<Credential> {
        let scheme_pointer = format!("#/components/securitySchemes/{}", escape_token(name));
        let found = self
            .document
            .get("components")
            .and_then(|components| components.get("securitySchemes"))
            .and_then(|schemes| schemes.get(name))
            .map(|scheme| resolve(self.document, scheme, scheme_pointer.clone()));
        let (scheme, scheme_pointer) = match found {
            Some(Ok(found)) => found,
            Some(Err(error)) => {
                self.push(error);
                return None;
            }
            None => {
                self.push(Diagnostic::new(
                    DeriveCode::UnsupportedConstruct,
                    at,
                    format!("security scheme {name:?} is not declared"),
                ));
                return None;
            }
        };
        let text = |key: &str| scheme.get(key).and_then(Json::as_str).unwrap_or_default();
        let credential = |kind, scheme_type: &str, application_owned_acquisition| Credential {
            kind,
            scheme_name: Some(name.to_owned()),
            scheme_type: scheme_type.to_owned(),
            from_override: false,
            application_owned_acquisition,
        };
        match (
            text("type"),
            text("scheme").to_ascii_lowercase().as_str(),
            text("in"),
        ) {
            ("http", "bearer", _) => Some(credential(CredentialKind::Bearer, "http/bearer", false)),
            ("oauth2", _, _) => Some(credential(CredentialKind::Bearer, "oauth2", true)),
            ("apiKey", _, "header") if header_allowed(text("name")) => Some(credential(
                CredentialKind::HeaderApiKey(text("name").to_owned()),
                "apiKey/header",
                false,
            )),
            (kind, scheme_name, location) => {
                let described = match kind {
                    "http" => format!("http/{scheme_name}"),
                    "apiKey" => format!("apiKey in {location} named {:?}", text("name")),
                    other => other.to_owned(),
                };
                self.push(Diagnostic::new(
                    DeriveCode::CredentialSchemeOutOfScope,
                    scheme_pointer,
                    format!("security scheme {name:?} is {described}; only bearer and one non-reserved API-key header are in scope"),
                ));
                None
            }
        }
    }

    fn parameters(&mut self, selected: &Selected<'a>) -> Vec<Parameter<'a>> {
        let mut found: Vec<Parameter<'a>> = Vec::new();
        for (container, base) in [
            (selected.item.get("parameters"), &selected.item_pointer),
            (selected.operation.get("parameters"), &selected.pointer),
        ] {
            let Some(container) = container else { continue };
            let Some(items) = container.as_array() else {
                self.push(Diagnostic::new(
                    DeriveCode::UnsupportedConstruct,
                    format!("{base}/parameters"),
                    "parameters is not an array",
                ));
                continue;
            };
            for (index, item) in items.iter().enumerate() {
                let (node, pointer) =
                    match resolve(self.document, item, format!("{base}/parameters/{index}")) {
                        Ok(found) => found,
                        Err(error) => {
                            self.push(error);
                            continue;
                        }
                    };
                let (Some(name), Some(location)) = (
                    node.get("name").and_then(Json::as_str),
                    node.get("in").and_then(Json::as_str),
                ) else {
                    self.push(Diagnostic::new(
                        DeriveCode::UnsupportedConstruct,
                        pointer,
                        "parameter has no name or location",
                    ));
                    continue;
                };
                found.retain(|existing| !(existing.name == name && existing.location == location));
                found.push(Parameter {
                    name: name.to_owned(),
                    location: location.to_owned(),
                    node,
                    pointer,
                });
            }
        }
        let mut path_parameters = Vec::new();
        for parameter in found {
            if parameter.location == "path" {
                path_parameters.push(parameter);
                continue;
            }
            let required = parameter.node.get("required").and_then(Json::as_bool) == Some(true);
            if !required && self.overrides.omit.take(&parameter.name).is_some() {
                self.omitted.push(Omitted {
                    pointer: parameter.pointer,
                    path: parameter.name,
                    reason: "--omit",
                });
                continue;
            }
            let code = if parameter.location == "query" {
                DeriveCode::QueryParameter
            } else {
                DeriveCode::UnsupportedParameter
            };
            self.push(
                Diagnostic::new(
                    code,
                    parameter.pointer,
                    format!(
                        "{} parameter {:?} has no form in the recipe language",
                        parameter.location, parameter.name
                    ),
                )
                .resolved_by((!required).then(|| format!("--omit {}", parameter.name))),
            );
        }
        path_parameters
    }

    fn path(
        &mut self,
        selected: &Selected<'a>,
        parameters: &[Parameter<'a>],
        server: Option<&Server>,
    ) -> Option<Vec<Segment>> {
        let template_pointer = selected.item_pointer.clone();
        let invalid = |message: String| {
            Diagnostic::new(
                DeriveCode::UnsupportedConstruct,
                template_pointer.clone(),
                message,
            )
        };
        let Some(rest) = selected.path.strip_prefix('/') else {
            self.push(invalid(format!(
                "path {:?} does not start with /",
                selected.path
            )));
            return None;
        };
        let mut segments: Vec<Segment> = server
            .map(|server| {
                server
                    .base_path
                    .iter()
                    .cloned()
                    .map(Segment::Fixed)
                    .collect()
            })
            .unwrap_or_default();
        let mut used: Vec<&str> = Vec::new();
        let mut failed = false;
        for raw in rest.split('/').filter(|_| !rest.is_empty()) {
            let variable = raw
                .strip_prefix('{')
                .and_then(|inner| inner.strip_suffix('}'));
            match variable {
                Some(name) if !name.contains(['{', '}']) && !name.is_empty() => {
                    let Some(parameter) =
                        parameters.iter().find(|parameter| parameter.name == name)
                    else {
                        self.push(invalid(format!(
                            "template variable {name:?} has no path parameter"
                        )));
                        failed = true;
                        continue;
                    };
                    if used.contains(&name) {
                        self.push(invalid(format!("template variable {name:?} repeats")));
                        failed = true;
                        continue;
                    }
                    used.push(name);
                    match self.path_parameter(parameter) {
                        Some(segment) => segments.push(segment),
                        None => failed = true,
                    }
                }
                _ if valid_fixed_segment(raw) => segments.push(Segment::Fixed(raw.to_owned())),
                _ if raw.is_empty() => {
                    self.push(invalid(
                        "an empty path segment or trailing slash has no recipe form".to_owned(),
                    ));
                    failed = true;
                }
                _ => {
                    self.push(invalid(format!("path segment {raw:?} is not a safe fixed literal or a whole template variable")));
                    failed = true;
                }
            }
        }
        for parameter in parameters
            .iter()
            .filter(|parameter| !used.contains(&parameter.name.as_str()))
        {
            self.push(Diagnostic::new(
                DeriveCode::UnsupportedConstruct,
                parameter.pointer.clone(),
                format!(
                    "path parameter {:?} is not in the path template",
                    parameter.name
                ),
            ));
            failed = true;
        }
        if segments.is_empty() || segments.len() > MAX_PATH_SEGMENTS {
            self.push(Diagnostic::new(
                DeriveCode::CompilerLimit,
                template_pointer,
                "the gateway recipe compiler needs 1 to 16 path segments",
            ));
            return None;
        }
        (!failed).then_some(segments)
    }

    /// Resolves a path parameter's schema after checking its serialization.
    fn path_schema(&mut self, parameter: &Parameter<'a>) -> Option<(&'a Json, String)> {
        let node = parameter.node;
        let fail = |message: &str| {
            Diagnostic::new(
                DeriveCode::UnsupportedConstruct,
                parameter.pointer.clone(),
                message.to_owned(),
            )
        };
        if node.get("required").and_then(Json::as_bool) != Some(true) {
            self.push(fail("a path parameter must be required"));
            return None;
        }
        if node.get("content").is_some()
            || node
                .get("style")
                .is_some_and(|style| style.as_str() != Some("simple"))
        {
            self.push(fail(
                "path parameter serialization other than simple style is not derived",
            ));
            return None;
        }
        let Some(schema) = node.get("schema") else {
            self.push(fail("path parameter has no schema"));
            return None;
        };
        resolve(
            self.document,
            schema,
            format!("{}/schema", parameter.pointer),
        )
        .map_err(|error| self.push(error))
        .ok()
    }

    fn path_literal(
        &mut self,
        schema: &'a Json,
        pointer: String,
        name: &str,
        literal: &Literal,
    ) -> Option<Segment> {
        let text = match literal {
            Literal::String(text) => text.clone(),
            Literal::Integer(number) => number.to_string(),
            Literal::Boolean(flag) => flag.to_string(),
        };
        match self.literal_fits(schema, &pointer, name, literal) {
            Ok(()) if valid_fixed_segment(&text) => Some(Segment::Fixed(text)),
            Ok(()) => {
                self.push(Diagnostic::new(
                    DeriveCode::InvalidOverride,
                    pointer,
                    format!("--literal {name} does not render as a safe fixed path segment"),
                ));
                None
            }
            Err(error) => {
                self.push(error);
                None
            }
        }
    }

    fn path_parameter(&mut self, parameter: &Parameter<'a>) -> Option<Segment> {
        let name = parameter.name.as_str();
        let (schema, pointer) = self.path_schema(parameter)?;
        if let Some(literal) = self.overrides.literal.take(name) {
            return self.path_literal(schema, pointer, name, &literal);
        }
        if !valid_argument_name(name) {
            self.push(
                Diagnostic::new(
                    DeriveCode::InvalidName,
                    parameter.pointer.clone(),
                    format!("path parameter name {name:?} is not a generated field name"),
                )
                .resolved_by([format!("--literal {name}=<value>")]),
            );
            return None;
        }
        let schema = match self
            .alternatives(schema, &pointer)
            .and_then(|found| self.select(found, name, &pointer))
            .and_then(|alternative| self.scalar(&alternative, name))
        {
            // The gateway refuses an empty segment at request time, so the
            // contract never admits one.
            Ok(ArgSchema::String { min: 0, max }) if max >= 1 => ArgSchema::String { min: 1, max },
            Ok(schema) => schema,
            Err(error) => {
                self.push(error);
                return None;
            }
        };
        if !schema.is_string_like() {
            self.push(
                Diagnostic::new(
                    DeriveCode::CompilerLimit,
                    pointer,
                    format!("path parameter {name:?} is not a string; the gateway compiler percent-encodes string segments only"),
                )
                .resolved_by([format!("--literal {name}=<value>")]),
            );
            return None;
        }
        self.arguments.push(Argument {
            name: name.to_owned(),
            schema,
            pointer,
        });
        Some(Segment::Field(name.to_owned()))
    }

    fn body(&mut self, selected: &Selected<'a>) -> Option<(Media, Vec<(String, Template)>)> {
        let base = format!("{}/requestBody", selected.pointer);
        let unsupported = |pointer: String, message: &str| {
            Diagnostic::new(DeriveCode::UnsupportedBody, pointer, message.to_owned())
        };
        let Some(raw) = selected.operation.get("requestBody") else {
            self.push(Diagnostic::new(
                DeriveCode::CompilerLimit,
                base,
                "the operation has no request body; the gateway recipe compiler needs a non-empty body",
            ));
            return None;
        };
        let (body, pointer) = match resolve(self.document, raw, base) {
            Ok(found) => found,
            Err(error) => {
                self.push(error);
                return None;
            }
        };
        if body.get("required").and_then(Json::as_bool) != Some(true) {
            self.push(unsupported(
                pointer,
                "the request body is not required: true",
            ));
            return None;
        }
        let content = body
            .get("content")
            .and_then(Json::as_object)
            .unwrap_or_default();
        let [(media_type, media_object)] = content else {
            self.push(unsupported(
                format!("{pointer}/content"),
                "the request body must declare exactly one media type",
            ));
            return None;
        };
        let media_pointer = format!("{pointer}/content/{}", escape_token(media_type));
        let media = match media_type.as_str() {
            "application/json" => Media::Json,
            "application/x-www-form-urlencoded" if media_object.get("encoding").is_none() => {
                Media::Form
            }
            _ => {
                self.push(unsupported(media_pointer, "only application/json and plain application/x-www-form-urlencoded bodies are derived"));
                return None;
            }
        };
        let Some(schema) = media_object.get("schema") else {
            self.push(unsupported(media_pointer, "the media type has no schema"));
            return None;
        };
        let (schema, schema_pointer) =
            match resolve(self.document, schema, format!("{media_pointer}/schema")) {
                Ok(found) => found,
                Err(error) => {
                    self.push(error);
                    return None;
                }
            };
        match self.alternatives(schema, &schema_pointer) {
            Ok(alternatives) if alternatives.len() == 1 && alternatives[0].kind == Kind::Object => {
            }
            Ok(_) => {
                self.push(Diagnostic::new(
                    DeriveCode::UnsupportedConstruct,
                    schema_pointer,
                    "the request body schema is not a single non-nullable object",
                ));
                return None;
            }
            Err(error) => {
                self.push(error);
                return None;
            }
        }
        self.object(schema, &schema_pointer, None, "", 1, media)
            .map(|fields| (media, fields))
    }

    fn limits(&mut self, request: &Request, body: Option<&(Media, Vec<(String, Template)>)>) {
        let mut names: Vec<&str> = BINDING_FIELDS.to_vec();
        let mut collisions = Vec::new();
        for argument in &self.arguments {
            if names.contains(&argument.name.as_str()) {
                collisions.push(Diagnostic::new(
                    DeriveCode::NameCollision,
                    argument.pointer.clone(),
                    format!(
                        "argument {:?} is derived twice or collides with a gateway binding field",
                        argument.name
                    ),
                ));
            }
            names.push(&argument.name);
        }
        self.diagnostics.extend(collisions);
        if !self.diagnostics.is_empty() {
            return;
        }
        let at = self
            .arguments
            .first()
            .map(|argument| argument.pointer.clone())
            .unwrap_or_default();
        let total = self.arguments.len() + BINDING_FIELDS.len();
        if total > MAX_FIELDS {
            self.push(Diagnostic::new(
                DeriveCode::FieldLimit,
                at.clone(),
                format!("{total} fields including the three gateway binding fields exceed 32"),
            ));
        }
        let worst = worst_case_json(&self.arguments, &request.operator_namespace);
        if worst > MAX_ARGUMENT_JSON_BYTES {
            self.push(Diagnostic::new(
                DeriveCode::FieldLimit,
                at.clone(),
                format!("worst-case canonical arguments are {worst} bytes; the limit is 4096"),
            ));
        }
        if let Some((media, fields)) = body {
            let nodes: usize = 1 + fields
                .iter()
                .map(|(_, template)| template.nodes())
                .sum::<usize>();
            if nodes > MAX_TEMPLATE_NODES
                || (*media == Media::Form && fields.len() > MAX_FORM_FIELDS)
            {
                self.push(Diagnostic::new(
                    DeriveCode::CompilerLimit,
                    at,
                    "the body template exceeds the gateway recipe compiler's node or form-field limit",
                ));
            }
        }
    }
}

/// Worst-case canonical argument JSON bytes, binding fields included, using
/// the packaged profile generator's formula.
pub(crate) fn worst_case_json(arguments: &[Argument], namespace: &str) -> usize {
    let binding = [
        (
            "operator_namespace",
            ArgSchema::Enum(vec![namespace.to_owned()]),
        ),
        (
            "operation_id",
            ArgSchema::String {
                min: 1,
                max: OPERATION_ID_MAX_BYTES,
            },
        ),
        ("recipe_digest", ArgSchema::String { min: 64, max: 64 }),
    ];
    let entries = binding
        .iter()
        .map(|(name, schema)| (name.len(), schema.worst_case_bytes()))
        .chain(
            arguments
                .iter()
                .map(|argument| (argument.name.len(), argument.schema.worst_case_bytes())),
        );
    let mut count = 0;
    let mut total = 2;
    for (name, value) in entries {
        count += 1;
        total += 2 + name + 1 + value;
    }
    total + count - 1
}

/// Reserved headers a static API key may never occupy.
fn header_allowed(header: &str) -> bool {
    !header.is_empty()
        && header.len() <= 64
        && header
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte.is_ascii_alphanumeric() || (index > 0 && byte == b'-'))
        && !matches!(
            header.to_ascii_lowercase().as_str(),
            "authorization"
                | "host"
                | "cookie"
                | "set-cookie"
                | "content-type"
                | "content-length"
                | "accept"
                | "connection"
                | "transfer-encoding"
        )
}

/// Splits a listed server into a pinned origin and fixed leading segments.
fn parse_server(url: &str) -> Result<(String, Vec<String>), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("server {url:?} is not an https URL"))?;
    if rest.contains(['?', '#', '@', '\\']) {
        return Err(format!(
            "server {url:?} has a query, fragment, or user information"
        ));
    }
    let (host, path) = rest
        .split_once('/')
        .map_or((rest, ""), |(host, path)| (host, path));
    let labels: Vec<&str> = host.split('.').collect();
    let valid_host = !host.is_empty()
        && host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        && !labels
            .last()
            .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
        && !matches!(labels.last(), Some(&("localhost" | "local" | "internal")));
    if !valid_host {
        return Err(format!(
            "server {url:?} is not a public lowercase DNS host without a port"
        ));
    }
    let mut segments: Vec<String> = path.split('/').map(str::to_owned).collect();
    if segments.last().is_some_and(String::is_empty) {
        segments.pop();
    }
    if let Some(bad) = segments
        .iter()
        .find(|segment| !valid_fixed_segment(segment))
    {
        return Err(format!(
            "server path segment {bad:?} is not a safe fixed literal"
        ));
    }
    Ok((format!("https://{host}"), segments))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_base_paths_become_fixed_segments() {
        assert_eq!(
            parse_server("https://api.github.com").unwrap(),
            ("https://api.github.com".to_owned(), vec![])
        );
        assert_eq!(
            parse_server("https://api.todoist.com/").unwrap(),
            ("https://api.todoist.com".to_owned(), vec![])
        );
        assert_eq!(
            parse_server("https://api.openai.com/v1").unwrap(),
            ("https://api.openai.com".to_owned(), vec!["v1".to_owned()])
        );
        for bad in [
            "http://api.example.com",
            "https://api.example.com:8443",
            "https://user@api.example.com",
            "https://localhost",
            "https://api.local",
            "https://10.0.0.1",
            "https://API.example.com",
            "https://api.example.com/v1//x",
            "https://api.example.com/a?b=1",
            "https://api.example.com/..",
            "https://example",
        ] {
            assert!(parse_server(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn reserved_headers_cannot_carry_an_api_key() {
        assert!(header_allowed("X-Api-Key"));
        for header in ["Authorization", "cookie", "Host", "-X", ""] {
            assert!(!header_allowed(header), "{header}");
        }
    }
}
