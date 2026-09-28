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
    AccountScopePlan, ActionReadPlan, BodyPlan, CredentialReadPlan, FormPiece, Header, HeaderPlan,
    JsonPiece, RequestMethod, ScopeGrammar, SegmentPlan, WritePlan, append_form_encoded,
    append_json_string,
};
use super::source::{
    BodySource, EchoPlacement, FormExpr, IdempotencySource, PathSegment, RecipeSource, ValueExpr,
};
use super::{
    FieldSchema, GatewayRecipeError, HeaderGrammar, IDEMPOTENCY_HEADER, WriteMethod,
    provider_header,
};
use std::collections::BTreeMap;

/// Every plan of one compiled recipe.
#[derive(Clone, Debug)]
pub(super) struct Plans {
    pub(super) write: WritePlan,
    /// Present only for a verified-locator observation.
    pub(super) observation: Option<ActionReadPlan>,
    pub(super) pre_entry: Option<ActionReadPlan>,
    pub(super) relative_ceiling: Option<ActionReadPlan>,
    pub(super) probe: Option<CredentialReadPlan>,
    pub(super) account: Option<CredentialReadPlan>,
    pub(super) denied: Vec<CredentialReadPlan>,
}

struct Lowering<'a> {
    fields: &'a BTreeMap<String, FieldSchema>,
    origin: Vec<u8>,
    headers: HeaderPlan,
}

/// Accumulates JSON pieces, merging adjacent pre-rendered bytes.
#[derive(Default)]
struct JsonPieces {
    pieces: Vec<JsonPiece>,
    raw: Vec<u8>,
}

impl JsonPieces {
    fn raw(&mut self, bytes: &[u8]) {
        self.raw.extend_from_slice(bytes);
    }

    fn piece(&mut self, piece: JsonPiece) {
        self.flush();
        self.pieces.push(piece);
    }

    fn flush(&mut self) {
        if !self.raw.is_empty() {
            self.pieces
                .push(JsonPiece::Raw(std::mem::take(&mut self.raw)));
        }
    }

    fn finish(mut self) -> Vec<JsonPiece> {
        self.flush();
        self.pieces
    }
}

/// Accumulates form pieces, merging adjacent pre-rendered bytes.
#[derive(Default)]
struct FormPieces {
    pieces: Vec<FormPiece>,
    raw: Vec<u8>,
}

impl FormPieces {
    fn raw(&mut self, bytes: &[u8]) {
        self.raw.extend_from_slice(bytes);
    }

    fn piece(&mut self, piece: FormPiece) {
        if !self.raw.is_empty() {
            self.pieces
                .push(FormPiece::Raw(std::mem::take(&mut self.raw)));
        }
        self.pieces.push(piece);
    }

    fn finish(mut self) -> Vec<FormPiece> {
        if !self.raw.is_empty() {
            self.pieces.push(FormPiece::Raw(self.raw));
        }
        self.pieces
    }
}

/// One member of a JSON object template, in canonical order.
enum Member<'a> {
    Value(&'a ValueExpr, Option<&'a [String]>),
    Echo,
}

/// One field of a form template, in canonical order.
enum FormMember<'a> {
    Value(&'a FormExpr),
    Echo,
}

const fn method(method: WriteMethod) -> RequestMethod {
    match method {
        WriteMethod::Post => RequestMethod::Post,
        WriteMethod::Put => RequestMethod::Put,
        WriteMethod::Patch => RequestMethod::Patch,
        WriteMethod::Delete => RequestMethod::Delete,
    }
}

fn form_encoded(text: &str) -> Vec<u8> {
    append_form_encoded(Vec::new(), text.as_bytes())
}

impl Lowering<'_> {
    fn index(&self, name: &str) -> Result<usize, GatewayRecipeError> {
        self.fields
            .keys()
            .position(|field| field == name)
            .ok_or(GatewayRecipeError::InvalidSource)
    }

    fn path(&self, path: &[PathSegment]) -> Result<Vec<SegmentPlan>, GatewayRecipeError> {
        path.iter()
            .map(|segment| match segment {
                PathSegment::Fixed { value } => Ok(SegmentPlan::Fixed(value.as_bytes().to_vec())),
                PathSegment::Field { name } => self.index(name).map(SegmentPlan::Field),
                PathSegment::ResponseField { .. } | PathSegment::Echo => {
                    Err(GatewayRecipeError::InvalidSource)
                }
            })
            .collect()
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
        let path = path
            .iter()
            .map(|segment| match segment {
                PathSegment::Fixed { value } => Ok(value.as_bytes().to_vec()),
                _ => Err(GatewayRecipeError::InvalidSource),
            })
            .collect::<Result<_, _>>()?;
        Ok(CredentialReadPlan {
            method,
            origin: self.origin.clone(),
            path,
            versions: self.headers.versions.clone(),
        })
    }

    fn json_value(
        &self,
        value: &ValueExpr,
        echo: Option<&[String]>,
        out: &mut JsonPieces,
    ) -> Result<(), GatewayRecipeError> {
        match value {
            ValueExpr::String { value } => {
                out.raw(&append_json_string(Vec::new(), value.as_bytes()));
            }
            ValueExpr::Integer { value } => out.raw(value.to_string().as_bytes()),
            ValueExpr::Boolean { value } => out.raw(if *value { b"true" } else { b"false" }),
            ValueExpr::Field { name } => out.piece(JsonPiece::Field(self.index(name)?)),
            ValueExpr::Array { items } => {
                out.raw(b"[");
                for (position, item) in items.iter().enumerate() {
                    if position > 0 {
                        out.raw(b",");
                    }
                    self.json_value(item, None, out)?;
                }
                out.raw(b"]");
            }
            ValueExpr::Object { fields } => {
                let mut members: Vec<(&str, Member<'_>)> = fields
                    .iter()
                    .map(|(key, child)| {
                        let nested = match echo {
                            Some([first, rest @ ..]) if first == key && !rest.is_empty() => {
                                Some(rest)
                            }
                            _ => None,
                        };
                        (key.as_str(), Member::Value(child, nested))
                    })
                    .collect();
                if let Some([last]) = echo {
                    members.push((last.as_str(), Member::Echo));
                }
                members.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
                out.raw(b"{");
                for (position, (key, member)) in members.into_iter().enumerate() {
                    if position > 0 {
                        out.raw(b",");
                    }
                    out.raw(&append_json_string(Vec::new(), key.as_bytes()));
                    out.raw(b":");
                    match member {
                        Member::Value(child, nested) => self.json_value(child, nested, out)?,
                        Member::Echo => out.piece(JsonPiece::Echo),
                    }
                }
                out.raw(b"}");
            }
            ValueExpr::Echo => return Err(GatewayRecipeError::EchoConflict),
        }
        Ok(())
    }

    fn body(
        &self,
        body: &BodySource,
        echo: Option<&EchoPlacement>,
    ) -> Result<BodyPlan, GatewayRecipeError> {
        match body {
            BodySource::Json { value } => {
                let tokens: Option<Vec<String>> = match echo {
                    Some(EchoPlacement::JsonPointer { pointer }) => {
                        Some(pointer.split('/').skip(1).map(str::to_owned).collect())
                    }
                    Some(EchoPlacement::FormField { .. }) => {
                        return Err(GatewayRecipeError::EchoConflict);
                    }
                    None => None,
                };
                let mut pieces = JsonPieces::default();
                self.json_value(value, tokens.as_deref(), &mut pieces)?;
                Ok(BodyPlan::Json(pieces.finish()))
            }
            BodySource::Form { fields } => {
                let mut members: Vec<(&str, FormMember<'_>)> = fields
                    .iter()
                    .map(|(name, value)| (name.as_str(), FormMember::Value(value)))
                    .collect();
                match echo {
                    Some(EchoPlacement::FormField { name }) => {
                        members.push((name.as_str(), FormMember::Echo));
                    }
                    Some(EchoPlacement::JsonPointer { .. }) => {
                        return Err(GatewayRecipeError::EchoConflict);
                    }
                    None => {}
                }
                members.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
                let mut pieces = FormPieces::default();
                for (position, (name, member)) in members.into_iter().enumerate() {
                    if position > 0 {
                        pieces.raw(b"&");
                    }
                    pieces.raw(&form_encoded(name));
                    pieces.raw(b"=");
                    match member {
                        FormMember::Echo => pieces.piece(FormPiece::Echo),
                        FormMember::Value(FormExpr::String { value }) => {
                            pieces.raw(&form_encoded(value));
                        }
                        FormMember::Value(FormExpr::Field { name }) => {
                            pieces.piece(FormPiece::Field(self.index(name)?));
                        }
                        FormMember::Value(FormExpr::Json { value }) => {
                            let mut json = JsonPieces::default();
                            self.json_value(value, None, &mut json)?;
                            pieces.piece(FormPiece::Json(json.finish()));
                        }
                        FormMember::Value(FormExpr::Echo) => {
                            return Err(GatewayRecipeError::EchoConflict);
                        }
                    }
                }
                Ok(BodyPlan::Form(pieces.finish()))
            }
        }
    }
}

fn header_plan(
    source: &RecipeSource,
    fields: &BTreeMap<String, FieldSchema>,
) -> Result<HeaderPlan, GatewayRecipeError> {
    let versions = source
        .provider_headers
        .iter()
        .flatten()
        .map(|(name, value)| Header {
            name: name.as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
        })
        .collect();
    let account_scope = source
        .account_scope
        .as_ref()
        .map(|scope| {
            let entry =
                provider_header(&scope.header).ok_or(GatewayRecipeError::InvalidAccountScope)?;
            let grammar = match entry.grammar {
                HeaderGrammar::StripeAccount => ScopeGrammar::StripeAccount,
                HeaderGrammar::StripeVersion | HeaderGrammar::IsoDate => {
                    return Err(GatewayRecipeError::InvalidAccountScope);
                }
            };
            let field = fields
                .keys()
                .position(|name| *name == scope.field)
                .ok_or(GatewayRecipeError::InvalidAccountScope)?;
            Ok(AccountScopePlan {
                name: scope.header.as_bytes().to_vec(),
                field,
                grammar,
            })
        })
        .transpose()?;
    Ok(HeaderPlan {
        versions,
        account_scope,
    })
}

/// Lowers a source the compile rules accepted.
pub(super) fn plans(
    source: &RecipeSource,
    fields: &BTreeMap<String, FieldSchema>,
) -> Result<Plans, GatewayRecipeError> {
    let lowering = Lowering {
        fields,
        origin: source.origin.as_bytes().to_vec(),
        headers: header_plan(source, fields)?,
    };
    let write = WritePlan {
        method: method(source.write.method),
        origin: lowering.origin.clone(),
        path: lowering.path(&source.write.path)?,
        headers: lowering.headers.clone(),
        idempotency_header: matches!(
            source.write.idempotency,
            Some(IdempotencySource::DerivedHeader { .. })
        )
        .then(|| IDEMPOTENCY_HEADER.as_bytes().to_vec()),
        body: lowering.body(
            &source.write.body,
            source.echo.as_ref().map(|echo| &echo.write),
        )?,
    };
    let observation = source
        .observation
        .as_ref()
        .filter(|observation| {
            !observation
                .path
                .iter()
                .any(|segment| matches!(segment, PathSegment::ResponseField { .. }))
        })
        .map(|observation| lowering.action_read(&observation.path))
        .transpose()?;
    let pre_entry = source
        .pre_entry
        .as_ref()
        .map(|pre_entry| lowering.action_read(&pre_entry.path))
        .transpose()?;
    let relative_ceiling = source
        .relative_ceiling
        .as_ref()
        .map(|ceiling| lowering.action_read(&ceiling.path))
        .transpose()?;
    let guard = source.credential.guard();
    let probe = guard
        .and_then(|guard| guard.probe.as_ref())
        .map(|probe| lowering.credential_read(RequestMethod::Get, &probe.path))
        .transpose()?;
    let account = guard
        .and_then(|guard| guard.account.as_ref())
        .map(|account| lowering.credential_read(RequestMethod::Get, &account.path))
        .transpose()?;
    let denied = guard
        .and_then(|guard| guard.denied_reads.as_ref())
        .into_iter()
        .flatten()
        .map(|read| {
            let method = if read.method == "HEAD" {
                RequestMethod::Head
            } else {
                RequestMethod::Get
            };
            lowering.credential_read(method, &read.path)
        })
        .collect::<Result<_, _>>()?;
    Ok(Plans {
        write,
        observation,
        pre_entry,
        relative_ceiling,
        probe,
        account,
        denied,
    })
}
