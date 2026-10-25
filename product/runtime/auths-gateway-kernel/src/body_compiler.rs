//! Exact-name lowering of the compiler's existing JSON/form template pieces.
//!
//! These carriers are an internal view of an already decoded template. They
//! have no wire format and grant no authority. Source traversal chooses the
//! approved literal bytes and echo location; this module resolves every named
//! value against the same immutable layout as path compilation and projection.

use alloc::vec::Vec;

use crate::arguments::MAX_PROFILE_FIELDS;
use crate::construct::{ConstructError, FormPiece, JsonPiece, copy_bytes};
use crate::path_compiler::lower_field;

/// A validated 64-node template has at most this many alternating raw/dynamic
/// pieces, including form separators and a compiler-inserted echo.
pub const MAX_TEMPLATE_PIECES: usize = 256;
/// Aggregate compilation envelope for all literal bytes in one template.
/// This exceeds the
/// 64-node, 1024-byte-literal, six-byte JSON escaping envelope, including
/// approved object keys. The outbound body retains its separate 16 KiB cap.
pub const MAX_TEMPLATE_LITERAL_BYTES: usize = 524_288;

/// A JSON template piece before profile names become positional indices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamedJsonPiece {
    /// Exact canonical literal/syntax bytes chosen by source traversal.
    Raw(Vec<u8>),
    /// One exact profile field name, with no case folding or coercion.
    Field(Vec<u8>),
    /// The compiler-selected gateway echo location.
    Echo,
}

/// A form template piece before profile names become positional indices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamedFormPiece {
    /// Exact pre-encoded literal/syntax bytes chosen by source traversal.
    Raw(Vec<u8>),
    /// One exact profile field name.
    Field(Vec<u8>),
    /// A canonical JSON template that the request writer form-encodes once.
    Json(Vec<NamedJsonPiece>),
    /// The compiler-selected gateway echo location.
    Echo,
}

/// Exact resource totals before any compiled literal is copied. Nested JSON
/// contributes to the same form budget; starting another JSON value does not
/// reset either total.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceUse {
    /// Total pre-rendered literal bytes, including nested form JSON.
    pub literal_bytes: usize,
    /// Total field/echo markers, including nested form JSON.
    pub dynamic_pieces: usize,
}

/// Adds a contribution only when both the old and resulting totals fit.
/// All subtractions and additions occur after bounds that prevent overflow.
#[must_use]
pub fn add_resources(current: ResourceUse, literal_bytes: usize, dynamic_pieces: usize) -> Option<ResourceUse> {
    if current.literal_bytes > MAX_TEMPLATE_LITERAL_BYTES
        || current.dynamic_pieces > MAX_TEMPLATE_PIECES
        || literal_bytes > MAX_TEMPLATE_LITERAL_BYTES - current.literal_bytes
        || dynamic_pieces > MAX_TEMPLATE_PIECES - current.dynamic_pieces
    {
        return None;
    }
    Some(ResourceUse {
        literal_bytes: current.literal_bytes + literal_bytes,
        dynamic_pieces: current.dynamic_pieces + dynamic_pieces,
    })
}

/// Checks the complete JSON template's totals without allocating or copying
/// literals. Refuses more than 256 pieces, 524288 literal bytes or 256 dynamic
/// markers; returns the exact totals on success.
#[must_use]
pub fn json_resources(pieces: &[NamedJsonPiece]) -> Option<ResourceUse> {
    if pieces.len() > MAX_TEMPLATE_PIECES {
        return None;
    }
    let mut used = ResourceUse { literal_bytes: 0, dynamic_pieces: 0 };
    let mut position = 0;
    while position < pieces.len() {
        let next = match &pieces[position] {
            NamedJsonPiece::Raw(bytes) => add_resources(used, bytes.len(), 0),
            NamedJsonPiece::Field(_) | NamedJsonPiece::Echo => add_resources(used, 0, 1),
        };
        match next {
            Some(next) => used = next,
            None => return None,
        }
        position += 1;
    }
    Some(used)
}

/// Charges one form piece, including all nested JSON, to the current budget.
/// Refuses a malformed or oversized current budget rather than resetting it.
#[must_use]
pub fn form_piece_resources(current: ResourceUse, piece: &NamedFormPiece) -> Option<ResourceUse> {
    match piece {
        NamedFormPiece::Raw(bytes) => add_resources(current, bytes.len(), 0),
        NamedFormPiece::Field(_) | NamedFormPiece::Echo => add_resources(current, 0, 1),
        NamedFormPiece::Json(pieces) => match json_resources(pieces) {
            Some(nested) => add_resources(current, nested.literal_bytes, nested.dynamic_pieces),
            None => None,
        },
    }
}

/// Checks the complete form template before lowering any piece. All nested
/// JSON values share one aggregate literal/dynamic budget. This performs no
/// action-value rendering and allocates no compiled plan.
#[must_use]
pub fn form_resources(pieces: &[NamedFormPiece]) -> Option<ResourceUse> {
    if pieces.len() > MAX_TEMPLATE_PIECES {
        return None;
    }
    let mut used = ResourceUse { literal_bytes: 0, dynamic_pieces: 0 };
    let mut position = 0;
    while position < pieces.len() {
        match form_piece_resources(used, &pieces[position]) {
            Some(next) => used = next,
            None => return None,
        }
        position += 1;
    }
    Some(used)
}

/// Lowers one named JSON piece without rendering any action value.
///
/// # Errors
/// Returns `BodySize` for a literal above the compilation envelope and
/// `ArgumentMismatch` for a malformed, absent or oversized field layout.
pub fn lower_json_piece(
    names: &[Vec<u8>],
    piece: &NamedJsonPiece,
) -> Result<JsonPiece, ConstructError> {
    match piece {
        NamedJsonPiece::Raw(bytes) => {
            if bytes.len() > MAX_TEMPLATE_LITERAL_BYTES {
                Err(ConstructError::BodySize)
            } else {
                Ok(JsonPiece::Raw(copy_bytes(bytes)))
            }
        }
        NamedJsonPiece::Field(name) => match lower_field(names, name) {
            Ok(index) => Ok(JsonPiece::Field(index)),
            Err(error) => Err(error),
        },
        NamedJsonPiece::Echo => Ok(JsonPiece::Echo),
    }
}

/// Lowers a complete named JSON template, forwarding the first piece error.
/// Empty plans are permitted here; the outbound writer refuses empty bodies.
///
/// # Errors
/// Returns `ArgumentMismatch` above 32 names or 256 pieces, then `BodySize`
/// for an invalid aggregate resource envelope. Otherwise forwards the first
/// piece error without producing a partial plan.
pub fn lower_json(
    names: &[Vec<u8>],
    pieces: &[NamedJsonPiece],
) -> Result<Vec<JsonPiece>, ConstructError> {
    if names.len() > MAX_PROFILE_FIELDS || pieces.len() > MAX_TEMPLATE_PIECES {
        return Err(ConstructError::ArgumentMismatch);
    }
    let Some(_) = json_resources(pieces) else {
        return Err(ConstructError::BodySize);
    };
    let mut output = Vec::new();
    let mut position = 0;
    while position < pieces.len() {
        let lowered = lower_json_piece(names, &pieces[position]);
        match &lowered {
            Ok(piece) => output.push(piece.clone()),
            Err(error) => return Err(*error),
        }
        position += 1;
    }
    Ok(output)
}

/// Lowers one form piece, including every field inside a nested JSON value.
///
/// # Errors
/// Forwards the exact JSON/name error, and returns `BodySize` for an oversized
/// raw literal. It performs no form or JSON escaping a second time.
pub fn lower_form_piece(
    names: &[Vec<u8>],
    piece: &NamedFormPiece,
) -> Result<FormPiece, ConstructError> {
    match piece {
        NamedFormPiece::Raw(bytes) => {
            if bytes.len() > MAX_TEMPLATE_LITERAL_BYTES {
                Err(ConstructError::BodySize)
            } else {
                Ok(FormPiece::Raw(copy_bytes(bytes)))
            }
        }
        NamedFormPiece::Field(name) => match lower_field(names, name) {
            Ok(index) => Ok(FormPiece::Field(index)),
            Err(error) => Err(error),
        },
        NamedFormPiece::Json(pieces) => {
            let lowered = lower_json(names, pieces);
            match &lowered {
                Ok(compiled) => Ok(FormPiece::Json(compiled.clone())),
                Err(error) => Err(*error),
            }
        }
        NamedFormPiece::Echo => Ok(FormPiece::Echo),
    }
}

/// Lowers a complete named form template with one fixed profile layout.
///
/// # Errors
/// Returns `ArgumentMismatch` above 32 names or 256 pieces, then `BodySize`
/// for an invalid aggregate/nested envelope. Otherwise forwards the exact
/// first piece error. No partial plan escapes an error branch.
pub fn lower_form(
    names: &[Vec<u8>],
    pieces: &[NamedFormPiece],
) -> Result<Vec<FormPiece>, ConstructError> {
    if names.len() > MAX_PROFILE_FIELDS || pieces.len() > MAX_TEMPLATE_PIECES {
        return Err(ConstructError::ArgumentMismatch);
    }
    let Some(_) = form_resources(pieces) else {
        return Err(ConstructError::BodySize);
    };
    let mut output = Vec::new();
    let mut position = 0;
    while position < pieces.len() {
        let lowered = lower_form_piece(names, &pieces[position]);
        match &lowered {
            Ok(piece) => output.push(piece.clone()),
            Err(error) => return Err(*error),
        }
        position += 1;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::construct::{ArgumentValue, BodyPlan, build_body};
    use crate::field_projection::{FieldSpec, NamedInput, field_names, project_object};
    use crate::scalars::{ScalarInput, ScalarSchema};
    use alloc::vec;

    #[test]
    fn raw_bytes_names_echo_and_nested_json_keep_their_exact_meaning() {
        let fields = [
            FieldSpec { name: b"record".to_vec(), schema: ScalarSchema::String { minimum: 0, maximum: 64 } },
            FieldSpec { name: b"amount".to_vec(), schema: ScalarSchema::Integer { minimum: -100, maximum: 100 } },
            FieldSpec { name: b"enabled".to_vec(), schema: ScalarSchema::Boolean },
        ];
        let names = field_names(&fields).unwrap();
        let supplied = [
            NamedInput { name: b"enabled", value: ScalarInput::Boolean(true) },
            NamedInput { name: b"amount", value: ScalarInput::Integer(-17) },
            NamedInput { name: b"record", value: ScalarInput::Text("x/é\n\"".as_bytes()) },
        ];
        let arguments = project_object(&fields, &supplied).unwrap();
        let source = vec![
            NamedJsonPiece::Raw(b"{\"a\":".to_vec()), NamedJsonPiece::Field(b"amount".to_vec()),
            NamedJsonPiece::Raw(b",\"b\":".to_vec()), NamedJsonPiece::Field(b"enabled".to_vec()),
            NamedJsonPiece::Raw(b",\"echo\":".to_vec()), NamedJsonPiece::Echo,
            NamedJsonPiece::Raw(b",\"record\":".to_vec()), NamedJsonPiece::Field(b"record".to_vec()),
            NamedJsonPiece::Raw(b"}".to_vec()),
        ];
        let json = lower_json(&names, &source).unwrap();
        assert_eq!(build_body(&BodyPlan::Json(json), &arguments, b"echo+token"), Ok(
            "{\"a\":-17,\"b\":true,\"echo\":\"echo+token\",\"record\":\"x/é\\n\\\"\"}".as_bytes().to_vec()
        ));
        let form = lower_form(&names, &[
            NamedFormPiece::Raw(b"metadata=".to_vec()), NamedFormPiece::Json(source),
            NamedFormPiece::Raw(b"&token=".to_vec()), NamedFormPiece::Echo,
        ]).unwrap();
        assert_eq!(build_body(&BodyPlan::Form(form), &arguments, b"echo+token"), Ok(
            b"metadata=%7B%22a%22%3A-17%2C%22b%22%3Atrue%2C%22echo%22%3A%22echo%2Btoken%22%2C%22record%22%3A%22x%2F%C3%A9%5Cn%5C%22%22%7D&token=echo%2Btoken".to_vec()
        ));
    }

    #[test]
    fn similar_names_and_all_field_kinds_are_resolved_without_coercion() {
        let names = vec![b"a".to_vec(), b"a.b".to_vec(), b"b".to_vec()];
        assert_eq!(lower_json(&names, &[
            NamedJsonPiece::Field(b"b".to_vec()), NamedJsonPiece::Field(b"a.b".to_vec()),
        ]), Ok(vec![JsonPiece::Field(2), JsonPiece::Field(1)]));
        for unknown in [b"A".as_slice(), b"a.b.c", b"a\0", b"missing"] {
            assert_eq!(lower_json(&names, &[NamedJsonPiece::Field(unknown.to_vec())]), Err(ConstructError::ArgumentMismatch));
        }
        let pieces = lower_form(&names, &[NamedFormPiece::Field(b"b".to_vec())]).unwrap();
        assert_eq!(build_body(&BodyPlan::Form(pieces), &[
            ArgumentValue::Text(vec![]), ArgumentValue::Integer(b"1".to_vec()), ArgumentValue::Boolean(true),
        ], b""), Err(ConstructError::ArgumentMismatch));
    }

    #[test]
    fn compilation_bounds_and_first_error_do_not_return_partial_plans() {
        let names = vec![b"a".to_vec()];
        let too_large = NamedJsonPiece::Raw(vec![b'x'; MAX_TEMPLATE_LITERAL_BYTES + 1]);
        let unknown = NamedJsonPiece::Field(b"missing".to_vec());
        assert_eq!(lower_json(&names, &[too_large.clone(), unknown.clone()]), Err(ConstructError::BodySize));
        // Whole-template resource refusal precedes name resolution.
        assert_eq!(lower_json(&names, &[unknown, too_large.clone()]), Err(ConstructError::BodySize));
        assert_eq!(lower_form(&names, &[NamedFormPiece::Json(vec![too_large])]), Err(ConstructError::BodySize));
        assert!(lower_json(&names, &vec![NamedJsonPiece::Echo; MAX_TEMPLATE_PIECES]).is_ok());
        assert_eq!(lower_json(&names, &vec![NamedJsonPiece::Echo; MAX_TEMPLATE_PIECES + 1]), Err(ConstructError::ArgumentMismatch));
        assert_eq!(lower_form(&vec![b"a".to_vec(); 33], &[]), Err(ConstructError::ArgumentMismatch));
    }

    #[test]
    fn resource_totals_are_exact_and_shared_across_nested_json_values() {
        let names = vec![b"a".to_vec()];
        let half = NamedJsonPiece::Raw(vec![b'x'; MAX_TEMPLATE_LITERAL_BYTES / 2]);
        assert_eq!(json_resources(&[half.clone(), half.clone()]), Some(ResourceUse {
            literal_bytes: MAX_TEMPLATE_LITERAL_BYTES, dynamic_pieces: 0,
        }));
        assert_eq!(json_resources(&[half.clone(), half.clone(), NamedJsonPiece::Raw(vec![b'x'])]), None);
        let nested = NamedFormPiece::Json(vec![half.clone()]);
        assert_eq!(form_resources(&[nested.clone(), nested.clone()]), Some(ResourceUse {
            literal_bytes: MAX_TEMPLATE_LITERAL_BYTES, dynamic_pieces: 0,
        }));
        assert_eq!(lower_form(&names, &[nested.clone(), nested, NamedFormPiece::Raw(vec![b'x'])]), Err(ConstructError::BodySize));
        let dynamics = NamedFormPiece::Json(vec![NamedJsonPiece::Field(b"a".to_vec()); MAX_TEMPLATE_PIECES / 2]);
        assert_eq!(form_resources(&[dynamics.clone(), dynamics.clone()]), Some(ResourceUse {
            literal_bytes: 0, dynamic_pieces: MAX_TEMPLATE_PIECES,
        }));
        assert_eq!(form_resources(&[dynamics.clone(), dynamics, NamedFormPiece::Echo]), None);
        let oversized_nested = NamedFormPiece::Json(vec![NamedJsonPiece::Raw(vec![]); MAX_TEMPLATE_PIECES + 1]);
        assert_eq!(form_resources(&[oversized_nested]), None);
    }

    #[test]
    fn resource_addition_refuses_word_limits_and_invalid_starting_states() {
        let empty = ResourceUse { literal_bytes: 0, dynamic_pieces: 0 };
        let full = ResourceUse { literal_bytes: MAX_TEMPLATE_LITERAL_BYTES, dynamic_pieces: MAX_TEMPLATE_PIECES };
        assert_eq!(add_resources(empty, 0, 0), Some(empty));
        assert_eq!(add_resources(empty, MAX_TEMPLATE_LITERAL_BYTES, MAX_TEMPLATE_PIECES), Some(full));
        assert_eq!(add_resources(full, 0, 0), Some(full));
        assert_eq!(add_resources(full, 1, 0), None);
        assert_eq!(add_resources(full, 0, 1), None);
        assert_eq!(add_resources(empty, usize::MAX, 0), None);
        assert_eq!(add_resources(empty, 0, usize::MAX), None);
        assert_eq!(add_resources(ResourceUse { literal_bytes: usize::MAX, dynamic_pieces: 0 }, 0, 0), None);
        assert_eq!(add_resources(ResourceUse { literal_bytes: 0, dynamic_pieces: usize::MAX }, 0, 0), None);
    }
}
