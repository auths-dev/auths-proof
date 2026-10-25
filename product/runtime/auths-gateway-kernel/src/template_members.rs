//! Canonical member selection and compiler-owned echo placement for the
//! existing JSON/form source vocabulary. These owned views have no wire
//! representation and do not extend the recipe language.

use alloc::vec::Vec;
use crate::construct::field_name_equal;
use crate::identity::valid_token;

/// Slash-inclusive byte bound of the existing JSON echo-pointer language.
pub const MAX_ECHO_POINTER_BYTES: usize = 128;
/// Maximum number of original-name tokens in a JSON echo pointer.
pub const MAX_ECHO_POINTER_TOKENS: usize = 6;

/// One original object/form key, before echo insertion or positional lowering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedKey {
    /// Exact source bytes; ordinary keys use the 1–64-byte field grammar.
    pub name: Vec<u8>,
}

/// The two existing member-count/name domains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberDomain {
    /// Nonempty JSON objects with at most 32 final members.
    Json,
    /// Nonempty forms with at most 16 final fields.
    Form,
}

/// A canonical-order choice refers to the original source entry, never an
/// argument index. Echo is a compiler-owned additional member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberChoice {
    /// The exact original entry at this position.
    Source(usize),
    /// The single new echo member.
    Echo,
}

/// The next step through a JSON echo pointer, without traversing a native AST.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EchoTarget {
    /// The last token names a new member of this object.
    Insert,
    /// The first token selects this exact original child; consume one token.
    Descend(usize),
}

/// Member/echo failures preserve the native public error families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberError {
    /// Ordinary source keys/count/order are invalid.
    Members,
    /// The declared echo is invalid, colliding, missing or over capacity.
    EchoConflict,
}

/// Exact lexicographic byte order, including prefix and empty cases.
#[must_use]
pub fn byte_less(left: &[u8], right: &[u8]) -> bool {
    let mut position = 0;
    while position < left.len() && position < right.len() {
        if left[position] < right[position] {
            return true;
        }
        if left[position] > right[position] {
            return false;
        }
        position += 1;
    }
    left.len() < right.len()
}

/// Validates the existing form echo grammar: one canonical field token, or
/// exactly `base[inner]` with each component a canonical 1–64-byte token.
#[must_use]
pub fn form_echo_name_valid(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > 130 {
        return false;
    }
    let mut position = 0;
    while position < name.len() {
        if name[position] == b'[' {
            if position == 0 || position + 2 >= name.len() || name[name.len() - 1] != b']' {
                return false;
            }
            return valid_token(&name[..position], 64)
                && valid_token(&name[position + 1..name.len() - 1], 64);
        }
        position += 1;
    }
    valid_token(name, 64)
}

/// Checks the whole ordinary-key column before any member choice is returned.
/// Strict byte order earns uniqueness; it does not trust native map iteration.
#[must_use]
pub fn keys_ordered(keys: &[NamedKey], domain: MemberDomain) -> bool {
    let maximum = match domain { MemberDomain::Json => 32, MemberDomain::Form => 16 };
    if keys.is_empty() || keys.len() > maximum {
        return false;
    }
    let mut position = 0;
    let mut ordered = true;
    while position < keys.len() && ordered {
        ordered = key_in_order(keys, position);
        position += 1;
    }
    ordered
}

// The whole-column caller supplies a current position. A previous key is
// inspected only after its subtraction is defined and this key is lexical.
fn key_in_order(keys: &[NamedKey], position: usize) -> bool {
    valid_token(&keys[position].name, 64)
        && (position == 0 || byte_less(&keys[position - 1].name, &keys[position].name))
}

/// Merges at most one new echo key into an independently checked canonical
/// column. Every ordinary member appears exactly once with its original
/// source index. Echo cannot replace, reorder or shadow an existing member.
///
/// # Errors
/// Returns `Members` for invalid ordinary keys/count/order, then
/// `EchoConflict` for an invalid/colliding/over-capacity echo declaration.
pub fn canonical_members(
    keys: &[NamedKey], echo: Option<&[u8]>, domain: MemberDomain,
) -> Result<Vec<MemberChoice>, MemberError> {
    if !keys_ordered(keys, domain) {
        return Err(MemberError::Members);
    }
    let maximum = match domain { MemberDomain::Json => 32, MemberDomain::Form => 16 };
    if let Some(name) = echo {
        let valid = match domain {
            MemberDomain::Json => valid_token(name, 64),
            MemberDomain::Form => form_echo_name_valid(name),
        };
        if !valid || keys.len() >= maximum {
            return Err(MemberError::EchoConflict);
        }
    }
    merge_members(keys, echo)
}

// Called only after the public compiler has checked the complete key/echo
// domain. Separating this bounded selector keeps the guard and copying
// refinement interfaces explicit without exposing an unchecked public path.
fn merge_members(keys: &[NamedKey], echo: Option<&[u8]>) -> Result<Vec<MemberChoice>, MemberError> {
    // Detect collision before allocating a selection. The remaining merge
    // loop only compares borrowed input and mutates the independent output.
    if let Some(name) = echo {
        if key_position(keys, name).is_some() {
            return Err(MemberError::EchoConflict);
        }
    }
    let mut output = Vec::new();
    let mut inserted = false;
    let mut position = 0;
    while position < keys.len() {
        let insert_here = echo_before(keys, position, echo, inserted);
        if insert_here {
            output.push(MemberChoice::Echo);
            inserted = true;
        }
        output.push(MemberChoice::Source(position));
        position += 1;
    }
    if echo.is_some() && !inserted {
        output.push(MemberChoice::Echo);
    }
    Ok(output)
}

fn echo_before(keys: &[NamedKey], position: usize, echo: Option<&[u8]>, inserted: bool) -> bool {
    match echo {
        Some(name) => !inserted && byte_less(name, &keys[position].name),
        None => false,
    }
}

/// Checks all tokens and their exact slash-inclusive pointer envelope without
/// selecting a child or allocating. Every contribution is bounded before use.
#[must_use]
pub fn pointer_tokens_valid(tokens: &[Vec<u8>]) -> bool {
    if tokens.is_empty() || tokens.len() > MAX_ECHO_POINTER_TOKENS {
        return false;
    }
    let mut bytes = 0;
    let mut position = 0;
    while position < tokens.len() {
        if !valid_token(&tokens[position], 64) {
            return false;
        }
        // At most six contributions of at most 65 bytes; no word overflow.
        bytes += tokens[position].len() + 1;
        if bytes > MAX_ECHO_POINTER_BYTES {
            return false;
        }
        position += 1;
    }
    true
}

fn finish_echo_token(mut tokens: Vec<Vec<u8>>, token: Vec<u8>) -> Result<Vec<Vec<u8>>, MemberError> {
    if tokens.len() >= MAX_ECHO_POINTER_TOKENS || !valid_token(&token, 64) {
        return Err(MemberError::EchoConflict);
    }
    tokens.push(token);
    Ok(tokens)
}

/// Decodes the complete existing JSON echo-pointer language from exact bytes.
/// The pointer starts with `/`, is at most 128 bytes including slashes, and
/// contains one through six 1–64-byte ASCII field names. No percent, Unicode
/// normalization or JSON-pointer escape decoding occurs. This language names
/// source object members; response pointers have a separate contract.
///
/// # Errors
/// Returns `EchoConflict` for every malformed or oversized pointer, empty
/// token, unsupported field byte or excess token. Bounds precede indexing or
/// token growth; no individual token grows beyond 64 bytes.
pub fn echo_pointer_tokens(pointer: &[u8]) -> Result<Vec<Vec<u8>>, MemberError> {
    if pointer.is_empty() || pointer.len() > MAX_ECHO_POINTER_BYTES || pointer[0] != b'/' {
        return Err(MemberError::EchoConflict);
    }
    let mut tokens = Vec::new();
    let mut token = Vec::new();
    let mut position = 1;
    loop {
        if position == pointer.len() {
            return finish_echo_token(tokens, token);
        }
        let byte = pointer[position];
        if byte == b'/' {
            let prefix = core::mem::replace(&mut tokens, Vec::new());
            let complete = core::mem::replace(&mut token, Vec::new());
            // Keep the result enum initialized during cleanup. The pinned
            // translator cannot consume a partially moved enum variant.
            let finished = finish_echo_token(prefix, complete);
            match &finished {
                Ok(finished) => tokens = finished.clone(),
                Err(error) => return Err(*error),
            }
        } else {
            if token.len() >= 64 { return Err(MemberError::EchoConflict); }
            token.push(byte);
        }
        position += 1;
    }
}

/// Finds the first exact original source key without normalizing its bytes.
#[must_use]
pub fn key_position(keys: &[NamedKey], name: &[u8]) -> Option<usize> {
    let mut index = 0;
    while index < keys.len() {
        if field_name_equal(&keys[index].name, name) {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// Selects the exact next JSON-object child or a new final echo key. It checks
/// pointer token count, grammar and complete slash-inclusive byte length before
/// selecting anything. The native caller must require each selected child to
/// be an object; this function grants no authority over a different tree.
///
/// # Errors
/// Returns `Members` for invalid ordinary keys/count/order, then
/// `EchoConflict` for malformed pointers, missing parents, collisions or a full
/// destination object. No fallback or similarly named child is selected.
pub fn json_echo_target(keys: &[NamedKey], tokens: &[Vec<u8>]) -> Result<EchoTarget, MemberError> {
    if !keys_ordered(keys, MemberDomain::Json) {
        return Err(MemberError::Members);
    }
    if !pointer_tokens_valid(tokens) {
        return Err(MemberError::EchoConflict);
    }
    let found = key_position(keys, &tokens[0]);
    if tokens.len() == 1 {
        if found.is_some() || keys.len() >= 32 {
            Err(MemberError::EchoConflict)
        } else {
            Ok(EchoTarget::Insert)
        }
    } else {
        match found {
            Some(index) => Ok(EchoTarget::Descend(index)),
            None => Err(MemberError::EchoConflict),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn keys(names: &[&[u8]]) -> Vec<NamedKey> {
        names.iter().map(|name| NamedKey { name: name.to_vec() }).collect()
    }

    fn frozen_echo_pointer(pointer: &[u8]) -> Result<Vec<Vec<u8>>, MemberError> {
        if !pointer.starts_with(b"/") || pointer.len() > 128 {
            return Err(MemberError::EchoConflict);
        }
        let tokens: Vec<Vec<u8>> = pointer[1..].split(|byte| *byte == b'/').map(<[u8]>::to_vec).collect();
        let lexical = |token: &[u8]| {
            !token.is_empty() && token.len() <= 64 && token[0].is_ascii_alphanumeric()
                && token[1..].iter().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(byte))
        };
        if tokens.len() > 6 || !tokens.iter().all(|token| lexical(token)) {
            return Err(MemberError::EchoConflict);
        }
        Ok(tokens)
    }

    #[test]
    fn complete_echo_pointer_decoder_matches_independent_split_and_name_grammar() {
        for seed in [b"".as_slice(), b"/", b"a", b"/a", b"/a.b/b_0-c", b"/a//b", b"/a/", b"//a",
            b"/a~0b", b"/a%2Fb", "/é".as_bytes(), b"/a/b/c/d/e/f", b"/a/b/c/d/e/f/g"] {
            assert_eq!(echo_pointer_tokens(seed), frozen_echo_pointer(seed));
        }
        for position in 1..4 {
            for byte in 0_u8..=255 {
                let mut pointer = b"/abc".to_vec();
                pointer[position] = byte;
                assert_eq!(echo_pointer_tokens(&pointer), frozen_echo_pointer(&pointer));
            }
        }
        for token_size in [0, 1, 63, 64, 65, 127, 128] {
            let pointer = [vec![b'/'], vec![b'a'; token_size]].concat();
            assert_eq!(echo_pointer_tokens(&pointer), frozen_echo_pointer(&pointer));
        }
        let exact = [vec![b'/'], vec![b'a'; 63], vec![b'/'], vec![b'b'; 63]].concat();
        assert_eq!(exact.len(), 128);
        assert_eq!(echo_pointer_tokens(&exact), Ok(vec![vec![b'a'; 63], vec![b'b'; 63]]));
        let mut oversized = exact;
        oversized.push(b'b');
        assert_eq!(echo_pointer_tokens(&oversized), Err(MemberError::EchoConflict));
    }

    #[test]
    fn decoded_pointer_round_trips_original_bytes_and_earns_existing_token_contract() {
        for pointer in [b"/echo".as_slice(), b"/A0/a.b/Z_9", b"/a/b/c/d/e/f"] {
            let tokens = echo_pointer_tokens(pointer).expect("bounded pointer");
            assert!(pointer_tokens_valid(&tokens));
            let mut encoded = Vec::new();
            for token in &tokens {
                encoded.push(b'/');
                encoded.extend_from_slice(token);
            }
            assert_eq!(encoded, pointer);
        }
        assert_eq!(finish_echo_token(vec![b"a".to_vec(); 6], b"b".to_vec()), Err(MemberError::EchoConflict));
        assert_eq!(finish_echo_token(Vec::new(), Vec::new()), Err(MemberError::EchoConflict));
        assert_eq!(finish_echo_token(Vec::new(), vec![b'a'; 65]), Err(MemberError::EchoConflict));
    }

    #[test]
    fn byte_comparison_matches_independent_slice_order_for_binary_prefixes() {
        for first in 0_u8..=255 {
            for second in 0_u8..=255 {
                let left = [first, second];
                let right = [second, first];
                for left_length in 0..=2 {
                    for right_length in 0..=2 {
                        assert_eq!(byte_less(&left[..left_length], &right[..right_length]),
                            left[..left_length] < right[..right_length]);
                    }
                }
            }
        }
    }

    #[test]
    fn canonical_selection_matches_frozen_sort_without_losing_original_indices() {
        let names: &[&[u8]] = &[b"a", b"a.a", b"aa", b"b", b"z"];
        let column = keys(names);
        assert_eq!(canonical_members(&column, None, MemberDomain::Json),
            Ok((0..names.len()).map(MemberChoice::Source).collect()));
        for echo in [b"A".as_slice(), b"a-", b"a.b", b"ab", b"m", b"zz"] {
            let order = canonical_members(&column, Some(echo), MemberDomain::Json).unwrap();
            let actual: Vec<_> = order.iter().map(|choice| match choice {
                MemberChoice::Source(index) => names[*index], MemberChoice::Echo => echo,
            }).collect();
            let mut expected = names.to_vec();
            expected.push(echo);
            expected.sort();
            assert_eq!(actual, expected);
            assert_eq!(order.iter().filter(|choice| **choice == MemberChoice::Echo).count(), 1);
            assert_eq!(order.iter().filter_map(|choice| match choice {
                MemberChoice::Source(index) => Some(*index), MemberChoice::Echo => None,
            }).collect::<Vec<_>>(), (0..names.len()).collect::<Vec<_>>());
        }
        for collision in names {
            assert_eq!(canonical_members(&column, Some(collision), MemberDomain::Json), Err(MemberError::EchoConflict));
        }
        assert_eq!(canonical_members(&keys(&[b"b", b"a"]), None, MemberDomain::Json), Err(MemberError::Members));
        assert_eq!(canonical_members(&keys(&[b"a", b"a"]), None, MemberDomain::Json), Err(MemberError::Members));
    }

    #[test]
    fn form_echo_grammar_and_capacity_do_not_expand_the_source_language() {
        for accepted in [b"echo".as_slice(), b"metadata[auths_echo]", b"a[b.c-d_e]"] {
            assert!(form_echo_name_valid(accepted));
        }
        for refused in [b"".as_slice(), b"[a]", b"a[]", b"a[b][c]", b"a[b", b"a[b]x", b"a[b[c]]", b"a[\0]", b"a/echo"] {
            assert!(!form_echo_name_valid(refused));
        }
        let longest = [vec![b'a'; 64], vec![b'['], vec![b'b'; 64], vec![b']']].concat();
        assert!(form_echo_name_valid(&longest));
        let mut too_long = longest.clone();
        too_long.insert(0, b'a');
        assert!(!form_echo_name_valid(&too_long));
        let names: Vec<_> = (0_u8..16).map(|index| vec![b'a', b'a' + index]).collect();
        let column: Vec<_> = names.iter().map(|name| NamedKey { name: name.to_vec() }).collect();
        assert!(canonical_members(&column, None, MemberDomain::Form).is_ok());
        assert_eq!(canonical_members(&column, Some(b"echo"), MemberDomain::Form), Err(MemberError::EchoConflict));
        assert!(canonical_members(&column[..15], Some(b"metadata[auths_echo]"), MemberDomain::Form).is_ok());
    }

    #[test]
    fn form_echo_scan_matches_the_frozen_native_string_grammar() {
        fn frozen(bytes: &[u8]) -> bool {
            let Ok(name) = core::str::from_utf8(bytes) else { return false; };
            fn part(value: &str) -> bool {
                !value.is_empty() && value.len() <= 64 && value.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'_' | b'.' | b'-'))
                })
            }
            match name.find('[') {
                None => part(name),
                Some(open) => {
                    let (base, rest) = name.split_at(open);
                    rest.strip_prefix('[').and_then(|inner| inner.strip_suffix(']'))
                        .is_some_and(|inner| part(base) && part(inner))
                }
            }
        }
        for seed in [b"metadata[auths_echo]".as_slice(), b"bare_echo", b"a[b]", b"[a]", b"a[]", b"a[b][c]"] {
            assert_eq!(form_echo_name_valid(seed), frozen(seed));
            for position in 0..seed.len() {
                for byte in 0_u8..=255 {
                    let mut mutated = seed.to_vec();
                    mutated[position] = byte;
                    assert_eq!(form_echo_name_valid(&mutated), frozen(&mutated));
                }
            }
        }
        for base_size in [0, 1, 63, 64, 65] {
            for inner_size in [0, 1, 63, 64, 65] {
                let name = [vec![b'a'; base_size], vec![b'['], vec![b'b'; inner_size], vec![b']']].concat();
                assert_eq!(form_echo_name_valid(&name), frozen(&name));
            }
        }
    }

    #[test]
    fn json_pointer_selection_is_exact_and_bounded_before_traversal() {
        let column = keys(&[b"a", b"a.b", b"z"]);
        assert_eq!(json_echo_target(&column, &[b"echo".to_vec()]), Ok(EchoTarget::Insert));
        assert_eq!(json_echo_target(&column, &[b"a.b".to_vec(), b"echo".to_vec()]), Ok(EchoTarget::Descend(1)));
        assert_eq!(json_echo_target(&column, &[b"a".to_vec()]), Err(MemberError::EchoConflict));
        assert_eq!(json_echo_target(&column, &[b"A".to_vec(), b"echo".to_vec()]), Err(MemberError::EchoConflict));
        assert_eq!(json_echo_target(&column, &[]), Err(MemberError::EchoConflict));
        assert_eq!(json_echo_target(&column, &vec![b"a".to_vec(); 7]), Err(MemberError::EchoConflict));
        let parent = vec![b'a'; 63];
        let parent_keys = [NamedKey { name: parent.clone() }];
        assert_eq!(json_echo_target(&parent_keys, &[parent.clone(), vec![b'b'; 63]]), Ok(EchoTarget::Descend(0)));
        assert_eq!(json_echo_target(&parent_keys, &[parent.clone(), vec![b'b'; 64]]), Err(MemberError::EchoConflict));
    }
}
