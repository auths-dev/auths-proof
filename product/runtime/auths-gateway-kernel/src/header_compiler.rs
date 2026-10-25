//! The existing closed provider-header catalog and exact named lowering.
//! Version values are approved literals. Account scope is an exact profile
//! field reference, rendered only from projected action values. Credential
//! reads consume the version column and have no account-scope input.

#![allow(
    clippy::manual_range_contains,
    reason = "explicit byte comparisons translate without an external RangeInclusive model"
)]

use alloc::vec::Vec;
use crate::construct::{AccountScopePlan, Header, HeaderPlan, ScopeGrammar, copy_bytes, field_name_equal, is_alphanumeric, scope_value_valid};
use crate::path_compiler::lower_field;

/// Maximum fixed provider headers in a declared source map.
pub const MAX_PROVIDER_HEADERS: usize = 2;

/// The class of an entry in the closed provider-header catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderHeaderClass {
    /// Approved fixed value on both action and credential requests.
    Version,
    /// Verified action field on action requests only.
    AccountScope,
}

/// How a provider response is checked against its version header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderResponseRule {
    /// A missing or differing response value is a version mismatch.
    Required,
    /// No provider-response version check.
    NotChecked,
}

impl ProviderResponseRule {
    /// Stable review spelling of the response rule.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self { Self::Required => "required", Self::NotChecked => "not-checked" }
    }
}

/// Existing value grammars; the date grammar specifies shape, not a calendar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderGrammar {
    /// 10–64 ASCII alphanumeric/dot/hyphen bytes, starting with a digit.
    StripeVersion,
    /// Ten bytes, digits except for hyphens at positions four and seven.
    IsoDate,
    /// The existing `acct_` account-scope grammar.
    StripeAccount,
}

impl HeaderGrammar {
    /// Tests the exact registered byte grammar without normalization.
    #[must_use]
    pub fn admits(self, value: &[u8]) -> bool {
        match self {
            Self::StripeVersion => stripe_version_valid(value),
            Self::IsoDate => iso_date_valid(value),
            Self::StripeAccount => scope_value_valid(ScopeGrammar::StripeAccount, value),
        }
    }
}

/// One immutable catalog entry. The catalog is shared by native review,
/// credential-header collision checks and compiled recipe validation.
#[derive(Clone, Copy, Debug)]
pub struct ProviderHeaderEntry {
    /// Exact canonical name.
    pub name: &'static str,
    /// Whether the value is fixed or action-derived.
    pub class: ProviderHeaderClass,
    /// Exact accepted value grammar.
    pub grammar: HeaderGrammar,
    /// Provider response interpretation.
    pub response: ProviderResponseRule,
}

const STRIPE_VERSION: &str = "Stripe-Version";
const GITHUB_VERSION: &str = "X-GitHub-Api-Version";
const STRIPE_ACCOUNT: &str = "Stripe-Account";
// Const evaluation supplies byte slices to the translated lookup; the native
// metadata and byte names have one literal source of truth.
const STRIPE_VERSION_BYTES: &[u8] = STRIPE_VERSION.as_bytes();
const GITHUB_VERSION_BYTES: &[u8] = GITHUB_VERSION.as_bytes();
const STRIPE_ACCOUNT_BYTES: &[u8] = STRIPE_ACCOUNT.as_bytes();

/// The three entries already admitted by the gateway recipe specification.
pub const PROVIDER_HEADERS: [ProviderHeaderEntry; 3] = [
    ProviderHeaderEntry { name: STRIPE_VERSION, class: ProviderHeaderClass::Version, grammar: HeaderGrammar::StripeVersion, response: ProviderResponseRule::Required },
    ProviderHeaderEntry { name: GITHUB_VERSION, class: ProviderHeaderClass::Version, grammar: HeaderGrammar::IsoDate, response: ProviderResponseRule::NotChecked },
    ProviderHeaderEntry { name: STRIPE_ACCOUNT, class: ProviderHeaderClass::AccountScope, grammar: HeaderGrammar::StripeAccount, response: ProviderResponseRule::NotChecked },
];

/// Resolves a canonical name to its exact catalog index, or refuses it.
#[must_use]
pub fn header_index(name: &[u8]) -> Option<usize> {
    if field_name_equal(name, STRIPE_VERSION_BYTES) {
        Some(0)
    } else if field_name_equal(name, GITHUB_VERSION_BYTES) {
        Some(1)
    } else if field_name_equal(name, STRIPE_ACCOUNT_BYTES) {
        Some(2)
    } else {
        None
    }
}

fn ascii_lower(byte: u8) -> u8 {
    if byte >= b'A' && byte <= b'Z' { byte + (b'a' - b'A') } else { byte }
}

fn ascii_name_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut position = 0;
    let mut equal = true;
    while position < left.len() && equal {
        equal = ascii_lower(left[position]) == ascii_lower(right[position]);
        position += 1;
    }
    equal
}

/// Whether a credential header collides with any catalog name, using the
/// existing ASCII case-insensitive HTTP header comparison. The literals are
/// the same ones used by the canonical, case-sensitive recipe lookup.
#[must_use]
pub fn registered_header_name(name: &[u8]) -> bool {
    ascii_name_equal(name, STRIPE_VERSION_BYTES)
        || ascii_name_equal(name, GITHUB_VERSION_BYTES)
        || ascii_name_equal(name, STRIPE_ACCOUNT_BYTES)
}

/// Existing transport/content/idempotency names that cannot carry an API
/// credential. Comparison is ASCII case-insensitive and allocates no string.
#[must_use]
pub fn reserved_credential_header_name(name: &[u8]) -> bool {
    ascii_name_equal(name, b"authorization") || ascii_name_equal(name, b"host")
        || ascii_name_equal(name, b"cookie") || ascii_name_equal(name, b"set-cookie")
        || ascii_name_equal(name, b"content-type") || ascii_name_equal(name, b"content-length")
        || ascii_name_equal(name, b"accept") || ascii_name_equal(name, b"connection")
        || ascii_name_equal(name, b"transfer-encoding") || ascii_name_equal(name, b"idempotency-key")
}

/// Whether an exact source name is the catalog's account-scope entry.
/// Credential collision checks deliberately use `registered_header_name`
/// instead; source names must retain the approved canonical spelling.
#[must_use]
pub fn account_scope_header_name(name: &[u8]) -> bool {
    match header_index(name) {
        Some(2) => true,
        Some(_) | None => false,
    }
}

/// One byte permitted after the first digit in a fixed version value.
#[must_use]
pub fn version_byte_valid(byte: u8) -> bool {
    is_alphanumeric(byte) || byte == b'.' || byte == b'-'
}

/// One byte at its position in the existing date-shape grammar.
#[must_use]
pub fn date_byte_valid(position: usize, byte: u8) -> bool {
    if position == 4 || position == 7 {
        byte == b'-'
    } else {
        byte >= b'0' && byte <= b'9'
    }
}

/// Complete bounded fixed-version grammar; CR/LF/NUL and non-ASCII refuse.
#[must_use]
pub fn stripe_version_valid(value: &[u8]) -> bool {
    if value.len() < 10 || value.len() > 64 {
        return false;
    }
    let first = value[0];
    if first < b'0' || first > b'9' {
        return false;
    }
    let mut position = 0;
    while position < value.len() {
        let byte = value[position];
        if !version_byte_valid(byte) {
            return false;
        }
        position += 1;
    }
    true
}

/// The existing ten-byte date shape, without imposing new calendar semantics.
#[must_use]
pub fn iso_date_valid(value: &[u8]) -> bool {
    if value.len() != 10 {
        return false;
    }
    let mut position = 0;
    while position < value.len() {
        let byte = value[position];
        if !date_byte_valid(position, byte) {
            return false;
        }
        position += 1;
    }
    true
}

/// Exact fixed version-name/value admission from the existing catalog.
#[must_use]
pub fn version_header_valid(name: &[u8], value: &[u8]) -> bool {
    match header_index(name) {
        Some(0) => stripe_version_valid(value),
        Some(1) => iso_date_valid(value),
        Some(_) | None => false,
    }
}

/// Owned decoded source entry; no request value or credential is supplied.
#[derive(Clone, Debug)]
pub struct NamedHeader {
    /// Exact source name.
    pub name: Vec<u8>,
    /// Approved fixed value bytes.
    pub value: Vec<u8>,
}

/// Owned account-scope source entry with its original profile field name.
#[derive(Clone, Debug)]
pub struct NamedScope {
    /// Exact registered account header.
    pub name: Vec<u8>,
    /// Exact profile name, before positional lowering.
    pub field: Vec<u8>,
}

/// Distinguishes the two existing public compiler error families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderCompileError {
    /// Invalid declared fixed provider headers.
    ProviderHeader,
    /// Invalid account header or field reference.
    AccountScope,
}

/// A declared fixed map is nonempty, has at most two distinct canonical names,
/// and every value satisfies its corresponding version grammar.
#[must_use]
pub fn version_headers_valid(headers: &[NamedHeader]) -> bool {
    if headers.is_empty() || headers.len() > MAX_PROVIDER_HEADERS {
        return false;
    }
    if headers.len() == 2 && field_name_equal(&headers[0].name, &headers[1].name) {
        return false;
    }
    let mut position = 0;
    while position < headers.len() {
        let header = &headers[position];
        if !version_header_valid(&header.name, &header.value) {
            return false;
        }
        position += 1;
    }
    true
}

// The complete validator earns the copy loop's size domain. Keeping the
// private copier separate also gives its translated loop a plain Vec result.
fn copy_versions(headers: &[NamedHeader]) -> Vec<Header> {
    let mut output = Vec::new();
    let mut position = 0;
    while position < headers.len() {
        let header = &headers[position];
        output.push(Header { name: copy_bytes(&header.name), value: copy_bytes(&header.value) });
        position += 1;
    }
    output
}

/// Lowers a complete declared fixed header map without changing order/bytes.
///
/// # Errors
/// Returns `ProviderHeader` for every map outside the complete fixed domain.
pub fn lower_versions(headers: &[NamedHeader]) -> Result<Vec<Header>, HeaderCompileError> {
    if !version_headers_valid(headers) {
        return Err(HeaderCompileError::ProviderHeader);
    }
    Ok(copy_versions(headers))
}

/// Lowers one exact scope reference; field type/exclusive consumption remain
/// source-validation obligations, and the writer checks the actual value.
///
/// # Errors
/// Returns `AccountScope` for an unsupported name or unresolved reference.
pub fn lower_scope(names: &[Vec<u8>], scope: &NamedScope) -> Result<AccountScopePlan, HeaderCompileError> {
    let Some(2) = header_index(&scope.name) else {
        return Err(HeaderCompileError::AccountScope);
    };
    match lower_field(names, &scope.field) {
        Ok(field) => Ok(AccountScopePlan { name: copy_bytes(&scope.name), field, grammar: ScopeGrammar::StripeAccount }),
        Err(_) => Err(HeaderCompileError::AccountScope),
    }
}

/// Complete optional-source lowering. Absence produces no fixed headers;
/// an explicitly declared empty map refuses. Scope never enters the fixed
/// version column that credential reads consume.
///
/// # Errors
/// Preserves provider-header errors before account-scope errors.
pub fn lower_headers(names: &[Vec<u8>], versions: Option<&[NamedHeader]>, scope: Option<&NamedScope>) -> Result<HeaderPlan, HeaderCompileError> {
    let versions = match versions {
        None => Vec::new(),
        Some(source) => {
            let lowered = lower_versions(source);
            match &lowered {
                Ok(compiled) => compiled.clone(),
                Err(error) => return Err(*error),
            }
        }
    };
    let account_scope = match scope {
        None => None,
        Some(source) => {
            let lowered = lower_scope(names, source);
            match &lowered {
                Ok(compiled) => Some(compiled.clone()),
                Err(error) => return Err(*error),
            }
        }
    };
    Ok(HeaderPlan { versions, account_scope })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::construct::{ArgumentValue, action_headers};
    use alloc::vec;

    #[test]
    fn catalog_lookup_and_value_grammars_match_the_frozen_native_rules() {
        for (index, entry) in PROVIDER_HEADERS.iter().enumerate() {
            assert_eq!(header_index(entry.name.as_bytes()), Some(index));
        }
        for name in [b"stripe-version".as_slice(), b"Stripe-Version\0", b"X-GitHub-Api-Version ", b"Authorization"] {
            assert_eq!(header_index(name), None);
        }
        for byte in 0_u8..=255 {
            for position in 0..10 {
                let mut stripe = *b"2026-10-18";
                stripe[position] = byte;
                let old_stripe = stripe[0].is_ascii_digit() && stripe.iter().all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-'));
                assert_eq!(stripe_version_valid(&stripe), old_stripe);
                let old_date = stripe.iter().enumerate().all(|(index, byte)| if matches!(index, 4 | 7) { *byte == b'-' } else { byte.is_ascii_digit() });
                assert_eq!(iso_date_valid(&stripe), old_date);
            }
        }
        assert!(iso_date_valid(b"0000-99-99"));
        assert!(!stripe_version_valid(b"2026-10-18\r\nX: a"));
        assert!(stripe_version_valid(&[b'1'; 64]));
        assert!(!stripe_version_valid(&[b'1'; 65]));
    }

    #[test]
    fn credential_collisions_preserve_ascii_case_while_scope_names_remain_exact() {
        for entry in PROVIDER_HEADERS {
            let canonical = entry.name.as_bytes();
            for position in 0..canonical.len() {
                for byte in 0_u8..=255 {
                    let mut candidate = canonical.to_vec();
                    candidate[position] = byte;
                    let reference = PROVIDER_HEADERS.iter().any(|registered| {
                        registered.name.as_bytes().eq_ignore_ascii_case(&candidate)
                    });
                    assert_eq!(registered_header_name(&candidate), reference);
                    assert_eq!(account_scope_header_name(&candidate), candidate == STRIPE_ACCOUNT_BYTES);
                }
            }
            assert!(registered_header_name(entry.name.to_ascii_lowercase().as_bytes()));
            assert!(registered_header_name(entry.name.to_ascii_uppercase().as_bytes()));
            let mut suffix = canonical.to_vec();
            suffix.push(0);
            assert!(!registered_header_name(&suffix));
            assert!(!registered_header_name(&canonical[..canonical.len() - 1]));
        }
        for candidate in [b"".as_slice(), b"Authorization", b"Stripe\xc2\xadVersion", b"stripe_account"] {
            assert!(!registered_header_name(candidate));
        }
    }

    #[test]
    fn optional_maps_duplicates_scope_fields_and_request_columns_are_exact() {
        let names = vec![b"account".to_vec(), b"account_suffix".to_vec()];
        let versions = [NamedHeader { name: b"Stripe-Version".to_vec(), value: b"2026-10-18".to_vec() }];
        let scope = NamedScope { name: b"Stripe-Account".to_vec(), field: b"account_suffix".to_vec() };
        let plan = lower_headers(&names, Some(&versions), Some(&scope)).unwrap();
        assert_eq!(plan.account_scope.as_ref().unwrap().field, 1);
        assert_eq!(plan.versions, vec![Header { name: b"Stripe-Version".to_vec(), value: b"2026-10-18".to_vec() }]);
        let action = action_headers(&plan, &[
            ArgumentValue::Text(b"acct_11111111".to_vec()), ArgumentValue::Text(b"acct_22222222".to_vec()),
        ]).unwrap();
        assert_eq!(action[1], Header { name: b"Stripe-Account".to_vec(), value: b"acct_22222222".to_vec() });
        assert!(lower_headers(&[], None, None).unwrap().versions.is_empty());
        assert_eq!(lower_headers(&names, Some(&[]), None), Err(HeaderCompileError::ProviderHeader));
        assert_eq!(lower_versions(&[versions[0].clone(), versions[0].clone()]), Err(HeaderCompileError::ProviderHeader));
        assert_eq!(lower_scope(&names, &NamedScope { name: b"Stripe-Version".to_vec(), field: b"account".to_vec() }), Err(HeaderCompileError::AccountScope));
        assert_eq!(lower_scope(&names, &NamedScope { name: b"Stripe-Account".to_vec(), field: b"Account".to_vec() }), Err(HeaderCompileError::AccountScope));
        assert_eq!(action_headers(&plan, &[ArgumentValue::Text(b"acct_11111111".to_vec()), ArgumentValue::Text(b"acct_22222222\r\nX: 1".to_vec())]), Err(crate::construct::ConstructError::HeaderValue));
    }

    #[test]
    fn actual_object_projection_and_header_writing_use_the_same_exact_layout() {
        use crate::field_projection::{FieldSpec, NamedInput, field_names, project_object};
        use crate::scalars::{ScalarInput, ScalarSchema};
        let fields = [
            FieldSpec { name: b"account".to_vec(), schema: ScalarSchema::String { minimum: 13, maximum: 64 } },
            FieldSpec { name: b"account_suffix".to_vec(), schema: ScalarSchema::String { minimum: 13, maximum: 64 } },
        ];
        let names = field_names(&fields).unwrap();
        let versions = [NamedHeader { name: b"Stripe-Version".to_vec(), value: b"2026-10-18".to_vec() }];
        let scope = NamedScope { name: b"Stripe-Account".to_vec(), field: b"account_suffix".to_vec() };
        let plan = lower_headers(&names, Some(&versions), Some(&scope)).unwrap();
        for account in [b"acct_22222222".as_slice(), b"acct_22222222\r\nX: 1"] {
            let supplied = [
                NamedInput { name: b"account_suffix", value: ScalarInput::Text(account) },
                NamedInput { name: b"account", value: ScalarInput::Text(b"acct_11111111") },
            ];
            let projected = project_object(&fields, &supplied).unwrap();
            let written = action_headers(&plan, &projected);
            if account == b"acct_22222222" {
                assert_eq!(written, Ok(vec![
                    Header { name: b"Stripe-Version".to_vec(), value: b"2026-10-18".to_vec() },
                    Header { name: b"Stripe-Account".to_vec(), value: b"acct_22222222".to_vec() },
                ]));
            } else {
                assert_eq!(written, Err(crate::construct::ConstructError::HeaderValue));
            }
        }
    }
}
