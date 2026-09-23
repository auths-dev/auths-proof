//! Parses the derivation flags once into a closed typed request.
//!
//! Both packaged CLIs pass their remaining arguments here unchanged, so flag
//! grammar, override paths, and normalization cannot differ by language.

use crate::diagnostic::{DeriveCode, Diagnostic};
use crate::json::SAFE_INTEGER;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

const MAX_ARGUMENTS: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 1024;
const MAX_PATH_SEGMENTS: usize = 8;

/// The spelling that names the root request-body object in override paths.
/// It cannot collide with a property path, which never starts with a dot.
pub(crate) const ROOT_PATH: &str = ".";

/// A literal the recipe sends instead of an argument.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Literal {
    String(String),
    Integer(i64),
    Boolean(bool),
}

/// A scalar type selectable from a union.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScalarType {
    String,
    Integer,
    Boolean,
}

impl ScalarType {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
        }
    }
}

/// A credential scheme supplied because the document declares none.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SchemeOverride {
    Bearer,
    ApiKey(String),
}

/// Overrides keyed by path; each records whether a construct consumed it.
#[derive(Debug)]
pub(crate) struct Table<T> {
    flag: &'static str,
    entries: BTreeMap<String, (T, usize)>,
}

impl<T: Clone> Table<T> {
    const fn new(flag: &'static str) -> Self {
        Self {
            flag,
            entries: BTreeMap::new(),
        }
    }

    fn insert(&mut self, path: String, value: T) -> Result<(), Diagnostic> {
        match self.entries.entry(path) {
            Entry::Occupied(entry) => Err(request_error(format!(
                "{} is given twice for {}",
                self.flag,
                entry.key()
            ))),
            Entry::Vacant(entry) => {
                entry.insert((value, 0));
                Ok(())
            }
        }
    }

    /// Returns the override for `path` and counts the construct that
    /// consumed it.
    pub(crate) fn take(&mut self, path: &str) -> Option<T> {
        self.entries.get_mut(path).map(|(value, uses)| {
            *uses += 1;
            value.clone()
        })
    }

    fn with_uses(&self, test: fn(usize) -> bool) -> impl Iterator<Item = String> + '_ {
        self.entries
            .iter()
            .filter(move |(_, (_, uses))| test(*uses))
            .map(|(path, _)| format!("{} {path}", self.flag))
    }
}

/// Path-addressed schema overrides.
#[derive(Debug)]
pub(crate) struct Overrides {
    pub(crate) max_bytes: Table<usize>,
    pub(crate) range: Table<(i64, i64)>,
    pub(crate) max_items: Table<usize>,
    pub(crate) require: Table<()>,
    pub(crate) omit: Table<()>,
    pub(crate) closed: Table<()>,
    pub(crate) pick: Table<ScalarType>,
    pub(crate) literal: Table<Literal>,
}

impl Overrides {
    fn tables(&self, test: fn(usize) -> bool) -> Vec<String> {
        self.max_bytes
            .with_uses(test)
            .chain(self.range.with_uses(test))
            .chain(self.max_items.with_uses(test))
            .chain(self.require.with_uses(test))
            .chain(self.omit.with_uses(test))
            .chain(self.closed.with_uses(test))
            .chain(self.pick.with_uses(test))
            .chain(self.literal.with_uses(test))
            .collect()
    }

    /// Lists every override no construct consumed.
    pub(crate) fn unused(&self) -> Vec<String> {
        self.tables(|uses| uses == 0)
    }

    /// Lists every override more than one construct consumed, such as a path
    /// parameter and a body property that share a name.
    pub(crate) fn ambiguous(&self) -> Vec<String> {
        self.tables(|uses| uses > 1)
    }
}

/// The closed derivation request.
#[derive(Debug)]
pub(crate) struct Request {
    pub(crate) operation: String,
    pub(crate) service: String,
    pub(crate) name: String,
    pub(crate) operator_namespace: String,
    pub(crate) version: u16,
    pub(crate) tool: Option<String>,
    pub(crate) server: Option<String>,
    pub(crate) security: Option<String>,
    pub(crate) security_scheme: Option<SchemeOverride>,
    /// Every override flag with its value, in fixed flag order and sorted.
    pub(crate) recorded: Vec<String>,
}

/// Flags in the order `derivation.json` records them.
const RECORDED_FLAGS: [&str; 12] = [
    "--max-bytes",
    "--range",
    "--max-items",
    "--require",
    "--omit",
    "--closed",
    "--pick",
    "--literal",
    "--server",
    "--security",
    "--security-scheme",
    "--tool",
];

const IDENTITY_FLAGS: [&str; 5] = [
    "--operation",
    "--service",
    "--name",
    "--operator-namespace",
    "--version",
];

fn request_error(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(DeriveCode::InvalidRequest, "", message)
}

fn override_error(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(DeriveCode::InvalidOverride, "", message)
}

/// Parses `--flag value` pairs.
///
/// # Errors
/// Returns every malformed, unknown, repeated, or missing flag.
pub(crate) fn parse(arguments: &[String]) -> Result<(Request, Overrides), Vec<Diagnostic>> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(vec![request_error("more than 256 derive arguments")]);
    }
    let mut singles: BTreeMap<&str, String> = BTreeMap::new();
    let mut repeated: Vec<(&str, String)> = Vec::new();
    let mut errors = Vec::new();
    let mut iterator = arguments.iter();
    while let Some(flag) = iterator.next() {
        let known = RECORDED_FLAGS
            .iter()
            .chain(IDENTITY_FLAGS.iter())
            .find(|candidate| **candidate == flag.as_str());
        let Some(known) = known else {
            errors.push(request_error(format!("unknown derive argument {flag:?}")));
            break;
        };
        let Some(value) = iterator.next().filter(|value| !value.starts_with("--")) else {
            errors.push(request_error(format!("{known} needs a value")));
            break;
        };
        if value.is_empty() || value.len() > MAX_ARGUMENT_BYTES || value.contains('\0') {
            errors.push(request_error(format!(
                "{known} value is empty or oversized"
            )));
            continue;
        }
        if is_repeatable(known) {
            repeated.push((known, value.clone()));
        } else if singles.insert(known, value.clone()).is_some() {
            errors.push(request_error(format!("{known} is given twice")));
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    build(singles, &repeated)
}

fn is_repeatable(flag: &str) -> bool {
    matches!(
        flag,
        "--max-bytes"
            | "--range"
            | "--max-items"
            | "--require"
            | "--omit"
            | "--closed"
            | "--pick"
            | "--literal"
    )
}

fn build(
    mut singles: BTreeMap<&str, String>,
    repeated: &[(&str, String)],
) -> Result<(Request, Overrides), Vec<Diagnostic>> {
    let mut errors = Vec::new();
    let mut required = |flag: &str| {
        singles.remove(flag).unwrap_or_else(|| {
            errors.push(request_error(format!("{flag} is required")));
            String::new()
        })
    };
    let operation = required("--operation");
    let service = required("--service");
    let name = required("--name");
    let operator_namespace = required("--operator-namespace");
    let version = match singles.remove("--version") {
        None => 1,
        Some(value) => match value.parse::<u16>() {
            Ok(number) if (1..=9999).contains(&number) && number.to_string() == value => number,
            _ => {
                errors.push(request_error("--version must be an integer from 1 to 9999"));
                1
            }
        },
    };
    let security_scheme = singles
        .get("--security-scheme")
        .map(|value| parse_scheme(value))
        .transpose()
        .unwrap_or_else(|error| {
            errors.push(error);
            None
        });
    let mut recorded: Vec<String> = singles
        .iter()
        .map(|(flag, value)| format!("{flag} {value}"))
        .collect();
    let overrides = parse_overrides(repeated, &mut errors);
    recorded.extend(
        repeated
            .iter()
            .map(|(flag, value)| format!("{flag} {value}")),
    );
    recorded.sort_by_key(|entry| {
        let flag = entry.split(' ').next().unwrap_or_default();
        (
            RECORDED_FLAGS
                .iter()
                .position(|candidate| *candidate == flag)
                .unwrap_or(RECORDED_FLAGS.len()),
            entry.clone(),
        )
    });
    if !errors.is_empty() {
        return Err(errors);
    }
    let request = Request {
        operation,
        service,
        name,
        operator_namespace,
        version,
        tool: singles.remove("--tool"),
        server: singles.remove("--server"),
        security: singles.remove("--security"),
        security_scheme,
        recorded,
    };
    Ok((request, overrides))
}

fn parse_scheme(value: &str) -> Result<SchemeOverride, Diagnostic> {
    if value == "bearer" {
        return Ok(SchemeOverride::Bearer);
    }
    if let Some(header) = value.strip_prefix("apikey:")
        && !header.is_empty()
        && header.len() <= 64
        && header
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte.is_ascii_alphanumeric() || (index > 0 && byte == b'-'))
    {
        return Ok(SchemeOverride::ApiKey(header.to_owned()));
    }
    Err(request_error(
        "--security-scheme must be bearer or apikey:<Header-Name>",
    ))
}

fn parse_overrides(repeated: &[(&str, String)], errors: &mut Vec<Diagnostic>) -> Overrides {
    let mut overrides = Overrides {
        max_bytes: Table::new("--max-bytes"),
        range: Table::new("--range"),
        max_items: Table::new("--max-items"),
        require: Table::new("--require"),
        omit: Table::new("--omit"),
        closed: Table::new("--closed"),
        pick: Table::new("--pick"),
        literal: Table::new("--literal"),
    };
    for (flag, value) in repeated {
        if let Err(error) = insert_override(&mut overrides, flag, value) {
            errors.push(error);
        }
    }
    overrides
}

fn insert_override(overrides: &mut Overrides, flag: &str, value: &str) -> Result<(), Diagnostic> {
    match flag {
        "--require" => overrides.require.insert(property_path(flag, value)?, ()),
        "--omit" => overrides.omit.insert(property_path(flag, value)?, ()),
        "--closed" => {
            let path = if value == ROOT_PATH {
                value.to_owned()
            } else {
                property_path(flag, value)?
            };
            overrides.closed.insert(path, ())
        }
        _ => {
            let (path, raw) = value
                .split_once('=')
                .ok_or_else(|| override_error(format!("{flag} needs path=value, got {value:?}")))?;
            let path = property_path(flag, path)?;
            match flag {
                "--max-bytes" => {
                    let bytes = positive(flag, raw, 4096)?;
                    overrides.max_bytes.insert(path, bytes)
                }
                "--max-items" => {
                    let items = positive(flag, raw, 32)?;
                    overrides.max_items.insert(path, items)
                }
                "--range" => overrides.range.insert(path, parse_range(raw)?),
                "--pick" => overrides.pick.insert(path, parse_type(raw)?),
                _ => overrides.literal.insert(path, parse_literal(raw)?),
            }
        }
    }
}

/// Validates a dotted property path relative to the request arguments.
fn property_path(flag: &str, value: &str) -> Result<String, Diagnostic> {
    let segments: Vec<&str> = value.split('.').collect();
    if segments.len() > MAX_PATH_SEGMENTS
        || segments.iter().any(|segment| {
            segment.is_empty()
                || segment.len() > 64
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
    {
        return Err(override_error(format!(
            "{flag} path {value:?} is not a dotted property path (the root body object is spelled {ROOT_PATH:?})"
        )));
    }
    Ok(value.to_owned())
}

fn positive(flag: &str, raw: &str, maximum: usize) -> Result<usize, Diagnostic> {
    match raw.parse::<usize>() {
        Ok(number) if (1..=maximum).contains(&number) && number.to_string() == raw => Ok(number),
        _ => Err(override_error(format!(
            "{flag} value {raw:?} must be an integer from 1 to {maximum}"
        ))),
    }
}

fn parse_integer(raw: &str) -> Option<i64> {
    let number = raw.parse::<i64>().ok()?;
    (number.to_string() == raw && (-SAFE_INTEGER..=SAFE_INTEGER).contains(&number))
        .then_some(number)
}

fn parse_range(raw: &str) -> Result<(i64, i64), Diagnostic> {
    let error = || {
        override_error(format!(
            "--range value {raw:?} must be min:max safe integers with min <= max"
        ))
    };
    let (low, high) = raw.split_once(':').ok_or_else(error)?;
    let low = parse_integer(low).ok_or_else(error)?;
    let high = parse_integer(high).ok_or_else(error)?;
    if low > high {
        return Err(error());
    }
    Ok((low, high))
}

fn parse_type(raw: &str) -> Result<ScalarType, Diagnostic> {
    match raw {
        "string" => Ok(ScalarType::String),
        "integer" => Ok(ScalarType::Integer),
        "boolean" => Ok(ScalarType::Boolean),
        _ => Err(override_error(format!(
            "--pick type {raw:?} must be string, integer, or boolean"
        ))),
    }
}

/// Parses a literal: `true`, `false`, a safe integer, or a JSON string.
fn parse_literal(raw: &str) -> Result<Literal, Diagnostic> {
    match raw {
        "true" => return Ok(Literal::Boolean(true)),
        "false" => return Ok(Literal::Boolean(false)),
        _ => {}
    }
    if let Some(number) = parse_integer(raw) {
        return Ok(Literal::Integer(number));
    }
    if raw.starts_with('"')
        && let Ok(serde_json::Value::String(text)) = serde_json::from_str::<serde_json::Value>(raw)
        && text.len() <= 1024
        && !text.contains('\0')
    {
        return Ok(Literal::String(text));
    }
    Err(override_error(format!(
        "--literal value {raw:?} must be true, false, a safe integer, or a JSON string of at most 1024 bytes"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    const BASE: [&str; 8] = [
        "--operation",
        "op",
        "--service",
        "svc",
        "--name",
        "profile",
        "--operator-namespace",
        "ns",
    ];

    #[test]
    fn overrides_are_recorded_in_one_normalized_order() {
        let mut first = arguments(&BASE);
        first.extend(arguments(&[
            "--omit",
            "b",
            "--max-bytes",
            "a=4",
            "--omit",
            "a",
            "--tool",
            "t",
        ]));
        let mut second = arguments(&BASE);
        second.extend(arguments(&[
            "--tool",
            "t",
            "--omit",
            "a",
            "--max-bytes",
            "a=4",
            "--omit",
            "b",
        ]));
        let first = parse(&first).unwrap().0;
        let second = parse(&second).unwrap().0;
        assert_eq!(first.recorded, second.recorded);
        assert_eq!(
            first.recorded,
            ["--max-bytes a=4", "--omit a", "--omit b", "--tool t"]
        );
    }

    #[test]
    fn malformed_flags_fail_closed() {
        for bad in [
            vec!["--unknown", "x"],
            vec!["--omit"],
            vec!["--omit", "a", "--omit", "a"],
            vec!["--max-bytes", "a=0"],
            vec!["--max-bytes", "a=4097"],
            vec!["--max-bytes", "a=04"],
            vec!["--range", "a=5:1"],
            vec!["--range", "a=0:9007199254740992"],
            vec!["--pick", "a=number"],
            vec!["--literal", "a=bare"],
            vec!["--closed", "body.."],
            vec!["--omit", ".a"],
            vec!["--version", "0"],
            vec!["--security-scheme", "basic"],
            vec!["--security-scheme", "apikey:-X"],
            vec!["--tool", "a", "--tool", "b"],
        ] {
            let mut values = arguments(&BASE);
            values.extend(arguments(&bad));
            assert!(parse(&values).is_err(), "{bad:?}");
        }
        assert!(parse(&arguments(&BASE[..6])).is_err());
    }

    #[test]
    fn literals_and_root_spelling_parse_exactly() {
        let mut values = arguments(&BASE);
        values.extend(arguments(&[
            "--literal",
            "a=\"x y\"",
            "--literal",
            "b=-3",
            "--literal",
            "c=true",
            "--closed",
            ".",
        ]));
        let (_, mut overrides) = parse(&values).unwrap();
        assert_eq!(
            overrides.literal.take("a"),
            Some(Literal::String("x y".into()))
        );
        assert_eq!(overrides.literal.take("b"), Some(Literal::Integer(-3)));
        assert_eq!(overrides.literal.take("c"), Some(Literal::Boolean(true)));
        assert!(overrides.closed.take(ROOT_PATH).is_some());
        assert!(overrides.unused().is_empty());
    }
}
