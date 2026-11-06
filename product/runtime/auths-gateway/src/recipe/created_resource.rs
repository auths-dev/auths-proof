//! Closed projection of a complete provider listing. A selected string is
//! private provider data, never authority or a downstream execution permit.
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const SCHEMA: &str = "auths.created-resource-selection/1";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    pub(crate) schema: String,
    pub(crate) resource_pointer: String,
    pub(crate) parent_pointer: String,
    pub(crate) parent_kind: ParentKind,
    pub(crate) maximum_items: u64,
    pub(crate) complete: Vec<Complete>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ParentKind {
    Scalar,
    SoleStringArray,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Complete {
    Absent { pointer: String },
    Boolean { pointer: String, equals: bool },
}
impl Complete {
    fn pointer(&self) -> &str {
        match self {
            Self::Absent { pointer } | Self::Boolean { pointer, .. } => pointer,
        }
    }
    fn holds(&self, document: &Value) -> bool {
        match self {
            Self::Boolean { pointer, equals } => {
                document.pointer(pointer).and_then(Value::as_bool) == Some(*equals)
            }
            Self::Absent { pointer } => {
                // Missing ancestors or arrays are uncertainty, not completeness.
                let Some((parent, last)) = pointer.rsplit_once('/') else {
                    return false;
                };
                let parent = if parent.is_empty() {
                    Some(document)
                } else {
                    document.pointer(parent)
                };
                parent
                    .and_then(Value::as_object)
                    .is_some_and(|object| !object.contains_key(&unescape(last)))
            }
        }
    }
}

/// No serialization or public constructor: this is a projection result, not
/// accepted evidence. Only the native source/read owner may persist it.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Candidate(String);
impl std::fmt::Debug for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Candidate { private: [redacted] }")
    }
}
impl Candidate {
    pub(crate) fn handle(&self) -> &str {
        &self.0
    }
}

fn unescape(value: &str) -> String {
    value.replace("~1", "/").replace("~0", "~")
}

fn overlap(a: &str, b: &str) -> bool {
    a == b
        || a.strip_prefix(b).is_some_and(|v| v.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|v| v.starts_with('/'))
}

impl Selection {
    pub(crate) fn valid(&self, items: &str, marker: &str) -> bool {
        let relative = [
            self.resource_pointer.as_str(),
            self.parent_pointer.as_str(),
            marker,
        ];
        self.schema == SCHEMA
            && (1..=64).contains(&self.maximum_items)
            && (1..=2).contains(&self.complete.len())
            && super::validate::valid_response_pointer(items)
            && relative
                .iter()
                .all(|value| super::validate::valid_response_pointer(value))
            && relative
                .iter()
                .enumerate()
                .all(|(i, a)| relative.iter().skip(i + 1).all(|b| !overlap(a, b)))
            && self.complete.iter().all(|condition| {
                super::validate::valid_response_pointer(condition.pointer())
                    && !overlap(condition.pointer(), items)
            })
            && self.complete.iter().enumerate().all(|(i, a)| {
                self.complete
                    .iter()
                    .skip(i + 1)
                    .all(|b| a.pointer() != b.pointer())
            })
    }
    /// `document` was decoded by the one bounded duplicate-free provider JSON
    /// owner. No status, freshness, authority, custody or provider truth follows.
    pub(crate) fn select(
        &self,
        document: &Value,
        items: &str,
        marker: &str,
        token: &str,
        parent: &str,
    ) -> Option<Candidate> {
        if !self.valid(items, marker)
            || !crate::resource_identity::valid_handle(parent)
            || token.len() != super::ECHO_PREFIX.len() + 64
            || !token.starts_with(super::ECHO_PREFIX)
            || !token[super::ECHO_PREFIX.len()..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !document.is_object()
            || !self
                .complete
                .iter()
                .all(|condition| condition.holds(document))
        {
            return None;
        }
        let candidates = document.pointer(items)?.as_array()?;
        if u64::try_from(candidates.len()).ok()? > self.maximum_items {
            return None;
        }
        let mut selected = None;
        for candidate in candidates {
            if !candidate.is_object() {
                return None;
            }
            let found_marker = candidate.pointer(marker)?.as_str()?;
            if !crate::resource_identity::valid_handle(found_marker) {
                return None;
            }
            if found_marker != token {
                continue;
            }
            let resource = candidate.pointer(&self.resource_pointer)?.as_str()?;
            if !crate::resource_identity::valid_handle(resource) {
                return None;
            }
            let found_parent = candidate.pointer(&self.parent_pointer)?;
            let found_parent = match self.parent_kind {
                ParentKind::Scalar => found_parent.as_str()?,
                ParentKind::SoleStringArray => {
                    let values = found_parent.as_array()?;
                    if values.len() != 1 {
                        return None;
                    }
                    values[0].as_str()?
                }
            };
            if !crate::resource_identity::valid_handle(found_parent) {
                return None;
            }
            if found_parent != parent {
                continue;
            }
            if selected.is_some() {
                return None;
            }
            selected = Some(Candidate(resource.into()));
        }
        selected
    }
}

#[cfg(test)]
#[path = "created_resource_tests.rs"]
mod tests;
