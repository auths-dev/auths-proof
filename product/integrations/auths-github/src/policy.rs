//! Root-anchored Git tree path grammar and containment.

use crate::types::HARD_MAX_PATH_BYTES;

/// Invalid root-anchored pattern or Git tree path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid root-anchored Git path grammar")]
pub struct PatternError;

/// Final path-policy result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathDecision {
    /// An allow pattern matched and no deny pattern matched.
    Allowed,
    /// A deny pattern matched; deny takes precedence.
    ExplicitlyDenied,
    /// No allow pattern matched.
    NotAllowed,
    /// The path itself is malformed.
    Malformed,
}

/// Validates one root-relative pattern.
///
/// `*` matches bytes inside one path component. `**` is valid only as a
/// complete component and matches zero or more complete components.
///
/// # Errors
///
/// Rejects non-root-relative, ambiguous, control-bearing, or overlong patterns.
pub fn validate_pattern(pattern: &str) -> Result<(), PatternError> {
    if pattern.is_empty()
        || pattern.len() > HARD_MAX_PATH_BYTES
        || pattern.starts_with('/')
        || pattern.ends_with('/')
    {
        return Err(PatternError);
    }
    for component in pattern.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || (component.contains("**") && component != "**")
            || component.bytes().any(invalid_path_byte)
        {
            return Err(PatternError);
        }
    }
    Ok(())
}

/// Validates one Git tree path without interpreting host filesystem semantics.
///
/// # Errors
///
/// Rejects traversal, separators, controls, and overlong paths.
pub fn validate_tree_path(path: &str) -> Result<(), PatternError> {
    if path.is_empty()
        || path.len() > HARD_MAX_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
    {
        return Err(PatternError);
    }
    for component in path.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || component.bytes().any(invalid_tree_path_byte)
        {
            return Err(PatternError);
        }
    }
    Ok(())
}

fn invalid_path_byte(byte: u8) -> bool {
    invalid_tree_path_byte(byte) || matches!(byte, b'[' | b']' | b'?' | b'\\')
}

fn invalid_tree_path_byte(byte: u8) -> bool {
    byte == b'\\' || byte.is_ascii_control()
}

/// Applies deny-first path containment.
#[must_use]
pub fn evaluate_path(path: &str, allowed: &[String], denied: &[String]) -> PathDecision {
    if validate_tree_path(path).is_err() {
        return PathDecision::Malformed;
    }
    if denied
        .iter()
        .any(|pattern| path_matches(pattern, path).unwrap_or(false))
    {
        return PathDecision::ExplicitlyDenied;
    }
    if allowed
        .iter()
        .any(|pattern| path_matches(pattern, path).unwrap_or(false))
    {
        PathDecision::Allowed
    } else {
        PathDecision::NotAllowed
    }
}

/// Matches one validated pattern against one validated tree path.
///
/// # Errors
///
/// Returns a grammar failure if either input is invalid.
pub fn path_matches(pattern: &str, path: &str) -> Result<bool, PatternError> {
    validate_pattern(pattern)?;
    validate_tree_path(path)?;
    let pattern = pattern.split('/').collect::<Vec<_>>();
    let path = path.split('/').collect::<Vec<_>>();
    let mut memo = vec![vec![None; path.len() + 1]; pattern.len() + 1];
    Ok(matches_from(&pattern, &path, 0, 0, &mut memo))
}

fn matches_from(
    pattern: &[&str],
    path: &[&str],
    pattern_index: usize,
    path_index: usize,
    memo: &mut [Vec<Option<bool>>],
) -> bool {
    if let Some(result) = memo[pattern_index][path_index] {
        return result;
    }
    let result = if pattern_index == pattern.len() {
        path_index == path.len()
    } else if pattern[pattern_index] == "**" {
        matches_from(pattern, path, pattern_index + 1, path_index, memo)
            || (path_index < path.len()
                && matches_from(pattern, path, pattern_index, path_index + 1, memo))
    } else {
        path_index < path.len()
            && component_matches(pattern[pattern_index], path[path_index])
            && matches_from(pattern, path, pattern_index + 1, path_index + 1, memo)
    };
    memo[pattern_index][path_index] = Some(result);
    result
}

fn component_matches(pattern: &str, component: &str) -> bool {
    let pattern = pattern.as_bytes();
    let component = component.as_bytes();
    let mut previous = vec![false; component.len() + 1];
    previous[0] = true;
    for byte in pattern {
        let mut next = vec![false; component.len() + 1];
        if *byte == b'*' {
            next[0] = previous[0];
            for index in 1..=component.len() {
                next[index] = previous[index] || next[index - 1];
            }
        } else {
            for index in 1..=component.len() {
                next[index] = previous[index - 1] && *byte == component[index - 1];
            }
        }
        previous = next;
    }
    previous[component.len()]
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn double_star_matches_complete_components_only() {
        assert!(path_matches("src/**", "src/lib.rs").unwrap());
        assert!(path_matches("src/**", "src/deep/lib.rs").unwrap());
        assert!(path_matches("src/**", "src").unwrap());
        assert!(!path_matches("src/**", "src-other/lib.rs").unwrap());
        assert!(validate_pattern("src/a**b").is_err());
    }

    #[test]
    fn deny_has_precedence_over_allow() {
        assert_eq!(
            evaluate_path(
                "src/secrets/key.rs",
                &["src/**".into()],
                &["src/secrets/**".into()]
            ),
            PathDecision::ExplicitlyDenied
        );
    }

    #[test]
    fn host_path_escape_forms_are_rejected() {
        for path in [
            "../secret",
            "src/../secret",
            "/src/lib.rs",
            "src\\lib.rs",
            "src//lib.rs",
            "src/\nlib.rs",
        ] {
            assert_eq!(
                evaluate_path(path, &["**".into()], &[]),
                PathDecision::Malformed
            );
        }
    }

    proptest! {
        #[test]
        fn arbitrary_strings_never_panic(pattern in any::<String>(), path in any::<String>()) {
            let _ = path_matches(&pattern, &path);
            let _ = evaluate_path(&path, &[pattern], &[]);
        }
    }
}
