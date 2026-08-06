//! Enforces that language bindings hold no protocol meaning of their own.
//!
//! Bindings exist to call the Rust core and the WASM authoring ABI. A
//! cryptographic primitive or protocol constant written directly in binding
//! source is a second opinion about what Auths means, and every additional
//! language multiplies it. Anything genuinely local must be declared in
//! `architecture.toml` with a written reason, and the declaration must stay
//! exact: a stale allowance fails just as loudly as an undeclared primitive.

use crate::architecture::repository_files;
use crate::process::root;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const MINIMUM_REASON_BYTES: usize = 32;

#[derive(Debug)]
struct BindingSemanticsPolicy {
    scanned_paths: Vec<String>,
    exempt_paths: Vec<String>,
    scanned_extensions: BTreeSet<String>,
    forbidden_patterns: Vec<String>,
    allowances: Vec<Allowance>,
}

#[derive(Debug, Clone)]
struct Allowance {
    path: String,
    pattern: String,
    reason: String,
}

#[derive(Debug)]
struct Finding {
    path: String,
    line: usize,
    pattern: String,
}

pub(crate) fn binding_semantics() -> Result<(), String> {
    let policy = load_policy()?;
    let mut findings = Vec::new();
    let mut used: BTreeSet<(String, String)> = BTreeSet::new();
    let mut scanned_files = 0_usize;

    for scanned in &policy.scanned_paths {
        let directory = root().join(scanned);
        if !directory.is_dir() {
            return Err(format!(
                "binding semantics scans {scanned}, which is not a directory"
            ));
        }
        for path in repository_files(&directory)? {
            let relative = relative_path(&path)?;
            if policy
                .exempt_paths
                .iter()
                .any(|exempt| relative.starts_with(exempt))
            {
                continue;
            }
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            if !policy.scanned_extensions.contains(extension) {
                continue;
            }
            let contents = fs::read_to_string(&path)
                .map_err(|error| format!("could not read {relative}: {error}"))?;
            scanned_files += 1;
            for (index, line) in contents.lines().enumerate() {
                for pattern in &policy.forbidden_patterns {
                    if !line.contains(pattern.as_str()) {
                        continue;
                    }
                    let allowed = policy.allowances.iter().any(|allowance| {
                        allowance.path == relative && allowance.pattern == *pattern
                    });
                    if allowed {
                        used.insert((relative.clone(), pattern.clone()));
                    } else {
                        findings.push(Finding {
                            path: relative.clone(),
                            line: index + 1,
                            pattern: pattern.clone(),
                        });
                    }
                }
            }
        }
    }

    let stale: Vec<_> = policy
        .allowances
        .iter()
        .filter(|allowance| !used.contains(&(allowance.path.clone(), allowance.pattern.clone())))
        .collect();

    if !findings.is_empty() || !stale.is_empty() {
        let mut message = String::new();
        if !findings.is_empty() {
            message.push_str(
                "binding source holds protocol meaning that belongs to the Rust core; \
                 call the authoring ABI instead, or declare an exact \
                 [[binding_semantics.allowances]] entry with a written reason:\n",
            );
            for finding in &findings {
                message.push_str(&format!(
                    "  {}:{} uses {}\n",
                    finding.path, finding.line, finding.pattern
                ));
            }
        }
        if !stale.is_empty() {
            message.push_str("stale binding-semantics allowances must be removed:\n");
            for allowance in &stale {
                message.push_str(&format!(
                    "  {} no longer uses {}\n",
                    allowance.path, allowance.pattern
                ));
            }
        }
        return Err(message.trim_end().to_owned());
    }

    println!(
        "binding semantics passed: {scanned_files} files, {} patterns, {} declared allowances",
        policy.forbidden_patterns.len(),
        policy.allowances.len()
    );
    Ok(())
}

fn relative_path(path: &Path) -> Result<String, String> {
    Ok(path
        .strip_prefix(root())
        .map_err(|_| format!("binding file escaped the repository: {}", path.display()))?
        .to_string_lossy()
        .replace('\\', "/"))
}

fn load_policy() -> Result<BindingSemanticsPolicy, String> {
    let source = fs::read_to_string(root().join("architecture.toml"))
        .map_err(|error| format!("could not read architecture.toml: {error}"))?;
    let document: toml::Value =
        toml::from_str(&source).map_err(|error| format!("invalid architecture.toml: {error}"))?;
    let table = document
        .get("binding_semantics")
        .and_then(toml::Value::as_table)
        .ok_or("architecture.toml has no binding_semantics table")?;

    let strings = |key: &str| -> Result<Vec<String>, String> {
        table
            .get(key)
            .and_then(toml::Value::as_array)
            .ok_or_else(|| format!("binding_semantics.{key} must be an array"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("binding_semantics.{key} must contain strings"))
            })
            .collect()
    };

    let scanned_paths = strings("scanned_paths")?;
    let exempt_paths = strings("exempt_paths")?;
    let scanned_extensions: BTreeSet<String> = strings("scanned_extensions")?.into_iter().collect();
    let forbidden_patterns = strings("forbidden_patterns")?;
    if scanned_paths.is_empty() || forbidden_patterns.is_empty() || scanned_extensions.is_empty() {
        return Err(
            "binding_semantics must declare scanned paths, extensions, and patterns".to_owned(),
        );
    }

    let mut allowances = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in table
        .get("allowances")
        .and_then(toml::Value::as_array)
        .unwrap_or(&Vec::new())
    {
        let entry = entry
            .as_table()
            .ok_or("binding_semantics.allowances entries must be tables")?;
        let field = |key: &str| -> Result<String, String> {
            entry
                .get(key)
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("binding_semantics allowance requires {key}"))
        };
        let allowance = Allowance {
            path: field("path")?,
            pattern: field("pattern")?,
            reason: field("reason")?,
        };
        if allowance.reason.trim().len() < MINIMUM_REASON_BYTES {
            return Err(format!(
                "binding_semantics allowance for {} must state why the meaning is local, in at least {MINIMUM_REASON_BYTES} characters",
                allowance.path
            ));
        }
        if !forbidden_patterns.contains(&allowance.pattern) {
            return Err(format!(
                "binding_semantics allowance for {} names unscanned pattern {}",
                allowance.path, allowance.pattern
            ));
        }
        if !seen.insert((allowance.path.clone(), allowance.pattern.clone())) {
            return Err(format!(
                "duplicate binding_semantics allowance for {} and {}",
                allowance.path, allowance.pattern
            ));
        }
        allowances.push(allowance);
    }

    Ok(BindingSemanticsPolicy {
        scanned_paths,
        exempt_paths,
        scanned_extensions,
        forbidden_patterns,
        allowances,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_policy_loads_and_is_exact() {
        let policy = load_policy().expect("binding semantics policy must load");
        assert!(
            policy
                .scanned_paths
                .iter()
                .any(|path| path.contains("typescript"))
        );
        assert!(
            policy
                .exempt_paths
                .iter()
                .any(|path| path.contains("independent"))
        );
        for allowance in &policy.allowances {
            assert!(allowance.reason.trim().len() >= MINIMUM_REASON_BYTES);
        }
    }

    #[test]
    fn repository_bindings_hold_no_undeclared_meaning() {
        binding_semantics().expect("binding semantics must pass");
    }
}
