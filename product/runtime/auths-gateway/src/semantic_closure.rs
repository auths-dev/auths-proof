//! The digest of this gateway's semantic closure: every source file and
//! manifest of this crate and of each workspace crate it is built from, and
//! the workspace lockfile.
//!
//! The digest is a constant so a running gateway states what it was built
//! from without reading a file. A test recomputes it from the repository
//! and fails when any listed file changed, was added, or was removed; this
//! file is the one source file outside the closure.

/// SHA-256 of the schema, a NUL byte, and `semantic-closure.json`.
/// Regenerate through `semantic_closure_is_current` with `AUTHS_UPDATE_FIXTURES=1`.
pub const GATEWAY_SEMANTIC_CLOSURE_SHA256: &str =
    "f4341fa858a06ea4219b9098ae9d143a1653907095d028be66b9efcfb2c9db28";

#[cfg(test)]
mod tests {
    use super::GATEWAY_SEMANTIC_CLOSURE_SHA256;
    use auths_recipe_qualification::{
        BoundedText, GatewaySemanticClosure, SEMANTIC_CLOSURE_SCHEMA, SemanticClosureBody,
        SemanticClosureFile, Sha256Digest,
    };
    use sha2::{Digest as _, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    const GATEWAY: &str = "auths-gateway";
    const THIS_FILE: &str = "product/runtime/auths-gateway/src/semantic_closure.rs";
    const MANIFEST: &str = "product/runtime/auths-gateway/semantic-closure.json";

    fn repository() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
    }

    /// The workspace crates a gateway build contains, with their paths,
    /// from the architecture snapshot the repository gate keeps current.
    fn built_from() -> BTreeMap<String, String> {
        let graph: serde_json::Value = serde_json::from_slice(
            &std::fs::read(repository().join("architecture/dependency-graph.json"))
                .expect("dependency graph"),
        )
        .expect("graph JSON");
        let text = |value: &serde_json::Value| value.as_str().expect("text").to_owned();
        let mut edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for edge in graph["dependencies"].as_array().expect("dependencies") {
            if edge["scope"] == "internal" && edge["kind"] != "dev" {
                edges
                    .entry(text(&edge["source"]))
                    .or_default()
                    .push(text(&edge["target"]));
            }
        }
        let mut reached = BTreeSet::new();
        let mut pending = vec![GATEWAY.to_owned()];
        while let Some(package) = pending.pop() {
            if reached.insert(package.clone()) {
                pending.extend(edges.get(&package).cloned().unwrap_or_default());
            }
        }
        graph["packages"]
            .as_array()
            .expect("packages")
            .iter()
            .filter(|package| reached.contains(package["name"].as_str().expect("name")))
            .map(|package| (text(&package["name"]), text(&package["path"])))
            .collect()
    }

    fn files_under(directory: &Path, found: &mut Vec<PathBuf>) {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(directory)
            .expect("source directory")
            .map(|entry| entry.expect("directory entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                files_under(&path, found);
            } else {
                found.push(path);
            }
        }
    }

    fn closure() -> GatewaySemanticClosure {
        let root = repository();
        let mut paths = vec![root.join("Cargo.lock"), root.join("Cargo.toml")];
        for package in built_from().values() {
            paths.push(root.join(package).join("Cargo.toml"));
            files_under(&root.join(package).join("src"), &mut paths);
        }
        let mut files: Vec<SemanticClosureFile> = paths
            .iter()
            .map(|path| {
                let relative = path
                    .strip_prefix(&root)
                    .expect("inside the repository")
                    .to_str()
                    .expect("UTF-8 path")
                    .replace('\\', "/");
                (relative, path)
            })
            .filter(|(relative, _)| relative != THIS_FILE)
            .map(|(relative, path)| SemanticClosureFile {
                path: BoundedText::parse(relative).expect("bounded path"),
                sha256: Sha256Digest::from_bytes(
                    Sha256::digest(std::fs::read(path).expect("source file")).into(),
                ),
            })
            .collect();
        files.sort_by(|left, right| left.path.cmp(&right.path));
        GatewaySemanticClosure::from_body(&SemanticClosureBody {
            schema: SEMANTIC_CLOSURE_SCHEMA.to_owned(),
            files,
        })
        .expect("closure")
    }

    /// A gateway build contains no qualification issuance, so it can
    /// neither sign a qualification nor run a family's oracle.
    #[test]
    fn a_gateway_build_contains_no_issuance_or_oracle() {
        let built_from = built_from();
        assert!(built_from.contains_key("auths-recipe-qualification"));
        for package in built_from.keys() {
            assert!(
                !package.contains("issuance") && !package.contains("oracle"),
                "{package} is part of the gateway build"
            );
        }
    }

    #[test]
    fn semantic_closure_is_current() {
        let closure = closure();
        let digest = closure.digest().to_hex();
        let manifest = repository().join(MANIFEST);
        if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
            std::fs::write(&manifest, closure.canonical_bytes()).expect("write closure");
            let this = repository().join(THIS_FILE);
            let source = std::fs::read_to_string(&this).expect("this file");
            let updated = source.replacen(GATEWAY_SEMANTIC_CLOSURE_SHA256, &digest, 1);
            std::fs::write(&this, updated).expect("write digest");
            return;
        }
        let committed = std::fs::read(&manifest).unwrap_or_default();
        assert!(
            committed == closure.canonical_bytes() && digest == GATEWAY_SEMANTIC_CLOSURE_SHA256,
            "the gateway semantic closure changed; rerun with AUTHS_UPDATE_FIXTURES=1"
        );
    }
}
