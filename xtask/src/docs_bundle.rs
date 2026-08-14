use crate::*;
use std::io::Write as _;

const MEMBERS: &[(&str, &str)] = &[
    ("contract.json", "release/auths-docs-contract-v1.json"),
    ("runtime-facts.json", "release/docs/runtime-facts-v1.json"),
    (
        "public-docs-report.json",
        "release/docs/public-docs-report.json",
    ),
    (
        "typescript-public-api.txt",
        "bindings/typescript/api/public-api.txt",
    ),
    (
        "python-public-api.txt",
        "bindings/python/api/public-api.txt",
    ),
    ("public-topology.json", "bindings/public-topology-v1.json"),
];

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BundleManifest {
    schema: &'static str,
    contract_digest: String,
    source_commit: String,
    files: Vec<BundleMember>,
}

#[derive(Serialize)]
struct BundleMember {
    path: String,
    sha256: String,
    bytes: usize,
}

pub(crate) fn docs_bundle(arguments: Vec<String>) -> Result<(), String> {
    let mut check = false;
    let mut output = None;
    for argument in arguments {
        if argument == "--check" {
            check = true;
        } else if output.replace(PathBuf::from(&argument)).is_some() {
            return Err("docs-bundle accepts one output directory".to_owned());
        }
    }
    let output = output.ok_or("usage: cargo xtask docs-bundle <output-dir> [--check]")?;
    if output.exists() && !output.is_dir() {
        return Err(format!(
            "docs bundle output is not a directory: {}",
            output.display()
        ));
    }
    fs::create_dir_all(&output)
        .map_err(|error| format!("could not create {}: {error}", output.display()))?;

    let contract: Value = serde_json::from_slice(
        &fs::read(root().join("release/auths-docs-contract-v1.json"))
            .map_err(|error| format!("could not read docs contract: {error}"))?,
    )
    .map_err(|error| format!("could not parse docs contract: {error}"))?;
    let contract_digest = contract["digest"]
        .as_str()
        .ok_or("docs contract has no digest")?
        .to_owned();
    let source_commit = command_output_in("git", &["rev-parse", "HEAD"], &root(), None)?
        .trim()
        .to_owned();

    let mut files = Vec::new();
    for (bundle_path, source_path) in MEMBERS {
        let bytes = fs::read(root().join(source_path))
            .map_err(|error| format!("could not read {source_path}: {error}"))?;
        if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 {
            return Err(format!(
                "documentation bundle member is outside bounds: {source_path}"
            ));
        }
        fs::write(output.join(bundle_path), &bytes)
            .map_err(|error| format!("could not write bundle member {bundle_path}: {error}"))?;
        files.push(BundleMember {
            path: (*bundle_path).to_owned(),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            bytes: bytes.len(),
        });
    }
    let manifest = BundleManifest {
        schema: "auths.docs.bundle/1",
        contract_digest,
        source_commit,
        files,
    };
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("could not encode docs bundle manifest: {error}"))?;
    manifest_bytes.push(b'\n');
    let manifest_path = output.join("manifest.json");
    if check && manifest_path.is_file() {
        if fs::read(&manifest_path).map_err(|error| error.to_string())? != manifest_bytes {
            return Err("documentation bundle manifest drifted".to_owned());
        }
    } else {
        fs::write(&manifest_path, &manifest_bytes)
            .map_err(|error| format!("could not write docs bundle manifest: {error}"))?;
    }

    let archive_path = output.join("auths-docs-bundle-v1.tar.zst");
    let archive_file = fs::File::create(&archive_path)
        .map_err(|error| format!("could not create {}: {error}", archive_path.display()))?;
    let encoder = zstd::Encoder::new(archive_file, 19)
        .map_err(|error| format!("could not create zstd encoder: {error}"))?;
    let mut archive = tar::Builder::new(encoder.auto_finish());
    archive.mode(tar::HeaderMode::Deterministic);
    for path in MEMBERS
        .iter()
        .map(|(path, _)| *path)
        .chain(["manifest.json"])
    {
        let bytes = fs::read(output.join(path))
            .map_err(|error| format!("could not read bundle member {path}: {error}"))?;
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        archive
            .append_data(&mut header, path, bytes.as_slice())
            .map_err(|error| format!("could not archive {path}: {error}"))?;
    }
    archive
        .into_inner()
        .map_err(|error| format!("could not finish docs bundle archive: {error}"))?
        .flush()
        .map_err(|error| format!("could not flush docs bundle archive: {error}"))?;
    println!("documentation bundle written to {}", output.display());
    Ok(())
}
