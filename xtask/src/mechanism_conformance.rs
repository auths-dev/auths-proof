use crate::*;

const MANIFEST: &str = "product/conformance/v1/mechanism-profile-conformance.json";
const TYPESCRIPT: &str = "bindings/typescript/src/generated/mechanism-conformance.ts";
const PYTHON: &str = "bindings/python/python/auths/_mechanism_conformance.py";

pub(crate) fn mechanism_conformance(update: bool) -> Result<(), String> {
    let catalog = auths_testkit::mechanism_conformance::mechanism_profile_conformance_catalog();
    catalog.validate()?;
    let mut encoded = serde_json::to_vec_pretty(&catalog)
        .map_err(|error| format!("could not encode mechanism conformance catalog: {error}"))?;
    encoded.push(b'\n');
    let json = String::from_utf8(encoded.clone())
        .map_err(|_| "mechanism conformance catalog was not UTF-8".to_owned())?;
    let typescript = format!(
        "export const CONFORMANCE_CATALOG = {} as const;\n",
        json.trim_end()
    );
    let python = format!(
        "from __future__ import annotations\n\nimport json\n\nCONFORMANCE_CATALOG = json.loads(r'''{json}''')\n\n__all__ = [\"CONFORMANCE_CATALOG\"]\n"
    );
    let artifacts = [
        (MANIFEST, encoded),
        (TYPESCRIPT, typescript.into_bytes()),
        (PYTHON, python.into_bytes()),
    ];
    if update {
        for (relative, bytes) in &artifacts {
            let path = root().join(relative);
            let parent = path
                .parent()
                .ok_or("mechanism conformance artifact has no parent directory")?;
            fs::create_dir_all(parent)
                .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
            fs::write(&path, bytes)
                .map_err(|error| format!("could not update {}: {error}", path.display()))?;
        }
        println!("mechanism/profile conformance catalog updated");
        return Ok(());
    }
    for (relative, bytes) in artifacts {
        let path = root().join(relative);
        let committed = fs::read(&path).map_err(|error| {
            format!(
                "could not read {}: {error}; run `cargo xtask mechanism-conformance --update`",
                path.display()
            )
        })?;
        if committed != bytes {
            return Err(format!(
                "mechanism/profile conformance artifact drifted: {relative}; run `cargo xtask mechanism-conformance --update`"
            ));
        }
    }
    println!(
        "mechanism/profile conformance catalog passed ({} suites)",
        catalog.suites.len()
    );
    Ok(())
}
