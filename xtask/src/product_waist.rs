use crate::*;

const PRODUCT_WAIST_MANIFEST: &str = "product/conformance/v1/simplified-product-waist.json";

pub(crate) fn product_waist_conformance(update: bool) -> Result<(), String> {
    let manifest = auths_testkit::product_waist::simplified_product_waist_manifest();
    manifest.validate()?;
    for case in &manifest.cases {
        for (surface, path) in [
            ("Rust", &case.evidence.rust),
            ("TypeScript", &case.evidence.typescript),
            ("Python", &case.evidence.python),
        ] {
            if !root().join(path).exists() {
                return Err(format!(
                    "product-waist case {} has missing {surface} evidence: {path}",
                    case.id
                ));
            }
        }
    }
    let generator = root().join(&manifest.fixture_generator);
    let generator_source = fs::read_to_string(&generator)
        .map_err(|error| format!("could not read {}: {error}", generator.display()))?;
    if !generator_source.contains("workflow.projection.json") {
        return Err("Rust fixture generator omitted the workflow projection".to_owned());
    }
    for field in &manifest.fixture_fields {
        let leaf = field.rsplit('.').next().unwrap_or(field);
        if !generator_source.contains(leaf) {
            return Err(format!(
                "Rust fixture generator omitted product-waist field {field}"
            ));
        }
    }

    let mut encoded = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("could not encode product-waist manifest: {error}"))?;
    encoded.push(b'\n');
    let path = root().join(PRODUCT_WAIST_MANIFEST);
    if update {
        let parent = path
            .parent()
            .ok_or("product-waist manifest has no parent directory")?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
        fs::write(&path, encoded)
            .map_err(|error| format!("could not update {}: {error}", path.display()))?;
        println!("simplified product-waist conformance manifest updated");
        return Ok(());
    }
    let committed = fs::read(&path).map_err(|error| {
        format!(
            "could not read {}: {error}; run `cargo xtask product-waist-conformance --update`",
            path.display()
        )
    })?;
    if committed != encoded {
        return Err(
            "simplified product-waist conformance drifted; run `cargo xtask product-waist-conformance --update`"
                .to_owned(),
        );
    }
    println!(
        "simplified product-waist conformance passed ({} cases)",
        manifest.cases.len()
    );
    Ok(())
}
