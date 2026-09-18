use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let input = PathBuf::from(
        args.next()
            .ok_or("usage: auths-sigstore-bundle-import <bundle.json> <output-directory>")?,
    );
    let output = PathBuf::from(args.next().ok_or("missing output directory")?);
    if args.next().is_some() {
        return Err("too many arguments".into());
    }
    let (chain, entry) = auths_sigstore_bundle_import::import_bundle(&fs::read(input)?)
        .map_err(|error| format!("bundle import failed: {error:?}"))?;
    fs::create_dir_all(&output)?;
    fs::write(output.join("certificate-chain.cbor"), chain)?;
    fs::write(output.join("rekor-entry.cbor"), entry)?;
    Ok(())
}
