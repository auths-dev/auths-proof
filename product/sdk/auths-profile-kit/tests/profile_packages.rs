use auths_profile_kit::{ProfileApi, ProfilePackage, ProfileRoster};
use std::path::{Path, PathBuf};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repository root")
}

#[test]
fn representative_packages_are_closed_and_rostered() {
    let root = repository_root();
    let roster_bytes = std::fs::read(root.join("product/runtime/auths-node/profile-packages.json"))
        .expect("profile roster");
    let roster = ProfileRoster::from_json(&roster_bytes).expect("valid profile roster");
    assert_eq!(roster.packages().len(), 3);

    for entry in roster.packages() {
        let manifest_path = root.join(entry.manifest_path());
        let manifest_bytes = std::fs::read(&manifest_path).expect("profile manifest");
        let api_bytes = std::fs::read(
            manifest_path
                .parent()
                .expect("manifest parent")
                .join("api/profile-api.json"),
        )
        .expect("profile api");
        let api = ProfileApi::from_json(&api_bytes)
            .unwrap_or_else(|error| panic!("valid {} profile api: {error:?}", entry.domain()));
        let package =
            ProfilePackage::from_json(&manifest_bytes, &api).expect("valid profile package");
        assert_eq!(package.domain().id(), entry.domain());
        for profile in package.profiles() {
            let digest = package
                .runtime_contract_digest(profile.id(), profile.version(), &api, [0; 32])
                .expect("runtime contract digest");
            assert_ne!(digest, [0; 32]);
        }
    }
}
