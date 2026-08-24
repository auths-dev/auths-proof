use auths_connections::{CredentialScope, ProviderConnectionAdapter};
use auths_opentofu::connection::OpenTofuConnectionAdapter;

#[test]
fn opentofu_descriptor_and_scope_are_exact() {
    let adapter = OpenTofuConnectionAdapter::new();
    let fixture: serde_json::Value =
        serde_json::from_slice(include_bytes!("../fixtures/connection/v1/valid.json")).unwrap();
    let canonical = serde_json_canonicalizer::to_vec(&fixture).unwrap();
    let validated = adapter.validate_descriptor(&canonical).unwrap();
    adapter
        .permits_scope(
            &validated,
            &CredentialScope::parse("opentofu.saved-plan.apply/1").unwrap(),
        )
        .unwrap();
    assert!(
        adapter
            .permits_scope(
                &validated,
                &CredentialScope::parse("opentofu.backend.admin/1").unwrap(),
            )
            .is_err()
    );
}
