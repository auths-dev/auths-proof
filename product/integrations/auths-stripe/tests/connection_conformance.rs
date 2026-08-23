use auths_connections::{CredentialScope, ProviderConnectionAdapter};
use auths_stripe::connection::StripeConnectionAdapter;

#[test]
fn stripe_descriptor_and_scope_are_exact() {
    let adapter = StripeConnectionAdapter::new();
    let descriptor = include_bytes!("../fixtures/connection/v1/valid.json");
    let validated = adapter.validate_descriptor(descriptor).unwrap();
    adapter
        .permits_scope(
            &validated,
            &CredentialScope::parse("stripe.refunds.write/1").unwrap(),
        )
        .unwrap();
    assert!(
        adapter
            .permits_scope(
                &validated,
                &CredentialScope::parse("stripe.payouts.write/1").unwrap(),
            )
            .is_err()
    );
}
