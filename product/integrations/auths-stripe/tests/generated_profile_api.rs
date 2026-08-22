use auths_stripe::generated::profile_api::{Currency, RefundInput};

#[test]
fn refund_input_matches_the_cross_language_canonical_fixture() {
    let value = RefundInput {
        payment_intent: "pi_abcdefgh".into(),
        amount: 2_500,
        currency: Currency::Usd,
    };
    let expected = hex::decode("a366616d6f756e741909c46863757272656e6379637573646d7061796d656e74496e74656e746b70695f6162636465666768").unwrap();
    assert_eq!(value.to_canonical_cbor().unwrap(), expected);
    assert_eq!(RefundInput::from_canonical_cbor(&expected).unwrap(), value);

    let invalid = RefundInput { amount: 0, ..value };
    assert!(invalid.to_canonical_cbor().is_err());
}
