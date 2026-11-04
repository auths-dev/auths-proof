//! Shared hostile journal corpus. Every alteration preserves the native writer's
//! encoding except the explicitly named encoding negatives, avoiding one broken
//! canonicalization check masking independent binding/evidence checks.
use crate::{GatewayAttemptKey, GatewayAttemptStore, GatewayRecordKind};
use serde_json::{Value, json};

fn member(bytes: &[u8], name: &str, replacement: &Value) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).expect("native JSON");
    let needle = format!("\"{name}\":");
    let start = text.find(&needle).expect("native member") + needle.len();
    let mut stream = serde_json::Deserializer::from_slice(&bytes[start..]).into_iter::<Value>();
    stream.next().expect("value").expect("native value");
    let end = start + stream.byte_offset();
    let mut changed = bytes[..start].to_vec();
    changed.extend(serde_json::to_vec(replacement).expect("replacement"));
    changed.extend_from_slice(&bytes[end..]);
    changed
}

pub(super) fn exercise(
    store: &dyn GatewayAttemptStore,
    key: GatewayAttemptKey,
    original: &[u8],
    mut refuse: impl FnMut(),
    mut positive: impl FnMut(),
) -> Vec<Value> {
    positive();
    let source: Value = serde_json::from_slice(original).expect("native record");
    let mut variants = vec![
        (
            "obsolete-schema",
            member(original, "schema", &json!("auths.obsolete-journal/0")),
        ),
        ("revision-zero", member(original, "revision", &json!(0))),
        (
            "revision-unsafe-integer",
            member(original, "revision", &json!(1_u64 << 53)),
        ),
        (
            "revision-boolean",
            member(original, "revision", &json!(true)),
        ),
        (
            "revision-fractional",
            member(original, "revision", &json!(1.5)),
        ),
        (
            "signed-time-unsafe-integer",
            member(original, "evaluated_at", &json!(1_u64 << 53)),
        ),
        (
            "changed-operation",
            member(original, "operation_id", &json!("unrelated-operation")),
        ),
        (
            "changed-binding",
            member(original, "binding_canonical", &json!("{}")),
        ),
        (
            "changed-authority",
            member(original, "authority_canonical_b64", &json!("e30=")),
        ),
        (
            "changed-approval",
            member(original, "approval_canonical", &json!("{}")),
        ),
        (
            "missing-entry-evidence",
            member(original, "entry", &Value::Null),
        ),
        (
            "inconsistent-protocol",
            member(original, "state", &json!({"protocol":"obsolete"})),
        ),
        ("truncated", original[..original.len() - 1].to_vec()),
        (
            "noncanonical-whitespace",
            [b" ".as_slice(), original].concat(),
        ),
    ];
    variants.push((
        "duplicate-member",
        [
            format!("{{\"revision\":{},", source["revision"]).as_bytes(),
            &original[1..],
        ]
        .concat(),
    ));
    variants.push((
        "unknown-member",
        [b"{\"obsolete_authority\":true,".as_slice(), &original[1..]].concat(),
    ));
    let mut cases = Vec::new();
    for (name, bytes) in variants {
        store
            .replace(GatewayRecordKind::Attempt, &key, original, &bytes)
            .expect("isolated corruption injection");
        refuse();
        assert_eq!(
            store.load(GatewayRecordKind::Attempt, &key).expect("load"),
            Some(bytes.clone()),
            "refusal cannot repair or re-sign {name}"
        );
        store
            .replace(GatewayRecordKind::Attempt, &key, &bytes, original)
            .expect("restore exact owned record");
        positive();
        cases.push(json!({"case":name,"refused_without_custody_or_transport":true,"bytes_unchanged":true,"restored_exact_positive":true}));
    }
    let oversized = vec![b' '; auths_stores::MAX_GATEWAY_RECORD_BYTES + 1];
    assert!(
        store
            .replace(GatewayRecordKind::Attempt, &key, original, &oversized)
            .is_err(),
        "adapter enforces the journal byte bound"
    );
    assert_eq!(
        store.load(GatewayRecordKind::Attempt, &key).expect("load"),
        Some(original.to_vec())
    );
    positive();
    cases.push(
        json!({"case":"record-limit-plus-one","refused_at_adapter":true,"original_preserved":true}),
    );
    cases
}
