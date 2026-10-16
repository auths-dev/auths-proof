#![allow(clippy::too_many_lines)]

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const QUALIFICATION_PATH: &str = "formal/qualification/aeneas/qualification.toml";
const QUALIFICATION_SCHEMA: &str = "auths-proof-aeneas-qualification/v1";
const QUALIFICATION_BOUNDARY_CONTRACT_SHA256: &str =
    "cb3d1bff851332bd0f01c207b6b551a99c276beb4d0cc3022190b8db49593a4b";

const AENEAS_OUTPUT_MAPPINGS: &[(&str, &str)] = &[
    (
        "scope_codec-run/qualification/aeneas/generated/scope_codec/Types.lean",
        "formal/qualification/aeneas/generated/scope_codec/Types.lean",
    ),
    (
        "scope_codec-run/qualification/aeneas/generated/scope_codec/Funs.lean",
        "formal/qualification/aeneas/generated/scope_codec/Funs.lean",
    ),
    (
        "scope_codec-run/qualification/aeneas/generated/scope_codec/TypesExternal_Template.lean",
        "formal/qualification/aeneas/generated/scope_codec/TypesExternal_Template.lean",
    ),
    (
        "scope_codec-run/qualification/aeneas/generated/scope_codec/FunsExternal_Template.lean",
        "formal/qualification/aeneas/generated/scope_codec/FunsExternal_Template.lean",
    ),
    (
        "scope_codec-run/translation.json",
        "formal/qualification/aeneas/generated/scope_codec/translation.json",
    ),
    (
        "status_selection-run/qualification/aeneas/generated/status_selection/Types.lean",
        "formal/qualification/aeneas/generated/status_selection/Types.lean",
    ),
    (
        "status_selection-run/qualification/aeneas/generated/status_selection/Funs.lean",
        "formal/qualification/aeneas/generated/status_selection/Funs.lean",
    ),
    (
        "status_selection-run/qualification/aeneas/generated/status_selection/FunsExternal_Template.lean",
        "formal/qualification/aeneas/generated/status_selection/FunsExternal_Template.lean",
    ),
    (
        "status_selection-run/translation.json",
        "formal/qualification/aeneas/generated/status_selection/translation.json",
    ),
    (
        "temporal_witness-run/qualification/aeneas/generated/temporal_witness/Types.lean",
        "formal/qualification/aeneas/generated/temporal_witness/Types.lean",
    ),
    (
        "temporal_witness-run/qualification/aeneas/generated/temporal_witness/Funs.lean",
        "formal/qualification/aeneas/generated/temporal_witness/Funs.lean",
    ),
    (
        "temporal_witness-run/qualification/aeneas/generated/temporal_witness/FunsExternal_Template.lean",
        "formal/qualification/aeneas/generated/temporal_witness/FunsExternal_Template.lean",
    ),
    (
        "temporal_witness-run/translation.json",
        "formal/qualification/aeneas/generated/temporal_witness/translation.json",
    ),
    (
        "suite_adapter-run/qualification/aeneas/generated/suite_adapter/Types.lean",
        "formal/qualification/aeneas/generated/suite_adapter/Types.lean",
    ),
    (
        "suite_adapter-run/qualification/aeneas/generated/suite_adapter/TypesExternal_Template.lean",
        "formal/qualification/aeneas/generated/suite_adapter/TypesExternal_Template.lean",
    ),
    (
        "suite_adapter-run/qualification/aeneas/generated/suite_adapter/Funs.lean",
        "formal/qualification/aeneas/generated/suite_adapter/Funs.lean",
    ),
    (
        "suite_adapter-run/qualification/aeneas/generated/suite_adapter/FunsExternal_Template.lean",
        "formal/qualification/aeneas/generated/suite_adapter/FunsExternal_Template.lean",
    ),
    (
        "suite_adapter-run/translation.json",
        "formal/qualification/aeneas/generated/suite_adapter/translation.json",
    ),
    (
        "p256-run/qualification/aeneas/generated/p256/Types.lean",
        "formal/qualification/aeneas/generated/p256/Types.lean",
    ),
    (
        "p256-run/qualification/aeneas/generated/p256/TypesExternal_Template.lean",
        "formal/qualification/aeneas/generated/p256/TypesExternal_Template.lean",
    ),
    (
        "p256-run/qualification/aeneas/generated/p256/Funs.lean",
        "formal/qualification/aeneas/generated/p256/Funs.lean",
    ),
    (
        "p256-run/qualification/aeneas/generated/p256/FunsExternal_Template.lean",
        "formal/qualification/aeneas/generated/p256/FunsExternal_Template.lean",
    ),
    (
        "p256-run/translation.json",
        "formal/qualification/aeneas/generated/p256/translation.json",
    ),
    (
        "p256-run/name-normalization.json",
        "formal/qualification/aeneas/generated/p256/name-normalization.json",
    ),
    (
        "sha256-run/qualification/aeneas/generated/sha256/Types.lean",
        "formal/qualification/aeneas/generated/sha256/Types.lean",
    ),
    (
        "sha256-run/qualification/aeneas/generated/sha256/TypesExternal_Template.lean",
        "formal/qualification/aeneas/generated/sha256/TypesExternal_Template.lean",
    ),
    (
        "sha256-run/qualification/aeneas/generated/sha256/Funs.lean",
        "formal/qualification/aeneas/generated/sha256/Funs.lean",
    ),
    (
        "sha256-run/qualification/aeneas/generated/sha256/FunsExternal_Template.lean",
        "formal/qualification/aeneas/generated/sha256/FunsExternal_Template.lean",
    ),
    (
        "sha256-run/translation.json",
        "formal/qualification/aeneas/generated/sha256/translation.json",
    ),
    (
        "sha256-run/foreign-name-normalization.json",
        "formal/qualification/aeneas/generated/sha256/foreign-name-normalization.json",
    ),
    (
        "signature-run/qualification/aeneas/generated/signature/TypesExternal_Template.lean",
        "formal/qualification/aeneas/generated/signature/TypesExternal_Template.lean",
    ),
    (
        "signature-run/qualification/aeneas/generated/signature/FunsExternal_Template.lean",
        "formal/qualification/aeneas/generated/signature/FunsExternal_Template.lean",
    ),
    (
        "signature-run/qualification/aeneas/generated/signature/Types.lean",
        "formal/qualification/aeneas/generated/signature/Types.lean",
    ),
    (
        "signature-run/qualification/aeneas/generated/signature/Funs.lean",
        "formal/qualification/aeneas/generated/signature/Funs.lean",
    ),
    (
        "signature-run/translation.json",
        "formal/qualification/aeneas/generated/signature/translation.json",
    ),
    (
        "composition-run/qualification/aeneas/generated/composition/Types.lean",
        "formal/qualification/aeneas/generated/composition/Types.lean",
    ),
    (
        "composition-run/qualification/aeneas/generated/composition/TypesExternal_Template.lean",
        "formal/qualification/aeneas/generated/composition/TypesExternal_Template.lean",
    ),
    (
        "composition-run/qualification/aeneas/generated/composition/Funs.lean",
        "formal/qualification/aeneas/generated/composition/Funs.lean",
    ),
    (
        "composition-run/qualification/aeneas/generated/composition/FunsExternal_Template.lean",
        "formal/qualification/aeneas/generated/composition/FunsExternal_Template.lean",
    ),
    (
        "composition-run/translation.json",
        "formal/qualification/aeneas/generated/composition/translation.json",
    ),
    (
        "stores-run/qualification/aeneas/generated/stores/Types.lean",
        "formal/qualification/aeneas/generated/stores/Types.lean",
    ),
    (
        "stores-run/qualification/aeneas/generated/stores/Funs.lean",
        "formal/qualification/aeneas/generated/stores/Funs.lean",
    ),
    (
        "stores-run/translation.json",
        "formal/qualification/aeneas/generated/stores/translation.json",
    ),
    (
        "codec-run/qualification/aeneas/generated/codec/Types.lean",
        "formal/qualification/aeneas/generated/codec/Types.lean",
    ),
    (
        "codec-run/qualification/aeneas/generated/codec/Funs.lean",
        "formal/qualification/aeneas/generated/codec/Funs.lean",
    ),
    (
        "codec-run/qualification/aeneas/generated/codec/TypesExternal_Template.lean",
        "formal/qualification/aeneas/generated/codec/TypesExternal_Template.lean",
    ),
    (
        "codec-run/qualification/aeneas/generated/codec/FunsExternal_Template.lean",
        "formal/qualification/aeneas/generated/codec/FunsExternal_Template.lean",
    ),
    (
        "codec-run/translation.json",
        "formal/qualification/aeneas/generated/codec/translation.json",
    ),
    (
        "model-run/qualification/aeneas/generated/model/Types.lean",
        "formal/qualification/aeneas/generated/model/Types.lean",
    ),
    (
        "model-run/qualification/aeneas/generated/model/Funs.lean",
        "formal/qualification/aeneas/generated/model/Funs.lean",
    ),
    (
        "model-run/qualification/aeneas/generated/model/FunsExternal_Template.lean",
        "formal/qualification/aeneas/generated/model/FunsExternal_Template.lean",
    ),
    (
        "model-run/translation.json",
        "formal/qualification/aeneas/generated/model/translation.json",
    ),
    (
        "algebra-run/qualification/aeneas/generated/algebra/Types.lean",
        "formal/qualification/aeneas/generated/algebra/Types.lean",
    ),
    (
        "algebra-run/qualification/aeneas/generated/algebra/Funs.lean",
        "formal/qualification/aeneas/generated/algebra/Funs.lean",
    ),
    (
        "algebra-run/translation.json",
        "formal/qualification/aeneas/generated/algebra/translation.json",
    ),
    (
        "authority-run/qualification/aeneas/generated/authority/Types.lean",
        "formal/qualification/aeneas/generated/authority/Types.lean",
    ),
    (
        "authority-run/qualification/aeneas/generated/authority/TypesExternal_Template.lean",
        "formal/qualification/aeneas/generated/authority/TypesExternal_Template.lean",
    ),
    (
        "authority-run/qualification/aeneas/generated/authority/Funs.lean",
        "formal/qualification/aeneas/generated/authority/Funs.lean",
    ),
    (
        "authority-run/qualification/aeneas/generated/authority/FunsExternal_Template.lean",
        "formal/qualification/aeneas/generated/authority/FunsExternal_Template.lean",
    ),
    (
        "authority-run/translation.json",
        "formal/qualification/aeneas/generated/authority/translation.json",
    ),
    (
        "bounded_policy-run/qualification/aeneas/generated/bounded_policy/Types.lean",
        "formal/qualification/aeneas/generated/bounded_policy/Types.lean",
    ),
    (
        "bounded_policy-run/qualification/aeneas/generated/bounded_policy/Funs.lean",
        "formal/qualification/aeneas/generated/bounded_policy/Funs.lean",
    ),
    (
        "bounded_policy-run/translation.json",
        "formal/qualification/aeneas/generated/bounded_policy/translation.json",
    ),
    (
        "lifecycle-run/qualification/aeneas/generated/lifecycle/Types.lean",
        "formal/qualification/aeneas/generated/lifecycle/Types.lean",
    ),
    (
        "lifecycle-run/qualification/aeneas/generated/lifecycle/Funs.lean",
        "formal/qualification/aeneas/generated/lifecycle/Funs.lean",
    ),
    (
        "lifecycle-run/translation.json",
        "formal/qualification/aeneas/generated/lifecycle/translation.json",
    ),
    (
        "gateway-run/qualification/aeneas/generated/gateway/Types.lean",
        "formal/qualification/aeneas/generated/gateway/Types.lean",
    ),
    (
        "gateway-run/qualification/aeneas/generated/gateway/Funs.lean",
        "formal/qualification/aeneas/generated/gateway/Funs.lean",
    ),
    (
        "gateway-run/qualification/aeneas/generated/gateway/FunsExternal_Template.lean",
        "formal/qualification/aeneas/generated/gateway/FunsExternal_Template.lean",
    ),
    (
        "gateway-run/translation.json",
        "formal/qualification/aeneas/generated/gateway/translation.json",
    ),
    (
        "connections-run/qualification/aeneas/generated/connections/Types.lean",
        "formal/qualification/aeneas/generated/connections/Types.lean",
    ),
    (
        "connections-run/qualification/aeneas/generated/connections/Funs.lean",
        "formal/qualification/aeneas/generated/connections/Funs.lean",
    ),
    (
        "connections-run/translation.json",
        "formal/qualification/aeneas/generated/connections/translation.json",
    ),
];

const REVIEWED_BRIDGE_ARTIFACTS: &[&str] = &[
    "formal/qualification/aeneas/generated/standard/CheckedResult.lean",
    "formal/qualification/aeneas/generated/gateway/FunsExternal.lean",
    "formal/qualification/aeneas/generated/scope_codec/TypesExternal.lean",
    "formal/qualification/aeneas/generated/scope_codec/FunsExternal.lean",
    "formal/qualification/aeneas/generated/status_selection/FunsExternal.lean",
    "formal/qualification/aeneas/generated/temporal_witness/FunsExternal.lean",
    "formal/qualification/aeneas/generated/suite_adapter/TypesExternal.lean",
    "formal/qualification/aeneas/generated/suite_adapter/FunsExternal.lean",
    "formal/qualification/aeneas/generated/p256/TypesExternal.lean",
    "formal/qualification/aeneas/generated/p256/FunsExternal.lean",
    "formal/qualification/aeneas/generated/sha256/TypesExternal.lean",
    "formal/qualification/aeneas/generated/sha256/FunsExternal.lean",
    "formal/qualification/aeneas/generated/signature/TypesExternal.lean",
    "formal/qualification/aeneas/generated/signature/FunsExternal.lean",
    "formal/qualification/aeneas/generated/composition/TypesExternal.lean",
    "formal/qualification/aeneas/generated/composition/FunsExternal.lean",
    "formal/qualification/aeneas/generated/codec/TypesExternal.lean",
    "formal/qualification/aeneas/generated/codec/FunsExternal.lean",
    "formal/qualification/aeneas/generated/model/FunsExternal.lean",
    "formal/qualification/aeneas/generated/authority/TypesExternal.lean",
    "formal/qualification/aeneas/generated/authority/FunsExternal.lean",
];

/// Exact artifact set whose bytes a successful clean reproduction certifies.
/// Keep this ordered list aligned with the checked-in qualification manifest;
/// synchronization and reviewed bridge destinations are checked against it.
const GENERATED_ARTIFACTS: &[&str] = &[
    "formal/qualification/aeneas/generated/standard/CheckedResult.lean",
    "formal/qualification/aeneas/generated/scope_codec/Types.lean",
    "formal/qualification/aeneas/generated/scope_codec/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/scope_codec/TypesExternal.lean",
    "formal/qualification/aeneas/generated/scope_codec/Funs.lean",
    "formal/qualification/aeneas/generated/scope_codec/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/scope_codec/FunsExternal.lean",
    "formal/qualification/aeneas/generated/scope_codec/translation.json",
    "formal/qualification/aeneas/generated/status_selection/Types.lean",
    "formal/qualification/aeneas/generated/status_selection/Funs.lean",
    "formal/qualification/aeneas/generated/status_selection/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/status_selection/FunsExternal.lean",
    "formal/qualification/aeneas/generated/status_selection/translation.json",
    "formal/qualification/aeneas/generated/temporal_witness/Types.lean",
    "formal/qualification/aeneas/generated/temporal_witness/Funs.lean",
    "formal/qualification/aeneas/generated/temporal_witness/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/temporal_witness/FunsExternal.lean",
    "formal/qualification/aeneas/generated/temporal_witness/translation.json",
    "formal/qualification/aeneas/generated/suite_adapter/Types.lean",
    "formal/qualification/aeneas/generated/suite_adapter/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/suite_adapter/TypesExternal.lean",
    "formal/qualification/aeneas/generated/suite_adapter/Funs.lean",
    "formal/qualification/aeneas/generated/suite_adapter/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/suite_adapter/FunsExternal.lean",
    "formal/qualification/aeneas/generated/suite_adapter/translation.json",
    "formal/qualification/aeneas/generated/p256/Types.lean",
    "formal/qualification/aeneas/generated/p256/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/p256/TypesExternal.lean",
    "formal/qualification/aeneas/generated/p256/Funs.lean",
    "formal/qualification/aeneas/generated/p256/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/p256/FunsExternal.lean",
    "formal/qualification/aeneas/generated/p256/translation.json",
    "formal/qualification/aeneas/generated/p256/name-normalization.json",
    "formal/qualification/aeneas/generated/sha256/Types.lean",
    "formal/qualification/aeneas/generated/sha256/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/sha256/TypesExternal.lean",
    "formal/qualification/aeneas/generated/sha256/Funs.lean",
    "formal/qualification/aeneas/generated/sha256/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/sha256/FunsExternal.lean",
    "formal/qualification/aeneas/generated/sha256/translation.json",
    "formal/qualification/aeneas/generated/sha256/foreign-name-normalization.json",
    "formal/qualification/aeneas/generated/signature/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/signature/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/signature/TypesExternal.lean",
    "formal/qualification/aeneas/generated/signature/FunsExternal.lean",
    "formal/qualification/aeneas/generated/signature/Types.lean",
    "formal/qualification/aeneas/generated/signature/Funs.lean",
    "formal/qualification/aeneas/generated/signature/translation.json",
    "formal/qualification/aeneas/generated/composition/Types.lean",
    "formal/qualification/aeneas/generated/composition/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/composition/TypesExternal.lean",
    "formal/qualification/aeneas/generated/composition/Funs.lean",
    "formal/qualification/aeneas/generated/composition/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/composition/FunsExternal.lean",
    "formal/qualification/aeneas/generated/composition/translation.json",
    "formal/qualification/aeneas/generated/stores/Types.lean",
    "formal/qualification/aeneas/generated/stores/Funs.lean",
    "formal/qualification/aeneas/generated/stores/translation.json",
    "formal/qualification/aeneas/generated/codec/Types.lean",
    "formal/qualification/aeneas/generated/codec/Funs.lean",
    "formal/qualification/aeneas/generated/codec/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/codec/TypesExternal.lean",
    "formal/qualification/aeneas/generated/codec/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/codec/FunsExternal.lean",
    "formal/qualification/aeneas/generated/codec/translation.json",
    "formal/qualification/aeneas/generated/model/Types.lean",
    "formal/qualification/aeneas/generated/model/Funs.lean",
    "formal/qualification/aeneas/generated/model/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/model/FunsExternal.lean",
    "formal/qualification/aeneas/generated/model/translation.json",
    "formal/qualification/aeneas/generated/algebra/Types.lean",
    "formal/qualification/aeneas/generated/algebra/Funs.lean",
    "formal/qualification/aeneas/generated/algebra/translation.json",
    "formal/qualification/aeneas/generated/authority/Types.lean",
    "formal/qualification/aeneas/generated/authority/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/authority/TypesExternal.lean",
    "formal/qualification/aeneas/generated/authority/Funs.lean",
    "formal/qualification/aeneas/generated/authority/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/authority/FunsExternal.lean",
    "formal/qualification/aeneas/generated/authority/translation.json",
    "formal/qualification/aeneas/generated/bounded_policy/Types.lean",
    "formal/qualification/aeneas/generated/bounded_policy/Funs.lean",
    "formal/qualification/aeneas/generated/bounded_policy/translation.json",
    "formal/qualification/aeneas/generated/lifecycle/Types.lean",
    "formal/qualification/aeneas/generated/lifecycle/Funs.lean",
    "formal/qualification/aeneas/generated/lifecycle/translation.json",
    "formal/qualification/aeneas/generated/gateway/Types.lean",
    "formal/qualification/aeneas/generated/gateway/Funs.lean",
    "formal/qualification/aeneas/generated/gateway/FunsExternal.lean",
    "formal/qualification/aeneas/generated/gateway/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/gateway/translation.json",
    "formal/qualification/aeneas/generated/connections/Types.lean",
    "formal/qualification/aeneas/generated/connections/Funs.lean",
    "formal/qualification/aeneas/generated/connections/translation.json",
];

const EXPECTED_CASE_MODULES: &[&str] = &[
    "qualification.aeneas.cases.ScopeCodec",
    "qualification.aeneas.cases.StatusSelection",
    "qualification.aeneas.cases.TemporalWitness",
    "qualification.aeneas.cases.SuiteAdapters",
    "qualification.aeneas.cases.P256",
    "qualification.aeneas.cases.Sha256",
    "qualification.aeneas.cases.Signature",
    "qualification.aeneas.cases.Composition",
    "qualification.aeneas.cases.Stores",
    "qualification.aeneas.cases.Codec",
    "qualification.aeneas.cases.Model",
    "qualification.aeneas.cases.Algebra",
    "qualification.aeneas.cases.Authority",
    "qualification.aeneas.cases.BoundedPolicy",
    "qualification.aeneas.cases.Lifecycle",
    "qualification.aeneas.cases.Gateway",
    "qualification.aeneas.cases.Connections",
];

const REQUIRED_AUTHORED_SOURCE_INPUTS: &[&str] = &[
    "product/runtime/auths-gateway-kernel/src/counter_preimages.rs",
    "product/runtime/auths-gateway/src/bounds.rs",
    "product/runtime/auths-gateway-kernel/src/frontier.rs",
    "product/runtime/auths-gateway-kernel/src/identity.rs",
    "product/runtime/auths-gateway/src/recipe.rs",
    "product/runtime/auths-gateway/src/recipe/lower.rs",
    "product/runtime/auths-gateway/src/recipe/strict_json.rs",
    "product/runtime/auths-gateway/src/recipe/tests.rs",
    "product/runtime/auths-gateway/src/store.rs",
    "core/crates/auths-model/src/principal_scheme_tests.rs",
    "core/crates/auths-model/src/scope_constructor_tests.rs",
    "core/crates/auths-codec/src/scope_decode_tests.rs",
    "formal/qualification/aeneas/cases/ScopeCodec.lean",
    "core/crates/auths-registries/Cargo.toml",
    "core/crates/auths-registries/src/lib.rs",
    "core/crates/auths-registries/src/status_selection_tests.rs",
    "formal/qualification/aeneas/cases/StatusSelection.lean",
    "core/crates/auths-verifier/Cargo.toml",
    "core/crates/auths-verifier/src/lib.rs",
    "core/crates/auths-verifier/src/temporal_tests.rs",
    "formal/qualification/aeneas/cases/TemporalWitness.lean",
    "core/fixtures/crypto/import_p256_wycheproof.py",
    "core/fixtures/crypto/p256-sha256-v1.tsv",
    "core/fixtures/crypto/upstream/ecdsa_secp256r1_sha256_p1363_test.json",
    "core/fixtures/crypto/README.md",
    "core/crates/auths-signature/tests/p256_corpus.rs",
    "bindings/independent/typescript/p256-corpus.test.ts",
    "bindings/independent/go/auths/p256_corpus_test.go",
    "bindings/independent/typescript/semantic-verifier.ts",
    "xtask/src/checks.rs",
    "core/crates/auths-signature/Cargo.toml",
    "core/crates/auths-signature/src/lib.rs",
    "core/crates/auths-ports/Cargo.toml",
    "core/crates/auths-ports/src/lib.rs",
    "formal/qualification/aeneas/cases/SuiteAdapters.lean",
    "formal/Auths/Crypto/P256Primitives.lean",
    "formal/qualification/aeneas/cases/P256.lean",
    "core/crates/auths-signature-core/Cargo.toml",
    "core/crates/auths-signature-core/src/lib.rs",
    "formal/qualification/aeneas/cases/Signature.lean",
    "core/crates/auths-composition/Cargo.toml",
    "core/crates/auths-composition/src/lib.rs",
    "core/crates/auths-composition/src/summary.rs",
    "formal/Auths/Support/Discriminant.lean",
    "formal/Auths/Support/PositiveVec.lean",
    "formal/Auths/Support/UnitCallback.lean",
    "formal/qualification/aeneas/cases/Composition.lean",
    "core/crates/auths-codec/src/decode.rs",
    "core/crates/auths-codec/src/encode.rs",
    "core/crates/auths-codec/src/error.rs",
    "core/crates/auths-codec/src/hash.rs",
    "formal/qualification/aeneas/cases/Stores.lean",
    "formal/qualification/aeneas/cases/Codec.lean",
    ".cargo/config.toml",
    "Cargo.toml",
    "Cargo.lock",
    "formal/algebra-contract-v1.toml",
    "formal/qualification/aeneas/qualification.toml",
    "formal/translation-toolchain.lock",
    "formal/qualification/aeneas/cases/Model.lean",
    "formal/qualification/aeneas/cases/Algebra.lean",
    "formal/qualification/aeneas/cases/Authority.lean",
    "formal/qualification/aeneas/cases/BoundedPolicy.lean",
    "formal/qualification/aeneas/cases/Lifecycle.lean",
    "formal/qualification/aeneas/cases/Gateway.lean",
    "formal/qualification/aeneas/cases/Connections.lean",
];

const EXPECTED_TRANSLATIONS: &[(&str, &str)] = &[
    (
        "auths_codec",
        "formal/qualification/aeneas/generated/scope_codec/translation.json",
    ),
    (
        "auths_registries",
        "formal/qualification/aeneas/generated/status_selection/translation.json",
    ),
    (
        "auths_verifier",
        "formal/qualification/aeneas/generated/temporal_witness/translation.json",
    ),
    (
        "auths_signature",
        "formal/qualification/aeneas/generated/suite_adapter/translation.json",
    ),
    (
        "auths_signature_core",
        "formal/qualification/aeneas/generated/p256/translation.json",
    ),
    (
        "auths_codec",
        "formal/qualification/aeneas/generated/sha256/translation.json",
    ),
    (
        "auths_signature_core",
        "formal/qualification/aeneas/generated/signature/translation.json",
    ),
    (
        "auths_composition",
        "formal/qualification/aeneas/generated/composition/translation.json",
    ),
    (
        "auths_stores",
        "formal/qualification/aeneas/generated/stores/translation.json",
    ),
    (
        "auths_codec",
        "formal/qualification/aeneas/generated/codec/translation.json",
    ),
    (
        "auths_model",
        "formal/qualification/aeneas/generated/model/translation.json",
    ),
    (
        "auths_algebra_kernel",
        "formal/qualification/aeneas/generated/algebra/translation.json",
    ),
    (
        "auths_lifecycle",
        "formal/qualification/aeneas/generated/lifecycle/translation.json",
    ),
    (
        "auths_authority",
        "formal/qualification/aeneas/generated/authority/translation.json",
    ),
    (
        "auths_bounded_policy",
        "formal/qualification/aeneas/generated/bounded_policy/translation.json",
    ),
    (
        "auths_gateway_kernel",
        "formal/qualification/aeneas/generated/gateway/translation.json",
    ),
    (
        "auths_connections",
        "formal/qualification/aeneas/generated/connections/translation.json",
    ),
];

const EXPECTED_TEMPLATE_AXIOMS: &[&str] = &[
    "formal/qualification/aeneas/generated/scope_codec/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/scope_codec/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/status_selection/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/temporal_witness/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/suite_adapter/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/suite_adapter/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/p256/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/p256/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/sha256/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/sha256/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/signature/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/signature/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/composition/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/composition/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/codec/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/codec/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/model/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/authority/TypesExternal_Template.lean",
    "formal/qualification/aeneas/generated/authority/FunsExternal_Template.lean",
    "formal/qualification/aeneas/generated/gateway/FunsExternal_Template.lean",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Qualification {
    schema: String,
    decision: String,
    adr: String,
    source_closure: String,
    production_features: Vec<String>,
    semantic_cfg: Vec<String>,
    extraction_cfg: Vec<String>,
    shipping_target: String,
    extraction_target: String,
    translation_warnings: Vec<String>,
    required_compiled_external_axioms: usize,
    source_files: Vec<String>,
    generated_files: Vec<String>,
    case_modules: Vec<String>,
    codegen_normalizations: Vec<String>,
    tools: QualificationTools,
    external_models: Vec<ExternalModel>,
    warning_inventory: Vec<WarningInventory>,
    translations: Vec<TranslationExpectation>,
    template_axioms: Vec<TemplateAxiomInventory>,
    qualified_delegations: Vec<QualifiedDelegation>,
}

#[derive(Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct QualifiedDelegation {
    importer_translation_json: String,
    rust_symbol: String,
    owner_translation_json: String,
    owner_lean_declaration: String,
    bridge_artifact: String,
    bridge_lean_declaration: String,
    delegation_theorem: String,
}

fn expected_qualified_delegations() -> Vec<QualifiedDelegation> {
    vec![
        QualifiedDelegation {
            importer_translation_json:
                "formal/qualification/aeneas/generated/suite_adapter/translation.json".to_owned(),
            rust_symbol: "auths_signature_core::verify_ed25519".to_owned(),
            owner_translation_json:
                "formal/qualification/aeneas/generated/signature/translation.json".to_owned(),
            owner_lean_declaration: "auths_signature_core.verify_ed25519".to_owned(),
            bridge_artifact:
                "formal/qualification/aeneas/generated/suite_adapter/FunsExternal.lean".to_owned(),
            bridge_lean_declaration: "AuthsSuiteAdapters.auths_signature_core.verify_ed25519"
                .to_owned(),
            delegation_theorem: "AuthsSuiteAdapters.ed25519_delegates".to_owned(),
        },
        QualifiedDelegation {
            importer_translation_json:
                "formal/qualification/aeneas/generated/suite_adapter/translation.json".to_owned(),
            rust_symbol: "auths_signature_core::verify_p256_sha256".to_owned(),
            owner_translation_json: "formal/qualification/aeneas/generated/p256/translation.json"
                .to_owned(),
            owner_lean_declaration: "AuthsNativeP256.verify_p256_sha256".to_owned(),
            bridge_artifact:
                "formal/qualification/aeneas/generated/suite_adapter/FunsExternal.lean".to_owned(),
            bridge_lean_declaration: "AuthsSuiteAdapters.auths_signature_core.verify_p256_sha256"
                .to_owned(),
            delegation_theorem: "AuthsSuiteAdapters.p256_delegates".to_owned(),
        },
    ]
}

fn delegation_endpoints_match(
    imported: &TranslationFunction,
    owned: &TranslationFunction,
    link: &QualifiedDelegation,
) -> bool {
    imported.rust_name == link.rust_symbol
        && !imported.is_local
        && imported.is_opaque
        && imported.lean_name == link.bridge_lean_declaration
        && owned.rust_name == link.rust_symbol
        && owned.is_local
        && !owned.is_opaque
        && owned.lean_name == link.owner_lean_declaration
}

fn delegation_statement_matches(declaration: &Value, link: &QualifiedDelegation) -> bool {
    let Some(constants) = declaration["statement_constants"].as_array() else {
        return false;
    };
    declaration["name"] == link.delegation_theorem
        && declaration["kind"] == "theorem"
        && constants
            .iter()
            .any(|name| name.as_str() == Some(link.owner_lean_declaration.as_str()))
        && constants
            .iter()
            .any(|name| name.as_str() == Some(link.bridge_lean_declaration.as_str()))
        && declaration["axioms"].as_array().is_some_and(|axioms| {
            axioms.iter().all(|axiom| {
                matches!(
                    axiom.as_str(),
                    Some("propext" | "Classical.choice" | "Quot.sound")
                )
            })
        })
}

fn validate_qualified_delegations(
    root: &Path,
    qualification: &Qualification,
) -> Result<(), String> {
    let audit: Value = serde_json::from_slice(
        &fs::read(root.join("formal/lean-assurance-audit-v1.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let declarations = audit["declarations"]
        .as_array()
        .ok_or("compiled delegation audit has no declarations")?;
    for link in &qualification.qualified_delegations {
        let load = |path: &str| -> Result<TranslationReport, String> {
            if !qualification
                .translations
                .iter()
                .any(|translation| translation.translation_json == path)
            {
                return Err(format!(
                    "qualified delegation references an unqualified unit {path}"
                ));
            }
            serde_json::from_slice(&fs::read(root.join(path)).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())
        };
        let importer = load(&link.importer_translation_json)?;
        let imported = importer
            .functions
            .iter()
            .find(|function| function.rust_name == link.rust_symbol)
            .ok_or("qualified delegation import is absent")?;
        if imported.is_local
            || !imported.is_opaque
            || imported.lean_name != link.bridge_lean_declaration
        {
            return Err("qualified delegation import identity or boundary drifted".to_owned());
        }
        let owner = load(&link.owner_translation_json)?;
        let owned = owner
            .functions
            .iter()
            .find(|function| function.rust_name == link.rust_symbol)
            .ok_or("qualified delegation owner is absent")?;
        if !delegation_endpoints_match(imported, owned, link) {
            return Err(
                "qualified delegation must resolve to the actual transparent local owner"
                    .to_owned(),
            );
        }
        if !REVIEWED_BRIDGE_ARTIFACTS.contains(&link.bridge_artifact.as_str()) {
            return Err(
                "qualified delegation bridge is not a reviewed compiled artifact".to_owned(),
            );
        }
        let declaration = declarations
            .iter()
            .find(|row| row["name"] == link.delegation_theorem)
            .ok_or("qualified delegation theorem is absent from the compiled audit")?;
        if !delegation_statement_matches(declaration, link) {
            return Err("qualified delegation lacks both exact kernel constant references or exceeds the axiom policy".to_owned());
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationTools {
    shipping_rust: String,
    extraction_rust: String,
    charon: String,
    charon_commit: String,
    aeneas_commit: String,
    lean_toolchain: String,
    kani: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalModel {
    id: String,
    kind: String,
    artifact: String,
    rust_symbols: Vec<String>,
    authority_semantics: bool,
    reviewed: bool,
    axiom: bool,
    scope: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WarningInventory {
    id: String,
    artifact: String,
    upstream_lines: Vec<usize>,
    classification: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TranslationExpectation {
    crate_name: String,
    translation_json: String,
    local_functions: usize,
    external_functions: usize,
    opaque_local_functions: usize,
    required_symbols: Vec<String>,
    allowed_external_symbols: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplateAxiomInventory {
    artifact: String,
    count: usize,
    compiled: bool,
}

#[derive(Deserialize)]
struct TranslationReport {
    aeneas_version: String,
    charon_version: String,
    #[serde(rename = "crate")]
    crate_name: String,
    functions: Vec<TranslationFunction>,
}

#[derive(Deserialize)]
struct TranslationFunction {
    rust_name: String,
    lean_name: String,
    is_local: bool,
    is_opaque: bool,
}

pub(crate) fn validate(root: &Path, attenuation_dimensions: &[String]) -> Result<String, String> {
    let qualification = load_qualification(root)?;
    validate_manifest(root, &qualification)?;
    ensure_clean_extraction_environment(root, &qualification)?;
    let closure_digest = synchronize_source_closure(root, &qualification, false)?;
    synchronize_reviewed_bridges(root, attenuation_dimensions, false)?;
    validate_generated_inventory(root, &qualification)?;
    validate_translation_reports(root, &qualification)?;
    validate_workflow_gates(root)?;
    build_qualification_cases(root, &qualification)?;
    validate_warning_inventory(root, &qualification)?;
    write_evidence(root, &qualification, &closure_digest, false)?;
    println!(
        "Aeneas qualification:       PASS ({} reviewed external links; 0 compiled external axioms)",
        qualification.external_models.len()
    );
    Ok(closure_digest)
}

/// Rewrites only the lightweight source closure. The closure hashes sources,
/// not translations, so it is reproducible without Aeneas; refreshing it
/// before a push leaves the hosted formal updater nothing to commit.
pub(crate) fn refresh_source_closure(root: &Path) -> Result<String, String> {
    let qualification = load_qualification(root)?;
    validate_manifest(root, &qualification)?;
    synchronize_source_closure(root, &qualification, true)
}

pub(crate) fn validate_source_closure(root: &Path) -> Result<String, String> {
    let qualification = load_qualification(root)?;
    validate_manifest(root, &qualification)?;
    synchronize_source_closure(root, &qualification, false)
}

/// Validate that workflow translation evidence applies byte-for-byte to the
/// committed generated artifacts in this checkout. The caller authenticates
/// the successful producer job and its phase result; this function rejects
/// stale source closure or generated bytes without a Lake dependency checkout.
pub(crate) fn validate_reusable_translation(
    root: &Path,
    evidence_path: &Path,
) -> Result<String, String> {
    let qualification = load_qualification(root)?;
    validate_manifest(root, &qualification)?;
    ensure_clean_extraction_environment(root, &qualification)?;
    let closure_digest = synchronize_source_closure(root, &qualification, false)?;
    validate_generated_inventory(root, &qualification)?;
    validate_translation_reports(root, &qualification)?;
    // The pinned Lake checkout is audited by authoritative Lean. Translation
    // reuse runs before Lean setup and must not require that package checkout.

    let evidence: Value = serde_json::from_slice(
        &fs::read(evidence_path)
            .map_err(|error| format!("could not read {}: {error}", evidence_path.display()))?,
    )
    .map_err(|error| {
        format!(
            "invalid reusable translation evidence {}: {error}",
            evidence_path.display()
        )
    })?;
    let generated_digest = generated_artifact_digest(root)?;
    if evidence["schema"].as_str() != Some("auths-proof-aeneas-qualification-evidence/v1")
        || evidence["decision"].as_str() != Some(qualification.decision.as_str())
        || evidence["source_closure_sha256"].as_str() != Some(closure_digest.as_str())
        || evidence["generated_artifacts_sha256"].as_str() != Some(generated_digest.as_str())
        || evidence["clean_reproduction"].as_str() != Some("byte-identical")
        || evidence["compiled_external_axioms"].as_u64() != Some(0)
    {
        return Err(
            "protected-base translation evidence does not apply to the current committed artifacts"
                .to_owned(),
        );
    }
    write_evidence(root, &qualification, &closure_digest, true)?;
    Ok(closure_digest)
}

/// Qualifies the Aeneas translation, translation-first.
///
/// `build_and_audit` compiles Lean and runs the compiled assurance audit. It is
/// invoked AFTER regenerated outputs and reviewed bridges are synchronized,
/// never before reproduction: qualification regenerates the Lean a build would
/// compile, so building first deadlocks the moment a translation references a
/// symbol its upstream crate has not exported yet.
///
/// A failing build still fails qualification. Intentionally regenerated files
/// are left in the tree for the proofs to be repaired, but no evidence is
/// written and no success is printed.
pub(crate) fn qualify(
    root: &Path,
    attenuation_dimensions: &[String],
    update: bool,
    build_and_audit: &dyn Fn() -> Result<(), String>,
) -> Result<(), String> {
    let (qualification, closure_digest) =
        reproduce_translation(root, attenuation_dimensions, update)?;

    // Everything below reads the generated Lean just synchronized by the
    // reproducer, so the compiled gate runs here and not a step earlier.
    build_and_audit()?;

    validate_generated_inventory(root, &qualification)?;
    validate_translation_reports(root, &qualification)?;
    validate_workflow_gates(root)?;
    build_qualification_cases(root, &qualification)?;
    validate_warning_inventory(root, &qualification)?;
    run_rust_qualification_cases(root)?;
    write_evidence(root, &qualification, &closure_digest, true)?;

    println!("Existing claim audit:              PASS");
    println!("Hosted/release formal gate:        CONFIGURED");
    println!("Production source closure:         {closure_digest}");
    println!("Shipping/extraction cfg parity:    PASS");
    println!("Lean/Aeneas compatibility:         PASS");
    println!(
        "External models and axioms:        {} reviewed, 0 unreviewed",
        qualification.external_models.len()
    );
    println!(
        "Qualification cases:               {}/{} PASS",
        qualification.case_modules.len() + 1,
        qualification.case_modules.len() + 1
    );
    println!("Clean reproduction:                byte-identical");
    println!(
        "Decision:                           {}",
        qualification.decision
    );
    println!("ADR:                                {}", qualification.adr);
    Ok(())
}

/// Reproduce the generated Lean twice without compiling authored proofs.
///
/// Hosted CI uses this phase to separate translator determinism from Lean
/// compilation. The complete developer command still calls [`qualify`], which
/// composes this exact reproducer with the authoritative build and audits. The
/// pinned Lake package warning inventory is audited by authoritative Lean,
/// where that dependency checkout exists, rather than coupling translation to
/// Lean setup.
pub(crate) fn reproduce_only(
    root: &Path,
    attenuation_dimensions: &[String],
    update: bool,
) -> Result<String, String> {
    let (qualification, closure_digest) =
        reproduce_translation(root, attenuation_dimensions, update)?;
    validate_generated_inventory(root, &qualification)?;
    validate_translation_reports(root, &qualification)?;
    write_evidence(root, &qualification, &closure_digest, true)?;
    println!("Production source closure:         {closure_digest}");
    println!("Clean reproduction:                byte-identical");
    Ok(closure_digest)
}

fn reproduce_translation(
    root: &Path,
    attenuation_dimensions: &[String],
    update: bool,
) -> Result<(Qualification, String), String> {
    let qualification = load_qualification(root)?;
    validate_manifest(root, &qualification)?;
    if !update {
        synchronize_source_closure(root, &qualification, false)?;
    }
    ensure_clean_extraction_environment(root, &qualification)?;
    let charon = required_tool("AUTHS_CHARON_BIN", "charon")?;
    let aeneas = required_tool("AUTHS_AENEAS_BIN", "aeneas")?;
    validate_translation_tool_versions(&charon, &aeneas, &qualification)?;

    let work = root.join("target/formal/qualification-reproduction");
    recreate_directory(&work)?;
    let first = work.join("run-1");
    let second = work.join("run-2");
    let stable_llbc = work.join("stable-llbc");
    reproduce(root, &charon, &aeneas, &stable_llbc, &first)?;
    reproduce(root, &charon, &aeneas, &stable_llbc, &second)?;
    canonicalize_aeneas_versions(&first, &qualification.tools.aeneas_commit)?;
    canonicalize_aeneas_versions(&second, &qualification.tools.aeneas_commit)?;

    let first_files = collect_files(&first)?;
    let second_files = collect_files(&second)?;
    if first_files != second_files {
        return Err(format!(
            "Aeneas clean reproduction is not byte-identical; compare {} and {}",
            first.display(),
            second.display()
        ));
    }

    synchronize_aeneas_output(root, &first, update)?;
    synchronize_reviewed_bridges(root, attenuation_dimensions, update)?;
    let closure_digest = synchronize_source_closure(root, &qualification, update)?;
    Ok((qualification, closure_digest))
}

fn load_qualification(root: &Path) -> Result<Qualification, String> {
    let path = root.join(QUALIFICATION_PATH);
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    toml::from_str(&source)
        .map_err(|error| format!("invalid Aeneas qualification {}: {error}", path.display()))
}

fn validate_manifest(root: &Path, qualification: &Qualification) -> Result<(), String> {
    if qualification.schema != QUALIFICATION_SCHEMA {
        return Err(format!(
            "unsupported Aeneas qualification schema {}",
            qualification.schema
        ));
    }
    if qualification.decision != "GO-AENEAS-WITH-PRODUCTION-RESHAPE" {
        return Err(format!(
            "qualification decision must be GO-AENEAS-WITH-PRODUCTION-RESHAPE, found {}",
            qualification.decision
        ));
    }
    if qualification.adr != "docs/adr/0011-rich-authority-rust-lean-link.md"
        || qualification.source_closure != "formal/qualification/aeneas/source-closure.json"
    {
        return Err("Aeneas qualification ADR or source-closure path drifted".to_owned());
    }
    if qualification.production_features != ["default"]
        || !qualification.semantic_cfg.is_empty()
        || !qualification.extraction_cfg.is_empty()
        || qualification.shipping_target != "workspace-host"
        || qualification.extraction_target != "workspace-host"
        || !qualification.translation_warnings.is_empty()
        || qualification.required_compiled_external_axioms != 0
    {
        return Err(
            "Aeneas qualification changed features, cfg, targets, warnings, or axiom policy"
                .to_owned(),
        );
    }
    if qualification.qualified_delegations != expected_qualified_delegations() {
        return Err("qualified source delegation inventory drifted".to_owned());
    }
    if qualification.case_modules.len() != 17
        || qualification.translations.len() != 17
        || qualification.external_models.len() != 25
        || qualification.warning_inventory.len() != 4
        || qualification.template_axioms.len() != 20
    {
        return Err("Aeneas qualification inventory cardinality drifted".to_owned());
    }

    if qualification.codegen_normalizations
        != [
            "scope-codec-qualified-discriminants-v1",
            "scope-codec-recursive-loops-v1",
            "composition-qualified-discriminants-v1",
            "composition-positive-vector-v1",
            "composition-recursive-loops-v1",
            "signature-recursive-loops-v1",
            "composition-unit-callback-return-v1",
            "signature-qualified-discriminants-v1",
            "signature-explicit-primitive-context-v1",
            "sha256-monomorphic-foreign-names-v1",
            "sha256-explicit-primitive-context-v1",
            "p256-monomorphic-export-names-v1",
            "p256-qualified-discriminants-v1",
            "p256-explicit-primitive-context-v1",
            "suite-qualified-discriminants-v1",
            "suite-explicit-linked-primitive-context-v1",
            "temporal-qualified-discriminants-v1",
            "temporal-recursive-loops-v1",
            "status-selection-qualified-discriminants-v1",
            "status-selection-recursive-loops-v1",
        ]
    {
        return Err("Aeneas code generation normalization inventory drifted".to_owned());
    }

    for path in [
        qualification.adr.as_str(),
        qualification.source_closure.as_str(),
    ] {
        if !root.join(path).is_file() && path != qualification.source_closure {
            return Err(format!("Aeneas qualification artifact is absent: {path}"));
        }
    }
    require_unique_nonempty("source files", &qualification.source_files)?;
    for required in REQUIRED_AUTHORED_SOURCE_INPUTS {
        if !qualification
            .source_files
            .iter()
            .any(|path| path == required)
        {
            return Err(format!(
                "Aeneas authored source inventory omits required qualification input {required}"
            ));
        }
    }
    validate_generated_artifact_inventory(&qualification.generated_files)?;
    validate_exact_inventory(
        "case modules",
        &qualification.case_modules,
        EXPECTED_CASE_MODULES,
    )?;
    let actual_translations = qualification
        .translations
        .iter()
        .map(|translation| {
            (
                translation.crate_name.as_str(),
                translation.translation_json.as_str(),
            )
        })
        .collect::<Vec<_>>();
    if actual_translations != EXPECTED_TRANSLATIONS {
        return Err("Aeneas translation crate/report inventory drifted".to_owned());
    }
    let actual_templates = qualification
        .template_axioms
        .iter()
        .map(|inventory| inventory.artifact.as_str())
        .collect::<Vec<_>>();
    if actual_templates != EXPECTED_TEMPLATE_AXIOMS {
        return Err("Aeneas template axiom inventory drifted".to_owned());
    }
    let boundary_digest = qualification_boundary_contract_sha256(qualification);
    if boundary_digest != QUALIFICATION_BOUNDARY_CONTRACT_SHA256 {
        return Err(format!(
            "Aeneas reviewed translation/external boundary contract drifted: expected {QUALIFICATION_BOUNDARY_CONTRACT_SHA256}, found {boundary_digest}"
        ));
    }

    let mut external_ids = BTreeSet::new();
    for model in &qualification.external_models {
        if !external_ids.insert(model.id.as_str())
            || model.id.trim().is_empty()
            || model.kind.trim().is_empty()
            || model.scope.trim().is_empty()
            || model.rust_symbols.is_empty()
            || !model.reviewed
            || model.axiom
        {
            return Err(format!(
                "external model {} is duplicate, incomplete, unreviewed, or axiomatic",
                model.id
            ));
        }
        if !root.join(&model.artifact).is_file() {
            return Err(format!(
                "reviewed external model artifact is absent: {}",
                model.artifact
            ));
        }
        require_unique_nonempty(
            &format!("external model {} Rust symbols", model.id),
            &model.rust_symbols,
        )?;
        let _ = model.authority_semantics;
    }

    for warning in &qualification.warning_inventory {
        if warning.id.trim().is_empty()
            || warning.artifact.trim().is_empty()
            || warning.upstream_lines.is_empty()
            || warning.classification.trim().is_empty()
        {
            return Err("Aeneas runtime warning inventory is incomplete".to_owned());
        }
    }
    validate_locked_tools(root, &qualification.tools)
}

fn qualification_boundary_contract_sha256(qualification: &Qualification) -> String {
    let external_models = qualification
        .external_models
        .iter()
        .map(|model| {
            json!({
                "id": model.id,
                "kind": model.kind,
                "artifact": model.artifact,
                "rust_symbols": model.rust_symbols,
                "authority_semantics": model.authority_semantics,
                "reviewed": model.reviewed,
                "axiom": model.axiom,
                "scope": model.scope,
            })
        })
        .collect::<Vec<_>>();
    let translations = qualification
        .translations
        .iter()
        .map(|translation| {
            json!({
                "crate_name": translation.crate_name,
                "translation_json": translation.translation_json,
                "local_functions": translation.local_functions,
                "external_functions": translation.external_functions,
                "opaque_local_functions": translation.opaque_local_functions,
                "required_symbols": translation.required_symbols,
                "allowed_external_symbols": translation.allowed_external_symbols,
            })
        })
        .collect::<Vec<_>>();
    let warnings = qualification
        .warning_inventory
        .iter()
        .map(|warning| {
            json!({
                "id": warning.id,
                "artifact": warning.artifact,
                "upstream_lines": warning.upstream_lines,
                "classification": warning.classification,
            })
        })
        .collect::<Vec<_>>();
    let templates = qualification
        .template_axioms
        .iter()
        .map(|template| {
            json!({
                "artifact": template.artifact,
                "count": template.count,
                "compiled": template.compiled,
            })
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&json!({
        "external_models": external_models,
        "translations": translations,
        "warning_inventory": warnings,
        "template_axioms": templates,
        "codegen_normalizations": qualification.codegen_normalizations,
        "qualified_delegations": qualification.qualified_delegations,
    }))
    .expect("in-memory qualification contract serializes");
    hex::encode(Sha256::digest(bytes))
}

fn validate_warning_inventory(root: &Path, qualification: &Qualification) -> Result<(), String> {
    let package = root.join("formal/.lake/packages/aeneas");
    let actual_commit = run_output("git", &["rev-parse", "HEAD"], &package, &[])?;
    if actual_commit.trim() != qualification.tools.aeneas_commit {
        return Err(format!(
            "pinned Aeneas package commit drifted: expected {}, found {}",
            qualification.tools.aeneas_commit,
            actual_commit.trim()
        ));
    }
    let status = run_output("git", &["status", "--porcelain=v1"], &package, &[])?;
    if !status.trim().is_empty() {
        return Err(format!(
            "pinned Aeneas package has local modifications; qualification refuses a dirty dependency:\n{}",
            status.trim_end()
        ));
    }

    let mut present = BTreeMap::new();
    collect_lean_sorries(root, &package.join("backends/lean"), &mut present)?;
    let mut inventoried = BTreeMap::new();
    for warning in &qualification.warning_inventory {
        if inventoried
            .insert(warning.artifact.clone(), warning.upstream_lines.clone())
            .is_some()
        {
            return Err(format!(
                "Aeneas warning inventory repeats artifact {}",
                warning.artifact
            ));
        }
    }
    if present != inventoried {
        return Err(format!(
            "pinned Aeneas package `sorry` inventory drifted: inventoried={inventoried:?}, present={present:?}"
        ));
    }
    Ok(())
}

/// Finds code-level `sorry`/`admit` identifiers while ignoring comments and
/// literal contents. Syntax quotations remain code and are inventoried because
/// a tactic capable of manufacturing `sorry` is part of the package surface.
fn lean_sorry_lines(source: &str) -> Vec<usize> {
    let bytes = source.as_bytes();
    let mut lines = BTreeSet::new();
    let mut index = 0;
    let mut line = 1;
    let mut block_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        if block_depth > 0 {
            if byte == b'\n' {
                line += 1;
            }
            if byte == b'/' && next == Some(b'-') {
                block_depth += 1;
                index += 2;
                continue;
            }
            if byte == b'-' && next == Some(b'/') {
                block_depth -= 1;
                index += 2;
                continue;
            }
            index += 1;
            continue;
        }
        if in_string {
            if byte == b'\n' {
                line += 1;
            }
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'-' && next == Some(b'-') {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if byte == b'/' && next == Some(b'-') {
            block_depth = 1;
            index += 2;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if byte == b'\'' {
            // Lean also uses `'(` for syntax quotation and apostrophes in
            // identifiers. Only skip a lexically complete character literal;
            // treating every apostrophe as one can hide arbitrary later code.
            index = lean_char_literal_end(source, index).unwrap_or(index + 1);
            continue;
        }
        if byte == b'\n' {
            line += 1;
            index += 1;
            continue;
        }
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || bytes[index] == b'_'
                    || bytes[index] == b'\'')
            {
                index += 1;
            }
            let token = &source[start..index];
            if token == "sorry" || token == "admit" {
                lines.insert(line);
            }
            continue;
        }
        index += 1;
    }
    lines.into_iter().collect()
}

fn lean_char_literal_end(source: &str, quote: usize) -> Option<usize> {
    let tail = source.get(quote + 1..)?;
    let mut chars = tail.char_indices();
    let (_, first) = chars.next()?;
    if first == '\n' || first == '\r' || first == '\'' {
        return None;
    }
    if first != '\\' {
        let closing = quote + 1 + first.len_utf8();
        return (source.as_bytes().get(closing) == Some(&b'\'')).then_some(closing + 1);
    }

    let escaped = tail.as_bytes().get(1).copied()?;
    let closing = match escaped {
        b'x' => quote + 5,
        b'u' if tail.as_bytes().get(2) == Some(&b'{') => {
            let brace = tail.find('}')?;
            quote + 1 + brace + 1
        }
        _ => quote + 3,
    };
    (source.as_bytes().get(closing) == Some(&b'\'')).then_some(closing + 1)
}

fn collect_lean_sorries(
    workspace_root: &Path,
    directory: &Path,
    output: &mut BTreeMap<String, Vec<usize>>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("could not read {}: {error}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("could not enumerate {}: {error}", directory.display()))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_lean_sorries(workspace_root, &path, output)?;
        } else if path.extension().and_then(|value| value.to_str()) == Some("lean") {
            let source = fs::read_to_string(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?;
            let lines = lean_sorry_lines(&source);
            if !lines.is_empty() {
                let relative = path
                    .strip_prefix(workspace_root)
                    .map_err(|error| format!("Aeneas source escaped workspace: {error}"))?
                    .to_string_lossy()
                    .replace('\\', "/");
                output.insert(relative, lines);
            }
        }
    }
    Ok(())
}

fn validate_locked_tools(root: &Path, tools: &QualificationTools) -> Result<(), String> {
    let path = root.join("formal/translation-toolchain.lock");
    let lock: toml::Value = toml::from_str(
        &fs::read_to_string(&path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("invalid formal toolchain lock: {error}"))?;
    let field = |table: &str, name: &str| -> Result<&str, String> {
        lock.get(table)
            .and_then(toml::Value::as_table)
            .and_then(|value| value.get(name))
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("formal toolchain lock omits {table}.{name}"))
    };
    for (actual, table, name) in [
        (tools.shipping_rust.as_str(), "rust", "shipping"),
        (tools.extraction_rust.as_str(), "charon", "toolchain"),
        (tools.charon.as_str(), "charon", "version"),
        (tools.charon_commit.as_str(), "charon", "commit"),
        (tools.aeneas_commit.as_str(), "aeneas", "commit"),
        (tools.lean_toolchain.as_str(), "lean", "toolchain"),
        (tools.kani.as_str(), "kani", "version"),
    ] {
        if field(table, name)? != actual {
            return Err(format!(
                "qualification tool {table}.{name} differs from translation-toolchain.lock"
            ));
        }
    }
    Ok(())
}

fn require_unique_nonempty(label: &str, values: &[String]) -> Result<(), String> {
    let unique: BTreeSet<_> = values.iter().map(String::as_str).collect();
    if unique.len() != values.len() || values.iter().any(|value| value.trim().is_empty()) {
        return Err(format!("{label} must be unique and non-empty"));
    }
    Ok(())
}

fn synchronize_source_closure(
    root: &Path,
    qualification: &Qualification,
    update: bool,
) -> Result<String, String> {
    let translation_roots: Vec<_> = qualification
        .translations
        .iter()
        .map(|translation| translation.crate_name.clone())
        .collect();
    let expected = auths_ci_plan::formal_source_closure_json(
        root,
        &qualification.source_files,
        &translation_roots,
    )?;
    let digest = expected["digest"]
        .as_str()
        .ok_or("formal source closure omits digest")?
        .to_owned();
    let path = root.join(&qualification.source_closure);
    if update {
        write_pretty_json(&path, &expected)?;
    } else {
        let actual: Value = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?,
        )
        .map_err(|error| format!("invalid source closure {}: {error}", path.display()))?;
        if actual != expected {
            return Err(format!(
                "production translation source closure drifted; run `cargo xtask formal qualify aeneas --update` (computed digest {digest})"
            ));
        }
    }
    Ok(digest)
}

fn synchronize_reviewed_bridges(
    root: &Path,
    attenuation_dimensions: &[String],
    update: bool,
) -> Result<(), String> {
    for (relative, expected) in [
        (
            "formal/qualification/aeneas/generated/standard/CheckedResult.lean",
            render_checked_result_interfaces(),
        ),
        (
            "formal/qualification/aeneas/generated/gateway/FunsExternal.lean",
            render_gateway_functions_external(),
        ),
        (
            "formal/qualification/aeneas/generated/scope_codec/TypesExternal.lean",
            render_scope_codec_types_external(),
        ),
        (
            "formal/qualification/aeneas/generated/scope_codec/FunsExternal.lean",
            render_scope_codec_functions_external(),
        ),
        (
            "formal/qualification/aeneas/generated/status_selection/FunsExternal.lean",
            render_status_selection_functions_external(),
        ),
        (
            "formal/qualification/aeneas/generated/temporal_witness/FunsExternal.lean",
            render_temporal_functions_external(),
        ),
        (
            "formal/qualification/aeneas/generated/suite_adapter/TypesExternal.lean",
            render_suite_adapter_types_external(),
        ),
        (
            "formal/qualification/aeneas/generated/suite_adapter/FunsExternal.lean",
            render_suite_adapter_functions_external(),
        ),
        (
            "formal/qualification/aeneas/generated/p256/TypesExternal.lean",
            render_p256_types_external(),
        ),
        (
            "formal/qualification/aeneas/generated/p256/FunsExternal.lean",
            render_p256_functions_external(),
        ),
        (
            "formal/qualification/aeneas/generated/sha256/TypesExternal.lean",
            render_sha256_types_external(),
        ),
        (
            "formal/qualification/aeneas/generated/sha256/FunsExternal.lean",
            render_sha256_functions_external(),
        ),
        (
            "formal/qualification/aeneas/generated/signature/TypesExternal.lean",
            render_signature_types_external(),
        ),
        (
            "formal/qualification/aeneas/generated/signature/FunsExternal.lean",
            render_signature_functions_external(),
        ),
        (
            "formal/qualification/aeneas/generated/composition/TypesExternal.lean",
            render_composition_types_external(),
        ),
        (
            "formal/qualification/aeneas/generated/composition/FunsExternal.lean",
            render_composition_external(),
        ),
        (
            "formal/qualification/aeneas/generated/codec/TypesExternal.lean",
            render_codec_types_external(),
        ),
        (
            "formal/qualification/aeneas/generated/codec/FunsExternal.lean",
            render_codec_functions_external(),
        ),
        (
            "formal/qualification/aeneas/generated/model/FunsExternal.lean",
            render_model_external(),
        ),
        (
            "formal/qualification/aeneas/generated/authority/TypesExternal.lean",
            render_authority_types_external(),
        ),
        (
            "formal/qualification/aeneas/generated/authority/FunsExternal.lean",
            render_authority_functions_external(attenuation_dimensions),
        ),
    ] {
        let path = root.join(relative);
        if update {
            fs::write(&path, expected)
                .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        } else {
            let actual = fs::read_to_string(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?;
            if actual != expected {
                return Err(format!(
                    "reviewed Aeneas bridge drifted: {relative}; run `cargo xtask formal qualify aeneas --update`"
                ));
            }
        }
    }
    Ok(())
}

fn render_checked_result_interfaces() -> String {
    r##"-- Exact checked conversion and Result projection shared by translation units.
import Aeneas
open Aeneas Aeneas.Std Result

def U64.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from (value : Std.Usize) :=
  core.num.tryFromUScalar .U64 value

def core.result.Result.unwrap_or {T E : Type} (value : core.result.Result T E) (fallback : T) :
    Result T := ok (match value with | .Ok value => value | .Err _ => fallback)
"##
    .to_owned()
}

fn render_gateway_functions_external() -> String {
    r##"-- Reuse the reviewed checked usize-to-u64 conversion and Result.unwrap_or models.
import qualification.aeneas.generated.gateway.Types
import qualification.aeneas.generated.standard.CheckedResult
"##
    .to_owned()
}

fn render_status_selection_functions_external() -> String {
    r#"import qualification.aeneas.generated.status_selection.Types
import qualification.aeneas.generated.model.FunsExternal
open Aeneas Aeneas.Std Result
namespace AuthsStatusSelection

@[trait_default]
def core.cmp.PartialOrd.lt.default {Self Rhs : Type}
    (implementation : Aeneas.Std.core.cmp.PartialOrd Self Rhs)
    (left : Self) (right : Rhs) : Result Bool :=
  Aeneas.Std.core.cmp.PartialOrd.lt.default implementation.partial_cmp left right
@[trait_default]
def core.cmp.PartialOrd.gt.default {Self Rhs : Type}
    (implementation : Aeneas.Std.core.cmp.PartialOrd Self Rhs)
    (left : Self) (right : Rhs) : Result Bool :=
  Aeneas.Std.core.cmp.PartialOrd.gt.default implementation.partial_cmp left right
@[trait_default]
def core.cmp.Ord.max.default {Self : Type}
    (implementation : Aeneas.Std.core.cmp.Ord Self) (left right : Self) : Result Self :=
  Aeneas.Std.core.cmp.Ord.max.default implementation.partialOrdInst.lt left right
abbrev alloc.string.String.Insts.CoreCmpPartialEqString.eq :=
  _root_.alloc.string.String.Insts.CoreCmpPartialEqString.eq
abbrev alloc.string.String.Insts.CoreCmpOrd.cmp :=
  _root_.alloc.string.String.Insts.CoreCmpOrd.cmp

/-- Reviewed standard-library boundary: pinned Rust binary_search_by's exact
    size/base transition and final comparison, including unsorted inputs.
    Fuel is initial length + 1; exhausted/invalid indexing refuses explicitly.
    This is not an Auths algorithm or an assumption of whitelist membership. -/
def binarySearchLoop {T : Type} (order : Aeneas.Std.core.cmp.Ord T)
    (values : List T) (target : T) : Nat → Nat → Nat → Result (core.result.Result Nat Nat)
  | 0, _, _ => fail .panic
  | fuel + 1, base, size => do
    if size > 1 then
      let half := size / 2
      let mid := base + half
      match values[mid]? with
      | none => fail .panic
      | some value =>
        let comparison ← order.cmp value target
        binarySearchLoop order values target fuel
          (if comparison = .gt then base else mid) (size - half)
    else
      match values[base]? with
      | none => fail .panic
      | some value =>
        let comparison ← order.cmp value target
        if comparison = .eq then ok (.Ok base)
        else ok (.Err (base + if comparison = .lt then 1 else 0))

def core.slice.Slice.binary_search {T : Type} (order : Aeneas.Std.core.cmp.Ord T)
    (values : Slice T) (target : T) : Result (core.result.Result Std.Usize Std.Usize) := do
  if values.val.isEmpty then ok (.Err 0#usize)
  else
    let result ← binarySearchLoop order values.val target (values.val.length + 1) 0 values.val.length
    match result with
    | .Ok index =>
      let result ← UScalar.tryMk .Usize index
      ok (.Ok result)
    | .Err index =>
      let result ← UScalar.tryMk .Usize index
      ok (.Err result)
theorem lt_default_delegates {Self Rhs : Type}
    (implementation : Aeneas.Std.core.cmp.PartialOrd Self Rhs) (left : Self) (right : Rhs) :
    core.cmp.PartialOrd.lt.default implementation left right =
      Aeneas.Std.core.cmp.PartialOrd.lt.default implementation.partial_cmp left right := rfl

theorem gt_default_delegates {Self Rhs : Type}
    (implementation : Aeneas.Std.core.cmp.PartialOrd Self Rhs) (left : Self) (right : Rhs) :
    core.cmp.PartialOrd.gt.default implementation left right =
      Aeneas.Std.core.cmp.PartialOrd.gt.default implementation.partial_cmp left right := rfl

theorem max_default_delegates {Self : Type}
    (implementation : Aeneas.Std.core.cmp.Ord Self) (left right : Self) :
    core.cmp.Ord.max.default implementation left right =
      Aeneas.Std.core.cmp.Ord.max.default implementation.partialOrdInst.lt left right := rfl
end AuthsStatusSelection
"#.to_owned()
}

fn render_temporal_functions_external() -> String {
    r#"import qualification.aeneas.generated.temporal_witness.Types
import qualification.aeneas.generated.codec.FunsExternal
open Aeneas Aeneas.Std Result
namespace AuthsTemporalWitness
@[trait_default]
def core.cmp.PartialOrd.lt.default {Self Rhs : Type}
    (implementation : Aeneas.Std.core.cmp.PartialOrd Self Rhs)
    (left : Self) (right : Rhs) : Result Bool :=
  Aeneas.Std.core.cmp.PartialOrd.lt.default implementation.partial_cmp left right
abbrev core.option.Option.ok_or := @_root_.core.option.Option.ok_or
theorem lt_default_delegates {Self Rhs : Type}
    (implementation : Aeneas.Std.core.cmp.PartialOrd Self Rhs) (left : Self) (right : Rhs) :
    core.cmp.PartialOrd.lt.default implementation left right =
      Aeneas.Std.core.cmp.PartialOrd.lt.default implementation.partial_cmp left right := rfl
end AuthsTemporalWitness
"#
    .to_owned()
}

fn render_suite_adapter_types_external() -> String {
    r#"-- REVIEWED STRING CARRIER FOR THE UNINSPECTED PRIVATE SUITE-ID FIELD.
-- The verified methods never read it; constructor/registry validity is separate.
import Aeneas
namespace AuthsSuiteAdapters
abbrev auths_model.SignatureSuiteId := Aeneas.Std.Str
end AuthsSuiteAdapters
"#
    .to_owned()
}

fn render_suite_adapter_functions_external() -> String {
    r#"-- EXACT DELEGATION TO QUALIFIED OWNING RUST UNITS, WITH EXHAUSTIVE ERROR REBOXING.
-- No Auths algorithm or crypto operation is assumed as an opaque function.
import qualification.aeneas.generated.suite_adapter.Types
import qualification.aeneas.generated.signature.Funs
import qualification.aeneas.generated.p256.Funs
import qualification.aeneas.generated.codec.FunsExternal
open Aeneas Aeneas.Std Result
namespace AuthsSuiteAdapters

abbrev core.result.Result.map_err := @_root_.core.result.Result.map_err

def fromEdError : _root_.auths_signature_core.Ed25519Error → auths_signature_core.Ed25519Error
  | .InvalidKey => .InvalidKey
  | .InvalidSignatureEncoding => .InvalidSignatureEncoding
  | .VerificationFailed => .VerificationFailed

def toEdError : auths_signature_core.Ed25519Error → _root_.auths_signature_core.Ed25519Error
  | .InvalidKey => .InvalidKey
  | .InvalidSignatureEncoding => .InvalidSignatureEncoding
  | .VerificationFailed => .VerificationFailed

def fromP256Error : AuthsNativeP256.P256Error → auths_signature_core.P256Error
  | .InvalidKey => .InvalidKey
  | .InvalidSignatureEncoding => .InvalidSignatureEncoding
  | .VerificationFailed => .VerificationFailed

def toP256Error : auths_signature_core.P256Error → AuthsNativeP256.P256Error
  | .InvalidKey => .InvalidKey
  | .InvalidSignatureEncoding => .InvalidSignatureEncoding
  | .VerificationFailed => .VerificationFailed

def edResult : Aeneas.Std.core.result.Result Unit _root_.auths_signature_core.Ed25519Error →
    Aeneas.Std.core.result.Result Unit auths_signature_core.Ed25519Error
  | .Ok value => .Ok value | .Err reason => .Err (fromEdError reason)

def p256Result : AuthsNativeP256.core.qualified_p256_type_decls_0 →
    Aeneas.Std.core.result.Result Unit auths_signature_core.P256Error
  | .Ok value => .Ok value | .Err reason => .Err (fromP256Error reason)

def auths_signature_core.verify_ed25519 [P : Auths.Crypto.Ed25519Primitives]
    (key message signature : Slice Std.U8) :
    Result (Aeneas.Std.core.result.Result Unit auths_signature_core.Ed25519Error) := do
  let result ← _root_.auths_signature_core.verify_ed25519 (primitives := P) key message signature
  ok (edResult result)

def auths_signature_core.verify_p256_sha256 [P : Auths.Crypto.P256Primitives]
    (key message signature : Slice Std.U8) :
    Result (Aeneas.Std.core.result.Result Unit auths_signature_core.P256Error) := do
  let result ← AuthsNativeP256.verify_p256_sha256 (primitive := P) key message signature
  ok (p256Result result)

-- Both conversions are isomorphisms on the complete error domains.
theorem ed_error_to_from (reason : _root_.auths_signature_core.Ed25519Error) :
    toEdError (fromEdError reason) = reason := by cases reason <;> rfl

theorem ed_error_from_to (reason : auths_signature_core.Ed25519Error) :
    fromEdError (toEdError reason) = reason := by cases reason <;> rfl

theorem p256_error_to_from (reason : AuthsNativeP256.P256Error) :
    toP256Error (fromP256Error reason) = reason := by cases reason <;> rfl

theorem p256_error_from_to (reason : auths_signature_core.P256Error) :
    fromP256Error (toP256Error reason) = reason := by cases reason <;> rfl

theorem ed25519_delegates [P : Auths.Crypto.Ed25519Primitives]
    (key message signature : Slice Std.U8) :
    auths_signature_core.verify_ed25519 (P := P) key message signature =
      (do let result ← _root_.auths_signature_core.verify_ed25519 (primitives := P) key message signature
          ok (edResult result)) := rfl

theorem p256_delegates [P : Auths.Crypto.P256Primitives]
    (key message signature : Slice Std.U8) :
    auths_signature_core.verify_p256_sha256 (P := P) key message signature =
      (do let result ← AuthsNativeP256.verify_p256_sha256 (primitive := P) key message signature
          ok (p256Result result)) := rfl

end AuthsSuiteAdapters
"#.to_owned()
}

fn render_p256_types_external() -> String {
    r#"-- REVIEWED EXPLICIT FOREIGN TYPES. NO GLOBAL INSTANCE OR AXIOM.
import Auths.Crypto.P256Primitives
namespace AuthsNativeP256
abbrev ecdsa.qualified_p256_type_decls_4 [P : Auths.Crypto.P256Primitives] := P.Key
abbrev ecdsa.qualified_p256_type_decls_11 [P : Auths.Crypto.P256Primitives] := P.Signature
abbrev signature.error.Error [P : Auths.Crypto.P256Primitives] := P.Error
end AuthsNativeP256
"#
    .to_owned()
}

fn render_p256_functions_external() -> String {
    r#"-- REVIEWED TRANSPARENT STANDARD MATCHES AND EXPLICIT FOREIGN PROJECTIONS.
import qualification.aeneas.generated.p256.Types
open Aeneas Aeneas.Std Result
namespace AuthsNativeP256
variable [P : Auths.Crypto.P256Primitives]

def SharedSliceU8.Insts.CoreConvertTryIntoArrayU864.try_into (bytes : Slice Std.U8) :
    Result core.qualified_p256_type_decls_9 :=
  if sized : bytes.val.length = 64 then
    ok (.Ok ⟨bytes.val, by scalar_tac⟩)
  else ok (.Err ())

def core.qualified_p256_fun_decls_27 (value : core.qualified_p256_type_decls_16) : Result Bool :=
  ok (match value with | .Ok _ => true | .Err _ => false)

def core.qualified_p256_fun_decls_30 (value : core.qualified_p256_type_decls_17) :
    Result core.qualified_p256_type_decls_13 :=
  ok (match value with | .Ok key => .Some key | .Err _ => .None)

def core.qualified_p256_fun_decls_24 (value : core.qualified_p256_type_decls_14) :
    Result core.qualified_p256_type_decls_12 :=
  ok (match value with | .Ok signature => .Some signature | .Err _ => .None)


def core.qualified_p256_type_decls_3.Insts.CoreOpsTry_traitTry.branch
    (value : core.qualified_p256_type_decls_3) : Result core.qualified_p256_type_decls_6 :=
  ok (match value with | .Ok key => .Continue key | .Err reason => .Break (.Err reason))

def core.qualified_p256_type_decls_0.Insts.CoreOpsTry_traitFromResidualqualified_p256_type_decls_7.from_residual
    (residual : core.qualified_p256_type_decls_7) : Result core.qualified_p256_type_decls_0 :=
  match residual with
  | .Ok impossible => nomatch impossible
  | .Err reason => ok (.Err reason)

def core.qualified_p256_fun_decls_20 (bytes : Slice Std.U8) : Result Std.Usize := ok (Slice.len bytes)

def ecdsa.qualified_p256_fun_decls_23 (bytes : Slice Std.U8) :
    Result core.qualified_p256_type_decls_14 := do
  let value ← P.parse bytes
  ok (match value with | .Ok signature => .Ok signature | .Err reason => .Err reason)

def ecdsa.qualified_p256_fun_decls_29 (bytes : Slice Std.U8) :
    Result core.qualified_p256_type_decls_17 := do
  let value ← P.decode bytes
  ok (match value with | .Ok key => .Ok key | .Err reason => .Err reason)

def ecdsa.qualified_p256_type_decls_4.Insts.SignatureVerifierVerifierqualified_p256_type_decls_11.verify
    (key : ecdsa.qualified_p256_type_decls_4) (message : Slice Std.U8)
    (signature : ecdsa.qualified_p256_type_decls_11) : Result core.qualified_p256_type_decls_16 := do
  let value ← P.verify key message signature
  ok (match value with | .Ok valueUnit => .Ok valueUnit | .Err reason => .Err reason)

end AuthsNativeP256
"#.to_owned()
}

fn render_sha256_types_external() -> String {
    r##"-- Explicit foreign output type, without a global instance or axiom.
import Auths.Crypto.Sha256Primitives
abbrev generic_array.qualified_sha256_type_decls_1 [P : Auths.Crypto.Sha256Primitives] := P.Output
"##
    .to_owned()
}

fn render_sha256_functions_external() -> String {
    r##"-- Exact selected foreign calls are explicit implementation projections.
import qualification.aeneas.generated.sha256.Types
open Aeneas Aeneas.Std Result

def generic_array.qualified_sha256_type_decls_1.Insts.CoreConvertIntoArrayU832.into
    [P : Auths.Crypto.Sha256Primitives] (value : generic_array.qualified_sha256_type_decls_1) :
    Result (Array Std.U8 32#usize) := P.intoBytes value

def digest.qualified_sha256_type_decls_11.Insts.DigestDigestDigest.digest
    [P : Auths.Crypto.Sha256Primitives] (value : Slice Std.U8) :
    Result generic_array.qualified_sha256_type_decls_1 := P.digest value
"##
    .to_owned()
}

fn render_signature_types_external() -> String {
    r##"-- REVIEWED FOREIGN TYPE INTERFACE. NO GLOBAL INSTANCE OR AXIOM.
import Auths.Crypto.NativePrimitives

abbrev ed25519.Signature [P : Auths.Crypto.Ed25519Primitives] := P.Signature
abbrev ed25519_dalek.verifying.VerifyingKey [P : Auths.Crypto.Ed25519Primitives] := P.Key
abbrev signature.error.Error [P : Auths.Crypto.Ed25519Primitives] := P.Error
"##
    .to_owned()
}

fn render_signature_functions_external() -> String {
    r##"-- REVIEWED TRANSPARENT STANDARD RESULT MODEL AND EXPLICIT FOREIGN INTERFACE.
import qualification.aeneas.generated.signature.Types
import qualification.aeneas.generated.codec.FunsExternal

open Aeneas Aeneas.Std Result

def core.result.Result.ok {T E : Type} (value : core.result.Result T E) : Result (Option T) :=
  Aeneas.Std.Result.ok (match value with | .Ok value => some value | .Err _ => none)

def ed25519.Signature.from_bytes [P : Auths.Crypto.Ed25519Primitives]
    (bytes : Array Std.U8 64#usize) : Result ed25519.Signature := P.signatureFromBytes bytes

def ed25519_dalek.verifying.VerifyingKey.from_bytes [P : Auths.Crypto.Ed25519Primitives]
    (bytes : Array Std.U8 32#usize) :
    Result (core.result.Result ed25519_dalek.verifying.VerifyingKey signature.error.Error) :=
  P.decode bytes

def ed25519_dalek.verifying.VerifyingKey.verify_strict [P : Auths.Crypto.Ed25519Primitives]
    (key : ed25519_dalek.verifying.VerifyingKey) (message : Slice Std.U8)
    (encodedSignature : ed25519.Signature) : Result (core.result.Result Unit signature.error.Error) :=
  P.verifyStrict key message encodedSignature
"##.to_owned()
}

fn render_composition_types_external() -> String {
    r##"-- REVIEWED: bounded ordered-set and consuming-iterator carriers.
-- Only Global allocation and the translated fixed-width ProofRef order are used.
import Aeneas
import Auths.Support.Discriminant
import Auths.Support.PositiveVec
open Aeneas Aeneas.Std
namespace alloc.collections.btree.set
structure BTreeSet (T A : Type) where
  values : List T
  bound : values.length ≤ Usize.max
structure IntoIter (T A : Type) where
  values : List T
  bound : values.length ≤ Usize.max
end alloc.collections.btree.set
"##
    .to_owned()
}

fn render_composition_external() -> String {
    r##"-- REVIEWED: exact standard-container links and the pinned Rust Ord::max rule.
-- Ordered-set models are scoped to Global + copied ProofRef values and their
-- proved lawful order. They model set behavior, not Rust allocation or tree cost.
import qualification.aeneas.generated.composition.Types
import qualification.aeneas.generated.codec.FunsExternal
open Aeneas Aeneas.Std Result

namespace auths_composition.alloc.vec

def Vec.with_capacity (T : Type) (capacity : Std.Usize) : Vec T :=
  Vec.ofBase (Aeneas.Std.alloc.vec.Vec.with_capacity T capacity)

def Vec.len {T : Type} (value : Vec T) : Std.Usize :=
  Aeneas.Std.alloc.vec.Vec.len value.toBase

def Vec.push {T : Type} (value : Vec T) (element : T) : Result (Vec T) := do
  let updated ← Aeneas.Std.alloc.vec.Vec.push value.toBase element
  ok (Vec.ofBase updated)

def Vec.is_empty {T : Type} (_A : Type) (value : Vec T) : Result Bool :=
  ok value.elements.toList.isEmpty

end auths_composition.alloc.vec

@[trait_default] def auths_composition.core.cmp.Ord.max.default {T : Type}
    (order : Aeneas.Std.core.cmp.Ord T) (left right : T) : Result T := do
  let greater ← order.partialOrdInst.lt right left
  if greater then ok left else ok right

def core.option.Option.Insts.CoreDefaultDefault.default (T : Type) : Result (Option T) := ok none

namespace alloc.collections.btree.set

def insertValues {T : Type} (order : core.cmp.Ord T) (value : T) :
    List T → Result (Bool × List T)
  | [] => ok (true, [value])
  | head :: tail => do
      let comparison ← order.cmp value head
      match comparison with
      | .lt => ok (true, value :: head :: tail)
      | .eq => ok (false, head :: tail)
      | .gt =>
          let (added, remaining) ← insertValues order value tail
          ok (added, head :: remaining)

def BTreeSetTGlobal.new (T : Type) : Result (BTreeSet T Global) :=
  ok ⟨[], by simp⟩

def BTreeSet.insert {T A : Type} (_allocator : core.clone.Clone A) (order : core.cmp.Ord T)
    (state : BTreeSet T A) (value : T) : Result (Bool × BTreeSet T A) := do
  let (added, values) ← insertValues order value state.values
  (if bound : values.length ≤ Usize.max then
    ok (added, ⟨values, bound⟩)
  else
    fail .maximumSizeExceeded)

def BTreeSet.len {T A : Type} (_allocator : core.clone.Clone A)
    (state : BTreeSet T A) : Result Std.Usize :=
  ok (Usize.ofNatCore state.values.length (by have bound := state.bound; scalar_tac))

def BTreeSet.Insts.CoreIterTraitsCollectIntoIteratorTIntoIter.into_iter
    {T A : Type} (_allocator : core.clone.Clone A) (state : BTreeSet T A) :
    Result (IntoIter T A) := ok ⟨state.values, state.bound⟩

def IntoIter.Insts.CoreIterTraitsIteratorIterator.next
    {T A : Type} (_allocator : core.clone.Clone A) (state : IntoIter T A) :
    Result (Option T × IntoIter T A) :=
  match same : state.values with
  | [] => ok (none, state)
  | head :: tail => ok (some head, ⟨tail, by have bound := state.bound; rw [same] at bound; simp only [List.length_cons] at bound; omega⟩)

end alloc.collections.btree.set
"##.to_owned()
}

fn render_model_external() -> String {
    r##"-- REVIEWED TRANSPARENT MODEL FOR AN AENEAS STANDARD-LIBRARY EXTERNAL.
--
-- Rust string equality and ordering use Lean's exact String instances,
-- `String::as_bytes` uses Aeneas' exact UTF-8 `Str` conversion, and fixed
-- arrays are compared lexicographically through the translated element
-- `Ord` instance. This file contains no authority semantics and no axiom.
import Aeneas
import qualification.aeneas.generated.model.Types

open Aeneas Aeneas.Std Result ControlFlow Error

set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false
set_option maxHeartbeats 1000000
set_option maxRecDepth 2048

private def compareLists {T : Type} (cmpOrdInst : core.cmp.Ord T) :
List T → List T → Result Ordering
| [], [] => ok .eq
| [], _ :: _ => ok .lt
| _ :: _, [] => ok .gt
| left :: leftTail, right :: rightTail => do
let ordering ← cmpOrdInst.cmp left right
match ordering with
| Ordering.eq => compareLists cmpOrdInst leftTail rightTail
| ordering => ok ordering

-- Public views expose the existing model for downstream proofs. Every
-- equation below reduces to the original private implementation.
def Array.Insts.CoreCmpOrd.compareValues {T : Type} (order : core.cmp.Ord T)
    (left right : List T) : Result Ordering := compareLists order left right

theorem Array.Insts.CoreCmpOrd.compareValues_nil_nil {T : Type} (order : core.cmp.Ord T) :
    compareValues order [] [] = ok .eq := rfl

theorem Array.Insts.CoreCmpOrd.compareValues_nil_cons {T : Type} (order : core.cmp.Ord T)
    (head : T) (tail : List T) : compareValues order [] (head :: tail) = ok .lt := rfl

theorem Array.Insts.CoreCmpOrd.compareValues_cons_nil {T : Type} (order : core.cmp.Ord T)
    (head : T) (tail : List T) : compareValues order (head :: tail) [] = ok .gt := rfl

theorem Array.Insts.CoreCmpOrd.compareValues_cons_cons {T : Type} (order : core.cmp.Ord T)
    (left right : T) (leftTail rightTail : List T) :
    compareValues order (left :: leftTail) (right :: rightTail) =
      (do let ordering ← order.cmp left right
          match ordering with
          | .eq => compareValues order leftTail rightTail
          | ordering => ok ordering) := rfl

@[rust_fun "core::array::{core::cmp::Ord<[@T; @N]>}::cmp"]
def Array.Insts.CoreCmpOrd.cmp
{T : Type} {N : Std.Usize} (cmpOrdInst : core.cmp.Ord T)
(left right : Array T N) : Result Ordering :=
compareLists cmpOrdInst left.val right.val

@[rust_fun
"alloc::string::{core::cmp::PartialEq<alloc::string::String, alloc::string::String>}::eq"]
def alloc.string.String.Insts.CoreCmpPartialEqString.eq
(left right : String) : Result Bool :=
ok (left == right)

@[rust_fun "alloc::string::{core::cmp::Ord<alloc::string::String>}::cmp"]
def alloc.string.String.Insts.CoreCmpOrd.cmp
(left right : String) : Result Ordering :=
ok (compare left right)

@[rust_fun "alloc::string::{alloc::string::String}::as_bytes"]
def alloc.string.String.as_bytes (value : String) : Result (Slice Std.U8) :=
if h : value.toByteArray.size ≤ U32.max then
ok (Aeneas.Std.toStr value h)
else
fail .panic

@[rust_fun "core::str::{str}::len"]
def core.str.Str.len (value : Str) : Result Std.Usize :=
ok (Slice.len value)

@[rust_fun "core::str::{str}::is_empty"]
def core.str.Str.is_empty (value : Str) : Result Bool :=
ok value.val.isEmpty

@[rust_fun "core::str::{str}::as_bytes"]
def core.str.Str.as_bytes (value : Str) : Result (Slice Std.U8) :=
ok value
"##
    .to_owned()
}

fn render_authority_types_external() -> String {
    "-- REVIEWED TYPE LINK FOR AENEAS-GENERATED PRODUCTION AUTHORITY CODE.\n\
--\n\
-- All external authority carriers are the mechanically translated\n\
-- `auths-model` carriers. No opaque type or axiom is introduced here.\n\
import qualification.aeneas.generated.model.Types\n"
        .to_owned()
}

/// Renders the authority external bridge: transparent adapters plus imports.
///
/// The authority translation emits its OWN copies of the algebra carriers,
/// `auths_authority.auths_algebra_kernel.RootLinkage` and
/// `...generated.AttenuationChecks`, distinct from the `_root_` types the
/// translated `auths_algebra_kernel` owns. Lean rejects passing one where the
/// other is expected.
///
/// This file reboxes, field by field, and delegates. It restates NO Boolean
/// semantics: `root_preserved` and `attenuation_checks_accept` remain owned by
/// the mechanically translated algebra crate, and the adapters below only move
/// fields and call them. No axiom, cast, assumed equality, or reimplementation.
///
/// The eleven attenuation assignments are generated from `dimensions`, i.e.
/// from `formal/algebra-contract-v1.toml`, so adding a twelfth dimension
/// regenerates this file rather than silently dropping the field.
///
/// Emitted as explicit lines: Lean structure literals are layout-sensitive and
/// Rust string continuations strip leading whitespace.
fn render_authority_functions_external(dimensions: &[String]) -> String {
    const LINKAGE_FIELDS: [&str; 4] = [
        "parent_root",
        "parent_subject",
        "parent_delegated",
        "grant_issuer",
    ];
    let mut lines: Vec<String> = vec![
        "-- REVIEWED TRANSPARENT ADAPTERS FOR AENEAS-GENERATED PRODUCTION AUTHORITY CODE.".into(),
        "--".into(),
        "-- The authority translation emits authority-local copies of the algebra".into(),
        "-- carriers. These adapters rebox them field by field into the carriers the".into(),
        "-- translated `auths_algebra_kernel` owns and delegate to its functions.".into(),
        "--".into(),
        "-- NO axiom, cast, assumed equality, or restated semantics. Every Boolean".into(),
        "-- decision below is computed by the mechanically translated owning crate.".into(),
        format!(
            "-- Attenuation dimensions bound by formal/algebra-contract-v1.toml: {}.",
            dimensions.len()
        ),
        "import Aeneas".into(),
        "import qualification.aeneas.generated.authority.Types".into(),
        "import qualification.aeneas.generated.model.Funs".into(),
        "import qualification.aeneas.generated.algebra.Funs".into(),
        String::new(),
        "open Aeneas Aeneas.Std Result ControlFlow Error".into(),
        String::new(),
        "set_option linter.dupNamespace false".into(),
        "set_option linter.hashCommand false".into(),
        "set_option linter.unusedVariables false".into(),
        "set_option maxHeartbeats 1000000".into(),
        "set_option maxRecDepth 2048".into(),
        String::new(),
        "namespace auths_authority".into(),
        String::new(),
        "/-- Reboxes the authority-local root linkage into the owning carrier. -/".into(),
        "def auths_algebra_kernel.toRootLinkage {Identity : Type}".into(),
        "    (value : auths_algebra_kernel.RootLinkage Identity) :".into(),
        "    _root_.auths_algebra_kernel.RootLinkage Identity :=".into(),
    ];
    for (index, field) in LINKAGE_FIELDS.iter().enumerate() {
        let open = if index == 0 { "  { " } else { "    " };
        let close = if index + 1 == LINKAGE_FIELDS.len() {
            " }"
        } else {
            ","
        };
        lines.push(format!("{open}{field} := value.{field}{close}"));
    }
    lines.extend([
        String::new(),
        "/-- Delegates root preservation to the translated algebra kernel. -/".into(),
        "@[rust_fun \"auths_algebra_kernel::root_preserved\"]".into(),
        "def auths_algebra_kernel.root_preserved {Identity : Type}".into(),
        "    (inst : core.cmp.PartialEq Identity Identity)".into(),
        "    (linkage : auths_algebra_kernel.RootLinkage Identity) : Result Bool :=".into(),
        "  _root_.auths_algebra_kernel.root_preserved inst".into(),
        "    (auths_algebra_kernel.toRootLinkage linkage)".into(),
        String::new(),
        "/-- Reboxes the authority-local attenuation checks into the owning carrier. -/".into(),
        "def auths_algebra_kernel.generated.toAttenuationChecks".into(),
        "    (value : auths_algebra_kernel.generated.AttenuationChecks) :".into(),
        "    _root_.auths_algebra_kernel.generated.AttenuationChecks :=".into(),
    ]);
    for (index, dimension) in dimensions.iter().enumerate() {
        let open = if index == 0 { "  { " } else { "    " };
        let close = if index + 1 == dimensions.len() {
            " }"
        } else {
            ","
        };
        lines.push(format!("{open}{dimension} := value.{dimension}{close}"));
    }
    lines.extend([
        String::new(),
        "/-- Delegates the attenuation conjunction to the translated algebra kernel. -/".into(),
        "@[rust_fun \"auths_algebra_kernel::generated::attenuation_checks_accept\"]".into(),
        "def auths_algebra_kernel.generated.attenuation_checks_accept".into(),
        "    (checks : auths_algebra_kernel.generated.AttenuationChecks) : Result Bool :=".into(),
        "  _root_.auths_algebra_kernel.generated.attenuation_checks_accept".into(),
        "    (auths_algebra_kernel.generated.toAttenuationChecks checks)".into(),
        String::new(),
        "-- EXACT BRIDGE PROOFS. Each reboxed field is definitionally its source".into(),
        "-- field, and each adapter is definitionally the owning-crate function".into(),
        "-- applied to the conversion. A rebox that dropped or crossed a field".into(),
        "-- would not close by rfl.".into(),
        String::new(),
    ]);
    for field in LINKAGE_FIELDS {
        lines.extend([
            format!("theorem auths_algebra_kernel.toRootLinkage_{field} {{Identity : Type}}"),
            "    (value : auths_algebra_kernel.RootLinkage Identity) :".into(),
            format!(
                "    (auths_algebra_kernel.toRootLinkage value).{field} = value.{field} := rfl"
            ),
            String::new(),
        ]);
    }
    for dimension in dimensions {
        lines.extend([
            format!("theorem auths_algebra_kernel.generated.toAttenuationChecks_{dimension}"),
            "    (value : auths_algebra_kernel.generated.AttenuationChecks) :".into(),
            format!(
                "    (auths_algebra_kernel.generated.toAttenuationChecks value).{dimension} = value.{dimension} := rfl"
            ),
            String::new(),
        ]);
    }
    lines.extend([
        "theorem auths_algebra_kernel.root_preserved_delegates {Identity : Type}".into(),
        "    (inst : core.cmp.PartialEq Identity Identity)".into(),
        "    (linkage : auths_algebra_kernel.RootLinkage Identity) :".into(),
        "    auths_algebra_kernel.root_preserved inst linkage =".into(),
        "      _root_.auths_algebra_kernel.root_preserved inst".into(),
        "        (auths_algebra_kernel.toRootLinkage linkage) := rfl".into(),
        String::new(),
        "theorem auths_algebra_kernel.generated.attenuation_checks_accept_delegates".into(),
        "    (checks : auths_algebra_kernel.generated.AttenuationChecks) :".into(),
        "    auths_algebra_kernel.generated.attenuation_checks_accept checks =".into(),
        "      _root_.auths_algebra_kernel.generated.attenuation_checks_accept".into(),
        "        (auths_algebra_kernel.generated.toAttenuationChecks checks) := rfl".into(),
        String::new(),
        "end auths_authority".into(),
    ]);
    let mut output = lines.join("\n");
    output.push('\n');
    output
}

// The pinned generator starts declarations on a new line but may place a long
// name after the keyword on the following line. Both layouts must be counted
// and forbidden identically in compiled bridges.
fn is_lean_axiom_declaration(line: &str) -> bool {
    line.trim_start()
        .strip_prefix("axiom")
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
}

fn validate_generated_inventory(root: &Path, qualification: &Qualification) -> Result<(), String> {
    for relative in &qualification.generated_files {
        let path = root.join(relative);
        if !path.is_file() {
            return Err(format!(
                "Aeneas generated artifact is absent: {}",
                path.display()
            ));
        }
        if path.extension().and_then(|value| value.to_str()) == Some("lean")
            && !relative.ends_with("_Template.lean")
        {
            let source = fs::read_to_string(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?;
            for forbidden in ["axiom", "sorry", "admit"] {
                if source.lines().any(|line| {
                    if forbidden == "axiom" {
                        is_lean_axiom_declaration(line)
                    } else {
                        line.trim_start().starts_with(forbidden)
                    }
                }) {
                    return Err(format!(
                        "compiled qualification artifact contains forbidden `{forbidden}`: {relative}"
                    ));
                }
            }
        }
    }
    for inventory in &qualification.template_axioms {
        if inventory.compiled {
            return Err(format!(
                "Aeneas external template must not be compiled: {}",
                inventory.artifact
            ));
        }
        let source = fs::read_to_string(root.join(&inventory.artifact))
            .map_err(|error| format!("could not read {}: {error}", inventory.artifact))?;
        let count = source
            .lines()
            .filter(|line| is_lean_axiom_declaration(line))
            .count();
        if count != inventory.count {
            return Err(format!(
                "Aeneas template axiom inventory drifted for {}: expected {}, found {count}",
                inventory.artifact, inventory.count
            ));
        }
    }
    Ok(())
}

fn validate_translation_reports(root: &Path, qualification: &Qualification) -> Result<(), String> {
    let expected_aeneas = qualification.tools.aeneas_commit.as_str();
    for expected in &qualification.translations {
        let path = root.join(&expected.translation_json);
        let report: TranslationReport = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?,
        )
        .map_err(|error| {
            format!(
                "invalid Aeneas translation report {}: {error}",
                path.display()
            )
        })?;
        if report.crate_name != expected.crate_name
            || !aeneas_version_matches(&report.aeneas_version, expected_aeneas)
            || report.charon_version != qualification.tools.charon
        {
            return Err(format!(
                "Aeneas translation identity drifted for {}",
                expected.crate_name
            ));
        }
        if matches!(
            report.crate_name.as_str(),
            "auths_codec"
                | "auths_composition"
                | "auths_signature_core"
                | "auths_verifier"
                | "auths_registries"
        ) && report
            .functions
            .iter()
            .any(|function| function.rust_name.starts_with("auths_") && function.is_opaque)
        {
            return Err(
                "the codec/composition/signature/temporal/status closure must translate every Auths constructor and helper"
                    .to_owned(),
            );
        }
        if report.crate_name == "auths_signature"
            && report.functions.iter().any(|function| {
                function.rust_name.starts_with("auths_")
                    && function.is_opaque
                    && !qualification.qualified_delegations.iter().any(|link| {
                        link.importer_translation_json == expected.translation_json
                            && link.rust_symbol == function.rust_name
                    })
            })
        {
            return Err(
                "suite adapter contains an Auths import without an exact qualified owner"
                    .to_owned(),
            );
        }
        let local = report
            .functions
            .iter()
            .filter(|function| function.is_local)
            .count();
        let external = report.functions.len() - local;
        let opaque_local = report
            .functions
            .iter()
            .filter(|function| function.is_local && function.is_opaque)
            .count();
        if local != expected.local_functions
            || external != expected.external_functions
            || opaque_local != expected.opaque_local_functions
        {
            return Err(format!(
                "Aeneas function inventory drifted for {}: local={local}, external={external}, opaque-local={opaque_local}",
                expected.crate_name
            ));
        }
        let symbols: BTreeSet<_> = report
            .functions
            .iter()
            .map(|function| function.rust_name.as_str())
            .collect();
        for symbol in &expected.required_symbols {
            if !symbols.contains(symbol.as_str()) {
                return Err(format!(
                    "Aeneas translation for {} omits required production symbol {symbol}",
                    expected.crate_name
                ));
            }
        }
        let external_symbols: BTreeSet<_> = report
            .functions
            .iter()
            .filter(|function| !function.is_local)
            .map(|function| function.rust_name.as_str())
            .collect();
        let allowed: BTreeSet<_> = expected
            .allowed_external_symbols
            .iter()
            .map(String::as_str)
            .collect();
        if external_symbols != allowed {
            return Err(format!(
                "unreviewed Aeneas external functions for {}: expected={allowed:?}, actual={external_symbols:?}",
                expected.crate_name
            ));
        }
    }
    validate_qualified_delegations(root, qualification)?;
    Ok(())
}

/// Whether a reported Aeneas version names the pinned commit.
///
/// `expected_commit` is the FULL commit from the qualification manifest. The
/// check used to compare against exactly its first seven characters, so an
/// Aeneas built from precisely the pinned commit was rejected whenever git
/// abbreviated to eight -- which is what a local build of 3a8586fa does. That
/// gate tested the abbreviation's formatting rather than the commit's identity.
///
/// Any abbreviation is accepted provided it is a genuine prefix of the pinned
/// commit and at least seven characters, which is git's own lower bound for an
/// unambiguous short hash. A shorter or non-prefix string still fails, so the
/// gate keeps refusing a genuinely different Aeneas.
fn aeneas_version_matches(actual: &str, expected_commit: &str) -> bool {
    let candidate = actual.rsplit('-').next().unwrap_or(actual);
    candidate.len() >= 7
        && candidate.len() <= expected_commit.len()
        && expected_commit.starts_with(candidate)
}

fn validate_workflow_gates(root: &Path) -> Result<(), String> {
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .map_err(|error| format!("could not read hosted CI workflow: {error}"))?;
    validate_ci_workflow_gates(&ci)?;

    let release = fs::read_to_string(root.join(".github/workflows/release.yml"))
        .map_err(|error| format!("could not read release workflow: {error}"))?;
    let builder = fs::read_to_string(root.join(".github/workflows/release-builder.yml"))
        .map_err(|error| format!("could not read reusable release builder: {error}"))?;
    validate_release_workflow_gates(&release, &builder)
}

fn validate_ci_workflow_gates(ci: &str) -> Result<(), String> {
    validate_gate_source(
        "hosted CI",
        ci,
        &[
            "uses: ./.github/actions/setup-lean",
            "kani-verifier --version 0.67.0",
            "cargo xtask ci preflight",
            "cargo xtask ci authoritative",
            "cargo xtask ci formal-proof-fast",
            "cargo xtask ci formal-translation-reproduce",
            "cargo xtask ci formal-translation-reuse",
            "cargo xtask ci formal-lean-authoritative",
            "cargo xtask ci formal-kani",
            "cargo xtask ci formal-evidence",
            "cargo xtask ci compliance",
            "target/formal/",
        ],
    )?;
    let proof_job = workflow_job_source(ci, "formal-proof-fast")?;
    if !proof_job.contains("needs: [ci-plan, formal-update-gate]")
        || ["nix build", "kani-verifier", "formal-translation-reproduce"]
            .iter()
            .any(|forbidden| proof_job.contains(forbidden))
    {
        return Err(
            "hosted fast proof gate must precede and exclude Aeneas, Charon, and Kani setup"
                .to_owned(),
        );
    }
    let formal_job = workflow_job_source(ci, "formal-translation-run")?;
    if !formal_job.contains("compiler-cache: \"false\"")
        || formal_job.contains("formal-proof-fast")
        || !formal_job.contains("AUTHS_FORMAL_UPDATE_MODE")
        || !formal_job.contains("formal-update-artifact create")
        || !formal_job.contains("Preserve the bounded translation update")
        || !formal_job.contains("Stop qualification until generated translation is committed")
        || formal_job.contains("setup-lean")
        || formal_job.contains("kani-verifier")
    {
        return Err(
            "hosted translation must run beside fast Lean, disable compiler caching, package bounded generated drift, and exclude Lean/Kani"
                .to_owned(),
        );
    }
    validate_translation_evidence_selection(formal_job)?;
    for job_name in [
        "authoritative-run",
        "compliance-run",
        "dependencies-run",
        "secrets-run",
        "opentofu-live-run",
        "postgresql-live-run",
        "records-api-live-run",
    ] {
        let job = workflow_job_source(ci, job_name)?;
        if !job.contains("needs: [ci-plan, formal-update-gate, repository-preflight]")
            || !job.contains("needs.repository-preflight.result == 'success'")
        {
            return Err(format!(
                "hosted CI job `{job_name}` can start before the repository preflight succeeds"
            ));
        }
    }
    for job_name in ["formal-translation-run", "formal-kani-run"] {
        let job = workflow_job_source(ci, job_name)?;
        if !job.contains("repository-preflight")
            || !job.contains("needs.repository-preflight.result == 'success'")
            || job.contains("formal-proof-fast")
        {
            return Err(format!(
                "hosted formal job `{job_name}` must wait for repository preflight and run beside fast proof"
            ));
        }
    }
    // Translation and Kani run beside the fast Lean gate for wall-clock time;
    // a fast-proof failure still blocks qualification here, because evidence
    // requires authoritative Lean.
    let lean_job = workflow_job_source(ci, "formal-lean-authoritative-run")?;
    if !lean_job.contains("needs.formal-translation-run.result == 'success'")
        || !lean_job.contains("needs.formal-proof-fast.result == 'success'")
        || !lean_job.contains("cargo xtask ci formal-lean-authoritative")
    {
        return Err(
            "authoritative Lean can start without qualified translation and fast proof".to_owned(),
        );
    }
    // Formal evidence skips aggregation on this output. A `needs` read of an
    // output the job never declares is an empty string, so the guard would pass
    // on every run and a pending update would surface only as missing evidence.
    if workflow_job_output(lean_job, "update_required")
        != Some("${{ steps.formal-update.outputs.update_required || 'false' }}")
        || !lean_job.contains("\n      - id: formal-update\n")
    {
        return Err(
            "authoritative Lean does not declare the `update_required` output that formal evidence reads"
                .to_owned(),
        );
    }
    // As in translation, the job that packaged drift fails itself, so a pending
    // update never shows as a green authoritative Lean run.
    if !lean_job.contains(
        "- name: Stop qualification until the assurance update is committed\n        if: steps.formal-update.outputs.update_required == 'true'\n",
    ) {
        return Err(
            "authoritative Lean must fail while its bounded assurance update is uncommitted"
                .to_owned(),
        );
    }
    let evidence_job = workflow_job_source(ci, "formal-evidence-run")?;
    for required in [
        "needs.formal-translation-run.result == 'success'",
        "needs.formal-lean-authoritative-run.result == 'success'",
        "needs.formal-lean-authoritative-run.outputs.update_required != 'true'",
        "needs.formal-kani-run.result == 'success'",
        "AUTHS_FORMAL_TRANSLATION_SOURCE_ATTEMPT",
        "AUTHS_FORMAL_LEAN_SOURCE_ATTEMPT",
        "AUTHS_FORMAL_KANI_SOURCE_ATTEMPT",
    ] {
        if !evidence_job.contains(required) {
            return Err(format!(
                "formal evidence aggregator omits required result `{required}`"
            ));
        }
    }
    let gate_job = workflow_job_source(ci, "formal-translation")?;
    if !gate_job.contains("needs: [ci-plan, formal-evidence-run]") {
        return Err(
            "formal-translation gate does not consume the sole evidence aggregator".to_owned(),
        );
    }
    // Kani can be planned without formal translation, and then the evidence
    // aggregator is skipped; its own gate must still reach the final result.
    let kani_gate = workflow_job_source(ci, "formal-kani")?;
    if !kani_gate.contains("needs: [ci-plan, formal-kani-run]")
        || !kani_gate.contains("needs.ci-plan.outputs.formal_kani_required")
        || !kani_gate.contains("needs.formal-kani-run.result")
    {
        return Err("formal-kani gate does not enforce the planned Kani result".to_owned());
    }
    let qualified = workflow_job_source(ci, "ci-qualified")?;
    if !qualified.contains("      - formal-kani\n")
        || !qualified.contains("needs.formal-kani.result")
        || !qualified.contains("[[ \"$FORMAL_KANI\" == success ]]")
    {
        return Err("CI qualified does not require the formal-kani gate".to_owned());
    }
    let compliance_job = workflow_job_source(ci, "compliance-run")?;
    if !compliance_job.contains("if: always() && hashFiles('target/compliance/**') != ''") {
        return Err(
            "hosted compliance evidence upload must skip a missing evidence directory without masking the primary failure"
                .to_owned(),
        );
    }
    Ok(())
}

/// Condition of every step on the two-reproduction path: it runs unless a
/// reuse step located evidence, so a cold plan, a same-PR miss, and absent
/// protected-base evidence all reach it.
const TRANSLATION_REPRODUCTION_CONDITION: &str = "steps.prior-pr-translation.outputs.reused != 'true' && steps.protected-base-translation.outputs.found != 'true'";

/// Protected-base evidence is an optimization, never a precondition. The base
/// commit's run may have failed in another job, been cancelled by a newer
/// push, still be running, or have expired; the job then executes the same two
/// clean reproductions as a cold plan. A pull-request reproduction runs in
/// update mode and rewrites drifted outputs in place, so the packaging step
/// must share its condition, or drift would qualify instead of stopping the
/// job. Located evidence is reused only through the binding step, whose
/// failure fails the job rather than falling back.
fn validate_translation_evidence_selection(job: &str) -> Result<(), String> {
    let locate = workflow_step_source(job, "Locate protected-base translation evidence")?;
    let bind = workflow_step_source(job, "Verify and bind protected-base translation evidence")?;
    let reproduce = workflow_step_source(job, "Reproduce translation twice")?;
    let package = workflow_step_source(job, "Package a bounded translation update")?;
    if !locate.contains("- id: protected-base-translation\n")
        || !bind.contains("\n        if: steps.protected-base-translation.outputs.found == 'true'\n")
        || !reproduce.contains(&format!(
            "\n        if: {TRANSLATION_REPRODUCTION_CONDITION}\n"
        ))
        || !package.contains(&format!(
            "\n        if: github.event_name == 'pull_request' && {TRANSLATION_REPRODUCTION_CONDITION}\n"
        ))
    {
        return Err(
            "hosted translation must reuse protected-base evidence only once located and bound, and otherwise execute two clean reproductions that package generated drift"
                .to_owned(),
        );
    }
    Ok(())
}

/// One step of a workflow job, from its list marker to the next step's, so a
/// condition is read from the step it gates rather than from anywhere in the
/// job.
fn workflow_step_source<'a>(job: &'a str, step_name: &str) -> Result<&'a str, String> {
    let name = format!("name: {step_name}");
    let starts: Vec<_> = job
        .match_indices("\n      - ")
        .map(|(index, _)| index)
        .collect();
    let ends = starts
        .iter()
        .skip(1)
        .copied()
        .chain(std::iter::once(job.len()));
    starts
        .iter()
        .copied()
        .zip(ends)
        .map(|(start, end)| &job[start..end])
        .find(|step| {
            step.lines().any(|line| {
                line.strip_prefix("      - ")
                    .or_else(|| line.strip_prefix("        "))
                    == Some(name.as_str())
            })
        })
        .ok_or_else(|| format!("hosted CI omits the `{step_name}` step"))
}

fn workflow_job_source<'a>(workflow: &'a str, job_name: &str) -> Result<&'a str, String> {
    let marker = format!("\n  {job_name}:");
    let tail = workflow
        .split_once(&marker)
        .map(|(_, tail)| tail)
        .ok_or_else(|| format!("hosted CI omits the `{job_name}` job boundary"))?;
    let next_job = tail.match_indices("\n  ").find_map(|(index, _)| {
        tail[index + 3..]
            .chars()
            .next()
            .filter(|character| !character.is_whitespace())
            .map(|_| index)
    });
    Ok(next_job.map_or(tail, |index| &tail[..index]))
}

/// One entry of a job's top-level `outputs:` mapping, the only place a
/// `needs.<job>.outputs.<name>` read resolves.
fn workflow_job_output<'a>(job: &'a str, output: &str) -> Option<&'a str> {
    job.split_once("\n    outputs:\n")?
        .1
        .lines()
        .take_while(|line| line.starts_with("      "))
        .find_map(|line| {
            line.strip_prefix("      ")?
                .strip_prefix(output)?
                .strip_prefix(": ")
        })
}

fn validate_release_workflow_gates(orchestration: &str, builder: &str) -> Result<(), String> {
    validate_gate_source(
        "release orchestration",
        orchestration,
        &["uses: ./.github/workflows/release-builder.yml"],
    )?;
    validate_gate_source(
        "reusable release builder",
        builder,
        &[
            "leanprover/lean-action@",
            "kani-verifier --version 0.67.0",
            "cargo xtask release-check",
            "cargo xtask formal qualify aeneas",
        ],
    )
}

fn validate_gate_source(label: &str, source: &str, needles: &[&str]) -> Result<(), String> {
    for needle in needles {
        if !source.contains(needle) {
            return Err(format!("{label} omits required formal gate `{needle}`"));
        }
    }
    Ok(())
}

fn build_qualification_cases(root: &Path, qualification: &Qualification) -> Result<(), String> {
    let formal = root.join("formal");
    for module in &qualification.case_modules {
        run_checked(
            "lake",
            &[String::from("build"), module.clone()],
            &formal,
            &[],
        )?;
    }
    Ok(())
}

fn run_rust_qualification_cases(root: &Path) -> Result<(), String> {
    run_checked(
        "python3",
        &[
            "core/fixtures/crypto/import_p256_wycheproof.py".to_owned(),
            "core/fixtures/crypto/upstream/ecdsa_secp256r1_sha256_p1363_test.json".to_owned(),
            "core/fixtures/crypto/p256-sha256-v1.tsv".to_owned(),
        ],
        root,
        &[],
    )?;
    run_checked(
        "cargo",
        &[
            "test".to_owned(),
            "-p".to_owned(),
            "auths-model".to_owned(),
            "-p".to_owned(),
            "auths-codec".to_owned(),
            "-p".to_owned(),
            "auths-composition".to_owned(),
            "-p".to_owned(),
            "auths-signature-core".to_owned(),
            "-p".to_owned(),
            "auths-signature".to_owned(),
            "-p".to_owned(),
            "auths-authority".to_owned(),
            "-p".to_owned(),
            "auths-author".to_owned(),
        ],
        root,
        &[],
    )?;
    run_checked(
        "cargo",
        &[
            "test".to_owned(),
            "--locked".to_owned(),
            "-p".to_owned(),
            "auths-verifier".to_owned(),
            "--lib".to_owned(),
            "temporal_tests".to_owned(),
        ],
        root,
        &[],
    )?;
    run_checked(
        "cargo",
        &[
            "test".to_owned(),
            "--locked".to_owned(),
            "-p".to_owned(),
            "auths-registries".to_owned(),
            "--lib".to_owned(),
        ],
        root,
        &[],
    )
}

fn required_tool(variable: &str, fallback: &str) -> Result<PathBuf, String> {
    if let Some(value) = env::var_os(variable) {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!(
            "{variable} does not identify a file: {}",
            path.display()
        ));
    }
    let output = Command::new(fallback).arg("--help").output().map_err(|_| {
        format!(
            "pinned {fallback} is unavailable; set {variable} to the exact binary from formal/translation-toolchain.lock"
        )
    })?;
    if !output.status.success() {
        return Err(format!("could not execute {fallback} from PATH"));
    }
    Ok(PathBuf::from(fallback))
}

fn validate_translation_tool_versions(
    charon: &Path,
    aeneas: &Path,
    qualification: &Qualification,
) -> Result<(), String> {
    let charon_version = run_output(charon, &["version"], Path::new("."), &[])?;
    if charon_version.trim() != qualification.tools.charon {
        return Err(format!(
            "Charon drift: expected {}, found {}",
            qualification.tools.charon,
            charon_version.trim()
        ));
    }
    let aeneas_version = run_output(aeneas, &["-version"], Path::new("."), &[])?;
    let expected_commit = qualification.tools.aeneas_commit.as_str();
    let expected = format!("aeneas {expected_commit}");
    let actual = aeneas_version.trim();
    let actual_version = actual.strip_prefix("aeneas ").unwrap_or(actual);
    if !aeneas_version_matches(actual_version, expected_commit) {
        return Err(format!(
            "Aeneas drift: expected {expected}, found {}",
            aeneas_version.trim()
        ));
    }
    Ok(())
}

fn ensure_clean_extraction_environment(
    root: &Path,
    qualification: &Qualification,
) -> Result<(), String> {
    for (variable, _) in env::vars_os() {
        let variable = variable.to_string_lossy();
        if is_semantic_build_variable(&variable) {
            return Err(format!(
                "Aeneas qualification refuses ambient semantic build variable {variable}"
            ));
        }
    }
    validate_ambient_cargo_configuration(root)?;
    if !qualification.semantic_cfg.is_empty() || !qualification.extraction_cfg.is_empty() {
        return Err("qualification requires empty shipping and extraction semantic cfg".to_owned());
    }
    Ok(())
}

fn is_semantic_build_variable(variable: &str) -> bool {
    if variable == "CARGO_TARGET_DIR" {
        return false;
    }
    matches!(
        variable,
        "RUSTFLAGS"
            | "CARGO_ENCODED_RUSTFLAGS"
            | "RUSTDOCFLAGS"
            | "RUSTC"
            | "RUSTC_WRAPPER"
            | "RUSTC_WORKSPACE_WRAPPER"
            | "RUSTC_BOOTSTRAP"
            | "CARGO_BUILD_TARGET"
    ) || variable.starts_with("CARGO_PROFILE_")
        || variable.starts_with("CARGO_TARGET_")
        || variable.starts_with("CARGO_BUILD_")
}

fn validate_ambient_cargo_configuration(root: &Path) -> Result<(), String> {
    let rustc = run_output("rustc", &["-vV"], Path::new("."), &[])?;
    let host = rustc
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or("rustc -vV omitted host triple")?;
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .ok_or("cannot resolve Cargo home for ambient configuration validation")?;
    let mut candidates = BTreeSet::new();
    for ancestor in root.ancestors() {
        for name in ["config.toml", "config"] {
            candidates.insert(ancestor.join(".cargo").join(name));
        }
    }
    for name in ["config.toml", "config"] {
        candidates.insert(cargo_home.join(name));
    }
    for path in candidates {
        if !path.exists() {
            continue;
        }
        let source = fs::read_to_string(&path).map_err(|error| {
            format!(
                "could not read ambient Cargo config {}: {error}",
                path.display()
            )
        })?;
        validate_ambient_cargo_config_source(&source, host).map_err(|error| {
            format!(
                "ambient Cargo config {} is semantic: {error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn validate_ambient_cargo_config_source(source: &str, host: &str) -> Result<(), String> {
    let config: toml::Value =
        toml::from_str(source).map_err(|error| format!("invalid Cargo config: {error}"))?;
    let table = config
        .as_table()
        .ok_or("Cargo config root is not a table")?;
    for (key, value) in table {
        match key.as_str() {
            // Aliases affect command spelling, not Cargo's build semantics.
            "alias" => {}
            // A concrete non-host target cannot affect this qualification,
            // which deliberately compiles for workspace-host. `cfg(...)`
            // selectors are rejected because they may match the host.
            "target" => {
                let targets = value
                    .as_table()
                    .ok_or("Cargo config [target] is not a table")?;
                if targets
                    .keys()
                    .any(|target| target == host || target.starts_with("cfg("))
                {
                    return Err("host-applicable [target] configuration is present".to_owned());
                }
            }
            _ => return Err(format!("unsupported ambient Cargo config section [{key}]")),
        }
    }
    Ok(())
}

fn recreate_directory(path: &Path) -> Result<(), String> {
    if path.exists() {
        fs::remove_dir_all(path)
            .map_err(|error| format!("could not clear {}: {error}", path.display()))?;
    }
    fs::create_dir_all(path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))
}

fn reproduce(
    root: &Path,
    charon: &Path,
    aeneas: &Path,
    stable_llbc: &Path,
    output: &Path,
) -> Result<(), String> {
    recreate_directory(output)?;
    recreate_directory(stable_llbc)?;
    let llbc = output.join("llbc");
    fs::create_dir_all(&llbc)
        .map_err(|error| format!("could not create {}: {error}", llbc.display()))?;

    run_checked(
        charon,
        &charon_arguments(
            "auths_signature_core::verify_ed25519,auths_signature_core::validate_ed25519_key,auths_signature_core::verify_p256_sha256_with",
            &stable_llbc.join("auths_signature_core.llbc"),
            "core/crates/auths-signature-core/Cargo.toml",
            &[],
        ),
        root,
        &[],
    )?;
    run_checked(
        charon,
        &charon_arguments(
            "auths_composition::evaluate,auths_composition::_::outcome",
            &stable_llbc.join("auths_composition.llbc"),
            "core/crates/auths-composition/Cargo.toml",
            &[
                "--include",
                "auths_model",
                "--include",
                "auths_algebra_kernel",
            ],
        ),
        root,
        &[],
    )?;
    run_checked(
        charon,
        &charon_arguments(
            "auths_codec::cbor::read_head,auths_codec::cbor::encode_head,auths_codec::decode::decode_canonical_action,auths_codec::hash::signing_preimage,auths_codec::hash::commitment_preimage,auths_codec::hash::identifier_preimage",
            &stable_llbc.join("auths_codec.llbc"),
            "core/crates/auths-codec/Cargo.toml",
            &["--include", "auths_model"],
        ),
        root,
        &[],
    )?;
    run_checked(
        charon,
        &charon_arguments(
            "auths_stores::gateway_fence::gateway_window_open,auths_stores::gateway_fence::advance_gateway_collection",
            &stable_llbc.join("auths_stores.llbc"),
            "product/stores/auths-stores/Cargo.toml",
            &[],
        ),
        root,
        &[],
    )?;
    run_checked(
        charon,
        &charon_arguments(
            "auths_codec::decode::status_trust",
            &stable_llbc.join("auths_scope_codec.llbc"),
            "core/crates/auths-codec/Cargo.toml",
            &["--include", "auths_model"],
        ),
        root,
        &[],
    )?;
    let model_starts = [
        "auths_model::identifier::bounded_identifier_valid",
        "auths_model::inclusive_window_contains",
        "auths_model::validity_window_contains",
        "auths_model::permission_set_contains",
        "auths_model::permission_set_is_subset",
        "auths_model::audience_set_contains",
        "auths_model::audience_set_is_subset",
        "auths_model::body_digest_set_contains",
        "auths_model::body_digest_set_is_subset",
        "auths_model::action_constraint_allows",
        "auths_model::action_constraint_attenuates",
        "auths_model::budget_ceiling_attenuates",
        "auths_model::optional_budget_attenuates",
        "auths_model::optional_budget_covers",
        "auths_model::budget_ceiling_covers_action",
        "auths_model::status_policy_attenuates",
        "auths_model::critical_extension_entries",
        "auths_model::critical_extension_id",
        "auths_model::critical_extension_payload",
        "auths_model::critical_extension_find",
        "auths_model::assurance_policy_id_equal",
        "auths_model::principal_id_equal",
        "auths_model::grant_id_equal",
        "auths_model::optional_grant_id_equal",
        "auths_model::profile_slice_contains",
        "auths_model::profile_ref_equal",
        "auths_model::observation::observation_fresh",
        "auths_model::observation::observation_subject_equal",
        "auths_model::observation::fact_name_equal",
        "auths_model::observation::fact_value_equal",
        "auths_model::observation::uint_range_contains",
        "auths_model::observation::member_values_contain",
        "auths_model::observation::observation_fact",
        "auths_model::observation::condition_value_holds",
        "auths_model::observation::observation_condition_holds",
        "auths_model::observation::observation_conditions_hold",
        "auths_model::observation::requirement_verdict",
        "auths_model::observation::observation_requirements_attenuate",
        "auths_model::bounded_policy::bounded_policy_link_accepts",
        "auths_model::approval::approval_counts",
        "auths_model::approval::approval_requirements_attenuate",
    ]
    .join(",");
    run_checked(
        charon,
        &charon_arguments(
            &model_starts,
            &stable_llbc.join("auths_model.llbc"),
            "core/crates/auths-model/Cargo.toml",
            &[],
        ),
        root,
        &[],
    )?;
    run_checked(
        charon,
        &charon_arguments(
            "auths_algebra_kernel::generated::attenuation_checks_accept,auths_algebra_kernel::root_preserved,auths_algebra_kernel::RootLinkage",
            &stable_llbc.join("auths_algebra_kernel.llbc"),
            "core/crates/auths-algebra-kernel/Cargo.toml",
            &[],
        ),
        root,
        &[],
    )?;
    let authority_options = [
        "--opaque",
        "auths_model",
        "--include",
        "auths_model::GrantAuthorityView",
        "--include",
        "auths_model::ActionAuthorityView",
        "--include",
        "auths_model::ScopeAuthorityView",
        "--include",
        "auths_model::DenialReason",
    ];
    run_checked(
        charon,
        &charon_arguments(
            "auths_authority::evaluate_grant_view,auths_authority::evaluate_action_coverage_view,auths_authority::evaluate_author_scope_view",
            &stable_llbc.join("auths_authority.llbc"),
            "core/crates/auths-authority/Cargo.toml",
            &authority_options,
        ),
        root,
        &[],
    )?;
    run_checked(
        charon,
        &charon_arguments(
            "auths_bounded_policy::kernel::configuration_match_code,auths_bounded_policy::kernel::checked_add_u64,auths_bounded_policy::kernel::checked_sub_u64,auths_bounded_policy::kernel::checked_mul_u64,auths_bounded_policy::kernel::checked_div_u64,auths_bounded_policy::kernel::ceiling_count_code,auths_bounded_policy::kernel::ceiling_count_tightens,auths_bounded_policy::kernel::window_index,auths_bounded_policy::kernel::chain_counts_admit,auths_bounded_policy::kernel::chain_sums_admit,auths_bounded_policy::kernel::argument_policy_tightens",
            &stable_llbc.join("auths_bounded_policy.llbc"),
            "product/policy/auths-bounded-policy/Cargo.toml",
            &[],
        ),
        root,
        &[],
    )?;
    run_checked(
        charon,
        &charon_arguments(
            "auths_lifecycle::kernel::transition_code,auths_lifecycle::kernel::additive_capacity_available,auths_lifecycle::kernel::exclusive_capacity_available,auths_lifecycle::kernel::replay_code",
            &stable_llbc.join("auths_lifecycle.llbc"),
            "product/runtime/auths-lifecycle/Cargo.toml",
            &[],
        ),
        root,
        &[],
    )?;
    run_checked(
        charon,
        &charon_arguments(
            "auths_gateway_kernel::counter_preimages::count_counter_preimage,auths_gateway_kernel::counter_preimages::sum_counter_preimage,auths_gateway_kernel::counter_preimages::count_slot_preimage,auths_gateway_kernel::counter_preimages::sum_slot_preimage,auths_gateway_kernel::frontier::_::new,auths_gateway_kernel::frontier::_::probe,auths_gateway_kernel::frontier::_::observe,auths_gateway_kernel::frontier::_::candidate,auths_gateway_kernel::deadline::entry_time_allows,auths_gateway_kernel::deadline::intersect_entry_bounds,auths_gateway_kernel::recovery::recovery_capability,auths_gateway_kernel::identity::valid_token,auths_gateway_kernel::identity::logical_operation_preimage,auths_gateway_kernel::construct::field_index,auths_gateway_kernel::construct::construct_write,auths_gateway_kernel::construct::construct_action_read,auths_gateway_kernel::construct::construct_credential_read,auths_gateway_kernel::order::start,auths_gateway_kernel::order::next_step,auths_gateway_kernel::transition::valid_transition,auths_gateway_kernel::ratio::relative_basis,auths_gateway_kernel::ratio::relative_ceiling_admits",
            &stable_llbc.join("auths_gateway_kernel.llbc"),
            "product/runtime/auths-gateway-kernel/Cargo.toml",
            &[],
        ),
        root,
        &[],
    )?;
    run_checked(
        charon,
        &charon_arguments(
            "auths_connections::kernel::next_generation,auths_connections::kernel::state_change,auths_connections::kernel::rotation,auths_connections::kernel::retained_generation,auths_connections::kernel::lease_generation",
            &stable_llbc.join("auths_connections.llbc"),
            "product/runtime/auths-connections/Cargo.toml",
            &[],
        ),
        root,
        &[],
    )?;

    run_checked(
        charon,
        &charon_arguments(
            "auths_codec::hash::raw_sha256",
            &stable_llbc.join("auths_codec_sha256.llbc"),
            "core/crates/auths-codec/Cargo.toml",
            &[
                "--monomorphize",
                "--include",
                "auths_model",
                "--opaque",
                "sha2",
                "--opaque",
                "digest",
                "--opaque",
                "crypto_common",
                "--opaque",
                "typenum",
            ],
        ),
        root,
        &[],
    )?;
    run_checked(
        charon,
        &charon_arguments(
            "auths_signature_core::verify_p256_sha256,auths_signature_core::validate_p256_key",
            &stable_llbc.join("auths_signature_core_p256.llbc"),
            "core/crates/auths-signature-core/Cargo.toml",
            &[
                "--monomorphize",
                "--opaque",
                "p256",
                "--opaque",
                "ecdsa",
                "--opaque",
                "elliptic_curve",
                "--opaque",
                "primeorder",
                "--opaque",
                "crypto_bigint",
                "--opaque",
                "signature",
            ],
        ),
        root,
        &[],
    )?;
    run_checked(
        charon,
        &charon_arguments(
            "{impl auths_ports::SignatureSuite for auths_signature::Ed25519Suite}::verify,{impl auths_ports::SignatureSuite for auths_signature::P256Sha256Suite}::verify",
            &stable_llbc.join("auths_signature.llbc"),
            "core/crates/auths-signature/Cargo.toml",
            &["--include", "auths_ports"],
        ),
        root,
        &[],
    )?;
    run_checked(
        charon,
        &charon_arguments(
            "auths_verifier::assurance_horizon,auths_verifier::status_horizon,auths_verifier::status_decision",
            &stable_llbc.join("auths_verifier.llbc"),
            "core/crates/auths-verifier/Cargo.toml",
            &["--include", "auths_model", "--include", "auths_ports"],
        ),
        root,
        &[],
    )?;
    run_checked(
        charon,
        &charon_arguments(
            "{impl auths_ports::StatusMethod for auths_registries::ExactStatusMethod}::principal,{impl auths_ports::StatusMethod for auths_registries::ExactStatusMethod}::grant",
            &stable_llbc.join("auths_registries.llbc"),
            "core/crates/auths-registries/Cargo.toml",
            &["--include", "auths_model", "--include", "auths_ports"],
        ),
        root,
        &[],
    )?;
    normalize_p256_llbc_names(
        &stable_llbc.join("auths_signature_core_p256.llbc"),
        output,
        charon,
        root,
    )?;
    normalize_sha256_llbc_names(
        &stable_llbc.join("auths_codec_sha256.llbc"),
        output,
        charon,
        root,
    )?;

    for crate_name in [
        "auths_scope_codec",
        "auths_registries",
        "auths_verifier",
        "auths_signature",
        "auths_signature_core_p256",
        "auths_codec_sha256",
        "auths_signature_core",
        "auths_composition",
        "auths_stores",
        "auths_codec",
        "auths_model",
        "auths_algebra_kernel",
        "auths_authority",
        "auths_bounded_policy",
        "auths_lifecycle",
        "auths_gateway_kernel",
        "auths_connections",
    ] {
        let snapshot = llbc.join(format!("{crate_name}.llbc"));
        fs::copy(stable_llbc.join(format!("{crate_name}.llbc")), &snapshot).map_err(|error| {
            format!("could not snapshot deterministic {crate_name} LLBC: {error}")
        })?;
        let arguments = ["pretty-print".to_owned(), snapshot.display().to_string()];
        let pretty = command_output(charon, &arguments, root, &[])?;
        if !pretty.status.success() {
            return Err(format_command_failure(&arguments, root, &pretty));
        }
        fs::write(
            llbc.join(format!("{crate_name}.llbc.pretty")),
            pretty.stdout,
        )
        .map_err(|error| format!("could not write canonical {crate_name} LLBC: {error}"))?;
    }

    for (crate_name, subdir) in [
        ("auths_scope_codec", "scope_codec"),
        ("auths_registries", "status_selection"),
        ("auths_verifier", "temporal_witness"),
        ("auths_signature", "suite_adapter"),
        ("auths_signature_core_p256", "p256"),
        ("auths_codec_sha256", "sha256"),
        ("auths_signature_core", "signature"),
        ("auths_composition", "composition"),
        ("auths_stores", "stores"),
        ("auths_codec", "codec"),
        ("auths_model", "model"),
        ("auths_algebra_kernel", "algebra"),
        ("auths_authority", "authority"),
        ("auths_bounded_policy", "bounded_policy"),
        ("auths_lifecycle", "lifecycle"),
        ("auths_gateway_kernel", "gateway"),
        ("auths_connections", "connections"),
    ] {
        let destination = output.join(format!("{subdir}-run"));
        fs::create_dir_all(&destination).map_err(|error| {
            format!(
                "could not create Aeneas destination {}: {error}",
                destination.display()
            )
        })?;
        let mut aeneas_arguments = vec![
            "-backend".to_owned(),
            "lean".to_owned(),
            "-split-files".to_owned(),
            "-emit-json".to_owned(),
            "-warnings-as-errors".to_owned(),
            "-subdir".to_owned(),
            format!("qualification/aeneas/generated/{subdir}"),
            "-dest".to_owned(),
            destination.display().to_string(),
            llbc.join(format!("{crate_name}.llbc"))
                .display()
                .to_string(),
        ];
        if matches!(
            crate_name,
            "auths_scope_codec"
                | "auths_composition"
                | "auths_signature_core"
                | "auths_signature_core_p256"
                | "auths_verifier"
                | "auths_registries"
        ) {
            aeneas_arguments.insert(0, "-loops-to-rec".to_owned());
        }
        if subdir == "scope_codec" {
            aeneas_arguments.splice(
                0..0,
                ["-namespace".to_owned(), "AuthsScopeCodec".to_owned()],
            );
        }
        if subdir == "status_selection" {
            aeneas_arguments.splice(
                0..0,
                ["-namespace".to_owned(), "AuthsStatusSelection".to_owned()],
            );
        }
        if subdir == "temporal_witness" {
            aeneas_arguments.splice(
                0..0,
                ["-namespace".to_owned(), "AuthsTemporalWitness".to_owned()],
            );
        }
        if subdir == "suite_adapter" {
            aeneas_arguments.splice(
                0..0,
                ["-namespace".to_owned(), "AuthsSuiteAdapters".to_owned()],
            );
        }
        if subdir == "p256" {
            aeneas_arguments.splice(
                0..0,
                ["-namespace".to_owned(), "AuthsNativeP256".to_owned()],
            );
        }
        if subdir == "sha256" {
            aeneas_arguments.splice(
                0..0,
                ["-namespace".to_owned(), "AuthsNativeSha256".to_owned()],
            );
        }
        run_checked(aeneas, &aeneas_arguments, root, &[])?;
    }
    for crate_name in [
        "auths_scope_codec",
        "auths_registries",
        "auths_verifier",
        "auths_signature",
        "auths_signature_core_p256",
        "auths_codec_sha256",
        "auths_signature_core",
        "auths_composition",
        "auths_stores",
        "auths_codec",
        "auths_model",
        "auths_algebra_kernel",
        "auths_authority",
        "auths_bounded_policy",
        "auths_lifecycle",
        "auths_gateway_kernel",
        "auths_connections",
    ] {
        fs::remove_file(llbc.join(format!("{crate_name}.llbc")))
            .map_err(|error| format!("could not remove raw nondeterministic LLBC: {error}"))?;
    }
    normalize_composition_discriminants(output)?;
    normalize_signature_discriminants(output)?;
    normalize_signature_primitive_context(output)?;
    normalize_sha256_primitive_context(output)?;
    normalize_p256_context(output)?;
    normalize_suite_adapter_context(output)?;
    normalize_temporal_context(output)?;
    normalize_scope_codec_context(output)?;
    normalize_status_selection_context(output)?;
    Ok(())
}

// Preserve every translated Rust function body and constructor. The support
// modules qualify instances and give an isomorphic bounded Vec. A single trait
// dictionary field restores its erased unit output with a proved Result
// isomorphism; the callback implementation itself is not rewritten.
fn normalize_composition_discriminants(output: &Path) -> Result<(), String> {
    let path = output.join("composition-run/qualification/aeneas/generated/composition/Types.lean");
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("could not read composition types: {error}"))?;
    if source.matches("discriminant isize").count() != 8
        || source.matches("import Aeneas\n").count() != 1
        || source.contains("qualified_discriminant")
    {
        return Err("composition discriminant normalization input drifted".to_owned());
    }
    let normalized = source
        .replace(
            "import Aeneas\n",
            "import Aeneas\nimport Auths.Support.Discriminant\nimport Auths.Support.PositiveVec\n",
        )
        .replace("discriminant isize", "qualified_discriminant isize");
    fs::write(path, normalized)
        .map_err(|error| format!("could not write composition types: {error}"))?;
    let functions =
        output.join("composition-run/qualification/aeneas/generated/composition/Funs.lean");
    let source = fs::read_to_string(&functions)
        .map_err(|error| format!("could not read composition functions: {error}"))?;
    let normalized = normalize_unit_observer_dictionary(&source)?;
    fs::write(functions, normalized)
        .map_err(|error| format!("could not write composition dictionary bridge: {error}"))
}

fn normalize_unit_observer_dictionary(source: &str) -> Result<String, String> {
    const ORIGINAL: &str = "  call_mut :=\n    evaluate.closure.Insts.CoreOpsFunctionFnMutTupleEvaluationEventTuple.call_mut\n    coreopsfunctionFnMutT0TupleProofRefBranchOutcomeInst\n}";
    const ADAPTED: &str = "  call_mut := fun state event => Auths.Support.UnitCallback.restore (\n    evaluate.closure.Insts.CoreOpsFunctionFnMutTupleEvaluationEventTuple.call_mut\n    coreopsfunctionFnMutT0TupleProofRefBranchOutcomeInst state event)\n}";
    if source.matches(ORIGINAL).count() != 1 || source.matches("import Aeneas\n").count() != 1 {
        return Err("composition unit-observer dictionary input drifted".to_owned());
    }
    Ok(source
        .replace(
            "import Aeneas\n",
            "import Aeneas\nimport Auths.Support.UnitCallback\n",
        )
        .replace(ORIGINAL, ADAPTED))
}

// Two signature-error enums share discriminant values with other extracted
// modules. Qualify only the generated instance names; preserve all types and
// translated Rust function bodies.
fn normalize_signature_discriminants(output: &Path) -> Result<(), String> {
    let path = output.join("signature-run/qualification/aeneas/generated/signature/Types.lean");
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("could not read signature types: {error}"))?;
    if source.matches("discriminant isize").count() != 2
        || source.matches("import Aeneas\n").count() != 1
        || source.contains("qualified_discriminant")
    {
        return Err("signature discriminant normalization input drifted".to_owned());
    }
    let normalized = source
        .replace(
            "import Aeneas\n",
            "import Aeneas\nimport Auths.Support.Discriminant\n",
        )
        .replace("discriminant isize", "qualified_discriminant isize");
    fs::write(path, normalized).map_err(|error| format!("could not write signature types: {error}"))
}

// Generalize only the explicit foreign implementation parameter. Lean threads
// this section variable through exactly the declarations using those foreign
// types/calls. No generated Rust function body is changed and no instance exists.
// The pinned OCaml name-pattern emitter cannot print `Instantiated` name
// elements. These are foreign declaration identities only: preserve every
// Auths name, body, signature, layout, source span and call/type ID.
fn p256_export_names(mut document: Value) -> Result<(Value, Value), String> {
    let original = document.clone();
    let mut substitutions = BTreeMap::<String, Value>::new();
    let mut selected = Vec::new();
    let mut identities = BTreeSet::new();
    let mut ledger = Vec::new();
    for group in [
        "type_decls",
        "fun_decls",
        "global_decls",
        "trait_decls",
        "trait_impls",
    ] {
        let rows = document["translated"][group]
            .as_array()
            .ok_or_else(|| format!("P-256 LLBC omits {group}"))?;
        for (index, row) in rows.iter().enumerate().filter(|(_, row)| !row.is_null()) {
            let name = row["item_meta"]["name"]
                .as_array()
                .ok_or("P-256 declaration has no name")?;
            if !name.iter().any(|part| part.get("Instantiated").is_some()) {
                continue;
            }
            let id = row["def_id"]
                .as_u64()
                .ok_or("P-256 declaration has no id")?;
            let root = name
                .first()
                .and_then(|part| part["Ident"][0].as_str())
                .ok_or("P-256 name has no crate root")?;
            let expected_root = match (group, id) {
                ("type_decls", 4 | 11) => "ecdsa",
                ("type_decls", 0 | 3 | 6 | 7 | 9 | 12 | 13 | 14 | 16 | 17) => "core",
                ("fun_decls", 2 | 4) => "auths_signature_core",
                ("fun_decls", 14 | 18 | 23 | 26 | 29) => "ecdsa",
                ("fun_decls", 5 | 6 | 7 | 13 | 15 | 17 | 20 | 22 | 24 | 27 | 30 | 31 | 32 | 33) => {
                    "core"
                }
                _ => "",
            };
            if root != expected_root || !identities.insert((group, id)) {
                return Err(
                    "P-256 export-name inventory contains an unreviewed identity".to_owned(),
                );
            }
            let renamed = if root == "auths_signature_core" {
                let base = if id == 2 {
                    "verify_p256_sha256_with"
                } else {
                    "decode_p256_key_with"
                };
                if row["item_meta"]["is_local"] != true
                    || name.len() != 3
                    || name[1] != json!({"Ident": [base, 0]})
                    || name[2].get("Instantiated").is_none()
                {
                    return Err(
                        "P-256 normalization would change an unreviewed Auths source name"
                            .to_owned(),
                    );
                }
                Value::Array(name[..2].to_vec())
            } else {
                if row["item_meta"]["is_local"] != false {
                    return Err("P-256 foreign alias names a local declaration".to_owned());
                }
                json!([{"Ident": [root, 0]}, {"Ident": [format!("qualified_p256_{group}_{id}"), 0]}])
            };
            let key = serde_json::to_string(&row["item_meta"]["name"])
                .map_err(|error| error.to_string())?;
            if substitutions.insert(key, renamed.clone()).is_some() {
                return Err("P-256 foreign declaration names are not unique".to_owned());
            }
            selected.push((group, index, renamed.clone()));
            ledger.push(json!({
                "declaration_group": group, "declaration_id": id,
                "original_name": row["item_meta"]["name"],
                "normalized_name": renamed, "source_span": row["item_meta"]["span"],
            }));
        }
    }
    if selected.len() != 33 {
        return Err("P-256 foreign monomorphized name inventory drifted".to_owned());
    }
    fn rewrite(value: &mut Value, substitutions: &BTreeMap<String, Value>) -> Result<(), String> {
        if value
            .as_array()
            .and_then(|array| array.first())
            .is_some_and(|first| first.get("Ident").is_some())
        {
            let key = serde_json::to_string(value).map_err(|error| error.to_string())?;
            if let Some(replacement) = substitutions.get(&key) {
                value.clone_from(replacement);
                return Ok(());
            }
        }
        match value {
            Value::Array(values) => {
                for value in values {
                    rewrite(value, substitutions)?;
                }
            }
            Value::Object(values) => {
                for value in values.values_mut() {
                    rewrite(value, substitutions)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
    rewrite(&mut document, &substitutions)?;
    let mut expected = original.clone();
    for (group, index, name) in selected {
        expected["translated"][group][index]["item_meta"]["name"] = name;
    }
    // Charon stores copies of declaration names in three metadata caches.
    for cache in ["item_names", "assoc_item_names", "short_names"] {
        expected["translated"][cache] = document["translated"][cache].clone();
    }
    if expected != document {
        return Err("P-256 name normalization changed non-name declaration data".to_owned());
    }
    Ok((
        document,
        json!({
            "schema": "auths-proof-foreign-name-normalization/v1",
            "declarations": ledger,
            "preserved": ["Auths base source names", "all function bodies", "signatures", "generics", "layouts", "source spans", "call and type IDs"],
        }),
    ))
}

fn sha256_foreign_names(mut document: Value) -> Result<(Value, Value), String> {
    let original = document.clone();
    let mut substitutions = BTreeMap::<String, Value>::new();
    let mut selected = Vec::new();
    let mut identities = BTreeSet::new();
    let mut ledger = Vec::new();
    for group in [
        "type_decls",
        "fun_decls",
        "global_decls",
        "trait_decls",
        "trait_impls",
    ] {
        let rows = document["translated"][group]
            .as_array()
            .ok_or_else(|| format!("SHA-256 LLBC omits {group}"))?;
        for (index, row) in rows.iter().enumerate().filter(|(_, row)| !row.is_null()) {
            let name = row["item_meta"]["name"]
                .as_array()
                .ok_or("SHA-256 declaration has no name")?;
            if !name.iter().any(|part| part.get("Instantiated").is_some()) {
                continue;
            }
            let id = row["def_id"]
                .as_u64()
                .ok_or("SHA-256 declaration has no id")?;
            let allowed = match group {
                "type_decls" => [1, 2, 3, 4, 5, 6, 7, 11, 12].contains(&id),
                "fun_decls" => [1, 2].contains(&id),
                _ => false,
            };
            let root = name
                .first()
                .and_then(|part| part["Ident"][0].as_str())
                .ok_or("SHA-256 name has no crate root")?;
            let expected_root = match (group, id) {
                ("type_decls", 1) => "generic_array",
                ("type_decls", 2..=7) => "typenum",
                ("type_decls", 11 | 12) | ("fun_decls", 1) => "digest",
                ("fun_decls", 2) => "core",
                _ => "",
            };
            if !allowed
                || root != expected_root
                || row["item_meta"]["is_local"] != false
                || root.starts_with("auths_")
                || !identities.insert((group, id))
            {
                return Err(
                    "SHA-256 name normalization would touch an unreviewed or Auths declaration"
                        .to_owned(),
                );
            }
            let renamed = json!([
                {"Ident": [root, 0]},
                {"Ident": [format!("qualified_sha256_{group}_{id}"), 0]},
            ]);
            let key = serde_json::to_string(&row["item_meta"]["name"])
                .map_err(|error| error.to_string())?;
            if substitutions.insert(key, renamed.clone()).is_some() {
                return Err("SHA-256 foreign declaration names are not unique".to_owned());
            }
            selected.push((group, index, renamed.clone()));
            ledger.push(json!({
                "declaration_group": group, "declaration_id": id,
                "original_name": row["item_meta"]["name"],
                "normalized_name": renamed, "source_span": row["item_meta"]["span"],
            }));
        }
    }
    if selected.len() != 11 {
        return Err("SHA-256 foreign monomorphized name inventory drifted".to_owned());
    }
    fn rewrite(value: &mut Value, substitutions: &BTreeMap<String, Value>) -> Result<(), String> {
        if value
            .as_array()
            .and_then(|array| array.first())
            .is_some_and(|first| first.get("Ident").is_some())
        {
            let key = serde_json::to_string(value).map_err(|error| error.to_string())?;
            if let Some(replacement) = substitutions.get(&key) {
                value.clone_from(replacement);
                return Ok(());
            }
        }
        match value {
            Value::Array(values) => {
                for value in values {
                    rewrite(value, substitutions)?;
                }
            }
            Value::Object(values) => {
                for value in values.values_mut() {
                    rewrite(value, substitutions)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
    rewrite(&mut document, &substitutions)?;
    let mut expected = original.clone();
    for (group, index, name) in selected {
        expected["translated"][group][index]["item_meta"]["name"] = name;
    }
    // Charon stores copies of declaration names in three metadata caches.
    for cache in ["item_names", "assoc_item_names", "short_names"] {
        expected["translated"][cache] = document["translated"][cache].clone();
    }
    if expected != document {
        return Err("SHA-256 name normalization changed non-name declaration data".to_owned());
    }
    Ok((
        document,
        json!({
            "schema": "auths-proof-foreign-name-normalization/v1",
            "declarations": ledger,
            "preserved": ["Auths names", "all function bodies", "signatures", "generics", "layouts", "source spans", "call and type IDs"],
        }),
    ))
}

fn normalize_p256_llbc_names(
    path: &Path,
    output: &Path,
    charon: &Path,
    root: &Path,
) -> Result<(), String> {
    let source = fs::read(path).map_err(|error| format!("could not read P-256 LLBC: {error}"))?;
    let document =
        serde_json::from_slice(&source).map_err(|error| format!("invalid P-256 LLBC: {error}"))?;
    let path_text = path.display().to_string();
    let arguments = ["pretty-print", path_text.as_str()];
    let original = run_output(charon, &arguments, root, &[])?;
    let (document, mut ledger) = p256_export_names(document)?;
    write_pretty_json(path, &document)?;
    let normalized = run_output(charon, &arguments, root, &[])?;
    // Charon's short-name cache has nondeterministic map iteration order and
    // hash-cons references. Use its pinned canonical printer, as the existing
    // two-run LLBC gate does. The full JSON preservation check above still
    // compares every body/type field and permits only reviewed name changes.
    ledger["canonicalization"] = json!("pinned-charon-pretty-print-v1");
    ledger["original_canonical_llbc_sha256"] =
        json!(hex::encode(Sha256::digest(original.as_bytes())));
    ledger["normalized_canonical_llbc_sha256"] =
        json!(hex::encode(Sha256::digest(normalized.as_bytes())));
    fs::create_dir_all(output.join("p256-run"))
        .map_err(|error| format!("could not create P-256 output directory: {error}"))?;
    write_pretty_json(&output.join("p256-run/name-normalization.json"), &ledger)
}

fn normalize_sha256_llbc_names(
    path: &Path,
    output: &Path,
    charon: &Path,
    root: &Path,
) -> Result<(), String> {
    let source = fs::read(path).map_err(|error| format!("could not read SHA-256 LLBC: {error}"))?;
    let document = serde_json::from_slice(&source)
        .map_err(|error| format!("invalid SHA-256 LLBC: {error}"))?;
    let path_text = path.display().to_string();
    let arguments = ["pretty-print", path_text.as_str()];
    let original = run_output(charon, &arguments, root, &[])?;
    let (document, mut ledger) = sha256_foreign_names(document)?;
    write_pretty_json(path, &document)?;
    let normalized = run_output(charon, &arguments, root, &[])?;
    // Charon's short-name cache has nondeterministic map iteration order and
    // hash-cons references. Use its pinned canonical printer, as the existing
    // two-run LLBC gate does. The full JSON preservation check above still
    // compares every body/type field and permits only reviewed name changes.
    ledger["canonicalization"] = json!("pinned-charon-pretty-print-v1");
    ledger["original_canonical_llbc_sha256"] =
        json!(hex::encode(Sha256::digest(original.as_bytes())));
    ledger["normalized_canonical_llbc_sha256"] =
        json!(hex::encode(Sha256::digest(normalized.as_bytes())));
    fs::create_dir_all(output.join("sha256-run"))
        .map_err(|error| format!("could not create SHA-256 output directory: {error}"))?;
    write_pretty_json(
        &output.join("sha256-run/foreign-name-normalization.json"),
        &ledger,
    )
}

fn normalize_scope_codec_context(output: &Path) -> Result<(), String> {
    let path = output.join("scope_codec-run/qualification/aeneas/generated/scope_codec/Types.lean");
    let source = fs::read_to_string(&path).map_err(|error| error.to_string())?;
    fs::write(path, scope_codec_type_context(&source)?).map_err(|error| error.to_string())
}
fn scope_codec_type_context(source: &str) -> Result<String, String> {
    if source.matches("namespace AuthsScopeCodec\n").count() != 1
        || source.matches("import Aeneas\n").count() != 1
        || source.contains("qualified_discriminant")
        || source.matches("@[discriminant isize").count() != 4
    {
        return Err("scope-codec type context input drifted".to_owned());
    }
    Ok(source
        .replace(
            "import Aeneas\n",
            "import Aeneas\nimport Auths.Support.Discriminant\n",
        )
        .replace("discriminant isize", "qualified_discriminant isize"))
}
#[cfg(test)]
mod scope_codec_context_tests {
    use super::scope_codec_type_context;
    #[test]
    fn context_preserves_bodies_and_rejects_missing_repeated_or_changed_input() {
        let reviewed =
            include_str!("../../formal/qualification/aeneas/generated/scope_codec/Types.lean");
        let raw = reviewed
            .replace("import Auths.Support.Discriminant\n", "")
            .replace("qualified_discriminant isize", "discriminant isize");
        assert_eq!(
            scope_codec_type_context(&raw).expect("reviewed context"),
            reviewed
        );
        assert!(scope_codec_type_context(reviewed).is_err());
        assert!(scope_codec_type_context(&raw.replace("namespace AuthsScopeCodec\n", "")).is_err());
        assert!(
            scope_codec_type_context(&raw.replacen(
                "@[discriminant isize",
                "@[rust_discriminant isize",
                1
            ))
            .is_err()
        );
    }
}

fn normalize_status_selection_context(output: &Path) -> Result<(), String> {
    let path = output
        .join("status_selection-run/qualification/aeneas/generated/status_selection/Types.lean");
    let source = fs::read_to_string(&path).map_err(|error| error.to_string())?;
    fs::write(path, status_selection_type_context(&source)?).map_err(|error| error.to_string())
}
fn status_selection_type_context(source: &str) -> Result<String, String> {
    if source.matches("namespace AuthsStatusSelection\n").count() != 1
        || source.matches("import Aeneas\n").count() != 1
        || source.contains("qualified_discriminant")
        || source.matches("@[discriminant isize").count() != 7
    {
        return Err("status-selection type context input drifted".to_owned());
    }
    Ok(source
        .replace(
            "import Aeneas\n",
            "import Aeneas\nimport Auths.Support.Discriminant\n",
        )
        .replace("discriminant isize", "qualified_discriminant isize"))
}
#[cfg(test)]
mod status_selection_context_tests {
    use super::status_selection_type_context;
    #[test]
    fn context_preserves_bodies_and_rejects_missing_repeated_or_changed_input() {
        let reviewed =
            include_str!("../../formal/qualification/aeneas/generated/status_selection/Types.lean");
        let raw = reviewed
            .replace("import Auths.Support.Discriminant\n", "")
            .replace("qualified_discriminant isize", "discriminant isize");
        assert_eq!(
            status_selection_type_context(&raw).expect("reviewed context"),
            reviewed
        );
        assert!(status_selection_type_context(reviewed).is_err());
        assert!(
            status_selection_type_context(&raw.replace("namespace AuthsStatusSelection\n", ""))
                .is_err()
        );
        assert!(
            status_selection_type_context(&raw.replacen(
                "@[discriminant isize",
                "@[rust_discriminant isize",
                1
            ))
            .is_err()
        );
    }
}

fn normalize_temporal_context(output: &Path) -> Result<(), String> {
    let path = output
        .join("temporal_witness-run/qualification/aeneas/generated/temporal_witness/Types.lean");
    let source = fs::read_to_string(&path).map_err(|error| error.to_string())?;
    fs::write(path, temporal_type_context(&source)?).map_err(|error| error.to_string())
}
fn temporal_type_context(source: &str) -> Result<String, String> {
    if source.matches("namespace AuthsTemporalWitness\n").count() != 1
        || source.matches("import Aeneas\n").count() != 1
        || source.contains("qualified_discriminant")
        || source.matches("@[discriminant isize").count() != 10
    {
        return Err("temporal type context input drifted".to_owned());
    }
    Ok(source
        .replace(
            "import Aeneas\n",
            "import Aeneas\nimport Auths.Support.Discriminant\n",
        )
        .replace("discriminant isize", "qualified_discriminant isize"))
}

#[cfg(test)]
mod temporal_context_tests {
    use super::temporal_type_context;

    #[test]
    fn context_preserves_the_exact_type_bodies_and_rejects_drift() {
        let reviewed =
            include_str!("../../formal/qualification/aeneas/generated/temporal_witness/Types.lean");
        let raw = reviewed
            .replace("import Auths.Support.Discriminant\n", "")
            .replace("qualified_discriminant isize", "discriminant isize");
        assert_eq!(temporal_type_context(&raw).unwrap(), reviewed);
        assert!(temporal_type_context(reviewed).is_err());
        assert!(temporal_type_context(&format!("{raw}{raw}")).is_err());
        assert!(
            temporal_type_context(&raw.replacen("@[discriminant isize", "@[other isize", 1))
                .is_err()
        );
        assert!(
            temporal_type_context(&raw.replace("namespace AuthsTemporalWitness\n", "")).is_err()
        );
    }
}

fn normalize_suite_adapter_context(output: &Path) -> Result<(), String> {
    let directory = output.join("suite_adapter-run/qualification/aeneas/generated/suite_adapter");
    for file in ["Types.lean", "Funs.lean"] {
        let path = directory.join(file);
        let source = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        fs::write(path, suite_adapter_context(&source, file == "Types.lean")?)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}
fn suite_adapter_context(source: &str, types: bool) -> Result<String, String> {
    if source.matches("namespace AuthsSuiteAdapters\n").count() != 1
        || source.contains("variable [edPrimitive")
        || source.contains("variable [p256Primitive")
        || source.contains("qualified_discriminant")
    {
        return Err("suite adapter context input drifted".to_owned());
    }
    if types {
        if source.matches("import Aeneas\n").count() != 1 {
            return Err("suite adapter type import drifted".to_owned());
        }
        Ok(source
            .replace(
                "import Aeneas\n",
                "import Aeneas\nimport Auths.Support.Discriminant\n",
            )
            .replace("discriminant isize", "qualified_discriminant isize"))
    } else {
        if source.matches("noncomputable section\n").count() != 1 {
            return Err("suite adapter section drifted".to_owned());
        }
        Ok(source.replace("noncomputable section\n", "noncomputable section\n\nvariable [edPrimitive : Auths.Crypto.Ed25519Primitives]\nvariable [p256Primitive : Auths.Crypto.P256Primitives]\n"))
    }
}

fn normalize_p256_context(output: &Path) -> Result<(), String> {
    let directory = output.join("p256-run/qualification/aeneas/generated/p256");
    for file in ["Types.lean", "Funs.lean"] {
        let path = directory.join(file);
        let source = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        fs::write(path, p256_context(&source, file == "Types.lean")?)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn p256_context(source: &str, types: bool) -> Result<String, String> {
    let marker = if types {
        "namespace AuthsNativeP256\n"
    } else {
        "noncomputable section\n"
    };
    if source.matches(marker).count() != 1
        || source.contains("variable [primitive")
        || !source.contains("namespace AuthsNativeP256\n")
        || source.contains("qualified_discriminant")
    {
        return Err("P-256 explicit primitive context input drifted".to_owned());
    }
    let generalized = source.replace(
        marker,
        &format!("{marker}\nvariable [primitive : Auths.Crypto.P256Primitives]\n"),
    );
    if !types {
        return Ok(generalized);
    }
    if generalized.matches("import Aeneas\n").count() != 1 {
        return Err("P-256 type import input drifted".to_owned());
    }
    Ok(generalized
        .replace(
            "import Aeneas\n",
            "import Aeneas\nimport Auths.Support.Discriminant\n",
        )
        .replace("discriminant isize", "qualified_discriminant isize"))
}

fn normalize_sha256_primitive_context(output: &Path) -> Result<(), String> {
    let path = output.join("sha256-run/qualification/aeneas/generated/sha256/Funs.lean");
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("could not read SHA-256 functions: {error}"))?;
    fs::write(path, sha256_primitive_context(&source)?)
        .map_err(|error| format!("could not write SHA-256 functions: {error}"))
}

fn sha256_primitive_context(source: &str) -> Result<String, String> {
    let marker = "noncomputable section\n";
    if source.matches(marker).count() != 1
        || source.matches("namespace AuthsNativeSha256\n").count() != 1
        || source.contains("Auths.Crypto.Sha256Primitives")
    {
        return Err("SHA-256 explicit primitive context input drifted".to_owned());
    }
    Ok(source.replace(
        marker,
        "noncomputable section\n\nvariable [primitive : Auths.Crypto.Sha256Primitives]\n",
    ))
}

fn normalize_signature_primitive_context(output: &Path) -> Result<(), String> {
    let path = output.join("signature-run/qualification/aeneas/generated/signature/Funs.lean");
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("could not read signature functions: {error}"))?;
    fs::write(path, signature_primitive_context(&source)?)
        .map_err(|error| format!("could not write signature functions: {error}"))
}

fn signature_primitive_context(source: &str) -> Result<String, String> {
    let marker = "noncomputable section\n";
    if source.matches(marker).count() != 1
        || source.matches("namespace auths_signature_core\n").count() != 1
        || source.contains("Auths.Crypto.Ed25519Primitives")
    {
        return Err("signature explicit primitive context input drifted".to_owned());
    }
    Ok(source.replace(
        marker,
        "noncomputable section\n\nvariable [primitives : Auths.Crypto.Ed25519Primitives]\n",
    ))
}

fn charon_arguments(
    start_from: &str,
    destination: &Path,
    manifest: &str,
    extra: &[&str],
) -> Vec<String> {
    let mut arguments = vec![
        "cargo".to_owned(),
        "--preset".to_owned(),
        "aeneas".to_owned(),
        "--start-from".to_owned(),
        start_from.to_owned(),
        "--error-on-warnings".to_owned(),
        "--dest-file".to_owned(),
        destination.display().to_string(),
        "--format".to_owned(),
        "json".to_owned(),
    ];
    for argument in extra {
        arguments.push((*argument).to_owned());
    }
    arguments.extend([
        "--".to_owned(),
        "--manifest-path".to_owned(),
        manifest.to_owned(),
    ]);
    arguments
}

fn synchronize_aeneas_output(root: &Path, reproduced: &Path, update: bool) -> Result<(), String> {
    for &(source, destination) in AENEAS_OUTPUT_MAPPINGS {
        let bytes = fs::read(reproduced.join(source)).map_err(|error| {
            format!("could not read reproduced Aeneas output {source}: {error}")
        })?;
        let destination = root.join(destination);
        if update {
            fs::write(&destination, bytes).map_err(|error| {
                format!(
                    "could not update generated Aeneas output {}: {error}",
                    destination.display()
                )
            })?;
        } else {
            let actual = fs::read(&destination).map_err(|error| {
                format!(
                    "could not read committed Aeneas output {}: {error}",
                    destination.display()
                )
            })?;
            if actual != bytes {
                return Err(format!(
                    "generated Aeneas output drifted: {}; reproduce with `cargo xtask formal qualify aeneas --update`",
                    destination.display()
                ));
            }
        }
    }
    Ok(())
}

fn canonicalize_aeneas_versions(reproduced: &Path, expected_commit: &str) -> Result<(), String> {
    for &(source, _) in AENEAS_OUTPUT_MAPPINGS
        .iter()
        .filter(|(source, _)| source.ends_with("translation.json"))
    {
        let path = reproduced.join(source);
        let mut report: Value = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?,
        )
        .map_err(|error| {
            format!(
                "invalid Aeneas translation report {}: {error}",
                path.display()
            )
        })?;
        let actual = report["aeneas_version"].as_str().ok_or_else(|| {
            format!(
                "Aeneas translation report omits aeneas_version: {}",
                path.display()
            )
        })?;
        if !aeneas_version_matches(actual, expected_commit) {
            return Err(format!(
                "Aeneas translation identity drifted for {source}: expected {expected_commit}, found {actual}"
            ));
        }
        report["aeneas_version"] = Value::String(expected_commit.to_owned());
        write_pretty_json(&path, &report)?;
    }
    Ok(())
}

fn collect_files(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    fn walk(
        base: &Path,
        directory: &Path,
        output: &mut BTreeMap<String, Vec<u8>>,
    ) -> Result<(), String> {
        let mut entries: Vec<_> = fs::read_dir(directory)
            .map_err(|error| format!("could not read {}: {error}", directory.display()))?
            .collect::<Result<_, _>>()
            .map_err(|error| format!("could not enumerate {}: {error}", directory.display()))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, output)?;
            } else if path.is_file() {
                let relative = path
                    .strip_prefix(base)
                    .map_err(|error| format!("could not relativize {}: {error}", path.display()))?
                    .to_string_lossy()
                    .replace('\\', "/");
                output.insert(
                    relative,
                    fs::read(&path)
                        .map_err(|error| format!("could not read {}: {error}", path.display()))?,
                );
            }
        }
        Ok(())
    }

    let mut files = BTreeMap::new();
    walk(root, root, &mut files)?;
    Ok(files)
}

fn write_evidence(
    root: &Path,
    qualification: &Qualification,
    closure_digest: &str,
    reproduced: bool,
) -> Result<(), String> {
    let path = root.join("target/formal/aeneas-qualification.json");
    let generated_artifacts_digest = generated_artifact_digest(root)?;
    let evidence = json!({
        "schema": "auths-proof-aeneas-qualification-evidence/v1",
        "decision": qualification.decision,
        "source_closure_sha256": closure_digest,
        "generated_artifacts_sha256": generated_artifacts_digest,
        "production_features": qualification.production_features,
        "semantic_cfg": qualification.semantic_cfg,
        "extraction_cfg": qualification.extraction_cfg,
        "compiled_external_axioms": 0,
        "reviewed_external_models": qualification.external_models.len(),
        "case_modules": qualification.case_modules,
        "clean_reproduction": if reproduced { "byte-identical" } else { "not-run-committed-artifacts-validated" },
        "adr": qualification.adr,
    });
    write_evidence_monotonic(&path, &evidence, reproduced)
}

fn validate_generated_artifact_inventory(paths: &[String]) -> Result<(), String> {
    let expected = GENERATED_ARTIFACTS
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<Vec<_>>();
    if paths != expected {
        return Err(format!(
            "Aeneas generated artifact inventory drifted; expected the canonical {}-artifact synchronization set",
            expected.len()
        ));
    }

    let synchronized = AENEAS_OUTPUT_MAPPINGS
        .iter()
        .map(|(_, destination)| *destination)
        .chain(REVIEWED_BRIDGE_ARTIFACTS.iter().copied())
        .collect::<BTreeSet<_>>();
    let canonical = GENERATED_ARTIFACTS.iter().copied().collect::<BTreeSet<_>>();
    if synchronized != canonical {
        return Err(
            "internal Aeneas synchronization destinations do not equal the canonical generated artifact inventory"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_exact_inventory(
    label: &str,
    actual: &[String],
    expected: &[&str],
) -> Result<(), String> {
    if actual.iter().map(String::as_str).collect::<Vec<_>>() != expected {
        return Err(format!("Aeneas {label} inventory drifted"));
    }
    Ok(())
}

fn generated_artifact_digest(root: &Path) -> Result<String, String> {
    let mut aggregate = Sha256::new();
    for relative in GENERATED_ARTIFACTS {
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("could not stat generated artifact {relative}: {error}"))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "generated artifact is not a regular non-symlink file: {relative}"
            ));
        }
        let bytes = fs::read(&path)
            .map_err(|error| format!("could not read generated artifact {relative}: {error}"))?;
        aggregate.update(relative.as_bytes());
        aggregate.update([0]);
        aggregate.update(&bytes);
        aggregate.update([0xff]);
    }
    Ok(hex::encode(aggregate.finalize()))
}

/// A cheaper committed-artifact validation must never erase stronger evidence
/// from an immediately preceding byte-identical reproduction. Preservation is
/// allowed only when every other field (especially source digest and config)
/// is identical; stale strong evidence is downgraded rather than carried over.
fn write_evidence_monotonic(
    path: &Path,
    candidate: &Value,
    reproduced: bool,
) -> Result<(), String> {
    if !reproduced && path.is_file() {
        let existing: Value = serde_json::from_slice(
            &fs::read(path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?,
        )
        .map_err(|error| format!("invalid existing evidence {}: {error}", path.display()))?;
        let mut normalized = existing.clone();
        if existing["clean_reproduction"] == "byte-identical" {
            normalized["clean_reproduction"] = candidate["clean_reproduction"].clone();
            if normalized == *candidate {
                return Ok(());
            }
        }
    }
    write_pretty_json(path, candidate)
}

fn write_pretty_json(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("could not encode {}: {error}", path.display()))?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|error| format!("could not write {}: {error}", path.display()))
}

fn run_checked<S: AsRef<std::ffi::OsStr>>(
    program: S,
    arguments: &[String],
    directory: &Path,
    environment: &[(&str, &str)],
) -> Result<(), String> {
    let output = command_output(program, arguments, directory, environment)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format_command_failure(arguments, directory, &output))
    }
}

fn run_output<S: AsRef<std::ffi::OsStr>>(
    program: S,
    arguments: &[&str],
    directory: &Path,
    environment: &[(&str, &str)],
) -> Result<String, String> {
    let owned: Vec<_> = arguments.iter().map(|value| (*value).to_owned()).collect();
    let output = command_output(program, &owned, directory, environment)?;
    if !output.status.success() {
        return Err(format_command_failure(&owned, directory, &output));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("tool emitted non-UTF-8 output: {error}"))
}

fn command_output<S: AsRef<std::ffi::OsStr>>(
    program: S,
    arguments: &[String],
    directory: &Path,
    environment: &[(&str, &str)],
) -> Result<Output, String> {
    let program_text = program.as_ref().to_string_lossy().into_owned();
    let mut command = Command::new(&program);
    command
        .args(arguments)
        .current_dir(directory)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTDOCFLAGS")
        .env_remove("CARGO_BUILD_TARGET");
    for (variable, _) in env::vars_os() {
        if is_semantic_build_variable(&variable.to_string_lossy()) {
            command.env_remove(variable);
        }
    }
    for (name, value) in environment {
        command.env(name, value);
    }
    command.output().map_err(|error| {
        format!(
            "could not run `{program_text} {}` in {}: {error}",
            arguments.join(" "),
            directory.display()
        )
    })
}

fn format_command_failure(arguments: &[String], directory: &Path, output: &Output) -> String {
    format!(
        "command failed in {}: {}\nstdout:\n{}\nstderr:\n{}",
        directory.display(),
        arguments.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn render_codec_types_external() -> String {
    r##"import Aeneas
open Aeneas Aeneas.Std
def core.str.error.Utf8Error : Type := Unit
"##
    .to_owned()
}

fn render_codec_functions_external() -> String {
    r##"-- REVIEWED TRANSPARENT STANDARD-LIBRARY MODELS; NO AUTHS ALGORITHM IS OPAQUE.
import qualification.aeneas.generated.codec.Types
import qualification.aeneas.generated.standard.CheckedResult
import qualification.aeneas.generated.model.FunsExternal
open Aeneas Aeneas.Std Result
set_option linter.unusedVariables false

-- UTF-8 error payload is unobserved; all failures map to Malformed.
def Auths.Codec.StdModel.bytes (bytes : Str) : ByteArray :=
  (bytes.val.map (fun byte => UInt8.ofNat byte.val)).toByteArray

def Usize.Insts.CoreConvertTryFromU64TryFromIntError.try_from (value : Std.U64) :=
  core.num.tryFromUScalar .Usize value

def U8.Insts.CoreConvertTryFromU64TryFromIntError.try_from (value : Std.U64) :=
  core.num.tryFromUScalar .U8 value

def U16.Insts.CoreConvertTryFromU64TryFromIntError.try_from (value : Std.U64) :=
  core.num.tryFromUScalar .U16 value

def U16.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from (value : Std.Usize) :=
  core.num.tryFromUScalar .U16 value

def core.option.Option.Some {T : Type} (value : T) : Result (Option T) := ok (some value)
def core.option.Option.as_ref {T : Type} (value : Option T) : Result (Option T) := ok value

def core.option.Option.ok_or {T E : Type} (value : Option T) (error : E) :
    Result (core.result.Result T E) :=
  ok (match value with | some x => .Ok x | none => .Err error)

def core.option.Option.Insts.CoreCmpPartialEqOption.eq {T : Type}
    (eqInst : core.cmp.PartialEq T T) (left right : Option T) : Result Bool :=
  match left, right with
  | none, none => ok true
  | some left, some right => eqInst.eq left right
  | _, _ => ok false

def core.result.Result.map {T E U F : Type}
    (function : core.ops.function.FnOnce F T U)
    (value : core.result.Result T E) (callback : F) : Result (core.result.Result U E) := do
  match value with
  | .Ok value =>
    let output ← function.call_once callback value
    ok (.Ok output)
  | .Err error => ok (.Err error)

def core.result.Result.map_err {T E F O : Type}
    (function : core.ops.function.FnOnce O E F)
    (value : core.result.Result T E) (callback : O) : Result (core.result.Result T F) := do
  match value with
  | .Ok value => ok (.Ok value)
  | .Err error =>
    let output ← function.call_once callback error
    ok (.Err output)

def core.str.converts.from_utf8 (bytes : Slice Std.U8) :
    Result (core.result.Result Str core.str.error.Utf8Error) :=
  ok (if (Auths.Codec.StdModel.bytes bytes).IsValidUTF8 then .Ok bytes else .Err ())

def alloc.string.String.Insts.CoreOpsDerefDerefStr.deref (value : String) : Result Str :=
  if bounded : value.toByteArray.size ≤ U32.max then ok (toStr value bounded) else fail .panic

def alloc.string.String.Insts.CoreConvertFromShared0Str.from (value : Str) : Result String :=
  match String.fromUTF8? (Auths.Codec.StdModel.bytes value) with
  | some value => ok value
  | none => fail .panic

def alloc.vec.Vec.as_slice {T : Type} (A : Type) (value : alloc.vec.Vec T) : Result (Slice T) :=
  ok (alloc.vec.Vec.deref value)

def alloc.vec.Vec.is_empty {T : Type} (A : Type) (value : alloc.vec.Vec T) : Result Bool :=
  ok value.val.isEmpty

-- The action call uses a stateless Unit closure for the digest key; the
-- scope constructor reuses this model with a stateless identity key.
-- This sorting model is sound only after proving purity and total-order laws
-- for that concrete callback; it is not an arbitrary FnMut Rust algorithm model.
private def insertKey {T K F : Type} (key : core.ops.function.FnMut F T K)
    (order : core.cmp.Ord K) (callback : F) (item : T) :
    (items : List T) → Result {output : List T // output.length = items.length + 1}
  | [] => ok ⟨[item], rfl⟩
  | first :: rest => do
    let (left, _) ← key.call_mut callback item
    let (right, _) ← key.call_mut callback first
    let comparison ← order.cmp left right
    if comparison = .gt then
      let inserted ← insertKey key order callback item rest
      ok ⟨first :: inserted.val, by simp [inserted.property]⟩
    else ok ⟨item :: first :: rest, rfl⟩

private def sortKey {T K F : Type} (key : core.ops.function.FnMut F T K)
    (order : core.cmp.Ord K) (callback : F) :
    (items : List T) → Result {output : List T // output.length = items.length}
  | [] => ok ⟨[], rfl⟩
  | first :: rest => do
    let sorted ← sortKey key order callback rest
    let inserted ← insertKey key order callback first sorted.val
    ok ⟨inserted.val, by simp [inserted.property, sorted.property]⟩

def alloc.slice.Slice.sort_by_key {T K F : Type}
    (key : core.ops.function.FnMut F T K) (order : core.cmp.Ord K)
    (input : Slice T) (callback : F) : Result (Slice T) := do
  let output ← sortKey key order callback input.val
  ok ⟨output.val, by rw [output.property]; exact input.property⟩

-- A fallible pointer-sized signed conversion, exactly as Rust TryFrom specifies.
def Isize.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from (value : Std.Usize) :
    Result (core.result.Result Std.Isize core.num.error.TryFromIntError) :=
  ok (match IScalar.tryMkOpt .Isize value.val with
    | some signed => .Ok signed
    | none => .Err ())

def core.option.Option.and_then {T U F : Type}
    (callback : core.ops.function.FnOnce F T (Option U)) (value : Option T) (function : F) :
    Result (Option U) :=
  match value with
  | none => ok none
  | some value => callback.call_once function value

-- Public equations expose the existing reviewed key-sort model without
-- duplicating or changing its algorithm. Downstream ordinary sorting uses
-- only the stateless identity key and earns its comparison laws separately.
namespace Auths.Codec.StdModel

def insertKeyValues {T K F : Type} (key : core.ops.function.FnMut F T K)
    (order : core.cmp.Ord K) (callback : F) (item : T) (items : List T) :=
  insertKey key order callback item items

theorem insertKeyValues_nil {T K F : Type} (key : core.ops.function.FnMut F T K)
    (order : core.cmp.Ord K) (callback : F) (item : T) :
    insertKeyValues key order callback item [] = ok ⟨[item], rfl⟩ := rfl

theorem insertKeyValues_cons {T K F : Type} (key : core.ops.function.FnMut F T K)
    (order : core.cmp.Ord K) (callback : F) (item first : T) (rest : List T) :
    insertKeyValues key order callback item (first :: rest) =
      (do let (left, _) ← key.call_mut callback item
          let (right, _) ← key.call_mut callback first
          let comparison ← order.cmp left right
          if comparison = .gt then
            let inserted ← insertKeyValues key order callback item rest
            ok ⟨first :: inserted.val, by simp [inserted.property]⟩
          else ok ⟨item :: first :: rest, rfl⟩) := rfl

def sortKeyValues {T K F : Type} (key : core.ops.function.FnMut F T K)
    (order : core.cmp.Ord K) (callback : F) (items : List T) :=
  sortKey key order callback items

theorem sortKeyValues_nil {T K F : Type} (key : core.ops.function.FnMut F T K)
    (order : core.cmp.Ord K) (callback : F) :
    sortKeyValues key order callback [] = ok ⟨[], rfl⟩ := rfl

theorem sortKeyValues_cons {T K F : Type} (key : core.ops.function.FnMut F T K)
    (order : core.cmp.Ord K) (callback : F) (first : T) (rest : List T) :
    sortKeyValues key order callback (first :: rest) =
      (do let sorted ← sortKeyValues key order callback rest
          let inserted ← insertKeyValues key order callback first sorted.val
          ok ⟨inserted.val, by simp [inserted.property, sorted.property]⟩) := rfl

theorem sort_by_key_values {T K F : Type} (key : core.ops.function.FnMut F T K)
    (order : core.cmp.Ord K) (input : Slice T) (callback : F) :
    _root_.alloc.slice.Slice.sort_by_key key order input callback =
      (do let output ← sortKeyValues key order callback input.val
          ok ⟨output.val, by rw [output.property]; exact input.property⟩) := rfl

end Auths.Codec.StdModel
"##
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CI_GATES: &str = r#"uses: ./.github/actions/setup-lean
kani-verifier --version 0.67.0
cargo xtask ci preflight
cargo xtask ci authoritative
target/formal/
  authoritative-run:
needs: [ci-plan, formal-update-gate, repository-preflight]
needs.repository-preflight.result == 'success'
  formal-proof-fast:
needs: [ci-plan, formal-update-gate]
cargo xtask ci formal-proof-fast
  formal-translation-run:
needs: [ci-plan, formal-update-gate, repository-preflight]
needs.repository-preflight.result == 'success'
compiler-cache: "false"
      - id: protected-base-translation
        name: Locate protected-base translation evidence
        if: needs.ci-plan.outputs.formal_cold_required != 'true'
        run: echo 'found=false' >> "$GITHUB_OUTPUT"
      - name: Verify and bind protected-base translation evidence
        if: steps.protected-base-translation.outputs.found == 'true'
        run: cargo xtask ci formal-translation-reuse
      - name: Reproduce translation twice
        if: steps.prior-pr-translation.outputs.reused != 'true' && steps.protected-base-translation.outputs.found != 'true'
        env:
          AUTHS_FORMAL_UPDATE_MODE: ${{ github.event_name == 'pull_request' && 'true' || 'false' }}
        run: cargo xtask ci formal-translation-reproduce
      - id: formal-update
        name: Package a bounded translation update
        if: github.event_name == 'pull_request' && steps.prior-pr-translation.outputs.reused != 'true' && steps.protected-base-translation.outputs.found != 'true'
        run: cargo run --locked -p auths-ci-plan -- formal-update-artifact create
      - name: Preserve the bounded translation update
      - name: Stop qualification until generated translation is committed
  formal-kani-run:
needs: [ci-plan, formal-update-gate, repository-preflight]
needs.repository-preflight.result == 'success'
cargo xtask ci formal-kani
  formal-lean-authoritative-run:
    outputs:
      update_required: ${{ steps.formal-update.outputs.update_required || 'false' }}
needs: [ci-plan, formal-update-gate, repository-preflight, formal-proof-fast, formal-translation-run]
needs.formal-proof-fast.result == 'success'
needs.formal-translation-run.result == 'success'
cargo xtask ci formal-lean-authoritative
      - id: formal-update
      - name: Stop qualification until the assurance update is committed
        if: steps.formal-update.outputs.update_required == 'true'
        run: exit 1
  formal-evidence-run:
needs.formal-translation-run.result == 'success'
needs.formal-lean-authoritative-run.result == 'success'
needs.formal-lean-authoritative-run.outputs.update_required != 'true'
needs.formal-kani-run.result == 'success'
AUTHS_FORMAL_TRANSLATION_SOURCE_ATTEMPT
AUTHS_FORMAL_LEAN_SOURCE_ATTEMPT
AUTHS_FORMAL_KANI_SOURCE_ATTEMPT
cargo xtask ci formal-evidence
  compliance-run:
needs: [ci-plan, formal-update-gate, repository-preflight]
needs.repository-preflight.result == 'success'
cargo xtask ci compliance
if: always() && hashFiles('target/compliance/**') != ''
  dependencies-run:
needs: [ci-plan, formal-update-gate, repository-preflight]
needs.repository-preflight.result == 'success'
  secrets-run:
needs: [ci-plan, formal-update-gate, repository-preflight]
needs.repository-preflight.result == 'success'
  opentofu-live-run:
needs: [ci-plan, formal-update-gate, repository-preflight]
needs.repository-preflight.result == 'success'
  postgresql-live-run:
needs: [ci-plan, formal-update-gate, repository-preflight]
needs.repository-preflight.result == 'success'
  records-api-live-run:
needs: [ci-plan, formal-update-gate, repository-preflight]
needs.repository-preflight.result == 'success'
  formal-translation:
needs: [ci-plan, formal-evidence-run]
  formal-kani:
needs: [ci-plan, formal-kani-run]
needs.ci-plan.outputs.formal_kani_required
needs.formal-kani-run.result
  ci-qualified:
      - formal-translation
      - formal-kani
needs.formal-kani.result
[[ "$FORMAL_KANI" == success ]]
"#;
    const BUILDER_GATES: &str = "leanprover/lean-action@\nkani-verifier --version 0.67.0\ncargo xtask release-check\ncargo xtask formal qualify aeneas\n";

    #[test]
    fn translation_reuse_defers_lake_package_audit_to_authoritative_lean() {
        let source = include_str!("formal_qualification.rs");
        let reuse = source
            .split_once("pub(crate) fn validate_reusable_translation(")
            .expect("reuse validator exists")
            .1
            .split_once("\n}\n")
            .expect("reuse validator body ends")
            .0;
        let authoritative = source
            .split_once("pub(crate) fn validate(")
            .expect("authoritative validator exists")
            .1
            .split_once("\n}\n")
            .expect("authoritative validator body ends")
            .0;
        assert!(!reuse.contains("validate_warning_inventory(root"));
        assert!(authoritative.contains("validate_warning_inventory(root"));
    }

    #[test]
    fn hosted_ci_uses_the_pinned_lean_setup() {
        validate_ci_workflow_gates(CI_GATES).expect("hosted CI gates must satisfy formal policy");
    }

    #[test]
    fn committed_hosted_ci_satisfies_formal_policy() {
        validate_ci_workflow_gates(include_str!("../../.github/workflows/ci.yml"))
            .expect("the committed hosted CI workflow must satisfy formal policy");
    }

    #[test]
    fn missing_protected_base_evidence_executes_two_clean_reproductions() {
        let base_run_required = CI_GATES.replace(
            "name: Reproduce translation twice\n        if: steps.prior-pr-translation.outputs.reused != 'true' && steps.protected-base-translation.outputs.found != 'true'\n",
            "name: Reproduce translation twice\n        if: needs.ci-plan.outputs.formal_cold_required == 'true' && steps.prior-pr-translation.outputs.reused != 'true'\n",
        );
        let error = validate_ci_workflow_gates(&base_run_required).expect_err(
            "a base commit without successful CI must not fail every pull request on it",
        );
        assert!(error.contains("otherwise execute two clean reproductions"));
    }

    #[test]
    fn every_update_mode_reproduction_packages_its_drift() {
        let unpackaged = CI_GATES.replace(
            "if: github.event_name == 'pull_request' && steps.prior-pr-translation.outputs.reused != 'true' && steps.protected-base-translation.outputs.found != 'true'\n",
            "if: github.event_name == 'pull_request' && needs.ci-plan.outputs.formal_cold_required == 'true' && steps.prior-pr-translation.outputs.reused != 'true'\n",
        );
        let error = validate_ci_workflow_gates(&unpackaged).expect_err(
            "a fallback reproduction that rewrote drifted outputs must still stop the job",
        );
        assert!(error.contains("that package generated drift"));
    }

    #[test]
    fn protected_base_reuse_requires_located_evidence() {
        let unlocated = CI_GATES.replace(
            "if: steps.protected-base-translation.outputs.found == 'true'\n",
            "if: needs.ci-plan.outputs.formal_cold_required != 'true'\n",
        );
        let error = validate_ci_workflow_gates(&unlocated)
            .expect_err("binding must not run when no evidence was located");
        assert!(error.contains("only once located and bound"));
    }

    #[test]
    fn hosted_ci_cannot_omit_pinned_lean_setup() {
        let error = validate_ci_workflow_gates(
            &CI_GATES.replace("uses: ./.github/actions/setup-lean\n", ""),
        )
        .expect_err("missing pinned Lean setup must fail");
        assert!(error.contains("hosted CI omits required formal gate"));
    }

    #[test]
    fn every_expensive_ci_job_waits_for_repository_preflight() {
        let bypass = CI_GATES.replacen(
            "needs: [ci-plan, formal-update-gate, repository-preflight]",
            "needs: [ci-plan, formal-update-gate]",
            1,
        );
        let error = validate_ci_workflow_gates(&bypass)
            .expect_err("an implementation job must not bypass the shared preflight");
        assert!(error.contains("can start before the repository preflight succeeds"));
    }

    #[test]
    fn ci_qualified_requires_the_kani_gate() {
        let bypass = CI_GATES.replace("      - formal-kani\n", "");
        let error = validate_ci_workflow_gates(&bypass)
            .expect_err("a Kani failure must not reach a qualified result");
        assert!(error.contains("CI qualified does not require the formal-kani gate"));
    }

    #[test]
    fn kani_gate_enforces_the_planned_kani_result() {
        let bypass = CI_GATES.replace(
            "needs: [ci-plan, formal-kani-run]",
            "needs: [ci-plan, formal-evidence-run]",
        );
        let error = validate_ci_workflow_gates(&bypass)
            .expect_err("the Kani gate must consume the Kani job itself");
        assert!(error.contains("formal-kani gate does not enforce the planned Kani result"));
    }

    #[test]
    fn authoritative_lean_still_requires_the_fast_proof() {
        let bypass = CI_GATES.replace("needs.formal-proof-fast.result == 'success'\n", "");
        let error = validate_ci_workflow_gates(&bypass)
            .expect_err("qualification must not proceed past a failed fast proof");
        assert!(error.contains("without qualified translation and fast proof"));
    }

    #[test]
    fn formal_evidence_guard_reads_a_declared_lean_output() {
        let undeclared = CI_GATES.replace(
            "    outputs:\n      update_required: ${{ steps.formal-update.outputs.update_required || 'false' }}\n",
            "",
        );
        let error = validate_ci_workflow_gates(&undeclared)
            .expect_err("an undeclared output leaves the evidence guard always true");
        assert!(error.contains("does not declare the `update_required` output"));
    }

    #[test]
    fn lean_update_output_reads_a_step_of_the_lean_job() {
        let dangling = CI_GATES.replace("      - id: formal-update\n", "");
        let error = validate_ci_workflow_gates(&dangling)
            .expect_err("an output bound to no step always takes its default");
        assert!(error.contains("does not declare the `update_required` output"));
    }

    #[test]
    fn authoritative_lean_fails_on_a_pending_assurance_update() {
        let green = CI_GATES.replace(
            "      - name: Stop qualification until the assurance update is committed\n",
            "",
        );
        let error = validate_ci_workflow_gates(&green)
            .expect_err("a pending assurance update must fail the job that packaged it");
        assert!(error.contains("must fail while its bounded assurance update is uncommitted"));
    }

    #[test]
    fn compliance_upload_does_not_mask_the_primary_failure() {
        let masking = CI_GATES.replace(
            "if: always() && hashFiles('target/compliance/**') != ''",
            "if: always()",
        );
        let error = validate_ci_workflow_gates(&masking)
            .expect_err("missing compliance evidence must not create a second failure");
        assert!(error.contains("without masking the primary failure"));
    }

    #[test]
    fn reusable_release_builder_owns_formal_gates() {
        validate_release_workflow_gates(
            "uses: ./.github/workflows/release-builder.yml\n",
            BUILDER_GATES,
        )
        .expect("reusable builder gates must satisfy release policy");
    }

    #[test]
    fn orchestration_must_call_the_reviewed_builder() {
        let error = validate_release_workflow_gates("workflow_dispatch:\n", BUILDER_GATES)
            .expect_err("missing reusable builder call must fail");
        assert!(error.contains("release orchestration omits required formal gate"));
    }

    #[test]
    fn reusable_builder_cannot_omit_formal_gate() {
        let error = validate_release_workflow_gates(
            "uses: ./.github/workflows/release-builder.yml\n",
            "cargo xtask release-check\n",
        )
        .expect_err("incomplete reusable builder must fail");
        assert!(error.contains("reusable release builder omits required formal gate"));
    }

    #[test]
    fn sorry_scanner_ignores_literals_and_comments_but_not_code_or_quotations() {
        let source = r#"
def x' : True := by sorry
-- sorry
/- admit -/
def text := "sorry"
def quoted ← `(tactic| sorry)
def oldQuoted := '(term| by sorry)
def character := 's'
"#;
        assert_eq!(lean_sorry_lines(source), vec![2, 6, 7]);
    }

    #[test]
    fn sorry_scanner_handles_nested_comments() {
        let source = "/- outer\n/- sorry -/\n-/\nexample : True := by admit\n";
        assert_eq!(lean_sorry_lines(source), vec![4]);
    }

    #[test]
    fn qualification_evidence_is_fail_monotonic_but_never_preserves_stale_digest() {
        let path = env::temp_dir().join(format!(
            "auths-qualification-evidence-{}.json",
            std::process::id()
        ));
        let strong = json!({
            "source_closure_sha256": "current",
            "generated_artifacts_sha256": "generated-current",
            "clean_reproduction": "byte-identical",
        });
        let weak = json!({
            "source_closure_sha256": "current",
            "generated_artifacts_sha256": "generated-current",
            "clean_reproduction": "not-run-committed-artifacts-validated",
        });
        write_evidence_monotonic(&path, &strong, true).expect("strong evidence");
        write_evidence_monotonic(&path, &weak, false).expect("later validation");
        let retained: Value = serde_json::from_slice(&fs::read(&path).expect("retained evidence"))
            .expect("valid retained evidence");
        assert_eq!(retained["clean_reproduction"], "byte-identical");

        let stale = json!({
            "source_closure_sha256": "current",
            "generated_artifacts_sha256": "generated-changed",
            "clean_reproduction": "not-run-committed-artifacts-validated",
        });
        write_evidence_monotonic(&path, &stale, false).expect("stale downgrade");
        let downgraded: Value =
            serde_json::from_slice(&fs::read(&path).expect("downgraded evidence"))
                .expect("valid downgraded evidence");
        assert_eq!(
            downgraded["clean_reproduction"],
            "not-run-committed-artifacts-validated"
        );
        assert_eq!(downgraded["source_closure_sha256"], "current");
        assert_eq!(
            downgraded["generated_artifacts_sha256"],
            "generated-changed"
        );
        fs::remove_file(path).expect("remove owned evidence fixture");
    }

    #[test]
    fn axiom_inventory_covers_split_names_and_compiled_bridge_refusal() {
        for source in [
            "axiom imported : Type",
            "axiom\n  imported : Type",
            "  axiom\timported : Type",
        ] {
            assert_eq!(
                source
                    .lines()
                    .filter(|line| is_lean_axiom_declaration(line))
                    .count(),
                1
            );
        }
        for line in [
            "-- axiom imported : Type",
            "def axiomName := true",
            "axiomatic_identifier",
        ] {
            assert!(!is_lean_axiom_declaration(line));
        }
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root");
        let mut qualification = load_qualification(repository).expect("current inventory");
        let directory = tempfile::tempdir().expect("owned gate fixture");
        qualification.generated_files = vec!["FunsExternal.lean".to_owned()];
        qualification.template_axioms.clear();
        fs::write(
            directory.path().join("FunsExternal.lean"),
            "axiom\n  unchecked : Type\n",
        )
        .expect("split declaration fixture");
        let error = validate_generated_inventory(directory.path(), &qualification)
            .expect_err("a split-name axiom must also be refused in compiled bridges");
        assert!(error.contains("forbidden `axiom`"));

        qualification.generated_files = vec!["FunsExternal_Template.lean".to_owned()];
        qualification.template_axioms.push(TemplateAxiomInventory {
            artifact: "FunsExternal_Template.lean".to_owned(),
            count: 1,
            compiled: false,
        });
        fs::write(
            directory.path().join("FunsExternal_Template.lean"),
            "axiom\n  imported : Type\n",
        )
        .expect("uncompiled template fixture");
        validate_generated_inventory(directory.path(), &qualification)
            .expect("exact template count");
        qualification.template_axioms[0].count = 0;
        assert!(validate_generated_inventory(directory.path(), &qualification).is_err());
    }

    #[test]
    fn generated_artifact_inventory_rejects_omission_and_substitution() {
        let exact = GENERATED_ARTIFACTS
            .iter()
            .map(|path| (*path).to_owned())
            .collect::<Vec<_>>();
        validate_generated_artifact_inventory(&exact).expect("canonical inventory");

        let mut omitted = exact.clone();
        omitted.pop();
        assert!(validate_generated_artifact_inventory(&omitted).is_err());

        let mut substituted = exact;
        substituted[0] = "formal/qualification/aeneas/generated/forged.lean".to_owned();
        assert!(validate_generated_artifact_inventory(&substituted).is_err());
    }

    #[test]
    fn semantic_rust_environment_and_host_cargo_config_fail_closed() {
        for variable in [
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTC_BOOTSTRAP",
            "CARGO_PROFILE_DEV_OPT_LEVEL",
            "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS",
        ] {
            assert!(is_semantic_build_variable(variable));
        }
        assert!(!is_semantic_build_variable("CARGO_TARGET_DIR"));

        validate_ambient_cargo_config_source(
            "[alias]\nxtask = 'run -p xtask --'\n[target.aarch64-apple-ios]\nlinker = 'clang'\n",
            "aarch64-apple-darwin",
        )
        .expect("alias and foreign target are non-semantic for host extraction");
        assert!(
            validate_ambient_cargo_config_source(
                "[target.aarch64-apple-darwin]\nrustflags = ['--cfg', 'forged']\n",
                "aarch64-apple-darwin",
            )
            .is_err()
        );
        assert!(
            validate_ambient_cargo_config_source(
                "[target.'cfg(unix)']\nrustflags = ['--cfg', 'forged']\n",
                "aarch64-apple-darwin",
            )
            .is_err()
        );
        assert!(
            validate_ambient_cargo_config_source(
                "[build]\nrustflags = ['--cfg', 'forged']\n",
                "aarch64-apple-darwin",
            )
            .is_err()
        );
    }

    #[test]
    fn every_mapped_translation_report_uses_the_full_pinned_commit() {
        let directory = tempfile::tempdir().expect("owned translation fixture");
        let commit = "3a8586facab25b31bdb1e1f5f45acd60d1cc5ff0";
        let reports = AENEAS_OUTPUT_MAPPINGS
            .iter()
            .filter(|(source, _)| source.ends_with("translation.json"))
            .map(|(source, _)| directory.path().join(source))
            .collect::<Vec<_>>();
        assert_eq!(reports.len(), EXPECTED_TRANSLATIONS.len());
        for (index, path) in reports.iter().enumerate() {
            fs::create_dir_all(path.parent().expect("report parent")).expect("fixture directory");
            let abbreviation = &commit[..if index % 2 == 0 { 7 } else { 8 }];
            write_pretty_json(
                path,
                &json!({"aeneas_version": abbreviation, "sentinel": 17}),
            )
            .expect("fixture report");
        }
        canonicalize_aeneas_versions(directory.path(), commit).expect("all report identities");
        for path in &reports {
            let report: Value = serde_json::from_slice(&fs::read(path).expect("report bytes"))
                .expect("report JSON");
            assert_eq!(report["aeneas_version"], commit);
            assert_eq!(report["sentinel"], 17);
        }
        write_pretty_json(&reports[0], &json!({"aeneas_version": "0000000"}))
            .expect("wrong identity");
        assert!(canonicalize_aeneas_versions(directory.path(), commit).is_err());
    }

    #[test]
    fn reviewed_translation_boundary_contract_is_exact() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask has repository parent");
        let qualification = load_qualification(repository).expect("qualification manifest");
        assert_eq!(
            qualification_boundary_contract_sha256(&qualification),
            QUALIFICATION_BOUNDARY_CONTRACT_SHA256
        );
    }
}

#[cfg(test)]
mod unit_observer_dictionary_tests {
    use super::normalize_unit_observer_dictionary;

    #[test]
    fn unit_adapter_is_single_site_and_preserves_the_callback_body() {
        let callback =
            "def native_callback (state : Unit) (_event : Unit) : Result Unit := ok state\n";
        let field = "  call_mut :=\n    evaluate.closure.Insts.CoreOpsFunctionFnMutTupleEvaluationEventTuple.call_mut\n    coreopsfunctionFnMutT0TupleProofRefBranchOutcomeInst\n}";
        let source = format!("import Aeneas\n{callback}{field}");
        let adapted = normalize_unit_observer_dictionary(&source).expect("reviewed dictionary");
        assert!(adapted.contains(callback));
        assert_eq!(
            adapted
                .matches("Auths.Support.UnitCallback.restore")
                .count(),
            1
        );
        assert!(normalize_unit_observer_dictionary(callback).is_err());
        assert!(normalize_unit_observer_dictionary(&format!("{source}\n{field}")).is_err());
        assert!(normalize_unit_observer_dictionary(&adapted).is_err());
    }
}

#[cfg(test)]
mod signature_primitive_context_tests {
    use super::signature_primitive_context;

    #[test]
    fn explicit_primitive_parameter_preserves_every_generated_body() {
        let marker = "noncomputable section\n";
        let parameter = "\nvariable [primitives : Auths.Crypto.Ed25519Primitives]\n";
        let body = "namespace auths_signature_core\ndef wrapper (bytes : Slice Std.U8) := do\n  let key ← foreign_decode bytes\n  concrete_guard_and_verify key bytes\nend auths_signature_core\n";
        let source = format!("import Aeneas\n{marker}{body}");
        let generalized = signature_primitive_context(&source).expect("one explicit interface");
        assert_eq!(generalized.replace(parameter, ""), source);
        assert!(signature_primitive_context(&generalized).is_err());
        assert!(signature_primitive_context(body).is_err());
        assert!(signature_primitive_context(&format!("{source}{marker}")).is_err());
        assert!(signature_primitive_context(&format!("{source}{body}")).is_err());
    }
}

#[cfg(test)]
mod sha256_foreign_name_tests {
    use super::{sha256_foreign_names, sha256_primitive_context};
    use serde_json::{Value, json};

    fn declaration(id: u64, root: &str, local: bool) -> Value {
        json!({
            "def_id": id,
            "item_meta": {"name": [
                {"Ident": [root, 0]}, {"Ident": [format!("item_{id}"), 0]},
                {"Instantiated": {"closed": true}},
            ], "is_local": local, "span": {"file": "source.rs", "line": id}},
            "body": {"calls": [1, 2], "guard": "retained"},
            "signature": {"inputs": ["bytes"], "output": "fixed32"},
            "generics": [], "layout": {"size": 32},
        })
    }

    fn fixture() -> Value {
        let mut types = vec![Value::Null; 15];
        for id in [1_u64, 2, 3, 4, 5, 6, 7, 11, 12] {
            let root = if id == 1 {
                "generic_array"
            } else if id <= 7 {
                "typenum"
            } else {
                "digest"
            };
            types[usize::try_from(id).expect("small fixture id")] = declaration(id, root, false);
        }
        let mut local = declaration(0, "auths_codec", true);
        local["item_meta"]["name"] =
            json!([{"Ident": ["auths_codec", 0]}, {"Ident": ["raw_sha256", 0]}]);
        json!({"translated": {
            "type_decls": types,
            "fun_decls": [local, declaration(1, "digest", false), declaration(2, "core", false)],
            "global_decls": [], "trait_decls": [], "trait_impls": [],
            "item_names": [], "assoc_item_names": [], "short_names": [],
            "target_information": {"pointer_bytes": 8},
        }})
    }

    #[test]
    fn foreign_aliases_preserve_bodies_types_layouts_and_auths_identity() {
        let original = fixture();
        let (renamed, ledger) =
            sha256_foreign_names(original.clone()).expect("reviewed name inventory");
        assert_eq!(ledger["declarations"].as_array().expect("ledger").len(), 11);
        assert_eq!(
            original["translated"]["fun_decls"][0],
            renamed["translated"]["fun_decls"][0]
        );
        for (old, new) in original["translated"]["fun_decls"]
            .as_array()
            .expect("functions")
            .iter()
            .zip(
                renamed["translated"]["fun_decls"]
                    .as_array()
                    .expect("functions"),
            )
        {
            for field in ["body", "signature", "generics", "layout", "def_id"] {
                assert_eq!(old[field], new[field]);
            }
        }
        assert!(sha256_foreign_names(renamed).is_err());
    }

    #[test]
    fn names_in_executable_data_or_unreviewed_declarations_are_refused() {
        let mut body_name = fixture();
        body_name["translated"]["fun_decls"][0]["body"] =
            body_name["translated"]["type_decls"][1]["item_meta"]["name"].clone();
        assert!(sha256_foreign_names(body_name).is_err());
        let mut auths = fixture();
        auths["translated"]["type_decls"][1]["item_meta"]["name"][0] =
            json!({"Ident": ["auths_model", 0]});
        assert!(sha256_foreign_names(auths).is_err());
        let mut missing = fixture();
        missing["translated"]["type_decls"][1] = Value::Null;
        assert!(sha256_foreign_names(missing).is_err());
        let mut extra = fixture();
        extra["translated"]["global_decls"] = json!([declaration(99, "sha2", false)]);
        assert!(sha256_foreign_names(extra).is_err());
    }

    #[test]
    fn explicit_hash_parameter_changes_no_generated_body() {
        let source = "noncomputable section\nnamespace AuthsNativeSha256\ndef wrapper := selected_digest\nend AuthsNativeSha256\n";
        let parameter = "\nvariable [primitive : Auths.Crypto.Sha256Primitives]\n";
        let generalized = sha256_primitive_context(source).expect("one interface");
        assert_eq!(generalized.replace(parameter, ""), source);
        assert!(sha256_primitive_context(&generalized).is_err());
        assert!(sha256_primitive_context(&format!("{source}{source}")).is_err());
        assert!(sha256_primitive_context("def wrapper := selected_digest").is_err());
    }
}

#[cfg(test)]
mod p256_export_name_tests {
    use super::{p256_context, p256_export_names};
    use serde_json::{Value, json};

    fn row(id: u64, root: &str) -> Value {
        let local = root == "auths_signature_core";
        let base = if local {
            if id == 2 {
                "verify_p256_sha256_with".to_owned()
            } else {
                "decode_p256_key_with".to_owned()
            }
        } else {
            format!("foreign_{id}")
        };
        json!({"def_id": id, "item_meta": {
            "name": [{"Ident": [root, 0]}, {"Ident": [base, 0]}, {"Instantiated": {"closed": true}}],
            "is_local": local, "span": {"source": "exact.rs", "line": id}},
            "body": {"guard": "preserved", "call_ids": [3, 7]},
            "signature": {"input": "bytes", "output": "retained"},
            "generics": [], "layout": {"size": 64}})
    }

    fn fixture() -> Value {
        let mut types = vec![Value::Null; 18];
        for id in [0_u64, 3, 4, 6, 7, 9, 11, 12, 13, 14, 16, 17] {
            types[usize::try_from(id).expect("fixture id")] = row(
                id,
                if [4, 11].contains(&id) {
                    "ecdsa"
                } else {
                    "core"
                },
            );
        }
        let mut functions = vec![Value::Null; 34];
        for id in [
            2_u64, 4, 5, 6, 7, 13, 14, 15, 17, 18, 20, 22, 23, 24, 26, 27, 29, 30, 31, 32, 33,
        ] {
            let root = if [2, 4].contains(&id) {
                "auths_signature_core"
            } else if [14, 18, 23, 26, 29].contains(&id) {
                "ecdsa"
            } else {
                "core"
            };
            let mut function = row(id, root);
            if root != "auths_signature_core" {
                function["item_meta"]["name"][1] = json!({"Ident": [format!("function_{id}"), 0]});
            }
            functions[usize::try_from(id).expect("fixture id")] = function;
        }
        json!({"translated": {"type_decls": types, "fun_decls": functions,
            "global_decls": [], "trait_decls": [], "trait_impls": [],
            "item_names": [], "assoc_item_names": [], "short_names": [],
            "target_information": {"pointer_bytes": 8}}})
    }

    #[test]
    fn exact_export_adaptation_preserves_all_executable_fields() {
        let original = fixture();
        let (normalized, ledger) = p256_export_names(original.clone()).expect("closed inventory");
        assert_eq!(ledger["declarations"].as_array().expect("ledger").len(), 33);
        for group in ["type_decls", "fun_decls"] {
            for (old, new) in original["translated"][group]
                .as_array()
                .expect("rows")
                .iter()
                .zip(normalized["translated"][group].as_array().expect("rows"))
            {
                if old.is_null() {
                    assert!(new.is_null());
                    continue;
                }
                let mut expected = old.clone();
                expected["item_meta"]["name"] = new["item_meta"]["name"].clone();
                assert_eq!(expected, *new);
            }
        }
        for id in [2, 4] {
            assert_eq!(
                normalized["translated"]["fun_decls"][id]["item_meta"]["name"]
                    .as_array()
                    .expect("base name")
                    .len(),
                2
            );
        }
        assert!(p256_export_names(normalized).is_err());
    }

    #[test]
    fn unreviewed_auths_paths_missing_identities_and_body_names_fail_closed() {
        let mut auths = fixture();
        auths["translated"]["fun_decls"][2]["item_meta"]["name"][1] =
            json!({"Ident": ["another_algorithm", 0]});
        assert!(p256_export_names(auths).is_err());
        let mut local_foreign = fixture();
        local_foreign["translated"]["type_decls"][4]["item_meta"]["is_local"] = json!(true);
        assert!(p256_export_names(local_foreign).is_err());
        let mut missing = fixture();
        missing["translated"]["type_decls"][4] = Value::Null;
        assert!(p256_export_names(missing).is_err());
        let mut body = fixture();
        body["translated"]["fun_decls"][2]["body"] =
            body["translated"]["type_decls"][4]["item_meta"]["name"].clone();
        assert!(p256_export_names(body).is_err());
        let mut extra = fixture();
        extra["translated"]["global_decls"] = json!([row(99, "core")]);
        assert!(p256_export_names(extra).is_err());
    }

    #[test]
    fn primitive_context_preserves_every_generated_body_and_rejects_repetition() {
        let functions = "noncomputable section\nnamespace AuthsNativeP256\ndef source := actual_calls_and_guards\nend AuthsNativeP256\n";
        let parameter = "\nvariable [primitive : Auths.Crypto.P256Primitives]\n";
        let normalized = p256_context(functions, false).expect("function context");
        assert_eq!(normalized.replace(parameter, ""), functions);
        assert!(p256_context(&normalized, false).is_err());
        assert!(p256_context(&format!("{functions}{functions}"), false).is_err());
        assert!(p256_context("def source := alternate", false).is_err());
        let types = "import Aeneas\nnamespace AuthsNativeP256\n@[discriminant isize]\ninductive Closed where | one\nend AuthsNativeP256\n";
        let normalized = p256_context(types, true).expect("type context");
        assert_eq!(
            normalized
                .replace(parameter, "")
                .replace("import Auths.Support.Discriminant\n", "")
                .replace("qualified_discriminant", "discriminant"),
            types
        );
        assert!(p256_context(&normalized, true).is_err());
    }
}

#[cfg(test)]
mod qualified_delegation_tests {
    use super::{
        TranslationFunction, delegation_endpoints_match, delegation_statement_matches,
        expected_qualified_delegations, suite_adapter_context,
    };
    use serde_json::json;

    #[test]
    fn printed_owner_name_cannot_replace_the_actual_kernel_reference() {
        let link = expected_qualified_delegations().remove(0);
        let mut declaration = json!({"name": link.delegation_theorem, "kind": "theorem",
            "statement": format!("{} = {}", link.bridge_lean_declaration, link.owner_lean_declaration),
            "statement_constants": [link.bridge_lean_declaration], "axioms": ["propext"]});
        assert!(!delegation_statement_matches(&declaration, &link));
        declaration["statement_constants"] =
            json!([link.bridge_lean_declaration, link.owner_lean_declaration]);
        assert!(delegation_statement_matches(&declaration, &link));
        declaration["axioms"] = json!(["propext", "sorryAx"]);
        assert!(!delegation_statement_matches(&declaration, &link));
        declaration["axioms"] = json!([]);
        declaration["kind"] = json!("axiom");
        assert!(!delegation_statement_matches(&declaration, &link));
    }

    #[test]
    fn an_opaque_foreign_or_wrong_owner_cannot_close_the_import() {
        let link = expected_qualified_delegations().remove(0);
        let imported = TranslationFunction {
            rust_name: link.rust_symbol.clone(),
            lean_name: link.bridge_lean_declaration.clone(),
            is_local: false,
            is_opaque: true,
        };
        let mut owned = TranslationFunction {
            rust_name: link.rust_symbol.clone(),
            lean_name: link.owner_lean_declaration.clone(),
            is_local: true,
            is_opaque: false,
        };
        assert!(delegation_endpoints_match(&imported, &owned, &link));
        owned.is_opaque = true;
        assert!(!delegation_endpoints_match(&imported, &owned, &link));
        owned.is_opaque = false;
        owned.is_local = false;
        assert!(!delegation_endpoints_match(&imported, &owned, &link));
        owned.is_local = true;
        owned.rust_name = "auths_signature_core::another_verifier".to_owned();
        assert!(!delegation_endpoints_match(&imported, &owned, &link));
        owned.rust_name.clone_from(&link.rust_symbol);
        owned.lean_name = "Unqualified.always_accept".to_owned();
        assert!(!delegation_endpoints_match(&imported, &owned, &link));
    }

    #[test]
    fn context_does_not_change_any_generated_adapter_body() {
        let source = "noncomputable section\nnamespace AuthsSuiteAdapters\ndef adapter := actual_fields_and_callback\nend AuthsSuiteAdapters\n";
        let parameter = "\nvariable [edPrimitive : Auths.Crypto.Ed25519Primitives]\nvariable [p256Primitive : Auths.Crypto.P256Primitives]\n";
        let normalized = suite_adapter_context(source, false).expect("one context");
        assert_eq!(normalized.replace(parameter, ""), source);
        assert!(suite_adapter_context(&normalized, false).is_err());
        assert!(suite_adapter_context(&format!("{source}{source}"), false).is_err());
        assert!(suite_adapter_context("def unreviewed := alternate", false).is_err());
    }
}

fn render_scope_codec_types_external() -> String {
    r##"import qualification.aeneas.generated.codec.TypesExternal
"##
    .to_owned()
}

fn render_scope_codec_functions_external() -> String {
    r##"import qualification.aeneas.generated.scope_codec.Types
import qualification.aeneas.generated.codec.FunsExternal
open Aeneas Aeneas.Std Result
namespace AuthsScopeCodec
abbrev Usize.Insts.CoreConvertTryFromU64TryFromIntError.try_from := _root_.Usize.Insts.CoreConvertTryFromU64TryFromIntError.try_from
abbrev U8.Insts.CoreConvertTryFromU64TryFromIntError.try_from := _root_.U8.Insts.CoreConvertTryFromU64TryFromIntError.try_from
abbrev core.option.Option.Some := @_root_.core.option.Option.Some
abbrev core.option.Option.ok_or := @_root_.core.option.Option.ok_or
abbrev core.option.Option.Insts.CoreCmpPartialEqOption.eq := @_root_.core.option.Option.Insts.CoreCmpPartialEqOption.eq
abbrev core.result.Result.map := @_root_.core.result.Result.map
abbrev core.result.Result.map_err := @_root_.core.result.Result.map_err
abbrev core.str.converts.from_utf8 := _root_.core.str.converts.from_utf8
abbrev core.str.Str.len := _root_.core.str.Str.len
abbrev core.str.Str.is_empty := _root_.core.str.Str.is_empty
abbrev core.str.Str.as_bytes := _root_.core.str.Str.as_bytes
abbrev alloc.string.String.Insts.CoreCmpPartialEqString.eq := _root_.alloc.string.String.Insts.CoreCmpPartialEqString.eq
abbrev alloc.string.String.Insts.CoreCmpOrd.cmp := _root_.alloc.string.String.Insts.CoreCmpOrd.cmp
abbrev alloc.string.String.Insts.CoreConvertFromShared0Str.from := _root_.alloc.string.String.Insts.CoreConvertFromShared0Str.from
abbrev alloc.vec.Vec.is_empty := @_root_.alloc.vec.Vec.is_empty

def identityKey {T : Type} : core.ops.function.FnMut Unit T T := {
  FnOnceInst := { call_once := fun _ value => ok value }
  call_mut := fun _ value => ok (value, ())
}

/-- Ordinary sorting delegates to the previously reviewed stable key-sort
    model using a pure, stateless identity key. String comparison laws and
    totality are earned separately for the actual native Ord dictionary. -/
def alloc.slice.Slice.sort {T : Type} (order : core.cmp.Ord T) (values : Slice T) : Result (Slice T) :=
  _root_.alloc.slice.Slice.sort_by_key identityKey order values ()

def core.ops.range.RangeInclusive.contains {Idx U : Type}
    (_indexOrder : core.cmp.PartialOrd Idx Idx) (lowerOrder : core.cmp.PartialOrd Idx U)
    (upperOrder : core.cmp.PartialOrd U Idx) (range : core.ops.range.RangeInclusive Idx) (item : U) : Result Bool := do
  let lower ← lowerOrder.le range.start item
  if lower then upperOrder.le item range.end else ok false
abbrev core.result.Result.unwrap_or := @_root_.core.result.Result.unwrap_or
end AuthsScopeCodec
"##.to_owned()
}
