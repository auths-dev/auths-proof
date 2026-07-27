//! Deterministic adversarial mutations and boundary oracles.

mod context;
mod mutation;
mod oracle;
mod shrink;

pub use context::{assert_canonical_context, context_bit_mutations};
pub use mutation::{ByteMutation, EvidenceMutation, Mutation, MutationError, MutationId};
pub use oracle::{
    ConformanceFailure, ControlOracle, ControlProjection, MethodCase, assert_method_contract,
};
pub use shrink::{ByteFailure, shrink_bytes};
