//! The gateway's translated decision leaves.
//!
//! Each module is a pure, total function of explicit inputs with no
//! dependency, no I/O, and no standard-library call beyond `Vec` and slice
//! access. The code follows the extraction rules of the pinned Charon/Aeneas
//! route (index loops over slices, one loop per helper, closed enums, byte
//! comparisons). Each decision leaf has a refinement theorem to a Lean model
//! in `formal/Auths/Product/`; the outcome presence rule in [`outcome`] is
//! checked exhaustively by a Kani harness instead, because it decides what a
//! signed record may say, not whether a credential is leased or a write is
//! sent. `auths-gateway` supplies every input from a compiled
//! recipe, a native-verified action, its attempt store, and the results of
//! the I/O the step machine in [`order`] directs.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod construct;
/// Lossless exact-name binding to the compiler's positional argument layout.
pub mod arguments;
/// Exact bounded scalar validation and arithmetic decimal projection.
pub mod scalars;
/// Complete named-object projection through paired field schemas.
pub mod field_projection;
/// Bounded exact-name lowering of the existing decoded path vocabulary.
pub mod path_compiler;
/// Exact named JSON/form template lowering into the request writer's plans.
pub mod body_compiler;
/// Canonical source member selection and compiler-owned JSON/form echo placement.
pub mod template_members;
/// Bounded emission of the existing decoded JSON/form source AST into named templates.
pub mod template_ast;
/// The shared closed header catalog, fixed value grammar and named lowering.
pub mod header_compiler;
/// One checked write-source compiler over the immutable paired field layout.
pub mod request_compiler;
/// Exact decoded profile/source metadata binding and original-source hash framing.
pub mod recipe_binding;
/// Complete decoded profile command-schema parsing and reserved bindings.
pub mod profile_schema;
/// Exact closed-request, installation and durable-claim identity binding.
pub mod attempt_binding;
pub mod deadline;
pub mod identity;
/// Exact derived echo/idempotency preimages and fixed ASCII token encodings.
pub mod derived_tokens;
pub mod order;
pub mod outcome;
pub mod ratio;
pub mod recovery;
pub mod transition;

/// Bounded slot-prefix search decisions; storage remains in the runtime.
pub mod frontier;

/// Exact bounded-counter and slot commitment bytes; hashing stays in the runtime.
pub mod counter_preimages;

/// Shared keyed minimum-capacity aggregation; no actor or process identity is added.
pub mod counter_aggregation;

/// Checked conflict retries for claim/count/sum reservation batches.
pub mod reservation_retry;

/// Complete checked claim/count/sum descriptions before record serialization.
pub mod reservation_batch;

/// Exact identity and numeric validation of decoded cumulative slot records.
pub mod slot_record;

/// Exact active-state, workload and profile/version checks for connection entry.
pub mod entry_authorization;

/// One-use ownership of the exact request captured after a durable claim.
pub mod write_permit;
