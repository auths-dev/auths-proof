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
pub mod order;
pub mod outcome;
pub mod ratio;
pub mod recovery;
pub mod transition;
