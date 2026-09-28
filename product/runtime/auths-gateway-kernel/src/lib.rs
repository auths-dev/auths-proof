//! The gateway's translated decision leaves.
//!
//! Each module is a pure, total function of explicit inputs with no
//! dependency, no I/O, and no standard-library call beyond `Vec` and slice
//! access. The code follows the extraction rules of the pinned Charon/Aeneas
//! route (index loops over slices, one loop per helper, closed enums, byte
//! comparisons), and each leaf has a refinement theorem to a Lean model in
//! `formal/Auths/Product/`. `auths-gateway` re-exports both modules from its
//! recipe module and supplies every input from a compiled recipe and a
//! native-verified action.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod construct;
pub mod recovery;
