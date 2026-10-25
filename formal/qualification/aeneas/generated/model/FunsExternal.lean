-- REVIEWED TRANSPARENT MODEL FOR AN AENEAS STANDARD-LIBRARY EXTERNAL.
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


-- String implements a total order; PartialOrd returns that same comparison.
@[rust_fun "alloc::string::{core::cmp::PartialOrd<alloc::string::String, alloc::string::String>}::partial_cmp"]
def alloc.string.String.Insts.CoreCmpPartialOrdString.partial_cmp
    (left right : String) : Result (Option Ordering) := ok (some (compare left right))

-- Eq's marker method has no runtime observation or state change.
@[rust_fun "alloc::string::{core::cmp::Eq<alloc::string::String>}::assert_fields_are_eq"]
def alloc.string.String.Insts.CoreCmpEq.assert_fields_are_eq (_ : String) : Result Unit := ok ()

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
