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
