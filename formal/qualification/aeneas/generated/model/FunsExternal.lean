-- REVIEWED TRANSPARENT MODEL FOR AN AENEAS STANDARD-LIBRARY EXTERNAL.
--
-- Rust `String::as_bytes` is represented by Aeneas' exact UTF-8 `Str`
-- conversion. This file contains no authority semantics and no axiom.
import Aeneas
import qualification.aeneas.generated.model.Types

open Aeneas Aeneas.Std Result ControlFlow Error

set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false
set_option maxHeartbeats 1000000
set_option maxRecDepth 2048

@[rust_fun "alloc::string::{alloc::string::String}::as_bytes"]
def alloc.string.String.as_bytes (value : String) : Result (Slice Std.U8) :=
if h : value.toByteArray.size ≤ U32.max then
ok (Aeneas.Std.toStr value h)
else
fail .panic
