-- Exact checked conversion and Result projection shared by translation units.
import Aeneas
open Aeneas Aeneas.Std Result

def U64.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from (value : Std.Usize) :=
  core.num.tryFromUScalar .U64 value

def core.result.Result.unwrap_or {T E : Type} (value : core.result.Result T E) (fallback : T) :
    Result T := ok (match value with | .Ok value => value | .Err _ => fallback)
