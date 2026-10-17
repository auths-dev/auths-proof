import qualification.aeneas.generated.temporal_witness.Types
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
