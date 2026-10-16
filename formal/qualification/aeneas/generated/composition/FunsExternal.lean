-- REVIEWED: Option::default is None; the two numeric/Result operations
-- delegate to the existing exact standard-library models.
import qualification.aeneas.generated.composition.Types
import qualification.aeneas.generated.codec.FunsExternal
open Aeneas Aeneas.Std Result

def core.option.Option.Insts.CoreDefaultDefault.default (T : Type) : Result (Option T) := ok none
