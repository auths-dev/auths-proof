import Aeneas
open Aeneas Aeneas.Std
namespace Auths.Crypto

/-- Explicit foreign P-256 implementation, with no instance or crypto law.
The public-wrapper theorems name its functional contract separately. -/
class P256Primitives where
  Key : Type
  Signature : Type
  Error : Type
  decode : Slice U8 → Result (core.result.Result Key Error)
  parse : Slice U8 → Result (core.result.Result Signature Error)
  verify : Key → Slice U8 → Signature → Result (core.result.Result Unit Error)

end Auths.Crypto
