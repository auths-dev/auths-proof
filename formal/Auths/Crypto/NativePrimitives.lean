import Aeneas

open Aeneas Aeneas.Std Result

namespace Auths.Crypto

/-- Explicit implementation parameter for the three foreign Ed25519 library
calls. There is deliberately no instance: every public-wrapper claim must
quantify over an implementation and state its primitive contracts. -/
class Ed25519Primitives where
  Key : Type
  Signature : Type
  Error : Type
  decode : Array Std.U8 32#usize → Result (core.result.Result Key Error)
  signatureFromBytes : Array Std.U8 64#usize → Result Signature
  verifyStrict : Key → Slice Std.U8 → Signature → Result (core.result.Result Unit Error)

end Auths.Crypto
