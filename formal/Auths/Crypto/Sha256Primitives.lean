import Aeneas
open Aeneas Aeneas.Std Result
namespace Auths.Crypto

/-- Explicit foreign SHA-256 and selected fixed-size output-conversion calls.
No global implementation instance or cryptographic axiom is supplied. -/
class Sha256Primitives where
  Output : Type
  digest : Slice Std.U8 → Result Output
  intoBytes : Output → Result (Array Std.U8 32#usize)

end Auths.Crypto
