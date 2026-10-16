import Auths.Crypto.Refinement
import Lean.Elab.Tactic.Cbv
open Aeneas Aeneas.Std Result
open auths_codec
set_option cbv.warning false
set_option maxRecDepth 4096
set_option maxHeartbeats 2000000

namespace Auths.Crypto.Examples

-- Opaque unsigned bytes: these establish framing, not signature authorization.
def minimalPreimage : alloc.vec.Vec Std.U8 := ⟨[
  65#u8, 85#u8, 84#u8, 72#u8, 83#u8, 0#u8, 1#u8, 0#u8,
  1#u8, 0#u8, 1#u8, 116#u8, 0#u8, 1#u8, 0#u8, 0#u8,
  0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 1#u8, 1#u8
], by scalar_tac⟩

theorem minimal_preimage_exact : hash.signing_preimage .Grant
    (toStr "t" (by change 1 ≤ U32.max; scalar_tac)) 1#u16
    (⟨[1#u8], by scalar_tac⟩ : Slice Std.U8) = ok (.Ok minimalPreimage) := by
  unfold hash.signing_preimage
  simp only [Auths.Crypto.Refinement.object_tag]
  cbv

def unicodePreimage : alloc.vec.Vec Std.U8 := ⟨[
  65#u8, 85#u8, 84#u8, 72#u8, 83#u8, 0#u8, 1#u8, 0#u8,
  10#u8, 0#u8, 2#u8, 206#u8, 187#u8, 255#u8, 255#u8, 0#u8,
  0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 1#u8, 1#u8
], by scalar_tac⟩

theorem unicode_preimage_exact : hash.signing_preimage .Approval
    (toStr "λ" (by change 2 ≤ U32.max; scalar_tac)) 65535#u16
    (⟨[1#u8], by scalar_tac⟩ : Slice Std.U8) = ok (.Ok unicodePreimage) := by
  unfold hash.signing_preimage
  simp only [Auths.Crypto.Refinement.object_tag]
  cbv

end Auths.Crypto.Examples
