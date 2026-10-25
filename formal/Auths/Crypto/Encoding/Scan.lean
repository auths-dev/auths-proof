import qualification.aeneas.generated.signature.Funs
open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace Auths.Crypto.Encoding.Scan

def update (state : Bool × Bool) (byte : Std.U8) : Bool × Bool :=
  (state.1 && decide (byte = 255#u8), state.2 && decide (byte = 0#u8))

def scan (bytes : List Std.U8) (maximum zero : Bool) : Bool × Bool :=
  bytes.foldl update (maximum, zero)

theorem loop_refines (encoded : Array Std.U8 32#usize) (remaining : Nat)
    (range : core.ops.range.Range Std.Usize) (maximum zero : Bool)
    (bounded : range.end.val ≤ 31) (count : range.start.val + remaining = range.end.val) :
    auths_signature_core.ed25519_point_encoding_is_canonical_loop range encoded maximum zero
      ⦃ result => result = scan ((encoded.val.drop range.start.val).take remaining) maximum zero ⦄ := by
  induction remaining generalizing range maximum zero with
  | zero =>
    rw [auths_signature_core.ed25519_point_encoding_is_canonical_loop.eq_def]
    have stop : range.end.val ≤ range.start.val := by omega
    apply spec_bind (core.iter.range.IteratorRange.next_Usize_none_spec range stop)
    rintro ⟨option, next⟩ ⟨noneEq, same⟩
    simp only [noneEq, uncurry, spec_ok, List.take_zero, scan, List.foldl_nil]
  | succ remaining ih =>
    rw [auths_signature_core.ed25519_point_encoding_is_canonical_loop.eq_def]
    have advances : range.start.val < range.end.val := by omega
    apply spec_bind (core.iter.range.IteratorRange.next_Usize_some_spec range advances)
    rintro ⟨option, next⟩ ⟨someEq, nextStart, nextEnd⟩
    simp only [someEq]
    have arraySize : encoded.val.length = 32 := by have bound := encoded.property; scalar_tac
    step as ⟨byte, byteEq⟩
    have nextBound : next.end.val ≤ 31 := by rw [nextEnd]; exact bounded
    have nextCount : next.start.val + remaining = next.end.val := by rw [nextEnd]; omega
    have executes := ih next (maximum && decide (byte = 255#u8))
      (zero && decide (byte = 0#u8)) nextBound nextCount
    apply spec_mono executes
    intro result meaning
    have first : (encoded.val.drop range.start.val).take (remaining + 1) =
        encoded.val[range.start.val] :: (encoded.val.drop (range.start.val + 1)).take remaining := by
      rw [List.drop_eq_getElem_cons (by omega)]
      rfl
    simpa only [first, scan, List.foldl_cons, update, byteEq, nextStart] using meaning

end Auths.Crypto.Encoding.Scan
