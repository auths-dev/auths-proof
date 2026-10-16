import Aeneas
import Auths.Codec.Semantics
open Aeneas Aeneas.Std Result
open Auths.Codec
set_option maxHeartbeats 2000000
namespace Auths.Crypto.Endian

theorem be16_exact (value : Std.U16) :
    (core.num.U16.to_be_bytes value).val.map (·.val) = bigEndian 2 value.val := by
  simp only [core.num.U16.to_be_bytes, BitVec.toBEBytes, BitVec.toLEBytes,
    UScalarTy.numBits, bigEndian, UScalar.val, List.map_map,
    gt_iff_lt, Nat.reduceLT, Nat.reduceSub, ↓reduceIte,
    List.reverse_cons, List.reverse_nil, List.nil_append, List.append_nil,
    List.map_cons, List.map_nil, List.cons_append,
    BitVec.toNat_setWidth, BitVec.toNat_ushiftRight, Nat.shiftRight_eq_div_pow]
  simp only [Nat.reducePow, Nat.mod_mod]


theorem be64_exact (value : Std.U64) :
    (core.num.U64.to_be_bytes value).val.map (·.val) = bigEndian 8 value.val := by
  have bound : value.bv.toNat < 18446744073709551616 := value.bv.isLt
  simp only [core.num.U64.to_be_bytes, List.map_map, UScalar.val, Function.comp_apply]
  change (@BitVec.toBEBytes 64 value.bv).map (fun byte => byte.toNat) =
    bigEndian 8 value.bv.toNat
  simp only [BitVec.toBEBytes, BitVec.toLEBytes,
    bigEndian, gt_iff_lt, Nat.reduceLT, Nat.reduceSub, ↓reduceIte,
    List.reverse_cons, List.reverse_nil, List.nil_append, List.append_nil,
    List.map_cons, List.map_nil, List.cons_append,
    BitVec.toNat_setWidth, BitVec.toNat_ushiftRight, Nat.shiftRight_eq_div_pow]
  simp only [Nat.reducePow, Nat.mod_mod]
  simp only [List.cons.injEq, and_true]
  omega


end Auths.Crypto.Endian
