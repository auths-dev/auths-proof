import Auths.Crypto.Encoding.Scan
import Auths.Crypto.Encoding.Digits
open Aeneas Aeneas.Std
namespace Auths.Crypto.Encoding.Flags
open Auths.Crypto.Encoding.Scan Auths.Crypto.Encoding.Digits

theorem scan_flags (bytes : List Std.U8) (maximum zero : Bool) :
    scan bytes maximum zero =
      (maximum && bytes.all (fun byte => decide (byte = 255#u8)),
       zero && bytes.all (fun byte => decide (byte = 0#u8))) := by
  induction bytes generalizing maximum zero with
  | nil => simp [scan]
  | cons head tail ih =>
    change scan tail (maximum && decide (head = 255#u8)) (zero && decide (head = 0#u8)) = _
    rw [ih]
    simp only [List.all_cons, Bool.and_assoc]

theorem all_maximum (bytes : List Std.U8) :
    bytes.all (fun byte => decide (byte = 255#u8)) = true ↔
      bytes.map UScalar.val = List.replicate bytes.length 255 := by
  simp only [List.all_eq_true, decide_eq_true_eq, List.eq_replicate_iff, List.length_map, true_and]
  constructor
  · intro all byte member
    rcases List.mem_map.mp member with ⟨value, present, same⟩
    have native := all value present
    subst value
    exact same.symm
  · intro all byte member
    have numeric := all byte.val (List.mem_map.mpr ⟨byte, member, rfl⟩)
    scalar_tac

theorem all_zero (bytes : List Std.U8) :
    bytes.all (fun byte => decide (byte = 0#u8)) = true ↔
      bytes.map UScalar.val = List.replicate bytes.length 0 := by
  simp only [List.all_eq_true, decide_eq_true_eq, List.eq_replicate_iff, List.length_map, true_and]
  constructor
  · intro all byte member
    rcases List.mem_map.mp member with ⟨value, present, same⟩
    have native := all value present
    subst value
    exact same.symm
  · intro all byte member
    have numeric := all byte.val (List.mem_map.mpr ⟨byte, member, rfl⟩)
    scalar_tac

theorem maximum_value (bytes : List Std.U8) :
    bytes.all (fun byte => decide (byte = 255#u8)) = true ↔
      Nat.ofDigits 256 (bytes.map UScalar.val) = 256 ^ bytes.length - 1 := by
  have bounded : ∀ byte ∈ bytes.map UScalar.val, byte < 256 := by
    intro byte member
    rcases List.mem_map.mp member with ⟨value, present, rfl⟩
    scalar_tac
  rw [all_maximum bytes]
  simpa only [List.length_map] using
    (Auths.Crypto.Encoding.Digits.maximum_iff (bytes.map UScalar.val) bounded).symm

theorem zero_value (bytes : List Std.U8) :
    bytes.all (fun byte => decide (byte = 0#u8)) = true ↔
      Nat.ofDigits 256 (bytes.map UScalar.val) = 0 := by
  have bounded : ∀ byte ∈ bytes.map UScalar.val, byte < 256 := by
    intro byte member
    rcases List.mem_map.mp member with ⟨value, present, rfl⟩
    scalar_tac
  rw [all_zero bytes]
  simpa only [List.length_map] using
    (Auths.Crypto.Encoding.Digits.zero_iff (bytes.map UScalar.val) bounded).symm

end Auths.Crypto.Encoding.Flags
