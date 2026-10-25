import Auths.Crypto.Encoding.Flags
import Auths.Crypto.Encoding.Byte
import Auths.Crypto.Encoding.Coordinate
open Aeneas Aeneas.Std
namespace Auths.Crypto.Encoding.Encoded
abbrev Input := Array Std.U8 32#usize

theorem input_length (input : Input) : input.val.length = 32 := by
  have bound := input.property
  scalar_tac

def first (input : Input) : Std.U8 := input.val[0]'(by rw [input_length]; decide)
def last (input : Input) : Std.U8 := input.val[31]'(by rw [input_length]; decide)
def middle (input : Input) : List Std.U8 := (input.val.drop 1).take 30

theorem middle_length (input : Input) : (middle input).length = 30 := by
  simp [middle]

theorem input_decomposes (input : Input) : input.val = first input :: middle input ++ [last input] := by
  have initial : input.val.take 31 = first input :: middle input := by
    cases values : input.val with
    | nil => have bound := input_length input; simp [values] at bound
    | cons head tail => simp [first, middle, values]
  have final : input.val.drop 31 = [last input] := by
    rw [List.drop_eq_getElem_cons (by rw [input_length]; decide)]
    have stop : input.val.drop 32 = [] := List.drop_eq_nil_iff.mpr (by have := input_length input; omega)
    simp only [last, stop]
  calc
    input.val = input.val.take 31 ++ input.val.drop 31 := (List.take_append_drop 31 input.val).symm
    _ = first input :: middle input ++ [last input] := by rw [initial, final]

def middleValue (input : Input) : Nat := Nat.ofDigits 256 ((middle input).map UScalar.val)
def topValue (input : Input) : Nat := (last input).val % 128
def upperValue (input : Input) : Nat := middleValue input + 256 ^ 30 * topValue input

def ordinate (input : Input) : Nat :=
  Nat.ofDigits 256 ((first input).val :: ((middle input).map UScalar.val ++ [topValue input]))

def Encoding (input : Input) : Prop :=
  Auths.Crypto.Encoding.Coordinate.Encoding (ordinate input) (128 ≤ (last input).val)

instance (input : Input) : Decidable (Encoding input) := inferInstanceAs
  (Decidable (ordinate input < Auths.Crypto.Encoding.Coordinate.prime ∧
    (128 ≤ (last input).val → ordinate input ≠ 1 ∧ ordinate input ≠ Auths.Crypto.Encoding.Coordinate.prime - 1)))

theorem middle_bound (input : Input) : middleValue input < 256 ^ 30 := by
  have bounded : ∀ byte ∈ (middle input).map UScalar.val, byte < 256 := by
    intro byte member
    rcases List.mem_map.mp member with ⟨value, present, rfl⟩
    scalar_tac
  simpa only [List.length_map, middle_length, middleValue] using
    Auths.Crypto.Encoding.Digits.value_bound ((middle input).map UScalar.val) bounded

theorem ordinate_frame (input : Input) : ordinate input = (first input).val + 256 * upperValue input := by
  unfold ordinate
  rw [Nat.ofDigits_cons, Nat.ofDigits_append, Nat.ofDigits_singleton]
  rw [List.length_map, middle_length]
  rfl


end Auths.Crypto.Encoding.Encoded
