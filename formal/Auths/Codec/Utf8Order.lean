import Auths.Model.IdentifierString
import Mathlib.Data.List.Lex
import Mathlib.Data.String.Basic
import Mathlib.Tactic

namespace Auths.Codec.Utf8Order
open Auths.Model.Identifier
set_option maxHeartbeats 2000000

/- UTF-8 preserves scalar order and is prefix-free. These statements use the
independent arithmetic encoding, not Rust/Lean string comparison as an assumed
byte-order oracle. The source bridge can therefore connect its string order to
the protocol's explicit UTF-8 byte order for every valid string. -/

theorem scalar_nonempty (scalar : Nat) : utf8 scalar ≠ [] := by
  unfold utf8
  split_ifs <;> simp

theorem scalar_prefix_lt (first second : Nat) (left right : List Nat)
    (firstBound : first ≤ 1114111) (secondBound : second ≤ 1114111)
    (less : first < second) : utf8 first ++ left < utf8 second ++ right := by
  unfold utf8
  split_ifs <;> simp only [List.cons_append, List.nil_append, List.cons_lt_cons_iff]
  all_goals omega

theorem shared_prefix_lt (prefix left right : List Nat) :
    prefix ++ left < prefix ++ right ↔ left < right := by
  induction prefix with
  | nil => rfl
  | cons first rest ih => simpa [List.cons_lt_cons_iff] using ih

def encode (characters : List Char) : List Nat :=
  characters.flatMap (fun character => utf8 character.toNat)

theorem encode_nonempty (characters : List Char) : encode characters = [] ↔ characters = [] := by
  cases characters with
  | nil => rfl
  | cons first rest => simp [encode, scalar_nonempty]

theorem encode_order (left right : List Char) : left < right ↔ encode left < encode right := by
  induction left generalizing right with
  | nil =>
    cases right with
    | nil => simp [encode]
    | cons first rest =>
      have present : encode (first :: rest) ≠ [] := by simp [encode_nonempty]
      cases meaning : encode (first :: rest) with
      | nil => contradiction
      | cons byte tail => simp [meaning, show encode ([] : List Char) = [] from rfl]
  | cons first rest ih =>
    cases right with
    | nil =>
      have present : encode (first :: rest) ≠ [] := by simp [encode_nonempty]
      cases meaning : encode (first :: rest) with
      | nil => contradiction
      | cons byte tail => simp [meaning, show encode ([] : List Char) = [] from rfl]
    | cons second tail =>
      have firstBound := character_bound first
      have secondBound := character_bound second
      by_cases same : first = second
      · subst second
        simpa [List.cons_lt_cons_iff, encode, shared_prefix_lt] using ih tail
      · rcases lt_or_gt_of_ne same with less | greater
        · have scalarLess : first.toNat < second.toNat := by
            simpa [Char.lt_def, Char.toNat] using less
          have bytesLess := scalar_prefix_lt first.toNat second.toNat (encode rest) (encode tail)
            firstBound secondBound scalarLess
          have charsLess : first :: rest < second :: tail := by simp [List.cons_lt_cons_iff, less]
          exact ⟨fun _ => bytesLess, fun _ => charsLess⟩
        · have scalarMore : second.toNat < first.toNat := by
            simpa [Char.lt_def, Char.toNat] using greater
          have bytesMore := scalar_prefix_lt second.toNat first.toNat (encode tail) (encode rest)
            secondBound firstBound scalarMore
          have charsMore : second :: tail < first :: rest := by simp [List.cons_lt_cons_iff, greater]
          exact ⟨fun less => False.elim ((not_lt_of_gt charsMore) less),
            fun less => False.elim ((not_lt_of_gt bytesMore) less)⟩

theorem string_order (left right : String) :
    left < right ↔
      left.toByteArray.toList.map UInt8.toNat < right.toByteArray.toList.map UInt8.toNat := by
  rw [String.lt_iff, string_encoding, string_encoding]
  exact encode_order left.toList right.toList

theorem string_bytes_injective : Function.Injective (fun value : String =>
    value.toByteArray.toList.map UInt8.toNat) := by
  intro left right same
  by_contra different
  rcases lt_or_gt_of_ne different with less | greater
  · have encoded := (string_order left right).mp less
    simpa [same] using encoded
  · have encoded := (string_order right left).mp greater
    simpa [same] using encoded

example : ([127] : List Nat) < utf8 128 := by decide
example : utf8 2047 < utf8 2048 := by decide
example : utf8 65535 < utf8 65536 := by decide
example : utf8 65536 < utf8 1114111 := by decide

end Auths.Codec.Utf8Order
