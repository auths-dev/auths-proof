import Auths.Crypto.UnsignedObjects
import Auths.Codec.ProtocolArrayWriters

open Aeneas Aeneas.Std
open AuthsProtocolCodec

namespace Auths.Crypto.WireCost
open Auths.Codec Auths.Codec.ProtocolArrayWriters

/- Independent conservative encoder budgets versus actual grammar length.
Forty-one covers the largest padded fixed leaf (an absent optional digest).
This is a logical capacity envelope, not measured memory or wall-clock work.
No Rust encoder result or trusted capacity flag appears in these definitions. -/
def Dominates (cost : Nat) (wire : List Nat) : Prop := cost ≤ 41 * wire.length

theorem head_positive (major value : Nat) : 1 ≤ (encodeHead ⟨major, value⟩).length := by
  simp [encodeHead]

theorem uint_positive (value : Nat) : 1 ≤ (UnsignedWire.uint value).length := head_positive 0 value

theorem bytes_positive (value : List Nat) : 1 ≤ (UnsignedWire.bytes value).length := by
  have head := head_positive 2 value.length
  simp only [UnsignedWire.bytes, List.length_append]
  omega

theorem text_positive (value : List Nat) : 1 ≤ (UnsignedWire.text value).length := by
  have head := head_positive 3 value.length
  simp only [UnsignedWire.text, List.length_append]
  omega

theorem fixed_bound (cost : Nat) (wire : List Nat) (small : cost ≤ 41) (positive : 1 ≤ wire.length) :
    Dominates cost wire := by unfold Dominates; omega

theorem uint_bound (value : Nat) : Dominates 9 (UnsignedWire.uint value) :=
  fixed_bound 9 _ (by decide) (uint_positive value)

theorem bytes_bound (value : List Nat) : Dominates (9 + value.length) (UnsignedWire.bytes value) := by
  have head := head_positive 2 value.length
  simp only [Dominates, UnsignedWire.bytes, List.length_append]
  omega

theorem text_bound (value : List Nat) : Dominates (9 + value.length) (UnsignedWire.text value) := by
  have head := head_positive 3 value.length
  simp only [Dominates, UnsignedWire.text, List.length_append]
  omega

theorem identifier_bound (value : String) : Dominates (9 + value.toByteArray.size) (UnsignedObjects.identifier value) := by
  simpa only [UnsignedObjects.identifier, UnsignedObjects.utf8, List.length_map, ByteArray.length_toList]
    using text_bound (UnsignedObjects.utf8 value)

theorem digest_bound (value : auths_model.Digest) : Dominates 41 (UnsignedObjects.digest value) :=
  fixed_bound 41 _ (by decide) (bytes_positive _)

theorem optional_digest_bound (value : Option auths_model.Digest) : Dominates 41 (UnsignedObjects.optionalDigest value) := by
  cases value with
  | none => exact fixed_bound 41 _ (by decide) (by simp [UnsignedObjects.optionalDigest, UnsignedWire.null])
  | some value => exact digest_bound value

private theorem contents_bound {Value : Type} (cost : Value → Nat) (wire : Value → List Nat)
    (values : List Value) (valid : ∀ value ∈ values, Dominates (cost value) (wire value)) :
    allocation cost values ≤ 41 * ((values.map wire).flatten).length := by
  revert valid
  induction values with
  | nil => intro valid; simp [allocation]
  | cons first rest ih =>
    intro valid
    have head := valid first (by simp)
    have tail := ih (fun value member => valid value (by simp [member]))
    simp only [allocation, List.map_cons, List.sum_cons, List.flatten_cons, List.length_append]
    unfold Dominates at head
    omega

theorem array_bound {Value : Type} (cost : Value → Nat) (wire : Value → List Nat)
    (values : List Value) (valid : ∀ value ∈ values, Dominates (cost value) (wire value)) :
    Dominates (9 + allocation cost values) (UnsignedWire.array (values.map wire)) := by
  have contents := contents_bound cost wire values valid
  have head := head_positive 4 values.length
  simp only [Dominates, UnsignedWire.array, List.length_append, List.length_map]
  omega

def mapCost (fields : List (Nat × Nat × List Nat)) : Nat :=
  9 + (fields.map (fun field => 9 + field.2.1)).sum

def mapBytes (fields : List (Nat × Nat × List Nat)) : List Nat :=
  UnsignedWire.map (fields.map (fun field => (field.1, field.2.2)))

private theorem entries_bound (fields : List (Nat × Nat × List Nat))
    (valid : ∀ field ∈ fields, Dominates field.2.1 field.2.2) :
    (fields.map (fun field => 9 + field.2.1)).sum ≤
      41 * (UnsignedWire.entries (fields.map (fun field => (field.1, field.2.2)))).length := by
  revert valid
  induction fields with
  | nil => intro valid; simp [UnsignedWire.entries]
  | cons first rest ih =>
    intro valid
    have head := valid first (by simp)
    have key := uint_bound first.1
    have tail := ih (fun value member => valid value (by simp [member]))
    simp only [List.map_cons, List.sum_cons, UnsignedWire.entries, List.length_append]
    unfold Dominates at head key
    simp only [UnsignedWire.uint] at key
    omega

theorem map_bound (fields : List (Nat × Nat × List Nat))
    (valid : ∀ field ∈ fields, Dominates field.2.1 field.2.2) :
    Dominates (mapCost fields) (mapBytes fields) := by
  have entries := entries_bound fields valid
  have head := head_positive 5 fields.length
  simp only [Dominates, mapCost, mapBytes, UnsignedWire.map, List.length_append, List.length_map]
  omega

theorem member_cost {Value : Type} (cost : Value → Nat) (values : List Value)
    (value : Value) (member : value ∈ values) : cost value ≤ allocation cost values := by
  revert member
  induction values with
  | nil => intro member; simp at member
  | cons first rest ih =>
    intro member
    simp only [List.mem_cons] at member
    simp only [allocation, List.map_cons, List.sum_cons]
    rcases member with same | member
    · subst value; omega
    · have tail := ih member; omega

end Auths.Crypto.WireCost
