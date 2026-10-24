import Auths.Codec.Semantics
import Mathlib.Tactic

namespace Auths.Crypto.UnsignedWire
open Auths.Codec

/- Independent definite CBOR byte grammar. These definitions call no Rust
writer, parser, constructor, hash or successful-result predicate. Integer map
keys and their order are explicit at each protocol schema call site. -/

def uint (value : Nat) : List Nat := encodeHead ⟨0, value⟩
def bytes (value : List Nat) : List Nat := encodeHead ⟨2, value.length⟩ ++ value
def text (value : List Nat) : List Nat := encodeHead ⟨3, value.length⟩ ++ value
def boolean (value : Bool) : List Nat := if value then [245] else [244]
def null : List Nat := [246]

def entries : List (Nat × List Nat) → List Nat
  | [] => []
  | (key, value) :: rest => uint key ++ value ++ entries rest

def map (fields : List (Nat × List Nat)) : List Nat :=
  encodeHead ⟨5, fields.length⟩ ++ entries fields

def array (values : List (List Nat)) : List Nat :=
  encodeHead ⟨4, values.length⟩ ++ values.flatten

theorem uint_length (value : Nat) : (uint value).length ≤ 9 :=
  encodeHead_length_le_nine _

theorem bytes_length (value : List Nat) : (bytes value).length ≤ 9 + value.length := by
  have bound := encodeHead_length_le_nine (⟨2, value.length⟩ : Head)
  simpa only [bytes, List.length_append] using Nat.add_le_add_right bound value.length

theorem text_length (value : List Nat) : (text value).length ≤ 9 + value.length := by
  have bound := encodeHead_length_le_nine (⟨3, value.length⟩ : Head)
  simpa only [text, List.length_append] using Nat.add_le_add_right bound value.length

theorem boolean_length (value : Bool) : (boolean value).length = 1 := by
  cases value <;> rfl

theorem entries_length (fields : List (Nat × List Nat)) :
    (entries fields).length ≤ (fields.map (fun field => 9 + field.2.length)).sum := by
  induction fields with
  | nil => simp [entries]
  | cons first rest ih =>
    have bound := uint_length first.1
    simp only [entries, List.length_append, List.map_cons, List.sum_cons]
    omega

theorem map_length (fields : List (Nat × List Nat)) :
    (map fields).length ≤ 9 + (fields.map (fun field => 9 + field.2.length)).sum := by
  have headBound := encodeHead_length_le_nine (⟨5, fields.length⟩ : Head)
  have fieldsBound := entries_length fields
  simp only [map, List.length_append]
  omega

theorem array_length (values : List (List Nat)) :
    (array values).length ≤ 9 + (values.map List.length).sum := by
  have headBound := encodeHead_length_le_nine (⟨4, values.length⟩ : Head)
  simp only [array, List.length_append, List.length_flatten]
  omega

structure Descriptor where
  principalMethod : List Nat
  verificationMethod : List Nat
  suite : List Nat
  deriving DecidableEq

def Descriptor.Valid (value : Descriptor) : Prop :=
  value.principalMethod.length < 2 ^ 64 ∧
  value.verificationMethod.length < 2 ^ 64 ∧ value.suite.length < 2 ^ 64 ∧
  BytesValid value.principalMethod ∧ BytesValid value.verificationMethod ∧ BytesValid value.suite

def descriptor (value : Descriptor) : List Nat :=
  map [(0, text value.principalMethod), (1, text value.verificationMethod), (2, text value.suite)]

def signingObject (unsignedStatement : List Nat) (value : Descriptor) : List Nat :=
  map [(0, unsignedStatement), (1, descriptor value)]

def expectHead (major argument : Nat) (input : List Nat) : Option (List Nat) := do
  let (head, rest) ← readHead input
  if head.major = major ∧ head.argument = argument then some rest else none

def readText (input : List Nat) : Option (List Nat × List Nat) := do
  let (head, rest) ← readHead input
  if head.major = 3 ∧ head.argument ≤ rest.length then
    some (rest.take head.argument, rest.drop head.argument)
  else none

def readDescriptor (input : List Nat) : Option (Descriptor × List Nat) := do
  let rest ← expectHead 5 3 input
  let rest ← expectHead 0 0 rest
  let (principal, rest) ← readText rest
  let rest ← expectHead 0 1 rest
  let (verification, rest) ← readText rest
  let rest ← expectHead 0 2 rest
  let (suite, rest) ← readText rest
  some (⟨principal, verification, suite⟩, rest)

theorem expect_head_encoded (major argument : Nat)
    (valid : (⟨major, argument⟩ : Head).Valid) (tail : List Nat) :
    expectHead major argument (encodeHead ⟨major, argument⟩ ++ tail) = some tail := by
  simp [expectHead, readHead_encodeHead _ valid tail]

theorem text_roundtrip (value tail : List Nat) (bounded : value.length < 2 ^ 64) :
    readText (text value ++ tail) = some (value, tail) := by
  have valid : (⟨3, value.length⟩ : Head).Valid := ⟨by decide, bounded⟩
  unfold text readText
  rw [List.append_assoc, readHead_encodeHead _ valid]
  have enough : value.length ≤ (value ++ tail).length := by simp
  simp [enough]

/-- A complete descriptor is recoverable before an arbitrary trailing value.
The argument is about framing bytes, independently of hashing and signatures. -/
theorem descriptor_roundtrip (value : Descriptor) (valid : value.Valid) (tail : List Nat) :
    readDescriptor (descriptor value ++ tail) = some (value, tail) := by
  rcases valid with ⟨principalBound, verificationBound, suiteBound, _⟩
  simp only [descriptor, map, entries, uint, List.length_cons, List.length_nil,
    List.append_nil, List.append_assoc]
  simp only [readDescriptor,
    expect_head_encoded 5 3 (by decide), expect_head_encoded 0 0 (by decide),
    expect_head_encoded 0 1 (by decide), expect_head_encoded 0 2 (by decide),
    text_roundtrip _ _ principalBound, text_roundtrip _ _ verificationBound,
    text_roundtrip _ _ suiteBound, Option.bind_some]
  cases value
  rfl

theorem descriptor_unambiguous (left right : Descriptor)
    (leftValid : left.Valid) (rightValid : right.Valid)
    (same : descriptor left = descriptor right) : left = right := by
  have decoded := congrArg readDescriptor same
  have leftInverse := descriptor_roundtrip left leftValid []
  have rightInverse := descriptor_roundtrip right rightValid []
  simp only [List.append_nil] at leftInverse rightInverse
  rw [leftInverse, rightInverse] at decoded
  simpa using congrArg (fun value => value.map (fun result => result.1)) decoded

theorem descriptor_binds_fields (left right : Descriptor)
    (leftValid : left.Valid) (rightValid : right.Valid)
    (same : descriptor left = descriptor right) :
    left.principalMethod = right.principalMethod ∧
      left.verificationMethod = right.verificationMethod ∧ left.suite = right.suite := by
  have exactValue := descriptor_unambiguous left right leftValid rightValid same
  subst right
  exact ⟨rfl, rfl, rfl⟩

theorem descriptor_field_change (left right : Descriptor)
    (leftValid : left.Valid) (rightValid : right.Valid)
    (different : left.principalMethod ≠ right.principalMethod ∨
      left.verificationMethod ≠ right.verificationMethod ∨ left.suite ≠ right.suite) :
    descriptor left ≠ descriptor right := by
  intro same
  have exactValue := descriptor_unambiguous left right leftValid rightValid same
  subst right
  simp at different

end Auths.Crypto.UnsignedWire
