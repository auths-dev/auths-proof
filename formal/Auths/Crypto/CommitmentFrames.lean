import Auths.Crypto.Framing
open Auths.Codec
namespace Auths.Crypto.CommitmentFrames
structure Application where
  domain : List Nat
  payload : List Nat
  deriving DecidableEq
structure Identifier where
  kind : Nat
  payload : List Nat
  deriving DecidableEq

def Application.Valid (frame : Application) : Prop :=
  0 < frame.domain.length ∧ frame.domain.length ≤ 128 ∧
  frame.payload.length < 18446744073709551616 ∧ BytesValid frame.domain ∧ BytesValid frame.payload

def Identifier.Valid (frame : Identifier) : Prop :=
  frame.kind < 65536 ∧ frame.payload.length < 18446744073709551616 ∧ BytesValid frame.payload

def application (frame : Application) : List Nat :=
  [65, 85, 84, 72, 83, 45, 67, 79, 77, 77, 73, 84, 77, 69, 78, 84, 0, 1] ++
    bigEndian 2 frame.domain.length ++ frame.domain ++
    bigEndian 8 frame.payload.length ++ frame.payload

def identifier (frame : Identifier) : List Nat :=
  [65, 85, 84, 72, 83, 45, 73, 68, 0, 1] ++ bigEndian 2 frame.kind ++
    bigEndian 8 frame.payload.length ++ frame.payload

theorem application_length (frame : Application) :
    (application frame).length = 28 + frame.domain.length + frame.payload.length := by
  simp [application, bigEndian_length]
  omega

theorem identifier_length (frame : Identifier) :
    (identifier frame).length = 20 + frame.payload.length := by
  simp [identifier, bigEndian_length]
  omega

theorem application_unambiguous (left right : Application)
    (leftValid : left.Valid) (rightValid : right.Valid)
    (same : application left = application right) : left = right := by
  have rest : bigEndian 2 left.domain.length ++ (left.domain ++
      (bigEndian 8 left.payload.length ++ left.payload)) =
      bigEndian 2 right.domain.length ++ (right.domain ++
      (bigEndian 8 right.payload.length ++ right.payload)) := by
    simpa only [application, List.append_assoc, List.cons_append, List.nil_append,
      List.cons.injEq, true_and] using same
  obtain ⟨lengthBytes, rest⟩ := List.append_inj rest (by simp [bigEndian_length])
  have lengths : left.domain.length = right.domain.length :=
    Framing.endian_injective 2 _ _ (by have := leftValid.2.1; omega)
      (by have := rightValid.2.1; omega) lengthBytes
  obtain ⟨domains, rest⟩ := List.append_inj rest lengths
  obtain ⟨_, payloads⟩ := List.append_inj rest (by simp [bigEndian_length])
  cases left; cases right
  simp_all

theorem identifier_unambiguous (left right : Identifier)
    (leftValid : left.Valid) (rightValid : right.Valid)
    (same : identifier left = identifier right) : left = right := by
  have rest : bigEndian 2 left.kind ++ (bigEndian 8 left.payload.length ++ left.payload) =
      bigEndian 2 right.kind ++ (bigEndian 8 right.payload.length ++ right.payload) := by
    simpa only [identifier, List.append_assoc, List.cons_append, List.nil_append,
      List.cons.injEq, true_and] using same
  obtain ⟨kindBytes, rest⟩ := List.append_inj rest (by simp [bigEndian_length])
  have kinds := Framing.endian_injective 2 left.kind right.kind leftValid.1 rightValid.1 kindBytes
  obtain ⟨_, payloads⟩ := List.append_inj rest (by simp [bigEndian_length])
  cases left; cases right
  simp_all

theorem application_identifier_separate (left : Application) (right : Identifier) :
    application left ≠ identifier right := by
  simp [application, identifier, List.append_assoc]

theorem signing_application_separate (left : Framing.Frame) (right : Application) :
    Framing.encode left ≠ application right := by
  simp [Framing.encode, application, List.append_assoc]

theorem signing_identifier_separate (left : Framing.Frame) (right : Identifier) :
    Framing.encode left ≠ identifier right := by
  simp [Framing.encode, identifier, List.append_assoc]
end Auths.Crypto.CommitmentFrames
