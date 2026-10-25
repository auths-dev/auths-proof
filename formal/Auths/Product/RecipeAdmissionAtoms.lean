import Auths.Product.OperationIdentity

/-!
Independent finite byte/word admission rules used by the original recipe
validator. These predicates contain no native result, accepted-source flag,
selected child or expected compiled plan. They are not RFC 6901 decoding.
-/
namespace Auths.Product.RecipeAdmissionAtoms
abbrev Bytes := List Nat

def ResponsePointer (bytes : Bytes) : Prop :=
  bytes.head? = some 47 ∧ bytes.length ≤ 128 ∧
    (bytes.filter (· == 47)).length ≤ 8 ∧
    (126, 50) ∉ bytes.zip (bytes.drop 1)
instance (bytes : Bytes) : Decidable (ResponsePointer bytes) := by unfold ResponsePointer; infer_instance

def responsePointer (bytes : Bytes) : Bool := decide (ResponsePointer bytes)

def Descends (child parent : Bytes) : Prop :=
  child.take parent.length = parent ∧ child[parent.length]? = some 47
instance (child parent : Bytes) : Decidable (Descends child parent) := by unfold Descends; infer_instance

def pointersOverlap (left right : Bytes) : Bool := decide (left = right ∨ Descends left right ∨ Descends right left)

def Prefix (bytes : Bytes) : Prop :=
  0 < bytes.length ∧ bytes.length ≤ 32 ∧ ∀ byte ∈ bytes, 33 ≤ byte ∧ byte ≤ 126
instance (bytes : Bytes) : Decidable (Prefix bytes) := by unfold Prefix; infer_instance

def Prefixes (prefixes : List Bytes) : Prop :=
  0 < prefixes.length ∧ prefixes.length ≤ 4 ∧ prefixes.Nodup ∧ ∀ prefix ∈ prefixes, Prefix prefix
instance (prefixes : List Bytes) : Decidable (Prefixes prefixes) := by unfold Prefixes; infer_instance

def RefusedStatus (status : Nat) : Prop := 400 ≤ status ∧ status ≤ 499 ∧ status ≠ 408 ∧ status ≠ 429
instance (status : Nat) : Decidable (RefusedStatus status) := by unfold RefusedStatus; infer_instance

def RefusedStatuses (statuses : List Nat) : Prop :=
  0 < statuses.length ∧ statuses.length ≤ 3 ∧ statuses.Nodup ∧ ∀ status ∈ statuses, RefusedStatus status
instance (statuses : List Nat) : Decidable (RefusedStatuses statuses) := by unfold RefusedStatuses; infer_instance

def ReadBound (maximum : Nat) : Prop := 1 ≤ maximum ∧ maximum ≤ 65536
instance (maximum : Nat) : Decidable (ReadBound maximum) := by unfold ReadBound; infer_instance

def PreEntryPointers (pointers : List Bytes) (maximum : Nat) : Prop :=
  0 < pointers.length ∧ pointers.length ≤ 4 ∧ pointers.Nodup ∧
    (∀ pointer ∈ pointers, ResponsePointer pointer) ∧ ReadBound maximum
instance (pointers : List Bytes) (maximum : Nat) : Decidable (PreEntryPointers pointers maximum) := by
  unfold PreEntryPointers
  infer_instance

def IndexSyntax (bytes : Bytes) : Prop :=
  bytes ≠ [] ∧ (bytes.length = 1 ∨ bytes.head? ≠ some 48) ∧ ∀ byte ∈ bytes, 48 ≤ byte ∧ byte ≤ 57
instance (bytes : Bytes) : Decidable (IndexSyntax bytes) := by unfold IndexSyntax; infer_instance

def readIndex (bytes : Bytes) : Nat := bytes.foldl (fun value byte => 10 * value + (byte - 48)) 0

def arrayIndex (maximum : Nat) (bytes : Bytes) : Option Nat :=
  if IndexSyntax bytes ∧ readIndex bytes ≤ maximum then some (readIndex bytes) else none

theorem response_pointer_earns_bounds (bytes : Bytes) (accepted : responsePointer bytes = true) :
    bytes ≠ [] ∧ bytes.length ≤ 128 ∧ (bytes.filter (· == 47)).length ≤ 8 := by
  have admitted : ResponsePointer bytes := by simpa only [responsePointer, decide_eq_true_eq] using accepted
  refine ⟨?_, admitted.2.1, admitted.2.2.1⟩
  intro empty
  simp [empty] at admitted

theorem pointer_overlap_symmetric (left right : Bytes) : pointersOverlap left right = pointersOverlap right left := by
  unfold pointersOverlap
  congr 1
  apply propext
  have equality : left = right ↔ right = left := ⟨Eq.symm, Eq.symm⟩
  tauto

theorem array_index_earns_original_digits (maximum : Nat) (bytes : Bytes) (value : Nat)
    (accepted : arrayIndex maximum bytes = some value) :
    IndexSyntax bytes ∧ value ≤ maximum ∧ value = readIndex bytes := by
  unfold arrayIndex at accepted
  split at accepted
  · rename_i admitted
    have same : readIndex bytes = value := Option.some.inj accepted
    exact ⟨admitted.1, by omega, same.symm⟩
  · contradiction

theorem array_index_refuses_word_overflow (maximum : Nat) (bytes : Bytes) (large : maximum < readIndex bytes) :
    arrayIndex maximum bytes = none := by
  simp [arrayIndex, Nat.not_le.mpr large]

theorem prefixes_earn_byte_envelope (prefixes : List Bytes) (accepted : Prefixes prefixes) :
    prefixes.length ≤ 4 ∧ ∀ prefix ∈ prefixes, prefix.length ≤ 32 := by
  exact ⟨accepted.2.1, fun prefix member => (accepted.2.2.2 prefix member).2.1⟩

end Auths.Product.RecipeAdmissionAtoms
