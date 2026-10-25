import Auths.Crypto.Framing
import Mathlib.Tactic
open Auths.Codec
namespace Auths.Product.CounterFrames
abbrev Bytes := List Nat

def fields : List Bytes → Bytes
  | [] => []
  | value :: rest => bigEndian 8 value.length ++ value ++ fields rest

def Bounded (values : List Bytes) : Prop := ∀ value ∈ values, value.length < 2 ^ 64

/-- Fixed field counts let the consumer separate the framed fields from the
    fixed-width final words, including empty components and embedded NUL. -/
theorem fields_cancel (left right : List Bytes) (leftTail rightTail : Bytes)
    (count : left.length = right.length) (leftBound : Bounded left) (rightBound : Bounded right)
    (same : fields left ++ leftTail = fields right ++ rightTail) :
    left = right ∧ leftTail = rightTail := by
  induction left generalizing right with
  | nil =>
    have empty : right = [] := List.length_eq_zero_iff.mp count.symm
    subst right
    exact ⟨rfl, by simpa [fields] using same⟩
  | cons first rest ih =>
    cases right with
    | nil => simp at count
    | cons next tail =>
      have firstBound := leftBound first (by simp)
      have nextBound := rightBound next (by simp)
      have framing : bigEndian 8 first.length ++ (first ++ (fields rest ++ leftTail)) =
          bigEndian 8 next.length ++ (next ++ (fields tail ++ rightTail)) := by
        simpa only [fields, List.append_assoc] using same
      obtain ⟨lengthBytes, remaining⟩ := List.append_inj framing (by simp [bigEndian_length])
      have sizes := Auths.Crypto.Framing.endian_injective 8 _ _ firstBound nextBound lengthBytes
      obtain ⟨exactFirst, suffix⟩ := List.append_inj remaining sizes
      have leftRest : Bounded rest := fun value member => leftBound value (by simp [member])
      have rightRest : Bounded tail := fun value member => rightBound value (by simp [member])
      obtain ⟨exactRest, exactTail⟩ := ih tail (by simpa using count) leftRest rightRest suffix
      exact ⟨by simp [exactFirst, exactRest], exactTail⟩

inductive Kind where
  | count | sum
  deriving DecidableEq

-- UTF-8 bytes of the registered tags, including their final NUL.
def domain : Kind → Bytes
  | .count => [97,117,116,104,115,46,103,97,116,101,119,97,121,45,98,111,117,110,100,101,100,45,99,111,117,110,116,47,50,0]
  | .sum => [97,117,116,104,115,46,103,97,116,101,119,97,121,45,98,111,117,110,100,101,100,45,115,117,109,47,49,0]

structure Counter where
  kind : Kind
  components : List Bytes
  window : Nat
  index : Nat
  deriving DecidableEq

def Counter.Valid (value : Counter) : Prop :=
  value.components.length = (if value.kind = .count then 3 else 4) ∧
    Bounded value.components ∧ value.window < 2 ^ 64 ∧ value.index < 2 ^ 64

def encode (value : Counter) : Bytes :=
  domain value.kind ++ fields value.components ++ bigEndian 8 value.window ++ bigEndian 8 value.index

/-- Exact bytes, rather than any collision-free hash assumption, bind every
    counter component and both fixed-window coordinates. -/
theorem encode_injective (left right : Counter) (leftValid : left.Valid) (rightValid : right.Valid)
    (same : encode left = encode right) : left = right := by
  have kind : left.kind = right.kind := by
    cases leftKind : left.kind <;> cases rightKind : right.kind
    · rfl
    · simp [encode, domain, leftKind, rightKind, List.append_assoc] at same
    · simp [encode, domain, leftKind, rightKind, List.append_assoc] at same
    · rfl
  have framed : fields left.components ++ (bigEndian 8 left.window ++ bigEndian 8 left.index) =
      fields right.components ++ (bigEndian 8 right.window ++ bigEndian 8 right.index) := by
    apply List.append_cancel_left (as := domain left.kind)
    simpa only [encode, kind, List.append_assoc] using same
  have counts : left.components.length = right.components.length := by
    rw [leftValid.1, rightValid.1, kind]
  obtain ⟨components, coordinates⟩ := fields_cancel _ _ _ _ counts leftValid.2.1 rightValid.2.1 framed
  obtain ⟨windows, indices⟩ := List.append_inj coordinates (by simp [bigEndian_length])
  have window := Auths.Crypto.Framing.endian_injective 8 _ _ leftValid.2.2.1 rightValid.2.2.1 windows
  have index := Auths.Crypto.Framing.endian_injective 8 _ _ leftValid.2.2.2 rightValid.2.2.2 indices
  cases left; cases right
  simp_all

def slotDomain : Kind → Bytes
  | .count => [97, 117, 116, 104, 115, 46, 103, 97, 116, 101, 119, 97, 121, 45, 98, 111, 117, 110, 100, 101, 100, 45, 99, 111, 117, 110, 116, 45, 115, 108, 111, 116, 47, 50, 0]
  | .sum => [97, 117, 116, 104, 115, 46, 103, 97, 116, 101, 119, 97, 121, 45, 98, 111, 117, 110, 100, 101, 100, 45, 115, 117, 109, 45, 115, 108, 111, 116, 47, 49, 0]

structure Slot where
  kind : Kind
  counter : Bytes
  index : Nat
  deriving DecidableEq

def Slot.Valid (value : Slot) : Prop := value.counter.length = 32 ∧ value.index < 2 ^ 64

def slotEncode (value : Slot) : Bytes := slotDomain value.kind ++ value.counter ++ bigEndian 8 value.index

theorem slot_injective (left right : Slot) (leftValid : left.Valid) (rightValid : right.Valid)
    (same : slotEncode left = slotEncode right) : left = right := by
  have kind : left.kind = right.kind := by
    cases leftKind : left.kind <;> cases rightKind : right.kind
    · rfl
    · simp [slotEncode, slotDomain, leftKind, rightKind, List.append_assoc] at same
    · simp [slotEncode, slotDomain, leftKind, rightKind, List.append_assoc] at same
    · rfl
  have remaining : left.counter ++ bigEndian 8 left.index = right.counter ++ bigEndian 8 right.index := by
    apply List.append_cancel_left (as := slotDomain left.kind)
    simpa only [slotEncode, kind, List.append_assoc] using same
  obtain ⟨counter, indices⟩ := List.append_inj remaining (leftValid.1.trans rightValid.1.symm)
  have index := Auths.Crypto.Framing.endian_injective 8 _ _ leftValid.2 rightValid.2 indices
  cases left; cases right
  simp_all

/-- Framing overhead is bounded independently of the component contents. -/
theorem fields_length (values : List Bytes) :
    (fields values).length = 8 * values.length + (values.map List.length).sum := by
  induction values with
  | nil => simp [fields]
  | cons first rest ih => simp [fields, ih, bigEndian_length]; omega

theorem count_frame_length (namespaceBytes subject evaluator : Bytes) (window index : Nat)
    (namespaceBound : namespaceBytes.length ≤ 64) (subjectBound : subject.length ≤ 512)
    (evaluatorBound : evaluator.length ≤ 128) :
    (encode ⟨.count, [namespaceBytes, subject, evaluator], window, index⟩).length ≤ 774 := by
  simp [encode, domain, fields, bigEndian_length]
  omega

theorem sum_frame_length (namespaceBytes subject evaluator partitionBytes : Bytes) (window index : Nat)
    (namespaceBound : namespaceBytes.length ≤ 64) (subjectBound : subject.length ≤ 512)
    (evaluatorBound : evaluator.length ≤ 128) (partitionBound : partitionBytes.length ≤ 64) :
    (encode ⟨.sum, [namespaceBytes, subject, evaluator, partitionBytes], window, index⟩).length ≤ 844 := by
  simp [encode, domain, fields, bigEndian_length]
  omega

theorem slot_frame_length (value : Slot) (valid : value.Valid) :
    (slotEncode value).length = (if value.kind = .count then 75 else 73) := by
  cases kind : value.kind <;> simp [slotEncode, slotDomain, kind, valid.1, bigEndian_length]

end Auths.Product.CounterFrames
