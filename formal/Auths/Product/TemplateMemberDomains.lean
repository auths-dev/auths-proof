import Auths.Product.TemplateMembers

namespace Auths.Product.TemplateMembers

/-- A suffix still to be validated, with its actual preceding source key. -/
def KeyTail : Option Bytes → List Bytes → Prop
  | _, [] => True
  | previous, key :: rest => OperationIdentity.validToken key 64 = true ∧
      (match previous with | none => True | some before => before < key) ∧ KeyTail (some key) rest

instance (previous : Option Bytes) (keys : List Bytes) : Decidable (KeyTail previous keys) := by
  induction keys generalizing previous with
  | nil => exact isTrue trivial
  | cons key rest ih =>
    haveI := ih (some key)
    cases previous <;> unfold KeyTail <;> infer_instance

def BeforeKeys : Option Bytes → List Bytes → Prop
  | none, _ => True
  | some before, keys => ∀ key ∈ keys, before < key

/-- Adjacent native checks earn strict order for the whole source column. -/
theorem key_tail_iff (previous : Option Bytes) (keys : List Bytes) :
    KeyTail previous keys ↔ (∀ key ∈ keys, OperationIdentity.validToken key 64 = true) ∧
      keys.Pairwise (· < ·) ∧ BeforeKeys previous keys := by
  induction keys generalizing previous with
  | nil => cases previous <;> simp [KeyTail, BeforeKeys]
  | cons key rest ih =>
    cases previous with
    | none =>
      simp only [KeyTail, ih, BeforeKeys, true_and, List.forall_mem_cons, List.pairwise_cons]
      tauto
    | some before =>
      simp only [KeyTail, ih, BeforeKeys, List.forall_mem_cons, List.pairwise_cons]
      constructor
      · rintro ⟨keyToken, beforeKey, restTokens, restSorted, keyRest⟩
        exact ⟨⟨keyToken, restTokens⟩, ⟨keyRest, restSorted⟩, beforeKey,
          fun value member => lt_trans beforeKey (keyRest value member)⟩
      · rintro ⟨⟨keyToken, restTokens⟩, ⟨keyRest, restSorted⟩, beforeKey, beforeRest⟩
        exact ⟨keyToken, beforeKey, restTokens, restSorted, keyRest⟩

def previousAt (keys : List Bytes) (position : Nat) : Option Bytes :=
  if position = 0 then none else keys[position - 1]?

theorem previous_at_next (keys : List Bytes) (position : Nat) :
    previousAt keys (position + 1) = keys[position]? := by simp [previousAt]

def KeyHead (keys : List Bytes) (position : Nat) : Prop :=
  match keys[position]? with
  | none => False
  | some key => OperationIdentity.validToken key 64 = true ∧
      match previousAt keys position with
      | none => True
      | some previous => previous < key

instance (keys : List Bytes) (position : Nat) : Decidable (KeyHead keys position) := by
  unfold KeyHead
  split <;> infer_instance

theorem key_tail_step (keys : List Bytes) (position : Nat) (inside : position < keys.length) :
    KeyTail (previousAt keys position) (keys.drop position) ↔
      KeyHead keys position ∧
        KeyTail (previousAt keys (position + 1)) (keys.drop (position + 1)) := by
  have suffix := List.drop_eq_getElem_cons inside
  have atKey := List.getElem?_eq_getElem inside
  rw [suffix, KeyTail, KeyHead, atKey, previous_at_next, atKey]
  tauto

theorem key_column_iff (keys : List Bytes) (domain : Domain) :
    KeyColumn keys domain ↔ 0 < keys.length ∧ keys.length ≤ maximum domain ∧ KeyTail none keys := by
  simp [KeyColumn, key_tail_iff, BeforeKeys, and_assoc]

def tokenCost (tokens : List Bytes) : Nat := (tokens.map (fun token => token.length + 1)).sum

/-- Independent remaining token grammar and total slash-inclusive byte cost. -/
def PointerPayload (tokens : List Bytes) (used : Nat) : Prop :=
  (∀ token ∈ tokens, OperationIdentity.validToken token 64 = true) ∧ used + tokenCost tokens ≤ 128
instance (tokens : List Bytes) (used : Nat) : Decidable (PointerPayload tokens used) := by
  unfold PointerPayload; infer_instance

theorem pointer_payload_cons (token : Bytes) (rest : List Bytes) (used : Nat) :
    PointerPayload (token :: rest) used ↔ OperationIdentity.validToken token 64 = true ∧
      PointerPayload rest (used + token.length + 1) := by
  simp [PointerPayload, tokenCost, Nat.add_assoc, Nat.add_left_comm, Nat.add_comm]

theorem pointer_payload_refuses_overflow (token : Bytes) (rest : List Bytes) (used : Nat)
    (large : 128 < used + token.length + 1) : ¬PointerPayload (token :: rest) used := by
  intro admitted
  have bound := (pointer_payload_cons token rest used).mp admitted |>.2.2
  omega

theorem pointer_payload_earns_start_bound (tokens : List Bytes) (used : Nat)
    (admitted : PointerPayload tokens used) : used ≤ 128 := by have bound := admitted.2; omega

theorem pointer_domain_iff (tokens : List Bytes) :
    PointerDomain tokens ↔ 0 < tokens.length ∧ tokens.length ≤ 6 ∧ PointerPayload tokens 0 := by
  simp [PointerDomain, PointerPayload, tokenCost]

theorem key_position_none_iff (keys : List Bytes) (name : Bytes) :
    keyPosition name keys = none ↔ name ∉ keys := by
  induction keys with
  | nil => simp [keyPosition]
  | cons key rest ih =>
    by_cases same : key = name
    · simp [keyPosition, same]
    · simpa [keyPosition, same, Ne.symm same] using ih

def TargetAdmitted (keys tokens : List Bytes) : Prop :=
  KeyColumn keys .json ∧ PointerDomain tokens ∧
    if tokens.length = 1 then (tokens.headD []) ∉ keys ∧ keys.length < 32
    else (tokens.headD []) ∈ keys
instance (keys tokens : List Bytes) : Decidable (TargetAdmitted keys tokens) := by
  unfold TargetAdmitted; infer_instance

theorem target_admitted_compiles (keys tokens : List Bytes) (admitted : TargetAdmitted keys tokens) :
    ∃ target, jsonEchoTarget keys tokens = .ok target := by
  unfold jsonEchoTarget
  simp only [admitted.1, admitted.2.1, ↓reduceIte]
  by_cases last : tokens.length = 1
  · have insertion : (tokens.headD []) ∉ keys ∧ keys.length < 32 := by simpa [last] using admitted.2.2
    exact ⟨.insert, by simp [last, insertion.1, Nat.not_le.mpr insertion.2]⟩
  · have present : (tokens.headD []) ∈ keys := by simpa [last] using admitted.2.2
    have found : keyPosition (tokens.headD []) keys ≠ none := by
      intro missing
      exact (key_position_none_iff _ _).mp missing present
    cases selected : keyPosition (tokens.headD []) keys with
    | none => exact False.elim (found selected)
    | some index => exact ⟨.descend index, by simp [last, selected]⟩

theorem target_success_earns_admission (keys tokens : List Bytes) (target : Target)
    (run : jsonEchoTarget keys tokens = .ok target) : TargetAdmitted keys tokens := by
  have domains := target_success_retains_pointer _ _ _ run
  refine ⟨domains.1, domains.2, ?_⟩
  by_cases last : tokens.length = 1
  · have insertion : target = .insert := by
      simp only [jsonEchoTarget, domains.1, domains.2, last, ↓reduceIte] at run
      split at run
      · contradiction
      · simpa using run.symm
    subst target
    have meaning := target_insert_is_new_member _ _ run
    simpa [last] using meaning.2
  · have selected : ∃ index, target = .descend index ∧ keys[index]? = some (tokens.headD []) := by
      simp only [jsonEchoTarget, domains.1, domains.2, last, ↓reduceIte] at run
      cases found : keyPosition (tokens.headD []) keys with
      | none => simp [found] at run
      | some index => exact ⟨index, by simpa [found] using run.symm, key_position_is_exact _ _ _ found⟩
    obtain ⟨index, same, found⟩ := selected
    simpa [last] using List.mem_iff_getElem?.mpr ⟨index, found⟩

end Auths.Product.TemplateMembers
