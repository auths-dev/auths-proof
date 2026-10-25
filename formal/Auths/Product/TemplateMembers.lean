import Auths.Product.OperationIdentity
import Mathlib.Data.List.Lex
import Mathlib.Data.List.Pairwise

namespace Auths.Product.TemplateMembers
abbrev Bytes := List Nat

inductive Domain where
  | json | form
  deriving DecidableEq
def maximum : Domain → Nat | .json => 32 | .form => 16

inductive Choice where
  | source (index : Nat)
  | echo
  deriving DecidableEq

inductive Target where
  | insert
  | descend (index : Nat)
  deriving DecidableEq

inductive Error where
  | members | echoConflict
  deriving DecidableEq

def byteLess : Bytes → Bytes → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | left :: ls, right :: rs =>
      if left < right then true else if right < left then false else byteLess ls rs

theorem byte_less_iff (left right : Bytes) : byteLess left right = true ↔ left < right := by
  induction left generalizing right with
  | nil => cases right <;> simp [byteLess, List.lt, List.Lex]
  | cons first rest ih =>
    cases right with
    | nil => simp [byteLess, List.lt, List.Lex]
    | cons other tail =>
      by_cases smaller : first < other
      · simp [byteLess, smaller]
        exact List.Lex.rel smaller
      · by_cases larger : other < first
        · have impossible : ¬List.Lex (· < ·) (first :: rest) (other :: tail) := by
            intro lex
            cases lex with
            | rel below => omega
            | cons below => omega
          simp [byteLess, smaller, larger, List.lt, impossible]
        · have same : first = other := by omega
          subst other
          simpa [byteLess, List.lt, List.lex_cons_iff] using ih tail

def KeyColumn (keys : List Bytes) (domain : Domain) : Prop :=
  0 < keys.length ∧ keys.length ≤ maximum domain ∧
    (∀ key ∈ keys, OperationIdentity.validToken key 64 = true) ∧ keys.Pairwise (· < ·)
instance (keys : List Bytes) (domain : Domain) : Decidable (KeyColumn keys domain) := by
  unfold KeyColumn; infer_instance

def formEchoValid (name : Bytes) : Bool :=
  if name.isEmpty || 130 < name.length then false else
    let position := name.findIdx (· == 91)
    if position < name.length then
      if position = 0 ∨ position + 2 ≥ name.length ∨ name.getLast? ≠ some 93 then false
      else OperationIdentity.validToken (name.take position) 64 &&
        OperationIdentity.validToken ((name.drop (position + 1)).take (name.length - position - 2)) 64
    else OperationIdentity.validToken name 64

def EchoName (domain : Domain) (name : Bytes) : Prop :=
  match domain with
  | .json => OperationIdentity.validToken name 64 = true
  | .form => formEchoValid name = true
instance (domain : Domain) (name : Bytes) : Decidable (EchoName domain name) := by
  cases domain <;> unfold EchoName <;> infer_instance

/-- The same bounded field vocabulary plus exactly one bracket pair, never
an arbitrary provider field path. -/
def FormEchoGrammar (name : Bytes) : Prop :=
  OperationIdentity.validToken name 64 = true ∨ ∃ base inner,
    name = base ++ [91] ++ inner ++ [93] ∧
    OperationIdentity.validToken base 64 = true ∧ OperationIdentity.validToken inner 64 = true

def EchoAdmitted (keys : List Bytes) (echo : Option Bytes) (domain : Domain) : Prop :=
  match echo with
  | none => True
  | some name => EchoName domain name ∧ keys.length < maximum domain ∧ name ∉ keys
instance (keys : List Bytes) (echo : Option Bytes) (domain : Domain) : Decidable (EchoAdmitted keys echo domain) := by
  cases echo <;> unfold EchoAdmitted <;> infer_instance

def Admitted (keys : List Bytes) (echo : Option Bytes) (domain : Domain) : Prop :=
  KeyColumn keys domain ∧ EchoAdmitted keys echo domain
instance (keys : List Bytes) (echo : Option Bytes) (domain : Domain) : Decidable (Admitted keys echo domain) := by
  unfold Admitted; infer_instance

def membersFrom : List Bytes → Option Bytes → Nat → Bool → Except Error (List Choice)
  | [], echo, _, inserted => .ok (if echo.isSome && !inserted then [.echo] else [])
  | key :: rest, echo, index, inserted =>
    match echo with
    | none => (membersFrom rest none (index + 1) inserted).map (Choice.source index :: ·)
    | some name =>
      if key = name then .error .echoConflict else
      if !inserted && byteLess name key then
        (membersFrom rest echo (index + 1) true).map (fun tail => .echo :: .source index :: tail)
      else (membersFrom rest echo (index + 1) inserted).map (.source index :: ·)

def canonicalMembers (keys : List Bytes) (echo : Option Bytes) (domain : Domain) : Except Error (List Choice) :=
  if KeyColumn keys domain then
    match echo with
    | none => membersFrom keys none 0 false
    | some name =>
      if EchoName domain name ∧ keys.length < maximum domain then membersFrom keys echo 0 false
      else .error .echoConflict
  else .error .members

def sourcePositions : Nat → List Bytes → List Nat
  | _, [] => []
  | start, _ :: rest => start :: sourcePositions (start + 1) rest
def sourceIndices (output : List Choice) : List Nat := output.filterMap fun choice =>
  match choice with | .source index => some index | .echo => none
def echoCount (output : List Choice) : Nat := (output.filter (· == .echo)).length

theorem source_positions_length (start : Nat) (keys : List Bytes) : (sourcePositions start keys).length = keys.length := by
  induction keys generalizing start <;> simp_all [sourcePositions]

theorem members_from_success_iff (keys : List Bytes) (echo : Option Bytes) (start : Nat) (inserted : Bool) :
    (∃ output, membersFrom keys echo start inserted = .ok output) ↔ ∀ name, echo = some name → name ∉ keys := by
  induction keys generalizing start inserted with
  | nil => simp [membersFrom]
  | cons key rest ih =>
    cases echo with
    | none => simpa [membersFrom, Except.map] using ih (start + 1) inserted
    | some name =>
      by_cases collision : key = name
      · simp [membersFrom, collision]
      · by_cases before : !inserted && byteLess name key
        · simpa [membersFrom, collision, before, Except.map, Ne.symm collision] using ih (start + 1) true
        · simpa [membersFrom, collision, before, Except.map, Ne.symm collision] using ih (start + 1) inserted

/-- Collision may be checked before constructing a selection. The refusal
is independent of the accumulated source index and previous insertion flag. -/
theorem members_from_collision_refuses (keys : List Bytes) (name : Bytes)
    (start : Nat) (inserted : Bool) (collision : name ∈ keys) :
    membersFrom keys (some name) start inserted = .error .echoConflict := by
  induction keys generalizing start inserted with
  | nil => simp at collision
  | cons key rest ih =>
      by_cases same : key = name
      · simp [membersFrom, same]
      · have remaining : name ∈ rest := by
          rcases List.mem_cons.mp collision with equal | remaining
          · exact False.elim (same equal.symm)
          · exact remaining
        by_cases before : (!inserted && byteLess name key) = true
        · simp [membersFrom, same, before, ih (start + 1) true remaining]
        · simp [membersFrom, same, before, ih (start + 1) inserted remaining]

/-- A complete collision preflight preserves every success and refusal of
the independent recursive specification, including malformed private inputs. -/
theorem members_from_preflight (keys : List Bytes) (echo : Option Bytes)
    (start : Nat) (inserted : Bool) :
    membersFrom keys echo start inserted =
      match echo with
      | none => membersFrom keys none start inserted
      | some name =>
          if name ∈ keys then .error .echoConflict
          else membersFrom keys (some name) start inserted := by
  cases echo with
  | none => rfl
  | some name =>
      by_cases collision : name ∈ keys
      · simpa only [if_pos collision] using
          members_from_collision_refuses keys name start inserted collision
      · simp only [if_neg collision]

theorem members_from_preserves_all_indices (keys : List Bytes) (echo : Option Bytes) (start : Nat)
    (inserted : Bool) (output : List Choice) (run : membersFrom keys echo start inserted = .ok output) :
    sourceIndices output = sourcePositions start keys := by
  induction keys generalizing start inserted output with
  | nil =>
    cases echo <;> cases inserted <;> simp [membersFrom] at run <;> subst output <;> rfl
  | cons key rest ih =>
    cases echo with
    | none =>
      cases tail : membersFrom rest none (start + 1) inserted with
      | error error => simp [membersFrom, tail, Except.map] at run
      | ok tail =>
        have same : .source start :: tail = output := by simpa [membersFrom, tail, Except.map] using run
        subst output
        simp [sourceIndices, sourcePositions, ih _ _ _ tail]
    | some name =>
      by_cases collision : key = name
      · simp [membersFrom, collision] at run
      · by_cases before : !inserted && byteLess name key
        · cases tail : membersFrom rest (some name) (start + 1) true with
          | error error => simp [membersFrom, collision, before, tail, Except.map] at run
          | ok tail =>
            have same : .echo :: .source start :: tail = output := by simpa [membersFrom, collision, before, tail, Except.map] using run
            subst output
            simp [sourceIndices, sourcePositions, ih _ _ _ tail]
        · cases tail : membersFrom rest (some name) (start + 1) inserted with
          | error error => simp [membersFrom, collision, before, tail, Except.map] at run
          | ok tail =>
            have same : .source start :: tail = output := by simpa [membersFrom, collision, before, tail, Except.map] using run
            subst output
            simp [sourceIndices, sourcePositions, ih _ _ _ tail]

theorem members_from_echo_count (keys : List Bytes) (echo : Option Bytes) (start : Nat)
    (inserted : Bool) (output : List Choice) (run : membersFrom keys echo start inserted = .ok output) :
    echoCount output = if echo.isSome && !inserted then 1 else 0 := by
  induction keys generalizing start inserted output with
  | nil =>
    cases echo <;> cases inserted <;> simp [membersFrom] at run <;> subst output <;> rfl
  | cons key rest ih =>
    cases echo with
    | none =>
      cases tail : membersFrom rest none (start + 1) inserted <;>
        simp_all [membersFrom, echoCount, Except.map]
    | some name =>
      by_cases collision : key = name
      · simp [membersFrom, collision] at run
      · cases inserted <;> by_cases before : byteLess name key = true <;>
          simp only [membersFrom, collision, Bool.not_false, Bool.not_true, Bool.true_and, Bool.false_and,
            before, ↓reduceIte] at run <;>
          cases tail : membersFrom rest (some name) (start + 1) true <;>
          cases other : membersFrom rest (some name) (start + 1) false <;>
          simp_all [Except.map, echoCount]

theorem canonical_success_earns_admission (keys : List Bytes) (echo : Option Bytes) (domain : Domain)
    (output : List Choice) (run : canonicalMembers keys echo domain = .ok output) : Admitted keys echo domain := by
  unfold canonicalMembers at run
  split at run
  · rename_i column
    cases echo with
    | none => exact ⟨column, trivial⟩
    | some name =>
      split at run
      · rename_i admitted
        have absent := (members_from_success_iff keys (some name) 0 false).mp ⟨output, run⟩ name rfl
        exact ⟨column, admitted.1, admitted.2, absent⟩
      · contradiction
  · contradiction

theorem canonical_useful_acceptance (keys : List Bytes) (echo : Option Bytes) (domain : Domain)
    (admitted : Admitted keys echo domain) : ∃ output, canonicalMembers keys echo domain = .ok output := by
  have run := (members_from_success_iff keys echo 0 false).mpr (by
    intro name same
    subst echo
    exact admitted.2.2.2)
  cases echo with
  | none => simpa [canonicalMembers, admitted.1] using run
  | some name => simpa [canonicalMembers, admitted.1, admitted.2.1, admitted.2.2.1] using run

theorem canonical_success_preserves_source (keys : List Bytes) (echo : Option Bytes) (domain : Domain)
    (output : List Choice) (run : canonicalMembers keys echo domain = .ok output) :
    sourceIndices output = sourcePositions 0 keys ∧ echoCount output = if echo.isSome then 1 else 0 := by
  have admitted := canonical_success_earns_admission _ _ _ _ run
  have merge : membersFrom keys echo 0 false = .ok output := by
    cases echo with
    | none => simpa [canonicalMembers, admitted.1] using run
    | some name => simpa [canonicalMembers, admitted.1, admitted.2.1, admitted.2.2.1] using run
  exact ⟨members_from_preserves_all_indices _ _ _ _ _ merge, by
    simpa using members_from_echo_count _ _ _ _ _ merge⟩

def PointerDomain (tokens : List Bytes) : Prop :=
  0 < tokens.length ∧ tokens.length ≤ 6 ∧
    (∀ token ∈ tokens, OperationIdentity.validToken token 64 = true) ∧
    (tokens.map (fun token => token.length + 1)).sum ≤ 128
instance (tokens : List Bytes) : Decidable (PointerDomain tokens) := by unfold PointerDomain; infer_instance

def keyPosition (name : Bytes) : List Bytes → Option Nat
  | [] => none
  | key :: rest => if key = name then some 0 else (keyPosition name rest).map (· + 1)

def jsonEchoTarget (keys tokens : List Bytes) : Except Error Target :=
  if KeyColumn keys .json then
    if PointerDomain tokens then
      if tokens.length = 1 then
        if (tokens.headD []) ∈ keys ∨ keys.length ≥ 32 then .error .echoConflict else .ok .insert
      else match keyPosition (tokens.headD []) keys with
        | none => .error .echoConflict
        | some index => .ok (.descend index)
    else .error .echoConflict
  else .error .members

theorem key_position_is_exact (keys : List Bytes) (name : Bytes) (index : Nat)
    (found : keyPosition name keys = some index) : keys[index]? = some name := by
  induction keys generalizing index with
  | nil => simp [keyPosition] at found
  | cons key rest ih =>
    by_cases same : key = name
    · simp [keyPosition, same] at found
      simp [← found, same]
    · cases tail : keyPosition name rest with
      | none => simp [keyPosition, same, tail] at found
      | some selected =>
        have equal : selected + 1 = index := by simpa [keyPosition, same, tail] using found
        subst index
        simpa using ih selected tail

theorem target_success_retains_pointer (keys tokens : List Bytes) (target : Target)
    (run : jsonEchoTarget keys tokens = .ok target) : KeyColumn keys .json ∧ PointerDomain tokens := by
  unfold jsonEchoTarget at run
  split at run
  · rename_i keysValid
    split at run
    · rename_i pointer
      exact ⟨keysValid, pointer⟩
    · contradiction
  · contradiction

theorem target_descends_to_original_name (keys tokens : List Bytes) (index : Nat)
    (run : jsonEchoTarget keys tokens = .ok (.descend index)) :
    1 < tokens.length ∧ keys[index]? = some (tokens.headD []) := by
  have domain := target_success_retains_pointer _ _ _ run
  simp only [jsonEchoTarget, domain.1, domain.2, ↓reduceIte] at run
  split at run
  · split at run <;> contradiction
  · rename_i notLast
    cases selected : keyPosition (tokens.headD []) keys with
    | none => simp [selected] at run
    | some actual =>
      have same : actual = index := by simpa [selected] using run
      exact ⟨by omega, by simpa [same] using key_position_is_exact _ _ _ selected⟩

theorem target_insert_is_new_member (keys tokens : List Bytes)
    (run : jsonEchoTarget keys tokens = .ok .insert) :
    tokens.length = 1 ∧ (tokens.headD []) ∉ keys ∧ keys.length < 32 := by
  have domain := target_success_retains_pointer _ _ _ run
  simp only [jsonEchoTarget, domain.1, domain.2, ↓reduceIte] at run
  split at run
  · rename_i last
    split at run
    · contradiction
    · rename_i safe
      exact ⟨last, by simpa only [not_or, not_le] using safe⟩
  · cases selected : keyPosition (tokens.headD []) keys <;> simp [selected] at run

end Auths.Product.TemplateMembers
