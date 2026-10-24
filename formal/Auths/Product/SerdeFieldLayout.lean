import Auths.Product.FullJsonValue

/-!
Independent field binding for the actual serde derive representations. Structs
accept maps AND positional sequences; defaults apply only to missing fields,
not to present nulls. This binds original full values before field-type
decoding. It is not an implementation or adequacy theorem for serde.
-/
namespace Auths.Product.SerdeFieldLayout

abbrev Json := FullJsonValue.Value

inductive Missing where
  | required
  | null
  | emptyArray
  deriving DecidableEq

def Missing.value : Missing → Except Unit Json
  | .required => .error ()
  | .null => .ok .null
  | .emptyArray => .ok (.array [])

structure Field (K : Type) where
  name : String
  kind : K
  onMissing : Missing

def lookup (name : String) : List (String × Json) → Option Json
  | [] => none
  | (key, value) :: rest => if key = name then some value else lookup name rest

def fillMap {K : Type} : List (Field K) → List (String × Json) → Except Unit (List Json)
  | [], _ => .ok []
  | field :: rest, members => do
      let value ← match lookup field.name members with
        | some value => .ok value
        | none => field.onMissing.value
      let values ← fillMap rest members
      pure (value :: values)

def fillSequence {K : Type} : List (Field K) → List Json → Except Unit (List Json)
  | [], [] => .ok []
  | [], _ :: _ => .error ()
  | field :: rest, [] => do
      let value ← field.onMissing.value
      let values ← fillSequence rest []
      pure (value :: values)
  | _ :: rest, value :: values => do
      let tail ← fillSequence rest values
      pure (value :: tail)

def normalize {K : Type} (fields : List (Field K)) : Json → Except Unit (List Json)
  | .object members =>
      if (members.map Prod.fst).Nodup ∧
          members.all (fun member => (fields.map Field.name).contains member.1) = true then
        fillMap fields members
      else .error ()
  | .array values => fillSequence fields values
  | _ => .error ()

def Assignment {K : Type} (members : List (String × Json)) (field : Field K) (value : Json) : Prop :=
  lookup field.name members = some value ∨
    lookup field.name members = none ∧ field.onMissing.value = .ok value

theorem fill_map_preserves_original_values {K : Type} (fields : List (Field K))
    (members : List (String × Json)) (values : List Json)
    (success : fillMap fields members = .ok values) : List.Forall₂ (Assignment members) fields values := by
  induction fields generalizing values with
  | nil => simp [fillMap] at success; subst values; exact .nil
  | cons field rest ih =>
      cases found : lookup field.name members with
      | some value =>
          cases tailAt : fillMap rest members with
          | error error => simp [fillMap, found, tailAt] at success
          | ok tail =>
              simp [fillMap, found, tailAt] at success
              subst values
              exact .cons (Or.inl found) (ih tail tailAt)
      | none =>
          cases defaultAt : field.onMissing.value with
          | error error => simp [fillMap, found, defaultAt] at success
          | ok value =>
              cases tailAt : fillMap rest members with
              | error error => simp [fillMap, found, defaultAt, tailAt] at success
              | ok tail =>
                  simp [fillMap, found, defaultAt, tailAt] at success
                  subst values
                  exact .cons (Or.inr ⟨found, defaultAt⟩) (ih tail tailAt)

theorem fill_map_complete_count {K : Type} (fields : List (Field K))
    (members : List (String × Json)) (values : List Json)
    (success : fillMap fields members = .ok values) : values.length = fields.length := by
  have original := fill_map_preserves_original_values fields members values success
  exact original.length_eq.symm

theorem fill_sequence_complete_count {K : Type} (fields : List (Field K))
    (input values : List Json) (success : fillSequence fields input = .ok values) :
    values.length = fields.length := by
  induction fields generalizing input values with
  | nil => cases input <;> simp [fillSequence] at success; subst values; rfl
  | cons field rest ih =>
      cases input with
      | nil =>
          cases defaultAt : field.onMissing.value with
          | error error => simp [fillSequence, defaultAt] at success
          | ok value =>
              cases tailAt : fillSequence rest [] with
              | error error => simp [fillSequence, defaultAt, tailAt] at success
              | ok tail =>
                  simp [fillSequence, defaultAt, tailAt] at success
                  subst values
                  simpa only [List.length_cons] using congrArg Nat.succ (ih [] tail tailAt)
      | cons value tail =>
          cases tailAt : fillSequence rest tail with
          | error error => simp [fillSequence, tailAt] at success
          | ok output =>
              simp [fillSequence, tailAt] at success
              subst values
              simpa only [List.length_cons] using congrArg Nat.succ (ih tail output tailAt)

theorem fill_sequence_retains_supplied_prefix {K : Type} (fields : List (Field K))
    (input values : List Json) (success : fillSequence fields input = .ok values) :
    input.length ≤ fields.length ∧ values.take input.length = input := by
  induction fields generalizing input values with
  | nil => cases input <;> simp [fillSequence] at success; subst values; simp
  | cons field rest ih =>
      cases input with
      | nil => simp
      | cons value tail =>
          cases tailAt : fillSequence rest tail with
          | error error => simp [fillSequence, tailAt] at success
          | ok output =>
              simp [fillSequence, tailAt] at success
              subst values
              obtain ⟨bound, prefix⟩ := ih tail output tailAt
              exact ⟨by simp only [List.length_cons]; omega, by simpa using congrArg (List.cons value) prefix⟩

theorem normalized_complete_count {K : Type} (fields : List (Field K)) (input : Json)
    (values : List Json) (success : normalize fields input = .ok values) :
    values.length = fields.length := by
  cases input with
  | object members =>
      unfold normalize at success
      split at success
      · exact fill_map_complete_count fields members values success
      · simp at success
  | array input => exact fill_sequence_complete_count fields input values success
  | null | boolean _ | number _ | text _ => simp [normalize] at success

theorem assignment_retains_present_value {K : Type} (field : Field K)
    (members : List (String × Json)) (original assigned : Json)
    (present : lookup field.name members = some original)
    (bound : Assignment members field assigned) : assigned = original := by
  rcases bound with found | ⟨missing, _⟩
  · exact Option.some.inj (found.symm.trans present)
  · rw [present] at missing
    cases missing

theorem normalize_refuses_duplicate_names {K : Type} (fields : List (Field K))
    (members : List (String × Json)) (repeated : ¬ (members.map Prod.fst).Nodup) :
    normalize fields (.object members) = .error () := by
  simp [normalize, repeated]

theorem normalize_refuses_unknown_member {K : Type} (fields : List (Field K))
    (members : List (String × Json)) (member : String × Json) (present : member ∈ members)
    (unknown : member.1 ∉ fields.map Field.name) : normalize fields (.object members) = .error () := by
  have notKnown : members.all (fun pair => (fields.map Field.name).contains pair.1) ≠ true := by
    intro allKnown
    have known := List.all_eq_true.mp allKnown member present
    exact unknown (List.contains_iff_mem.mp known)
  simp [normalize, notKnown]

inductive Mode where
  | direct
  | buffered
  deriving DecidableEq

/-- Raw JSON identifiers require strings. Serde's buffered ContentDeserializer
also accepts an unsigned declaration index. The caller must preserve this
mode transition when an internally tagged enum buffers its content. -/
def identifier (mode : Mode) (names : List String) : Json → Except Unit String
  | .text name => if name ∈ names then .ok name else .error ()
  | .number (.unsigned index) =>
      match mode with
      | .direct => .error ()
      | .buffered => match names[index]? with
          | some name => .ok name
          | none => .error ()
  | _ => .error ()

def internal (mode : Mode) (names : List String) : Json → Except Unit (String × Json)
  | .object members => do
      let tag ← match lookup "kind" members with
        | some value => identifier mode names value
        | none => .error ()
      pure (tag, .object (members.filter (fun member => member.1 != "kind")))
  | .array (tag :: rest) => do
      let name ← identifier mode names tag
      pure (name, .array rest)
  | _ => .error ()

/-- Serde's internally tagged unit visitor consumes and ignores a complete
map. A sequence is admitted only when empty, because ContentDeserializer
checks the remaining sequence length after the unit visitor returns. -/
def unitContent : Json → Bool
  | .object _ | .array [] => true
  | _ => false

/-- Owned buffered ContentDeserializer permits an empty-map unit payload;
direct serde_json unit decoding requires null. Keep that context explicit. -/
def externalUnit (mode : Mode) (names : List String) : Json → Except Unit String
  | .text name => if name ∈ names then .ok name else .error ()
  | .object [(name, payload)] =>
      if name ∈ names ∧ (payload = .null ∨ mode = .buffered ∧ payload = .object []) then
        .ok name else .error ()
  | _ => .error ()

theorem identifier_retains_declared_name (mode : Mode) (names : List String) (input : Json)
    (name : String) (success : identifier mode names input = .ok name) : name ∈ names := by
  cases input with
  | text value =>
      by_cases known : value ∈ names
      · simp [identifier, known] at success; subst name; exact known
      · simp [identifier, known] at success
  | number number =>
      cases number with
      | signed _ | floating _ => simp [identifier] at success
      | unsigned index =>
          cases mode with
          | direct => simp [identifier] at success
          | buffered =>
              cases selected : names[index]? with
              | none => simp [identifier, selected] at success
              | some value =>
                  simp [identifier, selected] at success
                  subst name
                  exact List.mem_of_getElem? selected
  | null | boolean _ | array _ | object _ => simp [identifier] at success

end Auths.Product.SerdeFieldLayout
