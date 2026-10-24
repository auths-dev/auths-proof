import Auths.Product.SchemaIndex

/-!
Named scalar environments are independent of compiled positional plans. The
acceptance relation below requires exact names and complete values; it does
not infer schema validity or verified provenance from a successful binding.
-/
namespace Auths.Product.ArgumentBinding

open RequestConstruction
abbrev Name := SchemaIndex.Name
abbrev Environment := List (Name × Arg)

def lookup (name : Name) : Environment → Option Arg
  | [] => none
  | (key, value) :: rest => if key = name then some value else lookup name rest

def project : List Name → Environment → Except ConstructError (List Arg)
  | [], _ => .ok []
  | name :: rest, supplied =>
    match lookup name supplied with
    | none => .error .argumentMismatch
    | some value => (project rest supplied).map (value :: ·)

def bind (fields : List Name) (supplied : Environment) : Except ConstructError (List Arg) :=
  if 32 < fields.length ∨ supplied.length ≠ fields.length ∨ ¬fields.Nodup then
    .error .argumentMismatch
  else project fields supplied

def FirstPositions (fields : List Name) : Prop :=
  ∀ index name, fields[index]? = some name → SchemaIndex.position fields name = some index

theorem nodup_iff_first_positions (fields : List Name) :
    fields.Nodup ↔ FirstPositions fields := by
  induction fields with
  | nil => simp [FirstPositions]
  | cons head rest ih =>
    constructor
    · intro unique index name atName
      obtain ⟨absent, tailUnique⟩ := List.nodup_cons.mp unique
      cases index with
      | zero =>
        have same : head = name := by simpa using atName
        simp [SchemaIndex.position, same]
      | succ index =>
        have tailAt : rest[index]? = some name := by simpa using atName
        have member : name ∈ rest := List.mem_iff_getElem?.mpr ⟨index, tailAt⟩
        have different : head ≠ name := fun same => absent (by simpa [same] using member)
        simp [SchemaIndex.position, different, ih.mp tailUnique index name tailAt]
    · intro first
      have absent : head ∉ rest := by
        intro member
        obtain ⟨index, atName⟩ := List.mem_iff_getElem?.mp member
        have actual := first (index + 1) head (by simpa using atName)
        simp [SchemaIndex.position] at actual
      refine List.nodup_cons.mpr ⟨absent, ih.mpr ?_⟩
      intro index name atName
      have member : name ∈ rest := List.mem_iff_getElem?.mpr ⟨index, atName⟩
      have different : head ≠ name := fun same => absent (by simpa [same] using member)
      have actual := first (index + 1) name (by simpa using atName)
      cases found : SchemaIndex.position rest name <;>
        simp_all [SchemaIndex.position]

theorem lookup_member (name : Name) (supplied : Environment) (value : Arg)
    (found : lookup name supplied = some value) : (name, value) ∈ supplied := by
  induction supplied with
  | nil => simp [lookup] at found
  | cons entry rest ih =>
    obtain ⟨key, actual⟩ := entry
    by_cases same : key = name
    · simp [lookup, same] at found
      simp [same, found]
    · simp only [lookup, same, ↓reduceIte] at found
      exact List.mem_cons_of_mem _ (ih found)

private theorem move_to_front {α : Type} (head : α) (prefix suffix : List α) :
    (prefix ++ head :: suffix).Perm (head :: (prefix ++ suffix)) := by
  induction prefix with
  | nil => simp
  | cons first rest ih =>
    exact (List.Perm.cons first ih).trans (List.Perm.swap _ _ _)

/-- Equal lengths plus coverage of a unique list exclude every extra or
duplicate member. This is a finite-list argument independent of the binder's
first-match implementation. -/
private theorem permutation_of_unique_cover {α : Type} [DecidableEq α]
    (expected supplied : List α) (unique : expected.Nodup)
    (covered : expected ⊆ supplied) (lengths : supplied.length = expected.length) :
    supplied.Perm expected := by
  induction expected generalizing supplied with
  | nil =>
    have empty : supplied = [] := List.length_eq_zero.mp (by simpa using lengths)
    simp [empty]
  | cons head rest ih =>
    obtain ⟨absent, restUnique⟩ := List.nodup_cons.mp unique
    have member : head ∈ supplied := covered (by simp)
    obtain ⟨prefix, suffix, split⟩ := List.mem_split member
    subst supplied
    have remaining : rest ⊆ prefix ++ suffix := by
      intro value inRest
      have different : value ≠ head := by
        intro same
        exact absent (same ▸ inRest)
      have inSupplied := covered (List.mem_cons_of_mem head inRest)
      simpa [List.mem_append, different] using inSupplied
    have tailLengths : (prefix ++ suffix).length = rest.length := by
      simp only [List.length_append, List.length_cons] at lengths ⊢
      omega
    exact (move_to_front head prefix suffix).trans
      (List.Perm.cons head (ih (prefix ++ suffix) restUnique remaining tailLengths))

/-- A successful projection earns the relation formerly supplied as a caller
premise to the source-level name/index rendering theorem. -/
theorem project_earns_alignment (fields : List Name) (supplied : Environment)
    (values : List Arg) (accepted : project fields supplied = .ok values) :
    SchemaIndex.Aligned fields values (fun name => lookup name supplied) := by
  induction fields generalizing values with
  | nil =>
    simp [project] at accepted
    subst values
    exact ⟨rfl, by simp⟩
  | cons name rest ih =>
    cases suppliedAt : lookup name supplied with
    | none => simp [project, suppliedAt] at accepted
    | some value =>
      cases remaining : project rest supplied with
      | error error => simp [project, suppliedAt, remaining] at accepted
      | ok tail =>
        have same : value :: tail = values := by
          simpa [project, suppliedAt, remaining] using accepted
        subst values
        obtain ⟨lengths, aligned⟩ := ih tail remaining
        refine ⟨by simp [lengths], ?_⟩
        intro index wanted atName
        cases index with
        | zero =>
          have sameName : name = wanted := by simpa using atName
          simp [← sameName, suppliedAt]
        | succ index => exact aligned index wanted (by simpa using atName)

theorem bind_earns_layout (fields : List Name) (supplied : Environment)
    (values : List Arg) (accepted : bind fields supplied = .ok values) :
    fields.length ≤ 32 ∧ fields.Nodup ∧ supplied.length = fields.length ∧
      SchemaIndex.Aligned fields values (fun name => lookup name supplied) := by
  unfold bind at accepted
  split at accepted
  · contradiction
  · rename_i admitted
    have shape : fields.length ≤ 32 ∧ supplied.length = fields.length ∧ fields.Nodup := by
      push_neg at admitted
      exact ⟨admitted.1, admitted.2.1, admitted.2.2⟩
    exact ⟨shape.1, shape.2.2, shape.2.1, project_earns_alignment _ _ _ accepted⟩

/-- An accepting layout consumes exactly the supplied field names. It cannot
silently drop an extra value or accept two supplied values under one name. -/
theorem bind_earns_exact_names (fields : List Name) (supplied : Environment)
    (values : List Arg) (accepted : bind fields supplied = .ok values) :
    (supplied.map Prod.fst).Perm fields := by
  obtain ⟨bounded, unique, lengths, aligned⟩ := bind_earns_layout _ _ _ accepted
  apply permutation_of_unique_cover fields (supplied.map Prod.fst) unique
  · intro name member
    obtain ⟨index, atName⟩ := List.mem_iff_getElem?.mp member
    have inside : index < fields.length := (List.getElem?_eq_some_iff.mp atName).1
    have valuesInside : index < values.length := by omega
    have atValue : values[index]? = some values[index] := List.getElem?_eq_getElem valuesInside
    have found : lookup name supplied = some values[index] := by
      rw [← aligned.2 index name atName]
      exact atValue
    exact List.mem_map.mpr ⟨(name, values[index]), lookup_member _ _ _ found, rfl⟩
  · simpa using lengths

theorem bind_excludes_duplicate_supplied_names (fields : List Name) (supplied : Environment)
    (values : List Arg) (accepted : bind fields supplied = .ok values) :
    (supplied.map Prod.fst).Nodup :=
  (bind_earns_exact_names fields supplied values accepted).nodup_iff.mpr
    (bind_earns_layout _ _ _ accepted).2.1

/-- Referenced names select the same complete scalar before and after
lowering. No alignment or expected output is a premise: binding earns it. -/
theorem binding_then_index_is_named (fields : List Name) (supplied : Environment)
    (values : List Arg) (name : Name) (index : Nat)
    (accepted : bind fields supplied = .ok values)
    (lowered : SchemaIndex.position fields name = some index) :
    values[index]? = lookup name supplied :=
  SchemaIndex.indexed_argument_is_named fields values (fun name => lookup name supplied)
    (bind_earns_layout _ _ _ accepted).2.2.2 name index lowered

theorem binding_then_path_preserves_named_value
    (fields : List Name) (supplied : Environment) (values : List Arg)
    (name : Name) (index : Nat) (bytes : Bytes)
    (accepted : bind fields supplied = .ok values)
    (lowered : SchemaIndex.position fields name = some index)
    (provided : lookup name supplied = some (.text bytes)) :
    segmentBytes values (.field index) = pathEncode bytes :=
  SchemaIndex.field_rendering_preserved fields values (fun name => lookup name supplied)
    (bind_earns_layout _ _ _ accepted).2.2.2 name index bytes lowered provided

theorem project_complete (fields : List Name) (supplied : Environment)
    (present : ∀ name ∈ fields, lookup name supplied ≠ none) :
    ∃ values, project fields supplied = .ok values := by
  induction fields with
  | nil => exact ⟨[], rfl⟩
  | cons name rest ih =>
    cases found : lookup name supplied with
    | none => exact False.elim (present name (by simp) found)
    | some value =>
      obtain ⟨tail, remaining⟩ := ih (fun name member => present name (by simp [member]))
      exact ⟨value :: tail, by simp [project, found, remaining]⟩

/-- The accepted domain contains every complete unique bounded field layout,
including useful scalar values rather than only empty inputs. -/
theorem complete_layout_accepts (fields : List Name) (supplied : Environment)
    (bounded : fields.length ≤ 32) (unique : fields.Nodup)
    (lengths : supplied.length = fields.length)
    (present : ∀ name ∈ fields, lookup name supplied ≠ none) :
    ∃ values, bind fields supplied = .ok values := by
  obtain ⟨values, run⟩ := project_complete fields supplied present
  exact ⟨values, by simp [bind, Nat.not_lt.mpr bounded, unique, lengths, run]⟩

end Auths.Product.ArgumentBinding
