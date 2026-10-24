import Auths.Product.NativeCompilerSchemaModel

/-!
Independent decoded-field and finite rule-map semantics. Names are decoded
losslessly from original bytes. A byte outside 0..255 is rejected before UInt8
construction, so the model cannot admit an alias created by modular conversion.
The finite-map primitive below has ordinary String order and replacement
semantics; the Auths rule builder must reject replacement, not silently accept it.
-/
namespace Auths.Product.NativeCompiler.Rules
open FieldProjection ScalarProjection
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

abbrev Entry := String × Schema

def ByteRange (raw : List Nat) : Prop := ∀ byte ∈ raw, byte < 256
instance (raw : List Nat) : Decidable (ByteRange raw) := by unfold ByteRange; infer_instance

def nameBytes (raw : List Nat) : ByteArray := (raw.map UInt8.ofNat).toByteArray

def decodeName (raw : List Nat) : Option String :=
  if ByteRange raw then String.fromUTF8? (nameBytes raw) else none

def insert {V : Type} (key : String) (value : V) : List (String × V) → Option V × List (String × V)
  | [] => (none, [(key, value)])
  | (previousKey, previousValue) :: rest =>
      match compare key previousKey with
      | .lt => (none, (key, value) :: (previousKey, previousValue) :: rest)
      | .eq => (some previousValue, (previousKey, value) :: rest)
      | .gt =>
          let (replaced, updated) := insert key value rest
          (replaced, (previousKey, previousValue) :: updated)

def Sorted {V : Type} (entries : List (String × V)) : Prop :=
  entries.Pairwise (fun first second => first.1 < second.1)

def decodeFields : List Field → Option (List Entry)
  | [] => some []
  | field :: rest => do
      let name ← decodeName field.name
      let decoded ← decodeFields rest
      some ((name, field.schema) :: decoded)

def Admitted (fields : List Field) : Prop :=
  ∃ decoded, decodeFields fields = some decoded ∧ (decoded.map Prod.fst).Nodup

/-- Complete original field associations, unique native names, and canonical
map order. No expected map, selected key/index or builder-success flag occurs. -/
def Meaning (fields : List Field) (entries : List Entry) : Prop :=
  ∃ decoded, decodeFields fields = some decoded ∧ (decoded.map Prod.fst).Nodup ∧
    entries.Perm decoded ∧ Sorted entries

def DecodedField (original : Field) (entry : Entry) : Prop :=
  decodeName original.name = some entry.1 ∧ entry.2 = original.schema

def buildDecoded (prefix : List Entry) : List Entry → Except Unit (List Entry)
  | [] => .ok prefix
  | (name, schema) :: rest =>
      let (previous, updated) := insert name schema prefix
      if previous.isSome then .error () else buildDecoded updated rest

def build (prefix : List Entry) : List Field → Except Unit (List Entry)
  | [] => .ok prefix
  | field :: rest =>
      match decodeName field.name with
      | none => .error ()
      | some name =>
          let (previous, updated) := insert name field.schema prefix
          if previous.isSome then .error () else build updated rest

theorem insert_length {V : Type} (key : String) (value : V) (entries : List (String × V)) :
    (insert key value entries).2.length ≤ entries.length + 1 := by
  induction entries with
  | nil => simp [insert]
  | cons first rest ih =>
      rcases first with ⟨previousKey, previousValue⟩
      cases comparison : compare key previousKey <;> simp [insert, comparison] <;> omega

theorem insert_map {V W : Type} (view : V → W) (key : String) (value : V) (entries : List (String × V)) :
    ((insert key value entries).1.map view,
      (insert key value entries).2.map (fun entry => (entry.1, view entry.2))) =
      insert key (view value) (entries.map (fun entry => (entry.1, view entry.2))) := by
  induction entries with
  | nil => rfl
  | cons first rest ih =>
      rcases first with ⟨previousKey, previousValue⟩
      cases comparison : compare key previousKey <;> simp [insert, comparison, ← ih]

theorem inserted_entry_is_original_or_new {V : Type} (key : String) (value : V)
    (entries : List (String × V)) (entry : String × V)
    (present : entry ∈ (insert key value entries).2) : entry = (key, value) ∨ entry ∈ entries := by
  induction entries with
  | nil => simpa [insert] using present
  | cons first rest ih =>
      rcases first with ⟨previousKey, previousValue⟩
      cases comparison : compare key previousKey with
      | lt => simpa [insert, comparison, List.mem_cons, or_assoc] using present
      | eq =>
          have same : key = previousKey := Std.compare_eq_iff_eq.mp comparison
          have found : entry = (previousKey, value) ∨ entry ∈ rest := by
            simpa [insert, comparison] using present
          rcases found with rfl | tail
          · exact Or.inl (by simp only [same])
          · exact Or.inr (List.mem_cons_of_mem _ tail)
      | gt =>
          have found : entry = (previousKey, previousValue) ∨ entry ∈ (insert key value rest).2 := by
            simpa [insert, comparison] using present
          rcases found with rfl | tail
          · exact Or.inr (by simp)
          · rcases ih tail with new | original
            · exact Or.inl new
            · exact Or.inr (by simp [original])

theorem insert_preserves_order {V : Type} (key : String) (value : V)
    (entries : List (String × V)) (ordered : Sorted entries) : Sorted (insert key value entries).2 := by
  induction entries with
  | nil => simp [insert, Sorted]
  | cons first rest ih =>
      rcases first with ⟨previousKey, previousValue⟩
      obtain ⟨headBefore, tailOrder⟩ := List.pairwise_cons.mp ordered
      cases comparison : compare key previousKey with
      | lt =>
          have before : key < previousKey := compare_lt_iff_lt.mp comparison
          simp only [insert, comparison]
          apply List.pairwise_cons.mpr
          refine ⟨?_, ordered⟩
          intro entry member
          rcases List.mem_cons.mp member with rfl | tail
          · exact before
          · exact lt_trans before (headBefore entry tail)
      | eq =>
          simpa only [insert, comparison] using (List.pairwise_cons.mpr ⟨headBefore, tailOrder⟩ :
            ((previousKey, value) :: rest).Pairwise (fun first second => first.1 < second.1))
      | gt =>
          have before : previousKey < key := compare_gt_iff_gt.mp comparison
          simp only [insert, comparison]
          change Sorted ((previousKey, previousValue) :: (insert key value rest).2)
          apply List.pairwise_cons.mpr
          refine ⟨?_, ih tailOrder⟩
          intro entry member
          rcases inserted_entry_is_original_or_new key value rest entry member with rfl | original
          · exact before
          · exact headBefore entry original

theorem sorted_keys_unique {V : Type} (entries : List (String × V)) (ordered : Sorted entries) :
    (entries.map Prod.fst).Nodup := by
  induction entries with
  | nil => simp
  | cons first rest ih =>
      obtain ⟨before, tailOrder⟩ := List.pairwise_cons.mp ordered
      apply List.nodup_cons.mpr
      refine ⟨?_, ih tailOrder⟩
      intro found
      obtain ⟨entry, member, same⟩ := List.mem_map.mp found
      have strict := before entry member
      simp only [same] at strict
      exact lt_irrefl _ strict

theorem insert_none_iff_absent {V : Type} (key : String) (value : V)
    (entries : List (String × V)) (ordered : Sorted entries) :
    (insert key value entries).1 = none ↔ key ∉ entries.map Prod.fst := by
  induction entries with
  | nil => simp [insert]
  | cons first rest ih =>
      rcases first with ⟨previousKey, previousValue⟩
      obtain ⟨headBefore, tailOrder⟩ := List.pairwise_cons.mp ordered
      cases comparison : compare key previousKey with
      | lt =>
          have before : key < previousKey := compare_lt_iff_lt.mp comparison
          have absent : key ∉ ((previousKey, previousValue) :: rest).map Prod.fst := by
            intro found
            rcases List.mem_cons.mp found with same | tail
            · exact (ne_of_lt before) same
            · obtain ⟨entry, member, same⟩ := List.mem_map.mp tail
              have after := headBefore entry member
              rw [same] at after
              exact lt_asymm before after
          simp [insert, comparison, absent]
      | eq =>
          have same : key = previousKey := Std.compare_eq_iff_eq.mp comparison
          simp [insert, comparison, same]
      | gt =>
          have different : key ≠ previousKey := ne_of_gt (compare_gt_iff_gt.mp comparison)
          simpa [insert, comparison, different, eq_comm] using ih tailOrder

theorem insert_without_replacement_perm {V : Type} (key : String) (value : V)
    (entries : List (String × V)) (fresh : (insert key value entries).1 = none) :
    (insert key value entries).2.Perm ((key, value) :: entries) := by
  induction entries with
  | nil => exact .refl _
  | cons first rest ih =>
      rcases first with ⟨previousKey, previousValue⟩
      cases comparison : compare key previousKey with
      | lt => simp only [insert, comparison]; exact .refl _
      | eq => simp [insert, comparison] at fresh
      | gt =>
          have tailFresh : (insert key value rest).1 = none := by simpa [insert, comparison] using fresh
          simpa only [insert, comparison] using
            (List.Perm.cons (previousKey, previousValue) (ih tailFresh)).trans (List.Perm.swap _ _ _)

private theorem move_to_front {T : Type} (head : T) (prefix suffix : List T) :
    (prefix ++ head :: suffix).Perm (head :: (prefix ++ suffix)) := by
  induction prefix with
  | nil => exact .refl _
  | cons first rest ih => exact (List.Perm.cons first ih).trans (List.Perm.swap _ _ _)

private theorem insertion_and_tail {V : Type} (key : String) (value : V)
    (prefix tail : List (String × V)) (fresh : (insert key value prefix).1 = none) :
    ((insert key value prefix).2 ++ tail).Perm (prefix ++ (key, value) :: tail) := by
  exact ((insert_without_replacement_perm key value prefix fresh).append (.refl tail)).trans
    (by simpa only [List.cons_append] using (move_to_front (key, value) prefix tail).symm)

theorem decode_fields_original (fields : List Field) (decoded : List Entry)
    (parsed : decodeFields fields = some decoded) : List.Forall₂ DecodedField fields decoded := by
  induction fields generalizing decoded with
  | nil => simp [decodeFields] at parsed; subst decoded; exact .nil
  | cons field rest ih =>
      cases nameAt : decodeName field.name with
      | none => simp [decodeFields, nameAt] at parsed
      | some name =>
          cases restAt : decodeFields rest with
          | none => simp [decodeFields, nameAt, restAt] at parsed
          | some tail =>
              have same : decoded = (name, field.schema) :: tail := by
                simpa [decodeFields, nameAt, restAt] using parsed.symm
              subst decoded
              exact .cons ⟨nameAt, rfl⟩ (ih tail restAt)

theorem build_decoded_source (prefix : List Entry) (fields : List Field) :
    build prefix fields = match decodeFields fields with
      | none => .error () | some decoded => buildDecoded prefix decoded := by
  induction fields generalizing prefix with
  | nil => rfl
  | cons field rest ih =>
      cases nameAt : decodeName field.name with
      | none => simp [build, decodeFields, nameAt]
      | some name =>
          cases previous : (insert name field.schema prefix).1 <;>
            cases tailAt : decodeFields rest <;>
            simp [build, decodeFields, buildDecoded, nameAt, previous, tailAt, ih]

theorem decoded_build_sound (prefix rows output : List Entry) (ordered : Sorted prefix)
    (built : buildDecoded prefix rows = .ok output) :
    ((prefix ++ rows).map Prod.fst).Nodup ∧ output.Perm (prefix ++ rows) ∧ Sorted output := by
  induction rows generalizing prefix output with
  | nil =>
      simp [buildDecoded] at built
      subst output
      exact ⟨by simpa using sorted_keys_unique prefix ordered, by simp, ordered⟩
  | cons first rest ih =>
      rcases first with ⟨name, schema⟩
      cases previous : (insert name schema prefix).1 with
      | some old => simp [buildDecoded, previous] at built
      | none =>
          have tailBuilt : buildDecoded (insert name schema prefix).2 rest = .ok output := by
            simpa [buildDecoded, previous] using built
          obtain ⟨unique, complete, sorted⟩ := ih _ _ (insert_preserves_order name schema prefix ordered) tailBuilt
          have whole := insertion_and_tail name schema prefix rest previous
          exact ⟨(whole.map Prod.fst).nodup_iff.mp unique, complete.trans whole, sorted⟩

theorem decoded_build_useful (prefix rows : List Entry) (ordered : Sorted prefix)
    (unique : ((prefix ++ rows).map Prod.fst).Nodup) :
    ∃ output, buildDecoded prefix rows = .ok output := by
  induction rows generalizing prefix with
  | nil => exact ⟨prefix, rfl⟩
  | cons first rest ih =>
      rcases first with ⟨name, schema⟩
      have frontUnique : (((name, schema) :: (prefix ++ rest)).map Prod.fst).Nodup :=
        ((move_to_front (name, schema) prefix rest).map Prod.fst).nodup_iff.mp unique
      have absent : name ∉ prefix.map Prod.fst := by
        intro found
        exact (List.nodup_cons.mp frontUnique).1 (by simp only [List.map_append, List.mem_append]; exact Or.inl found)
      have fresh : (insert name schema prefix).1 = none := (insert_none_iff_absent name schema prefix ordered).mpr absent
      have whole := insertion_and_tail name schema prefix rest fresh
      have nextUnique := (whole.map Prod.fst).nodup_iff.mpr unique
      obtain ⟨output, done⟩ := ih (insert name schema prefix).2
        (insert_preserves_order name schema prefix ordered) nextUnique
      exact ⟨output, by simpa [buildDecoded, fresh] using done⟩

theorem build_has_original_meaning (fields : List Field) (output : List Entry)
    (built : build [] fields = .ok output) : Meaning fields output := by
  rw [build_decoded_source] at built
  cases parsed : decodeFields fields with
  | none => simp [parsed] at built
  | some decoded =>
      have decodedBuilt : buildDecoded [] decoded = .ok output := by simpa only [parsed] using built
      obtain ⟨unique, complete, sorted⟩ := decoded_build_sound [] decoded output (by simp [Sorted]) decodedBuilt
      exact ⟨decoded, parsed, by simpa using unique, by simpa using complete, sorted⟩

theorem admitted_has_useful_build (fields : List Field) (admitted : Admitted fields) :
    ∃ output, build [] fields = .ok output := by
  obtain ⟨decoded, parsed, unique⟩ := admitted
  obtain ⟨output, built⟩ := decoded_build_useful [] decoded (by simp [Sorted]) (by simpa using unique)
  exact ⟨output, by simpa only [build_decoded_source, parsed] using built⟩

theorem build_refusal_exact (fields : List Field) : build [] fields = .error () ↔ ¬Admitted fields := by
  constructor
  · intro refused admitted
    obtain ⟨output, accepted⟩ := admitted_has_useful_build fields admitted
    simp [refused] at accepted
  · intro invalid
    cases outcome : build [] fields with
    | error unit => cases unit; rfl
    | ok output =>
        obtain ⟨decoded, parsed, unique, _, _⟩ := build_has_original_meaning fields output outcome
        exact False.elim (invalid ⟨decoded, parsed, unique⟩)

end Auths.Product.NativeCompiler.Rules
