import Auths.Product.ArgumentBinding
import Auths.Product.Refinement.SchemaIndex

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.Refinement.ByteIdentity
open Auths.Product.SchemaIndex.Refinement

namespace Auths.Product.ArgumentBinding.Refinement

set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

def environment (supplied : Slice arguments.NamedArgument) : Environment :=
  supplied.val.map (fun entry => (vecBytes entry.name, argOf entry.value))

def payloadLength : construct.ArgumentValue → Nat
  | .Text bytes | .Integer bytes => bytes.val.length
  | .Boolean _ => 0

/-- The JSON/schema boundary supplies at most 4096 bytes for text/enum values,
at most 17 decimal bytes for admitted integers, and closed booleans. This
source lemma needs only the weaker allocation-domain bound below. Establishing
that domain from native serde/schema/decimal conversion remains explicit. -/
def PayloadsFit (supplied : Slice arguments.NamedArgument) : Prop :=
  ∀ entry ∈ supplied.val, payloadLength entry.value < 4294967295

@[step] theorem copy_exact (value : construct.ArgumentValue)
    (fits : payloadLength value < 4294967295) :
    arguments.copy_argument value ⦃ actual => argOf actual = argOf value ⦄ := by
  cases value with
  | Text bytes =>
    simp only [payloadLength] at fits
    unfold arguments.copy_argument
    step with copy_bytes_spec as ⟨copied, same⟩
    simp only [spec_ok]
    simp [argOf, vecBytes, same]
  | Integer bytes =>
    simp only [payloadLength] at fits
    unfold arguments.copy_argument
    step with copy_bytes_spec as ⟨copied, same⟩
    simp only [spec_ok]
    simp [argOf, vecBytes, same]
  | Boolean value => rfl

private def rawLookup (name : List Std.U8) : List arguments.NamedArgument → Option construct.ArgumentValue
  | [] => none
  | entry :: rest => if entry.name.val = name then some entry.value else rawLookup name rest

private theorem lookup_view (name : Slice Std.U8) (supplied : Slice arguments.NamedArgument) :
    (rawLookup name.val supplied.val).map argOf = lookup (sliceBytes name) (environment supplied) := by
  unfold environment
  induction supplied.val with
  | nil => rfl
  | cons entry rest ih =>
    simp only [rawLookup, environment, List.map_cons, lookup, vecBytes, sliceBytes]
    have byteIdentity := byteList_inj entry.name.val name.val
    split_ifs <;> simp_all

private theorem raw_lookup_member (name : List Std.U8) (supplied : List arguments.NamedArgument)
    (value : construct.ArgumentValue) (found : rawLookup name supplied = some value) :
    ∃ entry ∈ supplied, entry.value = value := by
  induction supplied with
  | nil => simp [rawLookup] at found
  | cons entry rest ih =>
    by_cases same : entry.name.val = name
    · simp [rawLookup, same] at found
      exact ⟨entry, by simp, found⟩
    · simp only [rawLookup, same, ↓reduceIte] at found
      obtain ⟨entry, member, sameValue⟩ := ih found
      exact ⟨entry, List.mem_cons_of_mem _ member, sameValue⟩

/-- All names and values, including refusal after an arbitrary unmatched
prefix, are consumed by the actual borrowed lookup loop. -/
@[step] theorem named_argument_exact (supplied : Slice arguments.NamedArgument) (name : Slice Std.U8) :
    arguments.named_argument supplied name ⦃ actual => actual = rawLookup name.val supplied.val ⦄ := by
  unfold arguments.named_argument arguments.named_argument_loop
  apply loop.spec_decr_nat
    (measure := fun index => supplied.val.length - index.val)
    (inv := fun index => index.val ≤ supplied.val.length ∧
      rawLookup name.val supplied.val = rawLookup name.val (supplied.val.drop index.val))
  · intro index invariant
    unfold arguments.named_argument_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < supplied.val.length := by simpa using within
      step as ⟨entry, entryAt⟩
      step with field_name_equal_exact as ⟨same, sameMeaning⟩
      have suffix : supplied.val.drop index.val = entry :: supplied.val.drop (index.val + 1) := by
        simpa only [entryAt] using List.drop_eq_getElem_cons inside
      rw [suffix, rawLookup] at invariant
      cases same
      · have different : entry.name.val ≠ name.val := by
          simpa [alloc.vec.Vec.deref] using sameMeaning.symm
        simp only [Bool.false_eq_true, ↓reduceIte]
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, by omega⟩
        simpa [different, nextValue] using invariant.2
      · have equal : entry.name.val = name.val := by
          simpa [alloc.vec.Vec.deref] using sameMeaning.symm
        simpa [equal] using invariant.2.symm
    · simp only [spec_ok]
      have atEnd : supplied.val.length ≤ index.val := by simpa using within
      simpa [List.drop_of_length_le atEnd, rawLookup] using invariant.2.symm
  · exact ⟨by simp, by simp⟩

@[step] theorem unique_fields_exact (fields : Slice (alloc.vec.Vec Std.U8)) :
    arguments.unique_fields fields ⦃ actual => actual = decide (namesView fields).Nodup ⦄ := by
  unfold arguments.unique_fields arguments.unique_fields_loop
  apply loop.spec_decr_nat
    (measure := fun index => fields.val.length - index.val)
    (inv := fun index => index.val ≤ fields.val.length ∧
      ∀ earlier, earlier < index.val → ∀ name,
        (namesView fields)[earlier]? = some name →
          SchemaIndex.position (namesView fields) name = some earlier)
  · intro index invariant
    unfold arguments.unique_fields_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < fields.val.length := by simpa using within
      step as ⟨field, fieldAt⟩
      have atName : (namesView fields)[index.val]? = some (vecBytes field) := by
        simp [namesView, vecBytes, List.getElem?_map, List.getElem?_eq_getElem inside, fieldAt]
      step with field_index_spec as ⟨first, firstMeaning⟩
      have firstSpec : first.map UScalar.val = SchemaIndex.position (namesView fields) (vecBytes field) := by
        simpa [alloc.vec.Vec.deref, vecBytes] using firstMeaning
      cases first with
      | none =>
        have repeated : ¬(namesView fields).Nodup := by
          intro unique
          have required := (nodup_iff_first_positions _).mp unique index.val (vecBytes field) atName
          simp [← firstSpec] at required
        simp [repeated]
      | some first =>
        by_cases current : first = index
        · simp only [current, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
          step as ⟨next, nextValue⟩
          refine ⟨by omega, ?_, by omega⟩
          intro earlier before name nameAt
          by_cases previous : earlier < index.val
          · exact invariant.2 earlier previous name nameAt
          · have sameIndex : earlier = index.val := by omega
            subst earlier
            have sameName : name = vecBytes field := by simpa [atName] using nameAt.symm
            simpa [sameName, current] using firstSpec.symm
        · have repeated : ¬(namesView fields).Nodup := by
            intro unique
            have required := (nodup_iff_first_positions _).mp unique index.val (vecBytes field) atName
            rw [← firstSpec] at required
            have equalValues : first.val = index.val := Option.some.inj required
            exact current (UScalar.eq_of_val_eq equalValues)
          simp [current, repeated]
    · simp only [spec_ok]
      have atEnd : fields.val.length ≤ index.val := by simpa using within
      have unique : (namesView fields).Nodup := by
        apply (nodup_iff_first_positions _).mpr
        intro earlier name atName
        have bound : earlier < (namesView fields).length := (List.getElem?_eq_some_iff.mp atName).1
        exact invariant.2 earlier (by simp only [namesView, List.length_map] at bound; omega) name atName
      simp [unique]
  · exact ⟨by simp, by simp⟩

private def accumulate (built : List Arg) : List Name → Environment → Except ConstructError (List Arg)
  | [], _ => .ok built
  | name :: rest, supplied =>
    match lookup name supplied with
    | none => .error .argumentMismatch
    | some value => accumulate (built ++ [value]) rest supplied

private theorem accumulate_project (built : List Arg) (fields : List Name) (supplied : Environment) :
    accumulate built fields supplied = (project fields supplied).map (built ++ ·) := by
  induction fields generalizing built with
  | nil => simp [accumulate, project]
  | cons name rest ih =>
    cases found : lookup name supplied <;>
      simp [accumulate, project, found, ih, Except.map_map, Function.comp_def, List.append_assoc]

@[step] theorem bind_loop_exact (fields : Slice (alloc.vec.Vec Std.U8))
    (supplied : Slice arguments.NamedArgument) (initial : alloc.vec.Vec construct.ArgumentValue)
    (bounded : fields.val.length ≤ 32) (initialBound : initial.val.length ≤ 32)
    (payloads : PayloadsFit supplied) :
    arguments.bind_arguments_loop fields supplied initial 0#usize ⦃ actual =>
      resultOf (fun values => values.val.map argOf) actual =
        accumulate (initial.val.map argOf) (namesView fields) (environment supplied) ⦄ := by
  unfold arguments.bind_arguments_loop
  let wanted := accumulate (initial.val.map argOf) (namesView fields) (environment supplied)
  apply loop.spec_decr_nat
    (measure := fun state => fields.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ fields.val.length ∧
      state.1.val.length = initial.val.length + state.2.val ∧
      wanted = accumulate (state.1.val.map argOf) ((namesView fields).drop state.2.val)
        (environment supplied))
  · rintro ⟨current, index⟩ invariant
    unfold arguments.bind_arguments_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < fields.val.length := by simpa using within
      step as ⟨field, fieldAt⟩
      step with named_argument_exact as ⟨found, foundMeaning⟩
      have viewLookup := lookup_view (alloc.vec.Vec.deref field) supplied
      have foundView : found.map argOf = lookup (vecBytes field) (environment supplied) := by
        simpa only [foundMeaning, sliceBytes, alloc.vec.Vec.deref] using viewLookup
      have dropped : (namesView fields).drop index.val =
          vecBytes field :: (namesView fields).drop (index.val + 1) := by
        simpa [namesView, vecBytes, List.drop_map, fieldAt] using
          congrArg (List.map (fun name => name.val.map (·.val))) (List.drop_eq_getElem_cons inside)
      rw [dropped, accumulate] at invariant
      cases found with
      | none =>
        simp only [spec_ok, resultOf, errorOf]
        simpa [← foundView] using invariant.2.2.symm
      | some value =>
        obtain ⟨entry, member, sameValue⟩ := raw_lookup_member _ _ value foundMeaning.symm
        have fits : payloadLength value < 4294967295 := by
          simpa only [sameValue] using payloads entry member
        step with copy_exact as ⟨copied, copyMeaning⟩
        have room : current.length < Usize.max := by
          apply lt_usize_max
          change current.val.length < 4294967295
          omega
        step as ⟨updated, updatedMeaning⟩
        step as ⟨next, nextValue⟩
        refine ⟨by omega, by simp [updatedMeaning]; omega, ?_, by omega⟩
        simpa [← foundView, updatedMeaning, copyMeaning, List.map_append, nextValue]
          using invariant.2.2
    · simp only [spec_ok, resultOf]
      have atEnd : fields.val.length ≤ index.val := by simpa using within
      have modelAtEnd : (namesView fields).length ≤ index.val := by simpa [namesView] using atEnd
      simpa [List.drop_of_length_le modelAtEnd, accumulate] using invariant.2.2.symm
  · simp [wanted]

/-- Exact native binding, including every shape/duplicate/missing-name refusal.
PayloadsFit is an allocation-domain contract, not an authorization premise. -/
@[step] theorem bind_exact (fields : Slice (alloc.vec.Vec Std.U8))
    (supplied : Slice arguments.NamedArgument) (payloads : PayloadsFit supplied) :
    arguments.bind_arguments fields supplied ⦃ actual =>
      resultOf (fun values => values.val.map argOf) actual = bind (namesView fields) (environment supplied) ⦄ := by
  unfold arguments.bind_arguments
  unfold arguments.MAX_PROFILE_FIELDS
  dsimp only
  by_cases oversized : 32 < fields.val.length
  · have nativeOversized : fields.len > 32#usize := by scalar_tac
    simp [nativeOversized, bind, namesView, oversized, resultOf, errorOf]
  · have bounded : fields.val.length ≤ 32 := by omega
    have nativeBound : ¬fields.len > 32#usize := by scalar_tac
    simp only [nativeBound, Bool.false_or, ↓reduceIte]
    by_cases lengths : supplied.val.length = fields.val.length
    · have nativeLengths : supplied.len = fields.len := by scalar_tac
      simp only [nativeLengths, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
      step with unique_fields_exact as ⟨unique, uniqueMeaning⟩
      cases unique
      · have repeated : ¬(namesView fields).Nodup := by simpa using uniqueMeaning.symm
        simp [bind, repeated, resultOf, errorOf]
      · have unique : (namesView fields).Nodup := by simpa using uniqueMeaning.symm
        step as ⟨initial, initialMeaning⟩
        step with bind_loop_exact as ⟨actual, actualMeaning⟩
        simpa [bind, namesView, environment, bounded, lengths, unique,
          initialMeaning, accumulate_project] using actualMeaning
    · have nativeDifferent : supplied.len ≠ fields.len := by scalar_tac
      simp [nativeDifferent, bind, namesView, environment, lengths, resultOf, errorOf]

/-- Composition with the existing named/index model earns exact lookup from
the actual source result. It does not assume the alignment relation. -/
theorem source_earns_alignment (fields : Slice (alloc.vec.Vec Std.U8))
    (supplied : Slice arguments.NamedArgument) (payloads : PayloadsFit supplied) :
    arguments.bind_arguments fields supplied ⦃ actual =>
      ∀ values, actual = .Ok values →
        SchemaIndex.Aligned (namesView fields) (values.val.map argOf)
          (fun name => lookup name (environment supplied)) ⦄ := by
  apply spec_mono (bind_exact fields supplied payloads)
  intro actual meaning values accepted
  rw [accepted] at meaning
  exact (bind_earns_layout _ _ _ meaning.symm).2.2.2

theorem source_lowered_field_is_named (fields : Slice (alloc.vec.Vec Std.U8))
    (supplied : Slice arguments.NamedArgument) (payloads : PayloadsFit supplied)
    (name : Name) (index : Nat) (lowered : SchemaIndex.position (namesView fields) name = some index) :
    arguments.bind_arguments fields supplied ⦃ actual =>
      ∀ values, actual = .Ok values →
        (values.val.map argOf)[index]? = lookup name (environment supplied) ⦄ := by
  apply spec_mono (source_earns_alignment fields supplied payloads)
  intro actual earns values accepted
  exact SchemaIndex.indexed_argument_is_named _ _ _ (earns values accepted) name index lowered

theorem source_earns_exact_names (fields : Slice (alloc.vec.Vec Std.U8))
    (supplied : Slice arguments.NamedArgument) (payloads : PayloadsFit supplied) :
    arguments.bind_arguments fields supplied ⦃ actual =>
      ∀ values, actual = .Ok values →
        ((environment supplied).map Prod.fst).Perm (namesView fields) ∧
          ((environment supplied).map Prod.fst).Nodup ⦄ := by
  apply spec_mono (bind_exact fields supplied payloads)
  intro actual meaning values accepted
  rw [accepted] at meaning
  exact ⟨bind_earns_exact_names _ _ _ meaning.symm,
    bind_excludes_duplicate_supplied_names _ _ _ meaning.symm⟩

theorem source_complete_layout_accepts (fields : Slice (alloc.vec.Vec Std.U8))
    (supplied : Slice arguments.NamedArgument) (payloads : PayloadsFit supplied)
    (bounded : (namesView fields).length ≤ 32) (unique : (namesView fields).Nodup)
    (lengths : (environment supplied).length = (namesView fields).length)
    (present : ∀ name ∈ namesView fields, lookup name (environment supplied) ≠ none) :
    arguments.bind_arguments fields supplied ⦃ actual => ∃ values, actual = .Ok values ⦄ := by
  obtain ⟨values, accepted⟩ := complete_layout_accepts _ _ bounded unique lengths present
  apply spec_mono (bind_exact fields supplied payloads)
  intro actual meaning
  rw [accepted] at meaning
  cases actual with
  | Ok actual => exact ⟨actual, rfl⟩
  | Err error => simp [resultOf] at meaning

theorem source_bad_layout_refuses (fields : Slice (alloc.vec.Vec Std.U8))
    (supplied : Slice arguments.NamedArgument)
    (invalid : 32 < (namesView fields).length ∨
      (environment supplied).length ≠ (namesView fields).length ∨ ¬(namesView fields).Nodup) :
    arguments.bind_arguments fields supplied ⦃ actual => actual = .Err .ArgumentMismatch ⦄ := by
  unfold arguments.bind_arguments arguments.MAX_PROFILE_FIELDS
  dsimp only
  by_cases oversized : 32 < fields.val.length
  · have nativeOversized : fields.len > 32#usize := by scalar_tac
    simp [nativeOversized]
  · have bounded : fields.val.length ≤ 32 := by omega
    have nativeBound : ¬fields.len > 32#usize := by scalar_tac
    simp only [nativeBound, Bool.false_or, ↓reduceIte]
    by_cases lengths : supplied.val.length = fields.val.length
    · have nativeLengths : supplied.len = fields.len := by scalar_tac
      simp only [nativeLengths, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
      have repeated : ¬(namesView fields).Nodup := by
        simpa [namesView, environment, Nat.not_lt.mpr bounded, lengths] using invalid
      step with unique_fields_exact as ⟨unique, uniqueMeaning⟩
      have refused : unique = false := by simpa [repeated] using uniqueMeaning
      simp [refused]
    · have nativeDifferent : supplied.len ≠ fields.len := by scalar_tac
      simp [nativeDifferent]

end Auths.Product.ArgumentBinding.Refinement
