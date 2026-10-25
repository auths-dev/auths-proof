import Auths.Product.HeaderCompilerLeaves

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.SchemaIndex.Refinement

namespace Auths.Product.HeaderCompiler.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

def compileErrorOf : header_compiler.HeaderCompileError → CompileError
  | .ProviderHeader => .providerHeader
  | .AccountScope => .accountScope

def compiledResult {α β : Type} (value : α → β) :
    core.result.Result α header_compiler.HeaderCompileError → Except CompileError β
  | .Ok output => .ok (value output)
  | .Err error => .error (compileErrorOf error)

@[step] theorem version_header_exact (name value : Slice Std.U8) :
    header_compiler.version_header_valid name value ⦃ actual =>
      actual = decide (VersionValid (sliceBytes name) (sliceBytes value)) ⦄ := by
  unfold header_compiler.version_header_valid
  step with header_index_exact as ⟨index, indexMeaning⟩
  cases index with
  | none =>
    have invalid : ¬VersionValid (sliceBytes name) (sliceBytes value) := by
      rw [version_valid_by_index, ← indexMeaning]
      simp
    simp [invalid]
  | some position =>
    by_cases zero : position = 0#usize
    · subst position
      step with stripe_version_exact as ⟨actual, meaning⟩
      simpa [version_valid_by_index, ← indexMeaning] using meaning
    · by_cases one : position = 1#usize
      · subst position
        simp only [zero, ↓reduceIte]
        step with iso_date_exact as ⟨actual, meaning⟩
        simpa [version_valid_by_index, ← indexMeaning] using meaning
      · have notZero : position.val ≠ 0 := by scalar_tac
        have notOne : position.val ≠ 1 := by scalar_tac
        have invalid : ¬VersionValid (sliceBytes name) (sliceBytes value) := by
          rw [version_valid_by_index, ← indexMeaning]
          simp only [Option.map_some]
          split <;> simp_all
        simp [zero, one, invalid]

@[step] theorem version_rows_exact (source : Slice header_compiler.NamedHeader) :
    header_compiler.version_headers_valid_loop source 0#usize ⦃ actual =>
      actual = decide (∀ header ∈ source.val,
        VersionValid (sliceBytes header.name) (sliceBytes header.value)) ⦄ := by
  unfold header_compiler.version_headers_valid_loop
  apply loop.spec_decr_nat
    (measure := fun index => source.val.length - index.val)
    (inv := fun index => index.val ≤ source.val.length ∧
      ∀ header ∈ source.val.take index.val, VersionValid (sliceBytes header.name) (sliceBytes header.value))
  · intro index invariant
    unfold header_compiler.version_headers_valid_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < source.val.length := by simpa using within
      step as ⟨header, headerAt⟩
      step with version_header_exact as ⟨allowed, meaning⟩
      cases allowed
      · have invalid : ¬VersionValid (sliceBytes header.name) (sliceBytes header.value) := by simpa using meaning.symm
        have member : header ∈ source.val := by rw [headerAt]; exact List.getElem_mem inside
        have refused : ¬∀ item ∈ source.val, VersionValid (sliceBytes item.name) (sliceBytes item.value) :=
          fun every => invalid (every header member)
        simp [refused]
      · have admitted : VersionValid (sliceBytes header.name) (sliceBytes header.value) := by simpa using meaning.symm
        simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, by omega⟩
        rw [nextValue, List.take_succ_eq_append_getElem inside]
        intro current member
        rcases List.mem_append.mp member with earlier | current
        · exact invariant.2 _ earlier
        · simpa [List.mem_singleton, current, headerAt] using admitted
    · simp only [spec_ok]
      have atEnd : source.val.length ≤ index.val := by simpa using within
      have every : ∀ header ∈ source.val, VersionValid (sliceBytes header.name) (sliceBytes header.value) := by
        intro header member
        exact invariant.2 header (by simpa [List.take_of_length_le atEnd] using member)
      simp [every]
  · exact ⟨by simp, by simp⟩

@[step] theorem version_headers_exact (source : Slice header_compiler.NamedHeader) :
    header_compiler.version_headers_valid source ⦃ actual =>
      actual = decide (VersionsValid (versionsView source)) ⦄ := by
  unfold header_compiler.version_headers_valid header_compiler.MAX_PROVIDER_HEADERS
  cases items : source.val with
  | nil => simp [core.slice.Slice.is_empty, items, VersionsValid, versionsView]
  | cons first rest =>
    cases rest with
    | nil =>
      have count : source.len = 1#usize := by scalar_tac
      simp only [core.slice.Slice.is_empty, items, List.isEmpty_cons, count, ↓reduceIte]
      step with version_rows_exact as ⟨actual, meaning⟩
      simpa [VersionsValid, versionsView, items, namedHeaderOf] using meaning
    | cons second tail =>
      cases tail with
      | nil =>
        have count : source.len = 2#usize := by scalar_tac
        simp only [core.slice.Slice.is_empty, items, List.isEmpty_cons, count, ↓reduceIte]
        step as ⟨one, oneAt⟩
        step as ⟨two, twoAt⟩
        have firstSame : one = first := by simpa [items] using oneAt
        have secondSame : two = second := by simpa [items] using twoAt
        step with field_name_equal_spec as ⟨duplicate, duplicateMeaning⟩
        cases duplicate
        · have different : sliceBytes first.name ≠ sliceBytes second.name := by
            intro same
            have nativeSame : first.name.val = second.name.val := byteList_inj.mp same
            simp [firstSame, secondSame, nativeSame] at duplicateMeaning
          step with version_rows_exact as ⟨actual, meaning⟩
          simpa [VersionsValid, versionsView, items, namedHeaderOf, different, ne_comm] using meaning
        · have nativeSame : first.name.val = second.name.val := by
            simpa [firstSame, secondSame] using duplicateMeaning.symm
          have same : sliceBytes first.name = sliceBytes second.name := congrArg byteList nativeSame
          simp [VersionsValid, versionsView, items, namedHeaderOf, same]
      | cons third later =>
        have tooMany : 2 < source.val.length := by simp [items]
        have native : source.len > 2#usize := by scalar_tac
        have invalid : ¬VersionsValid (versionsView source) := by
          intro valid
          have bound := valid.2.1
          simp only [versionsView, List.length_map] at bound
          omega
        simp [native, invalid]

@[step] theorem versions_copy_loop_exact (source : Slice header_compiler.NamedHeader)
    (admitted : VersionsValid (versionsView source)) :
    header_compiler.copy_versions source
      ⦃ actual => actual.val.map headerOf = literalHeaders (versionsView source) ⦄ := by
  have bounded : source.val.length ≤ 2 := by simpa [versionsView] using admitted.2.1
  unfold header_compiler.copy_versions header_compiler.copy_versions_loop
  apply loop.spec_decr_nat
    (measure := fun state => source.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ source.val.length ∧ state.1.val.length = state.2.val ∧
      state.1.val.map headerOf = literalHeaders ((source.val.take state.2.val).map namedHeaderOf))
  · rintro ⟨current, index⟩ invariant
    unfold header_compiler.copy_versions_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < source.val.length := by simpa using within
      step as ⟨header, headerAt⟩
      have member : namedHeaderOf header ∈ versionsView source :=
        List.mem_map.mpr ⟨header, by rw [headerAt]; exact List.getElem_mem inside, rfl⟩
      have rowValid := admitted.2.2.2 _ member
      have rowBounds := valid_version_bounds _ _ rowValid
      have nameFits : header.name.val.length < 4294967295 := by
        have size := rowBounds.1
        simp only [namedHeaderOf, sliceBytes, byteList, List.length_map] at size
        omega
      have valueFits : header.value.val.length < 4294967295 := by
        have size := rowBounds.2
        simp only [namedHeaderOf, sliceBytes, byteList, List.length_map] at size
        omega
      step with copy_bytes_spec as ⟨name, nameValue⟩
      step with copy_bytes_spec as ⟨value, valueValue⟩
      have room : current.length < Usize.max := lt_usize_max (by change current.val.length < _; omega)
      step as ⟨updated, updatedValue⟩
      step as ⟨next, nextValue⟩
      refine ⟨by omega, by simp [updatedValue]; omega, ?_, by omega⟩
      rw [updatedValue, List.map_append, invariant.2.2, nextValue,
        List.take_succ_eq_append_getElem inside]
      simp [literalHeaders, List.map_append, headerOf, vecBytes, namedHeaderOf, nameValue, valueValue,
        headerAt, sliceBytes, List.append_assoc]
    · simp only [spec_ok]
      have atEnd : source.val.length ≤ index.val := by simpa using within
      simpa [List.take_of_length_le atEnd, versionsView] using invariant.2.2
  · simp [literalHeaders]

@[step] theorem lower_versions_exact (source : Slice header_compiler.NamedHeader) :
    header_compiler.lower_versions source ⦃ actual =>
      compiledResult (fun output => output.val.map headerOf) actual = lowerVersions (versionsView source) ⦄ := by
  unfold header_compiler.lower_versions
  step with version_headers_exact as ⟨valid, meaning⟩
  cases valid
  · have invalid : ¬VersionsValid (versionsView source) := by simpa using meaning.symm
    simp [compiledResult, compileErrorOf, lowerVersions, invalid]
  · have admitted : VersionsValid (versionsView source) := by simpa using meaning.symm
    simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
    step with versions_copy_loop_exact as ⟨output, outputMeaning⟩
    simp [compiledResult, lowerVersions, admitted, outputMeaning]

@[step] theorem lower_scope_exact (names : Slice (alloc.vec.Vec Std.U8)) (source : header_compiler.NamedScope) :
    header_compiler.lower_scope names source ⦃ actual =>
      compiledResult scopeOf actual = lowerScope (namesView names) (scopeSourceOf source) ⦄ := by
  unfold header_compiler.lower_scope
  step with header_index_exact as ⟨index, indexMeaning⟩
  cases index with
  | none =>
    have wrongName : sliceBytes source.name ≠ stripeAccountName := by
      intro same
      have classified := (header_index_two_iff _).mpr same
      simp [← indexMeaning] at classified
    simp [compiledResult, compileErrorOf, lowerScope, scopeSourceOf, wrongName]
  | some position =>
    by_cases account : position = 2#usize
    · subst position
      have nameSame : sliceBytes source.name = stripeAccountName :=
        (header_index_two_iff _).mp (by simpa using indexMeaning.symm)
      step with PathCompiler.Refinement.lower_field_exact as ⟨field, fieldMeaning⟩
      cases field with
      | Err error =>
        simp [compiledResult, compileErrorOf, lowerScope, scopeSourceOf, nameSame, ← fieldMeaning, resultOf]
      | Ok field =>
        have nameSize : source.name.val.length = 14 := by
          have size := congrArg List.length nameSame
          simpa [sliceBytes, byteList, stripeAccountName] using size
        have nameFits : source.name.val.length < 4294967295 := by omega
        step with copy_bytes_spec as ⟨name, nameValue⟩
        simp [compiledResult, lowerScope, scopeSourceOf, nameSame, ← fieldMeaning, resultOf, scopeOf,
          nameValue, vecBytes, sliceBytes]
    · have notTwo : position.val ≠ 2 := by scalar_tac
      have wrongName : sliceBytes source.name ≠ stripeAccountName := by
        intro same
        have classified := (header_index_two_iff _).mpr same
        simp [← indexMeaning, notTwo] at classified
      simp [account, compiledResult, compileErrorOf, lowerScope, scopeSourceOf, wrongName]

@[step] theorem lower_headers_exact (names : Slice (alloc.vec.Vec Std.U8))
    (versions : Option (Slice header_compiler.NamedHeader)) (scope : Option header_compiler.NamedScope) :
    header_compiler.lower_headers names versions scope ⦃ actual =>
      compiledResult headerPlanOf actual =
        lowerHeaders (namesView names) (versions.map versionsView) (scope.map scopeSourceOf) ⦄ := by
  unfold header_compiler.lower_headers
  cases versions with
  | none =>
    cases scope with
    | none => simp [compiledResult, headerPlanOf, lowerHeaders]
    | some source =>
      step with lower_scope_exact as ⟨account, accountMeaning⟩
      cases account <;>
        simp [compiledResult, compileErrorOf, headerPlanOf, lowerHeaders, ← accountMeaning]
  | some headers =>
    step with lower_versions_exact as ⟨fixed, fixedMeaning⟩
    cases fixed with
    | Err error => simp [compiledResult, compileErrorOf, lowerHeaders, ← fixedMeaning]
    | Ok fixed =>
      cases scope with
      | none => simp [compiledResult, headerPlanOf, lowerHeaders, ← fixedMeaning]
      | some source =>
        step with lower_scope_exact as ⟨account, accountMeaning⟩
        cases account <;>
          simp [compiledResult, compileErrorOf, headerPlanOf, lowerHeaders, ← fixedMeaning, ← accountMeaning]

theorem source_admissible_headers_compile (names : Slice (alloc.vec.Vec Std.U8))
    (versions : Option (Slice header_compiler.NamedHeader)) (scope : Option header_compiler.NamedScope)
    (admitted : HeaderAdmissible (namesView names) (versions.map versionsView) (scope.map scopeSourceOf)) :
    header_compiler.lower_headers names versions scope ⦃ actual => ∃ plan,
      actual = .Ok plan ∧ lowerHeaders (namesView names) (versions.map versionsView) (scope.map scopeSourceOf) =
        .ok (headerPlanOf plan) ⦄ := by
  obtain ⟨plan, modelAccepted⟩ := lower_headers_complete _ _ _ admitted
  apply spec_mono (lower_headers_exact names versions scope)
  intro actual meaning
  rw [modelAccepted] at meaning
  cases actual with
  | Err error => simp [compiledResult] at meaning
  | Ok native =>
    have same : headerPlanOf native = plan := by simpa [compiledResult] using meaning
    exact ⟨native, rfl, by simpa [same] using modelAccepted⟩

theorem source_invalid_headers_cannot_compile (names : Slice (alloc.vec.Vec Std.U8))
    (versions : Option (Slice header_compiler.NamedHeader)) (scope : Option header_compiler.NamedScope)
    (invalid : ¬HeaderAdmissible (namesView names) (versions.map versionsView) (scope.map scopeSourceOf)) :
    header_compiler.lower_headers names versions scope ⦃ actual => ∀ plan, actual ≠ .Ok plan ⦄ := by
  apply spec_mono (lower_headers_exact names versions scope)
  intro actual meaning plan accepted
  rw [accepted] at meaning
  exact invalid (lower_headers_earns_admissibility _ _ _ _ (by simpa [compiledResult] using meaning.symm))

theorem source_fixed_column_preserves_only_approved_versions (names : Slice (alloc.vec.Vec Std.U8))
    (versions : Option (Slice header_compiler.NamedHeader)) (scope : Option header_compiler.NamedScope) :
    header_compiler.lower_headers names versions scope ⦃ actual => ∀ plan, actual = .Ok plan →
      plan.versions.val.map headerOf = literalHeaders ((versions.map versionsView).getD []) ∧
      (∀ header ∈ plan.versions.val, VersionValid (vecBytes header.name) (vecBytes header.value)) ⦄ := by
  apply spec_mono (lower_headers_exact names versions scope)
  intro actual meaning plan accepted
  rw [accepted] at meaning
  have compiled : lowerHeaders (namesView names) (versions.map versionsView) (scope.map scopeSourceOf) =
      .ok (headerPlanOf plan) := by simpa [compiledResult] using meaning.symm
  have fixed := lower_headers_fixed_column _ _ _ _ compiled
  refine ⟨fixed, ?_⟩
  have admitted := lower_headers_versions_admitted _ _ _ _ compiled
  intro header member
  have modelMember : headerOf header ∈ (headerPlanOf plan).versions := List.mem_map.mpr ⟨header, member, rfl⟩
  rw [fixed] at modelMember
  cases versions with
  | none => simp [literalHeaders] at modelMember
  | some source =>
    obtain ⟨entry, atSource, same⟩ := List.mem_map.mp modelMember
    have row := admitted.2.2.2 entry atSource
    have headerSame : entry = (vecBytes header.name, vecBytes header.value) := by
      cases entry
      simpa [headerOf] using same
    simpa [headerSame] using row

theorem source_fixed_column_excludes_account_scope (names : Slice (alloc.vec.Vec Std.U8))
    (versions : Option (Slice header_compiler.NamedHeader)) (scope : Option header_compiler.NamedScope) :
    header_compiler.lower_headers names versions scope ⦃ actual => ∀ plan, actual = .Ok plan →
      ∀ header ∈ plan.versions.val, vecBytes header.name ≠ stripeAccountName ⦄ := by
  apply spec_mono (source_fixed_column_preserves_only_approved_versions names versions scope)
  intro actual meaning plan accepted header member
  exact version_name_excludes_account_scope _ _ ((meaning plan accepted).2 header member)

end Auths.Product.HeaderCompiler.Refinement
