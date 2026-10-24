import Auths.Product.NativeCompilerHeaderGrammar
import Auths.Product.NativeCompilerReadPlans

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativeHeaderError := AuthsNativeRecipe.auths_gateway_kernel.header_compiler.HeaderCompileError

def nativeHeaderError : NativeHeaderError → HeaderCompiler.CompileError
  | .ProviderHeader => .providerHeader
  | .AccountScope => .accountScope

def nativeHeaderResult {T V : Type} (view : T → V) :
    core.result.Result T NativeHeaderError → Except HeaderCompiler.CompileError V
  | .Ok output => .ok (view output)
  | .Err error => .error (nativeHeaderError error)

def nativeVersions (headers : Slice NativeNamedHeader) : HeaderCompiler.Versions :=
  headers.val.map (fun header => (bytes header.name, bytes header.value))

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open HeaderCompiler
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

-- Aeneas duplicates the same Rust loop at its two control-flow entries.
-- Both actual generated loops are proved here; neither is replaced by a model.
private theorem native_version_rows_suffix (headers : Slice NativeNamedHeader) (position : Std.Usize)
    (positionBound : position.val ≤ headers.val.length) :
    (AuthsNativeRecipe.auths_gateway_kernel.header_compiler.version_headers_valid_loop0 headers position
      ⦃ actual => actual = decide (∀ header ∈ headers.val.drop position.val,
        VersionValid (bytes header.name) (bytes header.value)) ⦄) ∧
    (AuthsNativeRecipe.auths_gateway_kernel.header_compiler.version_headers_valid_loop1 headers position
      ⦃ actual => actual = decide (∀ header ∈ headers.val.drop position.val,
        VersionValid (bytes header.name) (bytes header.value)) ⦄) := by
  generalize remaining : headers.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position with
  | h count ih =>
      constructor
      all_goals
        first
        | unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.version_headers_valid_loop0
        | unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.version_headers_valid_loop1
        by_cases inside : position.val < headers.val.length
        · have nativeInside : position < headers.len := by scalar_tac
          simp only [nativeInside, ↓reduceIte]
          step with Slice.index_usize_spec headers position inside as ⟨header, headerAt⟩
          have suffix : headers.val.drop position.val = header :: headers.val.drop (position.val + 1) := by
            simpa only [headerAt] using List.drop_eq_getElem_cons inside
          step with native_version_header_exact (AuthsNativeRecipe.alloc.vec.Vec.deref header.name)
            (AuthsNativeRecipe.alloc.vec.Vec.deref header.value) as ⟨valid, validMeaning⟩
          have rowMeaning : valid = decide (VersionValid (bytes header.name) (bytes header.value)) := by
            simpa only [schemaSliceBytes, bytes, native_deref_contents] using validMeaning
          cases valid with
          | false => simp [suffix, ← rowMeaning]
          | true =>
              simp only [Bool.true_eq_true, ↓reduceIte]
              step as ⟨next, nextValue⟩
              have nextBound : next.val ≤ headers.val.length := by omega
              have smaller : headers.val.length - next.val < count := by omega
              first
              | apply spec_mono (ih _ smaller next nextBound rfl).1
              | apply spec_mono (ih _ smaller next nextBound rfl).2
              intro actual exact
              simpa only [suffix, List.mem_cons, forall_eq_or_imp, ← rowMeaning,
                decide_true, true_and, nextValue] using exact
        · have ended : headers.val.length ≤ position.val := by omega
          have nativeEnded : ¬position < headers.len := by scalar_tac
          simp [nativeEnded, List.drop_eq_nil_of_le ended]

@[step] theorem native_versions_valid_exact (headers : Slice NativeNamedHeader) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.version_headers_valid headers ⦃ actual =>
      actual = decide (VersionsValid (nativeVersions headers)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.version_headers_valid
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.MAX_PROVIDER_HEADERS
  cases items : headers.val with
  | nil => simp [core.slice.Slice.is_empty, items, VersionsValid, nativeVersions]
  | cons first rest =>
      cases rest with
      | nil =>
          have length : headers.len = 1#usize := by scalar_tac
          simp only [core.slice.Slice.is_empty, items, List.isEmpty_cons, length,
            ↓reduceIte, bind_tc_ok]
          apply spec_mono (native_version_rows_suffix headers 0#usize (by simp)).2
          intro actual exact
          simpa [VersionsValid, nativeVersions, items] using exact
      | cons second tail =>
          cases tail with
          | nil =>
              have length : headers.len = 2#usize := by scalar_tac
              simp only [core.slice.Slice.is_empty, items, List.isEmpty_cons, length,
                ↓reduceIte, bind_tc_ok]
              step with Slice.index_usize_spec headers 0#usize
                (by simp only [items, List.length_cons]; omega) as ⟨one, oneAt⟩
              step with Slice.index_usize_spec headers 1#usize
                (by simp only [items, List.length_cons]; omega) as ⟨two, twoAt⟩
              have sameOne : one = first := by simpa only [items] using oneAt
              have sameTwo : two = second := by simpa only [items] using twoAt
              step with native_schema_byte_equality (AuthsNativeRecipe.alloc.vec.Vec.deref one.name)
                (AuthsNativeRecipe.alloc.vec.Vec.deref two.name) as ⟨duplicate, duplicateMeaning⟩
              have sameMeaning : duplicate = decide (bytes first.name = bytes second.name) := by
                simpa only [sameOne, sameTwo, schemaSliceBytes, bytes, native_deref_contents] using duplicateMeaning
              cases duplicate with
              | true => simp [VersionsValid, nativeVersions, items, ← sameMeaning]
              | false =>
                  simp only [Bool.false_eq_true, ↓reduceIte]
                  apply spec_mono (native_version_rows_suffix headers 0#usize (by simp)).1
                  intro actual exact
                  simpa [VersionsValid, nativeVersions, items, ← sameMeaning, ne_comm] using exact
          | cons third tail =>
              have nativeLarge : headers.len > 2#usize := by scalar_tac
              have invalid : ¬VersionsValid (nativeVersions headers) := by
                intro valid
                have bound := valid.2.1
                simp only [nativeVersions, items, List.map_cons, List.map_nil, List.length_cons] at bound
                omega
              simp [nativeLarge, invalid]

private theorem native_header_copy_suffix (headers : Slice NativeNamedHeader)
    (output : NativeVec NativeHeader) (position : Std.Usize)
    (positionBound : position.val ≤ headers.val.length)
    (room : output.val.length + (headers.val.length - position.val) ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.copy_versions_loop headers output position
      ⦃ actual => actual.val.map nativeHeader = output.val.map nativeHeader ++
        literalHeaders ((nativeVersions headers).drop position.val) ⦄ := by
  generalize remaining : headers.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position output with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.copy_versions_loop
      by_cases inside : position.val < headers.val.length
      · have nativeInside : position < headers.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec headers position inside as ⟨header, headerAt⟩
        have suffix : (nativeVersions headers).drop position.val =
            (bytes header.name, bytes header.value) :: (nativeVersions headers).drop (position.val + 1) := by
          simpa only [nativeVersions, List.drop_map, List.map_cons, headerAt] using
            congrArg (List.map (fun row : NativeNamedHeader => (bytes row.name, bytes row.value)))
              (List.drop_eq_getElem_cons inside)
        step with native_schema_copy_bytes (AuthsNativeRecipe.alloc.vec.Vec.deref header.name)
          as ⟨name, nameMeaning⟩
        step with native_schema_copy_bytes (AuthsNativeRecipe.alloc.vec.Vec.deref header.value)
          as ⟨value, valueMeaning⟩
        step with native_push_exact output (⟨name, value⟩ : NativeHeader) (by omega)
          as ⟨updated, appended⟩
        have updatedLength : updated.val.length = output.val.length + 1 := by
          simp only [appended, List.length_append, List.length_singleton]
        step as ⟨next, nextValue⟩
        apply spec_mono (ih _ (by omega) next updated (by omega) (by omega) rfl)
        intro actual exact
        simpa [suffix, literalHeaders, nativeHeader, bytes, nameMeaning, valueMeaning,
          native_deref_contents, appended, List.map_append, List.map_singleton,
          nextValue, List.append_assoc] using exact
      · have ended : headers.val.length ≤ position.val := by omega
        have nativeEnded : ¬position < headers.len := by scalar_tac
        have modelEnded : (nativeVersions headers).length ≤ position.val := by
          simpa only [nativeVersions, List.length_map] using ended
        simp [nativeEnded, List.drop_eq_nil_of_le modelEnded, literalHeaders]

@[step] theorem native_versions_copy_exact (headers : Slice NativeNamedHeader) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.copy_versions headers ⦃ actual =>
      actual.val.map nativeHeader = literalHeaders (nativeVersions headers) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.copy_versions
  apply spec_mono (native_header_copy_suffix headers (AuthsNativeRecipe.alloc.vec.Vec.new NativeHeader)
    0#usize (by simp) (by simpa only [native_empty_contents, List.length_nil,
      Nat.zero_add, Nat.sub_zero] using headers.property))
  intro actual exact
  simpa only [native_empty_contents, List.map_nil, List.nil_append, List.drop_zero] using exact

@[step] theorem native_lower_versions_exact (headers : Slice NativeNamedHeader) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.lower_versions headers ⦃ actual =>
      nativeHeaderResult (fun output => output.val.map nativeHeader) actual = lowerVersions (nativeVersions headers) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.lower_versions
  step with native_versions_valid_exact headers as ⟨valid, meaning⟩
  cases valid with
  | false => simp [lowerVersions, ← meaning, nativeHeaderResult, nativeHeaderError]
  | true =>
      simp only [Bool.true_eq_true, ↓reduceIte]
      step with native_versions_copy_exact headers as ⟨output, copied⟩
      simp [lowerVersions, ← meaning, nativeHeaderResult, copied]

@[step] theorem native_lower_scope_exact (names : Slice (NativeVec Std.U8)) (scope : NativeNamedScope) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.lower_scope names scope ⦃ actual =>
      nativeHeaderResult nativeScopePlan actual = lowerScope (nativeNameColumn names) (loweredScope scope) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.lower_scope
  step with native_header_index_exact (AuthsNativeRecipe.alloc.vec.Vec.deref scope.name)
    as ⟨index, indexMeaning⟩
  have indexSpec : index.map UScalar.val = headerIndex (bytes scope.name) := by
    simpa only [schemaSliceBytes, bytes, native_deref_contents] using indexMeaning
  cases index with
  | none =>
      have unsupported : bytes scope.name ≠ stripeAccountName := by
        intro same
        have required := (header_index_two_iff _).mpr same
        simp only [← indexSpec, Option.map_none] at required
        contradiction
      simp [lowerScope, loweredScope, unsupported, nativeHeaderResult, nativeHeaderError]
  | some position =>
      by_cases account : position.val = 2
      · have nameMeaning : bytes scope.name = stripeAccountName := by
          apply (header_index_two_iff _).mp
          simpa only [account, Option.map_some] using indexSpec.symm
        simp only [account]
        step with native_lower_field_exact names (AuthsNativeRecipe.alloc.vec.Vec.deref scope.field)
          as ⟨field, fieldMeaning⟩
        cases field with
        | Err error =>
            simp [lowerScope, loweredScope, nameMeaning, ← fieldMeaning, nativeConstructResult,
              schemaSliceBytes, bytes, native_deref_contents, nativeHeaderResult, nativeHeaderError]
        | Ok field =>
            step with native_schema_copy_bytes (AuthsNativeRecipe.alloc.vec.Vec.deref scope.name)
              as ⟨copied, copiedMeaning⟩
            simp [lowerScope, loweredScope, nameMeaning, ← fieldMeaning, nativeConstructResult,
              schemaSliceBytes, bytes, native_deref_contents, nativeHeaderResult, nativeScopePlan, copiedMeaning]
      · have unsupported : bytes scope.name ≠ stripeAccountName := by
          intro same
          have required := (header_index_two_iff _).mpr same
          rw [← indexSpec] at required
          simp only [Option.map_some, Option.some.injEq] at required
          exact account required
        simp [account, lowerScope, loweredScope, unsupported, nativeHeaderResult, nativeHeaderError]

@[step] theorem native_lower_headers_exact (names : Slice (NativeVec Std.U8))
    (versions : Option (Slice NativeNamedHeader)) (scope : Option NativeNamedScope) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.lower_headers names versions scope ⦃ actual =>
      nativeHeaderResult nativeHeaders actual =
        lowerHeaders (nativeNameColumn names) (versions.map nativeVersions) (scope.map loweredScope) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.lower_headers
  cases versions with
  | none =>
      cases scope with
      | none => simp [nativeHeaderResult, nativeHeaders, lowerHeaders, native_empty_contents]
      | some source =>
          step with native_lower_scope_exact names source as ⟨compiled, meaning⟩
          cases compiled with
          | Err error => simp [nativeHeaderResult, lowerHeaders, ← meaning]
          | Ok compiled =>
              step with native_scope_plan_clone_exact compiled as ⟨copied, same⟩
              simp [nativeHeaderResult, nativeHeaders, lowerHeaders, ← meaning, same, native_empty_contents]
  | some source =>
      step with native_lower_versions_exact source as ⟨compiled, meaning⟩
      cases compiled with
      | Err error => simp [nativeHeaderResult, lowerHeaders, ← meaning]
      | Ok compiled =>
          step with native_vector_clone_exact AuthsNativeRecipe.auths_gateway_kernel.construct.Header.Insts.CoreCloneClone
            compiled (by intro header _; exact native_header_clone_result header) as ⟨copied, same⟩
          cases scope with
          | none => simp [nativeHeaderResult, nativeHeaders, lowerHeaders, ← meaning, same]
          | some source =>
              step with native_lower_scope_exact names source as ⟨account, accountMeaning⟩
              cases account with
              | Err error => simp [nativeHeaderResult, lowerHeaders, ← meaning, ← accountMeaning]
              | Ok account =>
                  step with native_scope_plan_clone_exact account as ⟨copiedAccount, sameAccount⟩
                  simp [nativeHeaderResult, nativeHeaders, lowerHeaders, ← meaning, ← accountMeaning,
                    same, sameAccount]

/-- Native conversion feeds both complete original columns to the actual
header compiler, retaining None versus Some [] and exact refusal precedence. -/
theorem native_original_headers_verdict (names : Slice (NativeVec Std.U8))
    (source : NativeRecipeSource) (bounded : NativeHeaderFits source) :
    (do let (versions, scope) ← AuthsNativeRecipe.recipe.lower.header_source source
        AuthsNativeRecipe.auths_gateway_kernel.header_compiler.lower_headers names
          (versions.map AuthsNativeRecipe.alloc.vec.Vec.deref) scope) ⦃ actual =>
      nativeHeaderResult nativeHeaders actual = lowerHeaders (nativeNameColumn names)
        (source.provider_headers.map originalHeaders) (source.account_scope.map originalScope) ⦄ := by
  step with native_header_input_exact source bounded as ⟨converted, convertedMeaning⟩
  apply spec_mono (native_lower_headers_exact names
    (converted.1.map AuthsNativeRecipe.alloc.vec.Vec.deref) converted.2)
  intro actual exact
  have versionsMeaning :
      (converted.1.map AuthsNativeRecipe.alloc.vec.Vec.deref).map nativeVersions =
        source.provider_headers.map originalHeaders := by
    simpa only [Option.map_map, Function.comp_def, nativeVersions, loweredHeaders,
      native_deref_contents, bytes] using convertedMeaning.1
  simpa only [versionsMeaning, convertedMeaning.2] using exact

end Auths.Product.NativeCompiler.Refinement
