import Auths.Product.RequestCompiler
import Auths.Product.HeaderCompilerComposition
import Auths.Product.OriginFramingRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.SchemaIndex.Refinement
open Auths.Product.FieldProjection
open Auths.Product.FieldProjection.Refinement

namespace Auths.Product.RequestCompiler.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

def bodySourceOf : request_compiler.NamedBody → SourceBody
  | .Json source => .json (BodyCompiler.Refinement.jsonSource source)
  | .Form source => .form (BodyCompiler.Refinement.formSource source)

def sourceOf (source : request_compiler.WriteSource) : Source where
  method := methodOf source.method
  origin := sliceBytes source.origin
  parsedHost := sliceBytes source.parsed_host
  path := PathCompiler.Refinement.pathView source.path
  versions := source.versions.map HeaderCompiler.Refinement.versionsView
  scope := source.scope.map HeaderCompiler.Refinement.scopeSourceOf
  idempotency := source.idempotency_header
  body := bodySourceOf source.body

def compiledOf (actual : request_compiler.CompiledWrite) : Compiled :=
  ⟨actual.field_names.val.map vecBytes, writePlanOf actual.plan⟩

def compileErrorOf : request_compiler.CompileWriteError → CompileError
  | .Fields => .fields
  | .Origin => .origin
  | .Method => .method
  | .Headers error => .headers (HeaderCompiler.Refinement.compileErrorOf error)
  | .Path error => .path (errorOf error)
  | .Body error => .body (errorOf error)

def compiledResult {α β : Type} (value : α → β) :
    core.result.Result α request_compiler.CompileWriteError → Except CompileError β
  | .Ok output => .ok (value output)
  | .Err error => .error (compileErrorOf error)

@[step] theorem write_method_exact (method : construct.RequestMethod) :
    request_compiler.write_method_allowed method ⦃ actual => actual = writeMethodAllowed (methodOf method) ⦄ := by
  cases method <;> rfl

@[step] theorem lower_body_exact (names : Slice (alloc.vec.Vec Std.U8)) (source : request_compiler.NamedBody) :
    request_compiler.lower_body names source ⦃ actual =>
      resultOf bodyPlanOf actual = lowerBody (namesView names) (bodySourceOf source) ⦄ := by
  cases source with
  | Json source =>
    unfold request_compiler.lower_body
    step with BodyCompiler.Refinement.lower_json_exact as ⟨pieces, meaning⟩
    cases pieces <;> simp [lowerBody, bodySourceOf, ← meaning, resultOf, bodyPlanOf]
  | Form source =>
    unfold request_compiler.lower_body
    step with BodyCompiler.Refinement.lower_form_exact as ⟨pieces, meaning⟩
    cases pieces <;> simp [lowerBody, bodySourceOf, ← meaning, resultOf, bodyPlanOf]

/-- Every actual compiler outcome is related to the independent typed-source
compiler. All literal copy domains are earned from source layout/origin/body/
header checks; no successful component or expected plan is a premise. -/
@[step] theorem compile_write_exact (fields : Slice field_projection.FieldSpec)
    (source : request_compiler.WriteSource) :
    request_compiler.compile_write fields source ⦃ actual =>
      compiledResult compiledOf actual = compile (fieldsView fields) (sourceOf source) ⦄ := by
  unfold request_compiler.compile_write
  step with field_names_exact as ⟨namesResult, namesMeaning⟩
  cases namesResult with
  | Err error =>
    have invalid : ¬LayoutValid (fieldsView fields) := by
      intro valid
      simp [valid, resultOf] at namesMeaning
    simp [compiledResult, compileErrorOf, compile, invalid]
  | Ok namesResult =>
    have layout : LayoutValid (fieldsView fields) := by
      by_contra invalid
      simp [invalid, resultOf] at namesMeaning
    have exactNames : namesResult.val.map vecBytes = names (fieldsView fields) := by
      simpa [layout, resultOf] using namesMeaning
    have indexedNames : namesView (alloc.vec.Vec.deref namesResult) = names (fieldsView fields) := by
      simpa [namesView, vecBytes] using exactNames
    step with PathCompiler.Refinement.origin_matches_exact as ⟨origin, originMeaning⟩
    cases origin
    · have invalid : ¬PathCompiler.OriginMatches (sliceBytes source.origin) (sliceBytes source.parsed_host) := by
        simpa using originMeaning.symm
      simp [compiledResult, compileErrorOf, compile, sourceOf, layout, invalid]
    · have originFrame : PathCompiler.OriginMatches (sliceBytes source.origin) (sliceBytes source.parsed_host) := by
        simpa using originMeaning.symm
      have originSize : source.origin.val.length ≤ 261 := by
        have size := PathCompiler.origin_matches_bound _ _ originFrame
        simpa [sliceBytes, byteList] using size
      simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
      step with write_method_exact as ⟨method, methodMeaning⟩
      cases method
      · have invalidMethod : writeMethodAllowed (methodOf source.method) = false := methodMeaning.symm
        simp [compiledResult, compileErrorOf, compile, sourceOf, layout, originFrame, invalidMethod]
      · have allowedMethod : writeMethodAllowed (methodOf source.method) = true := methodMeaning.symm
        simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
        step with HeaderCompiler.Refinement.lower_headers_exact as ⟨headers, headerMeaning⟩
        cases headers with
        | Err error =>
          simp [compiledResult, compileErrorOf, compile, sourceOf, layout, originFrame, allowedMethod,
            ← headerMeaning, indexedNames, HeaderCompiler.Refinement.compiledResult]
        | Ok headers =>
          step with PathCompiler.Refinement.lower_path_exact as ⟨path, pathMeaning⟩
          cases path with
          | Err error =>
            simp [compiledResult, compileErrorOf, compile, sourceOf, layout, originFrame, allowedMethod,
              ← headerMeaning, ← pathMeaning, indexedNames, HeaderCompiler.Refinement.compiledResult, resultOf]
          | Ok path =>
            step with lower_body_exact as ⟨body, bodyMeaning⟩
            cases body with
            | Err error =>
              simp [compiledResult, compileErrorOf, compile, sourceOf, layout, originFrame, allowedMethod,
                ← headerMeaning, ← pathMeaning, ← bodyMeaning, indexedNames,
                HeaderCompiler.Refinement.compiledResult, resultOf]
            | Ok body =>
              cases idempotency : source.idempotency_header
              · simp only [idempotency, Bool.false_eq_true, ↓reduceIte]
                have originFits : source.origin.val.length < 4294967295 := by omega
                step with copy_bytes_spec as ⟨originCopy, originCopyValue⟩
                simp [compiledResult, compiledOf, writePlanOf, compile, sourceOf, layout, originFrame,
                  allowedMethod, ← headerMeaning, ← pathMeaning, ← bodyMeaning, indexedNames, exactNames,
                  HeaderCompiler.Refinement.compiledResult, resultOf, idempotency, originCopyValue, vecBytes, sliceBytes]
              · simp only [idempotency, ↓reduceIte]
                step with copy_bytes_spec as ⟨headerName, headerNameValue⟩
                have originFits : source.origin.val.length < 4294967295 := by omega
                step with copy_bytes_spec as ⟨originCopy, originCopyValue⟩
                simp [compiledResult, compiledOf, writePlanOf, compile, sourceOf, layout, originFrame,
                  allowedMethod, ← headerMeaning, ← pathMeaning, ← bodyMeaning, indexedNames, exactNames,
                  HeaderCompiler.Refinement.compiledResult, resultOf, idempotency, idempotencyHeader,
                  headerNameValue, originCopyValue, vecBytes, byteList, sliceBytes]

theorem source_admissible_writes_compile (fields : Slice field_projection.FieldSpec)
    (source : request_compiler.WriteSource) (admitted : Admissible (fieldsView fields) (sourceOf source)) :
    request_compiler.compile_write fields source ⦃ actual => ∃ output, actual = .Ok output ∧
      CompilationMeaning (fieldsView fields) (sourceOf source) (compiledOf output) ⦄ := by
  obtain ⟨compiled, accepted⟩ := compile_complete _ _ admitted
  apply spec_mono (compile_write_exact fields source)
  intro actual meaning
  rw [accepted] at meaning
  cases actual with
  | Err error => simp [compiledResult] at meaning
  | Ok output =>
    have same : compiledOf output = compiled := by simpa [compiledResult] using meaning
    exact ⟨output, rfl, by simpa [same] using compile_sound _ _ _ accepted⟩

theorem source_success_retains_all_components (fields : Slice field_projection.FieldSpec)
    (source : request_compiler.WriteSource) :
    request_compiler.compile_write fields source ⦃ actual => ∀ output, actual = .Ok output →
      CompilationMeaning (fieldsView fields) (sourceOf source) (compiledOf output) ⦄ := by
  apply spec_mono (compile_write_exact fields source)
  intro actual meaning output accepted
  rw [accepted] at meaning
  exact compile_sound _ _ _ (by simpa [compiledResult] using meaning.symm)

theorem source_origin_and_method_domains_earned (fields : Slice field_projection.FieldSpec)
    (source : request_compiler.WriteSource) :
    request_compiler.compile_write fields source ⦃ actual => ∀ output, actual = .Ok output →
      output.plan.origin.val.length ≤ 261 ∧
        output.plan.method ≠ .Get ∧ output.plan.method ≠ .Head ⦄ := by
  apply spec_mono (compile_write_exact fields source)
  intro actual meaning output accepted
  rw [accepted] at meaning
  have compiled : compile (fieldsView fields) (sourceOf source) = .ok (compiledOf output) := by
    simpa [compiledResult] using meaning.symm
  have originBound := successful_compile_earns_origin_bound _ _ _ compiled
  have methodBound := successful_compile_is_write_method _ _ _ compiled
  refine ⟨by simpa [compiledOf, writePlanOf, vecBytes, byteList] using originBound, ?_, ?_⟩
  · intro wrong
    exact methodBound.1 (by simp [compiledOf, writePlanOf, wrong, methodOf])
  · intro wrong
    exact methodBound.2 (by simp [compiledOf, writePlanOf, wrong, methodOf])

end Auths.Product.RequestCompiler.Refinement
