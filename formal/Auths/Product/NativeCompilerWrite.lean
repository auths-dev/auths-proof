import Auths.Product.NativeCompilerBodyLowering
import Auths.Product.NativeCompilerHeaders
import Auths.Product.NativeCompilerOrigin
import Auths.Product.NativeCompilerWriteClones
import Auths.Product.NativeCompilerSchemaFields

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativeWriteSource := AuthsNativeRecipe.auths_gateway_kernel.request_compiler.WriteSource
abbrev NativeCompiledWrite := AuthsNativeRecipe.auths_gateway_kernel.request_compiler.CompiledWrite
abbrev NativeCompileError := AuthsNativeRecipe.auths_gateway_kernel.request_compiler.CompileWriteError

def nativeWriteSource (source : NativeWriteSource) : RequestCompiler.Source where
  method := kernelWriteMethod source.method
  origin := schemaSliceBytes source.origin
  parsedHost := schemaSliceBytes source.parsed_host
  path := nativePath source.path
  versions := source.versions.map nativeVersions
  scope := source.scope.map loweredScope
  idempotency := source.idempotency_header
  body := nativeNamedBody source.body

def nativeWritePlan (source : NativeWritePlan) : RequestConstruction.WritePlan where
  method := kernelWriteMethod source.method
  origin := bytes source.origin
  path := source.path.val.map nativeSegment
  headers := nativeHeaders source.headers
  idempotency := source.idempotency_header.map bytes
  body := nativeBodyPlan source.body

def nativeCompiledWrite (output : NativeCompiledWrite) : RequestCompiler.Compiled :=
  ⟨output.field_names.val.map bytes, nativeWritePlan output.plan⟩

def nativeCompileError : NativeCompileError → RequestCompiler.CompileError
  | .Fields => .fields
  | .Origin => .origin
  | .Method => .method
  | .Headers error => .headers (nativeHeaderError error)
  | .Path error => .path (nativeConstructError error)
  | .Body error => .body (nativeConstructError error)

def nativeCompileResult : core.result.Result NativeCompiledWrite NativeCompileError →
    Except RequestCompiler.CompileError RequestCompiler.Compiled
  | .Ok output => .ok (nativeCompiledWrite output)
  | .Err error => .error (nativeCompileError error)

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RequestCompiler
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

@[step] theorem native_write_method_allowed_exact
    (method : AuthsNativeRecipe.auths_gateway_kernel.construct.RequestMethod) :
    AuthsNativeRecipe.auths_gateway_kernel.request_compiler.write_method_allowed method ⦃ actual =>
      actual = writeMethodAllowed (kernelWriteMethod method) ⦄ := by
  cases method <;> rfl

/-- Complete actual write compilation against the field layout earned from
the supplied FieldSpec slice. Every component/refusal and its ordering stays
in the result; no accepted layout, selected index or compiler outcome is a
premise. Native AST/source approval remains the next outer composition. -/
@[step] theorem native_compile_write_exact (fields : Slice NativeFieldSpec) (source : NativeWriteSource) :
    AuthsNativeRecipe.auths_gateway_kernel.request_compiler.compile_write fields source ⦃ actual =>
      nativeCompileResult actual = compile (nativeFieldColumn fields) (nativeWriteSource source) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.request_compiler.compile_write
  step with native_schema_field_names_exact fields as ⟨named, namesMeaning⟩
  cases named with
  | Err error =>
      have invalid : ¬FieldProjection.LayoutValid (nativeFieldColumn fields) := by
        intro valid
        simp [nativeNamesResult, valid] at namesMeaning
      simp [nativeCompileResult, nativeCompileError, compile, invalid]
  | Ok names =>
      have layout : FieldProjection.LayoutValid (nativeFieldColumn fields) := by
        by_contra invalid
        simp [nativeNamesResult, invalid] at namesMeaning
      have originalNames : names.val.map bytes = FieldProjection.names (nativeFieldColumn fields) := by
        simpa only [layout, ↓reduceIte, nativeNamesResult, Except.ok.injEq] using namesMeaning
      step with native_vector_clone_exact (AuthsNativeRecipe.core.clone.CloneallocvecVec core.clone.CloneU8)
        names (by intro name _; exact native_vector_clone_result core.clone.CloneU8 name (by intro byte _; rfl))
        as ⟨copiedNames, namesCopyMeaning⟩
      have indexedNames : nativeNameColumn (AuthsNativeRecipe.alloc.vec.Vec.deref copiedNames) =
          FieldProjection.names (nativeFieldColumn fields) := by
        simpa only [nativeNameColumn, native_deref_contents, namesCopyMeaning] using originalNames
      step with native_origin_frame_exact source.origin source.parsed_host as ⟨origin, originMeaning⟩
      cases origin with
      | false =>
          have invalid : ¬PathCompiler.OriginMatches (schemaSliceBytes source.origin)
              (schemaSliceBytes source.parsed_host) := by simpa using originMeaning.symm
          simp [nativeCompileResult, nativeCompileError, compile, nativeWriteSource, layout, invalid]
      | true =>
          have originFrame : PathCompiler.OriginMatches (schemaSliceBytes source.origin)
              (schemaSliceBytes source.parsed_host) := by simpa using originMeaning.symm
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_write_method_allowed_exact source.method as ⟨method, methodMeaning⟩
          cases method with
          | false =>
              simp [nativeCompileResult, nativeCompileError, compile, nativeWriteSource,
                layout, originFrame, ← methodMeaning]
          | true =>
              simp only [Bool.true_eq_true, ↓reduceIte]
              step with native_lower_headers_exact (AuthsNativeRecipe.alloc.vec.Vec.deref copiedNames)
                source.versions source.scope as ⟨headers, headerMeaning⟩
              cases headers with
              | Err error =>
                  simp [nativeCompileResult, nativeCompileError, compile, nativeWriteSource,
                    layout, originFrame, ← methodMeaning, ← headerMeaning, indexedNames, nativeHeaderResult]
              | Ok headers =>
                  step with native_header_plan_clone_exact headers as ⟨copiedHeaders, headersCopyMeaning⟩
                  step with native_lower_path_exact (AuthsNativeRecipe.alloc.vec.Vec.deref copiedNames)
                    source.path as ⟨path, pathMeaning⟩
                  cases path with
                  | Err error =>
                      simp [nativeCompileResult, nativeCompileError, compile, nativeWriteSource,
                        layout, originFrame, ← methodMeaning, ← headerMeaning, ← pathMeaning,
                        indexedNames, nativeHeaderResult, nativeConstructResult]
                  | Ok path =>
                      step with native_vector_clone_exact AuthsNativeRecipe.auths_gateway_kernel.construct.SegmentPlan.Insts.CoreCloneClone
                        path (by
                          intro segment _
                          obtain ⟨actual, run, same⟩ := spec_imp_exists (native_segment_clone_exact segment)
                          simpa only [same] using run) as ⟨copiedPath, pathCopyMeaning⟩
                      step with native_named_body_lowering_exact (AuthsNativeRecipe.alloc.vec.Vec.deref copiedNames)
                        source.body as ⟨body, bodyMeaning⟩
                      cases body with
                      | Err error =>
                          simp [nativeCompileResult, nativeCompileError, compile, nativeWriteSource,
                            layout, originFrame, ← methodMeaning, ← headerMeaning, ← pathMeaning,
                            ← bodyMeaning, indexedNames, nativeHeaderResult, nativeConstructResult]
                      | Ok body =>
                          step with native_body_plan_clone_exact body as ⟨copiedBody, bodyCopyMeaning⟩
                          cases idempotency : source.idempotency_header with
                          | false =>
                              simp only [idempotency, Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
                              step with native_schema_copy_bytes source.origin as ⟨originBytes, copyMeaning⟩
                              simp [nativeCompileResult, nativeCompiledWrite, nativeWritePlan, compile,
                                nativeWriteSource, layout, originFrame, ← methodMeaning, ← headerMeaning,
                                ← pathMeaning, ← bodyMeaning, indexedNames, nativeHeaderResult, nativeConstructResult,
                                namesCopyMeaning, headersCopyMeaning, pathCopyMeaning, bodyCopyMeaning,
                                originalNames, idempotency, bytes, copyMeaning, schemaSliceBytes]
                          | true =>
                              simp only [idempotency, ↓reduceIte]
                              step as ⟨headerName, headerNameMeaning⟩
                              step with native_schema_copy_bytes headerName as ⟨headerBytes, headerCopyMeaning⟩
                              step with native_schema_copy_bytes source.origin as ⟨originBytes, copyMeaning⟩
                              simp [nativeCompileResult, nativeCompiledWrite, nativeWritePlan, compile,
                                nativeWriteSource, layout, originFrame, ← methodMeaning, ← headerMeaning,
                                ← pathMeaning, ← bodyMeaning, indexedNames, nativeHeaderResult, nativeConstructResult,
                                namesCopyMeaning, headersCopyMeaning, pathCopyMeaning, bodyCopyMeaning,
                                originalNames, idempotency, idempotencyHeader, bytes, copyMeaning,
                                headerNameMeaning, headerCopyMeaning, schemaSliceBytes]

theorem native_write_success_has_complete_meaning (fields : Slice NativeFieldSpec) (source : NativeWriteSource) :
    AuthsNativeRecipe.auths_gateway_kernel.request_compiler.compile_write fields source ⦃ actual =>
      ∀ compiled, actual = .Ok compiled →
        CompilationMeaning (nativeFieldColumn fields) (nativeWriteSource source) (nativeCompiledWrite compiled) ⦄ := by
  apply spec_mono (native_compile_write_exact fields source)
  intro actual exact compiled accepted
  rw [accepted] at exact
  exact compile_sound _ _ _ (by simpa only [nativeCompileResult] using exact.symm)

theorem native_write_useful_compilation (fields : Slice NativeFieldSpec) (source : NativeWriteSource)
    (admitted : Admissible (nativeFieldColumn fields) (nativeWriteSource source)) :
    AuthsNativeRecipe.auths_gateway_kernel.request_compiler.compile_write fields source ⦃ actual =>
      ∃ compiled, actual = .Ok compiled ∧
        CompilationMeaning (nativeFieldColumn fields) (nativeWriteSource source) (nativeCompiledWrite compiled) ⦄ := by
  obtain ⟨meaning, useful⟩ := compile_complete _ _ admitted
  apply spec_mono (native_compile_write_exact fields source)
  intro actual exact
  rw [useful] at exact
  cases actual with
  | Err error => simp only [nativeCompileResult, Except.error_ne_ok] at exact
  | Ok compiled =>
      have same : nativeCompiledWrite compiled = meaning := by
        simpa only [nativeCompileResult, Except.ok.injEq] using exact
      exact ⟨compiled, rfl, by simpa only [same] using compile_sound _ _ _ useful⟩

/-- The model writer interprets the complete original named source for every
aligned argument environment. Actual wire-writer/driver consumption is a
separate source bridge, not hidden in the meaning of this statement. -/
theorem native_write_plan_has_named_rendering (fields : Slice NativeFieldSpec) (source : NativeWriteSource) :
    AuthsNativeRecipe.auths_gateway_kernel.request_compiler.compile_write fields source ⦃ actual =>
      ∀ compiled, actual = .Ok compiled → ∀ values environment echo key,
        SchemaIndex.Aligned (FieldProjection.names (nativeFieldColumn fields)) values environment →
        RequestConstruction.constructWrite (nativeWritePlan compiled.plan) values echo key =
          namedRequest environment (nativeWriteSource source) echo key ⦄ := by
  apply spec_mono (native_write_success_has_complete_meaning fields source)
  intro actual exact compiled accepted values environment echo key aligned
  exact compiled_request_preserves_named_source _ _ _ _ _ _ _ (exact compiled accepted) aligned

end Auths.Product.NativeCompiler.Refinement
