import Auths.Product.NativeCompilerObjectEmission

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RequestConstruction TemplateAst
set_option maxHeartbeats 12000000
set_option maxRecDepth 4096

/-- Every original finite JSON AST, optional complete echo path, represented
depth and mutable builder. The original-meaning relation contains no accepted
grammar or emitted output. Source depth admission discharges the complete
recursive-child contracts; no child result is a public input premise. -/
@[step] theorem native_json_value_effect (value : KernelAst) (meaning : TemplateAst.Value)
    (original : AstKernelMeaning value meaning) (echo : Option (Slice (NativeVec Std.U8)))
    (depth : Std.Usize) (output : NativeJsonBuild) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_value value echo depth output ⦃ actual =>
      nativeJsonEffect actual = emitJson 7 meaning (nativeEchoTokens echo) depth.val (nativeJsonBuild output) ⦄ := by
  generalize remaining : 7 - depth.val = count
  induction count using Nat.strong_induction_on generalizing value meaning echo depth output with
  | h count ih =>
      rw [emit_json_dispatch_exact]
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_value dispatchJson
      step with native_node_charge_exact output.nodes depth as ⟨charged, chargedMeaning⟩
      cases charged with
      | Err error =>
          simp [← chargedMeaning, nativeJsonEffect, nativeTemplateResult]
      | Ok next =>
          have chargedRun : chargeNode output.nodes.val depth.val = .ok next.val := by
            simpa only [nativeTemplateResult] using chargedMeaning.symm
          have admission := charge_node_earns_domain _ _ _ chargedRun
          have depthBound : depth.val ≤ 6 := admission.2.1
          have children : EmitterInternal.JsonChildren depth.val := by
            intro child childMeaning childOriginal nested childDepth initial childDepthMeaning
            exact ih _ (by omega) child childMeaning childOriginal nested childDepth initial rfl
          cases original with
          | text text =>
              cases echo with
              | some tokens =>
                  simp [core.option.Option.is_some, nativeEchoTokens, isObject, chargedRun,
                    nativeJsonEffect, nativeTemplateResult, nativeTemplateError]
              | none =>
                  simp only [core.option.Option.is_some, Bool.false_eq_true, ↓reduceIte]
                  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.MAX_LITERAL_BYTES
                  by_cases large : 1024 < text.val.length
                  · have nativeLarge : AuthsNativeRecipe.alloc.vec.Vec.len text > 1024#usize := by scalar_tac
                    simp [nativeLarge, chargedRun, nativeEchoTokens, isObject, bytes,
                      Nat.not_le.mpr large, nativeJsonEffect, nativeTemplateResult, nativeTemplateError]
                  · have bounded : text.val.length ≤ 1024 := by omega
                    have nativeBound : ¬AuthsNativeRecipe.alloc.vec.Vec.len text > 1024#usize := by scalar_tac
                    simp only [nativeBound, ↓reduceIte]
                    have quoteBound := BodyCompiler.json_string_length (bytes text)
                    have room : (AuthsNativeRecipe.alloc.vec.Vec.new Std.U8).val.length +
                        (jsonString (schemaSliceBytes (AuthsNativeRecipe.alloc.vec.Vec.deref text))).length ≤ Usize.max := by
                      simp only [native_empty_contents, List.length_nil, Nat.zero_add, schemaSliceBytes,
                        native_deref_contents, ← bytes]
                      simp only [bytes, List.length_map] at quoteBound
                      scalar_tac
                    step with native_json_string_exact (AuthsNativeRecipe.alloc.vec.Vec.new Std.U8)
                      (AuthsNativeRecipe.alloc.vec.Vec.deref text) room as ⟨quoted, quotedMeaning⟩
                    apply spec_mono (native_json_push_exact { output with nodes := next } (.Raw quoted))
                    intro actual exact
                    simpa [chargedRun, nativeEchoTokens, isObject, bounded, nativeJsonBuild,
                      nativeNamedJson, quotedMeaning, schemaSliceBytes, bytes, native_empty_contents] using exact
          | integer integer =>
              cases echo with
              | some tokens =>
                  simp [core.option.Option.is_some, nativeEchoTokens, isObject, chargedRun,
                    nativeJsonEffect, nativeTemplateResult, nativeTemplateError]
              | none =>
                  simp only [core.option.Option.is_some, Bool.false_eq_true, ↓reduceIte]
                  unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.MAX_JSON_INTEGER
                  step as ⟨minimum, minimumMeaning⟩
                  step with native_integer_value_exact minimum 9007199254740991#i64 integer as ⟨valid, validMeaning⟩
                  have validity : valid = decide (-9007199254740991 ≤ integer.val ∧ integer.val ≤ 9007199254740991) := by
                    simpa [ScalarProjection.IntegerValue, ScalarProjection.IntegerSchema, minimumMeaning] using validMeaning
                  cases valid with
                  | false =>
                      simp [chargedRun, nativeEchoTokens, isObject, ← validity,
                        nativeJsonEffect, nativeTemplateResult, nativeTemplateError]
                  | true =>
                      simp only [Bool.true_eq_true, ↓reduceIte]
                      step with native_integer_literal_exact integer as ⟨literal, literalMeaning⟩
                      apply spec_mono (native_json_push_exact { output with nodes := next } (.Raw literal))
                      intro actual exact
                      simpa [chargedRun, nativeEchoTokens, isObject, ← validity, nativeJsonBuild,
                        nativeNamedJson, literalMeaning] using exact
          | boolean boolean =>
              cases echo with
              | some tokens =>
                  simp [core.option.Option.is_some, nativeEchoTokens, isObject, chargedRun,
                    nativeJsonEffect, nativeTemplateResult, nativeTemplateError]
              | none =>
                  simp only [core.option.Option.is_some, Bool.false_eq_true, ↓reduceIte]
                  cases boolean <;> simp only [Bool.false_eq_true, Bool.true_eq_true, ↓reduceIte]
                  all_goals
                    step as ⟨source, sourceMeaning⟩
                    step with native_schema_copy_bytes source as ⟨literal, literalMeaning⟩
                    apply spec_mono (native_json_push_exact { output with nodes := next } (.Raw literal))
                    intro actual exact
                    simpa [chargedRun, nativeEchoTokens, isObject, nativeJsonBuild, nativeNamedJson,
                      bytes, literalMeaning, sourceMeaning] using exact
          | field name =>
              cases echo with
              | some tokens =>
                  simp [core.option.Option.is_some, nativeEchoTokens, isObject, chargedRun,
                    nativeJsonEffect, nativeTemplateResult, nativeTemplateError]
              | none =>
                  simp only [core.option.Option.is_some, Bool.false_eq_true, ↓reduceIte]
                  step with native_rendered_field_exact (AuthsNativeRecipe.alloc.vec.Vec.deref name)
                    as ⟨valid, validMeaning⟩
                  cases valid with
                  | false =>
                      simp [chargedRun, nativeEchoTokens, isObject, ← validMeaning,
                        schemaSliceBytes, bytes, nativeJsonEffect, nativeTemplateResult, nativeTemplateError]
                  | true =>
                      simp only [Bool.true_eq_true, ↓reduceIte]
                      step with native_schema_copy_bytes (AuthsNativeRecipe.alloc.vec.Vec.deref name)
                        as ⟨copied, copiedMeaning⟩
                      apply spec_mono (native_json_push_exact { output with nodes := next } (.Field copied))
                      intro actual exact
                      simpa [chargedRun, nativeEchoTokens, isObject, ← validMeaning, nativeJsonBuild,
                        nativeNamedJson, schemaSliceBytes, bytes, copiedMeaning] using exact
          | array originals =>
              cases echo with
              | some tokens =>
                  simp [core.option.Option.is_some, nativeEchoTokens, isObject, chargedRun,
                    nativeJsonEffect, nativeTemplateResult, nativeTemplateError]
              | none =>
                  simp only [core.option.Option.is_some, Bool.false_eq_true, ↓reduceIte]
                  apply spec_mono (EmitterInternal.array_exact _ _ originals depth
                    { output with nodes := next } depthBound children)
                  intro actual exact
                  simpa [chargedRun, nativeEchoTokens, isObject, nativeJsonBuild] using exact
          | object originals =>
              cases echo <;> simp only [core.option.Option.is_some, Bool.false_eq_true,
                Bool.true_eq_true, ↓reduceIte, bind_tc_ok]
              all_goals
                apply spec_mono (EmitterInternal.object_exact _ _ originals _ depth
                  { output with nodes := next } depthBound children)
                intro actual exact
                simpa [chargedRun, nativeEchoTokens, isObject, nativeJsonBuild] using exact
          | echo =>
              cases echo <;> simp [core.option.Option.is_some, chargedRun, nativeEchoTokens, isObject,
                nativeJsonEffect, nativeTemplateResult, nativeTemplateError]

end Auths.Product.NativeCompiler.Refinement
