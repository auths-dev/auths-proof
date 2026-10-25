import Auths.Product.NativeCompilerFormEmission

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RequestConstruction TemplateAst
set_option maxHeartbeats 12000000
set_option maxRecDepth 4096

/- These two private statements factor exact subexpressions of compile_body.
The public theorem unfolds the actual translated caller. Neither statement
supplies a compiler result or models an Auths call as an external operation. -/
private theorem native_json_program_exact (value : KernelAst) (meaning : TemplateAst.Value)
    (original : AstKernelMeaning value meaning) (echo : Option (Slice (NativeVec Std.U8))) :
    (do
      let output ← AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_start 0#usize
      let (result, output1) ← AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_value value echo 0#usize output
      match result with
      | .Err error => ok (.Err error)
      | .Ok _ =>
          let (pieces, _) ← AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_finish output1
          ok (.Ok (AuthsNativeRecipe.auths_gateway_kernel.template_ast.NamedTemplate.Json pieces)))
      ⦃ actual => nativeTemplateResult nativeTemplate actual =
        (emitJson 7 meaning (nativeEchoTokens echo) 0 (jsonStart 0)).map (fun output => .json output.pieces) ⦄ := by
  step with native_json_start_exact 0#usize as ⟨initial, initialMeaning⟩
  step with native_json_value_effect value meaning original echo 0#usize initial as ⟨rendered, renderedMeaning⟩
  rcases rendered with ⟨result, current⟩
  cases result with
  | Err error =>
      simp [← renderedMeaning, initialMeaning, nativeJsonEffect, nativeTemplateResult]
  | Ok unit =>
      simp only [bind_tc_ok]
      step with native_json_finish_exact current as ⟨finished, pieces, nodes, resources, emptied⟩
      simp [← renderedMeaning, initialMeaning, nativeJsonEffect, nativeTemplateResult,
        nativeTemplate, nativeJsonBuild, pieces]

private theorem native_form_program_exact (fields : NativeVec KernelFormMember)
    (meanings : List (List Nat × TemplateAst.FormValue))
    (original : List.Forall₂ KernelFormMemberMeaning fields.val meanings) (insertion : Option (Slice Std.U8)) :
    (do
      let keys ← AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_keys
        (AuthsNativeRecipe.alloc.vec.Vec.deref fields)
      match keys with
      | .Err error => ok (.Err error)
      | .Ok keys =>
          let order ← AuthsNativeRecipe.auths_gateway_kernel.template_members.canonical_members
            (AuthsNativeRecipe.alloc.vec.Vec.deref keys) insertion .Form
          match order with
          | .Err error =>
              let mapped ← AuthsNativeRecipe.auths_gateway_kernel.template_ast.member_error error
              ok (.Err mapped)
          | .Ok order =>
              let output ← AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_start
              let (result, output1) ← AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_members
                (AuthsNativeRecipe.alloc.vec.Vec.deref fields) (AuthsNativeRecipe.alloc.vec.Vec.deref order) insertion output
              match result with
              | .Err error => ok (.Err error)
              | .Ok _ =>
                  let (pieces, _) ← AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_finish output1
                  ok (.Ok (AuthsNativeRecipe.auths_gateway_kernel.template_ast.NamedTemplate.Form pieces)))
      ⦃ actual => nativeTemplateResult nativeTemplate actual = formProgram meanings (insertion.map schemaSliceBytes) ⦄ := by
  have names : meanings.map Prod.fst = nativeFormNames (AuthsNativeRecipe.alloc.vec.Vec.deref fields) :=
    kernel_form_original_names original
  rw [form_program_key_preflight]
  step with native_form_keys_exact (AuthsNativeRecipe.alloc.vec.Vec.deref fields) as ⟨keys, keysMeaning⟩
  cases keys with
  | Err error => simp [names, ← keysMeaning, nativeTemplateResult]
  | Ok keys =>
      have keysOriginal : nativeKeys keys = nativeFormNames (AuthsNativeRecipe.alloc.vec.Vec.deref fields) := by
        exact (key_names_success_earns_admission 16 _ _ (by
          simpa only [nativeTemplateResult] using keysMeaning.symm)).1
      step with native_canonical_members_exact (AuthsNativeRecipe.alloc.vec.Vec.deref keys) insertion .Form
        as ⟨order, orderMeaning⟩
      cases order with
      | Err error =>
          step with native_member_error_exact error as ⟨mapped, mappedMeaning⟩
          simp [names, ← keysMeaning, ← orderMeaning, nativeTemplateResult, nativeMemberResult,
            nativeMemberDomain, keysOriginal, mappedMeaning]
      | Ok order =>
          have memberRun : TemplateMembers.canonicalMembers
              (nativeFormNames (AuthsNativeRecipe.alloc.vec.Vec.deref fields))
              (insertion.map schemaSliceBytes) .form = .ok (nativeChoices order) := by
            simpa [nativeMemberResult, nativeMemberDomain, keysOriginal] using orderMeaning.symm
          have prefixes := canonical_members_earn_prefix_domain _ _ _ _ memberRun
          step with native_form_start_exact as ⟨initial, initialMeaning⟩
          unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_members
          step with EmitterInternal.form_suffix_exact (AuthsNativeRecipe.alloc.vec.Vec.deref fields)
            meanings original (AuthsNativeRecipe.alloc.vec.Vec.deref order) insertion initial 0#usize (by simp) prefixes
            as ⟨rendered, renderedMeaning⟩
          rcases rendered with ⟨result, current⟩
          cases result with
          | Err error =>
              simp [names, ← keysMeaning, ← orderMeaning, ← renderedMeaning, nativeTemplateResult,
                nativeFormEffect, nativeMemberResult, nativeMemberDomain, keysOriginal, nativeChoices,
                initialMeaning, formMembers]
          | Ok unit =>
              simp only [bind_tc_ok]
              step with native_form_finish_exact current as ⟨finished, pieces, nodes, resources, emptied⟩
              simp [names, ← keysMeaning, ← orderMeaning, ← renderedMeaning, nativeTemplateResult,
                nativeFormEffect, nativeMemberResult, nativeMemberDomain, keysOriginal, nativeChoices,
                initialMeaning, formMembers, nativeTemplate, nativeFormBuild, pieces]

/-- Complete public body compiler outcome over original finite typed JSON/form
meaning and the complete declared echo. The result includes the full emitted
template or exact refusal, with no mutable partial state exposed by this API. -/
@[step] theorem native_compile_body_exact (body : KernelBody) (meaning : TemplateAst.Body)
    (original : BodyKernelMeaning body meaning) (echo : Option NativeEcho) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.compile_body body echo ⦃ actual =>
      nativeTemplateResult nativeTemplate actual = compileBody meaning (echo.map nativeEchoMeaning) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.compile_body
  cases original with
  | json originals =>
      cases echo with
      | none =>
          apply spec_mono (native_json_program_exact _ _ originals none)
          intro actual exact
          simpa [compileBody, nativeEchoTokens, Except.map] using exact
      | some echo =>
          cases echo with
          | Form name => simp [compileBody, nativeEchoMeaning, nativeTemplateResult, nativeTemplateError]
          | Json tokens =>
              simp only [AuthsNativeRecipe.alloc.vec.Vec.as_slice, bind_tc_ok]
              apply spec_mono (native_json_program_exact _ _ originals
                (some (AuthsNativeRecipe.alloc.vec.Vec.deref tokens)))
              intro actual exact
              simpa [compileBody, nativeEchoMeaning, nativeEchoTokens, nativeTokens, nativeTokenNames,
                Except.map] using exact
  | form originals =>
      rename_i fields meanings
      have lengths : fields.val.length = meanings.length := List.Forall₂.length_eq originals
      rw [compile_body_form_normalized]
      by_cases count : 0 < fields.val.length ∧ fields.val.length ≤ 16
      · have nonempty : ¬fields.val.isEmpty := by
          cases actual : fields.val <;> simp_all
        have nativeBound : ¬AuthsNativeRecipe.alloc.vec.Vec.len fields > 16#usize := by scalar_tac
        have modelCount : 0 < meanings.length ∧ meanings.length ≤ 16 := by omega
        simp only [AuthsNativeRecipe.alloc.vec.Vec.is_empty, nonempty, Bool.false_eq_true,
          nativeBound, modelCount, ↓reduceIte, bind_tc_ok]
        cases echo with
        | none =>
            simp only [Option.map_none, bind_tc_ok, core.mem.replace]
            exact native_form_program_exact fields meanings originals none
        | some echo =>
            cases echo with
            | Json tokens => simp [nativeEchoMeaning, nativeTemplateResult, nativeTemplateError]
            | Form name =>
                simp only [AuthsNativeRecipe.alloc.vec.Vec.as_slice, bind_tc_ok, core.mem.replace]
                apply spec_mono (native_form_program_exact fields meanings originals
                  (some (AuthsNativeRecipe.alloc.vec.Vec.deref name)))
                intro actual exact
                simpa [nativeEchoMeaning, schemaSliceBytes, bytes] using exact
      · have modelCount : ¬(0 < meanings.length ∧ meanings.length ≤ 16) := by omega
        by_cases empty : fields.val = []
        · simp [AuthsNativeRecipe.alloc.vec.Vec.is_empty, empty, modelCount,
            nativeTemplateResult, nativeTemplateError]
        · have nativeLarge : AuthsNativeRecipe.alloc.vec.Vec.len fields > 16#usize := by
            have positive := List.length_pos.mpr empty
            scalar_tac
          have nonempty : fields.val.isEmpty = false := List.isEmpty_eq_false.mpr empty
          simp [AuthsNativeRecipe.alloc.vec.Vec.is_empty, nonempty, nativeLarge, modelCount,
            nativeTemplateResult, nativeTemplateError]

end Auths.Product.NativeCompiler.Refinement
