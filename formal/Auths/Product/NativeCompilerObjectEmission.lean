import Auths.Product.NativeCompilerArrayEmission

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.EmitterInternal
open Auths.Product.NativeCompiler.StdModel
open Auths.Product.NativeCompiler.Refinement
open TemplateAst
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

theorem object_member_exact (fields : Slice KernelMember) (meanings : List (List Nat × TemplateAst.Value))
    (original : AstKernelMembersMeaning fields.val meanings) (choice : NativeChoice)
    (target : Option NativeTarget) (echo : Option (Slice (NativeVec Std.U8)))
    (insertion : Option (Slice Std.U8)) (depth position : Std.Usize) (output : NativeJsonBuild)
    (depthBound : depth.val ≤ 6)
    (prefixes : PrefixDomain (nativeJsonNames fields) (insertion.map schemaSliceBytes))
    (children : JsonChildren depth.val) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_member fields choice target echo insertion
      depth position output ⦃ actual => nativeJsonEffect actual = objectStep meanings
        (nativeOptionalTarget target) (nativeEchoTokens echo) (insertion.map schemaSliceBytes)
        depth.val (nativeJsonBuild output) (nativeChoice choice, position.val) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_member
  have relation := kernel_members_full_relation original
  have separator : decide (position > 0#usize) = decide (0 < position.val) := by scalar_tac
  cases choice with
  | Source index =>
      step as ⟨selected, selectedMeaning⟩
      cases selected with
      | none =>
          have nativeAt : fields.val[index.val]? = none := by
            first | exact selectedMeaning | exact selectedMeaning.symm
          have modelAt : meanings[index.val]? = none := by
            have atPosition := original_relation_lookup relation index.val
            cases atMeaning : meanings[index.val]? <;> simp_all
          simp [objectStep, modelAt, nativeChoice, nativeJsonEffect, nativeTemplateResult, nativeTemplateError]
      | some member =>
          have nativeAt : fields.val[index.val]? = some member := by
            first | exact selectedMeaning | exact selectedMeaning.symm
          obtain ⟨meaning, meaningAt, nameMeaning, childMeaning⟩ := original_relation_selected relation index.val member nativeAt
          have namePresent : bytes member.name ∈ nativeJsonNames fields := by
            exact List.mem_map.mpr ⟨member, List.mem_iff_getElem?.mpr ⟨index.val, nativeAt⟩, rfl⟩
          have nameBound : member.name.val.length ≤ 130 := by
            simpa [bytes] using prefixes.1 (bytes member.name) namePresent
          step with native_json_prefix_exact (AuthsNativeRecipe.alloc.vec.Vec.deref member.name)
            (position > 0#usize) nameBound as ⟨prefix, prefixMeaning⟩
          step with native_json_push_exact output (.Raw prefix) as ⟨prefixed, prefixedMeaning⟩
          rcases prefixed with ⟨result, current⟩
          cases result with
          | Err error =>
              simp [objectStep, meaningAt, nativeChoice, nameMeaning, ← prefixedMeaning,
                nativeJsonEffect, nativeTemplateResult, nativeNamedJson, prefixMeaning, separator,
                schemaSliceBytes, bytes]
          | Ok unit =>
              simp only [bind_tc_ok]
              step with native_ast_child_echo_exact target echo index as ⟨nested, nestedMeaning⟩
              cases nested with
              | Err error =>
                  simp [objectStep, meaningAt, nativeChoice, nameMeaning, ← prefixedMeaning,
                    ← nestedMeaning, nativeJsonEffect, nativeTemplateResult, nativeNamedJson,
                    prefixMeaning, separator, schemaSliceBytes, bytes]
              | Ok nested =>
                  step as ⟨nextDepth, nextDepthMeaning⟩
                  apply spec_mono (children member.value meaning.2 childMeaning nested nextDepth current nextDepthMeaning)
                  intro actual exact
                  simpa [objectStep, meaningAt, nativeChoice, nameMeaning, ← prefixedMeaning,
                    ← nestedMeaning, nativeJsonEffect, nativeTemplateResult, nativeNamedJson,
                    prefixMeaning, separator, schemaSliceBytes, bytes, nextDepthMeaning] using exact
  | Echo =>
      cases insertion with
      | none => simp [objectStep, nativeChoice, nativeJsonEffect, nativeTemplateResult, nativeTemplateError]
      | some name =>
          have nameBound : name.val.length ≤ 130 := by
            simpa [schemaSliceBytes] using prefixes.2 (schemaSliceBytes name) rfl
          step with native_json_prefix_exact name (position > 0#usize) nameBound as ⟨prefix, prefixMeaning⟩
          step with native_json_push_exact output (.Raw prefix) as ⟨prefixed, prefixedMeaning⟩
          rcases prefixed with ⟨result, current⟩
          cases result with
          | Err error =>
              simp [objectStep, nativeChoice, ← prefixedMeaning, prefixMeaning, separator,
                nativeJsonEffect, nativeTemplateResult, nativeNamedJson]
          | Ok unit =>
              simp only [bind_tc_ok]
              apply spec_mono (native_json_push_exact current .Echo)
              intro actual exact
              simpa [objectStep, nativeChoice, ← prefixedMeaning, prefixMeaning, separator,
                nativeJsonEffect, nativeTemplateResult, nativeNamedJson] using exact

theorem object_suffix_exact (fields : Slice KernelMember) (meanings : List (List Nat × TemplateAst.Value))
    (original : AstKernelMembersMeaning fields.val meanings) (order : Slice NativeChoice)
    (target : Option NativeTarget) (echo : Option (Slice (NativeVec Std.U8)))
    (insertion : Option (Slice Std.U8)) (depth : Std.Usize) (output : NativeJsonBuild)
    (position : Std.Usize) (positionBound : position.val ≤ order.val.length)
    (depthBound : depth.val ≤ 6)
    (prefixes : PrefixDomain (nativeJsonNames fields) (insertion.map schemaSliceBytes))
    (children : JsonChildren depth.val) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_members_loop fields order target echo insertion
      depth output position ⦃ actual => nativeJsonEffect actual = objectFrom meanings (order.val.map nativeChoice)
        (nativeOptionalTarget target) (nativeEchoTokens echo) (insertion.map schemaSliceBytes)
        depth.val position.val (nativeJsonBuild output) ⦄ := by
  generalize remaining : order.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing output position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_members_loop
      by_cases inside : position.val < order.val.length
      · have nativeInside : position < order.len := by scalar_tac
        have modelInside : position.val < (order.val.map nativeChoice).length := by simpa using inside
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec order position inside as ⟨choice, choiceAt⟩
        step with object_member_exact fields meanings original choice target echo insertion depth position output
          depthBound prefixes children as ⟨memberResult, memberMeaning⟩
        rcases memberResult with ⟨result, current⟩
        cases result with
        | Err error =>
            simp [object_from_step meanings (order.val.map nativeChoice) (nativeOptionalTarget target)
              (nativeEchoTokens echo) (insertion.map schemaSliceBytes) depth.val position.val
              (nativeJsonBuild output) modelInside, choiceAt, ← memberMeaning, nativeJsonEffect, nativeTemplateResult]
        | Ok unit =>
            simp only [bind_tc_ok]
            step as ⟨nextPosition, nextPositionMeaning⟩
            apply spec_mono (ih _ (by omega) current nextPosition (by omega) rfl)
            intro actual exact
            simpa [object_from_step meanings (order.val.map nativeChoice) (nativeOptionalTarget target)
              (nativeEchoTokens echo) (insertion.map schemaSliceBytes) depth.val position.val
              (nativeJsonBuild output) modelInside, choiceAt, ← memberMeaning, nativeJsonEffect,
              nativeTemplateResult, nextPositionMeaning] using exact
      · have nativeEnded : ¬position < order.len := by scalar_tac
        have modelEnded : (order.val.map nativeChoice).length ≤ position.val := by simpa using Nat.le_of_not_gt inside
        simp [nativeEnded, object_from_done meanings (order.val.map nativeChoice) (nativeOptionalTarget target)
          (nativeEchoTokens echo) (insertion.map schemaSliceBytes) depth.val position.val
          (nativeJsonBuild output) modelEnded, nativeJsonEffect, nativeTemplateResult]

theorem object_exact (fields : Slice KernelMember) (meanings : List (List Nat × TemplateAst.Value))
    (original : AstKernelMembersMeaning fields.val meanings) (echo : Option (Slice (NativeVec Std.U8)))
    (depth : Std.Usize) (output : NativeJsonBuild) (depthBound : depth.val ≤ 6)
    (children : JsonChildren depth.val) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_object fields echo depth output ⦃ actual =>
      nativeJsonEffect actual = jsonObject meanings (nativeEchoTokens echo) depth.val (nativeJsonBuild output) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_object
  have names : meanings.map Prod.fst = nativeJsonNames fields := kernel_members_original_names original
  rw [json_object_key_preflight]
  step with native_json_keys_exact fields as ⟨keys, keysMeaning⟩
  cases keys with
  | Err error =>
      simp [names, ← keysMeaning, nativeJsonEffect, nativeTemplateResult]
  | Ok keys =>
      have keysOriginal : nativeKeys keys = nativeJsonNames fields := by
        have admitted := key_names_success_earns_admission 32 (nativeJsonNames fields) (nativeKeys keys)
          (by simpa only [nativeTemplateResult] using keysMeaning.symm)
        exact admitted.1
      simp only [core.mem.replace]
      step with native_ast_target_exact (AuthsNativeRecipe.alloc.vec.Vec.deref keys) echo as ⟨target, targetMeaning⟩
      cases target with
      | Err error =>
          simp [names, ← keysMeaning, ← targetMeaning, nativeJsonEffect, nativeTemplateResult,
            native_key_column_deref, keysOriginal]
      | Ok target =>
          step with native_ast_insertion_exact target echo as ⟨insertion, insertionMeaning⟩
          cases insertion with
          | Err error =>
              simp [names, ← keysMeaning, ← targetMeaning, ← insertionMeaning, nativeJsonEffect,
                nativeTemplateResult, native_key_column_deref, keysOriginal]
          | Ok insertion =>
              step with native_canonical_members_exact (AuthsNativeRecipe.alloc.vec.Vec.deref keys) insertion .Json
                as ⟨order, orderMeaning⟩
              cases order with
              | Err error =>
                  step with native_member_error_exact error as ⟨mapped, mappedMeaning⟩
                  simp [names, ← keysMeaning, ← targetMeaning, ← insertionMeaning, ← orderMeaning,
                    nativeJsonEffect, nativeTemplateResult, nativeMemberResult, nativeMemberDomain,
                    native_key_column_deref, keysOriginal, mappedMeaning]
              | Ok order =>
                  have memberRun : TemplateMembers.canonicalMembers (nativeJsonNames fields)
                      (insertion.map schemaSliceBytes) .json = .ok (nativeChoices order) := by
                    simpa [nativeMemberResult, nativeMemberDomain, keysOriginal] using orderMeaning.symm
                  have prefixes := canonical_members_earn_prefix_domain _ _ _ _ memberRun
                  simp only [core.mem.replace]
                  step as ⟨source, sourceMeaning⟩
                  step with native_schema_copy_bytes source as ⟨opening, openingMeaning⟩
                  step with native_json_push_exact output (.Raw opening) as ⟨opened, openedMeaning⟩
                  rcases opened with ⟨result, current⟩
                  cases result with
                  | Err error =>
                      simp [names, ← keysMeaning, ← targetMeaning, ← insertionMeaning, ← orderMeaning,
                        ← openedMeaning, nativeJsonEffect, nativeTemplateResult, nativeMemberResult,
                        nativeMemberDomain, keysOriginal, nativeNamedJson, bytes, openingMeaning, sourceMeaning]
                  | Ok unit =>
                      simp only [bind_tc_ok]
                      unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_members
                      step with object_suffix_exact fields meanings original (AuthsNativeRecipe.alloc.vec.Vec.deref order)
                        target echo insertion depth current 0#usize (by simp) depthBound prefixes children
                        as ⟨folded, foldedMeaning⟩
                      rcases folded with ⟨result, final⟩
                      cases result with
                      | Err error =>
                          simp [names, ← keysMeaning, ← targetMeaning, ← insertionMeaning, ← orderMeaning,
                            ← openedMeaning, ← foldedMeaning, nativeJsonEffect, nativeTemplateResult,
                            nativeMemberResult, nativeMemberDomain, keysOriginal, nativeChoices,
                            nativeNamedJson, bytes, openingMeaning, sourceMeaning]
                      | Ok unit =>
                          simp only [bind_tc_ok]
                          step as ⟨closingSource, closingSourceMeaning⟩
                          step with native_schema_copy_bytes closingSource as ⟨closing, closingMeaning⟩
                          apply spec_mono (native_json_push_exact final (.Raw closing))
                          intro actual exact
                          simpa [names, ← keysMeaning, ← targetMeaning, ← insertionMeaning, ← orderMeaning,
                            ← openedMeaning, ← foldedMeaning, nativeJsonEffect, nativeTemplateResult,
                            nativeMemberResult, nativeMemberDomain, keysOriginal, nativeChoices,
                            nativeNamedJson, bytes, openingMeaning, sourceMeaning, closingMeaning,
                            closingSourceMeaning] using exact

end Auths.Product.NativeCompiler.EmitterInternal
