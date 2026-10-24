import Auths.Product.NativeCompilerJsonEmission

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

theorem kernel_form_original_names {fields : List KernelFormMember}
    {meanings : List (List Nat × TemplateAst.FormValue)}
    (original : List.Forall₂ KernelFormMemberMeaning fields meanings) :
    meanings.map Prod.fst = fields.map (fun field => bytes field.name) := by
  induction original with
  | nil => rfl
  | cons head tail ih => simp [head.1, ih]

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RequestConstruction TemplateAst
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

@[step] theorem native_form_json_allowed_exact (value : KernelAst) (meaning : TemplateAst.Value)
    (original : AstKernelMeaning value meaning) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_json_allowed value ⦃ actual =>
      actual = decide (FormJsonAllowed meaning) ⦄ := by
  cases original <;> simp [AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_json_allowed, FormJsonAllowed]
  rename_i items meanings originals
  have lengths := List.Forall₂.length_eq (kernel_values_full_relation originals)
  simp [AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_json_allowed,
    FormJsonAllowed, UScalar.eq_equiv, lengths]

@[step] theorem native_form_value_effect (value : KernelForm) (meaning : TemplateAst.FormValue)
    (original : FormKernelMeaning value meaning) (output : NativeFormBuild) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_value value output ⦃ actual =>
      nativeFormEffect actual = emitFormValue meaning (nativeFormBuild output) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_value
  cases original with
  | text text =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.MAX_LITERAL_BYTES
      by_cases large : 1024 < text.val.length
      · have nativeLarge : AuthsNativeRecipe.alloc.vec.Vec.len text > 1024#usize := by scalar_tac
        simp [nativeLarge, emitFormValue, bytes, Nat.not_le.mpr large,
          nativeFormEffect, nativeTemplateResult, nativeTemplateError]
      · have bounded : text.val.length ≤ 1024 := by omega
        have nativeBound : ¬AuthsNativeRecipe.alloc.vec.Vec.len text > 1024#usize := by scalar_tac
        simp only [nativeBound, ↓reduceIte]
        have encodedBound := BodyCompiler.form_encode_length (bytes text)
        have room : (AuthsNativeRecipe.alloc.vec.Vec.new Std.U8).val.length +
            (formEncode (schemaSliceBytes (AuthsNativeRecipe.alloc.vec.Vec.deref text))).length ≤ Usize.max := by
          simp only [native_empty_contents, List.length_nil, Nat.zero_add, schemaSliceBytes,
            native_deref_contents, ← bytes]
          simp only [bytes, List.length_map] at encodedBound
          scalar_tac
        step with native_form_encode_exact (AuthsNativeRecipe.alloc.vec.Vec.new Std.U8)
          (AuthsNativeRecipe.alloc.vec.Vec.deref text) room as ⟨encoded, encodedMeaning⟩
        apply spec_mono (native_form_push_exact output (.Raw encoded))
        intro actual exact
        simpa [emitFormValue, bounded, bytes, nativeNamedForm, encodedMeaning,
          schemaSliceBytes, native_empty_contents] using exact
  | field name =>
      step with native_rendered_field_exact (AuthsNativeRecipe.alloc.vec.Vec.deref name) as ⟨valid, validMeaning⟩
      cases valid with
      | false =>
          simp [emitFormValue, ← validMeaning, schemaSliceBytes, bytes, nativeFormEffect,
            nativeTemplateResult, nativeTemplateError]
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_schema_copy_bytes (AuthsNativeRecipe.alloc.vec.Vec.deref name) as ⟨copied, copiedMeaning⟩
          apply spec_mono (native_form_push_exact output (.Field copied))
          intro actual exact
          simpa [emitFormValue, ← validMeaning, schemaSliceBytes, bytes, nativeNamedForm, copiedMeaning] using exact
  | echo => simp [emitFormValue, nativeFormEffect, nativeTemplateResult, nativeTemplateError]
  | json originals =>
      step with native_form_json_allowed_exact _ _ originals as ⟨allowed, allowedMeaning⟩
      cases allowed with
      | false =>
          simp [emitFormValue, ← allowedMeaning, nativeFormEffect, nativeTemplateResult, nativeTemplateError]
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_json_start_exact output.nodes as ⟨nested, nestedMeaning⟩
          step with native_json_value_effect _ _ originals none 0#usize nested as ⟨rendered, renderedMeaning⟩
          rcases rendered with ⟨result, current⟩
          cases result with
          | Err error =>
              simp [emitFormValue, ← allowedMeaning, ← renderedMeaning, nestedMeaning,
                nativeFormEffect, nativeJsonEffect, nativeTemplateResult, nativeEchoTokens]
          | Ok unit =>
              simp only [bind_tc_ok]
              step with native_json_finish_exact current as ⟨finished, pieces, nodes, resources, emptied⟩
              apply spec_mono (native_form_push_exact { output with nodes := current.nodes } (.Json finished.1))
              intro actual exact
              simpa [emitFormValue, ← allowedMeaning, ← renderedMeaning, nestedMeaning, pieces,
                nativeJsonEffect, nativeTemplateResult, nativeEchoTokens, nativeJsonBuild,
                nativeFormBuild, nativeNamedForm] using exact

end Auths.Product.NativeCompiler.Refinement

namespace Auths.Product.NativeCompiler.EmitterInternal
open Auths.Product.NativeCompiler.StdModel
open Auths.Product.NativeCompiler.Refinement
open TemplateAst
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

theorem form_member_exact (fields : Slice KernelFormMember) (meanings : List (List Nat × TemplateAst.FormValue))
    (original : List.Forall₂ KernelFormMemberMeaning fields.val meanings) (choice : NativeChoice)
    (insertion : Option (Slice Std.U8)) (position : Std.Usize) (output : NativeFormBuild)
    (prefixes : PrefixDomain (nativeFormNames fields) (insertion.map schemaSliceBytes)) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_member fields choice insertion position output ⦃ actual =>
      nativeFormEffect actual = formStep meanings (insertion.map schemaSliceBytes)
        (nativeFormBuild output) (nativeChoice choice, position.val) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_member
  have separator : decide (position > 0#usize) = decide (0 < position.val) := by scalar_tac
  cases choice with
  | Source index =>
      step as ⟨selected, selectedMeaning⟩
      cases selected with
      | none =>
          have nativeAt : fields.val[index.val]? = none := by
            first | exact selectedMeaning | exact selectedMeaning.symm
          have modelAt : meanings[index.val]? = none := by
            have atPosition := original_relation_lookup original index.val
            cases atMeaning : meanings[index.val]? <;> simp_all
          simp [formStep, modelAt, nativeChoice, nativeFormEffect, nativeTemplateResult, nativeTemplateError]
      | some member =>
          have nativeAt : fields.val[index.val]? = some member := by
            first | exact selectedMeaning | exact selectedMeaning.symm
          obtain ⟨meaning, meaningAt, nameMeaning, valueMeaning⟩ := original_relation_selected original index.val member nativeAt
          have namePresent : bytes member.name ∈ nativeFormNames fields := by
            exact List.mem_map.mpr ⟨member, List.mem_iff_getElem?.mpr ⟨index.val, nativeAt⟩, rfl⟩
          have nameBound : member.name.val.length ≤ 130 := by
            simpa [bytes] using prefixes.1 (bytes member.name) namePresent
          step with native_form_prefix_exact (AuthsNativeRecipe.alloc.vec.Vec.deref member.name)
            (position > 0#usize) nameBound as ⟨prefix, prefixMeaning⟩
          step with native_form_push_exact output (.Raw prefix) as ⟨prefixed, prefixedMeaning⟩
          rcases prefixed with ⟨result, current⟩
          cases result with
          | Err error =>
              simp [formStep, meaningAt, nativeChoice, nameMeaning, ← prefixedMeaning,
                nativeFormEffect, nativeTemplateResult, nativeNamedForm, prefixMeaning,
                separator, schemaSliceBytes, bytes]
          | Ok unit =>
              simp only [bind_tc_ok]
              apply spec_mono (native_form_value_effect member.value meaning.2 valueMeaning current)
              intro actual exact
              simpa [formStep, meaningAt, nativeChoice, nameMeaning, ← prefixedMeaning,
                nativeFormEffect, nativeTemplateResult, nativeNamedForm, prefixMeaning,
                separator, schemaSliceBytes, bytes] using exact
  | Echo =>
      cases insertion with
      | none => simp [formStep, nativeChoice, nativeFormEffect, nativeTemplateResult, nativeTemplateError]
      | some name =>
          have nameBound : name.val.length ≤ 130 := by
            simpa [schemaSliceBytes] using prefixes.2 (schemaSliceBytes name) rfl
          step with native_form_prefix_exact name (position > 0#usize) nameBound as ⟨prefix, prefixMeaning⟩
          step with native_form_push_exact output (.Raw prefix) as ⟨prefixed, prefixedMeaning⟩
          rcases prefixed with ⟨result, current⟩
          cases result with
          | Err error =>
              simp [formStep, nativeChoice, ← prefixedMeaning, prefixMeaning, separator,
                nativeFormEffect, nativeTemplateResult, nativeNamedForm]
          | Ok unit =>
              simp only [bind_tc_ok]
              apply spec_mono (native_form_push_exact current .Echo)
              intro actual exact
              simpa [formStep, nativeChoice, ← prefixedMeaning, prefixMeaning, separator,
                nativeFormEffect, nativeTemplateResult, nativeNamedForm] using exact

theorem form_suffix_exact (fields : Slice KernelFormMember) (meanings : List (List Nat × TemplateAst.FormValue))
    (original : List.Forall₂ KernelFormMemberMeaning fields.val meanings) (order : Slice NativeChoice)
    (insertion : Option (Slice Std.U8)) (output : NativeFormBuild) (position : Std.Usize)
    (positionBound : position.val ≤ order.val.length)
    (prefixes : PrefixDomain (nativeFormNames fields) (insertion.map schemaSliceBytes)) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_members_loop fields order insertion output position ⦃ actual =>
      nativeFormEffect actual = formFrom meanings (order.val.map nativeChoice) (insertion.map schemaSliceBytes)
        position.val (nativeFormBuild output) ⦄ := by
  generalize remaining : order.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing output position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_members_loop
      by_cases inside : position.val < order.val.length
      · have nativeInside : position < order.len := by scalar_tac
        have modelInside : position.val < (order.val.map nativeChoice).length := by simpa using inside
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec order position inside as ⟨choice, choiceAt⟩
        step with form_member_exact fields meanings original choice insertion position output prefixes as ⟨rendered, renderedMeaning⟩
        rcases rendered with ⟨result, current⟩
        cases result with
        | Err error =>
            simp [form_from_step meanings (order.val.map nativeChoice) (insertion.map schemaSliceBytes)
              position.val (nativeFormBuild output) modelInside, choiceAt, ← renderedMeaning,
              nativeFormEffect, nativeTemplateResult]
        | Ok unit =>
            simp only [bind_tc_ok]
            step as ⟨nextPosition, nextPositionMeaning⟩
            apply spec_mono (ih _ (by omega) current nextPosition (by omega) rfl)
            intro actual exact
            simpa [form_from_step meanings (order.val.map nativeChoice) (insertion.map schemaSliceBytes)
              position.val (nativeFormBuild output) modelInside, choiceAt, ← renderedMeaning,
              nativeFormEffect, nativeTemplateResult, nextPositionMeaning] using exact
      · have nativeEnded : ¬position < order.len := by scalar_tac
        have modelEnded : (order.val.map nativeChoice).length ≤ position.val := by simpa using Nat.le_of_not_gt inside
        simp [nativeEnded, form_from_done meanings (order.val.map nativeChoice) (insertion.map schemaSliceBytes)
          position.val (nativeFormBuild output) modelEnded, nativeFormEffect, nativeTemplateResult]

end Auths.Product.NativeCompiler.EmitterInternal
