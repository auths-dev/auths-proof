import Auths.Product.TemplateAstTraversalRefinement
import Auths.Product.TemplateAstCorrespondence

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.Refinement.Gateway
open Auths.Product.BodyCompiler.Refinement

namespace Auths.Product.TemplateAst.Refinement
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

@[step] theorem form_json_allowed_exact (value : template_ast.Value) : template_ast.form_json_allowed value ⦃ actual =>
    actual = decide (FormJsonAllowed (valueOf value)) ⦄ := by
  cases value <;> simp [template_ast.form_json_allowed, valueOf, FormJsonAllowed, array_source_order_preserved]

@[step] theorem form_value_exact (value : template_ast.FormValue) (output : template_ast.FormBuild) :
    template_ast.form_value value output ⦃ actual => templateResult formBuildOf actual = emitFormValue (formValueOf value) (formBuildOf output) ⦄ := by
  unfold template_ast.form_value
  cases value with
  | String text =>
    by_cases large : 1024 < text.val.length
    · have native : text.len > 1024#usize := by scalar_tac
      have model : ¬(vecBytes text).length ≤ 1024 := by simpa [vecBytes, byteList] using Nat.not_le.mpr large
      simp [native, emitFormValue, formValueOf, model, templateResult, templateErrorOf]
    · have native : ¬text.len > 1024#usize := by scalar_tac
      have size : text.val.length ≤ 1024 := by omega
      have model : (vecBytes text).length ≤ 1024 := by simpa [vecBytes, byteList] using size
      have encodedSize := BodyCompiler.form_encode_length (vecBytes text)
      have fits : (alloc.vec.Vec.new U8).val.length + (formEncode (byteList text.val)).length < 4294967295 := by
        simp only [alloc.vec.Vec.new, List.length_nil, zero_add]
        simp only [vecBytes, byteList, List.length_map] at encodedSize
        omega
      simp only [native, ↓reduceIte]
      step with append_form_encoded_spec as ⟨encoded, encodedMeaning⟩
      apply spec_mono (form_push_exact output (.Raw encoded))
      intro actual meaning
      simpa [emitFormValue, formValueOf, model, formSourceView, vecBytes, encodedMeaning] using meaning
  | Field name =>
    step with rendered_field_exact as ⟨allowed, allowedMeaning⟩
    cases allowed with
    | false =>
      have invalid : ¬RenderedField (vecBytes name) := by simpa [vecBytes, sliceBytes] using allowedMeaning.symm
      simp [emitFormValue, formValueOf, invalid, templateResult, templateErrorOf]
    | true =>
      have valid : RenderedField (vecBytes name) := by simpa [vecBytes, sliceBytes] using allowedMeaning.symm
      have size : name.val.length ≤ 64 := by
        simpa [vecBytes, byteList] using (TemplateMembers.token_shape_bounds _ valid.1).2.1
      step with copy_bytes_spec as ⟨copied, copiedMeaning⟩
      apply spec_mono (form_push_exact output (.Field copied))
      intro actual meaning
      simpa [emitFormValue, formValueOf, valid, formSourceView, vecBytes, copiedMeaning] using meaning
  | AuthorEcho => rfl
  | Json value =>
    step with form_json_allowed_exact as ⟨allowed, allowedMeaning⟩
    cases allowed with
    | false =>
      have invalid : ¬FormJsonAllowed (valueOf value) := by simpa using allowedMeaning.symm
      simp [emitFormValue, formValueOf, invalid, templateResult, templateErrorOf]
    | true =>
      have valid : FormJsonAllowed (valueOf value) := by simpa using allowedMeaning.symm
      step with json_start_exact as ⟨initial, initialMeaning⟩
      step with json_value_exact as ⟨nested, nestedMeaning⟩
      cases nested with
      | Err error => simp [emitFormValue, formValueOf, valid, ← initialMeaning, ← nestedMeaning, templateResult]
      | Ok nested =>
        apply spec_mono (form_push_exact { output with nodes := nested.nodes } (.Json nested.pieces))
        intro actual meaning
        simpa [emitFormValue, formValueOf, valid, ← initialMeaning, ← nestedMeaning, templateResult,
          formBuildOf, jsonBuildOf, formSourceView] using meaning

private theorem form_member_exact (fields : Slice template_ast.FormMember) (choice : template_members.MemberChoice)
    (insertion : Option (Slice U8)) (position : Usize) (output : template_ast.FormBuild)
    (prefixes : PrefixDomain (formFieldNames fields.val) (insertion.map sliceBytes)) :
    template_ast.form_member fields choice insertion position output ⦃ actual => templateResult formBuildOf actual =
      formStep (formMembersOf fields.val) (insertion.map sliceBytes) (formBuildOf output)
        (TemplateMembers.Refinement.choiceOf choice, position.val) ⦄ := by
  unfold template_ast.form_member
  have separator : decide (position > 0#usize) = decide (0 < position.val) := by scalar_tac
  cases choice with
  | Source index =>
    step as ⟨selected, selectedMeaning⟩
    cases selected with
    | none => simp [formStep, formMembersOf, selectedMeaning, TemplateMembers.Refinement.choiceOf,
        templateResult, templateErrorOf]
    | some member =>
      have present : vecBytes member.name ∈ formFieldNames fields.val := by
        exact List.mem_map.mpr ⟨member, List.mem_iff_getElem?.mpr ⟨index.val, selectedMeaning⟩, rfl⟩
      have size : member.name.val.length ≤ 130 := by
        simpa [vecBytes, byteList] using prefixes.1 _ present
      step with form_prefix_exact as ⟨prefix, prefixMeaning⟩
      step with form_push_exact as ⟨prefixed, prefixedMeaning⟩
      cases prefixed with
      | Err error => simp [formStep, formMembersOf, selectedMeaning, TemplateMembers.Refinement.choiceOf,
          ← prefixedMeaning, prefixMeaning, separator, templateResult, formSourceView]
      | Ok prefixed =>
        apply spec_mono (form_value_exact member.value prefixed)
        intro actual meaning
        simpa [formStep, formMembersOf, selectedMeaning, TemplateMembers.Refinement.choiceOf,
          ← prefixedMeaning, prefixMeaning, separator, templateResult, formSourceView] using meaning
  | Echo =>
    cases insertion with
    | none => simp [formStep, TemplateMembers.Refinement.choiceOf, templateResult, templateErrorOf]
    | some name =>
      have size : name.val.length ≤ 130 := by simpa [sliceBytes, byteList] using prefixes.2 (sliceBytes name) rfl
      step with form_prefix_exact as ⟨prefix, prefixMeaning⟩
      step with form_push_exact as ⟨prefixed, prefixedMeaning⟩
      cases prefixed with
      | Err error => simp [formStep, TemplateMembers.Refinement.choiceOf, ← prefixedMeaning,
          prefixMeaning, separator, templateResult, formSourceView]
      | Ok prefixed =>
        apply spec_mono (form_push_exact prefixed .Echo)
        intro actual meaning
        simpa [formStep, TemplateMembers.Refinement.choiceOf, ← prefixedMeaning,
          prefixMeaning, separator, templateResult, formSourceView] using meaning

private theorem form_loop_exact (fields : Slice template_ast.FormMember) (order : Slice template_members.MemberChoice)
    (insertion : Option (Slice U8)) (output : template_ast.FormBuild)
    (prefixes : PrefixDomain (formFieldNames fields.val) (insertion.map sliceBytes)) :
    template_ast.form_members_loop fields order insertion output 0#usize ⦃ actual => templateResult formBuildOf actual =
      formFrom (formMembersOf fields.val) (order.val.map TemplateMembers.Refinement.choiceOf) (insertion.map sliceBytes) 0 (formBuildOf output) ⦄ := by
  unfold template_ast.form_members_loop
  apply loop.spec_decr_nat
    (measure := fun state => order.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ order.val.length ∧
      formFrom (formMembersOf fields.val) (order.val.map TemplateMembers.Refinement.choiceOf) (insertion.map sliceBytes) 0 (formBuildOf output) =
        formFrom (formMembersOf fields.val) (order.val.map TemplateMembers.Refinement.choiceOf) (insertion.map sliceBytes) state.2.val (formBuildOf state.1))
  · rintro ⟨current, index⟩ invariant
    unfold template_ast.form_members_loop.body
    dsimp only
    split <;> rename_i guard
    · have inside : index.val < order.val.length := by scalar_tac
      have modelInside : index.val < (order.val.map TemplateMembers.Refinement.choiceOf).length := by simpa using inside
      have semantic := invariant.2
      rw [form_from_step _ _ _ _ _ modelInside] at semantic
      step as ⟨choice, choiceAt⟩
      step with form_member_exact as ⟨next, nextMeaning⟩
      cases next with
      | Err error => simpa [choiceAt, ← nextMeaning, templateResult, Bind.bind, Except.bind] using semantic.symm
      | Ok next =>
        have room : index.val + 1 ≤ Usize.max := by have bound := Slice.length_ineq order; omega
        step as ⟨nextIndex, nextIndexValue⟩
        refine ⟨by omega, ?_, by omega⟩
        simpa [choiceAt, ← nextMeaning, templateResult, nextIndexValue, Bind.bind, Except.bind] using semantic
    · have finished : (order.val.map TemplateMembers.Refinement.choiceOf).length ≤ index.val := by simp; scalar_tac
      rw [form_from_done _ _ _ _ _ finished] at invariant
      simpa [templateResult] using invariant.2.symm
  · exact ⟨by simp, rfl⟩

private theorem form_members_exact (fields : Slice template_ast.FormMember) (order : Slice template_members.MemberChoice)
    (insertion : Option (Slice U8)) (prefixes : PrefixDomain (formFieldNames fields.val) (insertion.map sliceBytes)) :
    template_ast.form_members fields order insertion ⦃ actual => templateResult formBuildOf actual =
      formMembers (formMembersOf fields.val) (order.val.map TemplateMembers.Refinement.choiceOf) (insertion.map sliceBytes) ⦄ := by
  unfold template_ast.form_members
  step with form_start_exact as ⟨initial, initialMeaning⟩
  apply spec_mono (form_loop_exact fields order insertion initial prefixes)
  intro actual meaning
  simpa [formMembers, initialMeaning] using meaning

private theorem compile_form_continuation (fields : Slice template_ast.FormMember) (keys : alloc.vec.Vec template_members.NamedKey)
    (insertion : Option (Slice U8))
    (keysExact : TemplateMembers.Refinement.keysView (alloc.vec.Vec.deref keys) = formFieldNames fields.val) :
    (do
      let order ← template_members.canonical_members (alloc.vec.Vec.deref keys) insertion .Form
      match order with
      | .Err error => do
        let mapped ← template_ast.member_error error
        ok (.Err mapped)
      | .Ok order => do
        let output ← template_ast.form_members fields (alloc.vec.Vec.deref order) insertion
        match output with
        | .Err error => ok (.Err error)
        | .Ok output => ok (.Ok (.Form output.pieces))) ⦃ actual => templateResult namedTemplateOf actual = do
          let order ← (TemplateMembers.canonicalMembers (formFieldNames fields.val) (insertion.map sliceBytes) .form).mapError memberError
          let output ← formMembers (formMembersOf fields.val) order (insertion.map sliceBytes)
          .ok (.form output.pieces) ⦄ := by
  step with TemplateMembers.Refinement.canonical_members_exact as ⟨order, orderMeaning⟩
  cases order with
  | Err error =>
    step with member_error_exact as ⟨mapped, mappedMeaning⟩
    simp [← orderMeaning, keysExact, TemplateMembers.Refinement.domainOf, TemplateMembers.Refinement.memberResult,
      templateResult, mappedMeaning, Except.mapError]
  | Ok order =>
    have run : TemplateMembers.canonicalMembers (formFieldNames fields.val) (insertion.map sliceBytes) .form =
        .ok (TemplateMembers.Refinement.choicesOf order) := by
      simpa [TemplateMembers.Refinement.memberResult, TemplateMembers.Refinement.domainOf, keysExact] using orderMeaning.symm
    have prefixes := canonical_members_earn_prefix_domain _ _ _ _ run
    step with form_members_exact as ⟨output, outputMeaning⟩
    cases output <;> simp [run, ← outputMeaning, templateResult, namedTemplateOf, formBuildOf,
      TemplateMembers.Refinement.choicesOf, alloc.vec.Vec.deref, Except.mapError]

/-- Complete source compilation, with all typed errors and native guard
precedence, refines the complete AST model. Name/echo prefix envelopes and
private recursive-call domains are derived inside the source proof. -/
@[step] theorem compile_body_exact (body : template_ast.Body) (echo : Option template_ast.Echo) :
    template_ast.compile_body body echo ⦃ actual => templateResult namedTemplateOf actual = compileBody (bodyOf body) (echo.map echoOf) ⦄ := by
  unfold template_ast.compile_body
  cases body with
  | Json value =>
    cases echo with
    | none =>
      step with json_start_exact as ⟨initial, initialMeaning⟩
      step with json_value_exact as ⟨output, outputMeaning⟩
      cases output <;> simp [compileBody, bodyOf, ← initialMeaning, ← outputMeaning, echoTokensOf,
        templateResult, namedTemplateOf, jsonBuildOf]
    | some echo =>
      cases echo with
      | Form name => simp [compileBody, bodyOf, echoOf, templateResult, templateErrorOf]
      | Json tokens =>
        step with json_start_exact as ⟨initial, initialMeaning⟩
        step with json_value_exact as ⟨output, outputMeaning⟩
        cases output <;> simp [compileBody, bodyOf, echoOf, ← initialMeaning, ← outputMeaning, echoTokensOf,
          TemplateMembers.Refinement.tokensView, templateResult, namedTemplateOf, jsonBuildOf]
  | Form fields =>
    step with form_keys_exact as ⟨keys, keysMeaning⟩
    cases keys with
    | Err error =>
      have invalid : ¬(0 < fields.val.length ∧ fields.val.length ≤ 16) := by
        intro admitted
        simp [admitted, templateResult] at keysMeaning
      simp [compileBody, bodyOf, formMembersOf, invalid, templateResult, templateErrorOf]
    | Ok keys =>
      have count : 0 < fields.val.length ∧ fields.val.length ≤ 16 := by
        by_contra invalid
        simp [invalid, templateResult] at keysMeaning
      have keysExact : TemplateMembers.Refinement.keysView (alloc.vec.Vec.deref keys) = formFieldNames fields.val := by
        simpa [count, templateResult] using keysMeaning
      cases echo with
      | none =>
        apply spec_mono (compile_form_continuation (alloc.vec.Vec.deref fields) keys none keysExact)
        intro actual meaning
        simpa [compileBody, bodyOf, formMembersOf, count, form_member_names_preserve_pairs,
          formMembers, formFrom, formStep] using meaning
      | some echo =>
        cases echo with
        | Json tokens => simp [compileBody, bodyOf, echoOf, formMembersOf, count, templateResult, templateErrorOf]
        | Form name =>
          apply spec_mono (compile_form_continuation (alloc.vec.Vec.deref fields) keys (some (alloc.vec.Vec.deref name)) keysExact)
          intro actual meaning
          simpa [compileBody, bodyOf, echoOf, formMembersOf, count, form_member_names_preserve_pairs,
            formMembers, formFrom, formStep, alloc.vec.Vec.deref, sliceBytes, vecBytes] using meaning

theorem source_body_earns_template_domain (body : template_ast.Body) (echo : Option template_ast.Echo) :
    template_ast.compile_body body echo ⦃ actual => ∀ output, actual = .Ok output → TemplateDomain (namedTemplateOf output) ⦄ := by
  apply spec_mono (compile_body_exact body echo)
  intro actual meaning output same
  rw [same] at meaning
  exact compile_body_earns_template_domain (bodyOf body) (echo.map echoOf) (namedTemplateOf output) meaning.symm

theorem source_body_refines_original_ast (body : template_ast.Body) (echo : Option template_ast.Echo)
    (environment : Bytes → Option RequestConstruction.Arg) (token : Bytes) :
    template_ast.compile_body body echo ⦃ actual => ∀ output, actual = .Ok output →
      interpretBody (bodyOf body) (echo.map echoOf) environment token = .ok (renderedTemplate (namedTemplateOf output) environment token) ⦄ := by
  apply spec_mono (compile_body_exact body echo)
  intro actual meaning output same
  rw [same] at meaning
  exact compile_body_refines_original_ast (bodyOf body) (echo.map echoOf) (namedTemplateOf output) meaning.symm environment token

theorem source_body_writer_reference_exact (body : template_ast.Body) (echo : Option template_ast.Echo)
    (environment : Bytes → Option RequestConstruction.Arg) (token : Bytes) :
    template_ast.compile_body body echo ⦃ actual => ∀ output, actual = .Ok output →
      referenceBody (bodyOf body) (echo.map echoOf) environment token = .ok
        (BodyCompiler.finishNamedBody (renderedTemplate (namedTemplateOf output) environment token).valid
          (renderedTemplate (namedTemplateOf output) environment token).bytes) ⦄ := by
  apply spec_mono (compile_body_exact body echo)
  intro actual meaning output same
  rw [same] at meaning
  exact compiled_body_reference_exact (bodyOf body) (echo.map echoOf) (namedTemplateOf output) meaning.symm environment token

end Auths.Product.TemplateAst.Refinement
