import Auths.Product.RequestBinding
import Auths.Product.FieldProjectionRefinement
import Auths.Product.DerivedTokensRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.Refinement.ByteIdentity

namespace Auths.Product.FieldProjection.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

def bindingErrorOf : field_projection.RequestBindingError → BindingError
  | .ActionMismatch => .actionMismatch
  | .Projection error => .projection (errorOf error)
  | .OperationId => .operationId

def boundArgumentsOf (actual : field_projection.RequestArguments) : BoundArguments :=
  ⟨actual.values.val.map argOf, vecBytes actual.operation_id⟩

def bindingResult : core.result.Result field_projection.RequestArguments field_projection.RequestBindingError →
    Except BindingError BoundArguments
  | .Err error => .error (bindingErrorOf error)
  | .Ok actual => .ok (boundArgumentsOf actual)

@[step] theorem text_member_exact (supplied : Slice field_projection.NamedInput) (name : Slice Std.U8) :
    field_projection.text_member supplied name ⦃ actual =>
      actual.map sliceBytes = textMember (sliceBytes name) (inputsView supplied) ⦄ := by
  unfold field_projection.text_member field_projection.text_member_loop
  apply loop.spec_decr_nat
    (measure := fun index => supplied.val.length - index.val)
    (inv := fun index => index.val ≤ supplied.val.length ∧
      textMember (sliceBytes name) (inputsView supplied) =
        textMember (sliceBytes name) ((inputsView supplied).drop index.val))
  · intro index invariant
    unfold field_projection.text_member_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < supplied.val.length := by simpa using within
      step as ⟨input, inputAt⟩
      have suffix : (inputsView supplied).drop index.val =
          (sliceBytes input.name, ScalarProjection.Dispatch.inputView input.value) ::
            (inputsView supplied).drop (index.val + 1) := by
        simpa [inputsView, List.drop_map, inputAt] using
          congrArg (List.map (fun row => (sliceBytes row.name, ScalarProjection.Dispatch.inputView row.value)))
            (List.drop_eq_getElem_cons inside)
      rw [suffix, textMember] at invariant
      step with field_name_equal_exact as ⟨same, sameMeaning⟩
      cases same
      · have different : sliceBytes input.name ≠ sliceBytes name := by
          intro equal
          have raw := byteList_inj _ _ |>.mp equal
          simp [raw] at sameMeaning
        simp only [Bool.false_eq_true, ↓reduceIte]
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, by omega⟩
        simpa [different, nextValue] using invariant.2
      · have equal : sliceBytes input.name = sliceBytes name := by
          simpa [sliceBytes] using congrArg byteList sameMeaning.symm
        cases value : input.value <;>
          simpa [equal, value, ScalarProjection.Dispatch.inputView, scalarText] using invariant.2.symm
    · have atEnd : supplied.val.length ≤ index.val := by simpa using within
      have modelEnd : (inputsView supplied).length ≤ index.val := by simpa [inputsView] using atEnd
      simpa [List.drop_of_length_le modelEnd, textMember] using invariant.2.symm
  · exact ⟨by simp, by simp⟩

/-- Actual request binding preserves exact native error precedence. All
projection/name/token facts are conclusions from the same supplied object. -/
@[step] theorem project_request_exact (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) (namespace recipe : Slice Std.U8) :
    field_projection.project_request fields supplied namespace recipe ⦃ actual =>
      RequestOutcome (fieldsView fields) (inputsView supplied) (sliceBytes namespace)
        (sliceBytes recipe) (bindingResult actual) ⦄ := by
  unfold field_projection.project_request arguments.MAX_PROFILE_FIELDS
  by_cases count : fields.val.length ≤ 32 ∧ supplied.val.length = fields.val.length
  · have nativeBound : ¬fields.len > 32#usize := by scalar_tac
    have nativeCount : supplied.len = fields.len := by scalar_tac
    simp only [nativeBound, nativeCount, bne_self_eq_false, Bool.false_or,
      Bool.false_eq_true, ↓reduceIte]
    step with OperationIdentity.Refinement.token_exact as ⟨namespaceValid, namespaceMeaning⟩
    cases namespaceValid
    · have invalid : OperationIdentity.validToken (sliceBytes namespace) 64 ≠ true := by
        simpa using namespaceMeaning.symm
      simp [RequestOutcome, RequestFrame, bindingResult, bindingErrorOf, invalid]
    · have namespaceToken : OperationIdentity.validToken (sliceBytes namespace) 64 = true := by
        simpa using namespaceMeaning.symm
      simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
      step with text_member_exact as ⟨actualNamespace, namespaceMember⟩
      cases actualNamespace with
      | none =>
        simp_all [RequestOutcome, RequestFrame, bindingResult, bindingErrorOf, namespaceName]
      | some actualNamespace =>
        step with field_name_equal_exact as ⟨sameNamespace, sameNamespaceMeaning⟩
        cases sameNamespace
        · have different : sliceBytes actualNamespace ≠ sliceBytes namespace := by
            intro equal
            have raw := byteList_inj _ _ |>.mp equal
            simp [raw] at sameNamespaceMeaning
          simp_all [RequestOutcome, RequestFrame, bindingResult, bindingErrorOf, namespaceName]
        · have equal : sliceBytes actualNamespace = sliceBytes namespace := by
            simpa [sliceBytes] using congrArg byteList sameNamespaceMeaning.symm
          simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
          step with text_member_exact as ⟨actualRecipe, recipeMember⟩
          cases actualRecipe with
          | none => simp_all [RequestOutcome, RequestFrame, bindingResult, bindingErrorOf, recipeName]
          | some actualRecipe =>
            step with field_name_equal_exact as ⟨sameRecipe, sameRecipeMeaning⟩
            cases sameRecipe
            · have different : sliceBytes actualRecipe ≠ sliceBytes recipe := by
                intro equal
                have raw := byteList_inj _ _ |>.mp equal
                simp [raw] at sameRecipeMeaning
              simp_all [RequestOutcome, RequestFrame, bindingResult, bindingErrorOf, recipeName]
            · have recipeEqual : sliceBytes actualRecipe = sliceBytes recipe := by
                simpa [sliceBytes] using congrArg byteList sameRecipeMeaning.symm
              have frame : RequestFrame (fieldsView fields) (inputsView supplied)
                  (sliceBytes namespace) (sliceBytes recipe) := by
                refine ⟨by simpa [fieldsView] using count.1, by simpa [fieldsView, inputsView] using count.2,
                  namespaceToken, ?_, ?_⟩
                · simpa [namespaceName, equal] using namespaceMember.symm
                · simpa [recipeName, recipeEqual] using recipeMember.symm
              simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
              step with project_object_exact as ⟨projected, objectMeaning⟩
              cases projected with
              | Err error => exact ⟨frame, objectMeaning⟩
              | Ok values =>
                step with text_member_exact as ⟨operation, operationMember⟩
                cases operation with
                | none =>
                  refine ⟨frame, ⟨values.val.map argOf, objectMeaning⟩, ?_⟩
                  simpa [OperationAccepted, operationName] using operationMember
                | some operation =>
                  step with OperationIdentity.Refinement.token_exact as ⟨valid, validMeaning⟩
                  cases valid
                  · have invalid : OperationIdentity.validToken (sliceBytes operation) 128 ≠ true := by
                      simpa using validMeaning.symm
                    refine ⟨frame, ⟨values.val.map argOf, objectMeaning⟩, ?_⟩
                    simp_all [OperationAccepted, operationName]
                  · have token : OperationIdentity.validToken (sliceBytes operation) 128 = true := by
                      simpa using validMeaning.symm
                    have bound : operation.val.length ≤ 128 := by
                      have lengths := request_success_earns_token_lengths (fieldsView fields) (inputsView supplied)
                        (sliceBytes namespace) (sliceBytes recipe) ⟨values.val.map argOf, sliceBytes operation⟩
                        ⟨frame, objectMeaning, by simpa [operationName] using operationMember.symm, token⟩
                      simpa [sliceBytes, byteList] using lengths.2
                    have copyFits : operation.val.length < 4294967295 := by omega
                    simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
                    step with copy_bytes_spec as ⟨copied, copiedMeaning⟩
                    have copiedBytes : vecBytes copied = sliceBytes operation := by
                      simp [vecBytes, sliceBytes, copiedMeaning]
                    simpa [RequestOutcome, bindingResult, boundArgumentsOf, copiedBytes] using
                      (show RequestOutcome (fieldsView fields) (inputsView supplied) (sliceBytes namespace)
                        (sliceBytes recipe) (.ok ⟨values.val.map argOf, sliceBytes operation⟩) from
                        ⟨frame, objectMeaning, by simpa [operationName] using operationMember.symm, token⟩)
  · have nativeInvalid : fields.len > 32#usize ∨ supplied.len ≠ fields.len := by
      rcases not_and_or.mp count with large | different
      · exact Or.inl (by scalar_tac)
      · exact Or.inr (by scalar_tac)
    have frameInvalid : ¬RequestFrame (fieldsView fields) (inputsView supplied)
        (sliceBytes namespace) (sliceBytes recipe) := by
      intro frame
      exact count ⟨by simpa [fieldsView] using frame.1, by simpa [fieldsView, inputsView] using frame.2.1⟩
    rcases nativeInvalid with large | different <;>
      simp_all [RequestOutcome, bindingResult, bindingErrorOf]

theorem source_request_earns_named_bindings (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) (namespace recipe : Slice Std.U8) :
    field_projection.project_request fields supplied namespace recipe ⦃ actual =>
      ∀ accepted, actual = .Ok accepted → ∃ environment,
        RowsMeaning (fieldsView fields) (inputsView supplied) environment ∧
        SchemaIndex.Aligned (names (fieldsView fields)) (accepted.values.val.map argOf)
          (fun name => ArgumentBinding.lookup name environment) ∧
        (ArgumentBinding.lookup namespaceName environment).bind argumentText = some (sliceBytes namespace) ∧
        (ArgumentBinding.lookup recipeName environment).bind argumentText = some (sliceBytes recipe) ∧
        (ArgumentBinding.lookup operationName environment).bind argumentText = some (vecBytes accepted.operation_id) ∧
        OperationIdentity.validToken (sliceBytes namespace) 64 = true ∧
        OperationIdentity.validToken (vecBytes accepted.operation_id) 128 = true ⦄ := by
  apply spec_mono (project_request_exact fields supplied namespace recipe)
  intro actual meaning accepted same
  rw [same] at meaning
  exact request_success_earns_named_bindings _ _ _ _ _ meaning

theorem source_accepted_requests_cannot_refuse (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) (namespace recipe : Slice Std.U8)
    (admitted : RequestAccepted (fieldsView fields) (inputsView supplied) (sliceBytes namespace) (sliceBytes recipe)) :
    field_projection.project_request fields supplied namespace recipe ⦃ actual => ∃ accepted, actual = .Ok accepted ⦄ := by
  apply spec_mono (project_request_exact fields supplied namespace recipe)
  intro actual meaning
  cases actual with
  | Err error => exact False.elim (request_refusal_excludes_acceptance _ _ _ _ _ meaning admitted)
  | Ok accepted => exact ⟨accepted, rfl⟩

theorem source_unbound_requests_cannot_project (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) (namespace recipe : Slice Std.U8)
    (invalid : ¬RequestAccepted (fieldsView fields) (inputsView supplied) (sliceBytes namespace) (sliceBytes recipe)) :
    field_projection.project_request fields supplied namespace recipe ⦃ actual => ∀ accepted, actual ≠ .Ok accepted ⦄ := by
  apply spec_mono (project_request_exact fields supplied namespace recipe)
  intro actual meaning accepted same
  rw [same] at meaning
  exact invalid (request_success_is_accepted _ _ _ _ _ meaning)

/-- Both actual token preimages consume the operation returned by complete
binding. Their size domains are earned from that result; no separate operation
or successful projection is supplied by the caller. Hashing is a later
primitive boundary and this statement makes no collision-resistance claim. -/
theorem source_bound_preimages_use_projected_operation (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) (namespace recipe : Slice Std.U8)
    (commitment : Array Std.U8 32#usize) :
    (do
      let projected ← field_projection.project_request fields supplied namespace recipe
      match projected with
      | .Err _ => ok none
      | .Ok accepted => do
        let echo ← derived_tokens.echo_preimage namespace (alloc.vec.Vec.deref accepted.operation_id) commitment
        let key ← derived_tokens.idempotency_preimage namespace (alloc.vec.Vec.deref accepted.operation_id)
        ok (some (accepted, echo, key))) ⦃ actual =>
      ∀ accepted echo key, actual = some (accepted, echo, key) →
        RequestOutcome (fieldsView fields) (inputsView supplied) (sliceBytes namespace)
          (sliceBytes recipe) (.ok (boundArgumentsOf accepted)) ∧
        vecBytes echo = DerivedTokens.echoPreimage (sliceBytes namespace) (vecBytes accepted.operation_id)
          (byteList commitment.val) ∧
        vecBytes key = DerivedTokens.idempotencyPreimage (sliceBytes namespace) (vecBytes accepted.operation_id) ⦄ := by
  step with project_request_exact as ⟨projected, projectedMeaning⟩
  cases projected with
  | Err error => simp
  | Ok accepted =>
    have meaning : RequestOutcome (fieldsView fields) (inputsView supplied) (sliceBytes namespace)
        (sliceBytes recipe) (.ok (boundArgumentsOf accepted)) := projectedMeaning
    have bounds := request_success_earns_token_lengths _ _ _ _ _ meaning
    have namespaceBound : namespace.val.length ≤ 64 := by simpa [sliceBytes, byteList] using bounds.1
    have operationBound : accepted.operation_id.val.length ≤ 128 := by
      simpa [boundArgumentsOf, vecBytes, byteList] using bounds.2
    step with DerivedTokens.Refinement.echo_preimage_exact as ⟨echo, echoMeaning⟩
    step with DerivedTokens.Refinement.idempotency_preimage_exact as ⟨key, keyMeaning⟩
    simp only [spec_ok]
    intro selected producedEcho producedKey same
    have equal := Option.some.inj same
    cases equal
    exact ⟨meaning, by simpa [alloc.vec.Vec.deref, vecBytes, sliceBytes] using echoMeaning,
      by simpa [alloc.vec.Vec.deref, vecBytes, sliceBytes] using keyMeaning⟩

end Auths.Product.FieldProjection.Refinement
