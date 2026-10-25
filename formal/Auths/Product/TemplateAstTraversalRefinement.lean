import Auths.Product.TemplateAstTraversal
import Auths.Product.TemplateAstKeysRefinement
import Auths.Product.TemplateAstPrefixRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.Refinement.Gateway
open Auths.Product.BodyCompiler.Refinement

namespace Auths.Product.TemplateAst.Refinement
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

def echoTokensOf (echo : Option (Slice (alloc.vec.Vec U8))) : Option (List Bytes) :=
  echo.map TemplateMembers.Refinement.tokensView
def optionalTargetOf (target : Option template_members.EchoTarget) : Option TemplateMembers.Target :=
  target.map TemplateMembers.Refinement.targetOf

private theorem json_member_at (fields : List template_ast.JsonMember) (index : Nat) :
    (jsonMembersOf fields)[index]? = (fields[index]?).map (fun member => (vecBytes member.name, valueOf member.value)) := by
  induction fields generalizing index with
  | nil => simp [jsonMembersOf]
  | cons member rest ih => cases member <;> cases index <;> simp [jsonMembersOf, ih]

@[step] theorem json_target_exact (keys : Slice template_members.NamedKey)
    (echo : Option (Slice (alloc.vec.Vec U8))) : template_ast.json_target keys echo ⦃ actual =>
      templateResult optionalTargetOf actual = objectTarget (TemplateMembers.Refinement.keysView keys) (echoTokensOf echo) ⦄ := by
  unfold template_ast.json_target
  cases echo with
  | none => rfl
  | some tokens =>
    step with TemplateMembers.Refinement.json_echo_target_exact as ⟨target, targetMeaning⟩
    cases target with
    | Err error =>
      step with member_error_exact as ⟨mapped, mappedMeaning⟩
      simpa [objectTarget, echoTokensOf, templateResult, optionalTargetOf, TemplateMembers.Refinement.memberResult,
        ← targetMeaning, mappedMeaning, Except.mapError, Except.map] using mappedMeaning
    | Ok target =>
      simpa [objectTarget, echoTokensOf, templateResult, optionalTargetOf, TemplateMembers.Refinement.memberResult,
        ← targetMeaning, Except.mapError, Except.map]

@[step] theorem json_insertion_exact (target : Option template_members.EchoTarget)
    (echo : Option (Slice (alloc.vec.Vec U8))) : template_ast.json_insertion target echo ⦃ actual =>
      templateResult (Option.map sliceBytes) actual = objectInsertion (optionalTargetOf target) (echoTokensOf echo) ⦄ := by
  unfold template_ast.json_insertion
  cases target with
  | none => cases echo <;> rfl
  | some target =>
    cases target with
    | Descend index => cases echo <;> rfl
    | Insert =>
      cases echo with
      | none => rfl
      | some tokens =>
        cases values : tokens.val with
        | nil => simp [values, templateResult, templateErrorOf, objectInsertion, optionalTargetOf,
            echoTokensOf, TemplateMembers.Refinement.tokensView]
        | cons first rest =>
          have nonempty : tokens.val.length ≠ 0 := by simp [values]
          simp only [core.slice.Slice.is_empty, bind_tc_ok, Slice.len_val, Slice.length, nonempty,
            decide_false, Bool.false_eq_true, ↓reduceIte]
          step as ⟨selected, selectedAt⟩
          simp [templateResult, objectInsertion, optionalTargetOf, echoTokensOf,
            TemplateMembers.Refinement.tokensView, values, selectedAt, alloc.vec.Vec.deref, sliceBytes, vecBytes]

@[step] theorem json_child_echo_exact (target : Option template_members.EchoTarget)
    (echo : Option (Slice (alloc.vec.Vec U8))) (index : Usize) :
    template_ast.json_child_echo target echo index ⦃ actual => templateResult echoTokensOf actual =
      objectChildEcho (optionalTargetOf target) (echoTokensOf echo) index.val ⦄ := by
  unfold template_ast.json_child_echo
  cases target with
  | none => cases echo <;> rfl
  | some target =>
    cases target with
    | Insert => cases echo <;> rfl
    | Descend selected =>
      cases echo with
      | none => rfl
      | some tokens =>
        by_cases same : selected = index
        · subst selected
          by_cases empty : tokens.val.length = 0
          · have values : tokens.val = [] := List.length_eq_zero_iff.mp empty
            simp [core.slice.Slice.get, core.slice.index.SliceIndexRangeFromUsizeSlice,
              core.slice.index.SliceIndexRangeFromUsizeSlice.get, values, templateResult, templateErrorOf,
              echoTokensOf, optionalTargetOf, objectChildEcho, TemplateMembers.Refinement.tokensView]
          · have positive : 0 < tokens.val.length := by omega
            have native : (1#usize).val ≤ tokens.length := by simpa using positive
            simp [core.slice.Slice.get, core.slice.index.SliceIndexRangeFromUsizeSlice,
              core.slice.index.SliceIndexRangeFromUsizeSlice.get, native, templateResult,
              echoTokensOf, optionalTargetOf, objectChildEcho, TemplateMembers.Refinement.tokensView,
              List.drop_map, positive]
        · have values : selected.val ≠ index.val := by intro equal; exact same (UScalar.eq_of_val_eq equal)
          simp [same, values, templateResult, echoTokensOf, optionalTargetOf, objectChildEcho]

/- These private induction hypotheses refer only to the actual recursive
callee. The public whole-source theorem supplies them by decreasing native
depth; no external callback, desired output or validity flag is accepted. -/
private def ChildRefinement (depth : Nat) : Prop :=
  ∀ (value : template_ast.Value) (echo : Option (Slice (alloc.vec.Vec U8)))
    (childDepth : Usize) (output : template_ast.JsonBuild), childDepth.val = depth + 1 →
      template_ast.json_value value echo childDepth output ⦃ actual => templateResult jsonBuildOf actual =
        emitJson 7 (valueOf value) (echoTokensOf echo) childDepth.val (jsonBuildOf output) ⦄

private theorem array_item_exact (value : template_ast.Value) (depth position : Usize)
    (output : template_ast.JsonBuild) (depthBound : depth.val ≤ 6) (children : ChildRefinement depth.val) :
    template_ast.json_array_item value depth position output ⦃ actual => templateResult jsonBuildOf actual =
      arrayItem (valueOf value) depth.val position.val (jsonBuildOf output) ⦄ := by
  unfold template_ast.json_array_item
  have fits : depth.val + 1 ≤ Usize.max := by scalar_tac
  by_cases separator : 0 < position.val
  · have native : position > 0#usize := by scalar_tac
    simp only [native, ↓reduceIte]
    step with copy_bytes_spec as ⟨comma, commaMeaning⟩
    step with json_push_exact as ⟨separated, separatedMeaning⟩
    cases separated with
    | Err error =>
      simpa [arrayItem, separator, templateResult, templateErrorOf, jsonSourceView, vecBytes, commaMeaning,
        Bind.bind, Except.bind] using separatedMeaning
    | Ok separated =>
      step as ⟨nextDepth, depthValue⟩
      apply spec_mono (children value none nextDepth separated depthValue)
      intro actual meaning
      simpa [arrayItem, separator, ← separatedMeaning, templateResult, jsonSourceView, vecBytes, commaMeaning,
        echoTokensOf, depthValue, Bind.bind, Except.bind] using meaning
  · have native : ¬position > 0#usize := by scalar_tac
    simp only [native, ↓reduceIte]
    step as ⟨nextDepth, depthValue⟩
    apply spec_mono (children value none nextDepth output depthValue)
    intro actual meaning
    simpa [arrayItem, separator, echoTokensOf, depthValue] using meaning

private theorem array_loop_exact (items : Slice template_ast.Value) (depth : Usize)
    (output : template_ast.JsonBuild) (depthBound : depth.val ≤ 6) (children : ChildRefinement depth.val)
    (count : items.val.length ≤ 16) :
    template_ast.json_array_loop items depth output 0#usize ⦃ actual => templateResult jsonBuildOf actual =
      arrayFrom (valuesOf items.val) depth.val 0 (jsonBuildOf output) ⦄ := by
  unfold template_ast.json_array_loop
  apply loop.spec_decr_nat
    (measure := fun state => items.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ items.val.length ∧
      arrayFrom (valuesOf items.val) depth.val 0 (jsonBuildOf output) =
        arrayFrom (valuesOf items.val) depth.val state.2.val (jsonBuildOf state.1))
  · rintro ⟨current, index⟩ invariant
    unfold template_ast.json_array_loop.body
    dsimp only
    split <;> rename_i guard
    · have inside : index.val < items.val.length := by scalar_tac
      have modelInside : index.val < (valuesOf items.val).length := by
        simpa [array_source_order_preserved] using inside
      have semantic := invariant.2
      rw [array_from_step _ _ _ _ modelInside] at semantic
      step as ⟨child, childAt⟩
      have childMeaning : (valuesOf items.val)[index.val] = valueOf child := by
        simp [array_source_order_preserved, childAt]
      step with array_item_exact as ⟨next, nextMeaning⟩
      cases next with
      | Err error =>
        rw [childMeaning] at semantic
        simp only [← nextMeaning, templateResult, Bind.bind, Except.bind] at semantic
        simpa [templateResult] using semantic.symm
      | Ok next =>
        step as ⟨nextIndex, nextIndexValue⟩
        refine ⟨by omega, ?_, by omega⟩
        rw [childMeaning] at semantic
        simpa [arrayItem, ← nextMeaning, templateResult, nextIndexValue, Bind.bind, Except.bind] using semantic
    · have finished : (valuesOf items.val).length ≤ index.val := by
        simp only [array_source_order_preserved, List.length_map]
        scalar_tac
      rw [array_from_done _ _ _ _ finished] at invariant
      simpa [templateResult] using invariant.2.symm
  · exact ⟨by simp, rfl⟩

private theorem array_exact (items : Slice template_ast.Value) (depth : Usize)
    (output : template_ast.JsonBuild) (depthBound : depth.val ≤ 6) (children : ChildRefinement depth.val) :
    template_ast.json_array items depth output ⦃ actual => templateResult jsonBuildOf actual =
      jsonArray (valuesOf items.val) depth.val (jsonBuildOf output) ⦄ := by
  unfold template_ast.json_array
  by_cases admitted : 0 < items.val.length ∧ items.val.length ≤ 16
  · have nonempty : items.val.length ≠ 0 := by omega
    have nativeLarge : ¬items.len > 16#usize := by scalar_tac
    have modelCount : 0 < (valuesOf items.val).length ∧ (valuesOf items.val).length ≤ 16 := by
      simpa [array_source_order_preserved] using admitted
    simp only [core.slice.Slice.is_empty, bind_tc_ok, Slice.len_val, Slice.length, nonempty,
      decide_false, Bool.false_or, nativeLarge, ↓reduceIte]
    step with copy_bytes_spec as ⟨opening, openingMeaning⟩
    step with json_push_exact as ⟨opened, openedMeaning⟩
    cases opened with
    | Err error => simpa [jsonArray, modelCount, ← openedMeaning, templateResult, jsonSourceView,
        vecBytes, openingMeaning, Bind.bind, Except.bind] using openedMeaning
    | Ok opened =>
      step with array_loop_exact as ⟨folded, foldedMeaning⟩
      cases folded with
      | Err error => simp [jsonArray, modelCount, ← openedMeaning, ← foldedMeaning, templateResult,
          jsonSourceView, vecBytes, openingMeaning]
      | Ok folded =>
        step with copy_bytes_spec as ⟨closing, closingMeaning⟩
        apply spec_mono (json_push_exact folded (.Raw closing))
        intro actual meaning
        simpa [jsonArray, modelCount, ← openedMeaning, ← foldedMeaning, templateResult,
          jsonSourceView, vecBytes, openingMeaning, closingMeaning] using meaning
  · have modelCount : ¬(0 < (valuesOf items.val).length ∧ (valuesOf items.val).length ≤ 16) := by
      simpa [array_source_order_preserved] using admitted
    by_cases empty : items.val.length = 0
    · have values : items.val = [] := List.length_eq_zero_iff.mp empty
      simp [values, jsonArray, modelCount, templateResult, templateErrorOf]
    · have tooMany : 16 < items.val.length := by omega
      have native : items.len > 16#usize := by scalar_tac
      simp [native, jsonArray, modelCount, templateResult, templateErrorOf]

private theorem object_member_exact (fields : Slice template_ast.JsonMember) (choice : template_members.MemberChoice)
    (target : Option template_members.EchoTarget) (echo : Option (Slice (alloc.vec.Vec U8))) (insertion : Option (Slice U8))
    (depth position : Usize) (output : template_ast.JsonBuild) (depthBound : depth.val ≤ 6)
    (prefixes : PrefixDomain (jsonFieldNames fields.val) (insertion.map sliceBytes)) (children : ChildRefinement depth.val) :
    template_ast.json_member fields choice target echo insertion depth position output ⦃ actual => templateResult jsonBuildOf actual =
      objectStep (jsonMembersOf fields.val) (optionalTargetOf target) (echoTokensOf echo) (insertion.map sliceBytes)
        depth.val (jsonBuildOf output) (TemplateMembers.Refinement.choiceOf choice, position.val) ⦄ := by
  unfold template_ast.json_member
  have nextDepthFits : depth.val + 1 ≤ Usize.max := by scalar_tac
  have separator : decide (position > 0#usize) = decide (0 < position.val) := by scalar_tac
  cases choice with
  | Source index =>
    step as ⟨selected, selectedMeaning⟩
    cases selected with
    | none => simp [objectStep, json_member_at, selectedMeaning, TemplateMembers.Refinement.choiceOf,
        templateResult, templateErrorOf]
    | some member =>
      have namePresent : vecBytes member.name ∈ jsonFieldNames fields.val := by
        exact List.mem_map.mpr ⟨member, List.mem_iff_getElem?.mpr ⟨index.val, selectedMeaning⟩, rfl⟩
      have nameBound : member.name.val.length ≤ 130 := by
        simpa [vecBytes, byteList] using prefixes.1 (vecBytes member.name) namePresent
      step with json_prefix_exact as ⟨prefix, prefixMeaning⟩
      step with json_push_exact as ⟨prefixed, prefixedMeaning⟩
      cases prefixed with
      | Err error => simp [objectStep, json_member_at, selectedMeaning, TemplateMembers.Refinement.choiceOf,
          ← prefixedMeaning, prefixMeaning, separator, templateResult, jsonSourceView]
      | Ok prefixed =>
        step with json_child_echo_exact as ⟨nested, nestedMeaning⟩
        cases nested with
        | Err error => simp [objectStep, json_member_at, selectedMeaning, TemplateMembers.Refinement.choiceOf,
            ← prefixedMeaning, ← nestedMeaning, prefixMeaning, separator, templateResult, jsonSourceView]
        | Ok nested =>
          step as ⟨nextDepth, nextDepthValue⟩
          apply spec_mono (children member.value nested nextDepth prefixed nextDepthValue)
          intro actual meaning
          simpa [objectStep, json_member_at, selectedMeaning, TemplateMembers.Refinement.choiceOf,
            ← prefixedMeaning, ← nestedMeaning, prefixMeaning, separator, templateResult,
            jsonSourceView, nextDepthValue] using meaning
  | Echo =>
    cases insertion with
    | none => simp [objectStep, TemplateMembers.Refinement.choiceOf, templateResult, templateErrorOf]
    | some name =>
      have nameBound : name.val.length ≤ 130 := by
        simpa [sliceBytes, byteList] using prefixes.2 (sliceBytes name) rfl
      step with json_prefix_exact as ⟨prefix, prefixMeaning⟩
      step with json_push_exact as ⟨prefixed, prefixedMeaning⟩
      cases prefixed with
      | Err error => simp [objectStep, TemplateMembers.Refinement.choiceOf, ← prefixedMeaning,
          prefixMeaning, separator, templateResult, jsonSourceView]
      | Ok prefixed =>
        apply spec_mono (json_push_exact prefixed .Echo)
        intro actual meaning
        simpa [objectStep, TemplateMembers.Refinement.choiceOf, ← prefixedMeaning,
          prefixMeaning, separator, templateResult, jsonSourceView] using meaning

private theorem object_loop_exact (fields : Slice template_ast.JsonMember) (order : Slice template_members.MemberChoice)
    (target : Option template_members.EchoTarget) (echo : Option (Slice (alloc.vec.Vec U8))) (insertion : Option (Slice U8))
    (depth : Usize) (output : template_ast.JsonBuild) (depthBound : depth.val ≤ 6)
    (prefixes : PrefixDomain (jsonFieldNames fields.val) (insertion.map sliceBytes)) (children : ChildRefinement depth.val) :
    template_ast.json_members_loop fields order target echo insertion depth output 0#usize ⦃ actual =>
      templateResult jsonBuildOf actual = objectFrom (jsonMembersOf fields.val) (order.val.map TemplateMembers.Refinement.choiceOf)
        (optionalTargetOf target) (echoTokensOf echo) (insertion.map sliceBytes) depth.val 0 (jsonBuildOf output) ⦄ := by
  unfold template_ast.json_members_loop
  apply loop.spec_decr_nat
    (measure := fun state => order.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ order.val.length ∧
      objectFrom (jsonMembersOf fields.val) (order.val.map TemplateMembers.Refinement.choiceOf)
        (optionalTargetOf target) (echoTokensOf echo) (insertion.map sliceBytes) depth.val 0 (jsonBuildOf output) =
      objectFrom (jsonMembersOf fields.val) (order.val.map TemplateMembers.Refinement.choiceOf)
        (optionalTargetOf target) (echoTokensOf echo) (insertion.map sliceBytes) depth.val state.2.val (jsonBuildOf state.1))
  · rintro ⟨current, index⟩ invariant
    unfold template_ast.json_members_loop.body
    dsimp only
    split <;> rename_i guard
    · have inside : index.val < order.val.length := by scalar_tac
      have modelInside : index.val < (order.val.map TemplateMembers.Refinement.choiceOf).length := by simpa using inside
      have semantic := invariant.2
      rw [object_from_step _ _ _ _ _ _ _ _ modelInside] at semantic
      step as ⟨choice, choiceAt⟩
      step with object_member_exact as ⟨next, nextMeaning⟩
      cases next with
      | Err error =>
        simpa [choiceAt, ← nextMeaning, templateResult, Bind.bind, Except.bind] using semantic.symm
      | Ok next =>
        have room : index.val + 1 ≤ Usize.max := by have bound := Slice.length_ineq order; omega
        step as ⟨nextIndex, nextIndexValue⟩
        refine ⟨by omega, ?_, by omega⟩
        simpa [choiceAt, ← nextMeaning, templateResult, nextIndexValue, Bind.bind, Except.bind] using semantic
    · have finished : (order.val.map TemplateMembers.Refinement.choiceOf).length ≤ index.val := by simp; scalar_tac
      rw [object_from_done _ _ _ _ _ _ _ _ finished] at invariant
      simpa [templateResult] using invariant.2.symm
  · exact ⟨by simp, rfl⟩

private theorem object_exact (fields : Slice template_ast.JsonMember) (echo : Option (Slice (alloc.vec.Vec U8)))
    (depth : Usize) (output : template_ast.JsonBuild) (depthBound : depth.val ≤ 6) (children : ChildRefinement depth.val) :
    template_ast.json_object fields echo depth output ⦃ actual => templateResult jsonBuildOf actual =
      jsonObject (jsonMembersOf fields.val) (echoTokensOf echo) depth.val (jsonBuildOf output) ⦄ := by
  unfold template_ast.json_object
  step with json_keys_exact as ⟨keys, keysMeaning⟩
  cases keys with
  | Err error =>
    have invalid : ¬(0 < fields.val.length ∧ fields.val.length ≤ 32) := by
      intro admitted
      simp [admitted, templateResult] at keysMeaning
    have modelInvalid : ¬(0 < (jsonMembersOf fields.val).length ∧ (jsonMembersOf fields.val).length ≤ 32) := by
      simpa [json_member_count_preserved] using invalid
    simp [jsonObject, modelInvalid, templateResult, templateErrorOf]
  | Ok keys =>
    have count : 0 < fields.val.length ∧ fields.val.length ≤ 32 := by
      by_contra invalid
      simp [invalid, templateResult] at keysMeaning
    have modelCount : 0 < (jsonMembersOf fields.val).length ∧ (jsonMembersOf fields.val).length ≤ 32 := by
      simpa [json_member_count_preserved] using count
    have keysExact : TemplateMembers.Refinement.keysView (alloc.vec.Vec.deref keys) = jsonFieldNames fields.val := by
      simpa [count, templateResult] using keysMeaning
    step with json_target_exact as ⟨target, targetMeaning⟩
    cases target with
    | Err error => simp [jsonObject, modelCount, json_member_names_preserve_pairs, ← keysExact,
        ← targetMeaning, templateResult]
    | Ok target =>
      step with json_insertion_exact as ⟨insertion, insertionMeaning⟩
      cases insertion with
      | Err error => simp [jsonObject, modelCount, json_member_names_preserve_pairs, ← keysExact,
          ← targetMeaning, ← insertionMeaning, templateResult]
      | Ok insertion =>
        step with TemplateMembers.Refinement.canonical_members_exact as ⟨order, orderMeaning⟩
        cases order with
        | Err error =>
          step with member_error_exact as ⟨mapped, mappedMeaning⟩
          simp [jsonObject, modelCount, json_member_names_preserve_pairs, ← keysExact,
            ← targetMeaning, ← insertionMeaning, ← orderMeaning, templateResult, mappedMeaning,
            TemplateMembers.Refinement.memberResult, Except.mapError]
        | Ok order =>
          have memberRun : TemplateMembers.canonicalMembers (jsonFieldNames fields.val) (insertion.map sliceBytes) .json =
              .ok (TemplateMembers.Refinement.choicesOf order) := by
            simpa [templateResult, TemplateMembers.Refinement.memberResult, TemplateMembers.Refinement.domainOf, keysExact] using orderMeaning.symm
          have prefixes := canonical_members_earn_prefix_domain _ _ _ _ memberRun
          step with copy_bytes_spec as ⟨opening, openingMeaning⟩
          step with json_push_exact as ⟨opened, openedMeaning⟩
          cases opened with
          | Err error => simp [jsonObject, modelCount, json_member_names_preserve_pairs, ← keysExact,
              ← targetMeaning, ← insertionMeaning, ← orderMeaning, ← openedMeaning,
              TemplateMembers.Refinement.memberResult, templateResult, jsonSourceView, openingMeaning, vecBytes]
          | Ok opened =>
            unfold template_ast.json_members
            step with object_loop_exact as ⟨folded, foldedMeaning⟩
            cases folded with
            | Err error => simp [jsonObject, modelCount, json_member_names_preserve_pairs, ← keysExact,
                ← targetMeaning, ← insertionMeaning, ← orderMeaning, ← openedMeaning, ← foldedMeaning,
                TemplateMembers.Refinement.memberResult, templateResult, jsonSourceView, openingMeaning, vecBytes]
            | Ok folded =>
              step with copy_bytes_spec as ⟨closing, closingMeaning⟩
              apply spec_mono (json_push_exact folded (.Raw closing))
              intro actual meaning
              simpa [jsonObject, modelCount, json_member_names_preserve_pairs, ← keysExact,
                ← targetMeaning, ← insertionMeaning, ← orderMeaning, ← openedMeaning, ← foldedMeaning,
                TemplateMembers.Refinement.memberResult, templateResult, jsonSourceView,
                openingMeaning, closingMeaning, vecBytes, TemplateMembers.Refinement.choicesOf] using meaning

/-- Complete recursive Rust emission refines the fixed seven-level model on
every represented AST, echo, starting counter/depth and builder. The actual
node charge earns each child-depth domain. Array/object induction hypotheses
are discharged here; no successful helper or expected template is a premise.
Fresh extraction must determine and validate the concrete recursive ABI. -/
@[step] theorem json_value_exact (value : template_ast.Value) (echo : Option (Slice (alloc.vec.Vec U8)))
    (depth : Usize) (output : template_ast.JsonBuild) : template_ast.json_value value echo depth output ⦃ actual =>
      templateResult jsonBuildOf actual = emitJson 7 (valueOf value) (echoTokensOf echo) depth.val (jsonBuildOf output) ⦄ := by
  generalize remainingEq : 7 - depth.val = remaining
  induction remaining using Nat.strong_induction_on generalizing value echo depth output with
  | h remaining ih =>
    rw [emit_json_dispatch_exact]
    unfold template_ast.json_value
    step with charge_node_exact as ⟨charged, chargedMeaning⟩
    cases charged with
    | Err error =>
      simp [dispatchJson, ← chargedMeaning, templateResult, templateErrorOf]
    | Ok nodes =>
      have chargeRun : chargeNode output.nodes.val depth.val = .ok nodes.val := by
        simpa [templateResult] using chargedMeaning.symm
      have earned := charge_node_earns_domain output.nodes.val depth.val nodes.val chargeRun
      have depthBound : depth.val ≤ 6 := earned.2.1
      let initial : template_ast.JsonBuild := { output with nodes }
      have children : ChildRefinement depth.val := by
        intro child nested childDepth childOutput nextDepth
        exact ih (7 - childDepth.val) (by omega) child nested childDepth childOutput rfl
      cases value with
      | String text =>
        cases echo with
        | some tokens => simp [dispatchJson, chargeRun, echoTokensOf, valueOf, isObject, templateResult, templateErrorOf]
        | none =>
          by_cases large : 1024 < text.val.length
          · have native : text.len > 1024#usize := by scalar_tac
            have model : ¬(vecBytes text).length ≤ 1024 := by simpa [vecBytes, byteList] using Nat.not_le.mpr large
            simp [native, dispatchJson, chargeRun, echoTokensOf, valueOf, isObject, model, templateResult, templateErrorOf]
          · have native : ¬text.len > 1024#usize := by scalar_tac
            have size : text.val.length ≤ 1024 := by omega
            have model : (vecBytes text).length ≤ 1024 := by simpa [vecBytes, byteList] using size
            simp only [native, ↓reduceIte]
            have quotedSize := BodyCompiler.json_string_length (vecBytes text)
            have fits : (alloc.vec.Vec.new U8).val.length + (jsonString (byteList text.val)).length < 4294967295 := by
              simp only [alloc.vec.Vec.new, List.length_nil, zero_add]
              simp only [vecBytes, byteList, List.length_map] at quotedSize
              omega
            step with append_json_string_spec as ⟨quoted, quotedMeaning⟩
            apply spec_mono (json_push_exact initial (.Raw quoted))
            intro actual meaning
            simpa [dispatchJson, chargeRun, echoTokensOf, valueOf, isObject, model, templateResult,
              initial, jsonBuildOf, jsonSourceView, vecBytes, quotedMeaning] using meaning
      | Integer value =>
        cases echo with
        | some tokens => simp [dispatchJson, chargeRun, echoTokensOf, valueOf, isObject, templateResult, templateErrorOf]
        | none =>
          step with ScalarProjection.Refinement.integer_valid_exact as ⟨allowed, allowedMeaning⟩
          have model : allowed = decide (-9007199254740991 ≤ value.val ∧ value.val ≤ 9007199254740991) := by
            simpa [ScalarProjection.IntegerValue, ScalarProjection.IntegerSchema, scalars.MAX_JSON_INTEGER] using allowedMeaning
          cases allowed with
          | false =>
            have invalid : ¬(-9007199254740991 ≤ value.val ∧ value.val ≤ 9007199254740991) := by simpa using model.symm
            simp [dispatchJson, chargeRun, echoTokensOf, valueOf, isObject, invalid, templateResult, templateErrorOf]
          | true =>
            have valid : -9007199254740991 ≤ value.val ∧ value.val ≤ 9007199254740991 := by simpa using model.symm
            step with integer_literal_exact as ⟨encoded, encodedMeaning⟩
            apply spec_mono (json_push_exact initial (.Raw encoded))
            intro actual meaning
            simpa [dispatchJson, chargeRun, echoTokensOf, valueOf, isObject, valid, templateResult,
              initial, jsonBuildOf, jsonSourceView, encodedMeaning] using meaning
      | Boolean value =>
        cases echo with
        | some tokens => simp [dispatchJson, chargeRun, echoTokensOf, valueOf, isObject, templateResult, templateErrorOf]
        | none =>
          cases value
          all_goals
            step with copy_bytes_spec as ⟨encoded, encodedMeaning⟩
            apply spec_mono (json_push_exact initial (.Raw encoded))
            intro actual meaning
            simpa [dispatchJson, chargeRun, echoTokensOf, valueOf, isObject, templateResult,
              initial, jsonBuildOf, jsonSourceView, vecBytes, encodedMeaning] using meaning
      | Field name =>
        cases echo with
        | some tokens => simp [dispatchJson, chargeRun, echoTokensOf, valueOf, isObject, templateResult, templateErrorOf]
        | none =>
          step with rendered_field_exact as ⟨allowed, allowedMeaning⟩
          cases allowed with
          | false =>
            have invalid : ¬RenderedField (vecBytes name) := by simpa [vecBytes, sliceBytes] using allowedMeaning.symm
            simp [dispatchJson, chargeRun, echoTokensOf, valueOf, isObject, invalid, templateResult, templateErrorOf]
          | true =>
            have valid : RenderedField (vecBytes name) := by simpa [vecBytes, sliceBytes] using allowedMeaning.symm
            have size : name.val.length ≤ 64 := by
              simpa [vecBytes, byteList] using (TemplateMembers.token_shape_bounds _ valid.1).2.1
            step with copy_bytes_spec as ⟨copied, copiedMeaning⟩
            apply spec_mono (json_push_exact initial (.Field copied))
            intro actual meaning
            simpa [dispatchJson, chargeRun, echoTokensOf, valueOf, isObject, valid, templateResult,
              initial, jsonBuildOf, jsonSourceView, vecBytes, copiedMeaning] using meaning
      | AuthorEcho =>
        cases echo <;> simp [dispatchJson, chargeRun, echoTokensOf, valueOf, isObject, templateResult, templateErrorOf]
      | Array items =>
        cases echo with
        | some tokens => simp [dispatchJson, chargeRun, echoTokensOf, valueOf, isObject, templateResult, templateErrorOf]
        | none =>
          apply spec_mono (array_exact (alloc.vec.Vec.deref items) depth initial depthBound children)
          intro actual meaning
          simpa [dispatchJson, chargeRun, echoTokensOf, valueOf, isObject, initial, jsonBuildOf, alloc.vec.Vec.deref] using meaning
      | Object fields =>
        apply spec_mono (object_exact (alloc.vec.Vec.deref fields) echo depth initial depthBound children)
        intro actual meaning
        simpa [dispatchJson, chargeRun, echoTokensOf, valueOf, isObject, initial, jsonBuildOf, alloc.vec.Vec.deref] using meaning

end Auths.Product.TemplateAst.Refinement
