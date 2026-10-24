import Auths.Product.TemplateAstSourceViews
import Auths.Product.TemplateMemberSelectionRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.Refinement.Gateway

namespace Auths.Product.TemplateAst.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

@[step] theorem json_key_column_loop_exact (fields : Slice template_ast.JsonMember)
    (bounded : fields.val.length ≤ 32) :
    template_ast.json_key_column_loop fields (alloc.vec.Vec.new template_members.NamedKey) 0#usize ⦃ actual =>
      TemplateMembers.Refinement.keysView (alloc.vec.Vec.deref actual) = jsonFieldNames fields.val ⦄ := by
  unfold template_ast.json_key_column_loop
  apply loop.spec_decr_nat
    (measure := fun state => fields.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ fields.val.length ∧
      TemplateMembers.Refinement.keysView (alloc.vec.Vec.deref state.1) = (jsonFieldNames fields.val).take state.2.val)
  · rintro ⟨current, index⟩ invariant
    unfold template_ast.json_key_column_loop.body
    dsimp only
    split <;> rename_i guard
    · have inside : index.val < fields.val.length := by scalar_tac
      step as ⟨member, memberAt⟩
      have size : current.val.length = index.val := by
        have lengths := congrArg List.length invariant.2
        simp only [TemplateMembers.Refinement.keysView, jsonFieldNames, alloc.vec.Vec.deref,
          List.length_map, List.length_take] at lengths
        omega
      have room : current.length < Usize.max := lt_usize_max (by change current.val.length < _; omega)
      step as ⟨updated, updatedValue⟩
      step as ⟨next, nextValue⟩
      refine ⟨by omega, ?_, by omega⟩
      have takeNext : (jsonFieldNames fields.val).take (index.val + 1) =
          (jsonFieldNames fields.val).take index.val ++ [vecBytes member.name] := by
        simpa [jsonFieldNames, memberAt] using List.take_succ_eq_append_getElem (by simpa [jsonFieldNames] using inside)
      simpa [nextValue, takeNext, TemplateMembers.Refinement.keysView, alloc.vec.Vec.deref,
        updatedValue, List.map_append, vecBytes, sliceBytes] using congrArg (· ++ [vecBytes member.name]) invariant.2
    · have endBound : (jsonFieldNames fields.val).length ≤ index.val := by
        simpa [jsonFieldNames] using (show fields.val.length ≤ index.val by scalar_tac)
      simpa [List.take_of_length_le endBound] using invariant.2
  · exact ⟨by simp, by simp [TemplateMembers.Refinement.keysView, jsonFieldNames]⟩

@[step] theorem json_key_column_exact (fields : Slice template_ast.JsonMember)
    (bounded : fields.val.length ≤ 32) : template_ast.json_key_column fields ⦃ actual =>
      TemplateMembers.Refinement.keysView (alloc.vec.Vec.deref actual) = jsonFieldNames fields.val ⦄ := by
  unfold template_ast.json_key_column
  exact json_key_column_loop_exact fields bounded

@[step] theorem json_keys_exact (fields : Slice template_ast.JsonMember) :
    template_ast.json_keys fields ⦃ actual => templateResult
      (fun keys => TemplateMembers.Refinement.keysView (alloc.vec.Vec.deref keys)) actual =
        if 0 < fields.val.length ∧ fields.val.length ≤ 32 then .ok (jsonFieldNames fields.val) else .error .shape ⦄ := by
  unfold template_ast.json_keys
  by_cases empty : fields.val.length = 0
  · have values : fields.val = [] := List.length_eq_zero_iff.mp empty
    simp [values, templateResult, templateErrorOf]
  · simp only [core.slice.Slice.is_empty, bind_tc_ok, Slice.len_val, Slice.length, empty, decide_false, Bool.false_or]
    by_cases large : 32 < fields.val.length
    · have native : fields.len > 32#usize := by scalar_tac
      simp [native, Nat.not_le.mpr large, templateResult, templateErrorOf]
    · have native : ¬fields.len > 32#usize := by scalar_tac
      have admitted : 0 < fields.val.length ∧ fields.val.length ≤ 32 := by omega
      simp only [native, ↓reduceIte]
      step with json_key_column_exact as ⟨keys, keysMeaning⟩
      simpa [templateResult, admitted] using keysMeaning

@[step] theorem form_key_column_loop_exact (fields : Slice template_ast.FormMember)
    (bounded : fields.val.length ≤ 16) :
    template_ast.form_key_column_loop fields (alloc.vec.Vec.new template_members.NamedKey) 0#usize ⦃ actual =>
      TemplateMembers.Refinement.keysView (alloc.vec.Vec.deref actual) = formFieldNames fields.val ⦄ := by
  unfold template_ast.form_key_column_loop
  apply loop.spec_decr_nat
    (measure := fun state => fields.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ fields.val.length ∧
      TemplateMembers.Refinement.keysView (alloc.vec.Vec.deref state.1) = (formFieldNames fields.val).take state.2.val)
  · rintro ⟨current, index⟩ invariant
    unfold template_ast.form_key_column_loop.body
    dsimp only
    split <;> rename_i guard
    · have inside : index.val < fields.val.length := by scalar_tac
      step as ⟨member, memberAt⟩
      have size : current.val.length = index.val := by
        have lengths := congrArg List.length invariant.2
        simp only [TemplateMembers.Refinement.keysView, formFieldNames, alloc.vec.Vec.deref,
          List.length_map, List.length_take] at lengths
        omega
      have room : current.length < Usize.max := lt_usize_max (by change current.val.length < _; omega)
      step as ⟨updated, updatedValue⟩
      step as ⟨next, nextValue⟩
      refine ⟨by omega, ?_, by omega⟩
      have takeNext : (formFieldNames fields.val).take (index.val + 1) =
          (formFieldNames fields.val).take index.val ++ [vecBytes member.name] := by
        simpa [formFieldNames, memberAt] using List.take_succ_eq_append_getElem (by simpa [formFieldNames] using inside)
      simpa [nextValue, takeNext, TemplateMembers.Refinement.keysView, alloc.vec.Vec.deref,
        updatedValue, List.map_append, vecBytes, sliceBytes] using congrArg (· ++ [vecBytes member.name]) invariant.2
    · have endBound : (formFieldNames fields.val).length ≤ index.val := by
        simpa [formFieldNames] using (show fields.val.length ≤ index.val by scalar_tac)
      simpa [List.take_of_length_le endBound] using invariant.2
  · exact ⟨by simp, by simp [TemplateMembers.Refinement.keysView, formFieldNames]⟩

@[step] theorem form_key_column_exact (fields : Slice template_ast.FormMember)
    (bounded : fields.val.length ≤ 16) : template_ast.form_key_column fields ⦃ actual =>
      TemplateMembers.Refinement.keysView (alloc.vec.Vec.deref actual) = formFieldNames fields.val ⦄ := by
  unfold template_ast.form_key_column
  exact form_key_column_loop_exact fields bounded

@[step] theorem form_keys_exact (fields : Slice template_ast.FormMember) :
    template_ast.form_keys fields ⦃ actual => templateResult
      (fun keys => TemplateMembers.Refinement.keysView (alloc.vec.Vec.deref keys)) actual =
        if 0 < fields.val.length ∧ fields.val.length ≤ 16 then .ok (formFieldNames fields.val) else .error .shape ⦄ := by
  unfold template_ast.form_keys
  by_cases empty : fields.val.length = 0
  · have values : fields.val = [] := List.length_eq_zero_iff.mp empty
    simp [values, templateResult, templateErrorOf]
  · simp only [core.slice.Slice.is_empty, bind_tc_ok, Slice.len_val, Slice.length, empty, decide_false, Bool.false_or]
    by_cases large : 16 < fields.val.length
    · have native : fields.len > 16#usize := by scalar_tac
      simp [native, Nat.not_le.mpr large, templateResult, templateErrorOf]
    · have native : ¬fields.len > 16#usize := by scalar_tac
      have admitted : 0 < fields.val.length ∧ fields.val.length ≤ 16 := by omega
      simp only [native, ↓reduceIte]
      step with form_key_column_exact as ⟨keys, keysMeaning⟩
      simpa [templateResult, admitted] using keysMeaning

end Auths.Product.TemplateAst.Refinement
