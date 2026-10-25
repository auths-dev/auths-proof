import Auths.Product.NativeCompilerEmitterState
import Auths.Product.TemplateAstKeyAdmission

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativeKey := AuthsNativeRecipe.auths_gateway_kernel.template_members.NamedKey

def nativeKeys (keys : NativeVec NativeKey) : List (List Nat) := keys.val.map (fun key => bytes key.name)
def nativeJsonNames (fields : Slice KernelMember) : List (List Nat) :=
  fields.val.map (fun field => bytes field.name)
def nativeFormNames (fields : Slice KernelFormMember) : List (List Nat) :=
  fields.val.map (fun field => bytes field.name)

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open TemplateAst
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

private theorem native_json_column_suffix (iterator : core.slice.iter.Iter KernelMember)
    (output : NativeVec NativeKey)
    (room : output.val.length + (iterator.slice.val.length - iterator.i) ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_key_column_loop iterator output ⦃ actual =>
      nativeKeys actual = nativeKeys output ++
        (iterator.slice.val.drop iterator.i).map (fun field => bytes field.name) ⦄ := by
  generalize remaining : iterator.slice.val.length - iterator.i = count
  induction count using Nat.strong_induction_on generalizing iterator output with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_key_column_loop
      by_cases inside : iterator.i < iterator.slice.val.length
      · simp only [core.slice.iter.IteratorSliceIter.next, dif_pos inside, bind_tc_ok]
        let field := iterator.slice.val[iterator.i]
        let next : core.slice.iter.Iter KernelMember := { iterator with i := iterator.i + 1 }
        have suffix : iterator.slice.val.drop iterator.i = field :: next.slice.val.drop next.i := by
          simpa only [field, next] using List.drop_eq_getElem_cons inside
        step with native_schema_copy_bytes (AuthsNativeRecipe.alloc.vec.Vec.deref field.name)
          as ⟨name, nameMeaning⟩
        step with native_push_exact output (⟨name⟩ : NativeKey) (by omega) as ⟨updated, appended⟩
        have updatedLength : updated.val.length = output.val.length + 1 := by
          simp only [appended, List.length_append, List.length_singleton]
        have nextRoom : updated.val.length + (next.slice.val.length - next.i) ≤ Usize.max := by
          simp only [next]
          omega
        have smaller : next.slice.val.length - next.i < count := by
          simp only [next] at *
          omega
        apply spec_mono (ih _ smaller next updated nextRoom rfl)
        intro actual exact
        simpa [nativeKeys, suffix, appended, bytes, nameMeaning, native_deref_contents,
          List.map_append, List.map_cons, List.append_assoc, List.singleton_append] using exact
      · have ended : iterator.slice.val.length ≤ iterator.i := by omega
        simp [core.slice.iter.IteratorSliceIter.next, inside, List.drop_eq_nil_of_le ended, nativeKeys]

@[step] theorem native_json_key_column_exact (fields : Slice KernelMember) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_key_column fields ⦃ actual =>
      nativeKeys actual = nativeJsonNames fields ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_key_column
    SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter
  simp only [bind_tc_ok]
  apply spec_mono (native_json_column_suffix ⟨fields, 0⟩ (AuthsNativeRecipe.alloc.vec.Vec.new NativeKey)
    (by simpa only [native_empty_contents, List.length_nil, Nat.zero_add, Nat.sub_zero] using fields.property))
  intro actual exact
  simpa only [nativeKeys, nativeJsonNames, native_empty_contents, List.map_nil, List.nil_append, List.drop_zero] using exact

private theorem native_json_keys_suffix (iterator : core.slice.iter.Iter KernelMember) (fields : Slice KernelMember) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_keys_loop iterator fields ⦃ actual =>
      nativeTemplateResult nativeKeys actual =
        if ∀ field ∈ iterator.slice.val.drop iterator.i, OperationIdentity.validToken (bytes field.name) 64 = true
        then .ok (nativeJsonNames fields) else .error .shape ⦄ := by
  generalize remaining : iterator.slice.val.length - iterator.i = count
  induction count using Nat.strong_induction_on generalizing iterator with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_keys_loop
      by_cases inside : iterator.i < iterator.slice.val.length
      · simp only [core.slice.iter.IteratorSliceIter.next, dif_pos inside, bind_tc_ok]
        let field := iterator.slice.val[iterator.i]
        let next : core.slice.iter.Iter KernelMember := { iterator with i := iterator.i + 1 }
        have suffix : iterator.slice.val.drop iterator.i = field :: next.slice.val.drop next.i := by
          simpa only [field, next] using List.drop_eq_getElem_cons inside
        step with native_schema_token_exact (AuthsNativeRecipe.alloc.vec.Vec.deref field.name) 64#usize
          as ⟨lexical, lexicalMeaning⟩
        have tokenMeaning : lexical = OperationIdentity.validToken (bytes field.name) 64 := by
          simpa only [schemaSliceBytes, bytes, native_deref_contents] using lexicalMeaning
        cases lexical with
        | false => simp [suffix, ← tokenMeaning, nativeTemplateResult, nativeTemplateError]
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            have smaller : next.slice.val.length - next.i < count := by
              simp only [next] at *
              omega
            apply spec_mono (ih _ smaller next rfl)
            intro actual exact
            simpa only [suffix, List.mem_cons, forall_eq_or_imp, ← tokenMeaning,
              true_and] using exact
      · have ended : iterator.slice.val.length ≤ iterator.i := by omega
        simp only [core.slice.iter.IteratorSliceIter.next, dif_neg inside, bind_tc_ok]
        step with native_json_key_column_exact fields as ⟨keys, keysMeaning⟩
        simp [nativeTemplateResult, keysMeaning, List.drop_eq_nil_of_le ended]

@[step] theorem native_json_keys_exact (fields : Slice KernelMember) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_keys fields ⦃ actual =>
      nativeTemplateResult nativeKeys actual = keyNames 32 (nativeJsonNames fields) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_keys
  by_cases empty : fields.val = []
  · simp [core.slice.Slice.is_empty, empty, nativeTemplateResult, nativeTemplateError, keyNames, nativeJsonNames]
  · have positive : 0 < fields.val.length := List.length_pos.mpr empty
    simp only [core.slice.Slice.is_empty, empty, List.isEmpty_eq_false,
      Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
    by_cases large : 32 < fields.val.length
    · have nativeLarge : fields.len > 32#usize := by scalar_tac
      simp [nativeLarge, keyNames, nativeJsonNames, Nat.not_le.mpr large, nativeTemplateResult, nativeTemplateError]
    · have bounded : fields.val.length ≤ 32 := by omega
      have nativeBound : ¬fields.len > 32#usize := by scalar_tac
      simp only [nativeBound, ↓reduceIte,
        SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_tc_ok]
      apply spec_mono (native_json_keys_suffix ⟨fields, 0⟩ fields)
      intro actual exact
      simpa [keyNames, nativeJsonNames, positive, bounded, LexicalKeys,
        List.forall_mem_map] using exact

private theorem native_form_column_suffix (iterator : core.slice.iter.Iter KernelFormMember)
    (output : NativeVec NativeKey)
    (room : output.val.length + (iterator.slice.val.length - iterator.i) ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_key_column_loop iterator output ⦃ actual =>
      nativeKeys actual = nativeKeys output ++
        (iterator.slice.val.drop iterator.i).map (fun field => bytes field.name) ⦄ := by
  generalize remaining : iterator.slice.val.length - iterator.i = count
  induction count using Nat.strong_induction_on generalizing iterator output with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_key_column_loop
      by_cases inside : iterator.i < iterator.slice.val.length
      · simp only [core.slice.iter.IteratorSliceIter.next, dif_pos inside, bind_tc_ok]
        let field := iterator.slice.val[iterator.i]
        let next : core.slice.iter.Iter KernelFormMember := { iterator with i := iterator.i + 1 }
        have suffix : iterator.slice.val.drop iterator.i = field :: next.slice.val.drop next.i := by
          simpa only [field, next] using List.drop_eq_getElem_cons inside
        step with native_schema_copy_bytes (AuthsNativeRecipe.alloc.vec.Vec.deref field.name)
          as ⟨name, nameMeaning⟩
        step with native_push_exact output (⟨name⟩ : NativeKey) (by omega) as ⟨updated, appended⟩
        have updatedLength : updated.val.length = output.val.length + 1 := by
          simp only [appended, List.length_append, List.length_singleton]
        have nextRoom : updated.val.length + (next.slice.val.length - next.i) ≤ Usize.max := by
          simp only [next]
          omega
        have smaller : next.slice.val.length - next.i < count := by
          simp only [next] at *
          omega
        apply spec_mono (ih _ smaller next updated nextRoom rfl)
        intro actual exact
        simpa [nativeKeys, suffix, appended, bytes, nameMeaning, native_deref_contents,
          List.map_append, List.map_cons, List.append_assoc, List.singleton_append] using exact
      · have ended : iterator.slice.val.length ≤ iterator.i := by omega
        simp [core.slice.iter.IteratorSliceIter.next, inside, List.drop_eq_nil_of_le ended, nativeKeys]

@[step] theorem native_form_key_column_exact (fields : Slice KernelFormMember) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_key_column fields ⦃ actual =>
      nativeKeys actual = nativeFormNames fields ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_key_column
    SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter
  simp only [bind_tc_ok]
  apply spec_mono (native_form_column_suffix ⟨fields, 0⟩ (AuthsNativeRecipe.alloc.vec.Vec.new NativeKey)
    (by simpa only [native_empty_contents, List.length_nil, Nat.zero_add, Nat.sub_zero] using fields.property))
  intro actual exact
  simpa only [nativeKeys, nativeFormNames, native_empty_contents, List.map_nil, List.nil_append, List.drop_zero] using exact

private theorem native_form_keys_suffix (iterator : core.slice.iter.Iter KernelFormMember) (fields : Slice KernelFormMember) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_keys_loop iterator fields ⦃ actual =>
      nativeTemplateResult nativeKeys actual =
        if ∀ field ∈ iterator.slice.val.drop iterator.i, OperationIdentity.validToken (bytes field.name) 64 = true
        then .ok (nativeFormNames fields) else .error .shape ⦄ := by
  generalize remaining : iterator.slice.val.length - iterator.i = count
  induction count using Nat.strong_induction_on generalizing iterator with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_keys_loop
      by_cases inside : iterator.i < iterator.slice.val.length
      · simp only [core.slice.iter.IteratorSliceIter.next, dif_pos inside, bind_tc_ok]
        let field := iterator.slice.val[iterator.i]
        let next : core.slice.iter.Iter KernelFormMember := { iterator with i := iterator.i + 1 }
        have suffix : iterator.slice.val.drop iterator.i = field :: next.slice.val.drop next.i := by
          simpa only [field, next] using List.drop_eq_getElem_cons inside
        step with native_schema_token_exact (AuthsNativeRecipe.alloc.vec.Vec.deref field.name) 64#usize
          as ⟨lexical, lexicalMeaning⟩
        have tokenMeaning : lexical = OperationIdentity.validToken (bytes field.name) 64 := by
          simpa only [schemaSliceBytes, bytes, native_deref_contents] using lexicalMeaning
        cases lexical with
        | false => simp [suffix, ← tokenMeaning, nativeTemplateResult, nativeTemplateError]
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            have smaller : next.slice.val.length - next.i < count := by
              simp only [next] at *
              omega
            apply spec_mono (ih _ smaller next rfl)
            intro actual exact
            simpa only [suffix, List.mem_cons, forall_eq_or_imp, ← tokenMeaning,
              true_and] using exact
      · have ended : iterator.slice.val.length ≤ iterator.i := by omega
        simp only [core.slice.iter.IteratorSliceIter.next, dif_neg inside, bind_tc_ok]
        step with native_form_key_column_exact fields as ⟨keys, keysMeaning⟩
        simp [nativeTemplateResult, keysMeaning, List.drop_eq_nil_of_le ended]

@[step] theorem native_form_keys_exact (fields : Slice KernelFormMember) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_keys fields ⦃ actual =>
      nativeTemplateResult nativeKeys actual = keyNames 16 (nativeFormNames fields) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_keys
  by_cases empty : fields.val = []
  · simp [core.slice.Slice.is_empty, empty, nativeTemplateResult, nativeTemplateError, keyNames, nativeFormNames]
  · have positive : 0 < fields.val.length := List.length_pos.mpr empty
    simp only [core.slice.Slice.is_empty, empty, List.isEmpty_eq_false,
      Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
    by_cases large : 16 < fields.val.length
    · have nativeLarge : fields.len > 16#usize := by scalar_tac
      simp [nativeLarge, keyNames, nativeFormNames, Nat.not_le.mpr large, nativeTemplateResult, nativeTemplateError]
    · have bounded : fields.val.length ≤ 16 := by omega
      have nativeBound : ¬fields.len > 16#usize := by scalar_tac
      simp only [nativeBound, ↓reduceIte,
        SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_tc_ok]
      apply spec_mono (native_form_keys_suffix ⟨fields, 0⟩ fields)
      intro actual exact
      simpa [keyNames, nativeFormNames, positive, bounded, LexicalKeys,
        List.forall_mem_map] using exact

end Auths.Product.NativeCompiler.Refinement
