import Auths.Product.NativeCompilerContainers
import Auths.Product.HeaderCompiler
import qualification.aeneas.generated.native_recipe.Funs

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativePathSource := AuthsNativeRecipe.recipe.source.PathSegment
abbrev NativeNamedSegment := AuthsNativeRecipe.auths_gateway_kernel.path_compiler.NamedSegment
abbrev NativeNamedHeader := AuthsNativeRecipe.auths_gateway_kernel.header_compiler.NamedHeader
abbrev NativeNamedScope := AuthsNativeRecipe.auths_gateway_kernel.header_compiler.NamedScope
abbrev NativeHeaders := AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap String String Global
abbrev NativeRecipeSource := AuthsNativeRecipe.recipe.source.RecipeSource

def sourceWriteMethod : AuthsNativeRecipe.recipe.WriteMethod → RequestConstruction.Method
  | .Post => .post | .Put => .put | .Patch => .patch | .Delete => .delete

def kernelWriteMethod : AuthsNativeRecipe.auths_gateway_kernel.construct.RequestMethod → RequestConstruction.Method
  | .Get => .get | .Head => .head | .Post => .post | .Put => .put | .Patch => .patch | .Delete => .delete

def NativePathFits : NativePathSource → Prop
  | .Fixed value => TextFits value
  | .Field name => TextFits name
  | .ResponseField _ _ | .Echo => True

/-- Refused path kinds remain an unsupported marker for the kernel. This
view grants them no field index or rendered-path meaning. -/
def originalPathSegment : NativePathSource → PathCompiler.SourceSegment
  | .Fixed value => .fixed (textBytes value)
  | .Field name => .field (textBytes name)
  | .ResponseField _ _ | .Echo => .unsupported

def loweredPathSegment : NativeNamedSegment → PathCompiler.SourceSegment
  | .Fixed value => .fixed (bytes value)
  | .Field name => .field (bytes name)
  | .Unsupported => .unsupported

def originalHeaders (headers : NativeHeaders) : HeaderCompiler.Versions :=
  headers.entries.val.map (fun pair => (textBytes pair.1, textBytes pair.2))

def loweredHeaders (headers : NativeVec NativeNamedHeader) : HeaderCompiler.Versions :=
  headers.val.map (fun header => (bytes header.name, bytes header.value))

def originalScope (scope : AuthsNativeRecipe.recipe.source.AccountScopeSource) : HeaderCompiler.ScopeSource :=
  ⟨textBytes scope.header, textBytes scope.field⟩

def loweredScope (scope : NativeNamedScope) : HeaderCompiler.ScopeSource :=
  ⟨bytes scope.name, bytes scope.field⟩

def NativeHeaderFits (source : NativeRecipeSource) : Prop :=
  (match source.provider_headers with
    | none => True
    | some headers => ∀ pair ∈ headers.entries.val, TextFits pair.1 ∧ TextFits pair.2) ∧
  (match source.account_scope with
    | none => True
    | some scope => TextFits scope.header ∧ TextFits scope.field)

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

@[step] theorem native_write_method_exact (method : AuthsNativeRecipe.recipe.WriteMethod) :
    AuthsNativeRecipe.recipe.lower.method method ⦃ actual =>
      kernelWriteMethod actual = sourceWriteMethod method ⦄ := by
  cases method <;> simp [AuthsNativeRecipe.recipe.lower.method, kernelWriteMethod, sourceWriteMethod]

private theorem native_path_suffix (iterator : core.slice.iter.Iter NativePathSource)
    (output : NativeVec NativeNamedSegment)
    (bounded : ∀ segment ∈ iterator.slice.val, NativePathFits segment)
    (room : output.val.length + (iterator.slice.val.length - iterator.i) ≤ Usize.max) :
    AuthsNativeRecipe.recipe.lower.named_path_loop iterator output ⦃ actual =>
      actual.val.map loweredPathSegment = output.val.map loweredPathSegment ++
        (iterator.slice.val.drop iterator.i).map originalPathSegment ⦄ := by
  generalize remaining : iterator.slice.val.length - iterator.i = count
  induction count using Nat.strong_induction_on generalizing iterator output with
  | h count ih =>
    unfold AuthsNativeRecipe.recipe.lower.named_path_loop
    by_cases inside : iterator.i < iterator.slice.val.length
    · simp only [core.slice.iter.IteratorSliceIter.next, dif_pos inside, bind_tc_ok]
      let segment := iterator.slice.val[iterator.i]
      let next : core.slice.iter.Iter NativePathSource := { iterator with i := iterator.i + 1 }
      have originalSuffix : iterator.slice.val.drop iterator.i = segment :: iterator.slice.val.drop next.i := by
        simpa only [segment, next] using List.drop_eq_getElem_cons inside
      have member : segment ∈ iterator.slice.val := List.getElem_mem inside
      have segmentBound := bounded segment member
      have capacity : output.val.length < Usize.max := by omega
      have continue (lowered : NativeNamedSegment)
          (same : loweredPathSegment lowered = originalPathSegment segment) :
          (do let updated ← AuthsNativeRecipe.alloc.vec.Vec.push output lowered
              AuthsNativeRecipe.recipe.lower.named_path_loop next updated) ⦃ actual =>
            actual.val.map loweredPathSegment = output.val.map loweredPathSegment ++
              (iterator.slice.val.drop iterator.i).map originalPathSegment ⦄ := by
        step with native_push_exact output lowered capacity as ⟨updated, appended⟩
        have updatedLength : updated.val.length = output.val.length + 1 := by
          simp only [appended, List.length_append, List.length_singleton]
        have nextRoom : updated.val.length + (next.slice.val.length - next.i) ≤ Usize.max := by
          simp only [next]
          omega
        have smaller : next.slice.val.length - next.i < count := by
          simp only [next] at *
          omega
        apply spec_mono (ih _ smaller next updated bounded nextRoom rfl)
        intro actual exact
        simpa only [appended, List.map_append, List.map_singleton, originalSuffix,
          List.map_cons, same, List.append_assoc, List.singleton_append, next] using exact
      cases shape : segment with
      | Fixed value =>
          have fits : TextFits value := by simpa only [shape, NativePathFits] using segmentBound
          step with borrow_text_exact value fits as ⟨raw, rawMeaning⟩
          step with copy_u8_exact raw as ⟨copied, copiedMeaning⟩
          apply continue (.Fixed copied)
          simpa only [loweredPathSegment, originalPathSegment, shape, bytes] using
            copiedMeaning.trans rawMeaning
      | Field name =>
          have fits : TextFits name := by simpa only [shape, NativePathFits] using segmentBound
          step with borrow_text_exact name fits as ⟨raw, rawMeaning⟩
          step with copy_u8_exact raw as ⟨copied, copiedMeaning⟩
          apply continue (.Field copied)
          simpa only [loweredPathSegment, originalPathSegment, shape, bytes] using
            copiedMeaning.trans rawMeaning
      | ResponseField pointer maximumAge =>
          apply continue .Unsupported
          simp only [loweredPathSegment, originalPathSegment, shape]
      | Echo =>
          apply continue .Unsupported
          simp only [loweredPathSegment, originalPathSegment, shape]
    · have ended : iterator.slice.val.length ≤ iterator.i := by omega
      simp only [core.slice.iter.IteratorSliceIter.next, dif_neg inside, bind_tc_ok,
        spec_ok, List.drop_eq_nil_of_le ended, List.map_nil, List.append_nil]

/-- Complete native path conversion: original fixed/name bytes and segment
order are retained; unsupported source kinds remain refused markers. -/
@[step] theorem native_path_input_exact (path : Slice NativePathSource)
    (bounded : ∀ segment ∈ path.val, NativePathFits segment) :
    AuthsNativeRecipe.recipe.lower.named_path path ⦃ actual =>
      actual.val.map loweredPathSegment = path.val.map originalPathSegment ⦄ := by
  unfold AuthsNativeRecipe.recipe.lower.named_path
    SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter
  simp only [bind_tc_ok]
  apply spec_mono (native_path_suffix ⟨path, 0⟩ (AuthsNativeRecipe.alloc.vec.Vec.new NativeNamedSegment)
    bounded (by simpa only [native_empty_contents, List.length_nil, Nat.zero_add, Nat.sub_zero] using path.property))
  intro actual exact
  simpa only [native_empty_contents, List.map_nil, List.nil_append, List.drop_zero] using exact

theorem native_path_input_keeps_count (path : Slice NativePathSource)
    (bounded : ∀ segment ∈ path.val, NativePathFits segment) :
    AuthsNativeRecipe.recipe.lower.named_path path ⦃ actual => actual.val.length = path.val.length ⦄ := by
  apply spec_mono (native_path_input_exact path bounded)
  intro actual exact
  simpa only [List.length_map] using congrArg List.length exact

private theorem native_header_suffix
    (iterator : AuthsNativeRecipe.alloc.collections.btree.map.Iter String String)
    (output : NativeVec NativeNamedHeader)
    (bounded : ∀ pair ∈ iterator.val, TextFits pair.1 ∧ TextFits pair.2)
    (room : output.val.length + iterator.val.length ≤ Usize.max) :
    AuthsNativeRecipe.recipe.lower.header_source_loop iterator output ⦃ actual =>
      loweredHeaders actual = loweredHeaders output ++
        iterator.val.map (fun pair => (textBytes pair.1, textBytes pair.2)) ⦄ := by
  generalize remaining : iterator.val.length = count
  induction count using Nat.strong_induction_on generalizing iterator output with
  | h count ih =>
    unfold AuthsNativeRecipe.recipe.lower.header_source_loop
    simp only [AuthsNativeRecipe.alloc.collections.btree.map.Iter.Insts.CoreIterTraitsIteratorIteratorPairSharedAKSharedAV.next]
    step with next_pair_exact iterator as ⟨next, nextMeaning⟩
    cases original : iterator.val with
    | nil =>
        have ended : next.1 = none := (by simpa only [original] using nextMeaning).1
        simp only [ended, spec_ok, original, List.map_nil, List.append_nil]
    | cons pair rest =>
        obtain ⟨headAt, tailAt⟩ : next.1 = some pair ∧ next.2.val = rest := by
          simpa only [original] using nextMeaning
        simp only [headAt]
        have member : pair ∈ iterator.val := by simp only [original, List.mem_cons]; exact Or.inl rfl
        step with borrow_text_exact pair.1 (bounded pair member).1 as ⟨rawName, rawNameMeaning⟩
        step with copy_u8_exact rawName as ⟨name, copiedNameMeaning⟩
        have nameMeaning : name.val.map (·.val) = textBytes pair.1 :=
          copiedNameMeaning.trans rawNameMeaning
        step with borrow_text_exact pair.2 (bounded pair member).2 as ⟨rawValue, rawValueMeaning⟩
        step with copy_u8_exact rawValue as ⟨value, copiedValueMeaning⟩
        have valueMeaning : value.val.map (·.val) = textBytes pair.2 :=
          copiedValueMeaning.trans rawValueMeaning
        let header : NativeNamedHeader := ⟨name, value⟩
        have capacity : output.val.length < Usize.max := by
          simp only [original, List.length_cons] at room
          omega
        step with native_push_exact output header capacity as ⟨updated, appended⟩
        have updatedLength : updated.val.length = output.val.length + 1 := by
          simp only [appended, List.length_append, List.length_singleton]
        have nextBounds : ∀ pair ∈ next.2.val, TextFits pair.1 ∧ TextFits pair.2 := by
          intro other belongs
          apply bounded other
          simp only [original, List.mem_cons]
          exact Or.inr (by simpa only [tailAt] using belongs)
        have nextRoom : updated.val.length + next.2.val.length ≤ Usize.max := by
          simp only [original, List.length_cons] at room
          simp only [tailAt]
          omega
        have smaller : next.2.val.length < count := by
          simp only [original, tailAt, List.length_cons] at *
          omega
        apply spec_mono (ih _ smaller next.2 updated nextBounds nextRoom rfl)
        intro actual exact
        simpa only [loweredHeaders, appended, List.map_append, List.map_singleton,
          header, nameMeaning, valueMeaning, original, List.map_cons, tailAt,
          List.append_assoc, List.singleton_append] using exact

/-- Both optional source columns remain exact, including None versus Some []
and every original account-scope header/field byte. This performs no header
catalog validation or field-index selection; those belong to the compiler. -/
@[step] theorem native_header_input_exact (source : NativeRecipeSource) (bounded : NativeHeaderFits source) :
    AuthsNativeRecipe.recipe.lower.header_source source ⦃ actual =>
      actual.1.map loweredHeaders = source.provider_headers.map originalHeaders ∧
      actual.2.map loweredScope = source.account_scope.map originalScope ⦄ := by
  cases headersAt : source.provider_headers with
  | none =>
      unfold AuthsNativeRecipe.recipe.lower.header_source
      simp only [headersAt]
      cases scopeAt : source.account_scope with
      | none => simp [scopeAt, headersAt]
      | some scope =>
          have scopeFits : TextFits scope.header ∧ TextFits scope.field := by
            simpa only [NativeHeaderFits, headersAt, scopeAt, true_and] using bounded
          simp only [scopeAt]
          step with borrow_text_exact scope.header scopeFits.1 as ⟨rawName, rawNameMeaning⟩
          step with copy_u8_exact rawName as ⟨name, copiedNameMeaning⟩
          have nameMeaning : name.val.map (·.val) = textBytes scope.header :=
            copiedNameMeaning.trans rawNameMeaning
          step with borrow_text_exact scope.field scopeFits.2 as ⟨rawField, rawFieldMeaning⟩
          step with copy_u8_exact rawField as ⟨field, copiedFieldMeaning⟩
          have fieldMeaning : field.val.map (·.val) = textBytes scope.field :=
            copiedFieldMeaning.trans rawFieldMeaning
          simp only [spec_ok, loweredScope, originalScope, nameMeaning, fieldMeaning,
            headersAt, scopeAt, Option.map_none, Option.map_some, and_self]
  | some headers =>
      have headerFits : ∀ pair ∈ headers.entries.val, TextFits pair.1 ∧ TextFits pair.2 := by
        simpa only [NativeHeaderFits, headersAt] using bounded.1
      unfold AuthsNativeRecipe.recipe.lower.header_source
      simp only [headersAt,
        AuthsNativeRecipe.SharedABTreeMap.Insts.CoreIterTraitsCollectIntoIteratorPairSharedAKSharedAVIter.into_iter,
        bind_tc_ok]
      step with native_header_suffix headers.entries (AuthsNativeRecipe.alloc.vec.Vec.new NativeNamedHeader)
        headerFits (by simpa only [native_empty_contents, List.length_nil, Nat.zero_add] using headers.entries.property)
        as ⟨output, exactHeaders⟩
      have headersMeaning : loweredHeaders output = originalHeaders headers := by
        simpa only [loweredHeaders, originalHeaders, native_empty_contents, List.map_nil, List.nil_append] using exactHeaders
      cases scopeAt : source.account_scope with
      | none => simp [headersAt, scopeAt, headersMeaning]
      | some scope =>
          have scopeFits : TextFits scope.header ∧ TextFits scope.field := by
            simpa only [NativeHeaderFits, scopeAt] using bounded.2
          simp only [scopeAt]
          step with borrow_text_exact scope.header scopeFits.1 as ⟨rawName, rawNameMeaning⟩
          step with copy_u8_exact rawName as ⟨name, copiedNameMeaning⟩
          have nameMeaning : name.val.map (·.val) = textBytes scope.header :=
            copiedNameMeaning.trans rawNameMeaning
          step with borrow_text_exact scope.field scopeFits.2 as ⟨rawField, rawFieldMeaning⟩
          step with copy_u8_exact rawField as ⟨field, copiedFieldMeaning⟩
          have fieldMeaning : field.val.map (·.val) = textBytes scope.field :=
            copiedFieldMeaning.trans rawFieldMeaning
          simp only [spec_ok, loweredScope, originalScope, nameMeaning, fieldMeaning,
            headersAt, scopeAt, Option.map_some, headersMeaning, and_self]

end Auths.Product.NativeCompiler.Refinement
