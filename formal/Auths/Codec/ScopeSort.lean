import qualification.aeneas.generated.scope_codec.Funs
import Auths.Codec.ScopeModel
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
namespace Auths.ScopeConstructor
open Auths.Codec.StdModel
open AuthsScopeCodec

theorem anchor_comparison (left right : String) :
    AuthsScopeCodec.auths_model.TrustAnchorId.Insts.CoreCmpOrd.cmp left right = ok (compare left right) := rfl

theorem identity_key_call {T : Type} (value : T) :
    (@AuthsScopeCodec.identityKey T).call_mut () value = ok (value, ()) := rfl

theorem identity_insert (order : Aeneas.Std.core.cmp.Ord String)
    (comparison : ∀ left right, order.cmp left right = ok (compare left right))
    (item : String) (values : List String) :
    insertKeyValues AuthsScopeCodec.identityKey order () item values =
      ok ⟨values.orderedInsert Model.stringLE item, List.orderedInsert_length Model.stringLE values item⟩ := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    rw [insertKeyValues_cons]
    simp only [identity_key_call, comparison, bind_tc_ok]
    cases ordering : compare item first <;>
      simp [ordering, List.orderedInsert_cons, Model.stringLE, ih]

theorem identity_sort (order : Aeneas.Std.core.cmp.Ord String)
    (comparison : ∀ left right, order.cmp left right = ok (compare left right))
    (values : List String) :
    sortKeyValues AuthsScopeCodec.identityKey order () values =
      ok ⟨Model.sorted values, Model.sorted_length values⟩ := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    rw [sortKeyValues_cons, ih]
    simp only [bind_tc_ok, identity_insert order comparison]
    rfl

theorem anchor_sort (values : Slice String) :
    AuthsScopeCodec.alloc.slice.Slice.sort AuthsScopeCodec.auths_model.TrustAnchorId.Insts.CoreCmpOrd values =
      ok ⟨Model.sorted values.val, by rw [Model.sorted_length]; exact values.property⟩ := by
  unfold AuthsScopeCodec.alloc.slice.Slice.sort
  rw [sort_by_key_values, identity_sort _ anchor_comparison]
  rfl

end Auths.ScopeConstructor
