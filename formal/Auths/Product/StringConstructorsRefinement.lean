import qualification.aeneas.generated.profile_construction.Funs
import Auths.Product.ConnectionBytesRefinement
import Auths.Product.SemanticIdRefinement
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_profile_construction
namespace Auths.Product.StringConstructors.Refinement

def utf8Bytes (value : String) : List Nat := value.toByteArray.toList.map UInt8.toNat

private theorem lower_delegation (value : Slice Std.U8) (maximum : Std.Usize) :
    auths_profile_construction.auths_connections.kernel.lower_token_valid value maximum ⦃ actual =>
      actual = decide (ConnectionBytes.lowerValid (ConnectionBytes.Refinement.bytes value.val) maximum.val) ⦄ := by
  change _root_.auths_connections.kernel.lower_token_valid value maximum ⦃ actual =>
    actual = decide (ConnectionBytes.lowerValid (ConnectionBytes.Refinement.bytes value.val) maximum.val) ⦄
  exact ConnectionBytes.Refinement.lower_valid_exact value maximum

private theorem semantic_delegation (value : Slice Std.U8) (maximum : Std.Usize) :
    auths_profile_construction.auths_connections.kernel.semantic_id_valid value maximum ⦃ actual =>
      actual = decide (SemanticId.valid (SemanticId.Refinement.bytes value.val) maximum.val) ⦄ := by
  change _root_.auths_connections.kernel.semantic_id_valid value maximum ⦃ actual =>
    actual = decide (SemanticId.valid (SemanticId.Refinement.bytes value.val) maximum.val) ⦄
  exact SemanticId.Refinement.semantic_valid_exact value maximum

private theorem projected_bytes (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    ConnectionBytes.Refinement.bytes (toStr value bounded).val = utf8Bytes value := by
  simp only [ConnectionBytes.Refinement.bytes, toStr, utf8Bytes, List.map_map, List.map_inj_left]
  intro byte member
  cases byte
  rfl

@[step] theorem actual_provider_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    auths_profile_construction.auths_connections.model.ProviderKind.parse (core.convert.IntoFrom (core.convert.FromSame String)) value ⦃ actual =>
      actual = if ConnectionBytes.lowerValid (utf8Bytes value) 64
        then .Ok value else .Err .InvalidProviderKind ⦄ := by
  unfold auths_profile_construction.auths_connections.model.ProviderKind.parse
  simp only [core.convert.IntoFrom.into, core.convert.FromSame.from, bind_tc_ok]
  unfold auths_profile_construction.alloc.string.String.Insts.CoreOpsDerefDerefStr.deref
  simp only [_root_.alloc.string.String.Insts.CoreOpsDerefDerefStr.deref, bounded, ↓reduceDIte, bind_tc_ok]
  unfold auths_profile_construction.auths_connections.model.is_lower_token auths_profile_construction.core.str.Str.as_bytes
  simp only [_root_.core.str.Str.as_bytes, bind_tc_ok]
  step with lower_delegation as ⟨allowed, allowedMeaning⟩
  rw [projected_bytes] at allowedMeaning
  rw [allowedMeaning]
  split <;> simp_all [spec_ok]
@[step] theorem actual_alias_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    auths_profile_construction.auths_connections.model.ConnectionAlias.parse (core.convert.IntoFrom (core.convert.FromSame String)) value ⦃ actual =>
      actual = if ConnectionBytes.lowerValid (utf8Bytes value) 64
        then .Ok value else .Err .InvalidAlias ⦄ := by
  unfold auths_profile_construction.auths_connections.model.ConnectionAlias.parse
  simp only [core.convert.IntoFrom.into, core.convert.FromSame.from, bind_tc_ok]
  unfold auths_profile_construction.alloc.string.String.Insts.CoreOpsDerefDerefStr.deref
  simp only [_root_.alloc.string.String.Insts.CoreOpsDerefDerefStr.deref, bounded, ↓reduceDIte, bind_tc_ok]
  unfold auths_profile_construction.auths_connections.model.is_lower_token auths_profile_construction.core.str.Str.as_bytes
  simp only [_root_.core.str.Str.as_bytes, bind_tc_ok]
  step with lower_delegation as ⟨allowed, allowedMeaning⟩
  rw [projected_bytes] at allowedMeaning
  rw [allowedMeaning]
  split <;> simp_all [spec_ok]
@[step] theorem actual_semantic_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    auths_profile_construction.auths_connections.model.SemanticId.parse (core.convert.IntoFrom (core.convert.FromSame String)) value ⦃ actual =>
      actual = if SemanticId.valid (utf8Bytes value) 128
        then .Ok value else .Err .InvalidSemanticId ⦄ := by
  unfold auths_profile_construction.auths_connections.model.SemanticId.parse
  simp only [core.convert.IntoFrom.into, core.convert.FromSame.from, bind_tc_ok]
  unfold auths_profile_construction.alloc.string.String.as_bytes
  simp only [_root_.alloc.string.String.as_bytes, bounded, ↓reduceDIte, bind_tc_ok]
  step with semantic_delegation as ⟨allowed, allowedMeaning⟩
  have projection : SemanticId.Refinement.bytes (toStr value bounded).val = utf8Bytes value := by
    exact projected_bytes value bounded
  rw [projection] at allowedMeaning
  rw [allowedMeaning]
  split <;> simp_all [spec_ok]

theorem provider_success_earns_exact_valid_payload (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    auths_profile_construction.auths_connections.model.ProviderKind.parse (core.convert.IntoFrom (core.convert.FromSame String)) value ⦃ actual =>
      ∀ parsed, actual = .Ok parsed → parsed = value ∧ ConnectionBytes.lowerValid (utf8Bytes parsed) 64 ⦄ := by
  step with actual_provider_exact as ⟨actual, exactMeaning⟩
  rename_i parsed accepted
  rw [accepted] at exactMeaning
  split at exactMeaning
  · have preserved : parsed = value := by simpa using exactMeaning
    subst parsed
    exact ⟨rfl, by assumption⟩
  · contradiction

theorem alias_success_earns_exact_valid_payload (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    auths_profile_construction.auths_connections.model.ConnectionAlias.parse (core.convert.IntoFrom (core.convert.FromSame String)) value ⦃ actual =>
      ∀ parsed, actual = .Ok parsed → parsed = value ∧ ConnectionBytes.lowerValid (utf8Bytes parsed) 64 ⦄ := by
  step with actual_alias_exact as ⟨actual, exactMeaning⟩
  rename_i parsed accepted
  rw [accepted] at exactMeaning
  split at exactMeaning
  · have preserved : parsed = value := by simpa using exactMeaning
    subst parsed
    exact ⟨rfl, by assumption⟩
  · contradiction

theorem semantic_success_earns_exact_valid_payload (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    auths_profile_construction.auths_connections.model.SemanticId.parse (core.convert.IntoFrom (core.convert.FromSame String)) value ⦃ actual =>
      ∀ parsed, actual = .Ok parsed → parsed = value ∧ SemanticId.valid (utf8Bytes parsed) 128 ⦄ := by
  step with actual_semantic_exact as ⟨actual, exactMeaning⟩
  rename_i parsed accepted
  rw [accepted] at exactMeaning
  split at exactMeaning
  · have preserved : parsed = value := by simpa using exactMeaning
    subst parsed
    exact ⟨rfl, by assumption⟩
  · contradiction

end Auths.Product.StringConstructors.Refinement
