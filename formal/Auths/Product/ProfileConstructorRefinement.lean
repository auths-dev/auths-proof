import qualification.aeneas.generated.profile_construction.Funs
import Mathlib.Tactic
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_profile_construction.auths_connections
namespace Auths.Product.ProfileConstructor.Refinement
@[step] theorem constructor_exact (id : model.SemanticId) (version : Std.U16) :
    model.ConnectionProfile.new id version ⦃ actual =>
      actual = if version.val = 0 then .Err .InvalidProfile else .Ok ⟨id, version⟩ ⦄ := by
  unfold model.ConnectionProfile.new
  by_cases zero : version.val = 0
  · have nativeZero : version = 0#u16 := by scalar_tac
    simp [nativeZero]
  · have nativeNonzero : version ≠ 0#u16 := by scalar_tac
    simp [zero, nativeNonzero]

theorem source_success_preserves_fields (id : model.SemanticId) (version : Std.U16) :
    model.ConnectionProfile.new id version ⦃ actual => ∀ profile, actual = .Ok profile →
      profile.id = id ∧ profile.version = version ∧ 0 < profile.version.val ⦄ := by
  step with constructor_exact as ⟨actual, exactMeaning⟩
  rename_i profile accepted
  rw [accepted] at exactMeaning
  split at exactMeaning
  · contradiction
  · have fields : profile = ⟨id, version⟩ := by simpa using exactMeaning
    subst profile
    simp_all
    omega
theorem source_zero_version_refused (id : model.SemanticId) :
    model.ConnectionProfile.new id 0#u16 ⦃ actual => actual = .Err .InvalidProfile ⦄ := by
  exact constructor_exact id 0#u16

end Auths.Product.ProfileConstructor.Refinement
