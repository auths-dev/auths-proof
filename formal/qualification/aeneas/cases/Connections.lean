import Auths.Product.RecordTimesRefinement
import Auths.Product.StringConstructorsRefinement
import Auths.Product.RecoveryGateRefinement
import Auths.Product.SemanticIdRefinement
import Auths.Product.ConnectionFrameRefinement
import Auths.Product.ProfileConstructorRefinement
import Auths.Product.ConnectionBytesRefinement
import qualification.aeneas.generated.connections.Funs

open Aeneas Aeneas.Std Result

namespace qualification.aeneas.cases

open auths_connections

-- A state change keeps the credential generation; a rotation sets both.
example :
    kernel.state_change { generation := 3#u64, credential_generation := 1#u64 } =
      ok (some { generation := 4#u64, credential_generation := 1#u64 }) := by
  rfl

example :
    kernel.rotation { generation := 3#u64, credential_generation := 1#u64 } =
      ok (some { generation := 4#u64, credential_generation := 4#u64 }) := by
  rfl

-- The last generation never wraps.
example : kernel.next_generation 18446744073709551615#u64 = ok none := by rfl

end qualification.aeneas.cases

#check Auths.Product.ConnectionBytes.Refinement.lower_tail_exact
#check Auths.Product.ConnectionBytes.Refinement.graphic_valid_exact
#check Auths.Product.ConnectionBytes.Refinement.lower_valid_exact
#check Auths.Product.ConnectionBytes.Refinement.source_lower_earns_no_nul
#check Auths.Product.ConnectionBytes.Refinement.source_graphic_earns_no_nul
#check Auths.Product.ConnectionBytes.Refinement.source_lower_earns_size_bound
#check Auths.Product.ConnectionBytes.Refinement.source_graphic_earns_size_bound

#check Auths.Product.ProfileConstructor.Refinement.constructor_exact
#check Auths.Product.ProfileConstructor.Refinement.source_success_preserves_fields
#check Auths.Product.ProfileConstructor.Refinement.source_zero_version_refused

namespace qualification.aeneas.cases.ConnectionBytes
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_connections
open Auths.Product.ConnectionBytes.Refinement
private def token : Slice U8 := ⟨[115#u8, 116#u8, 114#u8, 105#u8, 112#u8, 101#u8], by simp; scalar_tac⟩
private def injected : Slice U8 := ⟨[97#u8, 0#u8, 98#u8], by simp; scalar_tac⟩

example : kernel.lower_token_valid token 64#usize ⦃ actual => actual = true ⦄ := by
  step with lower_valid_exact as ⟨actual, exactMeaning⟩
  change actual = decide (Auths.Product.ConnectionBytes.lowerValid [115, 116, 114, 105, 112, 101] 64) at exactMeaning
  have allowed : Auths.Product.ConnectionBytes.lowerValid [115, 116, 114, 105, 112, 101] 64 := by decide
  simpa [allowed] using exactMeaning

example : kernel.lower_token_valid injected 64#usize ⦃ actual => actual = false ⦄ := by
  step with lower_valid_exact as ⟨actual, exactMeaning⟩
  change actual = decide (Auths.Product.ConnectionBytes.lowerValid [97, 0, 98] 64) at exactMeaning
  have denied : ¬ Auths.Product.ConnectionBytes.lowerValid [97, 0, 98] 64 := by decide
  simpa [denied] using exactMeaning

example : kernel.ascii_graphic_valid injected 128#usize ⦃ actual => actual = false ⦄ := by
  step with graphic_valid_exact as ⟨actual, exactMeaning⟩
  change actual = decide (Auths.Product.ConnectionBytes.graphicValid [97, 0, 98] 128) at exactMeaning
  have denied : ¬ Auths.Product.ConnectionBytes.graphicValid [97, 0, 98] 128 := by decide
  simpa [denied] using exactMeaning
end qualification.aeneas.cases.ConnectionBytes

namespace qualification.aeneas.cases.ProfileConstruction
open Aeneas Aeneas.Std Result
open auths_profile_construction.auths_connections
open Auths.Product.ProfileConstructor.Refinement
example : model.ConnectionProfile.new "auths.test" 1#u16
    ⦃ actual => actual = .Ok ⟨"auths.test", 1#u16⟩ ⦄ := by
  exact constructor_exact "auths.test" 1#u16
example : model.ConnectionProfile.new "auths.test" 0#u16
    ⦃ actual => actual = .Err .InvalidProfile ⦄ := by
  exact source_zero_version_refused "auths.test"
end qualification.aeneas.cases.ProfileConstruction

namespace qualification.aeneas.cases.SemanticIdentifier
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_connections
open Auths.Product.SemanticId.Refinement
private def accepted : Slice U8 := ⟨[65#u8, 58#u8, 49#u8], by simp; scalar_tac⟩
private def badHead : Slice U8 := ⟨[58#u8, 65#u8], by simp; scalar_tac⟩

example : kernel.semantic_id_valid accepted 128#usize ⦃ actual => actual = true ⦄ := by
  step with semantic_valid_exact as ⟨actual, exactMeaning⟩
  change actual = decide (Auths.Product.SemanticId.valid [65, 58, 49] 128) at exactMeaning
  have allowed : Auths.Product.SemanticId.valid [65, 58, 49] 128 := by decide
  simpa [allowed] using exactMeaning

example : kernel.semantic_id_valid badHead 128#usize ⦃ actual => actual = false ⦄ := by
  step with semantic_valid_exact as ⟨actual, exactMeaning⟩
  change actual = decide (Auths.Product.SemanticId.valid [58, 65] 128) at exactMeaning
  have refused : ¬ Auths.Product.SemanticId.valid [58, 65] 128 := by decide
  simpa [refused] using exactMeaning

example : kernel.semantic_id_valid accepted 2#usize ⦃ actual => actual = false ⦄ := by
  step with semantic_valid_exact as ⟨actual, exactMeaning⟩
  change actual = decide (Auths.Product.SemanticId.valid [65, 58, 49] 2) at exactMeaning
  have refused : ¬ Auths.Product.SemanticId.valid [65, 58, 49] 2 := by decide
  simpa [refused] using exactMeaning
end qualification.aeneas.cases.SemanticIdentifier

namespace qualification.aeneas.cases.RecoveryGuards
open Aeneas Aeneas.Std Result
open auths_connections
example : kernel.recovery_lease .Disabled 3#u64 2#u64 = ok (.Ok ()) := by rfl
example : kernel.recovery_lease .Revoked 0#u64 0#u64 = ok (.Err .Revoked) := by rfl
example : kernel.recovery_lease .Active 3#u64 0#u64 = ok (.Err .InvalidGeneration) := by rfl
example : kernel.recovery_lease .Active 3#u64 4#u64 = ok (.Err .InvalidGeneration) := by rfl
example : kernel.recovery_binding_requirement 4#u64 5#u64 4#u64 = ok .CurrentCommitment := by rfl
example : kernel.recovery_binding_requirement 4#u64 3#u64 2#u64 = ok .RecordedCommitment := by rfl
example : kernel.recovery_binding_requirement 4#u64 5#u64 3#u64 = ok .Refuse := by rfl
example : kernel.recovery_binding_requirement 4#u64 2#u64 3#u64 = ok .Refuse := by rfl
example : kernel.state_transition_allows .Active .Disabled 10#u64 10#u64 = ok true := by rfl
example : kernel.state_transition_allows .Revoked .Active 10#u64 11#u64 = ok false := by rfl
example : kernel.state_transition_allows .Disabled .Disabled 10#u64 11#u64 = ok false := by rfl
example : kernel.state_transition_allows .Active .Revoked 10#u64 9#u64 = ok false := by rfl
end qualification.aeneas.cases.RecoveryGuards

namespace qualification.aeneas.cases.AdministrativeChanges
open Aeneas Aeneas.Std Result
open auths_connections
example : kernel.record_change_allows .Disabled 10#u64 10#u64 = ok true := by rfl
example : kernel.record_change_allows .Revoked 10#u64 11#u64 = ok false := by rfl
example : kernel.record_change_allows .Active 10#u64 9#u64 = ok false := by rfl
end qualification.aeneas.cases.AdministrativeChanges

namespace qualification.aeneas.cases.OwnedStringConstructors
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open Auths.Product.StringConstructors.Refinement
private def provider := String.ofList ['s', 't', 'r', 'i', 'p', 'e']
private def unicodeAlias := String.ofList ['é']
private def semantic := String.ofList ['A', ':', '1']
example :
    auths_profile_construction.auths_connections.model.ProviderKind.parse
      (core.convert.IntoFrom (core.convert.FromSame String)) provider ⦃ actual => actual = .Ok provider ⦄ := by
  step with actual_provider_exact provider (by change 6 ≤ U32.max; scalar_tac) as ⟨actual, exactMeaning⟩
  have accepted : Auths.Product.ConnectionBytes.lowerValid (utf8Bytes provider) 64 := by
    unfold utf8Bytes provider
    simp only [String.toByteArray_ofList]
    unfold ByteArray.toList
    iterate 7 (rw [ByteArray.toList.loop]; norm_num only)
    change Auths.Product.ConnectionBytes.lowerValid [115, 116, 114, 105, 112, 101] 64
    decide
  simpa [accepted] using exactMeaning

example :
    auths_profile_construction.auths_connections.model.ConnectionAlias.parse
      (core.convert.IntoFrom (core.convert.FromSame String)) unicodeAlias ⦃ actual => actual = .Err .InvalidAlias ⦄ := by
  step with actual_alias_exact unicodeAlias (by change 2 ≤ U32.max; scalar_tac) as ⟨actual, exactMeaning⟩
  have refused : ¬ Auths.Product.ConnectionBytes.lowerValid (utf8Bytes unicodeAlias) 64 := by
    unfold utf8Bytes unicodeAlias
    simp only [String.toByteArray_ofList]
    unfold ByteArray.toList
    iterate 3 (rw [ByteArray.toList.loop]; norm_num only)
    change ¬ Auths.Product.ConnectionBytes.lowerValid [195, 169] 64
    decide
  simpa [refused] using exactMeaning

example :
    auths_profile_construction.auths_connections.model.SemanticId.parse
      (core.convert.IntoFrom (core.convert.FromSame String)) semantic ⦃ actual => actual = .Ok semantic ⦄ := by
  step with actual_semantic_exact semantic (by change 3 ≤ U32.max; scalar_tac) as ⟨actual, exactMeaning⟩
  have accepted : Auths.Product.SemanticId.valid (utf8Bytes semantic) 128 := by
    unfold utf8Bytes semantic
    simp only [String.toByteArray_ofList]
    unfold ByteArray.toList
    iterate 4 (rw [ByteArray.toList.loop]; norm_num only)
    change Auths.Product.SemanticId.valid [65, 58, 49] 128
    decide
  simpa [accepted] using exactMeaning
end qualification.aeneas.cases.OwnedStringConstructors

namespace qualification.aeneas.cases.RecordTimes
open Aeneas Aeneas.Std Result
open auths_connections
example : kernel.record_times_valid .Revoked 1#u64 3#u64 (some 2#u64) = ok true := by rfl
example : kernel.record_times_valid .Revoked 1#u64 3#u64 (some 3#u64) = ok true := by rfl
example : kernel.record_times_valid .Active 1#u64 3#u64 (some 2#u64) = ok false := by rfl
example : kernel.record_times_valid .Revoked 1#u64 3#u64 none = ok false := by rfl
example : kernel.record_times_valid .Revoked 1#u64 3#u64 (some 0#u64) = ok false := by rfl
example : kernel.record_times_valid .Active 3#u64 1#u64 none = ok false := by rfl
end qualification.aeneas.cases.RecordTimes
