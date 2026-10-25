import Auths.Codec.WireInverse
import Auths.Codec.DecodedFields
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.NativeFieldInverse
open Refinement ProtocolEncode ObjectEncode WireInverse DecodedFields

theorem stringBytes_injective : Function.Injective stringBytes := by
  intro left right same
  have converted := congrArg (List.map UInt8.ofNat) same
  simp only [stringBytes, List.map_map, Function.comp_def, UInt8.ofNat_toNat,
    List.map_id'] at converted
  apply String.toByteArray_inj.mp
  apply ByteArray.ext
  apply _root_.Array.toList_inj.mp
  simpa only [Auths.Model.Identifier.byte_array_list] using converted

theorem native_utf8 (value : String) : Payload.validUtf8 (stringBytes value) = true := by
  have bytes : ((stringBytes value).map UInt8.ofNat).toByteArray = value.toByteArray := by
    apply ByteArray.ext
    apply _root_.Array.toList_inj.mp
    simp [stringBytes, List.map_map, Function.comp_def, UInt8.ofNat_toNat,
      List.toList_data_toByteArray, Auths.Model.Identifier.byte_array_list]
  simp only [Payload.validUtf8, bytes, decide_eq_true_eq]
  exact value.isValidUTF8

theorem profileView_injective (left right : auths_codec.auths_model.ProfileRef)
    (same : ProfileDecode.profileView (.Ok left) = ProfileDecode.profileView (.Ok right)) : left = right := by
  have fields : stringBytes left.id = stringBytes right.id ∧ left.version.val = right.version.val := by
    simpa only [ProfileDecode.profileView, stringBytes, core.result.Result.Ok.injEq, Prod.mk.injEq] using same
  have id := stringBytes_injective fields.1
  have version : left.version = right.version := UScalar.eq_of_val_eq fields.2
  cases left
  cases right
  simp_all

theorem permissionView_injective (left right : auths_codec.auths_model.Permission)
    (same : PermissionDecode.permissionView (.Ok left) = PermissionDecode.permissionView (.Ok right)) : left = right := by
  have fields : stringBytes left.capability = stringBytes right.capability ∧
      stringBytes left.resource = stringBytes right.resource := by
    simpa only [PermissionDecode.permissionView, stringBytes, core.result.Result.Ok.injEq, Prod.mk.injEq] using same
  have capability := stringBytes_injective fields.1
  have resource := stringBytes_injective fields.2
  cases left
  cases right
  simp_all

theorem budgetView_injective (left right : auths_codec.auths_model.BudgetCeiling)
    (same : BudgetDecode.budgetView (.Ok left) = BudgetDecode.budgetView (.Ok right)) : left = right := by
  have fields : stringBytes left.algebra = stringBytes right.algebra ∧ left.value.val = right.value.val := by
    simpa only [BudgetDecode.budgetView, stringBytes, core.result.Result.Ok.injEq, Prod.mk.injEq] using same
  have algebra := stringBytes_injective fields.1
  have value : left.value = right.value := UScalar.eq_of_val_eq fields.2
  cases left
  cases right
  simp_all

/-- Native carrier inverse: the actual source reconstructs the identical
ProfileRef, rather than merely an equal diagnostic projection. -/
@[step] theorem profile_inverse (self : cbor.Decoder) (value : auths_codec.auths_model.ProfileRef)
    (leading trailing : List Nat)
    (inputBytes : byteList self.input.val = leading ++ profileEncoding (stringBytes value.id) value.version.val ++ trailing)
    (atStart : self.position.val = leading.length)
    (valid : ProfileValid (stringBytes value.id) value.version.val) :
    decode.profile_ref self ⦃ actual => actual.1 = .Ok value ∧
      actual.2.position.val = leading.length + (profileEncoding (stringBytes value.id) value.version.val).length ∧
      actual.2.input = self.input ⦄ := by
  have bound := (identifier_earns_bound _ _ valid.1).2.1
  have lengthBound : (stringBytes value.id).length < 2 ^ 64 := by omega
  apply spec_mono (WireInverse.profile_source_roundtrip self (stringBytes value.id) value.version.val
    leading trailing inputBytes atStart valid.1 (native_utf8 value.id) lengthBound valid.2.1 valid.2.2)
  rintro actual ⟨meaning, position, inputSame⟩
  cases result : actual.1 with
  | Err error => simp [result, ProfileDecode.profileView] at meaning
  | Ok decoded =>
    have exactValue : decoded = value := profileView_injective decoded value (by simpa [result, ProfileDecode.profileView, stringBytes] using meaning)
    exact ⟨by simpa only [result, exactValue], position, inputSame⟩

@[step] theorem permission_inverse (self : cbor.Decoder) (value : auths_codec.auths_model.Permission)
    (leading trailing : List Nat)
    (inputBytes : byteList self.input.val = leading ++ permissionEncoding (stringBytes value.capability) (stringBytes value.resource) ++ trailing)
    (atStart : self.position.val = leading.length)
    (valid : PermissionValid (stringBytes value.capability) (stringBytes value.resource)) :
    decode.permission self ⦃ actual => actual.1 = .Ok value ∧
      actual.2.position.val = leading.length + (permissionEncoding (stringBytes value.capability) (stringBytes value.resource)).length ∧
      actual.2.input = self.input ⦄ := by
  have capabilityBound := (identifier_earns_bound _ _ valid.1).2.1
  have resourceBound := (identifier_earns_bound _ _ valid.2).2.1
  apply spec_mono (WireInverse.permission_source_roundtrip self (stringBytes value.capability) (stringBytes value.resource)
    leading trailing inputBytes atStart valid.1 valid.2 (native_utf8 value.capability) (native_utf8 value.resource)
    (by omega) (by omega))
  rintro actual ⟨meaning, position, inputSame⟩
  cases result : actual.1 with
  | Err error => simp [result, PermissionDecode.permissionView] at meaning
  | Ok decoded =>
    have exactValue : decoded = value := permissionView_injective decoded value
      (by simpa [result, PermissionDecode.permissionView, stringBytes] using meaning)
    exact ⟨by simpa only [result, exactValue], position, inputSame⟩

@[step] theorem budget_inverse (self : cbor.Decoder) (value : auths_codec.auths_model.BudgetCeiling)
    (leading trailing : List Nat)
    (inputBytes : byteList self.input.val = leading ++ budgetEncoding (stringBytes value.algebra) value.value.val ++ trailing)
    (atStart : self.position.val = leading.length)
    (valid : BudgetValid (stringBytes value.algebra) value.value.val) :
    decode.budget self ⦃ actual => actual.1 = .Ok value ∧
      actual.2.position.val = leading.length + (budgetEncoding (stringBytes value.algebra) value.value.val).length ∧
      actual.2.input = self.input ⦄ := by
  have lengthBound := (identifier_earns_bound _ _ valid.1).2.1
  apply spec_mono (WireInverse.budget_source_roundtrip self (stringBytes value.algebra) value.value.val
    leading trailing inputBytes atStart valid.1 (native_utf8 value.algebra) (by omega) valid.2)
  rintro actual ⟨meaning, position, inputSame⟩
  cases result : actual.1 with
  | Err error => simp [result, BudgetDecode.budgetView] at meaning
  | Ok decoded =>
    have exactValue : decoded = value := budgetView_injective decoded value
      (by simpa [result, BudgetDecode.budgetView, stringBytes] using meaning)
    exact ⟨by simpa only [result, exactValue], position, inputSame⟩

theorem optionalView_injective (left right : Option auths_codec.auths_model.BudgetCeiling)
    (same : BudgetDecode.optionalView (.Ok left) = BudgetDecode.optionalView (.Ok right)) : left = right := by
  cases left with
  | none => cases right <;> simp_all [BudgetDecode.optionalView]
  | some left =>
    cases right with
    | none => simp [BudgetDecode.optionalView] at same
    | some right =>
      have fields : BudgetDecode.budgetView (.Ok left) = BudgetDecode.budgetView (.Ok right) := by
        simpa [BudgetDecode.optionalView, BudgetDecode.budgetView] using same
      rw [budgetView_injective left right fields]

@[step] theorem optional_budget_inverse (self : cbor.Decoder)
    (value : Option auths_codec.auths_model.BudgetCeiling) (leading trailing : List Nat)
    (inputBytes : byteList self.input.val = leading ++ optionalBudgetEncoding (value.map ObjectEncode.budgetView) ++ trailing)
    (atStart : self.position.val = leading.length)
    (valid : ∀ budget ∈ value, BudgetValid (stringBytes budget.algebra) budget.value.val) :
    decode.optional_budget self ⦃ actual => actual.1 = .Ok value ∧
      actual.2.position.val = leading.length + (optionalBudgetEncoding (value.map ObjectEncode.budgetView)).length ∧
      actual.2.input = self.input ⦄ := by
  have grammar : Consumes BudgetDecode.optionalAt (optionalBudgetEncoding (value.map ObjectEncode.budgetView))
      (value.map ObjectEncode.budgetView) := by
    cases value with
    | none => simpa [optionalBudgetEncoding] using optional_budget_none_roundtrip
    | some budget =>
      have budgetValid := valid budget (by simp)
      have lengthBound := (identifier_earns_bound _ _ budgetValid.1).2.1
      simpa [optionalBudgetEncoding, ObjectEncode.budgetView] using optional_budget_some_roundtrip
        (stringBytes budget.algebra) budget.value.val budgetValid.1 (native_utf8 budget.algebra)
        (by omega) budgetValid.2
  apply spec_mono (BudgetDecode.optional_budget_exact self)
  rintro actual ⟨meaning, inputSame⟩
  rw [inputBytes, atStart, grammar leading trailing] at meaning
  obtain ⟨sameView, samePosition⟩ := Prod.mk.inj meaning
  cases result : actual.1 with
  | Err error => simp [result, BudgetDecode.optionalView] at sameView
  | Ok decoded =>
    have exactValue : decoded = value := optionalView_injective decoded value
      (by simpa [result, BudgetDecode.optionalView, ObjectEncode.budgetView, stringBytes] using sameView)
    exact ⟨by simpa only [result, exactValue], samePosition, inputSame⟩

@[step] theorem media_parse_inverse (value : String) (bounded : value.toByteArray.size ≤ U32.max)
    (valid : ProfileDecode.identifierDecision (stringBytes value) 128 = true) :
    auths_model.MediaType.parse (toStr value bounded) ⦃ actual => actual = .Ok value ⦄ := by
  have utf8 : (StdModel.bytes (toStr value bounded)).IsValidUTF8 := by
    rw [StringRefinement.byte_array_round_trip]
    exact value.isValidUTF8
  apply spec_mono (MediaDecode.media_exact (toStr value bounded) utf8)
  intro actual meaning
  rw [borrowed_bytes, valid] at meaning
  cases actual with
  | Err error => simp at meaning
  | Ok decoded =>
    have same : decoded = value := stringBytes_injective (by simpa [stringBytes] using meaning)
    simp only [same]

end Auths.Codec.NativeFieldInverse
