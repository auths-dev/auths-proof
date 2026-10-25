import Auths.Codec.Fields
import Auths.Codec.String
import Auths.Refinement.Identifier
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.StringCarrier

private def owned (value : Str) (valid : (StdModel.bytes value).IsValidUTF8) : String :=
  String.fromUTF8 (StdModel.bytes value) valid

private theorem copy_exact (value : Str) (valid : (StdModel.bytes value).IsValidUTF8) :
    alloc.string.String.Insts.CoreConvertFromShared0Str.from value = ok (owned value valid) := by
  simp [alloc.string.String.Insts.CoreConvertFromShared0Str.from, String.fromUTF8?, valid, owned]

private theorem owned_bytes (value : Str) (valid : (StdModel.bytes value).IsValidUTF8) :
    (owned value valid).toByteArray.toList.map UInt8.toNat = Refinement.byteList value.val := by
  simp only [owned, String.fromUTF8, StdModel.bytes, Auths.Model.Identifier.byte_array_list,
    List.toList_data_toByteArray, List.map_map, Refinement.byteList]
  apply List.map_congr_left
  intro byte member
  have bound : byte.val < 256 := by scalar_tac
  simp [UInt8.toNat_ofNat, Nat.mod_eq_of_lt bound]

private def identifierDecision (bytes : List Std.U8) (maximum : Nat) : Bool :=
  !bytes.isEmpty && decide (bytes.length ≤ maximum) && !Auths.Refinement.Identifier.containsExcluded bytes

@[step] private theorem profile_parse_exact (value : Str) (valid : (StdModel.bytes value).IsValidUTF8) :
    auths_model.ProfileId.parse value ⦃ actual =>
      actual = if identifierDecision value.val 128 then .Ok (owned value valid)
        else .Err auths_model.ModelError.InvalidProfile ⦄ := by
  unfold auths_model.ProfileId.parse
  have checker := Auths.Refinement.Identifier.identifier_exact value 128#usize
  change auths_codec.auths_model.identifier.bounded_identifier_valid value 128#usize
    ⦃ result => result = _ ⦄ at checker
  step with checker as ⟨allowed, meaning⟩
  simp only [identifierDecision] at *
  rw [meaning]
  split <;> simp_all [copy_exact]

@[step] private theorem capability_parse_exact (value : Str) (valid : (StdModel.bytes value).IsValidUTF8) :
    auths_model.CapabilityId.parse value ⦃ actual =>
      actual = if identifierDecision value.val 128 then .Ok (owned value valid)
        else .Err auths_model.ModelError.InvalidCapability ⦄ := by
  unfold auths_model.CapabilityId.parse
  have checker := Auths.Refinement.Identifier.identifier_exact value 128#usize
  change auths_codec.auths_model.identifier.bounded_identifier_valid value 128#usize
    ⦃ result => result = _ ⦄ at checker
  step with checker as ⟨allowed, meaning⟩
  simp only [identifierDecision] at *
  rw [meaning]
  split <;> simp_all [copy_exact]

@[step] private theorem resource_parse_exact (value : Str) (valid : (StdModel.bytes value).IsValidUTF8) :
    auths_model.ResourceId.parse value ⦃ actual =>
      actual = if identifierDecision value.val 1024 then .Ok (owned value valid)
        else .Err auths_model.ModelError.InvalidResource ⦄ := by
  unfold auths_model.ResourceId.parse
  have checker := Auths.Refinement.Identifier.identifier_exact value 1024#usize
  change auths_codec.auths_model.identifier.bounded_identifier_valid value 1024#usize
    ⦃ result => result = _ ⦄ at checker
  step with checker as ⟨allowed, meaning⟩
  simp only [identifierDecision] at *
  rw [meaning]
  split <;> simp_all [copy_exact]

@[step] private theorem budget_algebra_parse_exact (value : Str) (valid : (StdModel.bytes value).IsValidUTF8) :
    auths_model.BudgetAlgebraId.parse value ⦃ actual =>
      actual = if identifierDecision value.val 128 then .Ok (owned value valid)
        else .Err auths_model.ModelError.InvalidRegistryId ⦄ := by
  unfold auths_model.BudgetAlgebraId.parse
  have checker := Auths.Refinement.Identifier.identifier_exact value 128#usize
  change auths_codec.auths_model.identifier.bounded_identifier_valid value 128#usize
    ⦃ result => result = _ ⦄ at checker
  step with checker as ⟨allowed, meaning⟩
  simp only [identifierDecision] at *
  rw [meaning]
  split <;> simp_all [copy_exact]

@[step] private theorem media_parse_exact (value : Str) (valid : (StdModel.bytes value).IsValidUTF8) :
    auths_model.MediaType.parse value ⦃ actual =>
      actual = if identifierDecision value.val 128 then .Ok (owned value valid)
        else .Err auths_model.ModelError.InvalidMediaType ⦄ := by
  unfold auths_model.MediaType.parse
  have checker := Auths.Refinement.Identifier.identifier_exact value 128#usize
  change auths_codec.auths_model.identifier.bounded_identifier_valid value 128#usize
    ⦃ result => result = _ ⦄ at checker
  step with checker as ⟨allowed, meaning⟩
  simp only [identifierDecision] at *
  rw [meaning]
  split <;> simp_all [copy_exact]

end Auths.Codec.StringCarrier

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.ProfileDecode

def andThen {α β : Type} (value : core.result.Result α error.CodecError × Nat)
    (next : α → Nat → core.result.Result β error.CodecError × Nat) :
    core.result.Result β error.CodecError × Nat :=
  match value with
  | (.Err error, position) => (.Err error, position)
  | (.Ok value, position) => next value position

def identifierDecision (bytes : List Nat) (maximum : Nat) : Bool :=
  !bytes.isEmpty && decide (bytes.length ≤ maximum) && !Auths.Model.Identifier.containsExcluded bytes

def wordAt (input : List Nat) (position : Nat) : core.result.Result Nat error.CodecError × Nat :=
  let (value, next) := Cursor.narrowHead input position 65535
  (match value with | none => .Err error.CodecError.Malformed | some value => .Ok value, next)

def profileAt (input : List Nat) (position : Nat) :
    core.result.Result (List Nat × Nat) error.CodecError × Nat :=
  andThen (Fields.mapAt input position 2) fun _ position =>
  andThen (Fields.keyAt input position 0) fun _ position =>
  andThen (Fields.textAt input position) fun id position =>
  if identifierDecision id 128 then
    andThen (Fields.keyAt input position 1) fun _ position =>
    andThen (wordAt input position) fun version position =>
    if version = 0 then (.Err (.Model .InvalidProfile), position)
    else (.Ok (id, version), position)
  else (.Err (.Model .InvalidProfile), position)

def profileView (value : core.result.Result auths_codec.auths_model.ProfileRef error.CodecError) :
    core.result.Result (List Nat × Nat) error.CodecError :=
  match value with
  | .Err error => .Err error
  | .Ok value => .Ok (value.id.toByteArray.toList.map UInt8.toNat, value.version.val)

private theorem identifier_view (value : Str) (maximum : Nat) :
    StringCarrier.identifierDecision value.val maximum = identifierDecision (Refinement.byteList value.val) maximum := by
  simp [StringCarrier.identifierDecision, identifierDecision, Refinement.byteList,
    Auths.Refinement.Identifier.scan_view]

private theorem text_valid (input : List Nat) (position : Nat) (bytes : List Nat) (next : Nat)
    (accepted : Fields.textAt input position = (.Ok bytes, next)) : Payload.validUtf8 bytes = true := by
  cases payloadEq : Payload.payloadAt input position 3 with
  | mk payload finish =>
    cases payload with
    | none => simp [Fields.textAt, Payload.textAt, payloadEq] at accepted
    | some raw =>
      by_cases valid : Payload.validUtf8 raw = true
      · simp [Fields.textAt, Payload.textAt, payloadEq, Option.filter, valid] at accepted
        obtain ⟨same, _⟩ := accepted
        subst bytes
        exact valid
      · simp [Fields.textAt, Payload.textAt, payloadEq, Option.filter, valid] at accepted

private theorem earned_utf8 (self : cbor.Decoder) (bytes : Str) (next : cbor.Decoder)
    (meaning : (Fields.codecBytesView (.Ok bytes), next.position.val) =
      Fields.textAt (Refinement.byteList self.input.val) self.position.val) :
    (StdModel.bytes bytes).IsValidUTF8 := by
  have valid := text_valid _ _ _ _ meaning.symm
  simpa [Payload.validUtf8, Refinement.byteList, StdModel.bytes,
    List.map_map, Function.comp_def] using valid


@[step] theorem profile_exact (self : cbor.Decoder) :
    decode.profile_ref self ⦃ actual =>
      (profileView actual.1, actual.2.position.val) =
        profileAt (Refinement.byteList self.input.val) self.position.val ∧
      actual.2.input = self.input ⦄ := by
  unfold decode.profile_ref
  step with Fields.map_exact as ⟨fields, afterMap, mapMeaning, mapInput⟩
  cases fields with
  | Err error =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, profileAt, andThen, ← mapMeaning, profileView, mapInput]
  | Ok _ =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with Fields.key_exact as ⟨key, afterKey, keyMeaning, keyInput⟩
    simp only [mapInput] at keyMeaning
    cases key with
    | Err error =>
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, profileAt, andThen, ← mapMeaning, ← keyMeaning,
        profileView, keyInput, mapInput]
    | Ok _ =>
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      step with Fields.text_exact as ⟨text, afterText, textMeaning, textInput⟩
      have textSource := textMeaning
      simp only [keyInput, mapInput] at textMeaning
      cases text with
      | Err error =>
        simp [core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame.from, profileAt, andThen, ← mapMeaning, ← keyMeaning,
          ← textMeaning, Fields.codecBytesView, profileView, textInput, keyInput, mapInput]
      | Ok bytes =>
        simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
        have valid := earned_utf8 afterKey bytes afterText textSource
        have parseContract := StringCarrier.profile_parse_exact bytes valid
        by_cases allowed : StringCarrier.identifierDecision bytes.val 128 = true
        · simp only [allowed, ↓reduceIte] at parseContract
          step with parseContract as ⟨parsed, parseMeaning⟩
          simp only [parseMeaning]
          simp only [core.result.Result.map_err, bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
          step with Fields.key_exact as ⟨key, afterVersionKey, versionKeyMeaning, versionKeyInput⟩
          simp only [textInput, keyInput, mapInput] at versionKeyMeaning
          cases key with
          | Err error =>
            simp [core.result.Result.Insts.CoreOpsTry.branch,
              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
              core.convert.FromSame.from, profileAt, andThen, ← mapMeaning, ← keyMeaning,
              ← textMeaning, Fields.codecBytesView, ← versionKeyMeaning,
              ← identifier_view, allowed, profileView, versionKeyInput, textInput, keyInput, mapInput]
          | Ok _ =>
            simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
            step with Cursor.u16_exact as ⟨word, finish, wordMeaning, wordInput⟩
            simp only [versionKeyInput, textInput, keyInput, mapInput] at wordMeaning
            cases word with
            | Err error =>
              simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                core.result.Result.Insts.CoreOpsTry.branch,
                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                core.convert.FromSame.from, profileAt, andThen, ← mapMeaning, ← keyMeaning,
                ← textMeaning, Fields.codecBytesView, ← versionKeyMeaning,
                ← identifier_view, allowed, wordAt, ← wordMeaning, Cursor.wordView,
                profileView, wordInput, versionKeyInput, textInput, keyInput, mapInput]
            | Ok version =>
              simp only [core.result.Result.map_err, bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
              unfold auths_model.ProfileRef.new
              by_cases zero : version = 0#u16
              · have zeroValue : version.val = 0 := by simpa using congrArg UScalar.val zero
                simp [zero, core.result.Result.map_err, BuiltinFnOnce,
                  error.CodecError.Insts.CoreConvertFromModelError.from,
                  profileAt, andThen, ← mapMeaning, ← keyMeaning,
                  ← textMeaning, Fields.codecBytesView, ← versionKeyMeaning,
                  ← identifier_view, allowed, wordAt, ← wordMeaning, Cursor.wordView,
                  profileView, zeroValue, wordInput, versionKeyInput, textInput, keyInput, mapInput]
              · have positive : version.val ≠ 0 := by
                  intro valueZero
                  exact zero ((UScalar.eq_equiv _ _).mpr (by simpa using valueZero))
                simp [zero, core.result.Result.map_err,
                  profileAt, andThen, ← mapMeaning, ← keyMeaning,
                  ← textMeaning, Fields.codecBytesView, ← versionKeyMeaning,
                  ← identifier_view, allowed, wordAt, ← wordMeaning, Cursor.wordView,
                  profileView, StringCarrier.owned_bytes, positive,
                  wordInput, versionKeyInput, textInput, keyInput, mapInput]
        · simp only [allowed, ↓reduceIte] at parseContract
          step with parseContract as ⟨parsed, parseMeaning⟩
          simp only [parseMeaning]
          simp [core.result.Result.map_err, BuiltinFnOnce,
            error.CodecError.Insts.CoreConvertFromModelError.from,
            core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame.from, profileAt, andThen, ← mapMeaning, ← keyMeaning,
            ← textMeaning, Fields.codecBytesView, ← identifier_view, allowed,
            profileView, textInput, keyInput, mapInput]

end Auths.Codec.ProfileDecode

namespace Auths.Codec.BudgetDecode
open ProfileDecode

def wordAt (input : List Nat) (position : Nat) : core.result.Result Nat error.CodecError × Nat :=
  let (value, next) := Cursor.typedHead input position 0
  (match value with | none => .Err error.CodecError.Malformed | some value => .Ok value, next)

def budgetAt (input : List Nat) (position : Nat) :
    core.result.Result (List Nat × Nat) error.CodecError × Nat :=
  andThen (Fields.mapAt input position 2) fun _ position =>
  andThen (Fields.keyAt input position 0) fun _ position =>
  andThen (Fields.textAt input position) fun id position =>
  if identifierDecision id 128 then
    andThen (Fields.keyAt input position 1) fun _ position =>
    andThen (wordAt input position) fun value position => (.Ok (id, value), position)
  else (.Err (.Model .InvalidRegistryId), position)

def budgetView (value : core.result.Result auths_codec.auths_model.BudgetCeiling error.CodecError) :
    core.result.Result (List Nat × Nat) error.CodecError :=
  match value with
  | .Err error => .Err error
  | .Ok value => .Ok (value.algebra.toByteArray.toList.map UInt8.toNat, value.value.val)

@[step] theorem budget_exact (self : cbor.Decoder) :
    decode.budget self ⦃ actual =>
      (budgetView actual.1, actual.2.position.val) =
        budgetAt (Refinement.byteList self.input.val) self.position.val ∧
      actual.2.input = self.input ⦄ := by
  unfold decode.budget
  step with Fields.map_exact as ⟨fields, afterMap, mapMeaning, mapInput⟩
  cases fields with
  | Err error =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, budgetAt, andThen, ← mapMeaning, budgetView, mapInput]
  | Ok _ =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with Fields.key_exact as ⟨key, afterKey, keyMeaning, keyInput⟩
    simp only [mapInput] at keyMeaning
    cases key with
    | Err error =>
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, budgetAt, andThen, ← mapMeaning, ← keyMeaning,
        budgetView, keyInput, mapInput]
    | Ok _ =>
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      step with Fields.text_exact as ⟨text, afterText, textMeaning, textInput⟩
      have textSource := textMeaning
      simp only [keyInput, mapInput] at textMeaning
      cases text with
      | Err error =>
        simp [core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame.from, budgetAt, andThen, ← mapMeaning, ← keyMeaning,
          ← textMeaning, Fields.codecBytesView, budgetView, textInput, keyInput, mapInput]
      | Ok bytes =>
        simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
        have valid := earned_utf8 afterKey bytes afterText textSource
        have parseContract := StringCarrier.budget_algebra_parse_exact bytes valid
        by_cases allowed : StringCarrier.identifierDecision bytes.val 128 = true
        · simp only [allowed, ↓reduceIte] at parseContract
          step with parseContract as ⟨parsed, parseMeaning⟩
          simp only [parseMeaning]
          simp only [core.result.Result.map_err, bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
          step with Fields.key_exact as ⟨key, afterVersionKey, versionKeyMeaning, versionKeyInput⟩
          simp only [textInput, keyInput, mapInput] at versionKeyMeaning
          cases key with
          | Err error =>
            simp [core.result.Result.Insts.CoreOpsTry.branch,
              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
              core.convert.FromSame.from, budgetAt, andThen, ← mapMeaning, ← keyMeaning,
              ← textMeaning, Fields.codecBytesView, ← versionKeyMeaning,
              ← identifier_view, allowed, budgetView, versionKeyInput, textInput, keyInput, mapInput]
          | Ok _ =>
            simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
            step with Cursor.u64_exact as ⟨word, finish, wordMeaning, wordInput⟩
            simp only [versionKeyInput, textInput, keyInput, mapInput] at wordMeaning
            cases word with
            | Err error =>
              simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
                core.result.Result.Insts.CoreOpsTry.branch,
                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                core.convert.FromSame.from, budgetAt, andThen, ← mapMeaning, ← keyMeaning,
                ← textMeaning, Fields.codecBytesView, ← versionKeyMeaning,
                ← identifier_view, allowed, wordAt, ← wordMeaning, Cursor.wordView,
                budgetView, wordInput, versionKeyInput, textInput, keyInput, mapInput]
            | Ok version =>
              simp only [core.result.Result.map_err, bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
              unfold auths_model.BudgetCeiling.new
              simp [core.result.Result.map_err,
                budgetAt, andThen, ← mapMeaning, ← keyMeaning,
                ← textMeaning, Fields.codecBytesView, ← versionKeyMeaning,
                ← identifier_view, allowed, wordAt, ← wordMeaning, Cursor.wordView,
                budgetView, StringCarrier.owned_bytes,
                wordInput, versionKeyInput, textInput, keyInput, mapInput]
        · simp only [allowed, ↓reduceIte] at parseContract
          step with parseContract as ⟨parsed, parseMeaning⟩
          simp only [parseMeaning]
          simp [core.result.Result.map_err, BuiltinFnOnce,
            error.CodecError.Insts.CoreConvertFromModelError.from,
            core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame.from, budgetAt, andThen, ← mapMeaning, ← keyMeaning,
            ← textMeaning, Fields.codecBytesView, ← identifier_view, allowed,
            budgetView, textInput, keyInput, mapInput]

end Auths.Codec.BudgetDecode

namespace Auths.Codec.PermissionDecode
open ProfileDecode

def permissionAt (input : List Nat) (position : Nat) :
    core.result.Result (List Nat × List Nat) error.CodecError × Nat :=
  andThen (Fields.mapAt input position 2) fun _ position =>
  andThen (Fields.keyAt input position 0) fun _ position =>
  andThen (Fields.textAt input position) fun capability position =>
  if identifierDecision capability 128 then
    andThen (Fields.keyAt input position 1) fun _ position =>
    andThen (Fields.textAt input position) fun resource position =>
    if identifierDecision resource 1024 then (.Ok (capability, resource), position)
    else (.Err (.Model .InvalidResource), position)
  else (.Err (.Model .InvalidCapability), position)

def permissionView (value : core.result.Result auths_codec.auths_model.Permission error.CodecError) :
    core.result.Result (List Nat × List Nat) error.CodecError :=
  match value with
  | .Err error => .Err error
  | .Ok value => .Ok (value.capability.toByteArray.toList.map UInt8.toNat,
      value.resource.toByteArray.toList.map UInt8.toNat)

@[step] theorem permission_exact (self : cbor.Decoder) :
    decode.permission self ⦃ actual =>
      (permissionView actual.1, actual.2.position.val) =
        permissionAt (Refinement.byteList self.input.val) self.position.val ∧
      actual.2.input = self.input ⦄ := by
  unfold decode.permission
  step with Fields.map_exact as ⟨fields, afterMap, mapMeaning, mapInput⟩
  cases fields with
  | Err error =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, permissionAt, andThen, ← mapMeaning, permissionView, mapInput]
  | Ok _ =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with Fields.key_exact as ⟨key, afterKey, keyMeaning, keyInput⟩
    simp only [mapInput] at keyMeaning
    cases key with
    | Err error =>
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, permissionAt, andThen, ← mapMeaning, ← keyMeaning,
        permissionView, keyInput, mapInput]
    | Ok _ =>
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      step with Fields.text_exact as ⟨text, afterText, textMeaning, textInput⟩
      have textSource := textMeaning
      simp only [keyInput, mapInput] at textMeaning
      cases text with
      | Err error =>
        simp [core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame.from, permissionAt, andThen, ← mapMeaning, ← keyMeaning,
          ← textMeaning, Fields.codecBytesView, permissionView, textInput, keyInput, mapInput]
      | Ok bytes =>
        simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
        have valid := earned_utf8 afterKey bytes afterText textSource
        have parseContract := StringCarrier.capability_parse_exact bytes valid
        by_cases allowed : StringCarrier.identifierDecision bytes.val 128 = true
        · simp only [allowed, ↓reduceIte] at parseContract
          step with parseContract as ⟨parsed, parseMeaning⟩
          simp only [parseMeaning]
          simp only [core.result.Result.map_err, bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
          step with Fields.key_exact as ⟨key, afterVersionKey, versionKeyMeaning, versionKeyInput⟩
          simp only [textInput, keyInput, mapInput] at versionKeyMeaning
          cases key with
          | Err error =>
            simp [core.result.Result.Insts.CoreOpsTry.branch,
              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
              core.convert.FromSame.from, permissionAt, andThen, ← mapMeaning, ← keyMeaning,
              ← textMeaning, Fields.codecBytesView, ← versionKeyMeaning,
              ← identifier_view, allowed, permissionView, versionKeyInput, textInput, keyInput, mapInput]
          | Ok _ =>
            simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
            step with Fields.text_exact as ⟨resourceResult, finish, resourceMeaning, resourceInput⟩
            have resourceSource := resourceMeaning
            simp only [versionKeyInput, textInput, keyInput, mapInput] at resourceMeaning
            cases resourceResult with
            | Err error =>
              simp [core.result.Result.Insts.CoreOpsTry.branch,
                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                core.convert.FromSame.from, permissionAt, andThen, ← mapMeaning, ← keyMeaning,
                ← textMeaning, Fields.codecBytesView, ← versionKeyMeaning, ← resourceMeaning,
                ← identifier_view, allowed, permissionView,
                resourceInput, versionKeyInput, textInput, keyInput, mapInput]
            | Ok resource =>
              simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
              have resourceValid := earned_utf8 afterVersionKey resource finish resourceSource
              have resourceParse := StringCarrier.resource_parse_exact resource resourceValid
              by_cases resourceAllowed : StringCarrier.identifierDecision resource.val 1024 = true
              · simp only [resourceAllowed, ↓reduceIte] at resourceParse
                step with resourceParse as ⟨parsedResource, resourceParseMeaning⟩
                simp only [resourceParseMeaning, core.result.Result.map_err, bind_tc_ok,
                  core.result.Result.Insts.CoreOpsTry.branch]
                unfold auths_model.Permission.new
                simp [permissionAt, andThen, ← mapMeaning, ← keyMeaning,
                  ← textMeaning, Fields.codecBytesView, ← versionKeyMeaning, ← resourceMeaning,
                  ← identifier_view, allowed, resourceAllowed, permissionView,
                  StringCarrier.owned_bytes, resourceInput, versionKeyInput, textInput, keyInput, mapInput]
              · simp only [resourceAllowed, ↓reduceIte] at resourceParse
                step with resourceParse as ⟨parsedResource, resourceParseMeaning⟩
                simp only [resourceParseMeaning]
                simp [core.result.Result.map_err, BuiltinFnOnce,
                  error.CodecError.Insts.CoreConvertFromModelError.from,
                  core.result.Result.Insts.CoreOpsTry.branch,
                  core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                  core.convert.FromSame.from, permissionAt, andThen, ← mapMeaning, ← keyMeaning,
                  ← textMeaning, Fields.codecBytesView, ← versionKeyMeaning, ← resourceMeaning,
                  ← identifier_view, allowed, resourceAllowed, permissionView,
                  resourceInput, versionKeyInput, textInput, keyInput, mapInput]
        · simp only [allowed, ↓reduceIte] at parseContract
          step with parseContract as ⟨parsed, parseMeaning⟩
          simp only [parseMeaning]
          simp [core.result.Result.map_err, BuiltinFnOnce,
            error.CodecError.Insts.CoreConvertFromModelError.from,
            core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame.from, permissionAt, andThen, ← mapMeaning, ← keyMeaning,
            ← textMeaning, Fields.codecBytesView, ← identifier_view, allowed,
            permissionView, textInput, keyInput, mapInput]

end Auths.Codec.PermissionDecode

namespace Auths.Codec.BudgetDecode
open ProfileDecode

def optionalAt (input : List Nat) (position : Nat) :
    core.result.Result (Option (List Nat × Nat)) error.CodecError × Nat :=
  match Fields.isNullAt input position with
  | .Err error => (.Err error, position)
  | .Ok true => andThen (Fields.nullAt input position) fun _ next => (.Ok none, next)
  | .Ok false => andThen (budgetAt input position) fun budget next => (.Ok (some budget), next)

def optionalView (value : core.result.Result (Option auths_codec.auths_model.BudgetCeiling) error.CodecError) :
    core.result.Result (Option (List Nat × Nat)) error.CodecError :=
  match value with
  | .Err error => .Err error
  | .Ok value => .Ok (value.map fun budget =>
      (budget.algebra.toByteArray.toList.map UInt8.toNat, budget.value.val))

@[step] theorem optional_budget_exact (self : cbor.Decoder) :
    decode.optional_budget self ⦃ actual =>
      (optionalView actual.1, actual.2.position.val) =
        optionalAt (Refinement.byteList self.input.val) self.position.val ∧
      actual.2.input = self.input ⦄ := by
  unfold decode.optional_budget
  step with Fields.is_null_exact as ⟨null, nullMeaning⟩
  cases null with
  | Err error =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, optionalAt, ← nullMeaning, optionalView]
  | Ok null =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    cases null with
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte]
      step with budget_exact as ⟨budget, finish, budgetMeaning, inputSame⟩
      cases budget <;>
        simp [core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame.from, optionalAt, ← nullMeaning,
          andThen, ← budgetMeaning, optionalView, budgetView, inputSame]
    | true =>
      simp only [↓reduceIte]
      step with Fields.null_exact as ⟨unit, finish, unitMeaning, inputSame⟩
      cases unit <;>
        simp [core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame.from, optionalAt, ← nullMeaning,
          andThen, ← unitMeaning, optionalView, inputSame]

end Auths.Codec.BudgetDecode

namespace Auths.Codec.MediaDecode

/-- Successful protocol text reading earns the UTF-8 copy premise. -/
theorem text_accepted_utf8 (self next : cbor.Decoder) (text : Str)
    (accepted : decode.text self = ok (.Ok text, next)) :
    (StdModel.bytes text).IsValidUTF8 := by
  have contract := Fields.text_exact self
  rw [accepted] at contract
  simp only [spec_ok] at contract
  exact ProfileDecode.earned_utf8 self text next contract.1

@[step] theorem media_exact (text : Str) (utf8 : (StdModel.bytes text).IsValidUTF8) :
    auths_model.MediaType.parse text ⦃ actual =>
      (match actual with | .Err error => .Err error
        | .Ok value => .Ok (value.toByteArray.toList.map UInt8.toNat)) =
      if ProfileDecode.identifierDecision (Refinement.byteList text.val) 128 then
        .Ok (Refinement.byteList text.val) else .Err auths_model.ModelError.InvalidMediaType ⦄ := by
  step with StringCarrier.media_parse_exact text utf8 as ⟨actual, meaning⟩
  rw [meaning]
  by_cases allowed : StringCarrier.identifierDecision text.val 128 = true
  · simp [allowed, StringCarrier.owned_bytes, StringCarrier.identifierDecision,
      ProfileDecode.identifierDecision, Refinement.byteList, Auths.Refinement.Identifier.scan_view]
  · simp [allowed, StringCarrier.identifierDecision, ProfileDecode.identifierDecision,
      Refinement.byteList, Auths.Refinement.Identifier.scan_view]

theorem media_parse_accepted_valid (text : Str) (value : String)
    (utf8 : (StdModel.bytes text).IsValidUTF8)
    (accepted : auths_model.MediaType.parse text = ok (.Ok value)) :
    ProfileDecode.identifierDecision (value.toByteArray.toList.map UInt8.toNat) 128 = true := by
  have contract := StringCarrier.media_parse_exact text utf8
  rw [accepted] at contract
  simp only [spec_ok] at contract
  by_cases allowed : StringCarrier.identifierDecision text.val 128 = true
  · simp only [allowed, ↓reduceIte, core.result.Result.Ok.injEq] at contract
    rw [contract]
    rw [StringCarrier.owned_bytes]
    simpa [StringCarrier.identifierDecision, ProfileDecode.identifierDecision, Refinement.byteList,
      Auths.Refinement.Identifier.scan_view] using allowed
  · simp [allowed] at contract

end Auths.Codec.MediaDecode
