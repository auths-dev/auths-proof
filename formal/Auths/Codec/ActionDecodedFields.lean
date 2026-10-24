import Auths.Codec.ActionEncode
import Auths.Codec.ProtocolEncode
import Auths.Codec.DecodedFields
import Auths.Codec.ActionValidity
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.ActionDecodedFields
open DecodedFields ProtocolEncode

def FieldsValid (action : auths_codec.auths_model.CanonicalAction) : Prop :=
  ProfileValid (stringBytes action.profile.id) action.profile.version.val ∧
  ProfileDecode.identifierDecision (stringBytes action.media_type) 128 = true ∧
  PermissionValid (stringBytes action.permission.capability) (stringBytes action.permission.resource) ∧
  ∀ budget ∈ action.requested_budget, BudgetValid (stringBytes budget.algebra) budget.value.val

theorem profile_accepted_valid (decoder : cbor.Decoder)
    (value : auths_codec.auths_model.ProfileRef) (next : cbor.Decoder)
    (accepted : decode.profile_ref decoder = ok (.Ok value, next)) :
    ProfileValid (stringBytes value.id) value.version.val := by
  have valid := profile_success_valid decoder
  rw [accepted] at valid
  simp only [spec_ok] at valid
  exact valid value rfl

theorem permission_accepted_valid (decoder : cbor.Decoder)
    (value : auths_codec.auths_model.Permission) (next : cbor.Decoder)
    (accepted : decode.permission decoder = ok (.Ok value, next)) :
    PermissionValid (stringBytes value.capability) (stringBytes value.resource) := by
  have valid := permission_success_valid decoder
  rw [accepted] at valid
  simp only [spec_ok] at valid
  exact valid value rfl

theorem budget_accepted_valid (decoder : cbor.Decoder)
    (value : auths_codec.auths_model.BudgetCeiling) (next : cbor.Decoder)
    (accepted : decode.budget decoder = ok (.Ok value, next)) :
    BudgetValid (stringBytes value.algebra) value.value.val := by
  have valid := budget_success_valid decoder
  rw [accepted] at valid
  simp only [spec_ok] at valid
  exact valid value rfl

theorem optional_budget_accepted_valid (decoder : cbor.Decoder)
    (value : Option auths_codec.auths_model.BudgetCeiling) (next : cbor.Decoder)
    (accepted : decode.optional_budget decoder = ok (.Ok value, next)) :
    ∀ budget ∈ value, BudgetValid (stringBytes budget.algebra) budget.value.val := by
  unfold decode.optional_budget at accepted
  simp only [Bind.bind, Aeneas.Std.bind] at accepted
  repeat' first
    | casesm* _ × _
    | dsimp only at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [uncurry, Bind.bind, Aeneas.Std.bind,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, core.result.Result.map, BuiltinFnOnce,
        core.option.Option.Some, bind_tc_ok, bind_tc_fail, bind_tc_div,
        Result.ok.injEq, core.result.Result.Ok.injEq, Prod.mk.injEq, reduceCtorEq] at accepted
    | contradiction
  all_goals
    subst value
    simp only [Option.mem_def, Option.some.injEq]
    aesop (add safe forward budget_accepted_valid)

theorem media_accepted_valid (self next : cbor.Decoder) (text : Str) (value : String)
    (read : decode.text self = ok (.Ok text, next))
    (parsed : auths_model.MediaType.parse text = ok (.Ok value)) :
    ProfileDecode.identifierDecision (stringBytes value) 128 = true := by
  exact MediaDecode.media_parse_accepted_valid text value (MediaDecode.text_accepted_utf8 self next text read) parsed

theorem constructed_fields_valid
    (profile : auths_codec.auths_model.ProfileRef) (media : auths_codec.auths_model.MediaType)
    (body : alloc.vec.Vec Std.U8) (permission : auths_codec.auths_model.Permission)
    (budget : Option auths_codec.auths_model.BudgetCeiling)
    (profileValid : ProfileValid (stringBytes profile.id) profile.version.val)
    (mediaValid : ProfileDecode.identifierDecision (stringBytes media) 128 = true)
    (permissionValid : PermissionValid (stringBytes permission.capability) (stringBytes permission.resource))
    (budgetValid : ∀ value ∈ budget, BudgetValid (stringBytes value.algebra) value.value.val)
    (output : auths_codec.auths_model.CanonicalAction)
    (accepted : auths_model.CanonicalAction.new profile media body permission budget = ok (.Ok output)) :
    FieldsValid output := by
  rw [Constructors.canonical_action_new_exact] at accepted
  split at accepted
  · have same : (⟨profile, media, body, permission, budget, alloc.vec.Vec.new _⟩ :
        auths_codec.auths_model.CanonicalAction) = output := by simpa using accepted
    subst output
    exact ⟨profileValid, mediaValid, permissionValid, budgetValid⟩
  · simp at accepted

theorem attachments_preserve_fields (action : auths_codec.auths_model.CanonicalAction)
    (attachments : alloc.vec.Vec auths_codec.auths_model.DetachedAttachment)
    (output : auths_codec.auths_model.CanonicalAction) (valid : FieldsValid action)
    (accepted : auths_model.CanonicalAction.with_detached_attachments action attachments = ok (.Ok output)) :
    FieldsValid output := by
  unfold auths_model.CanonicalAction.with_detached_attachments at accepted
  simp only [Bind.bind, Aeneas.Std.bind] at accepted
  repeat' first
    | casesm* _ × _
    | dsimp only at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [uncurry, Bind.bind, Aeneas.Std.bind,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, Result.ok.injEq, core.result.Result.Ok.injEq,
        reduceCtorEq] at accepted
    | contradiction
  all_goals subst output; exact valid

/-- The actual public decoder carries successful field-constructor checks
through action construction and attachment normalization. No caller-supplied
assertion of field validity is accepted as a premise. -/
theorem decoded_fields_valid (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action)) : FieldsValid action := by
  unfold decode.decode_canonical_action canonical.accept canonical.accept_with_error at accepted
  simp only [Bind.bind, Aeneas.Std.bind] at accepted
  repeat' first
    | casesm* _ × _
    | dsimp only at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [uncurry, Bind.bind, Aeneas.Std.bind,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, bind_tc_fail, bind_tc_div,
        Result.ok.injEq, core.result.Result.Ok.injEq, reduceCtorEq] at accepted
    | contradiction
  all_goals subst action
  all_goals casesm* core.result.Result auths_codec.auths_model.CanonicalAction _
  all_goals simp_all only [Result.ok.injEq, core.result.Result.Ok.injEq,
    core.ops.control_flow.ControlFlow.Continue.injEq, reduceCtorEq]
  all_goals
    aesop (add safe forward profile_accepted_valid)
      (add safe forward media_accepted_valid)
      (add safe forward permission_accepted_valid)
      (add safe forward optional_budget_accepted_valid)
      (add safe forward constructed_fields_valid)
      (add safe forward attachments_preserve_fields)

theorem fields_earn_strings (action : auths_codec.auths_model.CanonicalAction)
    (fields : FieldsValid action) : ActionEncode.StringsBounded action := by
  obtain ⟨profile, media, permission, budget⟩ := fields
  have profileBound := (identifier_earns_bound _ _ profile.1).2.1
  have mediaBound := (identifier_earns_bound _ _ media).2.1
  have capabilityBound := (identifier_earns_bound _ _ permission.1).2.1
  have resourceBound := (identifier_earns_bound _ _ permission.2).2.1
  simp only [stringBytes_length] at profileBound mediaBound capabilityBound resourceBound
  constructor
  · scalar_tac
  · scalar_tac
  · scalar_tac
  · scalar_tac
  · intro value member
    have algebraBound := (identifier_earns_bound _ _ (budget value member).1).2.1
    rw [stringBytes_length] at algebraBound
    scalar_tac

/-- The portable native-string carrier bounds used by encoding are a
consequence of real decoder constructor checks, not a user-supplied flag. -/
theorem decoded_strings_bounded (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action)) :
    ActionEncode.StringsBounded action := by
  exact fields_earn_strings action (decoded_fields_valid input limits action accepted)

end Auths.Codec.ActionDecodedFields
