import Auths.Codec.AttachmentValidation
import Auths.Codec.ActionResources
import Auths.Codec.Limits
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.DecoderContracts
open DecodedFields ProtocolEncode ActionDecodedFields

@[step] theorem text_checked (self : cbor.Decoder) :
    decode.text self ⦃ actual => ∀ text, actual.1 = .Ok text → (StdModel.bytes text).IsValidUTF8 ⦄ := by
  obtain ⟨actual, evaluates, _⟩ := spec_imp_exists (Fields.text_exact self)
  rw [evaluates]
  simp only [spec_ok]
  intro text same
  exact MediaDecode.text_accepted_utf8 self actual.2 text (by simpa only [same] using evaluates)

@[step] theorem media_checked (text : Str) (utf8 : (StdModel.bytes text).IsValidUTF8) :
    auths_model.MediaType.parse text ⦃ actual =>
      ∀ media, actual = .Ok media → ProfileDecode.identifierDecision (stringBytes media) 128 = true ⦄ := by
  obtain ⟨actual, evaluates, _⟩ := spec_imp_exists (MediaDecode.media_exact text utf8)
  rw [evaluates]
  simp only [spec_ok]
  intro media same
  exact MediaDecode.media_parse_accepted_valid text media utf8 (by simpa only [same] using evaluates)

@[step] theorem optional_budget_checked (self : cbor.Decoder) :
    decode.optional_budget self ⦃ actual =>
      ∀ value, actual.1 = .Ok value →
        ∀ budget ∈ value, BudgetValid (stringBytes budget.algebra) budget.value.val ⦄ := by
  obtain ⟨actual, evaluates, _⟩ := spec_imp_exists (BudgetDecode.optional_budget_exact self)
  rw [evaluates]
  simp only [spec_ok]
  intro value same
  exact optional_budget_accepted_valid self value actual.2 (by simpa only [same] using evaluates)

@[step] theorem action_new_checked
    (profile : auths_codec.auths_model.ProfileRef) (media : auths_codec.auths_model.MediaType)
    (body : alloc.vec.Vec Std.U8) (permission : auths_codec.auths_model.Permission)
    (budget : Option auths_codec.auths_model.BudgetCeiling)
    (profileValid : ProfileValid (stringBytes profile.id) profile.version.val)
    (mediaValid : ProfileDecode.identifierDecision (stringBytes media) 128 = true)
    (permissionValid : PermissionValid (stringBytes permission.capability) (stringBytes permission.resource))
    (budgetValid : ∀ value ∈ budget, BudgetValid (stringBytes value.algebra) value.value.val) :
    auths_model.CanonicalAction.new profile media body permission budget ⦃ actual =>
      ∀ action, actual = .Ok action → FieldsValid action ∧ action.body.val.length ≤ 8388608 ⦄ := by
  rw [Constructors.canonical_action_new_exact]
  split
  · rename_i bodyValid
    simp only [spec_ok, core.result.Result.Ok.injEq]
    intro action same
    subst action
    exact ⟨⟨profileValid, mediaValid, permissionValid, budgetValid⟩, bodyValid.2⟩
  · simp

@[step] theorem attachments_checked (action : auths_codec.auths_model.CanonicalAction)
    (attachments : alloc.vec.Vec auths_codec.auths_model.DetachedAttachment)
    (fields : FieldsValid action) (body : action.body.val.length ≤ 8388608) :
    auths_model.CanonicalAction.with_detached_attachments action attachments ⦃ actual =>
      ∀ output, actual = .Ok output →
        FieldsValid output ∧ output.body.val.length ≤ 8388608 ∧ AttachmentResources.Bounded output ⦄ := by
  obtain ⟨actual, evaluates, _⟩ := spec_imp_exists (AttachmentValidation.constructor_exact action attachments)
  rw [evaluates]
  simp only [spec_ok]
  intro output same
  have accepted : auths_model.CanonicalAction.with_detached_attachments action attachments = ok (.Ok output) := by
    simpa only [same] using evaluates
  exact ⟨attachments_preserve_fields action attachments output fields accepted,
    by simpa only [Action.attachments_preserve_body action attachments output accepted] using body,
    AttachmentResources.constructor_earns_bounds action attachments output accepted⟩

end Auths.Codec.DecoderContracts
