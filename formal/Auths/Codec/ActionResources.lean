import Auths.Codec.AttachmentResources
import Auths.Codec.ActionWire
open Aeneas Aeneas.Std Result
open auths_codec
namespace Auths.Codec.ActionResources
open DecodedFields ProtocolEncode ObjectEncode AttachmentEncode ActionEncode ActionDecodedFields

theorem attachment_cost_eq (attachments : List auths_codec.auths_model.DetachedAttachment) :
    attachmentsCost attachments = 77 * attachments.length + AttachmentResources.byteSum attachments := by
  induction attachments with
  | nil => simp [attachmentsCost, AttachmentResources.byteSum]
  | cons first rest ih =>
    simp only [attachmentsCost, List.map_cons, List.sum_cons, attachmentCost,
      AttachmentResources.byteSum, List.length_cons] at *
    omega

theorem optional_budget_cost_bounded (value : Option auths_codec.auths_model.BudgetCeiling)
    (valid : ∀ budget ∈ value, BudgetValid (stringBytes budget.algebra) budget.value.val) :
    optionalBudgetCost value ≤ 173 := by
  cases value with
  | none => simp [optionalBudgetCost]
  | some budget =>
    have bounded := (identifier_earns_bound _ _ (valid budget (by simp)).1).2.1
    rw [stringBytes_length] at bounded
    simp only [optionalBudgetCost]
    omega

theorem valid_allocation_envelope (action : auths_codec.auths_model.CanonicalAction)
    (fields : FieldsValid action) (body : action.body.val.length ≤ 8388608)
    (attachments : AttachmentResources.Bounded action) : actionCost action ≤ 16818401 := by
  obtain ⟨profile, media, permission, budget⟩ := fields
  have profileBound := (identifier_earns_bound _ _ profile.1).2.1
  have mediaBound := (identifier_earns_bound _ _ media).2.1
  have capabilityBound := (identifier_earns_bound _ _ permission.1).2.1
  have resourceBound := (identifier_earns_bound _ _ permission.2).2.1
  have budgetBound := optional_budget_cost_bounded action.requested_budget budget
  obtain ⟨attachmentCount, attachmentBytes⟩ := attachments
  simp only [stringBytes_length] at profileBound mediaBound capabilityBound resourceBound
  simp only [actionCost, attachment_cost_eq]
  omega

/-- An independently calculated portable envelope for every allocation in
re-encoding an accepted action. This closes the encoder's buffer premise
from actual decoded constructor checks and aggregate attachment validation. -/
theorem decoded_allocation_envelope (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action)) :
    actionCost action ≤ 16818401 := by
  exact valid_allocation_envelope action (decoded_fields_valid input limits action accepted)
    (Action.decoded_body_valid input limits action accepted).2
    (AttachmentResources.decoded_earns_bounds input limits action accepted)

theorem decoded_buffer_room (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action)) :
    actionCost action ≤ Usize.max := by
  have envelope := decoded_allocation_envelope input limits action accepted
  have portable : 16818401 ≤ Usize.max := by scalar_tac
  omega

/-- The public decoder's accepted bytes have exactly the independent six-field
wire form, with all string and allocation premises earned from source checks. -/
theorem decoded_wire_exact (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action)) :
    Refinement.byteList input.val = actionEncoding action :=
  ActionWire.decoded_bytes_equal_model input limits action accepted
    (decoded_buffer_room input limits action accepted)

end Auths.Codec.ActionResources
